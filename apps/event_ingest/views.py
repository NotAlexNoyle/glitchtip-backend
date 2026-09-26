import io
import logging
import uuid
from dataclasses import asdict

import orjson
import sentry_sdk
from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import RequestDataTooBig, TooManyFieldsSent
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.http.multipartparser import MultiPartParserError
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from ninja.errors import AuthenticationError
from ninja.errors import ValidationError as NinjaValidationError
from pydantic import ValidationError
from sentry_sdk import capture_exception, set_context, set_level

from apps.event_ingest.interfaces import IngestTaskMessage, LogIngestTaskMessage
from apps.issue_events.constants import IssueEventType
from apps.logs.tasks import ingest_logs
from glitchtip.api.exceptions import ThrottleException
from glitchtip.partition_manager import UUID7Helper

from .api import get_ip_address
from .authentication import EventAuthHttpRequest, event_auth
from .minidump_event import InvalidMinidump, merge_sdk_event, parse_minidump
from .minidump_upload import sdk_event_from_upload
from .pii_scrubber import resolve_scrubber
from .rust_envelope import (
    EnvelopeTooBig,
    decompress_body,
    envelope_error_response,
    frame_envelope,
    request_content_encoding,
)
from .schema import (
    SUPPORTED_ITEMS,
    EnvelopeHeaderSchema,
    EventUser,
    FeedbackPayload,
    ItemHeaderSchema,
    LogEnvelopePayload,
    LogItemSchema,
    TransactionEventSchema,
    UserReportPayload,
    UserReportTaskMessage,
    WebIngestIssueEvent,
    otel_log_to_log_item,
)
from .tasks import ingest_event, ingest_transaction, ingest_user_report
from .utils import serialize_for_vtasks

logger = logging.getLogger(__name__)

MINIDUMP_MAGIC = b"MDMP"


def handle_supported_payload_error(
    message: str,
    item_header: ItemHeaderSchema,
    payload_bytes: bytes,
    e: ValidationError,
    request: EventAuthHttpRequest,
) -> None:
    set_level("warning")
    context = {"item_header": item_header.dict()}
    try:
        # Try to get a preview, limit size
        context["payload_preview"] = orjson.loads(payload_bytes[:1024])
    except orjson.JSONDecodeError:
        context["payload_preview"] = {
            "hex": payload_bytes[:100].hex()
        }  # Show hex if not JSON
    set_context("incoming event error", context)
    capture_exception(e)
    logger.warning(
        f"{message} on {request.path} for type '{item_header.type}'", exc_info=e
    )


def _find_minidump_attachment(items) -> bytes | None:
    """The first ``event.minidump`` attachment's bytes, if the envelope has one."""
    for envelope_item in items:
        payload = envelope_item.payload
        if payload[:4] != MINIDUMP_MAGIC:
            continue
        try:
            header = ItemHeaderSchema.model_validate_json(envelope_item.header)
        except ValidationError:
            continue
        if header.type == "attachment" and header.attachment_type == "event.minidump":
            return payload
    return None


async def _parse_minidump_attachment(minidump_bytes: bytes, path: str) -> dict | None:
    """The dump's event fields, or None (logged) when it doesn't parse."""
    try:
        return await sync_to_async(parse_minidump)(minidump_bytes)
    except InvalidMinidump as e:
        logger.info("Rejected minidump attachment on %s: %s", path, e)
    except Exception as e:
        capture_exception(e)
        logger.error("Failed to process minidump attachment on %s", path, exc_info=e)
    return None


def _merge_event_item(
    payload_bytes: bytes, minidump_event: dict
) -> WebIngestIssueEvent | None:
    """The envelope's event item merged with its dump, or None.

    None means "ingest the event item as it is": the merged event didn't
    validate, so the SDK's own event still gets in, as it would have
    without a dump.
    """
    try:
        sdk_event = orjson.loads(payload_bytes)
    except orjson.JSONDecodeError:
        return None
    if not isinstance(sdk_event, dict):
        return None
    try:
        return WebIngestIssueEvent.model_validate(
            merge_sdk_event(minidump_event, sdk_event)
        )
    except ValidationError:
        return None


@csrf_exempt
async def event_envelope_view(request: EventAuthHttpRequest, project_id: int):
    """Django fallback for envelope ingest.

    Every envelope POST is served by the Rust pipeline
    (``glitchtip.rust_ingest``). What is left for this view is what that
    pipeline declines: non-POST methods (405, below), and envelopes carrying
    an SDK minidump attachment, which Rust hands back before any side effect
    because turning a minidump into an event is implemented in Python (the
    ``minidump`` package plus the schemas below).

    The dump is merged into the envelope's event item (the SDK's scope: release,
    user, tags, breadcrumbs) or, without one, becomes an event on its own.
    What a dump yields is still shallow — the exception, one frame per thread
    and the module list, with no stack walking — so treat the path as
    in-progress rather than as behavior worth preserving.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        project = await event_auth(request)
    except ThrottleException as e:
        response = HttpResponse("Too Many Requests", status=429)
        response["Retry-After"] = str(e.retry_after)
        return response
    except AuthenticationError:
        return JsonResponse({"detail": "Denied"}, status=403)
    except NinjaValidationError:
        return JsonResponse({"detail": "Invalid DSN"}, status=403)

    if project is None:
        # Should be caught by event_auth, but defensive check
        return JsonResponse({"detail": "Denied"}, status=403)
    request.auth = project  # Assuming event_auth returns the project object
    update_first_event = project.first_event is None
    client_ip = get_ip_address(request)
    # Server-side PII scrubbing config (per-project, falling back to the
    # fleet-wide default). Resolved once per request; scrub_event is a no-op
    # when scrubbing is disabled, so call sites stay unconditional.
    scrubber = resolve_scrubber(
        project.scrub_config, settings.GLITCHTIP_PII_SCRUB_DEFAULT
    )

    content_encoding = request_content_encoding(request)
    try:
        body = await sync_to_async(lambda: request.body)()
    except RequestDataTooBig as e:
        return HttpResponseForbidden(f"{e}", status=413)

    # Decompress (if Content-Encoded) and frame the envelope in Rust: gt_rust
    # takes the raw body plus its Content-Encoding and returns the lifted header
    # fields plus the item list, enforcing the decompressed-size cap in its own
    # allocator. The body is never decompressed in Python.
    try:
        envelope = frame_envelope(body, content_encoding)
    except (ValueError, EnvelopeTooBig) as e:
        response = envelope_error_response(e)
        if response is not None:
            return response
        raise

    # Validate Envelope Header
    try:
        envelope_header = EnvelopeHeaderSchema.model_validate_json(envelope.header)
    except ValidationError as e:
        set_level("warning")
        capture_exception(e)
        logger.warning(
            f"Envelope Header validation error on {request.path}", exc_info=e
        )
        # Return 400 Bad Request for malformed envelope structure
        return JsonResponse({"detail": "Invalid envelope header"}, status=400)
    envelope_header_event_id = envelope_header.event_id

    # An SDK that sends a minidump in an envelope (sentry-native's breakpad
    # backend, sentry-electron's default minidump integration) sends the
    # crash's event alongside it, carrying the scope but no stack. Find the
    # dump up front so the event item can be merged with it; an envelope
    # with a dump and no event item gets an event built from the dump alone.
    minidump_bytes = _find_minidump_attachment(envelope.items)
    # Parsed at most once, lazily; claimed by the first event item ingested.
    minidump_event: dict | None = None
    minidump_parsed = False
    minidump_claimed = False

    # Loop through items. gt_rust has already split each item into its header
    # line and verbatim payload bytes (length- or newline-delimited) and stopped
    # at the first non-JSON item header, so this loop does no framing or
    # short-read handling — just validate the header and dispatch on type.
    for envelope_item in envelope.items:
        item_header_line = envelope_item.header
        payload_bytes = envelope_item.payload

        # Validate Item Header
        try:
            item_header = ItemHeaderSchema.model_validate_json(item_header_line)
        except ValidationError as e:
            errors = e.errors()
            if any(err["type"] == "json_invalid" for err in errors):
                # Not valid JSON — corrupted/binary data, typically
                # from a tunnel proxy mangling binary envelope payloads.
                break
            # An unknown item type (a `literal_error` on the `type` field) is
            # a valid header for a type that is in neither the supported nor
            # the ignored list — e.g. the SDK spec added something new. Give
            # each distinct type its own fingerprint so a genuinely-new type
            # surfaces as its own issue instead of folding every unknown type
            # into one. Other schema failures (e.g. a malformed `length`) keep
            # the generic grouping so they aren't merged under a type.
            type_error = next(
                (
                    err
                    for err in errors
                    if err["type"] == "literal_error" and err["loc"][:1] == ("type",)
                ),
                None,
            )
            if type_error is not None:
                item_type = type_error.get("input")
                if not isinstance(item_type, str):
                    try:
                        item_type = orjson.loads(item_header_line).get("type")
                    except orjson.JSONDecodeError:
                        item_type = None
                    if not isinstance(item_type, str):
                        item_type = "unknown"
                with sentry_sdk.new_scope() as scope:
                    scope.level = "warning"
                    scope.fingerprint = [
                        "envelope-unsupported-item-type",
                        item_type,
                    ]
                    scope.set_tag("envelope_item_type", item_type)
                    scope.set_context(
                        "invalid item header",
                        {"line": item_header_line.decode(errors="replace")[:1024]},
                    )
                    sentry_sdk.capture_exception(e)
                break
            # Valid JSON that our schema doesn't understand — worth
            # knowing about in case the SDK spec evolved.
            set_level("warning")
            set_context(
                "invalid item header",
                {"line": item_header_line.decode(errors="replace")[:1024]},
            )
            capture_exception(e)
            break

        # Handle Payload based on Type
        if item_header.type in SUPPORTED_ITEMS:
            try:
                if item_header.type == "event":
                    # Heavy validation and normalization happens here
                    item = None
                    if minidump_bytes is not None and not minidump_claimed:
                        if not minidump_parsed:
                            minidump_parsed = True
                            minidump_event = await _parse_minidump_attachment(
                                minidump_bytes, request.path
                            )
                        if minidump_event is not None:
                            item = _merge_event_item(payload_bytes, minidump_event)
                    if item is None:
                        item = WebIngestIssueEvent.model_validate_json(payload_bytes)
                    minidump_claimed = True
                    issue_type = (
                        IssueEventType.ERROR
                        if item.exception
                        else IssueEventType.DEFAULT
                    )

                    if client_ip:
                        if item.user:
                            item.user.ip_address = client_ip
                        else:
                            item.user = EventUser(ip_address=client_ip)

                    # Prefer event item uuid, then enveloper header uuid, then if all else fails, generate one
                    if item.event_id is None:
                        item.event_id = envelope_header_event_id or uuid.uuid4()

                    primary_id = UUID7Helper.from_datetime()
                    interchange_event = IngestTaskMessage(
                        project_id=project_id,
                        organization_id=project.organization_id,
                        payload=scrubber.scrub_event(
                            item.dict() | {"type": issue_type}
                        ),
                        received=timezone.now(),
                        update_first_event=update_first_event,
                        uuid=primary_id.hex,
                    )
                    if await cache.aadd("uuid" + item.event_id.hex, True):
                        await ingest_event.aenqueue(
                            serialize_for_vtasks(asdict(interchange_event))
                        )

                elif item_header.type == "transaction":
                    item = TransactionEventSchema.model_validate_json(payload_bytes)
                    primary_id = UUID7Helper.from_datetime()
                    interchange_event = IngestTaskMessage(
                        project_id=project_id,
                        organization_id=project.organization_id,  # Use project from auth
                        payload=scrubber.scrub_event(item.dict()),
                        received=timezone.now(),
                        update_first_event=update_first_event,
                        uuid=primary_id.hex,
                    )
                    if await cache.aadd("uuid" + item.event_id.hex, True):
                        await ingest_transaction.aenqueue(
                            serialize_for_vtasks(asdict(interchange_event))
                        )

                elif item_header.type in ("user_report", "feedback"):
                    if item_header.type == "feedback":
                        item = FeedbackPayload.model_validate_json(payload_bytes)
                    else:
                        item = UserReportPayload.model_validate_json(payload_bytes)
                    report_data = item.to_user_report_data()
                    msg = UserReportTaskMessage(
                        project_id=project_id,
                        organization_id=project.organization_id,
                        **report_data,
                    )
                    await ingest_user_report.aenqueue(
                        serialize_for_vtasks(msg.model_dump())
                    )

                elif item_header.type in ("log", "otel_log"):
                    # Check if logs feature is enabled
                    if not settings.GLITCHTIP_ENABLE_LOGS:
                        # Silently ignore logs when feature is disabled
                        continue

                    if item_header.type == "otel_log":
                        # OTel log: single record per item, OTel data model format
                        otel_record = orjson.loads(payload_bytes)
                        converted = otel_log_to_log_item(otel_record)
                        log_items = [LogItemSchema(**converted)]
                    else:
                        # sentry-sdk log: multiple items in {"items": [...]} wrapper
                        log_payload = LogEnvelopePayload.model_validate_json(
                            payload_bytes
                        )
                        log_items = log_payload.items

                    log_message = LogIngestTaskMessage(
                        project_id=project_id,
                        organization_id=project.organization_id,
                        received=timezone.now(),
                        logs=[
                            scrubber.scrub_log(log_item.model_dump())
                            for log_item in log_items
                        ],
                    )
                    await ingest_logs.aenqueue(
                        serialize_for_vtasks(asdict(log_message))
                    )

            except ValidationError as e:
                # Payload validation failed for a supported type. Log it.
                handle_supported_payload_error(
                    f"{item_header.type.capitalize()} Item validation error",
                    item_header,
                    payload_bytes,
                    e,
                    request,
                )
                # Continue to the next item
                continue
            except (
                Exception
            ) as e:  # Catch other processing errors (like task enqueueing?)
                set_level("error")
                capture_exception(e)
                logger.error(
                    f"Error processing supported item type {item_header.type} on {request.path}",
                    exc_info=e,
                )
                # Decide whether to continue or break, maybe continue is okay
                continue

    # A minidump no event item claimed becomes an event of its own.
    if minidump_bytes is not None and not minidump_claimed:
        if not minidump_parsed:
            minidump_event = await _parse_minidump_attachment(
                minidump_bytes, request.path
            )
        if minidump_event is not None:
            try:
                item = WebIngestIssueEvent.model_validate(minidump_event)
                if client_ip:
                    item.user = EventUser(ip_address=client_ip)
                item.event_id = envelope_header_event_id or uuid.uuid4()
                issue_type = (
                    IssueEventType.ERROR if item.exception else IssueEventType.DEFAULT
                )
                primary_id = UUID7Helper.from_datetime()
                interchange_event = IngestTaskMessage(
                    project_id=project_id,
                    organization_id=project.organization_id,
                    payload=scrubber.scrub_event(item.dict() | {"type": issue_type}),
                    received=timezone.now(),
                    update_first_event=update_first_event,
                    uuid=primary_id.hex,
                )
                if await cache.aadd("uuid" + item.event_id.hex, True):
                    await ingest_event.aenqueue(
                        serialize_for_vtasks(asdict(interchange_event))
                    )
            except Exception as e:
                capture_exception(e)
                logger.error(
                    "Failed to process minidump attachment on %s",
                    request.path,
                    exc_info=e,
                )

    # Final Response
    # Return event_id from envelope header if it exists, as it might relate
    # to the overall submission even if items have their own IDs.
    if envelope_header.event_id:
        return JsonResponse({"id": envelope_header.event_id.hex})
    return JsonResponse({})  # Success, but maybe no specific ID to return


# Body bytes allowed past GLITCHTIP_MAX_MINIDUMP_SIZE for multipart framing
# and the metadata parts minidump_upload reads (each capped well below this).
_MINIDUMP_BODY_ALLOWANCE = 2 * 1024 * 1024


def _too_big(detail: str) -> HttpResponse:
    return HttpResponse(detail, status=413)


def _read_minidump_upload(request, content_encoding: str | None):
    """Parse the multipart body; return (minidump bytes, SDK event) or a response.

    Sync: it spools the file part to disk and reads it back, so the async
    view runs it in a worker thread instead of on the event loop.
    """
    max_size = settings.GLITCHTIP_MAX_MINIDUMP_SIZE
    # Refuse an oversized body before Django spools it to disk. The allowance
    # covers the multipart framing and the SDK metadata parts next to the dump.
    try:
        content_length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        content_length = 0
    if content_length > max_size + _MINIDUMP_BODY_ALLOWANCE:
        return _too_big("Minidump upload too large")
    # A Content-Encoded multipart upload arrives still compressed (crashpad
    # and Electron both gzip by default). Decompress it in Rust, capped, and
    # swap in a plain stream before Django parses request.FILES.
    if content_encoding:
        compressed = request._stream.read(max_size + 1)
        if len(compressed) > max_size:
            return _too_big("Minidump upload too large")
        try:
            decompressed = decompress_body(compressed, content_encoding, max_size)
        except EnvelopeTooBig as e:
            return _too_big(str(e))
        except ValueError:
            return JsonResponse({"detail": "Invalid compressed body"}, status=400)
        del compressed
        request._stream = io.BytesIO(decompressed)
        request.META["CONTENT_LENGTH"] = str(len(decompressed))
        request.META.pop("HTTP_CONTENT_ENCODING", None)
        del decompressed

    try:
        files = request.FILES
        post = request.POST
    except RequestDataTooBig as e:
        return _too_big(str(e))
    except TooManyFieldsSent:
        return JsonResponse({"detail": "Too many fields"}, status=400)
    except MultiPartParserError:
        return JsonResponse({"detail": "Invalid multipart body"}, status=400)
    # The file part now lives in its own buffer (or on disk past
    # FILE_UPLOAD_MAX_MEMORY_SIZE); drop the decompressed body.
    request._stream = io.BytesIO()

    upload_file = files.get("upload_file_minidump")
    if not upload_file:
        return JsonResponse({"detail": "Missing upload_file_minidump"}, status=400)
    if upload_file.size is not None and upload_file.size > max_size:
        return _too_big("Minidump too large")
    minidump_data = upload_file.read(max_size + 1)
    upload_file.close()
    if len(minidump_data) > max_size:
        return _too_big("Minidump too large")
    if len(minidump_data) < 4 or minidump_data[:4] != MINIDUMP_MAGIC:
        return JsonResponse({"detail": "Invalid minidump file"}, status=400)
    return minidump_data, sdk_event_from_upload(post, files)


def _validate_minidump_event(
    minidump_event: dict, sdk_event: dict, path: str
) -> WebIngestIssueEvent:
    """Validate the dump merged with its SDK event, or the dump alone.

    The SDK event is client-supplied; if it doesn't validate, keep the crash
    and drop the metadata rather than rejecting both.
    """
    try:
        return WebIngestIssueEvent.model_validate(
            merge_sdk_event(minidump_event, sdk_event)
        )
    except ValidationError as e:
        if not sdk_event:
            raise
        logger.info("Dropped invalid SDK event sent with minidump on %s: %s", path, e)
        return WebIngestIssueEvent.model_validate(minidump_event)


@csrf_exempt
async def minidump_view(request: EventAuthHttpRequest, project_id: int):
    """Accept Crashpad/Breakpad minidump uploads.

    POST /api/<project_id>/minidump/?sentry_key=<public_key>
    Content-Type: multipart/form-data

    Fields:
        upload_file_minidump: The binary minidump file
        plus the SDK event, in any of the shapes minidump_upload reads
        (crashpad's msgpack ``__sentry-event`` and breadcrumb files,
        Electron's ``sentry__N`` chunks, or a JSON ``sentry`` field)
    """
    if request.method != "POST":
        return JsonResponse({"detail": "Method not allowed"}, status=405)

    try:
        project = await event_auth(request)
    except ThrottleException as e:
        response = HttpResponse("Too Many Requests", status=429)
        response["Retry-After"] = str(e.retry_after)
        return response
    except AuthenticationError:
        return JsonResponse({"detail": "Denied"}, status=403)
    except NinjaValidationError:
        return JsonResponse({"detail": "Invalid DSN"}, status=403)

    if project is None:
        return JsonResponse({"detail": "Denied"}, status=403)
    request.auth = project  # get_ip_address reads the IP-scrubbing setting
    update_first_event = project.first_event is None

    result = await sync_to_async(_read_minidump_upload)(
        request, request_content_encoding(request)
    )
    if isinstance(result, HttpResponse):
        return result
    minidump_data, sdk_event = result

    try:
        minidump_event = await sync_to_async(parse_minidump)(minidump_data)
    except InvalidMinidump:
        return JsonResponse({"detail": "Invalid minidump file"}, status=400)
    except Exception as e:
        capture_exception(e)
        logger.error("Failed to parse minidump on %s", request.path, exc_info=e)
        return JsonResponse({"detail": "Failed to parse minidump"}, status=400)
    del minidump_data

    # Validate and enqueue
    try:
        item = await sync_to_async(_validate_minidump_event)(
            minidump_event, sdk_event, request.path
        )
    except ValidationError as e:
        set_level("warning")
        capture_exception(e)
        logger.warning(
            "Minidump event validation error on %s", request.path, exc_info=e
        )
        return JsonResponse({"detail": "Event validation failed"}, status=400)

    if item.event_id is None:
        item.event_id = uuid.uuid4()

    client_ip = get_ip_address(request)
    if client_ip:
        if item.user:
            item.user.ip_address = client_ip
        else:
            item.user = EventUser(ip_address=client_ip)

    issue_type = IssueEventType.ERROR if item.exception else IssueEventType.DEFAULT

    scrubber = resolve_scrubber(
        project.scrub_config, settings.GLITCHTIP_PII_SCRUB_DEFAULT
    )
    primary_id = UUID7Helper.from_datetime()
    interchange_event = IngestTaskMessage(
        project_id=project_id,
        organization_id=project.organization_id,
        payload=scrubber.scrub_event(item.dict() | {"type": issue_type}),
        received=timezone.now(),
        update_first_event=update_first_event,
        uuid=primary_id.hex,
    )
    if await cache.aadd("uuid" + item.event_id.hex, True):
        await ingest_event.aenqueue(serialize_for_vtasks(asdict(interchange_event)))

    return JsonResponse({"id": item.event_id.hex})

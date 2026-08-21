import asyncio
import uuid
from datetime import datetime, timedelta

from django.db.models import OuterRef, Subquery
from django.http import Http404, HttpResponse
from ninja.pagination import paginate

from glitchtip.api.authentication import AuthHttpRequest
from glitchtip.api.permissions import (
    has_permission,
    scoped_org_id,
)
from glitchtip.partition_manager import UUID7Helper

from ..models import Issue, IssueEvent, UserReport
from ..schema import IssueEventDetailSchema, IssueEventJsonSchema, IssueEventSchema
from ..services import is_uuid7
from . import router


def get_queryset(
    request: AuthHttpRequest,
    issue_id: int | None = None,
    project_slug: str | None = None,
):
    org_id = scoped_org_id(request)
    if org_id is None:
        # Both decorators refuse a non-member, so no resolved org means the
        # issue does not exist. Return nothing rather than falling back to a
        # membership filter, which would decide visibility in the view.
        return IssueEvent.objects.none()
    # Filtering on the resolved org id drops the join to organization *and* the
    # M2M join to the membership table.
    qs = IssueEvent.objects.filter(issue__project__organization_id=org_id)
    if issue_id:
        qs = qs.filter(issue_id=issue_id)
    if project_slug:
        qs = qs.filter(issue__project__slug=project_slug)
    return qs.select_related("issue")


async def get_user_report(event_id: uuid.UUID) -> UserReport | None:
    return await UserReport.objects.filter(event_id=event_id).afirst()


async def _resolve_issue(request: AuthHttpRequest, issue_id: int) -> Issue:
    """Resolve an issue in the decorator-resolved organization, or 404.

    Scoping by the resolved organization id is what makes the
    organization-scoped routes 404 a wrong-org request, and it prunes the
    IssueEvent hash sub-partitions downstream without joining back to
    organization.
    """
    org_id = scoped_org_id(request)
    if org_id is None:
        # No resolved org means the issue does not exist -- a non-member is
        # already refused by the decorator.
        raise Http404()
    issue = await (
        Issue.objects.filter(id=issue_id, project__organization_id=org_id)
        .select_related("project__organization", "index")
        .afirst()
    )
    if not issue:
        raise Http404()
    return issue


def _get_issue_event_queryset(
    request: AuthHttpRequest, issue_id: int, organization_id: int
):
    """Hot-table queryset for one issue, annotated for prev/next navigation.

    ``organization_id`` is filtered in before annotating so the constant lands on
    the prev/next subqueries too - they scan the same partitioned hot table and
    would otherwise hit every hash sub-partition.
    """
    qs = get_queryset(request, issue_id).filter(organization_id=organization_id)
    # Use id (UUIDv7) for prev/next navigation - enables partition pruning
    return qs.annotate(
        previous=Subquery(
            qs.filter(id__lt=OuterRef("id")).order_by("-id").values("id")[:1]
        ),
        next=Subquery(qs.filter(id__gt=OuterRef("id")).order_by("id").values("id")[:1]),
    )


async def _get_latest_event_for_issue(
    request: AuthHttpRequest,
    issue: Issue,
    issue_id: int,
):
    """Return the latest IssueEvent for an already-resolved issue.

    Shared by the bare and organization-scoped ``.../events/latest/`` routes so the
    hash-partition pruning, the ``previous`` subquery, and the cold-storage fallback
    live in one place. The caller is responsible for resolving ``issue``, which
    already pins the organization - so the hot queryset is scoped by
    ``organization_id`` alone, never by slug.
    """
    # Filter by organization_id to enable hash sub-partition pruning
    qs = (
        get_queryset(request, issue_id)
        .filter(organization_id=issue.project.organization_id)
        .order_by("-id")
    )
    qs = qs.annotate(
        previous=Subquery(
            qs.filter(id__lt=OuterRef("id")).order_by("-id").values("id")[:1]
        ),
    )
    event = await qs.afirst()
    if event:
        event.next = None  # We know the next after "latest" must be None
        event.user_report = await get_user_report(event.id)
        return event

    # Fall back to cold storage
    from ..cold_storage import is_duckdb_available

    if not is_duckdb_available():
        raise Http404()

    # Narrow date range using issue.last_seen to avoid scanning all cold
    # storage files. Buffer by 1 day to account for clock skew.
    cold_end = issue.last_seen + timedelta(days=1)
    cold_start = issue.last_seen - timedelta(days=1)
    cold_event = await asyncio.to_thread(
        _get_cold_events_for_issue,
        issue_id=issue_id,
        organization_id=issue.project.organization_id,
        start_dt=cold_start,
        end_dt=cold_end,
        limit=1,
    )
    if not cold_event:
        raise Http404()

    event = cold_event[0]
    event.issue = issue
    event.previous = None
    event.next = None
    event.user_report = await get_user_report(event.id)
    return event


def _get_event_from_cold(event_id: uuid.UUID, organization_id: int):
    """Try to find an event in cold storage by its UUIDv7 id."""
    from ..cold_storage import get_event_from_cold, is_duckdb_available

    if not is_duckdb_available():
        return None

    try:
        event_time = UUID7Helper.extract_datetime(event_id)
    except ValueError:
        return None
    return get_event_from_cold(organization_id, event_id, event_time)


def _get_cold_events_for_issue(
    issue_id: int,
    organization_id: int,
    start_dt: datetime,
    end_dt: datetime,
    limit: int = 100,
):
    """Query cold storage for events belonging to an issue."""
    from ..cold_storage import is_duckdb_available, query_cold_events

    if not is_duckdb_available():
        return []

    return query_cold_events(
        organization_id=organization_id,
        start_dt=start_dt,
        end_dt=end_dt,
        issue_id=issue_id,
        limit=limit,
    )


async def _get_issue_event(request: AuthHttpRequest, issue: Issue, event_id: uuid.UUID):
    """Return one event for an already-resolved issue: hot table, then cold storage.

    Shared by the bare and organization-scoped ``.../events/{event_id}/`` routes.
    The caller resolves ``issue`` and so pins the organization; the slug never
    reaches this far.
    """
    org_id = issue.project.organization_id
    # organization_id is already filtered in - it prunes the hash sub-partitions for
    # the event lookup and for the prev/next subqueries alike.
    qs = _get_issue_event_queryset(request, issue.id, org_id)

    # A UUIDv7 event_id is our own primary key; anything else is a client-provided
    # sentry SDK event_id (typically UUIDv4).
    if is_uuid7(event_id):
        event = await qs.filter(id=event_id).afirst()
    else:
        event = await qs.filter(event_id=event_id).afirst()

    if event:
        event.user_report = await get_user_report(event.id)
        return event

    # Fall back to cold storage
    cold_event = await asyncio.to_thread(_get_event_from_cold, event_id, org_id)
    if not cold_event:
        raise Http404()

    cold_event.issue = issue
    cold_event.previous = None
    cold_event.next = None
    cold_event.user_report = await get_user_report(cold_event.id)
    return cold_event

@router.get(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/events/",
    response=list[IssueEventSchema],
)
@paginate
@has_permission(["event:read", "event:write", "event:admin"])
async def list_organization_issue_event(
    request: AuthHttpRequest,
    response: HttpResponse,
    issue_id: int,
    organization_slug: str,
):
    # Order by -id (UUIDv7) for partition pruning; equivalent to -received ordering.
    # The permission decorator already established membership, so scope the hot
    # table by organization_id alone - it prunes the hash sub-partitions without
    # joining issue -> project -> organization.
    return (
        get_queryset(request, issue_id=issue_id)
        .filter(organization_id=scoped_org_id(request))
        .order_by("-id")
    )

@router.get(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/events/latest/",
    response=IssueEventDetailSchema,
    by_alias=True,
)
@has_permission(["event:read", "event:write", "event:admin"])
async def get_organization_latest_issue_event(
    request: AuthHttpRequest, organization_slug: str, issue_id: int
):
    # Resolve issue first to get organization_id for hash partition pruning
    issue = await _resolve_issue(request, issue_id)
    return await _get_latest_event_for_issue(request, issue, issue_id)

@router.get(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/events/{event_id}/",
    response=IssueEventDetailSchema,
    by_alias=True,
)
@has_permission(["event:read", "event:write", "event:admin"])
async def get_organization_issue_event(
    request: AuthHttpRequest, organization_slug: str, issue_id: int, event_id: uuid.UUID
):
    issue = await _resolve_issue(request, issue_id)
    return await _get_issue_event(request, issue, event_id)


@router.get(
    "/projects/{slug:organization_slug}/{slug:project_slug}/events/",
    response=list[IssueEventSchema],
    by_alias=True,
)
@paginate
@has_permission(["event:read", "event:write", "event:admin"])
async def list_project_issue_event(
    request: AuthHttpRequest,
    response: HttpResponse,
    organization_slug: str,
    project_slug: str,
):
    # Order by -id (UUIDv7) for partition pruning; equivalent to -received ordering
    return get_queryset(request, project_slug=project_slug).order_by("-id")


@router.get(
    "/projects/{slug:organization_slug}/{slug:project_slug}/events/{event_id}/",
    response=IssueEventDetailSchema,
    by_alias=True,
)
@has_permission(["event:read", "event:write", "event:admin"])
async def get_project_issue_event(
    request: AuthHttpRequest,
    organization_slug: str,
    project_slug: str,
    event_id: uuid.UUID,
):
    qs = get_queryset(request, project_slug=project_slug)
    # Use id (UUIDv7) for prev/next navigation - enables partition pruning
    qs = qs.annotate(
        previous=Subquery(
            qs.filter(id__lt=OuterRef("id")).order_by("-id").values("id")[:1]
        ),
        next=Subquery(qs.filter(id__gt=OuterRef("id")).order_by("id").values("id")[:1]),
    )

    if is_uuid7(event_id):
        event = await qs.filter(id=event_id).afirst()
    else:
        # Client-provided sentry SDK event_id (typically UUIDv4).
        # Include organization_id to prune hash sub-partitions.
        event = await qs.filter(
            event_id=event_id, organization_id=scoped_org_id(request)
        ).afirst()

    if event:
        event.user_report = await get_user_report(event.id)
        return event

    # Fall back to cold storage
    cold_event = await asyncio.to_thread(
        _get_event_from_cold, event_id, scoped_org_id(request)
    )
    if not cold_event:
        raise Http404()

    # Attach issue for schema resolution
    issue = (
        await Issue.objects.filter(id=cold_event.issue_id)
        .select_related("project")
        .afirst()
    )
    cold_event.issue = issue
    cold_event.previous = None
    cold_event.next = None
    cold_event.user_report = await get_user_report(cold_event.id)
    return cold_event


@router.get(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/events/{event_id}/json/",
    response=IssueEventJsonSchema,
    by_alias=True,
    exclude_none=True,
)
@has_permission(["event:read", "event:write", "event:admin"])
async def get_event_json(
    request: AuthHttpRequest, organization_slug: str, issue_id: int, event_id: uuid.UUID
):
    qs = get_queryset(request, issue_id=issue_id)

    if is_uuid7(event_id):
        obj = await qs.filter(id=event_id).afirst()
    else:
        obj = await qs.filter(
            event_id=event_id, organization_id=scoped_org_id(request)
        ).afirst()

    if obj:
        return obj

    # Fall back to cold storage
    issue = (
        await Issue.objects.filter(
            id=issue_id, project__organization_id=scoped_org_id(request)
        )
        .select_related("project__organization", "index")
        .afirst()
    )
    if not issue:
        raise Http404()

    cold_event = await asyncio.to_thread(
        _get_event_from_cold, event_id, issue.project.organization_id
    )
    if not cold_event:
        raise Http404()

    cold_event.issue = issue
    return cold_event

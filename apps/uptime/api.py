from collections import defaultdict
from datetime import datetime, timedelta
from uuid import UUID

from asgiref.sync import sync_to_async
from django.conf import settings
from django.db import connection
from django.db.models import Prefetch
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import aget_object_or_404
from django.utils import timezone
from ninja import Router, Status
from ninja.pagination import paginate

from apps.organizations_ext.models import Organization
from apps.projects.models import Project
from glitchtip.api.authentication import AuthHttpRequest
from glitchtip.api.pagination import AsyncLinkHeaderPagination
from glitchtip.partition_manager import UUID7Helper

from .models import Monitor, MonitorCheck, StatusPage
from .schema import (
    MonitorCheckResponseTimeSchema,
    MonitorCheckSchema,
    MonitorDetailSchema,
    MonitorIn,
    MonitorSchema,
    StatusPageIn,
    StatusPageSchema,
)
from .tasks import send_monitor_notification, update_uptime_statistics

router = Router()

# ── Check-fetch partition bounding ──────────────────────────────────
# ``uptime_monitorcheck`` is partitioned RANGE (id) — a UUIDv7, so effectively
# by time — and sub-partitioned HASH (organization_id). Filtering only on
# monitor_id/organization_id prunes the hash dimension but leaves the range
# dimension entirely unpruned, so Postgres opens an index scan on *every* daily
# partition (~97 at the default 90-day retention) for every monitor on the page
# — thousands of index descents to return 60 rows each. Adding a lower bound on
# ``id`` prunes the range dimension too.

# Coarse windows a bounded query may use. Each monitor is assigned the smallest
# window expected to hold ``limit`` checks, so a page issues one query per
# distinct window (usually one) instead of one per monitor.
CHECK_WINDOW_BUCKETS_DAYS = (1, 7, 30)

# Multiplier on the ideal span of ``limit`` checks. Absorbs missed checks and
# short outages so the bounded query alone satisfies the common case; genuine
# shortfalls fall through to an unbounded second pass.
CHECK_WINDOW_SLACK = 2

# Upper bound on how many monitors one ``/status-pages/`` response hydrates with
# checks. Without it the endpoint fetches and serializes checks for every monitor
# of every status page on the page — measured at 2,000 monitors and 120,000
# MonitorCheck objects in a single request, the bulk of the cost being Python
# object construction rather than SQL. Monitors past the cap serialize with an
# empty ``checks`` list.
STATUS_PAGE_CHECK_MONITOR_LIMIT = 50


class MonitorPagination(AsyncLinkHeaderPagination):
    """Custom pagination that efficiently fetches checks using LATERAL JOIN."""

    async def apaginate_queryset(
        self, queryset, pagination, request, response, **params
    ):
        page = await super().apaginate_queryset(
            queryset, pagination, request, response, **params
        )
        # Fetch checks for just the paginated monitors using efficient LATERAL JOIN
        await attach_checks_to_monitors(page)
        return page


class StatusPagePagination(AsyncLinkHeaderPagination):
    """Attach checks to the monitors nested within each paginated status page.

    MonitorSchema reads each monitor's checks (a reverse relation); without
    this the async serializer would trigger a synchronous ORM query per
    monitor and raise SynchronousOnlyOperation.
    """

    async def apaginate_queryset(
        self, queryset, pagination, request, response, **params
    ):
        page = await super().apaginate_queryset(
            queryset, pagination, request, response, **params
        )
        monitors = [
            monitor for status_page in page for monitor in status_page.monitors.all()
        ]
        # Cap by distinct monitor id rather than by instance: a monitor shared
        # across status pages yields one instance per page, and it must not be
        # hydrated on one page while blank on another. Sorted because neither
        # Monitor.Meta nor the prefetch queryset defines an ordering, so slicing
        # the database's own order would hydrate an arbitrary subset that varies
        # between otherwise identical requests.
        hydrate_ids = set(
            sorted({monitor.id for monitor in monitors})[
                :STATUS_PAGE_CHECK_MONITOR_LIMIT
            ]
        )
        await attach_checks_to_monitors(
            [monitor for monitor in monitors if monitor.id in hydrate_ids]
        )
        # Monitors past the cap still need an empty prefetch cache: MonitorSchema
        # reads ``checks`` as a reverse relation, which would otherwise fall back
        # to a synchronous ORM query mid-serialization and raise
        # SynchronousOnlyOperation.
        for monitor in monitors:
            if monitor.id not in hydrate_ids:
                monitor._prefetched_objects_cache = {"checks": []}
        return page


def get_monitor_queryset(user_id: int, organization_slug: str):
    """Get monitors with annotations but WITHOUT checks prefetch."""
    return (
        Monitor.objects.with_check_annotations()
        .filter(organization__users=user_id, organization__slug=organization_slug)
        .select_related("project", "organization")
    )


async def fetch_checks_lateral(
    monitor_ids: list[int],
    organization_ids: list[int],
    limit: int = 60,
    min_id: UUID | None = None,
) -> dict[int, list[MonitorCheck]]:
    """
    Efficiently fetch top N checks per monitor using LATERAL JOIN.

    This is much faster than window functions because:
    - Uses the (monitor_id, start_check DESC) index efficiently
    - Stops scanning after `limit` rows per monitor (early termination)
    - No need to process all historical checks
    - Filters by organization_id for partition pruning

    ``min_id`` bounds the RANGE partition key from below, pruning the daily
    partitions older than the bound. Callers should prefer
    ``attach_checks_to_monitors``, which derives a safe bound per monitor.
    Passing ``None`` scans every partition.

    Returns a dict mapping monitor_id -> list of MonitorCheck instances.
    """
    if not monitor_ids:
        return {}

    # Interpolated as a literal rather than bound as a query parameter so that
    # pruning is guaranteed to happen at plan time. Only a plan-time-pruned
    # query avoids the planner carrying all ~388 leaf partitions, which was
    # measured at ~45 ms of planning on its own — more than the execution it
    # was planning for.
    #
    # A bind parameter usually gets there too: Postgres builds a custom plan
    # per execution and prunes just as well (measured identical, and it keeps
    # choosing the custom plan here because the unpruned generic alternative
    # costs so much more). But that is a cost-based heuristic, not a promise —
    # under a generic plan the bound degrades to execution-time pruning and the
    # planning cost comes back in full. A literal does not depend on the
    # planner making that call correctly.
    #
    # Safe to interpolate — the round-trip through UUID() guarantees a bare
    # UUID, and the value is always generated by UUID7Helper, never user input.
    partition_bound = ""
    if min_id is not None:
        partition_bound = f"AND id >= '{UUID(str(min_id))}'::uuid"

    sql = f"""
        SELECT c.id, c.organization_id, c.monitor_id, c.start_check,
               c.response_time, c.reason, c.is_up, c.is_change, c.data
        FROM unnest(%(monitor_ids)s::int[], %(organization_ids)s::int[]) AS m(id, org_id)
        CROSS JOIN LATERAL (
            SELECT id, organization_id, monitor_id, start_check,
                   response_time, reason, is_up, is_change, data
            FROM uptime_monitorcheck
            WHERE monitor_id = m.id AND organization_id = m.org_id
                  {partition_bound}
            ORDER BY start_check DESC
            LIMIT %(limit)s
        ) c
        ORDER BY c.monitor_id, c.start_check DESC
    """

    def execute_query():
        with connection.cursor() as cursor:
            cursor.execute(
                sql,
                {
                    "monitor_ids": monitor_ids,
                    "organization_ids": organization_ids,
                    "limit": limit,
                },
            )
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    rows = await sync_to_async(execute_query)()

    checks_by_monitor: dict[int, list[MonitorCheck]] = defaultdict(list)
    for row in rows:
        check = MonitorCheck(
            id=row["id"],
            organization_id=row["organization_id"],
            monitor_id=row["monitor_id"],
            start_check=row["start_check"],
            response_time=row["response_time"],
            reason=row["reason"],
            is_up=row["is_up"],
            is_change=row["is_change"],
            data=row["data"],
        )
        checks_by_monitor[row["monitor_id"]].append(check)

    return dict(checks_by_monitor)


def _check_window(
    monitor: Monitor, limit: int, now: datetime, retention: timedelta
) -> timedelta | None:
    """Smallest bucketed window expected to contain ``limit`` checks.

    Returns ``None`` when no bucket is narrower than retention, i.e. the query
    would span every partition regardless and the bound buys nothing.
    """
    # Span that ``limit`` checks occupy at this monitor's configured interval,
    # widened to absorb gaps.
    needed = timedelta(seconds=monitor.interval * limit * CHECK_WINDOW_SLACK)
    # A monitor cannot have checks predating its own creation, so a young
    # monitor only needs a window back to when it was created. This is what
    # keeps newly-added monitors — which are always short of ``limit`` checks —
    # off the all-partitions path.
    span = min(needed, now - monitor.created)
    for days in CHECK_WINDOW_BUCKETS_DAYS:
        window = timedelta(days=days)
        if window >= span and window < retention:
            return window
    return None


async def attach_checks_to_monitors(
    monitors: list[Monitor], limit: int = 60
) -> list[Monitor]:
    """Fetch and attach checks to a list of monitors using LATERAL JOIN.

    Monitors are grouped by the partition-key window they need so each group is
    fetched with a single plan-time-pruned query. Instances must have
    ``interval`` and ``created`` loaded (no ``.only()``/``.defer()``), since the
    window is derived from them.

    Bounding ``id`` while ordering by ``start_check`` is safe because writers
    mint the UUIDv7 ``id`` no earlier than the ``start_check`` they record:
    ``save_monitor_checks`` passes the batch-start time while ids are minted
    afterwards, and ``heartbeat_check`` captures ``start_check`` before the
    insert. So a row inside the window by ``start_check`` is also inside it by
    ``id``, and the bound cannot hide it. The one wrinkle is that UUIDv7 floors
    to whole milliseconds, so the guarantee is exact only to within 1 ms —
    irrelevant against a window of a day or more, and the short-result retry
    below would catch it regardless. New write paths should preserve this
    ordering; a writer that backdates ``start_check`` is fine (its rows are
    merely returned by a wider bound than needed), one that backdates ``id`` is
    not.
    """
    if not monitors:
        return monitors
    # Fetch once per distinct monitor: the same monitor can appear multiple
    # times (e.g. shared across status pages), and duplicate ids in the
    # unnest() would run the LATERAL subquery once per copy and double the
    # returned checks. Attach the result to every instance below.
    distinct_monitors: dict[int, Monitor] = {}
    for monitor in monitors:
        distinct_monitors.setdefault(monitor.id, monitor)

    now = timezone.now()
    retention = timedelta(days=settings.GLITCHTIP_UPTIME_RETENTION_DAYS)
    by_window: dict[timedelta | None, list[Monitor]] = defaultdict(list)
    for monitor in distinct_monitors.values():
        by_window[_check_window(monitor, limit, now, retention)].append(monitor)

    checks_by_monitor: dict[int, list[MonitorCheck]] = {}
    unbounded_retry: list[Monitor] = []
    for window, group in by_window.items():
        fetched = await fetch_checks_lateral(
            [m.id for m in group],
            [m.organization_id for m in group],
            limit,
            min_id=None if window is None else UUID7Helper.from_datetime(now - window),
        )
        checks_by_monitor.update(fetched)
        if window is None:
            continue
        # A short result is only conclusive when the window covered the whole of
        # the monitor's existence. Otherwise the interval-derived estimate was
        # too optimistic — a paused monitor, or a long gap in checks — and older
        # rows may exist outside the window, so re-fetch those monitors
        # unbounded. Rare in practice, and exactly equivalent to the old
        # behaviour when it happens.
        for monitor in group:
            if (
                len(fetched.get(monitor.id, ())) < limit
                and window < now - monitor.created
            ):
                unbounded_retry.append(monitor)

    if unbounded_retry:
        checks_by_monitor.update(
            await fetch_checks_lateral(
                [m.id for m in unbounded_retry],
                [m.organization_id for m in unbounded_retry],
                limit,
            )
        )

    for monitor in monitors:
        # Use Django's prefetch cache so serializers see the checks
        monitor._prefetched_objects_cache = {
            "checks": checks_by_monitor.get(monitor.id, [])
        }
    return monitors


@router.post(
    "organizations/{slug:organization_slug}/heartbeat_check/{uuid:endpoint_id}/",
    response=MonitorCheckSchema,
    auth=None,
)
async def heartbeat_check(
    request: HttpRequest, organization_slug: str, endpoint_id: UUID
):
    """
    Heartbeat monitors allow an external service to contact this endpoint
    when the service is up.
    """
    monitor = await aget_object_or_404(
        Monitor.objects.with_check_annotations().select_related("organization"),
        organization__slug=organization_slug,
        endpoint_id=endpoint_id,
    )
    is_change = monitor.latest_is_up is not True or monitor.last_change is None
    monitor_check = await MonitorCheck.objects.acreate(
        monitor=monitor,
        organization=monitor.organization,
        is_up=True,
        reason=None,
        is_change=is_change,
        # Captured before the insert so it is not read from the field default,
        # which Django evaluates *after* the UUIDv7 ``id`` default. Bounded check
        # fetches assume a row's id timestamp is not earlier than its
        # ``start_check`` (see attach_checks_to_monitors); relying on the default
        # inverted that by up to a millisecond on every heartbeat.
        start_check=timezone.now(),
    )

    # Update hourly statistics
    await update_uptime_statistics(
        {monitor.organization_id: 1}, monitor_check.start_check
    )

    # Update cached fields on monitor. A successful check-in always resets the
    # consecutive-failure counter that drives confirmation_threshold debouncing.
    monitor.cached_is_up = True
    monitor.cached_last_change = (
        monitor_check.start_check if is_change else monitor.cached_last_change
    )
    monitor.cached_consecutive_down = 0
    await monitor.asave(
        update_fields=[
            "cached_is_up",
            "cached_last_change",
            "cached_consecutive_down",
        ]
    )

    if monitor.latest_is_up is False:
        last_change = monitor.last_change
        if last_change:
            last_change = last_change.isoformat()
        monitor_check_pk = [str(monitor_check.id), monitor.organization.id]
        await send_monitor_notification.aenqueue(
            monitor.id, monitor_check_pk, False, last_change
        )

    return monitor_check


@router.get(
    "organizations/{slug:organization_slug}/monitors/",
    response=list[MonitorSchema],
    by_alias=True,
)
@paginate(MonitorPagination)
async def list_monitors(
    request: AuthHttpRequest, response: HttpResponse, organization_slug: str
):
    return get_monitor_queryset(request.auth.user_id, organization_slug)


@router.get(
    "organizations/{slug:organization_slug}/monitors/{int:monitor_id}/",
    response=MonitorDetailSchema,
    by_alias=True,
)
async def get_monitor(
    request: AuthHttpRequest, organization_slug: str, monitor_id: int
):
    monitor = await aget_object_or_404(
        get_monitor_queryset(request.auth.user_id, organization_slug),
        id=monitor_id,
    )
    await attach_checks_to_monitors([monitor])
    return monitor


@router.post(
    "organizations/{slug:organization_slug}/monitors/",
    response={201: MonitorSchema},
    by_alias=True,
)
async def create_monitor(
    request: AuthHttpRequest, organization_slug: str, payload: MonitorIn
):
    user_id = request.auth.user_id
    organization = await aget_object_or_404(
        Organization, slug=organization_slug, users=user_id
    )
    data = payload.dict(exclude_defaults=True)
    if project_id := data.pop("project", None):
        data["project"] = await organization.projects.filter(id=project_id).afirst()
    monitor = await Monitor.objects.acreate(organization=organization, **data)
    monitor = await get_monitor_queryset(user_id, organization_slug).aget(id=monitor.id)
    await attach_checks_to_monitors([monitor])
    return Status(201, monitor)


@router.put(
    "organizations/{slug:organization_slug}/monitors/{int:monitor_id}/",
    response=MonitorSchema,
    by_alias=True,
)
async def update_monitor(
    request: AuthHttpRequest,
    organization_slug: str,
    monitor_id: int,
    payload: MonitorIn,
):
    monitor = await aget_object_or_404(
        get_monitor_queryset(request.auth.user_id, organization_slug),
        id=monitor_id,
    )
    data = payload.dict()
    if project_id := data["project"]:
        result = await Project.objects.filter(
            organization__slug=organization_slug,
            organization__users=request.auth.user_id,
            id=project_id,
        ).afirst()
        data["project"] = result
    for attr, value in data.items():
        setattr(monitor, attr, value)
    await monitor.asave()
    await attach_checks_to_monitors([monitor])
    return monitor


@router.get(
    "organizations/{slug:organization_slug}/monitors/{int:monitor_id}/checks/",
    response=list[MonitorCheckResponseTimeSchema],
    by_alias=True,
)
@paginate
async def list_monitor_checks(
    request: AuthHttpRequest,
    response: HttpResponse,
    organization_slug: str,
    monitor_id: int,
    is_change: bool | None = None,
):
    """
    List checks performed for a monitor
    Set is_change query param to True to show only changes,
    This is useful to see only when a service went up and down.
    """
    checks = (
        MonitorCheck.objects.filter(
            monitor_id=monitor_id,
            monitor__organization__slug=organization_slug,
            monitor__organization__users=request.auth.user_id,
        )
        .only("is_up", "start_check", "reason", "response_time")
        .order_by("-start_check")
    )
    if is_change is not None:
        checks = checks.filter(is_change=is_change)
    return checks


@router.get(
    "/organizations/{slug:organization_slug}/status-pages/",
    response=list[StatusPageSchema],
    by_alias=True,
)
@paginate(StatusPagePagination)
async def list_status_pages(
    request: AuthHttpRequest, response: HttpResponse, organization_slug: str
):
    """List status pages, used for showing the current status of an uptime monitor"""
    return StatusPage.objects.filter(
        organization__users=request.auth.user_id
    ).prefetch_related(
        # MonitorSchema reads the check annotations (is_up/last_change) and the
        # organization (heartbeat URL) and project (project_name); load them
        # eagerly so async serialization does not fall back to sync queries.
        Prefetch(
            "monitors",
            queryset=Monitor.objects.with_check_annotations().select_related(
                "organization", "project"
            ),
        )
    )


@router.post(
    "/organizations/{slug:organization_slug}/status-pages/",
    response={201: StatusPageSchema},
    by_alias=True,
)
async def create_status_page(
    request: AuthHttpRequest, organization_slug: str, payload: StatusPageIn
):
    organization = await aget_object_or_404(
        Organization, slug=organization_slug, users=request.auth.user_id
    )
    data = payload.dict()
    status_page = await StatusPage.objects.acreate(organization=organization, **data)
    return Status(
        201,
        await StatusPage.objects.prefetch_related("monitors").aget(id=status_page.id),
    )


@router.delete(
    "organizations/{slug:organization_slug}/monitors/{int:monitor_id}/",
    response={204: None},
)
async def delete_monitor(
    request: AuthHttpRequest, organization_slug: str, monitor_id: int
):
    result, _ = (
        await get_monitor_queryset(request.auth.user_id, organization_slug)
        .filter(id=monitor_id)
        .adelete()
    )
    if result:
        return Status(204, None)
    raise Http404

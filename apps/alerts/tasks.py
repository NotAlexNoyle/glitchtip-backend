from datetime import timedelta

from django.conf import settings
from django.core.cache import caches
from django.db.models import Count, DurationField, F, Func, Min, Q, UUIDField, Value
from django.db.models.functions import Cast
from django.tasks import task
from django.utils import timezone

from apps.issue_events.constants import EventStatus
from apps.issue_events.models import Issue
from glitchtip.partition_manager import UUID7Helper

from .constants import ISSUE_IDS_KEY
from .models import Notification, ProjectAlert

# Lua script for atomic smembers + del
LUA_SCRIPT = """
local members = redis.call('SMEMBERS', KEYS[1])
redis.call('DEL', KEYS[1])
return members
"""

# The ids drained from the set expire after an hour (see process_event.py)
MAX_ALERT_LAG = timedelta(hours=1)


class UUID7Floor(Func):
    """The lowest UUIDv7 for a timestamp, to compare against event ids.

    Built by hand because uuid7 functions need Postgres 18.
    """

    template = (
        "(lpad(to_hex(floor(extract(epoch FROM %(expressions)s) * 1000)::bigint), "
        "12, '0') || '00000000000000000000')::uuid"
    )
    output_field = UUIDField()


async def process_alert(project_alert_id: int, issue_ids: list[int]):
    notification = await Notification.objects.acreate(project_alert_id=project_alert_id)
    await notification.issues.aset(issue_ids)
    await send_notification.aenqueue(notification.pk)


@task
async def process_event_alerts():
    """Inspect alerts and determine if new notifications need sent"""
    now = timezone.now()

    issue_ids: list[int] | None = None
    # Support not having valkey, in theory
    if settings.CACHE_IS_VALKEY:
        # Note all recent issue_ids at ingest time. Then we can filter by them here.
        driver = caches["default"].get_raw_client()
        issue_ids = [int(x) for x in await driver.eval(LUA_SCRIPT, [ISSUE_IDS_KEY], [])]

    project_alerts = ProjectAlert.objects.filter(
        quantity__isnull=False, timespan_minutes__isnull=False
    ).select_related("project")
    if issue_ids == []:
        return  # There are no new issues, no work to do

    if issue_ids:
        project_alerts = project_alerts.filter(
            project__issues__id__in=issue_ids
        ).distinct()

    async for alert in project_alerts:
        timespan = timedelta(minutes=alert.timespan_minutes)
        organization_id = alert.project.organization_id
        if issue_ids:
            # Issues seen longer ago (a stalled scheduler, events redriven from
            # a dead-letter queue) are too late to alert on, and would pull the
            # scan below back over every partition since.
            seen_after = now - timespan - MAX_ALERT_LAG
        else:
            # Without the set of new issues, every run looks at issues seen
            # within the timespan, plus one run interval so an event seen just
            # before a late run is not skipped.
            seen_after = (
                now - timespan - timedelta(seconds=settings.ALERT_NOTIFICATION_INTERVAL)
            )
        candidates = Issue.objects.filter(
            project_id=alert.project_id,
            index__organization_id=organization_id,
            # Every status, so the (organization, status, last_seen) index
            # can seek on last_seen
            index__status__in=EventStatus.values,
            index__last_seen__gte=seen_after,
        ).exclude(notification__project_alert=alert)
        if issue_ids:
            candidates = candidates.filter(id__in=issue_ids)
        # The window ends at the issue's newest event (last_seen, the server
        # receive time), not at the time of this run, so a late run judges the
        # same events as a punctual one would have, and only the ingest clock
        # is compared. Events that arrive before the run move the window on.
        oldest = (await candidates.aaggregate(oldest=Min("index__last_seen")))["oldest"]
        if oldest is None:
            continue
        event_filter = Q(
            # Constant bound, so Postgres prunes partitions at plan time
            issueevent__id__gte=UUID7Helper._uuid7_for_timestamp(
                oldest - timespan, min_random=True
            ),
            issueevent__organization_id=organization_id,
        ) & Q(
            issueevent__id__gte=UUID7Floor(
                F("index__last_seen") - Cast(Value(timespan), DurationField())
            )
        )
        if alert.environments:
            event_filter &= Q(issueevent__tags__environment__in=alert.environments)
        # One filter() call, so the conditions share one join to the events and
        # Count() counts only the events that match all of them.
        issues = (
            candidates.filter(event_filter)
            .annotate(num_events=Count("issueevent"))
            .filter(num_events__gte=alert.quantity)
            .values_list("id", flat=True)
        )
        issue_id_list = [i async for i in issues]
        if issue_id_list:
            notification = await alert.notification_set.acreate()
            await notification.issues.aset(issue_id_list)
            await send_notification.aenqueue(notification.pk)


@task
async def send_notification(notification_id: int):
    notification = await Notification.objects.select_related("project_alert").aget(
        pk=notification_id
    )
    await notification.send_notifications()

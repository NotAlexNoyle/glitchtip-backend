from datetime import timedelta

from asgiref.sync import sync_to_async
from django.db import connection
from django.db.models import QuerySet
from django.http import Http404
from ninja import Query, Router

from apps.projects.models import Project
from glitchtip.api.permissions import OrgScopedHttpRequest, org_scoped

from .schema import StatsV2Schema

router = Router()

# Sum per bucket first, then join to the series so empty buckets stay
EVENT_TIME_SERIES_SQL = """
SELECT gs.ts, stat.total
FROM generate_series(%(start)s, %(end)s, %(interval)s::interval) gs (ts)
LEFT JOIN (
    SELECT date_bin(%(interval)s::interval, date, %(start)s) AS ts, sum(count) AS total
    FROM projects_issueeventprojecthourlystatistic
    WHERE organization_id = %(organization_id)s
    AND project_id = ANY(%(project_ids)s)
    AND date >= %(start)s AND date < %(end)s::timestamptz + %(interval)s::interval
    GROUP BY 1
) stat USING (ts)
ORDER BY gs.ts;
"""
TRANSACTION_TIME_SERIES_SQL = """
SELECT gs.ts, stat.total
FROM generate_series(%(start)s, %(end)s, %(interval)s::interval) gs (ts)
LEFT JOIN (
    SELECT date_bin(%(interval)s::interval, date, %(start)s) AS ts, sum(count) AS total
    FROM projects_transactioneventprojecthourlystatistic
    WHERE organization_id = %(organization_id)s
    AND project_id = ANY(%(project_ids)s)
    AND date >= %(start)s AND date < %(end)s::timestamptz + %(interval)s::interval
    GROUP BY 1
) stat USING (ts)
ORDER BY gs.ts;
"""


@sync_to_async
def get_timeseries(category, start, end, interval, organization_id, project_ids):
    params = {
        "start": start,
        "end": end,
        "interval": interval,
        "organization_id": organization_id,
        "project_ids": project_ids,
    }
    sql = EVENT_TIME_SERIES_SQL if category == "error" else TRANSACTION_TIME_SERIES_SQL
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return cursor.fetchall()


@router.get("organizations/{slug:organization_id_or_slug}/stats_v2/")
@org_scoped(["org:read", "org:write", "org:admin"], Project)
async def stats_v2(
    request: OrgScopedHttpRequest,
    qs: QuerySet[Project],
    organization_id_or_slug: str,
    filters: Query[StatsV2Schema],
):
    """
    Reverse engineered stats v2 endpoint. Endpoint in sentry not documented.
    Appears similar to documented sessions endpoint.
    Used by the Sentry Grafana integration.

    Used to return time series statistics.
    Submit query params start, end, and interval (defaults to 1h)
    Limits results to 1000 intervals. For example if using hours, max days would be 41
    """
    start = filters.start.replace(microsecond=0, second=0, minute=0)
    end = (filters.end + timedelta(hours=1)).replace(microsecond=0, second=0, minute=0)
    field = filters.field
    interval = filters.interval
    category = filters.category
    # Get projects that are authorized, filtered by organization, and selected by user
    # Intentionally separate SQL call to simplify raw SQL
    projects = qs
    if filters.project:
        projects = projects.filter(pk__in=filters.project)
    project_ids = [id async for id in projects.values_list("id", flat=True)]
    if not project_ids:
        raise Http404()

    series = await get_timeseries(
        category,
        start,
        end,
        interval,
        organization_id=request.org_scope.org_id,
        project_ids=project_ids,
    )

    return {
        "intervals": [
            row[0].astimezone().replace(microsecond=0).isoformat() for row in series
        ],
        "groups": [
            {
                "series": {field: [row[1] for row in series]},
            }
        ],
    }

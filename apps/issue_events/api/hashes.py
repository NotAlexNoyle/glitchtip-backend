from uuid import UUID

from django.http import HttpResponse
from ninja import Query, Schema, Status
from ninja.pagination import paginate

from apps.issue_events.models import IssueEvent, IssueHash
from apps.issue_events.schema import IssueHashSchema
from glitchtip.api.authentication import AuthHttpRequest
from glitchtip.api.pagination import AsyncLinkHeaderPagination
from glitchtip.api.permissions import has_permission, scoped_org_id

from . import router


class IssueHashPagination(AsyncLinkHeaderPagination):
    async def get_results(self, queryset, cursor, limit):
        result = await super().get_results(queryset, cursor, limit)
        # There is no foreign key connecting a hash to an event.
        # So we must query once per hash
        for issue_hash in result:
            issue_hash.latest_event = (
                await IssueEvent.objects.filter(
                    hashes__contains=[issue_hash.value.hex],
                    issue__project_id=issue_hash.project_id,
                )
                .select_related("issue")
                .order_by("-id")  # UUIDv7 ordering = time ordering
                .afirst()
            )
        return result


@router.get(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/hashes/",
    response=list[IssueHashSchema],
    by_alias=True,
)
@has_permission(["event:read"])
@paginate(IssueHashPagination)
async def list_issue_hashes(
    request: AuthHttpRequest,
    response: HttpResponse,
    organization_slug: str,
    issue_id: int,
):
    return IssueHash.objects.filter(
        issue_id=issue_id, issue__project__organization_id=scoped_org_id(request)
    ).order_by("value")


class IssueHashQuerySchema(Schema):
    id: list[UUID]


@router.delete(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/hashes/",
    response={202: None},
)
@has_permission(["event:admin"])
async def delete_hash(
    request: AuthHttpRequest,
    organization_slug: str,
    issue_id: int,
    query: Query[IssueHashQuerySchema],
):
    await IssueHash.objects.filter(
        value__in=query.id,
        issue_id=issue_id,
        issue__project__organization_id=scoped_org_id(request),
    ).adelete()
    return Status(202, None)

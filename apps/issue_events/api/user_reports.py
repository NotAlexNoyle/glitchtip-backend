from django.http import HttpResponse
from ninja.pagination import paginate

from glitchtip.api.permissions import (
    OrgAuthHttpRequest,
    has_permission,
    scoped_org_id,
)

from ..models import UserReport
from ..schema import UserReportSchema
from . import router


@router.get(
    "/organizations/{slug:organization_slug}/issues/{int:issue_id}/user-reports/",
    response=list[UserReportSchema],
    by_alias=True,
)
@paginate
@has_permission(["event:read", "event:write", "event:admin"])
async def list_organization_user_reports(
    request: OrgAuthHttpRequest,
    response: HttpResponse,
    organization_slug: str,
    issue_id: int,
):
    return UserReport.objects.filter(
        project__organization_id=scoped_org_id(request),
        issue__id=issue_id,
    )

from django.http import HttpResponse

from glitchtip.api.permissions import (
    OrgScopedHttpRequest,
    org_scoped_list,
)

from ..models import UserReport
from ..schema import UserReportSchema
from . import router


@router.get(
    "/organizations/{slug:organization_id_or_slug}/issues/{int:issue_id}/user-reports/",
    response=list[UserReportSchema],
    by_alias=True,
)
@org_scoped_list(["event:read"], UserReport)
async def list_organization_user_reports(
    request: OrgScopedHttpRequest,
    response: HttpResponse,
    organization_id_or_slug: str,
    issue_id: int,
):
    return UserReport.objects.filter(issue_id=issue_id)

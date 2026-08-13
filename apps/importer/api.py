from ninja import Router

from glitchtip.api.authentication import AuthHttpRequest
from glitchtip.api.permissions import has_permission, scoped_org_id

from .importer import GlitchTipImporter
from .schema import ImportIn

router = Router()


@router.post("organizations/{slug:organization_slug}/import/")
@has_permission(["org:admin"])
async def importer(request: AuthHttpRequest, organization_slug: str, payload: ImportIn):
    # Authorization is enforced by @has_permission resolving the caller's scope
    # for organization_slug (org:admin is owner-only), which also resolves the
    # organization id, so there is nothing left to look up here.
    importer = GlitchTipImporter(
        str(payload.url), payload.auth_token, organization_slug
    )
    await importer.check_auth()
    await importer.run(organization_id=scoped_org_id(request))

from django.shortcuts import aget_object_or_404
from ninja import Router

from apps.organizations_ext.models import Organization
from glitchtip.api.authentication import AuthHttpRequest
from glitchtip.api.permissions import has_permission

from .importer import GlitchTipImporter
from .schema import ImportIn

router = Router()


@router.post("organizations/{slug:organization_slug}/import/")
@has_permission(["org:admin"])
async def importer(request: AuthHttpRequest, organization_slug: str, payload: ImportIn):
    # Authorization is enforced by @has_permission resolving the caller's scope
    # for organization_slug (org:admin is owner-only). The membership filter here
    # just fetches the org (and 404s if it somehow isn't the caller's).
    organization = await aget_object_or_404(
        Organization,
        slug=organization_slug,
        users=request.auth.user_id,
    )
    importer = GlitchTipImporter(
        str(payload.url), payload.auth_token, organization_slug
    )
    await importer.check_auth()
    await importer.run(organization_id=organization.id)

from django.db.models import QuerySet
from django.shortcuts import aget_object_or_404
from ninja import Router

from apps.organizations_ext.models import Organization
from apps.organizations_ext.queryset_utils import annotate_actor_role
from glitchtip.api.authentication import AuthHttpRequest
from glitchtip.api.permissions import OrgScopedHttpRequest, org_scoped

from .schema import ImportIn

router = Router()


@router.post("import/")
async def importer(request: AuthHttpRequest, payload: ImportIn):
    """Deprecated: use POST organizations/{organization_id_or_slug}/import/."""
    return await import_organization(
        request, organization_id_or_slug=payload.organization_slug, payload=payload
    )


@router.post("organizations/{slug:organization_id_or_slug}/import/")
@org_scoped(["org:admin"], Organization)
async def import_organization(
    request: OrgScopedHttpRequest,
    qs: QuerySet[Organization],
    organization_id_or_slug: str,
    payload: ImportIn,
):
    """Import from another GlitchTip server. organizationSlug names the remote org."""
    # Imported here so loading the API doesn't import aiohttp; see
    # glitchtip.ssrf_protection.
    from .importer import GlitchTipImporter

    organization = await aget_object_or_404(
        annotate_actor_role(qs, request.auth.user_id, "pk")
    )
    importer = GlitchTipImporter(
        str(payload.url), payload.auth_token, payload.organization_slug
    )
    await importer.check_auth()
    await importer.run(
        organization_id=organization.id, max_role=organization.actor_role
    )

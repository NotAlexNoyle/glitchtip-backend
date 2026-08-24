from django.db import IntegrityError
from django.http import HttpResponse
from ninja import Router, Status
from ninja.errors import HttpError
from ninja.pagination import paginate

from apps.files.models import FileBlob
from apps.files.tasks import assemble_artifacts_task
from glitchtip.api.decorators import optional_slash
from glitchtip.api.permissions import OrgAuthHttpRequest, has_permission, scoped_org_id

from .models import Repository
from .schema import ArtifactBundleAssembleIn, RepositoryIn, RepositorySchema

router = Router()


def get_repositories_queryset(org_id: int):
    return Repository.objects.filter(organization_id=org_id).order_by("-created")


@router.get(
    "organizations/{slug:organization_slug}/repos/",
    response=list[RepositorySchema],
    by_alias=True,
)
@paginate
@has_permission(["org:read", "org:write", "org:admin"])
async def list_repositories(
    request: OrgAuthHttpRequest, response: HttpResponse, organization_slug: str
):
    return get_repositories_queryset(scoped_org_id(request))


@router.post(
    "organizations/{slug:organization_slug}/repos/",
    response={201: RepositorySchema},
    by_alias=True,
)
@has_permission(["org:write", "org:admin"])
async def create_repository(
    request: OrgAuthHttpRequest, organization_slug: str, payload: RepositoryIn
):
    try:
        repo = await Repository.objects.acreate(
            organization_id=scoped_org_id(request),
            name=payload.name,
            url=payload.url,
            provider=payload.provider or {},
        )
    except IntegrityError:
        raise HttpError(409, "A repository with this name already exists.")
    return Status(201, repo)


@optional_slash(
    router, "post", "organizations/{slug:organization_slug}/artifactbundle/assemble/"
)
@has_permission(["project:write", "project:admin", "project:releases"])
async def artifact_bundle_assemble(
    request: OrgAuthHttpRequest,
    organization_slug: str,
    payload: ArtifactBundleAssembleIn,
):
    """Associate files with assembly bundle and optionally release"""
    existing_chunks = [
        checksum
        async for checksum in FileBlob.objects.filter(
            checksum__in=payload.chunks
        ).values_list("checksum", flat=True)
    ]
    missing_chunks = list(set(payload.chunks) - set(existing_chunks))

    if missing_chunks:
        return {"state": "not_found", "missingChunks": missing_chunks}

    await assemble_artifacts_task.aenqueue(
        scoped_org_id(request),
        payload.version,
        payload.checksum,
        payload.chunks,
    )
    return {"state": "created", "missingChunks": []}

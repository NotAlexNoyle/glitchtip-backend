from asgiref.sync import sync_to_async
from django.tasks import task

from apps.organizations_ext.models import Organization

from .assemble import (
    AssembleTask,
    ChunkFileState,
    assemble_artifacts,
    set_assemble_status,
)


@task
async def assemble_artifacts_task(org_id, version, checksum, chunks, **kwargs):
    """
    Creates release files from an uploaded artifact bundle.
    """
    organization = await Organization.objects.aget(pk=org_id)
    try:
        await sync_to_async(assemble_artifacts)(organization, version, checksum, chunks)
    except Exception:
        # Without a final state, an upload tool polling the assemble endpoint
        # would see "assembling" until the status expires.
        await sync_to_async(set_assemble_status)(
            AssembleTask.ARTIFACTS,
            org_id,
            checksum,
            ChunkFileState.ERROR,
            detail="Failed to assemble bundle",
        )
        raise

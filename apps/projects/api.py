from uuid import UUID

from django.http import Http404, HttpResponse
from django.shortcuts import aget_object_or_404
from ninja import Router, Status
from ninja.errors import ValidationError
from ninja.pagination import paginate

from apps.organizations_ext.constants import OrganizationUserRole
from apps.shared.types import MeID
from apps.teams.models import Team
from apps.teams.schema import ProjectTeamSchema
from glitchtip.api.permissions import (
    AuthHttpRequest,
    has_permission,
    scoped_org_id,
)

from .models import Project, ProjectKey, UserProjectAlert
from .schema import (
    ProjectIn,
    ProjectKeyIn,
    ProjectKeySchema,
    ProjectOrganizationSchema,
    ProjectSchema,
    StrKeyIntValue,
)

router = Router()


"""
GET /api/0/projects/
GET /api/0/projects/{organization_slug}/{project_slug}/
DELETE /api/0/projects/{organization_slug}/{project_slug}/
POST /api/0/projects/{organization_slug}/{project_slug}/teams/{team_slug}/ (See teams)
DELETE /api/0/projects/{organization_slug}/{project_slug}/teams/{team_slug}/ (See teams)
GET /api/0/projects/{organization_slug}/{team_slug}/keys/
POST /api/0/projects/{organization_slug}/{team_slug}/keys/
GET /api/0/projects/{organization_slug}/{project_slug}/keys/{key_id}/
DELETE /api/0/projects/{organization_slug}/{project_slug}/keys/{key_id}/
GET /api/0/teams/{organization_slug}/{team_slug}/projects/
POST /api/0/teams/{organization_slug}/{team_slug}/projects/
GET /api/0/organizations/{organization_slug}/projects/
"""


def get_projects_queryset(org_id: int, user_id: int, team_slug: str | None = None):
    """Projects in one organization the caller is already known to belong to.

    Callers are behind ``@has_permission``, so ``org_id`` comes from
    ``scoped_org_id`` and scoping by it is the whole check -- no organization
    join for the slug, no membership M2M join. The is_member annotation stays:
    it is per-project payload, not authorization.

    For the org-less ``GET /projects/`` route, see
    :func:`get_user_projects_queryset`.
    """
    qs = Project.annotate_is_member(
        Project.undeleted_objects.filter(organization_id=org_id), user_id
    )
    if team_slug:
        qs = qs.filter(teams__slug=team_slug)
    return qs


def get_user_projects_queryset(user_id: int):
    """Every project the user can see, across all their organizations.

    For routes with no organization in the path, where there is no resolved
    org to scope by. The membership filter here IS the authorization -- do not
    "finish the port" by removing it.
    """
    return Project.annotate_is_member(
        Project.undeleted_objects.filter(organization__users=user_id), user_id
    )


def get_project_keys_queryset(
    org_id: int, project_slug: str, key_id: UUID | None = None
):
    qs = ProjectKey.objects.filter(
        project__organization_id=org_id,
        project__slug=project_slug,
    )
    if key_id:
        qs = qs.filter(public_key=key_id)
    return qs


@router.get(
    "projects/",
    response=list[ProjectOrganizationSchema],
    by_alias=True
)
@paginate
async def list_projects(request: AuthHttpRequest, response: HttpResponse):
    """List all projects that a user has access to"""
    return (
        get_user_projects_queryset(request.auth.user_id)
        .select_related("organization")
        .order_by("name")
    )


@router.get(
    "projects/{slug:organization_slug}/{slug:project_slug}/",
    response=ProjectOrganizationSchema,
    by_alias=True,
)
@has_permission(["project:read", "project:write", "project:admin"])
async def get_project(
    request: AuthHttpRequest, organization_slug: str, project_slug: str
):
    return await aget_object_or_404(
        get_projects_queryset(
            scoped_org_id(request), request.auth.user_id
        ).select_related("organization"),
        slug=project_slug,
    )


@router.put(
    "projects/{slug:organization_slug}/{slug:project_slug}/",
    response=ProjectOrganizationSchema,
    by_alias=True,
)
@has_permission(["project:write", "project:admin"])
async def update_project(
    request: AuthHttpRequest,
    organization_slug: str,
    project_slug: str,
    payload: ProjectIn,
):
    project = await aget_object_or_404(
        get_projects_queryset(
            scoped_org_id(request), request.auth.user_id
        ).select_related("organization"),
        slug=project_slug,
    )
    for attr, value in payload.dict(exclude_unset=True).items():
        setattr(project, attr, value)
    await project.asave()
    return project


@router.delete(
    "projects/{slug:organization_slug}/{slug:project_slug}/",
    response={204: None},
)
@has_permission(["project:admin"])
async def delete_project(
    request: AuthHttpRequest, organization_slug: str, project_slug: str
):
    project = await aget_object_or_404(
        get_projects_queryset(scoped_org_id(request), request.auth.user_id),
        slug=project_slug,
        organization__organization_users__user_id=request.auth.user_id,
        organization__organization_users__role__gte=OrganizationUserRole.ADMIN,
    )
    await project.adelete()
    return Status(204, None)


@router.get(
    "teams/{slug:organization_slug}/{slug:team_slug}/projects/",
    response=list[ProjectSchema],
    by_alias=True,
)
@paginate
@has_permission(["project:read"])
async def list_team_projects(
    request: AuthHttpRequest,
    response: HttpResponse,
    organization_slug: str,
    team_slug: str,
):
    """List all projects for a given team"""
    return get_projects_queryset(
        scoped_org_id(request), request.auth.user_id, team_slug=team_slug
    ).order_by("name")


@router.post(
    "teams/{slug:organization_slug}/{slug:team_slug}/projects/",
    response={201: ProjectSchema},
    by_alias=True,
)
@has_permission(["project:write", "project:admin"])
async def create_project(
    request: AuthHttpRequest, organization_slug: str, team_slug: str, payload: ProjectIn
):
    """Create a new project given a team and organization"""
    user_id = request.auth.user_id
    # The ADMIN floor is stricter than the project:write scope this route
    # requires, so it stays -- but both conditions now sit on one join, and
    # the organization comes from the decorator rather than the slug.
    team = await aget_object_or_404(
        Team,
        slug=team_slug,
        organization_id=scoped_org_id(request),
        organization__organization_users__user_id=user_id,
        organization__organization_users__role__gte=OrganizationUserRole.ADMIN,
    )
    project = await Project.objects.acreate(
        organization_id=scoped_org_id(request), **payload.dict(exclude_unset=True)
    )
    await project.teams.aadd(team)
    project = await get_projects_queryset(scoped_org_id(request), user_id).aget(
        id=project.id
    )
    return Status(201, project)


@router.get(
    "organizations/{slug:organization_slug}/projects/",
    response=list[ProjectTeamSchema],
    by_alias=True,
)
@paginate
@has_permission(["project:read"])
async def list_organization_projects(
    request: AuthHttpRequest,
    response: HttpResponse,
    organization_slug: str,
    query: str | None = None,
):
    """
    Fetch list of organizations for a project
    Contains team information
    query: Filter on team, ex: ?query=!team:burke-software
    """
    queryset = (
        get_projects_queryset(scoped_org_id(request), request.auth.user_id)
        .prefetch_related("teams")
        .order_by("name")
    )
    # This query param isn't documented in sentry api but exists
    if query:
        query_parts = query.split()
        for part in query_parts:
            query_part = part.split(":", 1)
            if len(query_part) == 2:
                query_name, query_value = query_part
                if query_name == "team":
                    queryset = queryset.filter(teams__slug=query_value)
                if query_name == "!team":
                    queryset = queryset.exclude(teams__slug=query_value)
    return queryset


@router.get(
    "projects/{slug:organization_slug}/{slug:project_slug}/keys/",
    response=list[ProjectKeySchema],
    by_alias=True,
)
@paginate
@has_permission(["project:read", "project:write", "project:admin"])
async def list_project_keys(
    request: AuthHttpRequest,
    response: HttpResponse,
    organization_slug: str,
    project_slug: str,
    status: str | None = None,
):
    """List all DSN keys for a given project"""
    return get_project_keys_queryset(scoped_org_id(request), project_slug)


@router.get(
    "projects/{slug:organization_slug}/{slug:project_slug}/keys/{uuid:key_id}/",
    response=ProjectKeySchema,
    by_alias=True,
)
@has_permission(["project:read", "project:write", "project:admin"])
async def get_project_key(
    request: AuthHttpRequest,
    organization_slug: str,
    project_slug: str,
    key_id: UUID,
):
    return await aget_object_or_404(
        get_project_keys_queryset(scoped_org_id(request), project_slug, key_id=key_id)
    )


@router.put(
    "projects/{slug:organization_slug}/{slug:project_slug}/keys/{uuid:key_id}/",
    response=ProjectKeySchema,
    by_alias=True,
)
@has_permission(["project:write", "project:admin"])
async def update_project_key(
    request: AuthHttpRequest,
    organization_slug: str,
    project_slug: str,
    key_id: UUID,
    payload: ProjectKeyIn,
):
    return await aget_object_or_404(
        get_project_keys_queryset(scoped_org_id(request), project_slug, key_id=key_id)
    )


@router.post(
    "projects/{slug:organization_slug}/{slug:project_slug}/keys/",
    response={201: ProjectKeySchema},
    by_alias=True,
)
@has_permission(["project:write", "project:admin"])
async def create_project_key(
    request: AuthHttpRequest,
    organization_slug: str,
    project_slug: str,
    payload: ProjectKeyIn,
):
    """Create new key for project. Rate limiting not implemented."""
    project = await aget_object_or_404(
        get_projects_queryset(scoped_org_id(request), request.auth.user_id),
        slug=project_slug,
    )
    return Status(
        201,
        await ProjectKey.objects.acreate(
            project=project,
            name=payload.name,
            rate_limit_count=payload.rate_limit.count if payload.rate_limit else None,
            rate_limit_window=payload.rate_limit.window if payload.rate_limit else None,
        ),
    )


@router.delete(
    "projects/{slug:organization_slug}/{slug:project_slug}/keys/{uuid:key_id}/",
    response={204: None},
)
@has_permission(["project:admin"])
async def delete_project_key(
    request: AuthHttpRequest, organization_slug: str, project_slug: str, key_id: UUID
):
    result, _ = (
        await get_project_keys_queryset(
            scoped_org_id(request), project_slug, key_id=key_id
        )
        .filter(
            project__organization__organization_users__user_id=request.auth.user_id,
            project__organization__organization_users__role__gte=OrganizationUserRole.ADMIN,
        )
        .adelete()
    )
    if not result:
        raise Http404
    return Status(204, None)


@router.get("/users/{slug:user_id}/notifications/alerts/", response=StrKeyIntValue)
async def user_notification_alerts(request: AuthHttpRequest, user_id: MeID):
    """
    Returns dictionary of project_id: status. Now project_id status means it's "default"

    To update, submit `{project_id: status}` where status is -1 (default), 0, or 1
    """
    if user_id != request.auth.user_id and user_id != "me":
        raise Http404
    user_id = request.auth.user_id

    data = {}
    async for alert in UserProjectAlert.objects.filter(user_id=user_id):
        data[str(alert.project_id)] = alert.status
    return data


@router.put("/users/{slug:user_id}/notifications/alerts/", response={204: None})
async def update_user_notification_alerts(
    request: AuthHttpRequest, user_id: MeID, payload: StrKeyIntValue
):
    if user_id != request.auth.user_id and user_id != "me":
        raise Http404
    user_id = request.auth.user_id
    items = [x for x in payload.root.items()]
    if len(items) != 1:
        raise ValidationError("Invalid alert format, expected one value")

    project_id, alert_status = items[0]
    if alert_status not in [1, 0, -1]:
        raise ValidationError("Invalid status, must be -1, 0, or 1")

    alert = await UserProjectAlert.objects.filter(
        user_id=user_id, project_id=project_id
    ).afirst()
    if alert_status == -1:
        if alert:
            await alert.adelete()
    else:
        await UserProjectAlert.objects.aupdate_or_create(
            user_id=user_id, project_id=project_id, defaults={"status": alert_status}
        )

    return Status(204, None)

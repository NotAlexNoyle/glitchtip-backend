from functools import wraps

from django.db.models import F, OuterRef, Subquery
from ninja.errors import HttpError

from apps.organizations_ext.constants import ROLES, OrganizationUserRole
from apps.organizations_ext.models import OrganizationUser

from .authentication import Auth, AuthHttpRequest


def get_org_slug(kwargs: dict) -> str | None:
    return kwargs.get("organization_slug")


def scoped_org_id(request: AuthHttpRequest) -> int | None:
    """The organization id the permission decorator already resolved.

    Views can filter on this instead if re-deriving membership on their own.
    Raises ScopeNotResolved if no permission decorator ran, should fail loudly.
    """
    if request.auth._resolved and request.auth._org_id is None:
        # The check ran and found no membership. The route deliberately defers
        # to the view so its own membership-scoped queryset raises 404 (rather
        # than confirming the object exists).
        return None
    return request.auth.org_id


async def resolve_scope_for_issue(auth: Auth, issue_id: int) -> set:
    """One-query scope resolution for the bare ``/issues/{id}/`` routes.

    Walks issue -> project -> organization in a single query, carrying the
    actor's role in that organization as a correlated subquery, where resolving
    the organization slug first and the membership second would need two.

    Membership is annotated rather than filtered on, which keeps "the issue does
    not exist" (no row) distinguishable from "the issue exists but you are not a
    member" (a row with a null role).
    """
    if auth._resolved and auth._resolved_for == issue_id:
        return auth.scope

    # Local import avoids an import cycle at module load time.
    from apps.issue_events.models import Issue

    row = await (
        Issue.objects.filter(id=issue_id)
        .values(
            organization_id=F("project__organization_id"),
            role=Subquery(
                OrganizationUser.objects.filter(
                    organization_id=OuterRef("project__organization_id"),
                    user_id=auth.user_id,
                ).values("role")[:1]
            ),
        )
        .afirst()
    )
    auth._issue_exists = row is not None
    # A row whose role is null means the issue exists but the actor is not a
    # member, which must not resolve an organization id.
    auth._apply_membership_row(
        row if row is not None and row["role"] is not None else None, issue_id
    )
    return auth.scope


async def resolve_403_message(user_auth: Auth, permissions: list[str]):
    """
    Provides informative 403 Messages.

    When the actor has no membership in the organization at all, say that.

    When a token 403s, tell the user exactly what scope they are lacking
    (example: 'org:write'). When a user in a session 403s, tell the user what
    role they need to perform the action (example: need Admin, but are Member).
    """

    if user_auth._resolved_for is None and user_auth.auth_type == "token":
        missing = set(permissions).difference(set(user_auth.data.get_scopes()))
        return f"Permission denied. Token must have one or more of these scopes: {sorted(missing)}"

    if user_auth.actor_role is None:
        return "Permission denied. You are not a member of this organization"

    actor_role_name = OrganizationUserRole(user_auth.actor_role).label

    if user_auth.auth_type == "token":
        missing = set(permissions).difference(set(user_auth.data.get_scopes()))
        if not missing:
            # The token was granted a scope the route accepts, but its owner's
            # role in this organization is not, so the token was capped to the
            # role.
            return (
                "Permission denied. A token cannot exceed your role in the "
                f"organization, and you are a {actor_role_name.upper()}"
            )
        # Sorted, not just listed: set iteration order for strings shifts with
        # per-process hash randomization.
        return (
            "Permission denied. Token must have one or more of these scopes: "
            f"{sorted(missing)}"
        )

    # Stepping up through the roles, find the minimum role needed to perform
    # the operation.
    for role in ROLES:
        if set(permissions) & role["scopes"]:
            return (
                f"Permission denied. Operation requires {role['name'].upper()}, "
                f"you are a {actor_role_name.upper()}"
            )
    return "Permission denied"


def has_permission(permissions: list[str], session_bypass: bool = False):
    """
    Check scoped permissions.

    Example: @has_permission(["event:write", "event:admin"])

    The decorated function requires at least one of the specified permissions.

    session_bypass: for routes in which sessions can always perform the action
    (and there is no organization to check for scope against) and tokens should
    be checked. Currently just create_organization.
    """

    def decorator(f):
        @wraps(f)
        async def decorated_function(request: AuthHttpRequest, *args, **kwargs):
            org_slug = get_org_slug(kwargs)
            scopes = await request.auth.resolve_scope(org_slug)
            if (
                session_bypass
                and org_slug is None
                and request.auth.auth_type == "session"
            ):
                return await f(request, *args, **kwargs)
            if not any(s in permissions for s in scopes):
                raise HttpError(
                    403, await resolve_403_message(request.auth, permissions)
                )
            return await f(request, *args, **kwargs)

        return decorated_function

    return decorator


def has_issue_permission(permissions: list[str]):
    """Scoped-permission check for the *bare* ``/issues/{id}/...`` routes.

    Unlike :func:`glitchtip.api.permissions.has_permission`, these routes carry
    no ``organization_slug`` in the path, so there is nothing for
    ``resolve_scope`` to scope a session user's permissions against. A user may
    belong to many organizations with different roles, so we resolve the *one*
    organization that owns the issue being accessed (issue -> project ->
    organization) and scope against that.

    A token is resolved the same way and against the same organization: its
    scopes are capped by its owner's role there, and a non-member is refused
    regardless of what the token carries.
    """

    def decorator(f):
        @wraps(f)
        async def decorated_function(request: AuthHttpRequest, *args, **kwargs):
            auth = request.auth
            issue_id = kwargs.get("issue_id")
            if issue_id is None:
                # No issue to resolve an organization from. Resolve anyway so
                # the request counts as scope-resolved and the view's
                # scoped_org_id() reads None instead of raising. A token still
                # carries its own scopes, so check those; a session user has
                # nothing to authorize against, so defer to the view.
                scopes = await auth.resolve_scope(None)
                if auth.auth_type == "token" and not any(
                    s in permissions for s in scopes
                ):
                    raise HttpError(403, "Permission denied")
                return await f(request, *args, **kwargs)

            scopes = await resolve_scope_for_issue(auth, issue_id)
            if not auth._issue_exists:
                # Nothing to authorize against, and nothing to leak. Defer to
                # the view, whose queryset raises 404.
                return await f(request, *args, **kwargs)
            if auth._org_id is None:
                # The issue exists but the actor is not a member of its
                # organization. Tokens are refused here rather than deferred to
                # the view: a session user in this position is already told 403
                raise HttpError(403, "Permission denied")
            if not any(s in permissions for s in scopes):
                raise HttpError(403, "Permission denied")
            return await f(request, *args, **kwargs)

        return decorated_function

    return decorator


def public_route(f):
    """
    There are two public actions in GT currently, list_organizations and list_projects

    All tokens and users regardless of scopes granted in these organizations/projects
    should be able to access these endpoints, because they already check for membership.
    """

    @wraps(f)
    async def decorated_function(request: AuthHttpRequest, *args, **kwargs):
        await request.auth.resolve_scope(None)
        return await f(request, *args, **kwargs)

    decorated_function._gt_public_route = True
    return decorated_function

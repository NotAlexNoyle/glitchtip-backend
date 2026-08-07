from functools import wraps

from ninja.errors import HttpError

from apps.organizations_ext.constants import ROLES
from apps.organizations_ext.models import OrganizationUser

from .authentication import Auth, AuthHttpRequest


def get_org_slug(kwargs: dict) -> str | None:
    return kwargs.get("organization_slug")

async def resolve_403_message(user_auth: Auth, permissions: list[str], organization_slug: str):
    """
    Provides informative 403 Messages. 

    When a token 403s, tell the user exactly what scope they are lacking (example: 'org:write')
    When a user in a session 403s, tell the user what role they need to perform the action (example: 'need Admin, but are Member)
    """
    if user_auth.auth_type == "token":
        missing = set(permissions).difference(set(user_auth.data.get_scopes()))
        return f'Permission denied. Token must have one or more of these scopes: {list(missing)}'
    else:
        # resolve the role from the user_id
        org_user = await OrganizationUser.objects.filter(
            user_id=user_auth.user_id,
            organization__slug=organization_slug,
        ).afirst()

        if not org_user: return "Permission denied"

        # stepping up through the roles, find the minimum role needed to perform operation.
        for role in ROLES:
            if set(permissions) & role['scopes']:
                return f'Permission denied. Operation requires {role['name'].upper()}, you are a {org_user.get_role().upper()}'
    return "Permission denied"

def has_permission(permissions: list[str]):
    """
    Check scoped permissions.

    Example: @has_permission(["event:write", "event:admin"])

    The decorated function requires at least one of the specified permissions.
    """

    def decorator(f):
        @wraps(f)
        async def decorated_function(request: AuthHttpRequest, *args, **kwargs):
            scopes = await request.auth.resolve_scope(get_org_slug(kwargs))
            if not any(s in permissions for s in scopes):
                raise HttpError(403, await resolve_403_message(request.auth, permissions, get_org_slug(kwargs)))
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

    Token auth carries its scopes on the token itself, independent of any
    organization, so we skip the extra lookup for tokens entirely.
    """

    def decorator(f):
        @wraps(f)
        async def decorated_function(request: AuthHttpRequest, *args, **kwargs):
            # Token scopes live on the token itself, independent of any
            # organization, so resolve_scope(None) checks them directly and we
            # skip the extra issue lookup entirely.
            if request.auth.auth_type != "token":
                issue_id = kwargs.get("issue_id")
                organization_slug: str | None = None
                if issue_id is not None:
                    # Local import avoids an import cycle at module load time.
                    from apps.issue_events.models import Issue

                    organization_slug = await (
                        Issue.objects.filter(id=issue_id)
                        .values_list("project__organization__slug", flat=True)
                        .afirst()
                    )
                if organization_slug is None:
                    # The issue does not exist in any organization (or the route
                    # carries no issue_id). There is nothing to authorize
                    # against and nothing to leak, so defer to the view, whose
                    # membership-scoped queryset raises 404.
                    return await f(request, *args, **kwargs)
                scopes = await request.auth.resolve_scope(organization_slug)
            else:
                scopes = await request.auth.resolve_scope(None)
            if not any(s in permissions for s in scopes):
                raise HttpError(403, "Permission denied")
            return await f(request, *args, **kwargs)

        return decorated_function

    return decorator

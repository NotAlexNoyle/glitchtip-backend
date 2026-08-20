from functools import wraps
from dataclasses import dataclass
from typing import Literal

from django.db.models import F, OuterRef, Subquery
from ninja.errors import HttpError

from apps.organizations_ext.constants import ROLES, OrganizationUserRole
from apps.organizations_ext.models import OrganizationUser

from .authentication import Auth, AuthHttpRequest

from .scopes import Scopes

class OrgAuth(): 
	auth: Auth
	scope: set[Scopes]
	org_id: int
	role: str

@dataclass
class OrgAuthError():
    auth: Auth
    org_slug: str
    membership: bool
    user_scope: set[Scopes] | None = None
    user_role: str | None = None

async def resolve_org_auth(auth: Auth, required: set[Scopes], organization_slug: str | None = None) -> OrgAuth | OrgAuthError:
    """ The beating heart of the Authorization pipeline.
    resolve_org_auth returning an OrgAuth object is proof that authorization ran and passed.
    """
    row = await (
            OrganizationUser.objects.filter(
                user_id=auth.user_id, organization__slug=organization_slug
            )
            .values("organization_id", "role")
            .afirst()
        )

    # either there is no membership or the org doesn't exist
    if row is None:
        return OrgAuthError(auth, organization_slug, False)

    org_auth = OrgAuth()
    org_auth.auth = auth
    org_auth.org_id = row['organization_id']

    org_auth.role = OrganizationUserRole.get_role(row["role"])\
    
    role_scopes = set(org_auth.role["scopes"])
    if auth.auth_type == 'token':
        org_auth.scope = role_scopes & set(auth.token.get_scopes())
    else: 
        org_auth.scope = role_scopes

    # with orgAuth built, now we check if the user has the required scopes
    # A user just needs one scope from required, so we check if the intersection exists (not empty set)
    if not (org_auth.scope & required):
        return OrgAuthError(auth, organization_slug, True, org_auth.scope, org_auth.role)

    return org_auth

def has_permission(permissions: list[str]):
    """
    Check scoped permissions.
    Example: @has_permission(["event:write", "event:admin"])
    The decorated function requires at least one of the specified permissions.
    """
    required = frozenset(permissions)

    def decorator(f):
        @wraps(f)
        async def decorated_function(request: AuthHttpRequest, *args, **kwargs):
            org_slug = kwargs.get("organization_slug")
            result = await resolve_org_auth(request.auth, required, org_slug)

            if isinstance(result, OrgAuthError):
                raise HttpError(403, resolve_403_message(result, required))
            
            request.org_auth = result
            return await f(request, *args, **kwargs)

        return decorated_function

    return decorator

def resolve_403_message(err: OrgAuthError, required: set[Scopes]) -> str:
    # if the user is a member, then we have to report what role/scopes they're missing
    if err.membership:
        if err.auth.auth_type == 'token': # report scopes missing
            # two cases:
            # the token have the scopes necessary, but the user role doesn't allow it.
            missing = set(required).difference(set(err.auth.data.get_scopes()))
            if not missing:
                return f"Permission denied. A token cannot exceed your role in the organization, and you are a {err.user_role.upper()}"

            # The token lacks the scopes in the first place.
            missing = set(required).difference(err.user_scope)
            return f"Permission denied. Token must have one or more of these scopes: {sorted(missing)}"
        else:
            for role in ROLES:
                if err.user_scope & role["scopes"]:
                    return (
                        f"Permission denied. Operation requires {role['name'].upper()}, "
                        f"you are a {err.user_role.upper()}"
                    )
    else:
        return f'Permission denied. You are not a member of this organization'
    return "Permission denied"

""" 
OrgAuth, after it exists, holds information that routes can use.
These getters will expose this information
"""

def scoped_org_id(request: AuthHttpRequest) -> int | None:
    """The organization id the permission decorator already resolved.

    Views can filter on this instead if re-deriving membership on their own.
    """
    if request.org_auth and request.org_auth._org_id is None:
        # The check ran and found no membership. The route deliberately defers
        # to the view so its own membership-scoped queryset raises 404 (rather
        # than confirming the object exists).
        return None
    return request.org_auth.org_id
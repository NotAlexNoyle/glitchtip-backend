from dataclasses import dataclass
from functools import wraps

from django.core.exceptions import ImproperlyConfigured
from django.db.models import Exists, QuerySet, Subquery
from ninja.errors import HttpError
from ninja.pagination import paginate

from apps.organizations_ext.constants import ROLES, OrganizationUserRole
from apps.organizations_ext.models import Organization, OrganizationUser

from .authentication import Auth, AuthHttpRequest
from .scopes import Scopes


@dataclass(frozen=True)
class OrgScope:
    user_id: int
    org_slug: str
    required: frozenset[Scopes]
    roles: tuple[int, ...]  # role values holding any required scope
    org_id: int | None = None  # set only when already known for free

    @property
    def org_id_expr(self):
        # An int when we know it, otherwise an UNCORRELATED scalar
        # subquery. Never a join to organization from the data model --
        # that measured ~14x slower. See "The slug" below.
        if self.org_id is not None:
            return self.org_id
        return Subquery(
            Organization.objects.filter(slug=self.org_slug, is_deleted=False).values(
                "id"
            )[:1]
        )

    @property
    def gate(self) -> Exists:
        # No OuterRef. Deliberately UNCORRELATED, so Postgres evaluates
        # this once as an InitPlan instead of once per row. Adding an
        # OuterRef here looks more correct and silently makes it per-row.
        qs = OrganizationUser.objects.filter(
            user_id=self.user_id,
            role__in=self.roles,
            organization__slug=self.org_slug,  # slug and id must AGREE, so a
            organization__is_deleted=False,  # stale resolved id fails CLOSED
        )
        if self.org_id is not None:
            qs = qs.filter(organization_id=self.org_id)
        return Exists(qs)

    def apply(self, qs):
        return qs.filter(self.gate, **{qs.model.org_field: self.org_id_expr})


def org_scoped_list(scopes: list[Scopes]):
    required = frozenset(scopes)
    # Import time: which role ints hold at least one required scope.
    roles = tuple(i for i, r in enumerate(ROLES) if required & r["scopes"])
    if not roles:
        raise ImproperlyConfigured(f"no role holds any of {sorted(required)}")

    def decorator(view):
        @wraps(view)  # ninja reads the signature for path params
        async def gated(request, **kwargs):
            if request.auth.auth_type == "token" and not (
                required & set(request.auth.token.get_scopes())
            ):
                raise HttpError(403, "Permission Denied.")

            scope = OrgScope(
                request.auth.user_id, kwargs["organization_slug"], required, roles
            )
            request.org_scope = scope  # set before the view runs
            qs = await view(request, **kwargs)
            if not isinstance(qs, QuerySet):
                raise TypeError(f"{view.__qualname__} must return a QuerySet")
            return scope.apply(qs)

        return paginate(gated)

    return decorator


@dataclass
class OrgAuth:
    auth: Auth
    scope: set[Scopes]
    org_id: int
    role: int
    role_details: dict


class OrgAuthHttpRequest(AuthHttpRequest):
    """A request that has passed @has_permission, so org_auth is resolved."""

    org_auth: OrgAuth


@dataclass
class OrgAuthError:
    auth: Auth
    org_slug: str
    membership: bool
    user_scope: set[Scopes] | None = None
    role_details: dict | None = None


async def resolve_org_auth(
    auth: Auth, required: set[Scopes], organization_slug: str | None = None
) -> OrgAuth | OrgAuthError:
    """The beating heart of the Authorization pipeline.
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

    role_details = OrganizationUserRole.get_role(row["role"])
    role_scopes = set(role_details["scopes"])
    if auth.auth_type == "token":
        role_scopes = role_scopes & set(auth.token.get_scopes())

    org_auth = OrgAuth(
        auth=auth,
        scope=role_scopes,
        org_id=row["organization_id"],
        role=row["role"],
        role_details=role_details,
    )

    # with orgAuth built, now we check if the user has the required scopes
    # A user just needs one scope from required, so we check if the intersection exists (not empty set)
    if not (org_auth.scope & required):
        return OrgAuthError(
            auth, organization_slug, True, org_auth.scope, org_auth.role_details
        )

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


def _minimum_role_name(required) -> str | None:
    """ROLES is ordered lowest-first, so the first role holding any required
    scope is the lowest role that can pass."""
    for role in ROLES:
        if required & role["scopes"]:
            return role["name"].upper()
    return None


def resolve_403_message(err: OrgAuthError, required: set[Scopes]) -> str:
    if not err.membership:
        return "Permission denied. You are not a member of this organization"

    you_are = err.role_details["name"].upper()
    # Denial means role ∩ token ∩ required was empty. If the role alone grants
    # nothing required, no token can help; otherwise the token is the gap.
    attainable = set(err.role_details["scopes"]) & set(required)

    if attainable and err.auth.auth_type == "token":
        return (
            "Permission denied. Token must have one or more of these scopes: "
            f"{sorted(attainable)}"
        )

    needs = _minimum_role_name(set(required))
    if needs is None:
        return "Permission denied"
    if err.auth.auth_type == "token":
        return (
            "Permission denied. A token cannot exceed your role in the "
            f"organization: this requires {needs}, you are a {you_are}"
        )
    return f"Permission denied. Operation requires {needs}, you are a {you_are}"


""" 
OrgAuth and Auth, after they exist, holds information that routes can use.
These getters will expose this information to save views from re-deriving
them.
"""


def scoped_org_id(request: OrgAuthHttpRequest) -> int | None:
    return request.org_auth.org_id


def scoped_user_id(request: AuthHttpRequest) -> int | None:
    return request.auth.user_id


def scoped_user_role(request: OrgAuthHttpRequest) -> int | None:
    return request.org_auth.role

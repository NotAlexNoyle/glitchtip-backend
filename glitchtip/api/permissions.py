from dataclasses import dataclass, field
from functools import wraps

from django.core.exceptions import ImproperlyConfigured
from django.db.models import Exists, QuerySet, Subquery
from ninja.errors import HttpError
from ninja.pagination import paginate

from apps.organizations_ext.constants import ROLES, OrganizationUserRole
from apps.organizations_ext.models import Organization, OrganizationUser

from .authentication import Auth, AuthHttpRequest
from .org_ids import aresolve_org_id
from .scopes import Scopes


@dataclass(frozen=True)
class OrgScope:
    user_id: int
    org_slug: str
    required: frozenset[Scopes]
    roles: tuple[int, ...]  # role values holding any required scope
    # Resolved from the slug by org_ids.aresolve_org_id; None only when no
    # organization has that slug, which the subquery fallback handles.
    org_id: int | None = None

    # Proof that the gate reached a query. ``org_scoped_list``/``_all`` apply the
    # scope themselves so they never need this, but ``org_scoped`` hands the job
    # to the view, and a view that forgets is an ungated route that still looks
    # gated to the invariant test. Mutating a frozen dataclass needs the
    # documented escape hatch; the alternative is losing the check.
    _applied: bool = field(default=False, compare=False, repr=False)

    @property
    def applied(self) -> bool:
        return self._applied

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
        object.__setattr__(self, "_applied", True)
        return qs.filter(self.gate, **{qs.model.org_field: self.org_id_expr})


def _resolve_roles(scopes: list[Scopes]) -> tuple[frozenset[Scopes], tuple[int, ...]]:
    """Import time: which role ints hold at least one required scope."""
    required = frozenset(scopes)
    roles = tuple(i for i, r in enumerate(ROLES) if required & r["scopes"])
    if not roles:
        raise ImproperlyConfigured(f"no role holds any of {sorted(required)}")
    return required, roles


async def _enter_scope(request, required, roles, kwargs) -> OrgScope:
    """Token ceiling, then the scope the view will be gated by."""
    if request.auth.auth_type == 'token':
        effective = required & set(request.auth.token.get_scopes())
        if not effective:
            raise HttpError(403, "Permission Denied.")
        roles = tuple(i for i, r in enumerate(ROLES) if effective & r["scopes"])

    # Warm, this is free; cold, it is one indexed probe per slug per worker.
    # It buys plan-time partition pruning on the nested RANGE -> HASH tables,
    # which a subquery cannot give us. See glitchtip/api/org_ids.py.
    slug = kwargs["organization_slug"]
    scope = OrgScope(
        request.auth.user_id,
        slug,
        required,
        roles,
        org_id=await aresolve_org_id(slug),
    )
    request.org_scope = scope  # set before the view runs
    return scope


def _org_gate(required: frozenset[Scopes], roles: tuple[int, ...], view):
    """The gate, with nothing about response shape in it.

    Checks the token, builds the ``OrgScope``, runs the view, and folds the
    gate into whatever queryset the view hands back. What happens to that
    queryset afterwards -- paginated, or evaluated whole -- is the caller's
    business, and is the ONLY thing the wrappers below differ in.
    """

    @wraps(view)  # ninja reads the signature for path params
    async def gated(request, **kwargs):
        scope = await _enter_scope(request, required, roles, kwargs)
        qs = await view(request, **kwargs)
        if not isinstance(qs, QuerySet):
            raise TypeError(f"{view.__qualname__} must return a QuerySet")
        return scope.apply(qs)

    return gated


def org_scoped_list(scopes: list[Scopes]):
    """Folded gate on a paginated list route.

    The paginator evaluates the page for us -- see ``org_scoped_all`` for why
    that matters.
    """
    required, roles = _resolve_roles(scopes)

    def decorator(view):
        return paginate(_org_gate(required, roles, view))

    return decorator


def org_scoped_all(scopes: list[Scopes]):
    """Folded gate on a list route that returns everything, unpaginated.

    Identical to ``org_scoped_list`` but for the missing ``paginate``, plus one
    consequence of dropping it: something has to evaluate the queryset. Our
    paginator sets ``Output = None``, which switches off the branch in ninja's
    ``_inject_pagination`` that would force evaluation, so today it is
    ``apaginate_queryset`` alone that materializes the rows. With no paginator
    in the stack there is nobody left to do it, and handing pydantic a lazy
    queryset would iterate it synchronously inside the event loop --
    ``SynchronousOnlyOperation``. So we evaluate here.
    """
    required, roles = _resolve_roles(scopes)

    def decorator(view):
        gated = _org_gate(required, roles, view)

        @wraps(view)
        async def evaluated(request, **kwargs):
            return [obj async for obj in await gated(request, **kwargs)]

        return evaluated

    return decorator


def org_scoped(scopes: list[Scopes]):
    """Folded gate for a view whose response is not one queryset.

    An aggregate, a bulk mutation, or a route that resolves a single object
    returns computed data rather than a queryset, so there is nothing for the
    decorator to fold the gate into. This variant only builds the scope; the
    view must call ``request.org_scope.apply(qs)`` itself on the queryset that
    decides which rows it may touch.

    That moves the gate out of the decorator, which is exactly what
    ``DecoratorIsTheBoundaryTestCase`` relies on not happening, so the promise
    is enforced at runtime instead: a view that returns without ever applying
    the scope raises rather than serving. The check is not a substitute for
    reading the view -- applying the scope to the wrong queryset still passes --
    but it does catch the gate being dropped entirely.
    """
    required, roles = _resolve_roles(scopes)

    def decorator(view):
        @wraps(view)
        async def gated(request, **kwargs):
            scope = await _enter_scope(request, required, roles, kwargs)
            result = await view(request, **kwargs)
            if not scope.applied:
                raise ImproperlyConfigured(
                    f"{view.__qualname__} is @org_scoped but never called "
                    "request.org_scope.apply() -- nothing authorized it"
                )
            return result

        return gated

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


class OrgScopedHttpRequest(AuthHttpRequest):
    """A request under a folded gate, so org_scope is set and org_auth is not.

    The folded gate never resolves an ``OrganizationUser`` row, so there is no
    role, no scope set, and no org id as an int -- only ``org_scope``, whose
    ``org_id_expr`` is usable in a filter and nowhere else. Routes that need any
    of the rest want ``@has_permission`` and ``OrgAuthHttpRequest``.
    """

    org_scope: OrgScope


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

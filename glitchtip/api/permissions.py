import inspect
from dataclasses import dataclass
from functools import wraps

from django.core.exceptions import ImproperlyConfigured
from django.db.models import Exists, QuerySet, Subquery
from ninja.errors import HttpError
from ninja.pagination import paginate

from apps.organizations_ext.constants import ROLES, OrganizationUserRole
from apps.organizations_ext.models import Organization, OrganizationUser
from glitchtip.base_models import OrgScopedModel

from .authentication import Auth, AuthHttpRequest
from .scopes import Scopes


@dataclass(frozen=True)
class OrgScope:
    user_id: int
    org_slug: str
    required: frozenset[Scopes]
    roles: tuple[int, ...]  # role values holding any required scope

    @property
    def org_id_expr(self) -> Subquery:
        # An UNCORRELATED scalar subquery, never a join to organization from
        # the data model -- that measured ~14x slower.
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
            organization__slug=self.org_slug,
            organization__is_deleted=False,
        )
        if len(self.roles) < len(ROLES):
            # A no-op on event:* routes, where every role qualifies.
            qs = qs.filter(role__in=self.roles)
        return Exists(qs)

    def apply(self, qs):
        model = qs.model
        if not issubclass(model, OrgScopedModel):
            raise ImproperlyConfigured(
                f"{model._meta.label} is returned by a gated route but is not "
                "an OrgScopedModel, so the gate cannot isolate it. Declare "
                "org_field on it via OrgScopedModel."
            )
        return qs.filter(self.gate, **{model.org_field: self.org_id_expr})


# Route-state declarations. Markers only -- they change no behavior. CI reads
# them (RouteStateLedgerTestCase) so that every route is either gated, declared
# with one of these, or public: three states, no undeclared fourth.


def self_service(view):
    """Identity is the scope. No organization in the path (``/users/{id}/``)."""
    view.__route_state__ = "self_service"
    return view


def legacy_any_member(view):
    """Membership only, deliberately -- there is no organization to scope to.

    Never on a route with an organization in its path: those get a real scope.
    """
    view.__route_state__ = "legacy_any_member"
    return view


def gates_manually(view):
    """Isolation is hand-written, so ORM injection cannot reach it.

    Raw-SQL routes. Each one is a hole in the guarantee, which is why the count
    is budgeted rather than merely recorded.
    """
    view.__route_state__ = "gates_manually"
    return view


def _resolve_roles(scopes: list[Scopes]) -> tuple[frozenset[Scopes], tuple[int, ...]]:
    """Import time: which role ints hold at least one required scope."""
    required = frozenset(scopes)
    roles = tuple(i for i, r in enumerate(ROLES) if required & r["scopes"])
    if not roles:
        raise ImproperlyConfigured(f"no role holds any of {sorted(required)}")
    return required, roles


def _require_slug_param(view) -> None:
    """Import time: a gated route must have a slug for the gate to scope to."""
    if "organization_slug" not in inspect.signature(view).parameters:
        raise ImproperlyConfigured(
            f"{view.__qualname__} is org-scoped but takes no "
            "`organization_slug` parameter -- the gate has nothing to scope to"
        )


async def _enter_scope(request, required, roles, kwargs) -> OrgScope:
    """Token ceiling, then the scope the view will be gated by."""
    if request.auth.auth_type == "token":
        effective = required & set(request.auth.token.get_scopes())
        if not effective:
            raise HttpError(
                403,
                f"Permission denied. This endpoint requires one of {sorted(required)}; "
                "your token grants none of them.",
            )
        roles = tuple(i for i, r in enumerate(ROLES) if effective & r["scopes"])

    scope = OrgScope(request.auth.user_id, kwargs["organization_slug"], required, roles)
    request.org_scope = scope  # set before the view runs
    return scope


def _org_gate(required: frozenset[Scopes], roles: tuple[int, ...], view):
    """The gate, with nothing about response shape in it.

    Checks the token, builds the ``OrgScope``, runs the view, and folds the
    gate into whatever queryset the view hands back. What happens to that
    queryset afterwards -- paginated, or evaluated whole -- is the caller's
    business, and is the ONLY thing the wrappers below differ in.
    """
    _require_slug_param(view)

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

    An unpaginated variant would have to evaluate the queryset itself:
    ``apaginate_queryset`` is what materializes the rows today, and handing
    pydantic a lazy queryset iterates it in the event loop.
    """
    required, roles = _resolve_roles(scopes)

    def decorator(view):
        return paginate(_org_gate(required, roles, view))

    return decorator


def org_scoped_qs(scopes: list[Scopes], queryset):
    """Folded gate for a view whose response is not one queryset.

    An aggregate, a bulk mutation, or a route that resolves a single object
    needs *rows* in the middle of its body, so by the time it returns there is
    nothing left for ``_org_gate`` to fold into. A decorator wraps -- it runs
    before the view and after it, never in the middle -- so the only way to
    gate these is to fold on the way IN rather than on the way out.

    ``queryset`` is an async ``(request, **kwargs) -> QuerySet`` called once the
    scope exists, with ninja's already-parsed parameters, so it can narrow by
    ``filters`` or a path id. Whatever it returns is gated before the view sees
    it and handed over as ``qs``.

    The direction is the whole point. The view cannot forget to authorize,
    because it is never handed anything unauthorized to work with -- where the
    previous ``@org_scoped`` asked the view to remember a call and could only
    check afterwards that it had. What remains is a view that ignores ``qs``
    and reaches for a manager itself, which is a ``.objects`` sitting in a route
    body; ``DecoratorIsTheBoundaryTestCase`` reads the source for exactly that.
    """
    required, roles = _resolve_roles(scopes)

    def decorator(view):
        _require_slug_param(view)
        signature = inspect.signature(view)
        if "qs" not in signature.parameters:
            raise ImproperlyConfigured(
                f"{view.__qualname__} is @org_scoped_qs but takes no `qs` "
                "parameter -- there is nowhere to hand it the gated queryset"
            )

        @wraps(view)  # ninja reads the signature for path params
        async def gated(request, **kwargs):
            scope = await _enter_scope(request, required, roles, kwargs)
            return await view(
                request, qs=scope.apply(await queryset(request, **kwargs)), **kwargs
            )

        # ninja builds the operation's parameters from the signature, and ``qs``
        # is ours to supply -- it is not a query param and must not show up in
        # the schema. ``@wraps`` leaves a ``__wrapped__`` that
        # ``inspect.signature`` follows straight back to the undecorated view,
        # so setting ``__signature__`` here is what stops that unwrap.
        gated.__signature__ = signature.replace(
            parameters=[
                param for name, param in signature.parameters.items() if name != "qs"
            ]
        )
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

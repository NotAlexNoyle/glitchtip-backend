from dataclasses import dataclass, field
from typing import Any, Literal

from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest
from ninja.security import HttpBearer
from ninja.security import SessionAuth as BaseSessionAuth

from apps.api_tokens.models import APIToken
from apps.organizations_ext.constants import OrganizationUserRole
from apps.organizations_ext.models import OrganizationUser

from glitchtip.api.scopes import Scopes


class ScopeNotResolved(Exception):
    """A view asked for a scope-derived value before any permission check ran.

    Views filter by ``Auth.org_id`` instead of re-deriving membership, so a
    route that forgot its permission decorator must fail loudly (500) rather
    than fall through to an unfiltered queryset.
    """


@dataclass
class Auth:
    user_id: int
    auth_type: Literal["session", "token"]
    token: APIToken | None = None

    # these will be cut.
    data: Any = None
    scope: set[Scopes] = field(default_factory=set)
    # Populated by resolve_scope. actor_role is the OrganizationUserRole int of
    # the acting user's membership in the resolved organization.
    actor_role: int | None = None
    # The resolved organization PK, and the memo key it was resolved for (an
    # organization slug, or an issue id for the bare /issues/{id}/ routes).
    _org_id: int | None = None
    _resolved_for: str | int | None = None
    _resolved: bool = False
    # Only meaningful when _resolved_for is an issue id: whether that issue
    # exists at all, which separates "not found" from "not a member of its org".
    _issue_exists: bool = False

    @property
    def org_id(self) -> int:
        """The organization the permission check resolved for this request."""
        if not self._resolved or self._org_id is None:
            raise ScopeNotResolved(
                "Auth.org_id read before a permission check resolved an "
                "organization -- is the view missing @has_permission?"
            )
        return self._org_id

    async def resolve_scope(self, organization_slug: str | None = None) -> set[Scopes]:
        """Resolve (org id, role, scope) in one query, memoized per request.

        Pulls the source of permissions - scope - up into its own field in the
        Auth class. Depending on the type of Auth this generates the related
        scope.
        """
        if self._resolved and self._resolved_for == organization_slug:
            return self.scope

        if organization_slug is None:
            # Token auth with no organization in the path (the bare
            # /issues/{id}/ routes): scopes come off the token alone.
            self.scope = (
                set(self.data.get_scopes()) if self.auth_type == "token" else set()
            )
            self._resolved, self._resolved_for = True, organization_slug
            return self.scope

        row = await (
            OrganizationUser.objects.filter(
                user_id=self.user_id, organization__slug=organization_slug
            )
            .values("organization_id", "role")
            .afirst()
        )
        self._apply_membership_row(row, organization_slug)
        return self.scope

    def _apply_membership_row(
        self, row: dict | None, resolved_for: str | int | None
    ) -> None:
        """Set scope/org_id/actor_role from a ``{organization_id, role}`` row."""
        self._resolved, self._resolved_for = True, resolved_for
        if row is None:
            self._org_id, self.actor_role, self.scope = None, None, set()
            return
        self._org_id = row["organization_id"]
        self.actor_role = row["role"]
        role_scopes = set(OrganizationUserRole.get_role(row["role"])["scopes"])
        if self.auth_type == "token":
            # takes the intersection of user's role's scopes and
            # selected scopes for the token to prevent priv.
            # escalation
            self.scope = set(self.data.get_scopes()) & role_scopes
        else:
            self.scope = role_scopes


class AuthHttpRequest(HttpRequest):
    """Django HttpRequest that is known to be authenticated by a user"""

    auth: Auth


class SessionAuth(BaseSessionAuth):
    """
    Check if user is logged in by checking session
    This avoids an unnecessary database call.
    request.auth will result in the user id
    """

    async def authenticate(self, request: HttpRequest, key: str | None) -> Auth | None:
        if settings.SESSION_ENGINE == "django.contrib.sessions.backends.cache":
            user_id = request.session.get(SESSION_KEY)
        # Django DB backed sessions don't support async yet
        else:
            user_id = await sync_to_async(request.session.get)(SESSION_KEY)
        return Auth(int(user_id), "session") if user_id else None


class TokenAuth(HttpBearer):
    """
    API Token based authentication always connects to a specific user.
    Store the token object under data for checking scopes permissions.
    """

    def __call__(self, request: HttpRequest) -> Any | None:
        # Workaround https://github.com/vitalik/django-ninja/issues/989
        if request.resolver_match and request.resolver_match.url_name in [
            "setup_wizard_hash"
        ]:
            request.auth = None  # type: ignore
            return self.get_anon()

        return super().__call__(request)

    async def get_anon(self):
        return AnonymousUser()

    async def authenticate(self, request: HttpRequest, key: str) -> Auth | None:
        try:
            token = await APIToken.objects.aget(token=key, user__is_active=True)
        except APIToken.DoesNotExist:
            return None

        return Auth(token.user_id, "token", token=token)

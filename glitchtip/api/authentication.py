from dataclasses import dataclass, field
from typing import Any, Literal

from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.http import HttpRequest
from ninja.security import HttpBearer
from ninja.security import SessionAuth as BaseSessionAuth

from apps.api_tokens.models import APIToken
from apps.organizations_ext.models import OrganizationUser
from apps.organizations_ext.scopes import Scopes
from apps.users.models import User

USER_SCOPE_CACHE_KEY = "user_scope:v1:"
USER_SCOPE_CACHE_TTL = 300
USER_SUPERUSER_CACHE_KEY = "user_superuser:v1:"
# Deliberately shorter than the scope TTL: nothing invalidates this entry (the
# scope cache has membership-change hooks, is_superuser has none), and the flag
# grants every scope, so a stale True is the most expensive staleness we have.
USER_SUPERUSER_CACHE_TTL = 60


def user_scope_cache_key(user_id: int, org_slug: str) -> str:
    return f"{USER_SCOPE_CACHE_KEY}{user_id}:{org_slug}"


def user_superuser_cache_key(user_id: int) -> str:
    return f"{USER_SUPERUSER_CACHE_KEY}{user_id}"


@dataclass
class Auth:
    user_id: int
    auth_type: Literal["session", "token"]
    data: Any = None
    scope: set[Scopes] = field(default_factory=set)

    async def resolve_scope(self, organization_slug: str | None = None) -> set[Scopes]:
        """
        Pulls the source of permissions - scope - up into its own field
        in Auth class. Depending on the type of Auth this generates the
        related scope.
        """
        if self.auth_type == "token":
            self.scope = set(self.data.get_scopes())
        elif organization_slug:
            key = user_scope_cache_key(self.user_id, organization_slug)
            cached = await cache.aget(key)
            if cached is None:
                org_user = await OrganizationUser.objects.filter(
                    user_id=self.user_id,
                    organization__slug=organization_slug,
                ).afirst()
                cached = list(org_user.get_scopes()) if org_user else []
                await cache.aset(key, cached, USER_SCOPE_CACHE_TTL)
            self.scope = set(cached)
        else:
            self.scope = set()
        return self.scope

    async def is_superuser(self) -> bool:
        """Whether this user is a Django superuser, cached per user.

        ``is_superuser`` is a column on ``users_user``, and the session path
        never loads the user row (see ``SessionAuth``), so this is a real query.
        Call it only when a scope check has already failed - see
        ``glitchtip.api.permissions``. Denials are rare, so the cost never lands
        on the hot path.
        """
        key = user_superuser_cache_key(self.user_id)
        cached = await cache.aget(key)
        if cached is None:
            cached = (
                await User.objects.filter(id=self.user_id)
                .values_list("is_superuser", flat=True)
                .afirst()
                or False
            )
            await cache.aset(key, cached, USER_SUPERUSER_CACHE_TTL)
        return cached


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

        return Auth(token.user_id, "token", data=token)

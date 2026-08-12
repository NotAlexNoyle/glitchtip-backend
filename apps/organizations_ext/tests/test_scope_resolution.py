from django.test import TestCase
from model_bakery import baker

from apps.organizations_ext.constants import OrganizationUserRole
from glitchtip.api.authentication import Auth, ScopeNotResolved


class ResolveScopeTestCase(TestCase):
    """Exercises Auth.resolve_scope directly.

    Scope is resolved once per request from the membership row and memoized on
    the Auth instance, so there is no cross-request cache to invalidate and a
    role change takes effect on the next request.
    """

    @classmethod
    def setUpTestData(cls):
        cls.org = baker.make("organizations_ext.Organization")
        # The first user added to an organization is always made its owner, so
        # add a throwaway owner first to get a genuine non-owner membership.
        cls.org.add_user(baker.make("users.user"), OrganizationUserRole.OWNER)
        cls.user = baker.make("users.user")
        cls.org_user = cls.org.add_user(cls.user, OrganizationUserRole.MEMBER)
        cls.token = baker.make("api_tokens.APIToken", user=cls.user)
        cls.token.add_permissions(["org:read", "project:read"])

    async def test_token_scope_from_token_object(self):
        auth = Auth(self.user.id, "token", data=self.token)
        self.assertEqual(await auth.resolve_scope(), set(self.token.get_scopes()))

    async def test_session_member_returns_role_scopes(self):
        auth = Auth(self.user.id, "session")
        scope = await auth.resolve_scope(self.org.slug)
        self.assertEqual(scope, set(self.org_user.get_scopes()))

    async def test_resolution_populates_org_id_and_actor_role(self):
        auth = Auth(self.user.id, "session")
        await auth.resolve_scope(self.org.slug)
        self.assertEqual(auth.org_id, self.org.id)
        self.assertEqual(auth.actor_role, OrganizationUserRole.MEMBER)

    async def test_role_change_takes_effect_immediately(self):
        """No cross-request cache, so a role change is not masked by a TTL."""
        member_scope = set(self.org_user.get_scopes())
        await Auth(self.user.id, "session").resolve_scope(self.org.slug)
        self.org_user.role = OrganizationUserRole.OWNER
        await self.org_user.asave()
        # A new request means a new Auth, and therefore a fresh resolution.
        scope = await Auth(self.user.id, "session").resolve_scope(self.org.slug)
        self.assertNotEqual(scope, member_scope)
        self.assertEqual(scope, set(self.org_user.get_scopes()))

    async def test_repeat_resolution_is_memoized(self):
        """The memo is per-Auth, so a mid-request role change is not re-read."""
        auth = Auth(self.user.id, "session")
        member_scope = await auth.resolve_scope(self.org.slug)
        self.org_user.role = OrganizationUserRole.OWNER
        await self.org_user.asave()
        self.assertEqual(await auth.resolve_scope(self.org.slug), member_scope)

    async def test_non_member_returns_empty(self):
        other = await baker.amake("users.user")
        auth = Auth(other.id, "session")
        self.assertEqual(await auth.resolve_scope(self.org.slug), set())
        with self.assertRaises(ScopeNotResolved):
            _ = auth.org_id

    async def test_no_org_slug_returns_empty(self):
        self.assertEqual(await Auth(self.user.id, "session").resolve_scope(), set())

    def test_org_id_before_resolution_raises(self):
        """A view that forgot its permission decorator must fail loudly."""
        with self.assertRaises(ScopeNotResolved):
            _ = Auth(self.user.id, "session").org_id

import json

from django.core.cache import cache
from django.test import TestCase
from model_bakery import baker

from apps.organizations_ext.constants import OrganizationUserRole
from apps.organizations_ext.invitation_backend import InvitationTokenGenerator
from apps.organizations_ext.models import OrganizationUser
from glitchtip.api.authentication import Auth, user_scope_cache_key


class ResolveScopeLogicTestCase(TestCase):
    """Exercises resolve_scope directly (it isn't wired into has_permission yet)."""

    @classmethod
    def setUpTestData(cls):
        cls.org = baker.make("organizations_ext.Organization")
        cls.user = baker.make("users.user")
        cls.org_user = cls.org.add_user(cls.user, OrganizationUserRole.ADMIN)
        cls.token = baker.make("api_tokens.APIToken", user=cls.user)
        cls.token.add_permissions(["org:read", "project:read"])

    def setUp(self):
        cache.clear()

    async def test_token_scope_from_token_object(self):
        auth = Auth(self.user.id, "token", data=self.token)
        self.assertEqual(await auth.resolve_scope(), set(self.token.get_scopes()))

    async def test_session_member_returns_role_scopes_and_populates_cache(self):
        key = user_scope_cache_key(self.user.id, self.org.slug)
        self.assertIsNone(await cache.aget(key))  # cold
        scope = await Auth(self.user.id, "session").resolve_scope(self.org.slug)
        self.assertEqual(scope, set(self.org_user.get_scopes()))
        self.assertEqual(set(await cache.aget(key)), set(self.org_user.get_scopes()))

    async def test_session_reads_cache_not_db(self):
        """Prove the cached value is used: change role in DB w/o invalidating."""
        admin_scope = set(self.org_user.get_scopes())
        await Auth(self.user.id, "session").resolve_scope(self.org.slug)  # prime
        self.org_user.role = OrganizationUserRole.OWNER
        await self.org_user.asave()  # deliberately NOT invalidated
        scope = await Auth(self.user.id, "session").resolve_scope(self.org.slug)
        self.assertEqual(scope, admin_scope)  # stale == cache was used

    async def test_non_member_returns_empty(self):
        other = await baker.amake("users.user")
        scope = await Auth(other.id, "session").resolve_scope(self.org.slug)
        self.assertEqual(scope, set())

    async def test_no_org_slug_returns_empty(self):
        self.assertEqual(await Auth(self.user.id, "session").resolve_scope(), set())


class ScopeCacheInvalidationTestCase(TestCase):
    """Endpoint tests covering cache invalidation on membership/role changes."""

    def setUp(self):
        cache.clear()
        self.org = baker.make("organizations_ext.Organization")
        self.owner = baker.make("users.user")
        self.org.add_user(self.owner, OrganizationUserRole.OWNER)
        self.member = baker.make("users.user")
        self.member_ou = self.org.add_user(self.member, OrganizationUserRole.MEMBER)
        self.invitee = baker.make("users.user")
        self.async_client.force_login(self.owner)

    async def _prime(self, user_id):
        await Auth(user_id, "session").resolve_scope(self.org.slug)
        return user_scope_cache_key(user_id, self.org.slug)

    async def test_update_member_role_invalidates_cache(self):
        key = await self._prime(self.member.id)
        self.assertIsNotNone(await cache.aget(key))
        url = f"/api/0/organizations/{self.org.slug}/members/{self.member_ou.id}/"
        res = await self.async_client.put(
            url, json.dumps({"orgRole": "manager"}), content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(await cache.aget(key))

    async def test_delete_member_invalidates_cache(self):
        key = await self._prime(self.member.id)
        self.assertIsNotNone(await cache.aget(key))
        url = f"/api/0/organizations/{self.org.slug}/members/{self.member_ou.id}/"
        res = await self.async_client.delete(url)
        self.assertEqual(res.status_code, 204)
        self.assertIsNone(await cache.aget(key))

    async def test_accept_invite_does_not_crash_and_invalidates(self):
        invite = await OrganizationUser.objects.acreate(
            organization=self.org,
            email="invitee@example.com",
            role=OrganizationUserRole.MEMBER,
        )
        token = InvitationTokenGenerator().make_token(invite)
        # invitee probed the org before accepting -> empty scope cached
        key = await self._prime(self.invitee.id)
        self.assertIsNotNone(await cache.aget(key))
        await self.async_client.aforce_login(self.invitee)
        res = await self.async_client.post(
            f"/api/0/accept/{invite.id}/{token}/",
            json.dumps({"acceptInvite": True}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(await cache.aget(key))

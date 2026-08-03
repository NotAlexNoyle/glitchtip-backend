from django.core.cache import cache
from django.urls import reverse
from model_bakery import baker

from apps.organizations_ext.constants import OrganizationUserRole
from glitchtip.api.authentication import user_superuser_cache_key
from glitchtip.test_utils.test_case import APIPermissionTestCase


class OrganizationAPIPermissionTests(APIPermissionTestCase):
    def setUp(self):
        self.create_user_org()
        self.set_client_credentials(self.auth_token.token)
        self.list_url = reverse("api:list_organizations")
        self.detail_url = reverse("api:get_organization", args=[self.organization.slug])

    # test_list and test_retrieve should always work, no matter the user's scope.
    def test_list(self):
        self.assertGetReqStatusCode(self.list_url, 200)

    def test_create(self):
        data = {"name": "new org"}
        self.assertPostReqStatusCode(self.list_url, data, 201)

    def test_retrieve(self):
        self.assertGetReqStatusCode(self.detail_url, 403)
        self.auth_token.add_permission("org:read")
        self.assertGetReqStatusCode(self.detail_url, 200)

    def test_destroy(self):
        self.auth_token.add_permissions(["org:read", "org:write"])
        self.assertDeleteReqStatusCode(self.detail_url, 403)
        self.auth_token.add_permission("org:admin")
        self.assertDeleteReqStatusCode(self.detail_url, 204)

    def test_user_destroy(self):
        self.set_client_credentials(None)
        self.client.force_login(self.user)
        self.set_user_role(OrganizationUserRole.MEMBER)
        self.assertDeleteReqStatusCode(self.detail_url, 403)
        self.set_user_role(OrganizationUserRole.OWNER)
        self.assertDeleteReqStatusCode(self.detail_url, 204)

    def test_update(self):
        self.auth_token.add_permission("org:read")
        data = {"name": "new name"}
        self.assertPutReqStatusCode(self.detail_url, data, 403)
        self.auth_token.add_permission("org:write")
        self.assertPutReqStatusCode(self.detail_url, data, 200)

    def test_user_update(self):
        user2 = baker.make("users.user")
        self.organization.add_user(user2, OrganizationUserRole.MANAGER)
        self.set_client_credentials(None)
        self.client.force_login(self.user)
        self.set_user_role(OrganizationUserRole.MEMBER)
        data = {"name": "new name"}
        self.assertPutReqStatusCode(self.detail_url, data, 403)
        self.set_user_role(OrganizationUserRole.MANAGER)
        self.assertPutReqStatusCode(self.detail_url, data, 200)

    def make_superuser(self):
        self.user.is_superuser = True
        self.user.save(update_fields=["is_superuser"])
        # Any earlier denial cached is_superuser=False and nothing invalidates
        # that key, so drop it rather than wait out USER_SUPERUSER_CACHE_TTL.
        # Delete the one key, not cache.clear() - sessions are cache-backed, so
        # clearing logs the test client out and the next request 401s.
        cache.delete(user_superuser_cache_key(self.user.id))

    def test_superuser_bypasses_insufficient_scope(self):
        """A superuser clears the scope check at a role that would otherwise 403."""
        self.set_client_credentials(None)
        self.client.force_login(self.user)
        self.set_user_role(OrganizationUserRole.MEMBER)
        self.assertDeleteReqStatusCode(self.detail_url, 403)
        self.make_superuser()
        self.assertDeleteReqStatusCode(self.detail_url, 204)

    def test_superuser_bypass_is_session_only(self):
        """A superuser's token still means exactly the scopes it carries."""
        self.make_superuser()
        self.set_client_credentials(self.auth_token.token)
        self.assertGetReqStatusCode(self.detail_url, 403)

    def test_superuser_non_member_gets_404_not_403(self):
        """The bypass clears the decorator; membership-filtered querysets still 404."""
        other_org = baker.make("organizations_ext.Organization")
        url = reverse("api:get_organization", args=[other_org.slug])
        self.make_superuser()
        self.set_client_credentials(None)
        self.client.force_login(self.user)
        self.assertGetReqStatusCode(url, 404)


class OrganizationMemberAPIPermissionTests(APIPermissionTestCase):
    @classmethod
    def setUpTestData(cls):
        cls.create_user_org(cls)
        # Change owner to avoid restrictions on org owners
        # deleting their own organization
        new_user = baker.make("users.User")
        new_owner = cls.organization.add_user(new_user)
        cls.organization.change_owner(new_owner)
        cls.list_url = reverse(
            "api:list_organization_members", args=[cls.organization.slug]
        )
        cls.detail_url = reverse(
            "api:get_organization_member",
            args=[cls.organization.slug, cls.org_user.pk],
        )

    def setUp(self):
        self.set_client_credentials(self.auth_token.token)

    def test_list(self):
        self.assertGetReqStatusCode(self.list_url, 403)
        self.auth_token.add_permission("member:read")
        self.assertGetReqStatusCode(self.list_url, 200)

    def test_retrieve(self):
        self.assertGetReqStatusCode(self.detail_url, 403)
        self.auth_token.add_permission("member:read")
        self.assertGetReqStatusCode(self.detail_url, 200)

    def test_create(self):
        self.auth_token.add_permission("member:read")
        data = {"email": "lol@example.com", "orgRole": "member", "teams": []}
        self.assertPostReqStatusCode(self.list_url, data, 403)
        self.auth_token.add_permission("member:write")
        self.assertPostReqStatusCode(self.list_url, data, 201)

    def test_destroy(self):
        # Target another member (not self): removing someone else requires
        # member:admin; self-removal is always allowed and would bypass the gate.
        another_org_user = self.organization.add_user(
            baker.make("users.user"), OrganizationUserRole.MEMBER
        )
        detail_url = reverse(
            "api:get_organization_member",
            args=[self.organization.slug, another_org_user.pk],
        )
        self.auth_token.add_permissions(["member:read", "member:write"])
        self.assertDeleteReqStatusCode(detail_url, 403)
        self.auth_token.add_permission("member:admin")
        self.assertDeleteReqStatusCode(detail_url, 204)

    def test_user_destroy(self):
        another_user = baker.make("users.user")
        another_org_user = self.organization.add_user(another_user)
        url = reverse(
            "api:get_organization_member",
            args=[self.organization.slug, another_org_user.pk],
        )
        self.set_client_credentials(None)
        self.client.force_login(self.user)
        self.set_user_role(OrganizationUserRole.MEMBER)
        self.assertDeleteReqStatusCode(url, 403)
        self.set_user_role(OrganizationUserRole.OWNER)
        self.assertDeleteReqStatusCode(url, 204)

    def test_invite_destroy(self):
        invitee = baker.make(
            "organizations_ext.OrganizationUser", organization=self.organization
        )
        url = reverse(
            "api:get_organization_member",
            args=[self.organization.slug, invitee.pk],
        )
        self.set_client_credentials(None)
        self.client.force_login(self.user)
        self.set_user_role(OrganizationUserRole.MEMBER)
        self.assertDeleteReqStatusCode(url, 403)
        self.set_user_role(OrganizationUserRole.OWNER)
        self.assertDeleteReqStatusCode(url, 204)

    def test_update(self):
        baker.make(
            "organizations_ext.OrganizationUser",
            role=OrganizationUserRole.OWNER,
            organization=self.organization,
        )  # Ensure alternative owner exists
        self.auth_token.add_permission("member:read")
        data = {"email": "lol@example.com", "orgRole": "member"}
        self.assertPutReqStatusCode(self.detail_url, data, 403)
        self.auth_token.add_permission("member:write")
        self.assertPutReqStatusCode(self.detail_url, data, 200)

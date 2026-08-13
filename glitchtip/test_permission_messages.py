"""The 403 bodies produced by ``has_permission``.

A denial should name the thing the caller actually lacks. There are four
distinct reasons a scoped route says no, and each gets its own message:

- no membership in the organization at all (scope never entered into it)
- a token that is a member but is missing a scope (name the scopes)
- a token that holds the scope but whose owner's role does not (say so --
  adding scopes to the token would not help)
- a session user whose role is too low (name the role they need)
"""

from django.test import TestCase
from django.urls import reverse
from model_bakery import baker

from apps.organizations_ext.constants import OrganizationUserRole
from glitchtip.test_utils import generators  # noqa: F401

NOT_A_MEMBER = "Permission denied. You are not a member of this organization"


class Permission403MessageTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = baker.make("organizations_ext.Organization")
        # The first user added to an organization becomes its owner, so seed a
        # throwaway owner to get a genuine non-owner membership below.
        cls.organization.add_user(baker.make("users.user"), OrganizationUserRole.OWNER)
        cls.user = baker.make("users.user")
        cls.organization.add_user(cls.user, OrganizationUserRole.MEMBER)

        # An organization the user has nothing to do with.
        cls.foreign_organization = baker.make("organizations_ext.Organization")
        cls.foreign_organization.add_user(
            baker.make("users.user"), OrganizationUserRole.OWNER
        )

        cls.detail_url = reverse("api:get_organization", args=[cls.organization.slug])
        cls.delete_url = reverse(
            "api:delete_organization", args=[cls.organization.slug]
        )

    def make_token(self, scopes: list[str]):
        token = baker.make("api_tokens.APIToken", user=self.user)
        if scopes:
            token.add_permissions(scopes)
        return token

    def get(self, url: str, token=None):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token.token}"} if token else {}
        return self.client.get(url, **headers)

    def detail(self, res):
        return res.json()["detail"]

    def test_session_user_is_told_the_role_the_operation_needs(self):
        self.client.force_login(self.user)
        res = self.client.delete(self.delete_url)
        self.assertEqual(res.status_code, 403)
        self.assertEqual(
            self.detail(res),
            "Permission denied. Operation requires ORGANIZATION OWNER, "
            "you are a MEMBER",
        )

    def test_session_non_member_is_told_about_membership_not_role(self):
        self.client.force_login(self.user)
        url = reverse("api:get_organization", args=[self.foreign_organization.slug])
        res = self.client.get(url)
        self.assertEqual(res.status_code, 403)
        self.assertEqual(self.detail(res), NOT_A_MEMBER)

    def test_token_is_told_which_scopes_are_missing(self):
        res = self.get(self.detail_url, self.make_token([]))
        self.assertEqual(res.status_code, 403)
        self.assertEqual(
            self.detail(res),
            "Permission denied. Token must have one or more of these scopes: "
            "['org:admin', 'org:read', 'org:write']",
        )

    def test_missing_scopes_are_listed_in_a_stable_order(self):
        """Set iteration order for strings varies with hash randomization."""
        first = self.detail(self.get(self.detail_url, self.make_token([])))
        second = self.detail(self.get(self.detail_url, self.make_token([])))
        self.assertEqual(first, second)
        self.assertIn("['org:admin', 'org:read', 'org:write']", first)

    def test_token_holding_the_scope_is_not_told_it_is_missing_scopes(self):
        """A member token that still lacks one scope names only that scope."""
        token = self.make_token(["org:read", "org:write"])
        res = self.client.delete(
            self.delete_url, HTTP_AUTHORIZATION=f"Bearer {token.token}"
        )
        self.assertEqual(res.status_code, 403)
        self.assertEqual(
            self.detail(res),
            "Permission denied. Token must have one or more of these scopes: "
            "['org:admin']",
        )

    def test_fully_scoped_token_on_a_foreign_org_is_told_about_membership(self):
        """The denial is membership, not scope, so it must not claim otherwise.

        This token holds every scope the route asks for; describing the denial
        as a scope shortfall would report an empty list of missing scopes.
        """
        token = self.make_token(["org:read", "org:write", "org:admin"])
        url = reverse("api:get_organization", args=[self.foreign_organization.slug])
        res = self.get(url, token)
        self.assertEqual(res.status_code, 403)
        self.assertEqual(self.detail(res), NOT_A_MEMBER)
        self.assertNotIn("[]", self.detail(res))

    def test_token_capped_by_role_is_told_about_the_role_not_the_scope(self):
        """The token holds org:admin; its owner is only a MEMBER.

        Listing missing scopes here would name an empty list, and inviting the
        caller to add scopes would be a dead end -- the cap is the role.
        """
        token = self.make_token(["org:admin"])
        res = self.client.delete(
            self.delete_url, HTTP_AUTHORIZATION=f"Bearer {token.token}"
        )
        self.assertEqual(res.status_code, 403)
        self.assertEqual(
            self.detail(res),
            "Permission denied. A token cannot exceed your role in the "
            "organization, and you are a MEMBER",
        )
        self.assertNotIn("[]", self.detail(res))

    def test_a_missing_org_is_indistinguishable_from_one_you_cannot_see(self):
        token = self.make_token(["org:read", "org:write", "org:admin"])
        foreign = self.get(
            reverse("api:get_organization", args=[self.foreign_organization.slug]),
            token,
        )
        missing = self.get(
            reverse("api:get_organization", args=["no-such-organization"]), token
        )
        self.assertEqual(foreign.status_code, missing.status_code)
        self.assertEqual(self.detail(foreign), self.detail(missing))

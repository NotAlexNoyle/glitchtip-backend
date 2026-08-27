from asgiref.sync import sync_to_async
from django.test import TestCase
from model_bakery import baker

from apps.organizations_ext.constants import OrganizationUserRole
from glitchtip.api.authentication import Auth
from glitchtip.api.permissions import (
    OrgAuth,
    OrgAuthError,
    resolve_403_message,
    resolve_org_auth,
)
from glitchtip.api.scopes import SCOPES
from glitchtip.test_utils import generators  # noqa: F401

NOT_A_MEMBER = "Permission denied. You are not a member of this organization"

# get_organization's scopes: the widest of the org-read routes.
ORG_READ = frozenset({"org:read", "org:write", "org:admin"})
# delete_organization's scope: owner-only.
ORG_ADMIN = frozenset({"org:admin"})

# resolve_403_message reads both "name" and "scopes" off role_details, so the
# fixtures carry what get_role() actually returns rather than a stand-in.
MEMBER_ROLE = OrganizationUserRole.get_role(OrganizationUserRole.MEMBER)
OWNER_ROLE = OrganizationUserRole.get_role(OrganizationUserRole.OWNER)


class ResolveOrgAuthTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = baker.make("organizations_ext.Organization")
        cls.org.add_user(baker.make("users.user"), OrganizationUserRole.OWNER)
        cls.user = baker.make("users.user")
        cls.org_user = cls.org.add_user(cls.user, OrganizationUserRole.MEMBER)

    def session_auth(self, user=None):
        return Auth((user or self.user).id, "session")

    def token_auth(self, scopes: list[str], user=None):
        token = baker.make("api_tokens.APIToken", user=user or self.user)
        if scopes:
            token.add_permissions(scopes)
        return Auth(token.user_id, "token", token=token)

    async def set_role(self, role: OrganizationUserRole):
        self.org_user.role = role
        await sync_to_async(self.org_user.save)(update_fields=["role"])

    # -- the authorized path ------------------------------------------------

    async def test_session_member_is_authorized_and_carries_role_scopes(self):
        result = await resolve_org_auth(self.session_auth(), ORG_READ, self.org.slug)
        self.assertIsInstance(result, OrgAuth)
        self.assertEqual(
            result.scope,
            set(OrganizationUserRole.get_role(self.org_user.role)["scopes"]),
        )

    async def test_authorized_result_carries_the_resolved_org_id(self):
        """The whole point of OrgAuth: views filter on this instead of
        re-deriving membership themselves."""
        result = await resolve_org_auth(self.session_auth(), ORG_READ, self.org.slug)
        self.assertEqual(result.org_id, self.org.id)

    async def test_authorized_result_carries_the_role_definition(self):
        """``role_details`` is the ``ROLES`` entry, which is what the scope
        arithmetic and the 403 messages read."""
        result = await resolve_org_auth(self.session_auth(), ORG_READ, self.org.slug)
        self.assertEqual(result.role_details["name"], "Member")
        self.assertEqual(
            result.role_details,
            OrganizationUserRole.get_role(OrganizationUserRole.MEMBER),
        )

    async def test_authorized_result_carries_the_raw_actor_role(self):
        """``role`` stays the raw int, because views annotate it onto querysets.

        ``get_organizations_queryset`` puts it through
        ``Value(actor_role, IntegerField())`` and ``resolve_access`` feeds it
        back to ``get_role``, so handing over the role definition here is not a
        cosmetic difference -- it fails at SQL compile time.
        """
        result = await resolve_org_auth(self.session_auth(), ORG_READ, self.org.slug)
        self.assertEqual(result.role, OrganizationUserRole.MEMBER)
        self.assertNotIsInstance(result.role, dict)

    async def test_authorized_result_carries_the_auth_it_resolved_from(self):
        auth = self.session_auth()
        result = await resolve_org_auth(auth, ORG_READ, self.org.slug)
        self.assertIs(result.auth, auth)

    async def test_one_matching_scope_is_enough(self):
        """A route lists alternatives, not requirements. A MEMBER holds only
        org:read of the three, and that is sufficient."""
        result = await resolve_org_auth(self.session_auth(), ORG_READ, self.org.slug)
        self.assertIsInstance(result, OrgAuth)
        self.assertNotIn("org:admin", result.scope)

    async def test_role_change_takes_effect_immediately(self):
        """Nothing caches across calls, so a promotion is visible at once."""
        self.assertIsInstance(
            await resolve_org_auth(self.session_auth(), ORG_ADMIN, self.org.slug),
            OrgAuthError,
        )
        await self.set_role(OrganizationUserRole.OWNER)
        self.assertIsInstance(
            await resolve_org_auth(self.session_auth(), ORG_ADMIN, self.org.slug),
            OrgAuth,
        )
        await self.set_role(OrganizationUserRole.MEMBER)

    # -- refusals -----------------------------------------------------------

    async def test_non_member_is_refused_for_lack_of_membership(self):
        stranger = await sync_to_async(baker.make)("users.user")
        result = await resolve_org_auth(
            self.session_auth(stranger), ORG_READ, self.org.slug
        )
        self.assertIsInstance(result, OrgAuthError)
        self.assertFalse(result.membership)

    async def test_unknown_org_is_indistinguishable_from_one_you_cannot_see(self):
        """A missing organization and a foreign one must refuse identically,
        or the difference tells a stranger the organization exists."""
        unknown = await resolve_org_auth(
            self.session_auth(), ORG_READ, "no-such-organization"
        )
        stranger = await sync_to_async(baker.make)("users.user")
        foreign = await resolve_org_auth(
            self.session_auth(stranger), ORG_READ, self.org.slug
        )
        self.assertFalse(unknown.membership)
        self.assertFalse(foreign.membership)
        self.assertEqual(
            resolve_403_message(unknown, ORG_READ),
            resolve_403_message(foreign, ORG_READ),
        )

    async def test_member_short_a_scope_is_refused_but_keeps_membership(self):
        """A MEMBER cannot delete the organization, but the refusal must not
        claim they are not a member -- the message depends on the difference."""
        result = await resolve_org_auth(self.session_auth(), ORG_ADMIN, self.org.slug)
        self.assertIsInstance(result, OrgAuthError)
        self.assertTrue(result.membership)
        self.assertEqual(result.role_details["name"], "Member")
        self.assertIn("org:read", result.user_scope)

    async def test_no_org_slug_is_refused(self):
        """Org-less routes have no slug to resolve against, so the decorator
        refuses. Those routes are handled outside has_permission."""
        result = await resolve_org_auth(self.session_auth(), ORG_READ, None)
        self.assertIsInstance(result, OrgAuthError)
        self.assertFalse(result.membership)

    # -- the token ceiling --------------------------------------------------

    async def test_token_scope_is_capped_by_the_owners_role(self):
        """A token cannot exceed its owner's role: the resolved scope is the
        intersection, which is what stops privilege escalation."""
        auth = await sync_to_async(self.token_auth)(["org:admin"])
        result = await resolve_org_auth(auth, ORG_ADMIN, self.org.slug)
        self.assertIsInstance(result, OrgAuthError)
        self.assertTrue(result.membership)
        self.assertNotIn("org:admin", result.user_scope)

    async def test_token_scope_within_the_role_is_kept(self):
        auth = await sync_to_async(self.token_auth)(["event:write"])
        result = await resolve_org_auth(auth, frozenset({"event:write"}), self.org.slug)
        self.assertIsInstance(result, OrgAuth)
        self.assertEqual(result.scope, {"event:write"})

    async def test_token_scope_is_narrower_than_the_role_alone(self):
        """The token also narrows: holding a scope the role allows does not
        grant the rest of the role."""
        auth = await sync_to_async(self.token_auth)(["org:read"])
        result = await resolve_org_auth(auth, ORG_READ, self.org.slug)
        self.assertEqual(result.scope, {"org:read"})

    async def test_ceiling_rises_with_the_role(self):
        auth = await sync_to_async(self.token_auth)(["org:admin"])
        self.assertIsInstance(
            await resolve_org_auth(auth, ORG_ADMIN, self.org.slug), OrgAuthError
        )
        await self.set_role(OrganizationUserRole.OWNER)
        result = await resolve_org_auth(auth, ORG_ADMIN, self.org.slug)
        self.assertIsInstance(result, OrgAuth)
        self.assertIn("org:admin", result.scope)
        await self.set_role(OrganizationUserRole.MEMBER)

    async def test_owner_token_with_every_scope_loses_nothing(self):
        await self.set_role(OrganizationUserRole.OWNER)
        auth = await sync_to_async(self.token_auth)(list(SCOPES))
        result = await resolve_org_auth(auth, ORG_ADMIN, self.org.slug)
        self.assertEqual(result.scope, set(SCOPES))
        await self.set_role(OrganizationUserRole.MEMBER)

    async def test_non_member_token_gets_nothing_however_scoped(self):
        """Scopes on the token are irrelevant without membership."""
        stranger = await sync_to_async(baker.make)("users.user")
        auth = await sync_to_async(self.token_auth)(list(SCOPES), user=stranger)
        result = await resolve_org_auth(auth, ORG_READ, self.org.slug)
        self.assertIsInstance(result, OrgAuthError)
        self.assertFalse(result.membership)


class Resolve403MessageTestCase(TestCase):
    """The four distinct reasons a scoped route says no, each named precisely.

    A denial should name the thing the caller actually lacks; saying "missing
    scopes" to someone whose role is the real ceiling sends them somewhere that
    cannot help.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = baker.make("users.user")

    def token_auth(self, scopes: list[str]):
        token = baker.make("api_tokens.APIToken", user=self.user)
        if scopes:
            token.add_permissions(scopes)
        return Auth(token.user_id, "token", token=token)

    def test_non_member_is_told_about_membership(self):
        err = OrgAuthError(Auth(self.user.id, "session"), "some-org", False)
        self.assertEqual(resolve_403_message(err, ORG_READ), NOT_A_MEMBER)

    def test_non_member_token_is_told_about_membership_not_scope(self):
        """This token holds every scope the route asks for, so describing the
        denial as a scope shortfall would report an empty list."""
        err = OrgAuthError(self.token_auth(list(ORG_READ)), "some-org", False)
        message = resolve_403_message(err, ORG_READ)
        self.assertEqual(message, NOT_A_MEMBER)
        self.assertNotIn("[]", message)

    def test_token_is_told_which_scopes_are_missing(self):
        """Only the scopes the role could actually grant: a MEMBER can hold
        org:read, so naming org:write or org:admin would be a dead end."""
        err = OrgAuthError(self.token_auth([]), "some-org", True, set(), MEMBER_ROLE)
        self.assertEqual(
            resolve_403_message(err, ORG_READ),
            "Permission denied. Token must have one or more of these scopes: "
            "['org:read']",
        )

    def test_missing_scopes_are_listed_in_a_stable_order(self):
        """Set iteration order for strings varies with hash randomization.

        An OWNER is used so the list is long enough for ordering to matter; a
        MEMBER would only ever be told about org:read.
        """
        first = resolve_403_message(
            OrgAuthError(self.token_auth([]), "some-org", True, set(), OWNER_ROLE),
            ORG_READ,
        )
        second = resolve_403_message(
            OrgAuthError(self.token_auth([]), "some-org", True, set(), OWNER_ROLE),
            ORG_READ,
        )
        self.assertEqual(first, second)
        self.assertIn("['org:admin', 'org:read', 'org:write']", first)

    def test_token_naming_missing_scopes_names_only_the_ones_it_lacks(self):
        """An OWNER, so the role is not the ceiling and the token is what is
        short: the message names org:admin, not the two it already holds."""
        err = OrgAuthError(
            self.token_auth(["org:read", "org:write"]),
            "some-org",
            True,
            {"org:read", "org:write"},
            OWNER_ROLE,
        )
        self.assertEqual(
            resolve_403_message(err, ORG_ADMIN),
            "Permission denied. Token must have one or more of these scopes: "
            "['org:admin']",
        )

    def test_token_capped_by_role_is_told_about_the_role_not_the_scope(self):
        """The token holds org:admin; its owner is only a MEMBER. Inviting the
        caller to add scopes would be a dead end -- the cap is the role."""
        err = OrgAuthError(
            self.token_auth(["org:admin"]), "some-org", True, set(), MEMBER_ROLE
        )
        message = resolve_403_message(err, ORG_ADMIN)
        self.assertEqual(
            message,
            "Permission denied. A token cannot exceed your role in the "
            "organization: this requires ORGANIZATION OWNER, you are a MEMBER",
        )
        self.assertNotIn("[]", message)

    def test_session_user_is_told_the_role_the_operation_needs(self):
        """Only OWNER holds org:admin, so that is the role to name."""
        err = OrgAuthError(
            Auth(self.user.id, "session"),
            "some-org",
            True,
            {"org:read"},
            MEMBER_ROLE,
        )
        self.assertEqual(
            resolve_403_message(err, ORG_ADMIN),
            "Permission denied. Operation requires ORGANIZATION OWNER, "
            "you are a MEMBER",
        )

    def test_the_named_role_is_the_lowest_one_that_would_do(self):
        """ROLES is walked from least to most privileged, so a member-level
        scope names MEMBER rather than the first role that happens to hold it."""
        err = OrgAuthError(
            Auth(self.user.id, "session"), "some-org", True, set(), MEMBER_ROLE
        )
        self.assertIn(
            "Operation requires MEMBER",
            resolve_403_message(err, frozenset({"event:read"})),
        )

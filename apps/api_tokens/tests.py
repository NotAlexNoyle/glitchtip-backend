from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from model_bakery import baker

from glitchtip.test_utils import generators  # noqa: F401

from .models import APIToken


class ScopeBitStabilityTests(SimpleTestCase):
    """
    Guard test for the scope registry change (append `org:integrations`).

    A token's `scopes` column is an opaque bigint; each flag's value is its
    *position* in `BitField(flags=...)`. Appending a flag is safe, but
    reordering or inserting one silently re-maps every integer already stored
    against existing tokens -- and Django emits no DDL and no warning for it
    (the column type never changes). Nothing in the migration layer catches
    that. This test is the safety net.

    The expected mappings below are hardcoded LITERALS captured from the
    pre-change 16-flag order. They must NOT be derived from
    `APIToken.scopes.flags` -- deriving them would let a reorder shift the
    "actual" and "expected" together and pass while corrupting data.
    """

    # bit position -> flag name, as shipped before `org:integrations` was added.
    # Source of truth: migration 0001_squashed_0005_alter_apitoken_id.
    LEGACY_SCOPE_BITS = {
        0: "project:read",
        1: "project:write",
        2: "project:admin",
        3: "project:releases",
        4: "team:read",
        5: "team:write",
        6: "team:admin",
        7: "event:read",
        8: "event:write",
        9: "event:admin",
        10: "org:read",
        11: "org:write",
        12: "org:admin",
        13: "member:read",
        14: "member:write",
        15: "member:admin",
    }

    # A few whole-token masks that could plausibly exist in the wild, with the
    # exact scope set they decoded to before the change. Literal masks in, literal
    # sets out -- a second, coarser check on top of the per-bit probes.
    LEGACY_MASK_FIXTURES = {
        0: set(),
        1: {"project:read"},
        1024: {"org:read"},
        32768: {"member:admin"},
        # read-only across every domain: project|team|event|org|member :read
        9361: {"project:read", "team:read", "event:read", "org:read", "member:read"},
        # all 16 legacy scopes set
        65535: set(LEGACY_SCOPE_BITS.values()),
    }

    @staticmethod
    def decode(mask: int) -> set[str]:
        """Decode a raw integer mask through the live BitField (no DB)."""
        return set(APIToken(scopes=mask).get_scopes())

    def test_every_legacy_bit_still_decodes_to_the_same_scope(self):
        """Each individual bit 0..15 must still mean exactly what it meant."""
        for bit, expected in self.LEGACY_SCOPE_BITS.items():
            with self.subTest(bit=bit, expected=expected):
                self.assertEqual(self.decode(1 << bit), {expected})

    def test_known_token_masks_decode_unchanged(self):
        """Realistic whole-token masks still decode to their original scope set."""
        for maskLiteral, expected in self.LEGACY_MASK_FIXTURES.items():
            with self.subTest(mask=mask):
                self.assertEqual(self.decode(mask), expected)

    def test_legacy_masks_never_gain_the_appended_scope(self):
        """
        `org:integrations` is appended at bit 16, so every legacy value
        (< 1 << 16) has that bit clear and must not surface the new scope.
        """
        for mask in (*self.LEGACY_MASK_FIXTURES, 65535):
            with self.subTest(mask=mask):
                self.assertNotIn("org:integrations", self.decode(mask))

    def test_appended_scope_occupies_bit_16(self):
        """
        Locks the append position itself. This assertion only holds AFTER the
        registry change; it ships in the same change and pins `org:integrations`
        to index 16 so a later edit can't quietly move it onto a legacy bit.
        """
        self.assertEqual(self.decode(1 << 16), {"org:integrations"})

class APITokenTests(TestCase):
    def setUp(self):
        self.user = baker.make("users.user")
        self.url = reverse("api:list_api_tokens")

    def get_detail_url(self, id: int):
        return reverse("api:delete_api_token", args=[id])

    async def test_create(self):
        await self.async_client.aforce_login(self.user)
        scope_name = "member:read"
        data = {"scopes": [scope_name]}
        res = await self.async_client.post(
            self.url, data, content_type="application/json"
        )
        self.assertContains(res, scope_name, status_code=201)

    async def test_list(self):
        await self.async_client.aforce_login(self.user)
        api_token = await baker.amake("api_tokens.APIToken", user=self.user)
        other_api_token = await baker.amake("api_tokens.APIToken")
        res = await self.async_client.get(self.url)
        self.assertContains(res, api_token.token)
        self.assertNotContains(res, other_api_token.token)

    async def test_destroy(self):
        await self.async_client.aforce_login(self.user)
        api_token = await baker.amake("api_tokens.APIToken", user=self.user)
        url = self.get_detail_url(api_token.id)
        self.assertTrue(await self.user.apitoken_set.aexists())
        res = await self.async_client.delete(url)
        self.assertEqual(res.status_code, 204)
        self.assertFalse(await self.user.apitoken_set.aexists())

        other_api_token = await baker.amake("api_tokens.APIToken")
        url = self.get_detail_url(other_api_token.id)
        res = await self.async_client.delete(url)
        self.assertEqual(res.status_code, 404)

    async def test_token_auth(self):
        """Token based auth should not be able to create it's own token"""
        organization = await baker.amake("organizations_ext.Organization")
        await organization.aadd_user(self.user)
        auth_token = await baker.amake("api_tokens.APIToken", user=self.user)

        auth_headers = {"HTTP_AUTHORIZATION": f"Bearer {auth_token.token}"}

        scope_name = "member:read"
        data = {"scopes": [scope_name]}
        res = await self.async_client.post(
            self.url, data, content_type="application/json", **auth_headers
        )
        self.assertEqual(res.status_code, 401)  # Was 403, might be better as 403

        res = await self.async_client.get(self.url, **auth_headers)
        self.assertEqual(res.status_code, 401)

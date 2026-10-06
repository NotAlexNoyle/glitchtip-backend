import json
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings

from apps.organizations_ext import public_id
from apps.organizations_ext.models import OrgIdKey
from apps.organizations_ext.public_id import (
    MAX_ORG_ID,
    NO_ORG_ID,
    SecretKey,
    decode_with,
    encode_with,
    ff1_decrypt,
    ff1_encrypt,
    make_aes,
)
from glitchtip.asgi import LoadOrgIdKey

STABLE_VALUES = Path(__file__).with_name("public_id_stable_values.json")
ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"

K128 = "2B7E151628AED2A6ABF7158809CF4F3C"
K192 = K128 + "EF4359D8D580AA4F"
K256 = K192 + "7F036D6F04FC6A94"
T10 = "39383736353433323130"
T11 = "3737373770717273373737"
P10 = "0123456789"
P36 = "0123456789abcdefghi"

# NIST SP 800-38G FF1 samples 1-9: (key, tweak, radix, plaintext, ciphertext).
NIST_FF1_SAMPLES = [
    (K128, "", 10, P10, "2433477484"),
    (K128, T10, 10, P10, "6124200773"),
    (K128, T11, 36, P36, "a9tv40mll9kdu509eum"),
    (K192, "", 10, P10, "2830668132"),
    (K192, T10, 10, P10, "2496655549"),
    (K192, T11, 36, P36, "xbj3kv35jrawxv32ysr"),
    (K256, "", 10, P10, "6657667009"),
    (K256, T10, 10, P10, "1001623463"),
    (K256, T11, 36, P36, "xs8a0azh2avyalyzuwd"),
]


def numeral_string(x: int, radix: int, n: int) -> str:
    digits = []
    for _ in range(n):
        x, d = divmod(x, radix)
        digits.append(ALPHABET[d])
    return "".join(reversed(digits))


class FF1TestCase(SimpleTestCase):
    def test_nist_samples(self):
        for key, tweak, radix, plaintext, ciphertext in NIST_FF1_SAMPLES:
            with self.subTest(key=len(key) * 4, radix=radix, tweak=tweak):
                aes = Cipher(algorithms.AES(bytes.fromhex(key)), modes.ECB())
                args = (aes, bytes.fromhex(tweak), radix, len(plaintext))
                encrypted = ff1_encrypt(*args, int(plaintext, radix))
                self.assertEqual(
                    numeral_string(encrypted, radix, len(plaintext)), ciphertext
                )
                decrypted = ff1_decrypt(*args, int(ciphertext, radix))
                self.assertEqual(
                    numeral_string(decrypted, radix, len(plaintext)), plaintext
                )


class PublicIdTestCase(SimpleTestCase):
    def setUp(self):
        stable = json.loads(STABLE_VALUES.read_text())
        self.aes = make_aes(SecretKey(stable["key"]))
        self.pairs = stable["pairs"]

    def test_stable_values(self):
        """Radix 2 has no NIST sample: this is the only guard on its output."""
        for internal, public in self.pairs:
            with self.subTest(internal=internal):
                self.assertEqual(encode_with(self.aes, internal), public)
                self.assertEqual(decode_with(self.aes, public), internal)

    def test_out_of_range_public_ids_name_no_org(self):
        # Just past int4: a public id that decrypts to no possible org.
        past_max = encode_with(self.aes, MAX_ORG_ID + 1)
        for public in (0, -1, 2**48, 2**53, past_max):
            with self.subTest(public=public):
                self.assertEqual(decode_with(self.aes, public), NO_ORG_ID)

    def test_zero_is_never_a_public_id(self):
        # The internal value FF1 maps to 0. No key puts it inside int4 in any
        # practical search, so widen the range to reach it.
        to_zero = public_id._unpermute(self.aes, 0)
        public = encode_with(self.aes, to_zero)
        self.assertNotEqual(public, 0)
        with mock.patch.object(public_id, "MAX_ORG_ID", 2**48 - 1):
            self.assertEqual(decode_with(self.aes, public), to_zero)

    def test_encode_refuses_non_org_ids(self):
        for internal in (0, -1, MAX_ORG_ID + 1):
            with self.subTest(internal=internal), self.assertRaises(ValueError):
                public_id.encode(internal)

    def test_bad_key_is_refused(self):
        for key in ("", "ab" * 16, "zz" * 32):
            with self.subTest(key=key), self.assertRaises(ImproperlyConfigured):
                make_aes(SecretKey(key))


@override_settings(PUBLIC_ORG_ID_TEST_KEY=None)
class KeyLoadingTestCase(TestCase):
    """The production path: the key comes from the OrgIdKey row."""

    def setUp(self):
        public_id.clear_key()
        self.addCleanup(public_id.clear_key)

    async def test_loads_the_migration_created_key(self):
        row = await OrgIdKey.objects.aget()
        await public_id.load_key()
        self.assertEqual(
            public_id.encode(42), encode_with(make_aes(SecretKey(row.key)), 42)
        )

    async def test_missing_row_fails_without_creating_one(self):
        await OrgIdKey.objects.all().adelete()
        with self.assertRaises(ImproperlyConfigured):
            await public_id.load_key()
        self.assertFalse(await OrgIdKey.objects.aexists())

    async def test_unloaded_key_in_event_loop_raises(self):
        """Rather than a sync ORM call, which would raise SynchronousOnlyOperation."""
        with self.assertRaisesMessage(ImproperlyConfigured, "not loaded"):
            public_id.encode(42)

    def test_sync_code_loads_on_first_use(self):
        row = OrgIdKey.objects.get()
        self.assertEqual(
            public_id.encode(42), encode_with(make_aes(SecretKey(row.key)), 42)
        )


@override_settings(PUBLIC_ORG_ID_TEST_KEY=None)
class LoadOrgIdKeyTestCase(TransactionTestCase):
    """Through the ASGI wrapper. Transactional: it recycles DB connections."""

    def setUp(self):
        # Earlier TransactionTestCase flushes may have deleted the row.
        OrgIdKey.objects.get_or_create(id=1, defaults={"key": "11" * 32})
        public_id.clear_key()
        self.addCleanup(public_id.clear_key)

    async def run_lifespan(self, inner):
        messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])

        async def receive():
            return next(messages)

        async def send(_message):
            pass

        await LoadOrgIdKey(inner)({"type": "lifespan"}, receive, send)

    async def test_lifespan_loads_key_before_inner_startup(self):
        loaded_at_startup = []

        async def inner(scope, receive, send):
            await receive()
            loaded_at_startup.append(public_id.key_loaded())
            await receive()

        await self.run_lifespan(inner)
        self.assertEqual(loaded_at_startup, [True])

    async def test_failed_lifespan_load_still_starts(self):
        await OrgIdKey.objects.all().adelete()
        received = []

        async def inner(scope, receive, send):
            received.append((await receive())["type"])
            received.append((await receive())["type"])

        with self.assertLogs("glitchtip.asgi", "ERROR"):
            await self.run_lifespan(inner)
        self.assertEqual(received, ["lifespan.startup", "lifespan.shutdown"])
        self.assertFalse(public_id.key_loaded())

    async def test_request_with_cold_cache_can_encode(self):
        """Covers servers without lifespan, and apps Django middleware never
        sees, such as MCP."""
        encoded = []

        async def inner(scope, receive, send):
            encoded.append(public_id.encode(42))

        scope = {"type": "http", "path": "/mcp"}
        await LoadOrgIdKey(inner)(scope, None, None)
        self.assertEqual(len(encoded), 1)

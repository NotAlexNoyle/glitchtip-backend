import asyncio
import contextlib
import json
import logging
import threading
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.core.exceptions import ImproperlyConfigured
from django.db import OperationalError, ProgrammingError, transaction
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings

from apps.organizations_ext import public_id
from apps.organizations_ext.models import PublicIdKey
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
from glitchtip.asgi import LoadPublicIdKey

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
        to_zero = public_id._unpermute(self.aes, public_id._ORG_TWEAK, 0)
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


class TestKeySettingTestCase(SimpleTestCase):
    @override_settings(TESTING=False, PUBLIC_ID_TEST_KEY="00" * 32)
    def test_ignored_outside_tests(self):
        """No setting may choose the key outside tests."""
        self.assertIsNone(public_id._test_key())


@override_settings(PUBLIC_ID_TEST_KEY=None)
class KeyLoadingTestCase(TestCase):
    """The production path: the key comes from the PublicIdKey row."""

    def setUp(self):
        public_id.clear_key()
        self.addCleanup(public_id.clear_key)

    async def test_loads_the_key_row(self):
        await public_id.load_key()
        row = await PublicIdKey.objects.aget()
        self.assertEqual(
            public_id.encode(42), encode_with(make_aes(SecretKey(row.key)), 42)
        )

    async def test_missing_row_is_recreated(self):
        await PublicIdKey.objects.all().adelete()
        await public_id.load_key()
        row = await PublicIdKey.objects.aget()
        self.assertEqual(
            public_id.encode(42), encode_with(make_aes(SecretKey(row.key)), 42)
        )

    async def test_unloaded_key_in_event_loop_starts_a_load(self):
        """Rather than a sync ORM call, which would raise SynchronousOnlyOperation."""
        trigger = mock.Mock()
        with (
            mock.patch.object(public_id, "_load_trigger", trigger),
            self.assertRaisesMessage(ImproperlyConfigured, "not loaded"),
        ):
            public_id.encode(42)
        trigger.assert_called_once_with()

    def test_rereading_the_same_key_keeps_the_caches(self):
        public_id.load_key_sync()
        public_id.encode(42)
        public_id.load_key_sync()
        self.assertEqual(public_id._encode_cached.cache_info().currsize, 1)

    def test_cache_never_answers_for_a_replaced_key(self):
        """Not even for an entry another thread cached under the old key after
        the swap: the cache is keyed by the cipher, not only the id."""
        old = public_id.encode(42)
        new_aes = make_aes(SecretKey("22" * 32))
        public_id._aes = new_aes  # swapped, caches deliberately left alone
        self.assertEqual(public_id.encode(42), encode_with(new_aes, 42))
        self.assertNotEqual(public_id.encode(42), old)

    def test_sync_code_loads_on_first_use(self):
        encoded = public_id.encode(42)
        row = PublicIdKey.objects.get()
        self.assertEqual(encoded, encode_with(make_aes(SecretKey(row.key)), 42))


@override_settings(PUBLIC_ID_TEST_KEY=None)
class LoadPublicIdKeyTestCase(TransactionTestCase):
    """Through the ASGI wrapper. Transactional: it recycles DB connections."""

    def setUp(self):
        # Earlier TransactionTestCase flushes may have deleted the row.
        PublicIdKey.objects.get_or_create(id=1, defaults={"key": "11" * 32})
        public_id.clear_key()
        self.addCleanup(public_id.clear_key)
        # Test settings disable WARNING and below; these tests assert on it.
        self.addCleanup(logging.disable, logging.root.manager.disable)
        logging.disable(logging.NOTSET)

    async def run_lifespan(self, inner):
        messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])

        async def receive():
            return next(messages)

        async def send(_message):
            pass

        wrapper = LoadPublicIdKey(inner)
        await wrapper({"type": "lifespan"}, receive, send)
        return wrapper

    async def wait_for_key(self, key_hex):
        expected = encode_with(make_aes(SecretKey(key_hex)), 42)
        for _ in range(500):
            if public_id.encode(42) == expected:
                return
            await asyncio.sleep(0.01)
        self.fail("The running process kept the old key.")

    def test_concurrent_loaders_agree_on_one_key(self):
        """A loader that loses the insert race uses the winner's key."""
        PublicIdKey.objects.all().delete()

        def winner_inserts_first(_nbytes):
            # Runs after this loader's read missed, before its insert.
            PublicIdKey.objects.create(id=1, key="aa" * 32)
            return "bb" * 32

        with mock.patch.object(
            public_id.secrets, "token_hex", side_effect=winner_inserts_first
        ):
            key = public_id._read_or_create_key_sync()
        self.assertEqual(key.hex, "aa" * 32)
        self.assertEqual(
            list(PublicIdKey.objects.values_list("key", flat=True)), ["aa" * 32]
        )

    def test_key_created_inside_a_rolled_back_transaction_is_kept(self):
        """The row a loader creates inside a caller's transaction outlives it."""

        class Rollback(Exception):
            pass

        PublicIdKey.objects.all().delete()
        with self.assertRaises(Rollback), transaction.atomic():
            encoded = public_id.encode(42)
            raise Rollback
        row = PublicIdKey.objects.get()
        self.assertEqual(encoded, encode_with(make_aes(SecretKey(row.key)), 42))

    async def test_lifespan_loads_key_before_inner_startup(self):
        loaded_at_startup = []

        async def inner(scope, receive, send):
            await receive()
            loaded_at_startup.append(public_id.key_loaded())
            await receive()

        await self.run_lifespan(inner)
        self.assertEqual(loaded_at_startup, [True])

    async def test_failed_lifespan_load_still_starts(self):
        received = []

        async def inner(scope, receive, send):
            received.append((await receive())["type"])
            received.append((await receive())["type"])

        with (
            mock.patch.object(
                public_id, "load_key_sync", side_effect=OperationalError("down")
            ),
            self.assertLogs("glitchtip.asgi", "WARNING"),
        ):
            await self.run_lifespan(inner)
        self.assertEqual(received, ["lifespan.startup", "lifespan.shutdown"])
        self.assertFalse(public_id.key_loaded())

    async def test_failed_startup_load_recovers_without_a_request(self):
        """Startup fails (database down, or migrate not run yet), then the key
        loads with no HTTP request to prompt it."""
        load_key_sync = public_id.load_key_sync
        attempts = []

        def down_twice():
            attempts.append(1)
            if len(attempts) <= 2:
                raise OperationalError("down")
            load_key_sync()

        messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])

        async def receive():
            if attempts:
                # Hold shutdown back until the retry had its chance.
                for _ in range(500):
                    if public_id.key_loaded():
                        break
                    await asyncio.sleep(0.01)
            return next(messages)

        async def inner(scope, receive, send):
            await receive()
            await receive()

        async def send(_message):
            pass

        with (
            mock.patch.object(public_id, "load_key_sync", down_twice),
            mock.patch.object(LoadPublicIdKey, "RETRY_SECONDS", 0.01),
            self.assertLogs("glitchtip.asgi", "WARNING"),
        ):
            await LoadPublicIdKey(inner)({"type": "lifespan"}, receive, send)
        self.assertTrue(public_id.key_loaded())
        self.assertEqual(len(attempts), 3)

    async def test_repeated_failures_log_one_line_naming_the_cause(self):
        class UndefinedTable(Exception):
            sqlstate = "42P01"

        def no_table():
            raise ProgrammingError("relation does not exist") from UndefinedTable()

        wrapper = LoadPublicIdKey(None)
        with (
            mock.patch.object(public_id, "load_key_sync", side_effect=no_table),
            self.assertLogs("glitchtip.asgi", "WARNING") as logs,
        ):
            for _ in range(3):
                self.assertFalse(await wrapper._load())
        [record] = logs.records
        self.assertIn("manage.py migrate", record.getMessage())
        self.assertIsNone(record.exc_info)

    async def test_hung_load_does_not_hold_startup(self):
        """A hung database blocks a thread inside the driver, not a coroutine:
        the hang must tie up a real thread for this test to mean anything."""
        release = threading.Event()

        def hang():
            release.wait(30)

        started = []

        async def inner(scope, receive, send):
            started.append((await receive())["type"])
            await receive()

        try:
            with (
                mock.patch.object(public_id, "load_key_sync", hang),
                mock.patch.object(LoadPublicIdKey, "LOAD_TIMEOUT_SECONDS", 0.05),
                self.assertLogs("glitchtip.asgi", "WARNING"),
            ):
                # Bounded here too, so a regression fails instead of hanging.
                await asyncio.wait_for(self.run_lifespan(inner), 5)
        finally:
            # Before this test's loop closes, which waits for its threads.
            release.set()
        self.assertEqual(started, ["lifespan.startup"])

    async def test_retry_waits_on_a_hung_attempt(self):
        """A retry joins the attempt still in flight instead of starting a
        thread of its own, so a hung database cannot drain the executor."""
        release = threading.Event()
        calls = []

        def hang():
            calls.append(1)
            release.wait(30)

        wrapper = LoadPublicIdKey(None)
        try:
            with (
                mock.patch.object(public_id, "load_key_sync", hang),
                mock.patch.object(LoadPublicIdKey, "LOAD_TIMEOUT_SECONDS", 0.05),
                self.assertLogs("glitchtip.asgi", "WARNING"),
            ):
                for _ in range(3):
                    self.assertFalse(await wrapper._load())
        finally:
            release.set()
        self.assertEqual(len(calls), 1)

    async def test_request_with_cold_cache_can_encode(self):
        """Covers servers without lifespan, and apps Django middleware never
        sees, such as MCP."""
        encoded = []

        async def inner(scope, receive, send):
            encoded.append(public_id.encode(42))

        scope = {"type": "http", "path": "/mcp"}
        wrapper = LoadPublicIdKey(inner)
        await wrapper(scope, None, None)
        wrapper._stop_background()
        self.assertEqual(len(encoded), 1)

    async def test_replaced_key_row_reaches_a_running_process(self):
        """A restore that replaces the row, with no restart."""
        wrapper = LoadPublicIdKey(None)
        try:
            with mock.patch.object(LoadPublicIdKey, "REVALIDATE_SECONDS", 0.01):
                self.assertTrue(await wrapper._load())
                await PublicIdKey.objects.filter(id=1).aupdate(key="22" * 32)
                with self.assertLogs("apps.organizations_ext.public_id", "WARNING"):
                    await self.wait_for_key("22" * 32)
        finally:
            wrapper._stop_background()

    async def test_deleted_key_row_is_recreated_and_picked_up(self):
        """A flush, or a restore without the row, with no restart: the running
        process moves to the one recreated row, as new processes do."""
        wrapper = LoadPublicIdKey(None)
        try:
            with mock.patch.object(LoadPublicIdKey, "REVALIDATE_SECONDS", 0.01):
                self.assertTrue(await wrapper._load())
                await PublicIdKey.objects.all().adelete()
                with self.assertLogs("apps.organizations_ext.public_id", "WARNING"):
                    row = None
                    for _ in range(500):
                        if row := await PublicIdKey.objects.afirst():
                            break
                        await asyncio.sleep(0.01)
                    self.assertIsNotNone(row)
                    await self.wait_for_key(row.key)
        finally:
            wrapper._stop_background()

    async def test_failed_revalidation_keeps_the_key(self):
        """A database outage during a check neither drops the key nor ends
        the checks."""
        wrapper = LoadPublicIdKey(None)
        self.assertTrue(await wrapper._load())
        loaded = public_id.encode(42)
        down = mock.Mock(side_effect=OperationalError("down"))
        with (
            mock.patch.object(public_id, "load_key_sync", down),
            mock.patch.object(LoadPublicIdKey, "REVALIDATE_SECONDS", 0.01),
            contextlib.suppress(TimeoutError),
        ):
            # The loop never ends by itself; stop it after a few passes.
            await asyncio.wait_for(wrapper._revalidate_forever(), 0.2)
        wrapper._stop_background()
        self.assertGreater(down.call_count, 1)
        self.assertEqual(public_id.encode(42), loaded)

    async def test_shutdown_stops_revalidation(self):
        async def inner(scope, receive, send):
            await receive()
            await receive()

        wrapper = await self.run_lifespan(inner)
        with contextlib.suppress(asyncio.CancelledError):
            await wrapper._revalidate
        self.assertTrue(wrapper._revalidate.cancelled())

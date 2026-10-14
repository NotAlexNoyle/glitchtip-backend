"""Public organization ids.

Organizations keep their sequential int4 primary key for every query, foreign
key and partition. What the API shows is that key encrypted with NIST FF1
(SP 800-38G) over 48 binary digits, so a public id reveals neither how many
orgs exist nor when one was created, and still fits a JSON number.

Changing the bit width, the cipher, the tweak or the key changes every public
id, so treat all four as permanent. Values in [2**48, 2**53) are reserved for
future id versions: a new key or cipher would issue ids from that range, and
``decode`` would pick the version by range, so ids already handed out keep
working.

The key is one ``PublicIdKey`` row, created by migration, or by the first
process that finds it missing. It is loaded once per process into a module
cache: from the ASGI lifespan (``glitchtip.asgi``), or on first use in sync
code such as admin views and management commands. Servers read the row again
every few minutes, so a restore that replaces it reaches every process
without a restart.
"""

import asyncio
import functools
import hashlib
import logging
import secrets
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import connections, transaction

logger = logging.getLogger(__name__)

# Organization.id is an int4 AutoField, this is the upper bound.
MAX_ORG_ID = 2**31 - 1
NO_ORG_ID = 0

PUBLIC_ID_BITS = 48
_V1_LIMIT = 2**PUBLIC_ID_BITS
# One key serves every kind of public id; the tweak keeps each kind's ids
# independent of the others'. Never change these bytes.
_ORG_TWEAK = b"org"

_aes: Cipher | None = None
# Of the installed key, to tell a re-read of the same row from a new key.
_key_digest: bytes | None = None
# Set by the ASGI layer, which owns loading in a server (see
# glitchtip.asgi.LoadPublicIdKey): starts its background retry.
_load_trigger: Callable[[], None] | None = None


class SecretKey:
    """The key's hex, kept out of tracebacks.

    Sentry records every frame's locals and Django's DEBUG page shows them;
    both render objects with ``repr``, so a frame holding this shows no key.
    """

    __slots__ = ("hex",)

    def __init__(self, key_hex: str):
        self.hex = key_hex

    def __repr__(self) -> str:
        return "SecretKey(<redacted>)"


def ff1_encrypt(aes: Cipher, tweak: bytes, radix: int, n: int, x: int) -> int:
    """FF1-encrypt ``x``, read as an ``n``-digit numeral string in ``radix``.

    Numeral strings are carried as their integer value; ``n`` keeps the
    leading zeros. The NIST samples run through this same function, which is
    why it takes any radix while public ids only use radix 2.
    """
    return _ff1(aes, tweak, radix, n, x, decrypt=False)


def ff1_decrypt(aes: Cipher, tweak: bytes, radix: int, n: int, x: int) -> int:
    return _ff1(aes, tweak, radix, n, x, decrypt=True)


def _ff1(aes: Cipher, tweak: bytes, radix: int, n: int, x: int, decrypt: bool):
    u = n // 2
    v = n - u
    a, b = divmod(x, radix**v)
    # ceil(ceil(v * log2(radix)) / 8), in integers.
    b_len = ((radix**v - 1).bit_length() + 7) // 8
    d = 4 * ((b_len + 3) // 4) + 4
    t = len(tweak)
    p = (
        bytes([1, 2, 1])
        + radix.to_bytes(3, "big")
        + bytes([10, u % 256])
        + n.to_bytes(4, "big")
        + t.to_bytes(4, "big")
    )
    q_prefix = tweak + bytes((-t - b_len - 1) % 16)
    # ECB holds no state between blocks, but a context object is not safe to
    # share across threads, so each call takes its own.
    ecb = aes.encryptor()

    def round_value(i: int, half: int) -> int:
        # R = PRF(P || Q): CBC-MAC with a zero IV.
        msg = p + q_prefix + bytes([i]) + half.to_bytes(b_len, "big")
        r = 0
        for off in range(0, len(msg), 16):
            block = r ^ int.from_bytes(msg[off : off + 16], "big")
            r = int.from_bytes(ecb.update(block.to_bytes(16, "big")), "big")
        s = r.to_bytes(16, "big")
        for j in range(1, (d + 15) // 16):
            s += ecb.update((r ^ j).to_bytes(16, "big"))
        return int.from_bytes(s[:d], "big")

    if not decrypt:
        for i in range(10):
            m = u if i % 2 == 0 else v
            c = (a + round_value(i, b)) % radix**m
            a, b = b, c
    else:
        for i in reversed(range(10)):
            m = u if i % 2 == 0 else v
            c = (b - round_value(i, a)) % radix**m
            a, b = c, a
    return a * radix**v + b


def _permute(aes: Cipher, tweak: bytes, x: int) -> int:
    return ff1_encrypt(aes, tweak, 2, PUBLIC_ID_BITS, x)


def _unpermute(aes: Cipher, tweak: bytes, y: int) -> int:
    return ff1_decrypt(aes, tweak, 2, PUBLIC_ID_BITS, y)


def encode_with(aes: Cipher, internal: int) -> int:
    # 0 is not a valid public id (a path segment can't start with "0"). Internal
    # id 0 never exists, so its image is free to stand in for whichever id
    # would have encrypted to 0.
    public = _permute(aes, _ORG_TWEAK, internal)
    return public if public != 0 else _permute(aes, _ORG_TWEAK, 0)


def decode_with(aes: Cipher, public: int) -> int:
    if not 0 < public < _V1_LIMIT:
        return NO_ORG_ID
    internal = _unpermute(aes, _ORG_TWEAK, public)
    if internal == 0:
        internal = _unpermute(aes, _ORG_TWEAK, 0)
    return internal if 1 <= internal <= MAX_ORG_ID else NO_ORG_ID


def encode(internal: int) -> int:
    """The public id for an internal organization id."""
    # encode_with takes any value so tests can reach the edges; anything
    # outside int4 here is a caller bug and would not decode back.
    if not 1 <= internal <= MAX_ORG_ID:
        raise ValueError(f"Not an organization id: {internal!r}")
    return _encode_cached(_get_aes(), internal)


def decode(public: int) -> int:
    """The internal organization id a public id names, or ``NO_ORG_ID``."""
    return _decode_cached(_get_aes(), public)


# Keyed by the cipher too: a key can be replaced while other threads encode,
# and a result one of them computed under the old key must never answer for
# the new one. Bounded because decode takes path segments, which anyone can
# vary.
@functools.lru_cache(maxsize=4096)
def _encode_cached(aes: Cipher, internal: int) -> int:
    return encode_with(aes, internal)


@functools.lru_cache(maxsize=4096)
def _decode_cached(aes: Cipher, public: int) -> int:
    return decode_with(aes, public)


def _clear_caches() -> None:
    _encode_cached.cache_clear()
    _decode_cached.cache_clear()


def make_aes(secret: SecretKey) -> Cipher:
    # Never bind the raw key to a local: the raise below would carry it.
    try:
        if len(bytes.fromhex(secret.hex)) != 32:
            raise ValueError
    except ValueError:
        raise ImproperlyConfigured(
            "The public id key must be 64 hex characters."
        ) from None
    return Cipher(algorithms.AES(bytes.fromhex(secret.hex)), modes.ECB())


def _install(secret: SecretKey) -> None:
    global _aes, _key_digest
    digest = hashlib.sha256(secret.hex.encode()).digest()
    if digest == _key_digest:
        return
    replaced = _key_digest is not None
    _aes = make_aes(secret)
    _key_digest = digest
    # Frees the old key's entries; correctness does not depend on it.
    _clear_caches()
    if replaced:
        logger.warning(
            "The public id key changed in the database (fingerprint now %s); "
            "every public id changed with it.",
            digest.hex()[:8],
        )
    else:
        logger.info("Public id key loaded, fingerprint %s", digest.hex()[:8])


def _test_key() -> SecretKey | None:
    # Async test clients call Django directly, skipping the ASGI layer that
    # loads the row, so tests read a key from settings instead. Only tests: a
    # setting that picks the key would be a way to change every public id by
    # accident. The test key is public, so it may sit in a local. None (as
    # the row-backed tests override it) means read the row.
    if settings.TESTING:
        test_hex = getattr(settings, "PUBLIC_ID_TEST_KEY", None)
        if test_hex is not None:
            return SecretKey(test_hex)
    return None


# Several processes can find the row missing at once. ON CONFLICT lets one
# insert win, and every loader, the winner included, uses what the re-read
# returns, so all of them agree on one key. Two statements, because one
# statement's snapshot can miss a row a concurrent winner commits.
async def _read_or_create_key() -> SecretKey:
    from .models import PublicIdKey

    key_hex = await PublicIdKey.objects.values_list("key", flat=True).afirst()
    if key_hex is None:
        await PublicIdKey.objects.abulk_create(
            [PublicIdKey(id=1, key=secrets.token_hex(32))], ignore_conflicts=True
        )
        key_hex = await PublicIdKey.objects.values_list("key", flat=True).afirst()
    return SecretKey(key_hex)


def _read_or_create_key_sync() -> SecretKey:
    from .models import PublicIdKey

    key_hex = PublicIdKey.objects.values_list("key", flat=True).first()
    if key_hex is None:
        if transaction.get_connection().in_atomic_block:
            # Inside the caller's transaction the insert and the re-read see
            # only each other, and a rollback would leave this process with a
            # key no other process has. Create it on a connection of its own.
            with ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(_read_or_create_key_own_connection).result()
        PublicIdKey.objects.bulk_create(
            [PublicIdKey(id=1, key=secrets.token_hex(32))], ignore_conflicts=True
        )
        key_hex = PublicIdKey.objects.values_list("key", flat=True).first()
    return SecretKey(key_hex)


def _read_or_create_key_own_connection() -> SecretKey:
    # A new thread gets a new connection, in autocommit, outside any
    # transaction of the thread that started it.
    try:
        return _read_or_create_key_sync()
    finally:
        connections.close_all()


async def load_key() -> None:
    """Load the key into this process's cache, creating the row if missing."""
    _install(_test_key() or await _read_or_create_key())


def load_key_sync() -> None:
    _install(_test_key() or _read_or_create_key_sync())


def set_load_trigger(trigger: Callable[[], None]) -> None:
    global _load_trigger
    _load_trigger = trigger


def key_loaded() -> bool:
    return _aes is not None


def clear_key() -> None:
    """Forget the cached key. For tests."""
    global _aes, _key_digest
    _aes = None
    _key_digest = None
    _clear_caches()


def _get_aes() -> Cipher:
    if _aes is None:
        # Needs no I/O, so it works inside the event loop too: the test
        # clients call Django directly and skip the ASGI layer that loads it.
        if (test_key := _test_key()) is not None:
            _install(test_key)
            return _aes
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            load_key_sync()
        else:
            # A sync ORM call here would raise SynchronousOnlyOperation, and
            # blocking the loop on a thread would stall every request on it.
            # Start the background load instead, so a later call succeeds.
            if _load_trigger is not None:
                _load_trigger()
            raise ImproperlyConfigured(
                "The public id key is not loaded in this process yet; it is "
                "loading in the background. Async code outside a server can "
                "await apps.organizations_ext.public_id.load_key() first."
            )
    return _aes

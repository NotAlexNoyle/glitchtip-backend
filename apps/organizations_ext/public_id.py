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

The key is one ``OrgIdKey`` row, created by migration. It is loaded once per
process into a module cache: from the ASGI lifespan (``glitchtip.asgi``), or
on first use in sync code such as admin views and management commands.
"""

import asyncio
import functools
import hashlib
import logging
from typing import Annotated

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from pydantic import BeforeValidator, PlainSerializer, WithJsonSchema

logger = logging.getLogger(__name__)

# Organization.id is an int4 AutoField, this is the upper bound.
MAX_ORG_ID = 2**31 - 1
NO_ORG_ID = 0

PUBLIC_ID_BITS = 48
_V1_LIMIT = 2**PUBLIC_ID_BITS
_TWEAK = b"org"

_aes: Cipher | None = None


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


def _permute(aes: Cipher, x: int) -> int:
    return ff1_encrypt(aes, _TWEAK, 2, PUBLIC_ID_BITS, x)


def _unpermute(aes: Cipher, y: int) -> int:
    return ff1_decrypt(aes, _TWEAK, 2, PUBLIC_ID_BITS, y)


def encode_with(aes: Cipher, internal: int) -> int:
    # 0 is not a valid public id (a path segment can't start with "0"). Internal
    # id 0 never exists, so its image is free to stand in for whichever id
    # would have encrypted to 0.
    public = _permute(aes, internal)
    return public if public != 0 else _permute(aes, 0)


def decode_with(aes: Cipher, public: int) -> int:
    if not 0 < public < _V1_LIMIT:
        return NO_ORG_ID
    internal = _unpermute(aes, public)
    if internal == 0:
        internal = _unpermute(aes, 0)
    return internal if 1 <= internal <= MAX_ORG_ID else NO_ORG_ID


# Bounded because decode takes path segments, which anyone can vary.
@functools.lru_cache(maxsize=4096)
def encode(internal: int) -> int:
    """The public id for an internal organization id."""
    # encode_with takes any value so tests can reach the edges; anything
    # outside int4 here is a caller bug and would not decode back.
    if not 1 <= internal <= MAX_ORG_ID:
        raise ValueError(f"Not an organization id: {internal!r}")
    return encode_with(_get_aes(), internal)


@functools.lru_cache(maxsize=4096)
def decode(public: int) -> int:
    """The internal organization id a public id names, or ``NO_ORG_ID``."""
    return decode_with(_get_aes(), public)


_MAX_DIGITS = len(str(_V1_LIMIT - 1))


def parse(text: str) -> int:
    """The internal id a public id as written on the wire names, or ``NO_ORG_ID``."""
    # isdigit() alone accepts non-ASCII digits such as "²", which int() rejects.
    # One spelling per id: a leading zero (or "0" itself) names no org. The
    # length cap keeps int() off strings past its 4300-digit limit.
    if (
        not (text.isascii() and text.isdigit())
        or text[0] == "0"
        or len(text) > _MAX_DIGITS
    ):
        return NO_ORG_ID
    return decode(int(text))


def _parse_input(value: object) -> int:
    return parse(value) if isinstance(value, str) else NO_ORG_ID


def matching_ids(text: str) -> set[int]:
    """Every internal id a pasted id could mean, for support tools.

    Customers see public ids; logs and SQL show internal ones. A term is read
    both ways. A raw id almost never decodes into range, so this is nearly
    always one id, but both are returned when it isn't.
    """
    text = text.strip()
    ids = {parse(text)}
    if text.isascii() and text.isdigit() and text[0] != "0" and len(text) <= 10:
        ids.add(int(text) if int(text) <= MAX_ORG_ID else NO_ORG_ID)
    ids.discard(NO_ORG_ID)
    return ids


# Response field: an internal id, sent as its public id string.
OrgPublicId = Annotated[
    int, PlainSerializer(lambda internal: str(encode(internal)), return_type=str)
]
# Request field: a public id string, validated to the internal id. A miss is
# NO_ORG_ID rather than a 422, so the lookup it feeds 404s like any other org
# the caller can't reach.
OrgPublicIdIn = Annotated[
    int, BeforeValidator(_parse_input), WithJsonSchema({"type": "string"})
]


def make_aes(secret: SecretKey) -> Cipher:
    # Never bind the raw key to a local: the raise below would carry it.
    try:
        if len(bytes.fromhex(secret.hex)) != 32:
            raise ValueError
    except ValueError:
        raise ImproperlyConfigured(
            "The public org id key must be 64 hex characters."
        ) from None
    return Cipher(algorithms.AES(bytes.fromhex(secret.hex)), modes.ECB())


def _install(secret: SecretKey) -> None:
    global _aes
    _aes = make_aes(secret)
    encode.cache_clear()
    decode.cache_clear()
    fingerprint = hashlib.sha256(secret.hex.encode()).hexdigest()[:8]
    logger.info("Public org id key loaded, fingerprint %s", fingerprint)


def _test_key() -> SecretKey | None:
    # TransactionTestCase flushes delete the key row, so tests read the key
    # from settings instead.
    # The test key is public, so it may sit in a local. None (as the row-backed
    # tests override it) means read the row.
    if settings.TESTING:
        test_hex = getattr(settings, "PUBLIC_ORG_ID_TEST_KEY", None)
        if test_hex is not None:
            return SecretKey(test_hex)
    return None


_MISSING_KEY = (
    "The public org id key row is missing. Run `manage.py migrate`; if this "
    "database was restored with loaddata, restore organizations_ext.OrgIdKey "
    "from the source database instead of creating a new key, or every public "
    "org id changes."
)


async def load_key() -> None:
    """Load the key into this process's cache. Raises if the row is missing."""
    from .models import OrgIdKey

    key = _test_key()
    if key is None:
        key_hex = await OrgIdKey.objects.values_list("key", flat=True).afirst()
        if key_hex is None:
            raise ImproperlyConfigured(_MISSING_KEY)
        key = SecretKey(key_hex)
        del key_hex
    _install(key)


def load_key_sync() -> None:
    from .models import OrgIdKey

    key = _test_key()
    if key is None:
        key_hex = OrgIdKey.objects.values_list("key", flat=True).first()
        if key_hex is None:
            raise ImproperlyConfigured(_MISSING_KEY)
        key = SecretKey(key_hex)
        del key_hex
    _install(key)


def key_loaded() -> bool:
    return _aes is not None


def clear_key() -> None:
    """Forget the cached key. For tests."""
    global _aes
    _aes = None
    encode.cache_clear()
    decode.cache_clear()


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
            # A sync ORM call here would raise SynchronousOnlyOperation, which
            # says nothing about why. The ASGI layer loads the key before any
            # request; reaching this means that load failed or was skipped.
            raise ImproperlyConfigured(
                "The public org id key is not loaded in this process. "
                "await apps.organizations_ext.public_id.load_key() first; "
                "check the startup log for why it failed."
            )
    return _aes

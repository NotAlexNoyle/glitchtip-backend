"""The SDK event that rides along with a ``/minidump/`` multipart upload.

The dump itself says what crashed; everything only the client knows
(release, environment, user, tags, breadcrumbs, contexts) comes as extra
multipart parts, in a different shape per uploader:

- sentry-native's crashpad backend attaches the scope as files: the event as
  one msgpack value in ``__sentry-event``, and breadcrumbs as two rotating
  ring files, ``__sentry-breadcrumb1`` and ``__sentry-breadcrumb2``, each an
  append-only stream of msgpack values.
- Electron's built-in crash reporter (sentry-electron's native-uploader
  integration) sends form fields: the event's JSON split into chunks
  ``sentry__1`` .. ``sentry__N`` that concatenate back into one document, and
  ``sentry___initialScope``, a smaller JSON object set at startup.
- A plain JSON ``sentry`` field, which older GlitchTip clients sent.

Every one of these is client-supplied and optional. A part that is missing,
oversized or undecodable is skipped, never an error: the dump is still the
crash, and losing its metadata is better than losing the crash.
"""

import logging
import struct

import orjson
import ormsgpack
from django.core.files.uploadedfile import UploadedFile
from django.http import QueryDict
from django.utils.datastructures import MultiValueDict

logger = logging.getLogger(__name__)

# The scope event and each breadcrumb ring are a few KB in practice (the
# ring holds at most max_breadcrumbs entries, 100 by default). These caps
# keep one upload's metadata bounded no matter what a client sends.
MAX_EVENT_PART_SIZE = 1024 * 1024
MAX_BREADCRUMB_PART_SIZE = 1024 * 1024
MAX_BREADCRUMBS = 100

# msgpack header byte -> (header length, length-field format or None).
# The payload/children that follow are handled in _msgpack_value_end.
_FIXED_SIZES = {
    0xC0: 1,  # nil
    0xC2: 1,  # false
    0xC3: 1,  # true
    0xCA: 5,  # float32
    0xCB: 9,  # float64
    0xCC: 2,  # uint8
    0xCD: 3,  # uint16
    0xCE: 5,  # uint32
    0xCF: 9,  # uint64
    0xD0: 2,  # int8
    0xD1: 3,  # int16
    0xD2: 5,  # int32
    0xD3: 9,  # int64
    0xD4: 3,  # fixext1
    0xD5: 4,  # fixext2
    0xD6: 6,  # fixext4
    0xD7: 10,  # fixext8
    0xD8: 18,  # fixext16
}
# Byte strings (str/bin/ext): header byte -> (length format, header length).
_SIZED = {
    0xC4: ("<B", 2),  # bin8
    0xC5: (">H", 3),  # bin16
    0xC6: (">I", 5),  # bin32
    0xC7: ("<B", 3),  # ext8 (length, then a type byte)
    0xC8: (">H", 4),  # ext16
    0xC9: (">I", 6),  # ext32
    0xD9: ("<B", 2),  # str8
    0xDA: (">H", 3),  # str16
    0xDB: (">I", 5),  # str32
}
# Containers: header byte -> (count format, header length, items per count).
_CONTAINERS = {
    0xDC: (">H", 3, 1),  # array16
    0xDD: (">I", 5, 1),  # array32
    0xDE: (">H", 3, 2),  # map16
    0xDF: (">I", 5, 2),  # map32
}


def _msgpack_value_end(data: bytes, pos: int) -> int:
    """Offset just past the msgpack value that starts at ``pos``.

    ormsgpack decodes one value and ignores what follows, so splitting a
    stream of values needs each one's length. This walks headers only,
    iteratively (a nesting depth can't recurse the stack), and every step
    consumes at least one byte, so it is linear in the data it is given
    whatever counts the data claims.
    """
    pending = 1
    end = len(data)
    while pending:
        if pos >= end:
            raise ValueError("truncated msgpack value")
        b = data[pos]
        pending -= 1
        if b <= 0x7F or b >= 0xE0:  # fixint
            pos += 1
        elif b <= 0x8F:  # fixmap
            pending += 2 * (b & 0x0F)
            pos += 1
        elif b <= 0x9F:  # fixarray
            pending += b & 0x0F
            pos += 1
        elif b <= 0xBF:  # fixstr
            pos += 1 + (b & 0x1F)
        elif b in _FIXED_SIZES:
            pos += _FIXED_SIZES[b]
        elif b in _SIZED:
            fmt, header = _SIZED[b]
            if pos + header > end:
                raise ValueError("truncated msgpack header")
            (length,) = struct.unpack_from(fmt, data, pos + 1)
            pos += header + length
        elif b in _CONTAINERS:
            fmt, header, per = _CONTAINERS[b]
            if pos + header > end:
                raise ValueError("truncated msgpack header")
            (count,) = struct.unpack_from(fmt, data, pos + 1)
            pending += per * count
            pos += header
        else:  # 0xC1 is never used
            raise ValueError("invalid msgpack header byte")
    if pos > end:
        raise ValueError("truncated msgpack value")
    return pos


def decode_msgpack_stream(data: bytes, max_values: int) -> list:
    """Decode up to ``max_values`` concatenated msgpack values.

    Stops quietly at the first value that doesn't decode, keeping what came
    before it: a crash can cut the last append short.
    """
    values = []
    pos = 0
    while pos < len(data) and len(values) < max_values:
        try:
            end = _msgpack_value_end(data, pos)
            values.append(ormsgpack.unpackb(data[pos:end]))
        except ValueError:  # includes ormsgpack.MsgpackDecodeError
            break
        pos = end
    return values


def _read_part(files: MultiValueDict, name: str, max_size: int) -> bytes | None:
    upload: UploadedFile | None = files.get(name)
    if upload is None or upload.size is None or upload.size > max_size:
        return None
    return upload.read()


def _load_json_object(raw: str | bytes | None) -> dict | None:
    if not raw:
        return None
    try:
        value = orjson.loads(raw)
    except orjson.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _merge(base: dict, extra: dict | None) -> dict:
    """Shallow merge where ``extra`` wins, merging dict values one level."""
    if not extra:
        return base
    merged = dict(base)
    for key, value in extra.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = current | value
        else:
            merged[key] = value
    return merged


def _crashpad_breadcrumbs(files: MultiValueDict) -> list[dict]:
    """The newest MAX_BREADCRUMBS from sentry-native's two breadcrumb rings.

    The SDK alternates between the two files, rewriting one from scratch each
    time it fills, so neither alone is in order relative to the other; sort
    by timestamp (RFC 3339 strings, which sort as text) as the SDK does when
    it merges them itself.
    """
    crumbs = []
    for name in ("__sentry-breadcrumb1", "__sentry-breadcrumb2"):
        data = _read_part(files, name, MAX_BREADCRUMB_PART_SIZE)
        if data:
            crumbs.extend(
                c
                for c in decode_msgpack_stream(data, MAX_BREADCRUMBS)
                if isinstance(c, dict)
            )
    crumbs.sort(key=lambda c: str(c.get("timestamp") or ""))
    return crumbs[-MAX_BREADCRUMBS:]


def _crashpad_event(files: MultiValueDict) -> dict | None:
    data = _read_part(files, "__sentry-event", MAX_EVENT_PART_SIZE)
    if not data:
        return None
    values = decode_msgpack_stream(data, 1)
    event = values[0] if values and isinstance(values[0], dict) else None
    breadcrumbs = _crashpad_breadcrumbs(files)
    if breadcrumbs:
        event = (event or {}) | {"breadcrumbs": breadcrumbs}
    return event


def _electron_event(post: QueryDict) -> dict | None:
    """Reassemble the event sentry-electron split across ``sentry__N`` fields.

    The number of fields is bounded by DATA_UPLOAD_MAX_NUMBER_FIELDS and
    their total size by DATA_UPLOAD_MAX_MEMORY_SIZE, both enforced while
    Django parses the multipart body.
    """
    chunks = []
    index = 1
    while (chunk := post.get(f"sentry__{index}")) is not None:
        chunks.append(chunk)
        index += 1
    return _load_json_object("".join(chunks)) if chunks else None


def sdk_event_from_upload(post: QueryDict, files: MultiValueDict) -> dict:
    """The SDK event sent alongside a minidump, from whichever parts exist.

    Later sources win: Electron's startup scope, then its full event, then
    sentry-native's crashpad event and breadcrumbs, then a JSON ``sentry``
    field.
    """
    event: dict = {}
    for source in (
        _load_json_object(post.get("sentry___initialScope")),
        _electron_event(post),
        _crashpad_event(files),
        _load_json_object(post.get("sentry")),
    ):
        event = _merge(event, source)
    return event

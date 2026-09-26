import bisect
import io
import logging
import struct

from gt_rust.symbolic import normalize_debug_id
from minidump.directory import MINIDUMP_STREAM_TYPE
from minidump.minidumpfile import MinidumpFile
from minidump.streams.ExceptionStream import ExceptionCode
from minidump.streams.ModuleListStream import MINIDUMP_MODULE_LIST
from minidump.streams.SystemInfoStream import PLATFORM_ID, PROCESSOR_ARCHITECTURE

# Maps PROCESSOR_ARCHITECTURE enum to standard arch strings
ARCH_MAP = {
    PROCESSOR_ARCHITECTURE.AMD64: "x86_64",
    PROCESSOR_ARCHITECTURE.INTEL: "x86",
    PROCESSOR_ARCHITECTURE.ARM: "arm",
    PROCESSOR_ARCHITECTURE.AARCH64: "arm64",
    PROCESSOR_ARCHITECTURE.IA64: "ia64",
}

# Maps PLATFORM_ID to (os_name, debug_image_type)
PLATFORM_MAP = {
    PLATFORM_ID.VER_PLATFORM_WIN32s: ("Windows", "pe"),
    PLATFORM_ID.VER_PLATFORM_WIN32_WINDOWS: ("Windows", "pe"),
    PLATFORM_ID.VER_PLATFORM_WIN32_NT: ("Windows", "pe"),
    PLATFORM_ID.VER_PLATFORM_CRASHPAD_MAC: ("macOS", "macho"),
    PLATFORM_ID.VER_PLATFORM_CRASHPAD_IOS: ("iOS", "macho"),
    PLATFORM_ID.VER_PLATFORM_CRASHPAD_LINUX: ("Linux", "elf"),
    PLATFORM_ID.VER_PLATFORM_CRASHPAD_ANDROID: ("Android", "elf"),
    PLATFORM_ID.VER_PLATFORM_CRASHPAD_SOLARIS: ("Solaris", "elf"),
    PLATFORM_ID.VER_PLATFORM_CRASHPAD_FUSCHIA: ("Fuchsia", "elf"),
}

# Overrides for exception code display names where the enum member name
# doesn't produce the expected result after stripping the EXCEPTION_ prefix.
_EXCEPTION_NAME_OVERRIDES: dict[ExceptionCode, str] = {
    ExceptionCode.EXCEPTION_SIGIOT: "SIGABRT",  # SIGIOT is the obscure name for SIGABRT
}

# Instruction pointer offsets for each architecture's context structure.
# (offset_in_bytes, field_size_in_bytes)
_IP_OFFSETS: dict[PROCESSOR_ARCHITECTURE, tuple[int, int]] = {
    PROCESSOR_ARCHITECTURE.AMD64: (248, 8),  # Rip
    PROCESSOR_ARCHITECTURE.INTEL: (184, 4),  # Eip
    PROCESSOR_ARCHITECTURE.AARCH64: (256, 8),  # PC in Breakpad ARM64 context
    PROCESSOR_ARCHITECTURE.ARM: (60, 4),  # PC (r15) in Breakpad ARM context
}


class InvalidMinidump(ValueError):
    """The minidump's structure doesn't fit inside the file."""


# Streams minidump_to_event reads, with the size of one list entry for the
# list-shaped ones (MINIDUMP_THREAD, MINIDUMP_MODULE).
_KEPT_STREAMS: dict[MINIDUMP_STREAM_TYPE, int | None] = {
    MINIDUMP_STREAM_TYPE.ThreadListStream: 48,
    MINIDUMP_STREAM_TYPE.ModuleListStream: 108,
    MINIDUMP_STREAM_TYPE.ExceptionStream: None,
    MINIDUMP_STREAM_TYPE.SystemInfoStream: None,
}
_MAX_STREAMS = 1024
# Real processes have tens to a few hundred threads and modules. Past this the
# lists are truncated: every entry costs Python objects and an event field,
# and a dump can otherwise claim ~100k of each within the size cap.
_MAX_LIST_ITEMS = 4096


def bound_minidump(data: bytes) -> bytes:
    """Return ``data``, or a copy of it, that is safe to hand to MinidumpFile.

    The ``minidump`` package trusts every count in the file and loops that
    many times, so a few crafted bytes can claim millions of streams or
    threads and exhaust memory. Reject any header, directory entry or list
    count that doesn't fit inside the file, truncate thread and module lists
    to _MAX_LIST_ITEMS, and mark the streams we never read as unused so the
    package skips them rather than trusting their counts too.
    """
    if len(data) < 32 or data[:4] != b"MDMP":
        raise InvalidMinidump("truncated header")
    count, dir_rva = struct.unpack_from("<II", data, 8)
    dir_end = dir_rva + count * 12
    if count > _MAX_STREAMS or dir_end > len(data):
        raise InvalidMinidump("stream directory out of bounds")
    # 4-byte rewrites, by offset: stream types in the directory, list counts
    # in their streams. Spliced into one new buffer (none if nothing changes).
    patches: dict[int, bytes] = {}
    unused = struct.pack("<I", MINIDUMP_STREAM_TYPE.UnusedStream.value)
    for i in range(count):
        entry = dir_rva + i * 12
        stream_type, size, rva = struct.unpack_from("<III", data, entry)
        if rva + size > len(data):
            raise InvalidMinidump("stream out of bounds")
        try:
            kept = MINIDUMP_STREAM_TYPE(stream_type) in _KEPT_STREAMS
        except ValueError:
            kept = False
        if not kept:
            patches[entry] = unused
            continue
        item_size = _KEPT_STREAMS[MINIDUMP_STREAM_TYPE(stream_type)]
        if item_size is None:
            continue
        if size < 4:
            raise InvalidMinidump("list stream too short")
        (items,) = struct.unpack_from("<I", data, rva)
        if 4 + items * item_size > size:
            raise InvalidMinidump("list count exceeds stream size")
        if items > _MAX_LIST_ITEMS:
            if dir_rva - 4 < rva < dir_end:
                raise InvalidMinidump("list count overlaps the directory")
            patches[rva] = struct.pack("<I", _MAX_LIST_ITEMS)
    if not patches:
        return data
    view = memoryview(data)
    pieces = []
    pos = 0
    for offset in sorted(patches):
        if offset < pos:
            raise InvalidMinidump("overlapping streams")
        pieces += (view[pos:offset], patches[offset])
        pos = offset + 4
    pieces.append(view[pos:])
    return b"".join(pieces)


def parse_cv_record_debug_id(cv_record_bytes: bytes) -> str | None:
    """Parse a CodeView PDB70 (RSDS) record to extract a normalized debug_id.

    The PDB70 record layout:
      - 4 bytes: signature (b'RSDS' = 0x53445352)
      - 16 bytes: GUID (mixed-endian UUID)
      - 4 bytes: age
      - variable: PDB filename (null-terminated UTF-8)
    """
    if len(cv_record_bytes) < 24 or cv_record_bytes[:4] != b"RSDS":
        return None

    guid_bytes = cv_record_bytes[4:20]
    (age,) = struct.unpack_from("<I", cv_record_bytes, 20)
    # GUID fields: Data1 (LE 4B), Data2 (LE 2B), Data3 (LE 2B), Data4 (BE 8B)
    a, b, c = struct.unpack_from("<IHH", guid_bytes, 0)
    d = guid_bytes[8:16]
    debug_id = f"{a:08x}-{b:04x}-{c:04x}-{d[:2].hex()}-{d[2:].hex()}"
    if age > 0:
        debug_id += f"-{age:x}"
    return normalize_debug_id(debug_id)


def _get_os_and_image_type(mf: MinidumpFile) -> tuple[str, str]:
    """Return (os_name, image_type) from system info, with defaults."""
    if mf.sysinfo and mf.sysinfo.PlatformId:
        os_name, image_type = PLATFORM_MAP.get(
            mf.sysinfo.PlatformId, ("Unknown", "elf")
        )
        return os_name, image_type
    return "Unknown", "elf"


def _get_arch(mf: MinidumpFile) -> str:
    """Return architecture string from system info."""
    if mf.sysinfo and mf.sysinfo.ProcessorArchitecture:
        return ARCH_MAP.get(mf.sysinfo.ProcessorArchitecture, "unknown")
    return "unknown"


def _read_cv_records(mf: MinidumpFile) -> list[bytes | None]:
    """Read raw CvRecord bytes for each module from the minidump.

    The high-level MinidumpModule doesn't preserve CvRecord data, so we
    re-parse the module list stream to access the raw MINIDUMP_MODULE
    structures which contain CvRecord location descriptors.
    """
    cv_records: list[bytes | None] = []
    for dir_entry in mf.directories:
        if dir_entry.StreamType == MINIDUMP_STREAM_TYPE.ModuleListStream:
            mf.file_handle.seek(dir_entry.Location.Rva)
            chunk = io.BytesIO(mf.file_handle.read(dir_entry.Location.DataSize))
            module_list = MINIDUMP_MODULE_LIST.parse(chunk)
            for mod in module_list.Modules:
                cv_data = None
                if mod.CvRecord.DataSize > 0 and mod.CvRecord.Rva > 0:
                    mf.file_handle.seek(mod.CvRecord.Rva)
                    cv_data = mf.file_handle.read(mod.CvRecord.DataSize)
                cv_records.append(cv_data)
            break
    return cv_records


def _extract_ip_from_context(
    context_rva: int,
    context_size: int,
    file_handle: io.BytesIO,
    arch: PROCESSOR_ARCHITECTURE | None,
) -> int | None:
    """Extract instruction pointer from a raw thread context."""
    if arch is None or arch not in _IP_OFFSETS:
        return None
    offset, size = _IP_OFFSETS[arch]
    if context_size < offset + size:
        return None
    file_handle.seek(context_rva + offset)
    raw = file_handle.read(size)
    if len(raw) < size:
        return None
    fmt = "<Q" if size == 8 else "<I"
    return struct.unpack(fmt, raw)[0]


class _ModuleIndex:
    """Address -> containing module, by binary search over sorted bases."""

    def __init__(self, modules):
        ranges = sorted(
            (mod.baseaddress, mod.endaddress, mod.name)
            for mod in (modules.modules if modules else ())
        )
        self._bases = [r[0] for r in ranges]
        self._ranges = ranges

    def find(self, addr: int) -> tuple[str | None, int | None]:
        """Return (code_file, base_address) or (None, None)."""
        i = bisect.bisect_right(self._bases, addr) - 1
        if i >= 0:
            base, end, name = self._ranges[i]
            if addr < end:
                return name, base
        return None, None


def _build_debug_images(mf: MinidumpFile, image_type: str) -> list[dict]:
    """Build debug_meta.images list from minidump modules."""
    if not mf.modules:
        return []

    cv_records = _read_cv_records(mf)
    images = []

    for i, mod in enumerate(mf.modules.modules):
        image: dict = {
            "type": image_type,
            "image_addr": hex(mod.baseaddress),
            "image_size": mod.size,
            "code_file": mod.name,
        }
        if i < len(cv_records) and cv_records[i]:
            debug_id = parse_cv_record_debug_id(cv_records[i])
            if debug_id:
                image["debug_id"] = debug_id
        images.append(image)

    return images


def _get_exception_name(exc_code: ExceptionCode) -> str:
    """Get a human-readable exception name.

    Derives display names from the ExceptionCode enum member name:
    - Unix signals: strip EXCEPTION_ prefix (EXCEPTION_SIGSEGV → SIGSEGV)
    - Windows exceptions: keep the full name (EXCEPTION_ACCESS_VIOLATION)
    - Explicit overrides for edge cases (SIGIOT → SIGABRT)
    """
    if exc_code in _EXCEPTION_NAME_OVERRIDES:
        return _EXCEPTION_NAME_OVERRIDES[exc_code]
    name = exc_code.name
    # Strip EXCEPTION_ prefix only for Unix signals (result starts with SIG)
    if name.startswith("EXCEPTION_SIG"):
        return name[len("EXCEPTION_") :]
    return name


def parse_minidump(data: bytes) -> dict:
    """Parse a minidump binary into the event fields it can supply.

    Returns a dict suitable for validation with WebIngestIssueEvent, without
    an event_id (the caller has the one the client knows the crash by):
    exception (signal/exception code and the crashing frame), threads (one
    frame per thread), debug_meta images, and the os/device contexts. Raises
    InvalidMinidump for a file whose structure doesn't fit inside it.
    """
    # The minidump library logs a noisy "PEB parsing error!" at ERROR level
    # via the root logger when memory segments are absent (normal for
    # crashpad/breakpad minidumps).  Suppress during parsing.
    # Note: not fully thread-safe, but parsing is fast (<10ms) and this
    # runs in sync_to_async's thread pool, limiting blast radius.
    _root = logging.getLogger()
    _prev_level = _root.level
    _root.setLevel(logging.CRITICAL)
    try:
        mf = MinidumpFile.parse_bytes(bound_minidump(data))
    finally:
        _root.setLevel(_prev_level)
    os_name, image_type = _get_os_and_image_type(mf)
    arch = _get_arch(mf)
    proc_arch = mf.sysinfo.ProcessorArchitecture if mf.sysinfo else None
    module_index = _ModuleIndex(mf.modules)

    # --- Exception info ---
    exception_values = []
    crashing_thread_id = None
    crash_ip = None

    if mf.exception and mf.exception.exception_records:
        exc_stream = mf.exception.exception_records[0]
        exc_record = exc_stream.ExceptionRecord
        crashing_thread_id = exc_stream.ThreadId

        # ExceptionAddress is the instruction pointer at crash time
        crash_ip = exc_record.ExceptionAddress

        exc_name = _get_exception_name(exc_record.ExceptionCode)
        exc_value = f"Crash with signal {exc_name} at address {hex(crash_ip)}"

        # Build crashing frame
        frames = []
        if crash_ip is not None:
            package, image_addr = module_index.find(crash_ip)
            frame: dict = {
                "instruction_addr": hex(crash_ip),
                "in_app": True,
            }
            if package:
                frame["package"] = package
            if image_addr is not None:
                frame["image_addr"] = hex(image_addr)
            frames.append(frame)

        exc_entry: dict = {
            "type": exc_name,
            "value": exc_value,
            "mechanism": {"type": "minidump", "handled": False},
        }
        if frames:
            exc_entry["stacktrace"] = {"frames": frames}

        exception_values.append(exc_entry)

    # --- Threads ---
    thread_values = []
    if mf.threads:
        for thread in mf.threads.threads:
            tid = thread.ThreadId
            is_crashed = tid == crashing_thread_id

            thread_entry: dict = {
                "id": str(tid),
                "crashed": is_crashed,
                "current": is_crashed,
            }

            # For non-crashing threads, try to extract top frame from context
            if not is_crashed and thread.ThreadContext:
                ip = _extract_ip_from_context(
                    thread.ThreadContext.Rva,
                    thread.ThreadContext.DataSize,
                    mf.file_handle,
                    proc_arch,
                )
                if ip and ip != 0:
                    package, image_addr = module_index.find(ip)
                    frame = {"instruction_addr": hex(ip)}
                    if package:
                        frame["package"] = package
                    if image_addr is not None:
                        frame["image_addr"] = hex(image_addr)
                    thread_entry["stacktrace"] = {"frames": [frame]}

            thread_values.append(thread_entry)

    # --- Debug images ---
    debug_images = _build_debug_images(mf, image_type)

    # --- Build event ---
    event: dict = {
        "platform": "native",
        "level": "fatal",
        "contexts": {
            "os": {"name": os_name, "type": "os"},
            "device": {"arch": arch, "type": "device"},
        },
    }

    if exception_values:
        event["exception"] = {"values": exception_values}

    if thread_values:
        event["threads"] = {"values": thread_values}

    if debug_images:
        event["debug_meta"] = {"images": debug_images}

    return event


# Event keys the minidump is the authority for when the SDK didn't send them.
# An SDK that unwound the crash itself (sentry-native's in-process backend)
# sends its own exception/threads, which beat a single frame per thread.
_MINIDUMP_FILLS = ("exception", "threads", "debug_meta")


def _is_empty(key: str, value) -> bool:
    """Missing, or an interface with nothing in it (``{"values": []}``)."""
    if isinstance(value, dict):
        return not value.get("images" if key == "debug_meta" else "values")
    return not value


def merge_sdk_event(minidump_event: dict, sdk_event: dict | None) -> dict:
    """Combine the event an SDK sent alongside a minidump with the dump.

    The SDK event carries what only the client knows (release, environment,
    user, tags, breadcrumbs, contexts, its event_id) and typically no
    stack; the dump carries the crash. SDK values win wherever both have one,
    except that the dump fills exception, threads and debug_meta when the SDK
    left them empty, and its os/device context fields fill gaps in the SDK's.
    """
    if not sdk_event:
        return minidump_event
    event = dict(sdk_event)
    for key in _MINIDUMP_FILLS:
        if _is_empty(key, event.get(key)) and key in minidump_event:
            event[key] = minidump_event[key]
    contexts = event.get("contexts")
    if not isinstance(contexts, dict):
        contexts = {}
    contexts = dict(contexts)
    for name, value in minidump_event["contexts"].items():
        sdk_value = contexts.get(name)
        contexts[name] = (
            value | sdk_value if isinstance(sdk_value, dict) else sdk_value or value
        )
    event["contexts"] = contexts
    for key in ("platform", "level"):
        if not event.get(key):
            event[key] = minidump_event[key]
    return event


def minidump_to_event(data: bytes, sdk_event: dict | None = None) -> dict:
    """Parse a minidump and merge in the event its SDK sent with it."""
    return merge_sdk_event(parse_minidump(data), sdk_event)

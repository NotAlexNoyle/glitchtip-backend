import gzip
import random
import struct
import uuid

import orjson
import ormsgpack
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.tasks import task_backends
from django.test import TestCase, override_settings
from django.test.client import BOUNDARY, MULTIPART_CONTENT, encode_multipart
from django.urls import reverse

from apps.event_ingest.minidump_event import (
    InvalidMinidump,
    bound_minidump,
    merge_sdk_event,
    minidump_to_event,
    parse_cv_record_debug_id,
    parse_minidump,
)
from apps.event_ingest.minidump_upload import decode_msgpack_stream
from apps.issue_events.models import IssueEvent
from apps.releases.models import Release

from .utils import EventIngestTestCase


class ParseCvRecordDebugIdTest(TestCase):
    def test_valid_rsds_record(self):
        """Parse a valid PDB70 (RSDS) CodeView record."""
        import struct

        cv = b"RSDS"
        cv += struct.pack("<I", 0x01020304)
        cv += struct.pack("<H", 0x0506)
        cv += struct.pack("<H", 0x0708)
        cv += bytes([0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
        cv += struct.pack("<I", 1)  # age
        cv += b"test.pdb\x00"

        result = parse_cv_record_debug_id(cv)
        self.assertIsNotNone(result)
        self.assertEqual(result, "01020304-0506-0708-090a-0b0c0d0e0f10-1")

    def test_invalid_signature(self):
        """Non-RSDS records return None."""
        self.assertIsNone(parse_cv_record_debug_id(b"NB10" + b"\x00" * 20))

    def test_too_short(self):
        """Records shorter than 24 bytes return None."""
        self.assertIsNone(parse_cv_record_debug_id(b"RSDS" + b"\x00" * 10))


def _minidump(streams: list[tuple[int, bytes]]) -> bytes:
    """Build a minidump: header, stream directory, then the stream bodies."""
    dir_rva = 32
    body_rva = dir_rva + 12 * len(streams)
    directory, bodies = b"", b""
    for stream_type, body in streams:
        directory += struct.pack("<III", stream_type, len(body), body_rva + len(bodies))
        bodies += body
    header = b"MDMP" + struct.pack("<IIIIIQ", 0xA793, len(streams), dir_rva, 0, 0, 0)
    return header + directory + bodies


class BoundMinidumpTest(TestCase):
    """The minidump package loops over whatever counts a file claims, so a
    few bytes claiming millions of entries exhaust memory. These inputs must
    be rejected before it sees them."""

    def test_rejects_truncated_header(self):
        with self.assertRaises(InvalidMinidump):
            bound_minidump(b"MDMPgarbage")

    def test_rejects_stream_count_past_end_of_file(self):
        data = bytearray(_minidump([]))
        struct.pack_into("<I", data, 8, 0x00FFFFFF)
        with self.assertRaises(InvalidMinidump):
            bound_minidump(bytes(data))

    def test_rejects_stream_past_end_of_file(self):
        data = bytearray(_minidump([(7, b"\0" * 56)]))
        struct.pack_into("<I", data, 36, 1 << 30)  # DataSize of stream 0
        with self.assertRaises(InvalidMinidump):
            bound_minidump(bytes(data))

    def test_rejects_thread_count_larger_than_stream(self):
        thread_list = struct.pack("<I", 134_217_730) + b"\0" * 96
        with self.assertRaises(InvalidMinidump):
            bound_minidump(_minidump([(3, thread_list)]))

    def test_unread_streams_are_marked_unused(self):
        memory_list = struct.pack("<I", 0xFFFFFFFF)
        bounded = bound_minidump(_minidump([(5, memory_list)]))
        self.assertEqual(struct.unpack_from("<I", bounded, 32)[0], 0)

    def test_real_minidumps_pass_unchanged_in_meaning(self):
        for name in ("minidump_linux_x86_64.dmp", "breakpad_linux_null_deref.dmp"):
            with open(f"apps/event_ingest/tests/test_data/{name}", "rb") as f:
                data = f.read()
            bounded = bound_minidump(data)
            self.assertEqual(len(bounded), len(data))
            self.assertEqual(
                minidump_to_event(bounded)["threads"],
                minidump_to_event(data)["threads"],
            )

    def test_mutated_minidumps_are_bounded_or_rejected(self):
        """Every list stream left for the parser fits in its stream."""
        with open(
            "apps/event_ingest/tests/test_data/breakpad_linux_null_deref.dmp", "rb"
        ) as f:
            base = f.read()
        rng = random.Random(0)
        for _ in range(500):
            data = bytearray(base)
            for _ in range(rng.randint(1, 4)):
                off = rng.randrange(0, len(data) - 4) & ~3
                struct.pack_into(
                    "<I",
                    data,
                    off,
                    rng.choice([0xFFFFFFFF, 1 << 24, rng.getrandbits(32)]),
                )
            try:
                bounded = bound_minidump(bytes(data))
            except InvalidMinidump:
                continue
            count, dir_rva = struct.unpack_from("<II", bounded, 8)
            for i in range(count):
                stream_type, size, rva = struct.unpack_from(
                    "<III", bounded, dir_rva + i * 12
                )
                self.assertLessEqual(rva + size, len(bounded))
                item_size = {3: 48, 4: 108}.get(stream_type)
                if item_size:
                    (items,) = struct.unpack_from("<I", bounded, rva)
                    self.assertLessEqual(4 + items * item_size, size)
                else:
                    self.assertIn(stream_type, (0, 6, 7))


class MinidumpToEventTest(TestCase):
    """Unit tests for the minidump-to-event conversion."""

    def _load_fixture(self):
        with open(
            "apps/event_ingest/tests/test_data/minidump_linux_x86_64.dmp", "rb"
        ) as f:
            return f.read()

    def test_basic_event_structure(self):
        data = self._load_fixture()
        event = minidump_to_event(data)

        self.assertEqual(event["platform"], "native")
        self.assertEqual(event["level"], "fatal")
        self.assertIn("event_id", event)
        self.assertIn("exception", event)
        self.assertIn("threads", event)
        self.assertIn("debug_meta", event)

    def test_system_info(self):
        data = self._load_fixture()
        event = minidump_to_event(data)

        self.assertEqual(event["contexts"]["os"]["name"], "Linux")
        self.assertEqual(event["contexts"]["device"]["arch"], "x86_64")

    def test_exception(self):
        data = self._load_fixture()
        event = minidump_to_event(data)

        exc = event["exception"]["values"][0]
        self.assertEqual(exc["type"], "SIGSEGV")
        self.assertIn("SIGSEGV", exc["value"])
        self.assertEqual(exc["mechanism"]["type"], "minidump")
        self.assertFalse(exc["mechanism"]["handled"])

    def test_crashing_frame(self):
        data = self._load_fixture()
        event = minidump_to_event(data)

        exc = event["exception"]["values"][0]
        frame = exc["stacktrace"]["frames"][0]
        self.assertEqual(frame["instruction_addr"], "0x400100")
        self.assertEqual(frame["image_addr"], "0x400000")
        self.assertEqual(frame["package"], "/usr/bin/test_app")

    def test_threads(self):
        data = self._load_fixture()
        event = minidump_to_event(data)

        threads = event["threads"]["values"]
        self.assertEqual(len(threads), 2)

        crashed = [t for t in threads if t["crashed"]]
        self.assertEqual(len(crashed), 1)
        self.assertEqual(crashed[0]["id"], "100")

    def test_debug_images(self):
        data = self._load_fixture()
        event = minidump_to_event(data)

        images = event["debug_meta"]["images"]
        self.assertEqual(len(images), 1)
        self.assertEqual(images[0]["type"], "elf")
        self.assertEqual(images[0]["image_addr"], "0x400000")
        self.assertEqual(images[0]["image_size"], 0x10000)
        self.assertEqual(
            images[0]["debug_id"], "01020304-0506-0708-090a-0b0c0d0e0f10-1"
        )
        self.assertEqual(
            images[0]["debug_id"], "01020304-0506-0708-090a-0b0c0d0e0f10-1"
        )

    def test_sentry_metadata_merged(self):
        data = self._load_fixture()
        event = minidump_to_event(
            data, {"release": "2.0.0", "environment": "staging", "tags": {"a": "b"}}
        )

        self.assertEqual(event["release"], "2.0.0")
        self.assertEqual(event["environment"], "staging")
        self.assertEqual(event["tags"], {"a": "b"})

    def test_no_sentry_metadata(self):
        data = self._load_fixture()
        event = minidump_to_event(data)

        self.assertNotIn("release", event)
        self.assertNotIn("environment", event)


class RealBreakpadMinidumpTest(TestCase):
    """Tests using a real minidump from Google Breakpad's test suite.

    This validates our parser against a minidump produced by a real crash
    (null pointer dereference on Linux x86_64), not a synthetic fixture.
    """

    def _load_fixture(self):
        with open(
            "apps/event_ingest/tests/test_data/breakpad_linux_null_deref.dmp", "rb"
        ) as f:
            return f.read()

    def test_parses_without_error(self):
        """Real Breakpad minidump parses successfully."""
        data = self._load_fixture()
        event = minidump_to_event(data)
        self.assertEqual(event["platform"], "native")
        self.assertEqual(event["level"], "fatal")

    def test_exception_is_sigsegv(self):
        data = self._load_fixture()
        event = minidump_to_event(data)

        exc = event["exception"]["values"][0]
        self.assertEqual(exc["type"], "SIGSEGV")
        self.assertIn("0x0", exc["value"])
        self.assertEqual(exc["mechanism"]["type"], "minidump")
        self.assertFalse(exc["mechanism"]["handled"])

    def test_crashing_frame_at_address_zero(self):
        """Crash IP of 0x0 (null pointer jump) still produces a frame."""
        data = self._load_fixture()
        event = minidump_to_event(data)

        exc = event["exception"]["values"][0]
        self.assertIn("stacktrace", exc)
        frame = exc["stacktrace"]["frames"][0]
        self.assertEqual(frame["instruction_addr"], "0x0")

    def test_system_info(self):
        data = self._load_fixture()
        event = minidump_to_event(data)

        self.assertEqual(event["contexts"]["os"]["name"], "Linux")
        self.assertEqual(event["contexts"]["device"]["arch"], "x86_64")

    def test_debug_images_have_debug_ids(self):
        """Real modules produce debug images with debug_ids."""
        data = self._load_fixture()
        event = minidump_to_event(data)

        images = event["debug_meta"]["images"]
        self.assertGreater(len(images), 0)
        # All real modules should have ELF type on Linux
        for img in images:
            self.assertEqual(img["type"], "elf")
            self.assertIn("image_addr", img)
            self.assertIn("image_size", img)
            self.assertIn("code_file", img)
        # At least some should have debug_ids from CvRecords
        with_debug_id = [img for img in images if "debug_id" in img]
        self.assertGreater(len(with_debug_id), 0)

    def test_thread_marked_as_crashed(self):
        data = self._load_fixture()
        event = minidump_to_event(data)

        threads = event["threads"]["values"]
        crashed = [t for t in threads if t["crashed"]]
        self.assertEqual(len(crashed), 1)


class MinidumpViewTest(EventIngestTestCase):
    """Integration tests for the minidump HTTP endpoint."""

    def setUp(self):
        super().setUp()
        cache.clear()
        self.url = reverse("minidump", args=[self.project.id]) + self.params
        with open(
            "apps/event_ingest/tests/test_data/minidump_linux_x86_64.dmp", "rb"
        ) as f:
            self.minidump_data = f.read()

    def test_upload_minidump(self):
        """Successful minidump upload creates an event."""
        from django.core.files.uploadedfile import SimpleUploadedFile

        uploaded = SimpleUploadedFile(
            "crash.dmp", self.minidump_data, content_type="application/octet-stream"
        )
        res = self.client.post(
            self.url,
            {"upload_file_minidump": uploaded, "sentry": '{"release":"1.0.0"}'},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("id", data)
        # Verify it's a valid hex UUID
        uuid.UUID(data["id"])

        task_backends["default"].flush_batches()

        event = IssueEvent.objects.first()
        self.assertIsNotNone(event)
        self.assertEqual(event.data["platform"], "native")
        exc = event.data["exception"]["values"][0]
        self.assertEqual(exc["type"], "SIGSEGV")
        # Release is stored as a FK, not in event.data
        self.assertTrue(Release.objects.filter(version="1.0.0").exists())

    def test_upload_minidump_gzipped(self):
        """A gzip Content-Encoded multipart upload is decompressed in Rust.

        With DecompressBodyMiddleware gone, the view decompresses the body via
        gt_rust before Django parses request.FILES.
        """
        uploaded = SimpleUploadedFile(
            "crash.dmp", self.minidump_data, content_type="application/octet-stream"
        )
        body = encode_multipart(
            BOUNDARY,
            {"upload_file_minidump": uploaded, "sentry": '{"release":"1.0.0"}'},
        )
        res = self.client.generic(
            "POST",
            self.url,
            data=gzip.compress(body),
            content_type=MULTIPART_CONTENT,
            HTTP_CONTENT_ENCODING="gzip",
        )
        self.assertEqual(res.status_code, 200)
        uuid.UUID(res.json()["id"])
        task_backends["default"].flush_batches()
        event = IssueEvent.objects.first()
        self.assertIsNotNone(event)
        self.assertEqual(event.data["platform"], "native")

    async def test_missing_file(self):
        """Request without upload_file_minidump returns 400."""
        res = await self.async_client.post(self.url, {"sentry": "{}"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Missing", res.json()["detail"])

    async def test_malformed_minidump_is_rejected(self):
        """A dump whose counts overrun the file is a 400, not a parse."""
        uploaded = SimpleUploadedFile(
            "crash.dmp", b"MDMPgarbage", content_type="application/octet-stream"
        )
        res = await self.async_client.post(self.url, {"upload_file_minidump": uploaded})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid minidump", res.json()["detail"])

    async def test_invalid_magic(self):
        """Non-minidump file returns 400."""
        from django.core.files.uploadedfile import SimpleUploadedFile

        uploaded = SimpleUploadedFile(
            "crash.dmp", b"NOT_A_MINIDUMP_FILE", content_type="application/octet-stream"
        )
        res = await self.async_client.post(self.url, {"upload_file_minidump": uploaded})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid minidump", res.json()["detail"])

    async def test_bad_sentry_key(self):
        """Invalid sentry_key returns 403."""
        url = (
            reverse("minidump", args=[self.project.id])
            + "?sentry_key=00000000000000000000000000000000"
        )
        from django.core.files.uploadedfile import SimpleUploadedFile

        uploaded = SimpleUploadedFile(
            "crash.dmp", self.minidump_data, content_type="application/octet-stream"
        )
        res = await self.async_client.post(url, {"upload_file_minidump": uploaded})
        self.assertEqual(res.status_code, 403)

    async def test_method_not_allowed(self):
        """GET returns 405."""
        res = await self.async_client.get(self.url)
        self.assertEqual(res.status_code, 405)


class DecodeMsgpackStreamTest(TestCase):
    """sentry-native appends breadcrumbs to a file as back-to-back msgpack
    values; the decoder splits them without trusting any claimed length."""

    def test_splits_concatenated_values(self):
        values = [{"a": 1}, [1, "two", None, 3.5], "x" * 300, {"n": {"m": [True]}}]
        data = b"".join(ormsgpack.packb(v) for v in values)
        self.assertEqual(decode_msgpack_stream(data, 10), values)

    def test_stops_at_max_values(self):
        data = ormsgpack.packb(1) * 5
        self.assertEqual(decode_msgpack_stream(data, 3), [1, 1, 1])

    def test_keeps_values_before_a_truncated_tail(self):
        data = ormsgpack.packb({"a": 1}) + ormsgpack.packb({"b": "long" * 10})[:-3]
        self.assertEqual(decode_msgpack_stream(data, 10), [{"a": 1}])

    def test_huge_claimed_counts_and_lengths_are_rejected_quickly(self):
        for data in (
            b"\xdf\xff\xff\xff\xff",  # map32 with 4 billion entries
            b"\xdd\xff\xff\xff\xff\x01",  # array32
            b"\xdb\xff\xff\xff\xffab",  # str32
            b"\xc1",  # never-used byte
        ):
            self.assertEqual(decode_msgpack_stream(data, 10), [])

    def test_random_bytes_never_raise(self):
        rng = random.Random(0)
        for _ in range(500):
            decode_msgpack_stream(rng.randbytes(rng.randint(1, 64)), 10)


class MergeSdkEventTest(TestCase):
    def setUp(self):
        with open(
            "apps/event_ingest/tests/test_data/minidump_linux_x86_64.dmp", "rb"
        ) as f:
            self.minidump_event = parse_minidump(f.read())

    def test_sdk_metadata_wins_and_dump_supplies_the_crash(self):
        event_id = uuid.uuid4().hex
        sdk_event = {
            "event_id": event_id,
            "release": "app@1.2.3",
            "environment": "production",
            "user": {"id": "42"},
            "tags": {"a": "b"},
            "contexts": {"os": {"name": "Linux", "version": "6.1", "type": "os"}},
        }
        event = merge_sdk_event(self.minidump_event, sdk_event)
        self.assertEqual(event["event_id"], event_id)
        self.assertEqual(event["release"], "app@1.2.3")
        self.assertEqual(event["user"], {"id": "42"})
        self.assertEqual(event["exception"], self.minidump_event["exception"])
        self.assertEqual(event["threads"], self.minidump_event["threads"])
        self.assertEqual(event["debug_meta"], self.minidump_event["debug_meta"])
        self.assertEqual(event["contexts"]["os"]["version"], "6.1")
        # The dump fills the context fields the SDK didn't send.
        self.assertEqual(
            event["contexts"]["device"], self.minidump_event["contexts"]["device"]
        )
        self.assertEqual(event["level"], "fatal")
        self.assertEqual(event["platform"], "native")

    def test_sdk_stack_beats_the_dump(self):
        """An SDK that unwound the crash itself keeps its own stack."""
        exception = {"values": [{"type": "SIGSEGV", "stacktrace": {"frames": []}}]}
        event = merge_sdk_event(self.minidump_event, {"exception": exception})
        self.assertEqual(event["exception"], exception)

    def test_without_sdk_event_the_dump_is_the_event(self):
        self.assertIs(merge_sdk_event(self.minidump_event, {}), self.minidump_event)


def _crashpad_breadcrumbs(start: int, count: int) -> bytes:
    return b"".join(
        ormsgpack.packb(
            {
                "timestamp": f"2026-01-01T00:00:{i:02d}.000Z",
                "message": f"crumb {i}",
                "category": "test",
            }
        )
        for i in range(start, start + count)
    )


class MinidumpMetadataViewTest(EventIngestTestCase):
    """What each uploader sends next to the dump reaches the event."""

    def setUp(self):
        super().setUp()
        cache.clear()
        self.url = reverse("minidump", args=[self.project.id]) + self.params
        with open(
            "apps/event_ingest/tests/test_data/breakpad_linux_null_deref.dmp", "rb"
        ) as f:
            self.minidump_data = f.read()

    def _dump(self):
        return SimpleUploadedFile(
            "crash.dmp", self.minidump_data, content_type="application/octet-stream"
        )

    def _post_gzipped(self, fields):
        body = encode_multipart(BOUNDARY, fields)
        return self.client.generic(
            "POST",
            self.url,
            data=gzip.compress(body),
            content_type=MULTIPART_CONTENT,
            HTTP_CONTENT_ENCODING="gzip",
        )

    def _stored_event(self):
        task_backends["default"].flush_batches()
        self.assertEqual(IssueEvent.objects.count(), 1)
        return IssueEvent.objects.get()

    def test_crashpad_msgpack_event_and_breadcrumbs(self):
        """sentry-native's crashpad backend: msgpack files, gzipped body."""
        event_id = uuid.uuid4().hex
        sdk_event = {
            "event_id": event_id,
            "level": "fatal",
            "platform": "native",
            "release": "native-app@2.0.0",
            "environment": "production",
            "user": {"id": "user-1"},
            "tags": {"channel": "beta"},
            "contexts": {"os": {"name": "Linux", "version": "6.8.0", "type": "os"}},
            "sdk": {"name": "sentry.native", "version": "0.12.0"},
        }
        # Ring 2 holds the newer crumbs; they merge into timestamp order.
        res = self._post_gzipped(
            {
                "upload_file_minidump": self._dump(),
                "__sentry-event": SimpleUploadedFile(
                    "__sentry-event", ormsgpack.packb(sdk_event)
                ),
                "__sentry-breadcrumb1": SimpleUploadedFile(
                    "__sentry-breadcrumb1", _crashpad_breadcrumbs(10, 3)
                ),
                "__sentry-breadcrumb2": SimpleUploadedFile(
                    "__sentry-breadcrumb2", _crashpad_breadcrumbs(0, 3)
                ),
                "prod": "native-app",  # crashpad's own annotations are ignored
            }
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["id"], event_id)

        event = self._stored_event()
        self.assertEqual(event.event_id.hex, event_id)
        self.assertEqual(event.release.version, "native-app@2.0.0")
        self.assertEqual(event.tags["environment"], "production")
        self.assertEqual(event.tags["channel"], "beta")
        self.assertEqual(event.data["user"]["id"], "user-1")
        self.assertEqual(event.data["contexts"]["os"]["version"], "6.8.0")
        self.assertEqual(
            [c["message"] for c in event.data["breadcrumbs"]["values"]],
            [f"crumb {i}" for i in (0, 1, 2, 10, 11, 12)],
        )
        self.assertEqual(event.data["exception"]["values"][0]["type"], "SIGSEGV")

    def test_electron_chunked_event(self):
        """Electron's native uploader: the event JSON split over sentry__N."""
        event_id = uuid.uuid4().hex
        sdk_event = orjson.dumps(
            {
                "event_id": event_id,
                "level": "fatal",
                "platform": "native",
                "release": "electron-app@3.1.0",
                "environment": "staging",
                "tags": {"event.environment": "native"},
                "user": {"id": "user-2"},
            }
        ).decode()
        third = len(sdk_event) // 3
        res = self._post_gzipped(
            {
                "upload_file_minidump": self._dump(),
                "sentry__1": sdk_event[:third],
                "sentry__2": sdk_event[third : 2 * third],
                "sentry__3": sdk_event[2 * third :],
                "sentry___initialScope": orjson.dumps(
                    {"release": "electron-app@3.0.0", "tags": {"initial": "yes"}}
                ).decode(),
            }
        )
        self.assertEqual(res.status_code, 200)
        event = self._stored_event()
        self.assertEqual(event.event_id.hex, event_id)
        # The full event beats the startup scope, whose other fields remain.
        self.assertEqual(event.release.version, "electron-app@3.1.0")
        self.assertEqual(event.tags["environment"], "staging")
        self.assertEqual(event.tags["initial"], "yes")
        self.assertEqual(event.data["user"]["id"], "user-2")

    def test_invalid_sdk_event_keeps_the_crash(self):
        res = self.client.post(
            self.url,
            {
                "upload_file_minidump": self._dump(),
                "sentry": orjson.dumps(
                    {"release": "x", "event_id": "not-a-uuid"}
                ).decode(),
            },
        )
        self.assertEqual(res.status_code, 200)
        event = self._stored_event()
        self.assertIsNone(event.release)
        self.assertEqual(event.data["exception"]["values"][0]["type"], "SIGSEGV")

    def test_garbage_metadata_parts_are_ignored(self):
        res = self.client.post(
            self.url,
            {
                "upload_file_minidump": self._dump(),
                "__sentry-event": SimpleUploadedFile("__sentry-event", b"\xdf\xff"),
                "__sentry-breadcrumb1": SimpleUploadedFile("b", b"\xc1\xc1"),
                "sentry__1": "{not json",
            },
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(
            self._stored_event().data["exception"]["values"][0]["type"], "SIGSEGV"
        )

    @override_settings(GLITCHTIP_MAX_UNZIPPED_PAYLOAD_SIZE=1024)
    def test_minidump_cap_is_separate_from_the_ingest_cap(self):
        """A dump past the event ingest cap is still accepted."""
        self.assertGreater(len(self.minidump_data), 1024)
        res = self._post_gzipped({"upload_file_minidump": self._dump()})
        self.assertEqual(res.status_code, 200)

    @override_settings(GLITCHTIP_MAX_MINIDUMP_SIZE=16 * 1024)
    def test_dump_over_the_minidump_cap_is_413(self):
        self.assertGreater(len(self.minidump_data), 16 * 1024)
        res = self._post_gzipped({"upload_file_minidump": self._dump()})
        self.assertEqual(res.status_code, 413)
        res = self.client.post(self.url, {"upload_file_minidump": self._dump()})
        self.assertEqual(res.status_code, 413)
        self.assertEqual(IssueEvent.objects.count(), 0)


class MinidumpEnvelopeTest(EventIngestTestCase):
    """sentry-native's breakpad backend and sentry-electron send the crash
    as an envelope: a stack-less event item plus an event.minidump
    attachment. The dump fills in the crash; the event keeps its scope."""

    def setUp(self):
        super().setUp()
        cache.clear()
        self.url = reverse("event_envelope", args=[self.project.id]) + self.params
        with open(
            "apps/event_ingest/tests/test_data/breakpad_linux_null_deref.dmp", "rb"
        ) as f:
            self.minidump_data = f.read()

    def _envelope(self, *items: tuple[dict, bytes]) -> bytes:
        event_id = uuid.uuid4().hex
        lines = [orjson.dumps({"event_id": event_id})]
        for header, payload in items:
            lines.append(orjson.dumps(header | {"length": len(payload)}))
            lines.append(payload)
        return b"\n".join(lines)

    def _attachment(self):
        return (
            {
                "type": "attachment",
                "attachment_type": "event.minidump",
                "filename": "crash.dmp",
            },
            self.minidump_data,
        )

    def _post(self, body):
        res = self.client.generic(
            "POST", self.url, data=body, content_type="application/x-sentry-envelope"
        )
        self.assertEqual(res.status_code, 200)
        task_backends["default"].flush_batches()

    def test_event_item_is_merged_with_the_dump(self):
        event_id = uuid.uuid4().hex
        sdk_event = {
            "event_id": event_id,
            "level": "fatal",
            "platform": "native",
            "release": "breakpad-app@1.0.0",
            "user": {"id": "user-3"},
            "breadcrumbs": [{"message": "before the crash"}],
        }
        self._post(
            self._envelope(
                ({"type": "event"}, orjson.dumps(sdk_event)), self._attachment()
            )
        )
        self.assertEqual(IssueEvent.objects.count(), 1)
        event = IssueEvent.objects.get()
        self.assertEqual(event.event_id.hex, event_id)
        self.assertEqual(event.release.version, "breakpad-app@1.0.0")
        self.assertEqual(event.data["exception"]["values"][0]["type"], "SIGSEGV")
        self.assertEqual(
            event.data["breadcrumbs"]["values"][0]["message"], "before the crash"
        )

    def test_invalid_dump_keeps_the_event_item(self):
        event_id = uuid.uuid4().hex
        sdk_event = {"event_id": event_id, "release": "r@1", "message": "crash"}
        self._post(
            self._envelope(
                ({"type": "event"}, orjson.dumps(sdk_event)),
                (self._attachment()[0], b"MDMPgarbage"),
            )
        )
        event = IssueEvent.objects.get()
        self.assertEqual(event.event_id.hex, event_id)
        self.assertNotIn("exception", event.data)

    def test_dump_without_event_item_becomes_an_event(self):
        self._post(self._envelope(self._attachment()))
        event = IssueEvent.objects.get()
        self.assertEqual(event.data["exception"]["values"][0]["type"], "SIGSEGV")

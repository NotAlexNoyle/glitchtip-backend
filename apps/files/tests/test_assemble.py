import io
import json
import os
import shutil
import tempfile
import uuid
import zipfile
from hashlib import sha1
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from apps.sourcecode.models import DebugSymbolBundle
from glitchtip.test_utils.test_case import GlitchTipTestCaseMixin

from ..assemble import (
    AssembleTask,
    ChunkFileState,
    assemble_artifacts,
    get_assemble_status,
)
from ..models import File, FileBlob


def build_bundle(manifest: dict, contents: dict[str, str]) -> tuple[bytes, str]:
    """Zip a manifest and its artifacts, returning the bytes and their SHA-1."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as zipf:
        zipf.writestr("manifest.json", json.dumps(manifest))
        for name, content in contents.items():
            zipf.writestr(name, content)
    data = buffer.getvalue()
    return data, sha1(data).hexdigest()


class ArtifactBundleAssembleTests(GlitchTipTestCaseMixin, TestCase):
    def setUp(self):
        self.create_logged_in_user()
        self.async_client.force_login(self.user)
        self.url = reverse(
            "api:artifact_bundle_assemble", args=[self.organization.slug]
        )

    async def assemble(
        self, manifest: dict, contents: dict[str, str], version: str | None = None
    ) -> str:
        data, checksum = build_bundle(manifest, contents)
        await FileBlob.objects.acreate(
            blob=SimpleUploadedFile(checksum, data),
            size=len(data),
            checksum=checksum,
        )
        payload = {
            "checksum": checksum,
            "chunks": [checksum],
            "projects": [self.project.slug],
        }
        if version is not None:
            payload["version"] = version
        res = await self.async_client.post(
            self.url, payload, content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        return checksum

    def assertAssembleState(self, checksum: str, state: ChunkFileState):
        """Assert how the assemble task finished.

        This is the load-bearing assertion in every test here. The task runs
        inline under the immediate backend, which swallows exceptions into a
        failed result, so the 200 from the enqueueing request says nothing
        about whether assembling itself blew up.
        """
        status = get_assemble_status(
            AssembleTask.ARTIFACTS, self.organization.pk, checksum
        )
        self.assertIsNotNone(status, "assemble status was never set")
        self.assertEqual(status[0], state, status[1])

    async def test_artifact_without_debug_id_or_release_is_skipped(self):
        """An unreferenceable artifact must not abort the rest of the upload.

        With no release and no debug-id header, a bundle row would violate the
        debug_id_or_release_required constraint. bulk_create(ignore_conflicts)
        does not swallow check violations, so the whole assemble used to raise
        and every other bundle in the upload was lost.
        """
        debug_id = str(uuid.uuid4())
        manifest = {
            "org": self.organization.slug,
            "project": self.project.slug,
            "files": {
                "files/_/_/good.js": {
                    "type": "minified_source",
                    "url": "~/good.js",
                    "headers": {"debug-id": debug_id, "sourcemap": "good.js.map"},
                },
                "files/_/_/good.js.map": {
                    "type": "source_map",
                    "url": "~/good.js.map",
                    "headers": {"debug-id": debug_id},
                },
                "files/_/_/orphan.js": {
                    "type": "minified_source",
                    "url": "~/orphan.js",
                    "headers": {},
                },
            },
        }
        checksum = await self.assemble(
            manifest,
            {
                "files/_/_/good.js": "function a(n,t){return n+t}",
                "files/_/_/good.js.map": "{}",
                "files/_/_/orphan.js": "function b(){}",
            },
        )

        self.assertAssembleState(checksum, ChunkFileState.OK)

        # The valid sibling bundle in the same upload still exists.
        bundle = await DebugSymbolBundle.objects.select_related(
            "file", "sourcemap_file"
        ).aget(organization=self.organization, debug_id=debug_id)
        self.assertEqual(bundle.file.name, "good.js")
        self.assertEqual(bundle.sourcemap_file.name, "good.js.map")

        # The unreferenceable artifact produced no bundle, and its file row
        # was not left behind.
        self.assertEqual(await DebugSymbolBundle.objects.acount(), 1)
        self.assertFalse(await File.objects.filter(name="orphan.js").aexists())

    async def test_skipped_source_map_still_referenced_is_kept(self):
        """A skipped artifact that another bundle points at must survive.

        A source map matched by the minified file's ``sourcemap`` header needs
        no debug-id of its own. It gets no bundle row, but deleting its File
        would break the sourcemap_file reference of the bundle that does.
        """
        debug_id = str(uuid.uuid4())
        manifest = {
            "org": self.organization.slug,
            "project": self.project.slug,
            "files": {
                "files/_/_/app.js": {
                    "type": "minified_source",
                    "url": "~/app.js",
                    "headers": {"debug-id": debug_id, "sourcemap": "app.js.map"},
                },
                "files/_/_/app.js.map": {
                    "type": "source_map",
                    "url": "~/app.js.map",
                    "headers": {},
                },
            },
        }
        checksum = await self.assemble(
            manifest,
            {
                "files/_/_/app.js": "function a(n,t){return n+t}",
                "files/_/_/app.js.map": "{}",
            },
        )

        self.assertAssembleState(checksum, ChunkFileState.OK)
        bundle = await DebugSymbolBundle.objects.select_related("sourcemap_file").aget(
            organization=self.organization, debug_id=debug_id
        )
        self.assertEqual(bundle.sourcemap_file.name, "app.js.map")
        self.assertTrue(await File.objects.filter(name="app.js.map").aexists())

    async def test_artifact_without_debug_id_is_kept_when_release_is_set(self):
        """A release makes a debug-id-less artifact resolvable, so keep it."""
        version = "1.0.0"
        manifest = {
            "org": self.organization.slug,
            "project": self.project.slug,
            "release": version,
            "files": {
                "files/_/_/plain.js": {
                    "type": "minified_source",
                    "url": "~/plain.js",
                    "headers": {},
                },
            },
        }
        checksum = await self.assemble(
            manifest, {"files/_/_/plain.js": "function b(){}"}, version=version
        )

        self.assertAssembleState(checksum, ChunkFileState.OK)
        bundle = await DebugSymbolBundle.objects.select_related("file", "release").aget(
            organization=self.organization
        )
        self.assertIsNone(bundle.debug_id)
        self.assertEqual(bundle.release.version, version)
        self.assertEqual(bundle.file.name, "plain.js")

    async def test_unusable_debug_id_headers_do_not_abort_the_upload(self):
        """debug-id is client-supplied, so it need not be a usable uuid.

        An empty, malformed, or non-string value reaches a UUIDField. Each
        would raise during insert and lose the whole upload, so they are
        treated as no debug id at all.
        """
        debug_id = str(uuid.uuid4())
        manifest = {
            "org": self.organization.slug,
            "project": self.project.slug,
            "files": {
                "files/_/_/good.js": {
                    "type": "minified_source",
                    "url": "~/good.js",
                    "headers": {"debug-id": debug_id},
                },
                "files/_/_/empty.js": {
                    "type": "minified_source",
                    "url": "~/empty.js",
                    "headers": {"debug-id": ""},
                },
                "files/_/_/malformed.js": {
                    "type": "minified_source",
                    "url": "~/malformed.js",
                    "headers": {"debug-id": "not-a-uuid"},
                },
                "files/_/_/wrongtype.js": {
                    "type": "minified_source",
                    "url": "~/wrongtype.js",
                    "headers": {"debug-id": ["nope"]},
                },
                "files/_/_/nullheaders.js": {
                    "type": "minified_source",
                    "url": "~/nullheaders.js",
                    "headers": None,
                },
            },
        }
        checksum = await self.assemble(
            manifest,
            {
                f"files/_/_/{name}": "x"
                for name in (
                    "good.js",
                    "empty.js",
                    "malformed.js",
                    "wrongtype.js",
                    "nullheaders.js",
                )
            },
        )

        self.assertAssembleState(checksum, ChunkFileState.OK)
        bundle = await DebugSymbolBundle.objects.select_related("file").aget(
            organization=self.organization
        )
        self.assertEqual(str(bundle.debug_id), debug_id)
        self.assertEqual(bundle.file.name, "good.js")

    async def test_same_debug_id_in_different_spellings_is_deduplicated(self):
        """Two spellings of one uuid must not both reach the unique index.

        Upper case and unhyphenated are distinct strings but the same UUID
        once stored. Both artifacts here carry a source map, so both bundles
        take the upsert path, where hitting the arbiter twice in one statement
        is a cardinality violation that aborts the upload.
        """
        debug_id = uuid.uuid4()
        manifest = {
            "org": self.organization.slug,
            "project": self.project.slug,
            "files": {
                "files/_/_/a.js": {
                    "type": "minified_source",
                    "url": "~/a.js",
                    "headers": {
                        "debug-id": str(debug_id).upper(),
                        "sourcemap": "a.js.map",
                    },
                },
                "files/_/_/a.js.map": {
                    "type": "source_map",
                    "url": "~/a.js.map",
                    "headers": {"debug-id": str(debug_id).upper()},
                },
                "files/_/_/b.js": {
                    "type": "minified_source",
                    "url": "~/b.js",
                    "headers": {"debug-id": debug_id.hex, "sourcemap": "b.js.map"},
                },
                "files/_/_/b.js.map": {
                    "type": "source_map",
                    "url": "~/b.js.map",
                    "headers": {"debug-id": debug_id.hex},
                },
            },
        }
        checksum = await self.assemble(
            manifest,
            {
                "files/_/_/a.js": "x",
                "files/_/_/a.js.map": "{}",
                "files/_/_/b.js": "y",
                "files/_/_/b.js.map": "{}",
            },
        )

        self.assertAssembleState(checksum, ChunkFileState.OK)
        bundle = await DebugSymbolBundle.objects.aget(organization=self.organization)
        self.assertEqual(bundle.debug_id, debug_id)


class AssembleArtifactsCleanupTests(GlitchTipTestCaseMixin, TestCase):
    """
    Every way out of assemble_artifacts must remove the scratchpad and bundle
    file and leave a terminal status, or a polling client waits forever.
    """

    def setUp(self):
        self.create_project()
        self.scratchpads: list[str] = []
        real_mkdtemp = tempfile.mkdtemp

        def recording_mkdtemp(*args, **kwargs):
            scratchpad = real_mkdtemp(*args, **kwargs)
            self.scratchpads.append(scratchpad)
            return scratchpad

        # Patched on the tempfile module so TemporaryDirectory is caught too.
        patcher = mock.patch("tempfile.mkdtemp", side_effect=recording_mkdtemp)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(
            lambda: [shutil.rmtree(p, ignore_errors=True) for p in self.scratchpads]
        )

    def run_assemble(
        self, manifest, contents: dict[str, str], may_raise: bool = True
    ) -> str:
        data, checksum = build_bundle(manifest, contents)
        FileBlob.objects.create(
            blob=SimpleUploadedFile(checksum, data),
            size=len(data),
            checksum=checksum,
        )
        if not may_raise:
            assemble_artifacts(self.organization, None, checksum, [checksum])
            return checksum
        try:
            assemble_artifacts(self.organization, None, checksum, [checksum])
        except Exception:
            # Re-raising after cleanup is fine; only the cleanup is pinned.
            pass
        return checksum

    def manifest(self, files: dict) -> dict:
        return {
            "org": self.organization.slug,
            "project": self.project.slug,
            "files": files,
        }

    def artifact(self, name: str, debug_id: str, **extra) -> dict:
        return {
            "type": "minified_source",
            "url": f"~/{name}",
            "headers": {"debug-id": debug_id},
            **extra,
        }

    def assertCleanedUp(self, checksum: str, state: ChunkFileState):
        status = get_assemble_status(
            AssembleTask.ARTIFACTS, self.organization.pk, checksum
        )
        self.assertIsNotNone(status, "assemble status was never set")
        self.assertEqual(status[0], state, status[1])
        self.assertTrue(self.scratchpads, "no scratchpad was created")
        for scratchpad in self.scratchpads:
            self.assertFalse(os.path.exists(scratchpad), "scratchpad left on disk")
        self.assertFalse(
            File.objects.filter(type="release.bundle").exists(),
            "bundle file left in storage",
        )
        if state == ChunkFileState.ERROR:
            self.assertFalse(File.objects.exists(), "artifact files left behind")
            self.assertFalse(DebugSymbolBundle.objects.exists())

    def test_success_cleans_up(self):
        checksum = self.run_assemble(
            self.manifest({"files/_/_/a.js": self.artifact("a.js", str(uuid.uuid4()))}),
            {"files/_/_/a.js": "function a(){}"},
            may_raise=False,
        )
        self.assertCleanedUp(checksum, ChunkFileState.OK)
        self.assertEqual(DebugSymbolBundle.objects.count(), 1)

    def test_handled_failure_does_not_raise(self):
        """A failure the code already handles must not clean up twice."""
        manifest = self.manifest({})
        manifest["org"] = "some-other-org"
        checksum = self.run_assemble(manifest, {}, may_raise=False)
        self.assertCleanedUp(checksum, ChunkFileState.ERROR)

    def test_handled_failure_after_files_created_does_not_raise(self):
        checksum = self.run_assemble(
            self.manifest(
                {
                    "files/_/_/a.js": self.artifact("a.js", str(uuid.uuid4())),
                    "../escape.js": self.artifact("escape.js", str(uuid.uuid4())),
                }
            ),
            {"files/_/_/a.js": "function a(){}"},
            may_raise=False,
        )
        self.assertCleanedUp(checksum, ChunkFileState.ERROR)

    def test_manifest_not_an_object(self):
        checksum = self.run_assemble([], {})
        self.assertCleanedUp(checksum, ChunkFileState.ERROR)

    def test_artifact_missing_type(self):
        """The first artifact's File row is already written when the second fails."""
        bad = self.artifact("b.js", str(uuid.uuid4()))
        del bad["type"]
        checksum = self.run_assemble(
            self.manifest(
                {
                    "files/_/_/a.js": self.artifact("a.js", str(uuid.uuid4())),
                    "files/_/_/b.js": bad,
                }
            ),
            {"files/_/_/a.js": "function a(){}", "files/_/_/b.js": "function b(){}"},
        )
        self.assertCleanedUp(checksum, ChunkFileState.ERROR)

    def test_listed_artifact_missing_from_zip(self):
        checksum = self.run_assemble(
            self.manifest(
                {"files/_/_/gone.js": self.artifact("gone.js", str(uuid.uuid4()))}
            ),
            {},
        )
        self.assertCleanedUp(checksum, ChunkFileState.ERROR)

    def test_bundle_insert_fails(self):
        with mock.patch.object(
            DebugSymbolBundle.objects,
            "bulk_create",
            side_effect=RuntimeError("insert failed"),
        ):
            checksum = self.run_assemble(
                self.manifest(
                    {"files/_/_/a.js": self.artifact("a.js", str(uuid.uuid4()))}
                ),
                {"files/_/_/a.js": "function a(){}"},
            )
        self.assertCleanedUp(checksum, ChunkFileState.ERROR)

    def test_cleanup_failure_after_success_keeps_upload(self):
        """A failed bundle-file delete must not undo a saved upload."""
        real_delete = File.delete
        failed = []

        def flaky_delete(file, *args, **kwargs):
            if file.type == "release.bundle" and not failed:
                failed.append(file.id)
                raise OSError("storage unavailable")
            return real_delete(file, *args, **kwargs)

        with mock.patch.object(File, "delete", flaky_delete):
            checksum = self.run_assemble(
                self.manifest(
                    {"files/_/_/a.js": self.artifact("a.js", str(uuid.uuid4()))}
                ),
                {"files/_/_/a.js": "function a(){}"},
            )

        self.assertTrue(failed, "bundle file delete was never attempted")
        status = get_assemble_status(
            AssembleTask.ARTIFACTS, self.organization.pk, checksum
        )
        self.assertEqual(status[0], ChunkFileState.OK, status[1])
        self.assertEqual(DebugSymbolBundle.objects.count(), 1)
        self.assertTrue(File.objects.filter(name="a.js").exists())
        for scratchpad in self.scratchpads:
            self.assertFalse(os.path.exists(scratchpad), "scratchpad left on disk")

    def test_partial_insert_keeps_existing_bundle(self):
        """
        When the second insert fails, the upsert before it must be rolled back.
        Otherwise the existing bundle is repointed at the new files, and
        deleting those cascades to the bundle.
        """
        debug_id = str(uuid.uuid4())
        complete_pair = {
            "files/_/_/a.js": self.artifact("a.js", debug_id),
            "files/_/_/a.js.map": {
                "type": "source_map",
                "url": "~/a.js.map",
                "headers": {"debug-id": debug_id},
            },
        }
        self.run_assemble(
            self.manifest(complete_pair),
            {"files/_/_/a.js": "function a(){}", "files/_/_/a.js.map": "{}"},
            may_raise=False,
        )
        existing = DebugSymbolBundle.objects.get(debug_id=debug_id)
        self.assertIsNotNone(existing.sourcemap_file_id)

        real_bulk_create = DebugSymbolBundle.objects.bulk_create

        def fail_incomplete_insert(objs, **kwargs):
            if kwargs.get("ignore_conflicts"):
                raise RuntimeError("insert failed")
            return real_bulk_create(objs, **kwargs)

        with mock.patch.object(
            DebugSymbolBundle.objects,
            "bulk_create",
            side_effect=fail_incomplete_insert,
        ):
            checksum = self.run_assemble(
                self.manifest(
                    {
                        **complete_pair,
                        "files/_/_/b.js": self.artifact("b.js", str(uuid.uuid4())),
                    }
                ),
                {
                    "files/_/_/a.js": "function a(){return 2}",
                    "files/_/_/a.js.map": '{"version":3}',
                    "files/_/_/b.js": "function b(){}",
                },
            )

        status = get_assemble_status(
            AssembleTask.ARTIFACTS, self.organization.pk, checksum
        )
        self.assertEqual(status[0], ChunkFileState.ERROR, status[1])
        bundle = DebugSymbolBundle.objects.get(debug_id=debug_id)
        self.assertEqual(bundle.file_id, existing.file_id)
        self.assertEqual(bundle.sourcemap_file_id, existing.sourcemap_file_id)
        self.assertEqual(DebugSymbolBundle.objects.count(), 1)
        self.assertFalse(File.objects.filter(name="b.js").exists())

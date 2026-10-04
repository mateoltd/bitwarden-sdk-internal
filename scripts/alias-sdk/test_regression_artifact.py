"""Negative transport tests, not SDK or Android runtime acceptance."""

import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location(
    "regression_artifact", pathlib.Path(__file__).with_name("regression-artifact.py")
)
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)
SOURCE = "a" * 40


class RegressionDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)

    def npm(self, extra=None):
        entries = {
            "package/VERSION": SOURCE.encode(),
            "package/package.json": json.dumps({
                "name": "@bitwarden/sdk-internal", "license": "GPL-3.0-only", "version": "test"
            }).encode(),
        }
        if extra:
            entries.update(extra)
        with tarfile.open(self.directory / "sdk.tgz", "w:gz") as archive:
            for name, content in entries.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))

    def manifest(self, platform="typescript"):
        manifest = artifact.identity(self.directory, platform, SOURCE)
        (self.directory / "BUILD-ONLY.json").write_text(json.dumps(manifest))
        return manifest

    def test_npm_source_mismatch(self):
        self.npm()
        self.manifest()
        with self.assertRaisesRegex(ValueError, "source mismatch"):
            artifact.verify(self.directory, "typescript", "b" * 40)

    def test_changed_checksum(self):
        self.npm()
        manifest = self.manifest()
        manifest["sha256"] = "0" * 64
        (self.directory / "BUILD-ONLY.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "checksum"):
            artifact.verify(self.directory, "typescript", SOURCE)

    def test_malformed_and_qualified_manifests(self):
        self.npm()
        manifest = self.manifest()
        for change in ({"securityQualified": True}, {"file": "../sdk.tgz"}, {"schemaVersion": True}):
            with self.subTest(change=change):
                (self.directory / "BUILD-ONLY.json").write_text(json.dumps(manifest | change))
                with self.assertRaises(ValueError):
                    artifact.verify(self.directory, "typescript", SOURCE)
        (self.directory / "BUILD-ONLY.json").write_text("{")
        with self.assertRaises(json.JSONDecodeError):
            artifact.verify(self.directory, "typescript", SOURCE)

    def test_archive_traversal_and_link(self):
        self.npm({"package/../../escape": b"bad"})
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            artifact.identity(self.directory, "typescript", SOURCE)
        with tarfile.open(self.directory / "sdk.tgz", "w:gz") as archive:
            member = tarfile.TarInfo("package/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../escape"
            archive.addfile(member)
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            artifact.identity(self.directory, "typescript", SOURCE)

    def test_aliased_archive_path(self):
        self.npm({"package//VERSION": b"different-source"})
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            artifact.identity(self.directory, "typescript", SOURCE)

    def test_undeclared_delivery_content(self):
        self.npm()
        self.manifest()
        (self.directory / "extra").write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            artifact.verify(self.directory, "typescript", SOURCE)

    def test_missing_android_abi(self):
        with zipfile.ZipFile(self.directory / "sdk.aar", "w") as archive:
            archive.writestr("classes.jar", b"test")
            for abi in ("armeabi-v7a", "arm64-v8a", "x86_64"):
                archive.writestr(f"jni/{abi}/libbitwarden_uniffi.so", b"test")
        with self.assertRaises(KeyError):
            artifact.identity(self.directory, "android", SOURCE)

    def test_android_manifest_source_mismatch(self):
        with zipfile.ZipFile(self.directory / "sdk.aar", "w") as archive:
            archive.writestr("classes.jar", b"test")
            for abi in ("armeabi-v7a", "arm64-v8a", "x86", "x86_64"):
                archive.writestr(f"jni/{abi}/libbitwarden_uniffi.so", b"test")
        self.manifest("android")
        with self.assertRaisesRegex(ValueError, "source mismatch"):
            artifact.verify(self.directory, "android", "b" * 40)


if __name__ == "__main__":
    unittest.main()

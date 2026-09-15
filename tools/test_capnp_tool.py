"""Integrity and publication contracts shared by both schema-tool consumers."""

import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import capnp_tool as tool


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="capnp tools test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def package(self):
        package = self.root / "package"
        contents = {"wasm/capnp.wasm": b"\x00asm\x01\x00\x00\x00",
                    "include/capnp/schema.capnp": b"@0xabc;\n",
                    "bin/capnp-wasm": b"#!/bin/bash\nexit 0\n"}
        for name, data in contents.items():
            path = package / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        manifest = {"format": 1, "source": {"commit": "a" * 40, "dirty": False},
                    "files": [{"path": name, "bytes": len(data), "sha256": tool.digest(data)}
                              for name, data in contents.items()]}
        raw = json.dumps(manifest).encode()
        (package / "manifest.json").write_bytes(raw)
        pin = {"manifest_sha256": tool.digest(raw), "source_commit": "a" * 40,
               "compiler_sha256": tool.digest(contents["wasm/capnp.wasm"]),
               "include_sha256": tool.includes_digest(contents)}
        return package, pin

    def test_verified_package_rejects_tampering_missing_and_extra_files(self):
        package, pin = self.package()
        self.assertEqual(tool.verify_package(package, pin), package)
        path = package / "wasm/capnp.wasm"
        original = path.read_bytes()
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "integrity"):
            tool.verify_package(package, pin)
        path.unlink()
        with self.assertRaisesRegex(ValueError, "integrity"):
            tool.verify_package(package, pin)
        path.write_bytes(original)
        (package / "extra").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "inventory"):
            tool.verify_package(package, pin)

    def test_manifest_cannot_be_replaced_to_bless_modified_compiler(self):
        package, pin = self.package()
        manifest = tool.read_json(package / "manifest.json")
        (package / "wasm/capnp.wasm").write_bytes(b"forged")
        manifest["files"][0].update(bytes=6, sha256=tool.digest(b"forged"))
        (package / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            tool.verify_package(package, pin)

    def test_package_source_and_include_pins_are_enforced(self):
        package, pin = self.package()
        for field in ("source_commit", "compiler_sha256", "include_sha256"):
            bad = dict(pin, **{field: "0" * len(pin[field])})
            with self.assertRaises(ValueError):
                tool.verify_package(package, bad)

    def test_symlinks_are_not_tool_inputs(self):
        package, pin = self.package()
        (package / "linked").symlink_to(package / "wasm/capnp.wasm")
        with self.assertRaisesRegex(ValueError, "symlink"):
            tool.verify_package(package, pin)

    def test_unsafe_archives_are_rejected_before_any_file_is_extracted(self):
        for name, kind in [("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("package/link", tarfile.SYMTYPE), ("package/link", tarfile.LNKTYPE)]:
            with self.subTest(name=name, kind=kind):
                archive = self.root / "bad.tgz"
                with tarfile.open(archive, "w:gz") as tar:
                    good = tarfile.TarInfo("package/good")
                    good.size = 2
                    tar.addfile(good, io.BytesIO(b"ok"))
                    bad = tarfile.TarInfo(name)
                    bad.type = kind
                    bad.linkname = "../escape"
                    tar.addfile(bad)
                out = self.root / "unpacked"
                with self.assertRaises(ValueError):
                    tool.extract_archive(archive, out)
                self.assertFalse(out.exists())

    def test_archive_with_duplicate_members_is_rejected(self):
        archive = self.root / "bad.tgz"
        with tarfile.open(archive, "w:gz") as tar:
            for _ in range(2):
                tar.addfile(tarfile.TarInfo("package/repeated"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            tool.extract_archive(archive, self.root / "out")

    def test_drift_check_preserves_unstaged_changes(self):
        staged = self.root / "staged"
        staged.mkdir()
        (staged / "schema.zig").write_text("generated\n")
        target = self.root / "src/gen/schema.zig"
        target.parent.mkdir(parents=True)
        target.write_text("local unstaged edit\n")
        mapping = {"schema.zig": "src/gen/schema.zig"}
        with self.assertRaisesRegex(ValueError, "drift"):
            tool.publish(self.root, staged, mapping, check=True)
        self.assertEqual(target.read_text(), "local unstaged edit\n")
        tool.publish(self.root, staged, mapping, check=False)
        self.assertEqual(target.read_text(), "generated\n")
        tool.publish(self.root, staged, mapping, check=True)

    def test_unexpected_or_missing_output_cannot_change_destinations(self):
        staged = self.root / "staged"
        staged.mkdir()
        target = self.root / "schema.zig"
        target.write_text("keep\n")
        mapping = {"schema.zig": "schema.zig"}
        for extras in (False, True):
            if extras:
                (staged / "schema.zig").write_text("replace\n")
                (staged / "surprise").write_text("bad\n")
            with self.assertRaisesRegex(ValueError, "output set"):
                tool.publish(self.root, staged, mapping, check=False)
            self.assertEqual(target.read_text(), "keep\n")

    def test_output_cannot_escape_or_follow_symlinks(self):
        staged = self.root / "staged"
        staged.mkdir()
        (staged / "schema.zig").write_text("generated\n")
        with self.assertRaises(ValueError):
            tool.publish(self.root, staged, {"schema.zig": "../escape"}, check=False)
        (self.root / "linked").symlink_to(self.root / "staged", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            tool.publish(self.root, staged, {"schema.zig": "linked/schema.zig"}, check=False)


if __name__ == "__main__":
    unittest.main()

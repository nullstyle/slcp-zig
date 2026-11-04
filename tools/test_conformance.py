"""Artifact integrity, source identity and fail-closed qualification contracts."""

import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import conformance as tool

PROFILE_ID = "SLCP-v1-static-strict-default-driver+SLCPRUN1"
REQUIRED_GATES = ["vector-conformance", "runner-conformance", "wasm-diff",
                  "canonical-reference", "packaged-runner", "packaged-cross-target"]


class ConformanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="slcp conformance test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self):
        files = {name: b"fixture" for name in (
            "reference.bundle", "README.md", "bin/slcp-conformance-runner",
            "wasm/slcp_core.wasm", "runner/host.mjs", "pins/build.zig.zon",
            "pins/mise.toml", "pins/capnp-toolchain.json", "pins/capnp-generation.json")}
        files["profile.json"] = tool.json_bytes({"format": "SLCP-CONFORMANCE-PROFILE-1", "id": PROFILE_ID,
                                                "requiredFiles": ["schema/slcp.capnp"],
                                                "requiredGates": REQUIRED_GATES})
        files["schema/slcp.capnp"] = b"schema"
        manifest = {"format": "SLCP-CONFORMANCE-1", "profile": PROFILE_ID,
                    "source": {"commit": "a" * 40, "tree": "b" * 40, "dirty": False},
                    "files": [{"path": name, "bytes": len(data), "sha256": tool.digest(data)}
                              for name, data in sorted(files.items())]}
        files["manifest.json"] = tool.json_bytes(manifest)
        return files, manifest

    def archive(self, files, name="artifact.tgz"):
        archive = self.root / name
        tool.write_archive(archive, files)
        return archive, tool.digest(archive.read_bytes())

    def test_verified_inventory_rejects_tampered_missing_extra_and_manifest_forgery(self):
        files, manifest = self.fixture()
        tool.verify_inventory(files, manifest)
        for kind in ("tampered", "missing", "extra"):
            changed = dict(files)
            if kind == "tampered":
                changed["schema/slcp.capnp"] = b"changed"
            elif kind == "missing":
                del changed["schema/slcp.capnp"]
            else:
                changed["extra"] = b"extra"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                tool.verify_inventory(changed, manifest)
        archive, digest = self.archive(files)
        tool.read_archive(archive, digest)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            tool.read_archive(archive, "0" * 64)

    def test_archive_encoding_is_deterministic(self):
        files, _ = self.fixture()
        first, _ = self.archive(files)
        second, _ = self.archive(dict(reversed(list(files.items()))), "second.tgz")
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_dirty_and_substituted_manifest_source_is_rejected(self):
        files, manifest = self.fixture()
        for key, value in (("dirty", True), ("commit", "not-a-commit"), ("tree", "0")):
            changed = {**manifest, "source": {**manifest["source"], key: value}}
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "identity"):
                tool.verify_inventory(files, changed)

    def test_profile_cannot_omit_its_required_fixture(self):
        files, manifest = self.fixture()
        del files["schema/slcp.capnp"]
        manifest["files"] = [entry for entry in manifest["files"] if entry["path"] != "schema/slcp.capnp"]
        with self.assertRaisesRegex(ValueError, "profile fixture"):
            tool.verify_inventory(files, manifest)

    def test_self_consistent_unknown_profile_or_required_gate_is_refused(self):
        for kind in ("profile", "additional-gate", "missing-gate", "duplicate-gate"):
            files, manifest = self.fixture()
            profile = json.loads(files["profile.json"])
            if kind == "profile":
                profile["id"] = manifest["profile"] = "future-profile"
            elif kind == "additional-gate":
                profile["requiredGates"].append("future-required-gate")
            elif kind == "missing-gate":
                profile["requiredGates"].remove("packaged-cross-target")
            else:
                profile["requiredGates"].append("wasm-diff")
            files["profile.json"] = tool.json_bytes(profile)
            manifest["files"] = [{"path": name, "bytes": len(data), "sha256": tool.digest(data)}
                                 for name, data in sorted(files.items()) if name != "manifest.json"]
            files["manifest.json"] = tool.json_bytes(manifest)
            archive, digest = self.archive(files, kind + ".tgz")
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "unsupported.*profile|unsupported.*gates"):
                tool.read_archive(archive, digest)

    def test_self_consistent_broken_packaged_wasm_cannot_qualify_rebuilt_source(self):
        files, manifest = self.fixture()
        files["wasm/slcp_core.wasm"] = b"broken packaged WASM, even though source gates pass"
        fixture = {"format": "SLCPRUN1", "cases": [{"name": "positive-native", "steps": [{"input": "00"}]}]}
        files["vectors/runner/SLCPRUN1.json"] = tool.json_bytes(fixture)
        native_lines = [
            {"format": "SLCPRUN1", "case": "positive-native", "v1_config": "00", "driver": "default", "limits": {}},
            {"format": "SLCPRUN1", "case": "positive-native", "index": 0,
             "outcome": {"push_error": None, "failed": False, "effects": [], "observable_effects": [], "disposition": "apply"}},
            {"format": "SLCPRUN1", "result": "PASS", "cases": 1, "inputs": 1},
        ]
        script = "#!" + tool.sys.executable + "\nimport json\n"
        script += "\n".join("print(" + repr(json.dumps(line)) + ")" for line in native_lines) + "\n"
        files["bin/slcp-conformance-runner"] = script.encode()
        repository = self.repository()
        for name, data in files.items():
            source_name = ("conformance/profile.json" if name == "profile.json" else
                           "conformance/README.md" if name == "README.md" else
                           "tests/wasm/host.mjs" if name == "runner/host.mjs" else
                           "tools/" + name[5:] if name.startswith("pins/capnp-") else
                           name[5:] if name.startswith("pins/") else
                           name if name.startswith(("schema/", "vectors/")) else None)
            if source_name:
                path = repository / source_name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        (repository / "mise.toml").write_text('zig = "0.17.0"\nwasmtime = "48.0.1"\n')
        files["pins/mise.toml"] = (repository / "mise.toml").read_bytes()
        helper = repository / "tools/test_runner_conformance.py"
        helper.write_bytes((tool.ROOT / "tools/test_runner_conformance.py").read_bytes())
        tool.invoke(["git", "-C", repository, "add", "."])
        tool.invoke(["git", "-C", repository, "commit", "-m", "portable packaged WASM witness"])
        manifest["source"] = tool.clean_identity(repository, "HEAD")
        manifest["builtWith"] = {"node": "v26.13.0", "nativeTarget": {
            "system": tool.platform.system(), "machine": tool.platform.machine()}}
        bundle = self.root / "broken-reference.bundle"
        tool.invoke(["git", "-C", repository, "bundle", "create", bundle, "HEAD"])
        files["reference.bundle"] = bundle.read_bytes()
        manifest["files"] = [{"path": name, "bytes": len(data), "sha256": tool.digest(data)}
                             for name, data in sorted(files.items()) if name != "manifest.json"]
        files["manifest.json"] = tool.json_bytes(manifest)
        archive, digest = self.archive(files, "broken-wasm.tgz")
        # Inventory/digest/source are coherent. Only the packaged-WASM gate
        # distinguishes this from successful source rebuilds and native replay.
        tool.read_archive(archive, digest)
        original_run = subprocess.run

        def source_gates_pass(argv, *args, **kwargs):
            command = [str(arg) for arg in argv]
            versions = {("test-zig", "version"): b"0.17.0\n", ("node", "--version"): b"v26.13.0\n",
                        ("wasmtime", "--version"): b"wasmtime 48.0.1\n"}
            if tuple(command) in versions:
                return subprocess.CompletedProcess(argv, 0, versions[tuple(command)])
            if command[:2] == ["test-zig", "build"]:
                return subprocess.CompletedProcess(argv, 0,
                    b"Build Summary: 1/1 tests passed\n[wasm-diff] traces=4 normative_effects=32\n"
                    b"[wasm-diff] fuzz iters=300 inputs=1\n"
                    b"canonical-reference: 2 statements and 4 quorum sets verified through capnp-wasm\n")
            if command[1:3] == ["tools/capnp_tool.py", "bootstrap"]:
                return subprocess.CompletedProcess(argv, 0, b"capnp-wasm: verified fixture\n")
            return original_run(argv, *args, **kwargs)

        destination = self.root / "broken-qualified"
        with mock.patch.dict(os.environ, {"ZIG": "test-zig"}), \
                mock.patch.object(tool.subprocess, "run", side_effect=source_gates_pass):
            with self.assertRaisesRegex(ValueError, "packaged-cross-target"):
                tool.qualify(archive, digest, destination)
        receipt = json.loads((destination / "qualification.json").read_text())
        self.assertFalse(receipt["passed"])
        self.assertEqual(receipt["gates"][-1]["gate"], "packaged-cross-target")
        self.assertFalse(receipt["gates"][-1]["completedWork"])
        self.assertNotIn(b'"result": "PASS"', (destination / "logs/packaged-cross-target.log").read_bytes())

    def test_unsafe_entries_rejected_before_destination_creation(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("link", tarfile.SYMTYPE), ("hard", tarfile.LNKTYPE),
                           ("directory", tarfile.DIRTYPE)):
            with self.subTest(name=name):
                archive = self.root / ("unsafe-" + kind.decode() + str(len(name)) + ".tgz")
                with tarfile.open(archive, "w:gz") as tar:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = "../escape"
                    item.size = 1 if kind == tarfile.REGTYPE else 0
                    tar.addfile(item, io.BytesIO(b"x") if item.size else None)
                destination = self.root / (archive.stem + "-destination")
                with self.assertRaises(ValueError):
                    tool.restore(archive, tool.digest(archive.read_bytes()), destination)
                self.assertFalse(destination.exists())

    def test_duplicate_archive_entries_rejected(self):
        archive = self.root / "duplicate.tgz"
        with tarfile.open(archive, "w:gz") as tar:
            for _ in range(2):
                item = tarfile.TarInfo("same")
                item.size = 1
                tar.addfile(item, io.BytesIO(b"x"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            tool.read_archive(archive, tool.digest(archive.read_bytes()))

    def repository(self):
        repository = self.root / "source"
        repository.mkdir()
        tool.invoke(["git", "init", repository])
        tool.invoke(["git", "-C", repository, "config", "user.email", "test@example.invalid"])
        tool.invoke(["git", "-C", repository, "config", "user.name", "Conformance Test"])
        tool.invoke(["git", "-C", repository, "remote", "add", "origin", "https://example.invalid/slcp"])
        (repository / "source.txt").write_text("original\n")
        tool.invoke(["git", "-C", repository, "add", "source.txt"])
        tool.invoke(["git", "-C", repository, "commit", "-m", "source"])
        return repository

    def test_reference_rejects_tracked_changes_and_different_checkout(self):
        repository = self.repository()
        identity = tool.clean_identity(repository, "HEAD")
        (repository / "private-untracked.txt").write_text("excluded")
        self.assertEqual(tool.clean_identity(repository, "HEAD"), identity)
        (repository / "source.txt").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "tracked changes"):
            tool.clean_identity(repository, "HEAD")
        tool.invoke(["git", "-C", repository, "add", "source.txt"])
        tool.invoke(["git", "-C", repository, "commit", "-m", "next"])
        with self.assertRaisesRegex(ValueError, "checked-out"):
            tool.clean_identity(repository, identity["commit"])
        with self.assertRaisesRegex(ValueError, "commit mismatch"):
            tool.check_checkout(repository, identity)

    def test_pack_rejects_actual_shallow_clone_before_building_source_bundle(self):
        repository = self.repository()
        (repository / "source.txt").write_text("second commit\n")
        tool.invoke(["git", "-C", repository, "add", "source.txt"])
        tool.invoke(["git", "-C", repository, "commit", "-m", "second commit"])
        shallow = self.root / "shallow"
        # file:// forces the transport's real depth handling; a local path
        # clone otherwise ignores --depth and would not exercise the failure.
        tool.invoke(["git", "clone", "--depth=1", repository.as_uri(), shallow])
        self.assertEqual(tool.git(shallow, "rev-parse", "--is-shallow-repository"), "true")
        artifact = self.root / "must-not-exist.tgz"
        with self.assertRaisesRegex(ValueError, "shallow reference.*self-contained"):
            tool.pack(shallow, artifact, "HEAD")
        self.assertFalse(artifact.exists())

    def test_restored_tree_and_tracked_source_are_checked(self):
        repository = self.repository()
        identity = tool.clean_identity(repository, "HEAD")
        tool.check_checkout(repository, identity)
        with self.assertRaisesRegex(ValueError, "tree mismatch"):
            tool.check_checkout(repository, {**identity, "tree": "0" * 40})
        (repository / "source.txt").write_text("modified")
        with self.assertRaisesRegex(ValueError, "tracked changes"):
            tool.check_checkout(repository, identity)

    def test_self_contained_restore_checks_bundle_and_portable_source_binding(self):
        repository = self.repository()
        files, manifest = self.fixture()
        for name, data in files.items():
            source_name = ("conformance/profile.json" if name == "profile.json" else
                           "conformance/README.md" if name == "README.md" else
                           "tests/wasm/host.mjs" if name == "runner/host.mjs" else
                           "tools/" + name[5:] if name.startswith("pins/capnp-") else
                           name[5:] if name.startswith("pins/") else
                           name if name.startswith("schema/") else None)
            if source_name:
                path = repository / source_name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        tool.invoke(["git", "-C", repository, "add", "."])
        tool.invoke(["git", "-C", repository, "commit", "-m", "portable inputs"])
        manifest["source"] = tool.clean_identity(repository, "HEAD")
        bundle = self.root / "reference.bundle"
        tool.invoke(["git", "-C", repository, "bundle", "create", bundle, "HEAD"])
        files["reference.bundle"] = bundle.read_bytes()
        manifest["files"] = [{"path": name, "bytes": len(data), "sha256": tool.digest(data)}
                             for name, data in sorted(files.items()) if name != "manifest.json"]
        files["manifest.json"] = tool.json_bytes(manifest)
        archive, digest = self.archive(files)
        restored = self.root / "restored"
        tool.restore(archive, digest, restored)
        self.assertEqual((restored / "reference/source.txt").read_text(), "original\n")
        forged = dict(files)
        forged["schema/slcp.capnp"] = b"substituted"
        manifest["files"] = [{"path": name, "bytes": len(data), "sha256": tool.digest(data)}
                             for name, data in sorted(forged.items()) if name != "manifest.json"]
        forged["manifest.json"] = tool.json_bytes(manifest)
        other, other_digest = self.archive(forged, "substituted.tgz")
        with self.assertRaisesRegex(ValueError, "differs from reference"):
            tool.restore(other, other_digest, self.root / "substituted")

    def test_qualification_marks_skipped_required_gate_failed(self):
        destination = self.root / "qualified"
        destination.mkdir()
        reference = destination / "reference"
        reference.mkdir()
        (reference / "mise.toml").write_text('zig = "0.17.0"\nwasmtime = "48.0.1"\n')
        manifest = {"source": {"commit": "a" * 40},
                    "builtWith": {"node": "v26.13.0", "nativeTarget": {
                        "system": tool.platform.system(), "machine": tool.platform.machine()}}}
        versions = [b"0.17.0\n", b"v26.13.0\n", b"wasmtime 48.0.1\n"]
        result = subprocess.CompletedProcess([], 0, b"Build Summary: 2/2 steps succeeded; 1 skipped\n")
        with mock.patch.object(tool, "restore", return_value=manifest), \
                mock.patch.object(tool, "invoke", side_effect=versions), \
                mock.patch.object(tool.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "failed, skipped"):
                tool.qualify(self.root / "unused", "a" * 64, destination)
        receipt = json.loads((destination / "qualification.json").read_text())
        self.assertFalse(receipt["passed"])
        self.assertTrue(receipt["gates"][0]["skipped"])

    def test_successful_noop_or_empty_runner_is_not_completed_work(self):
        for name in ("bootstrap", "vectors", "runner", "wasm", "canonical", "packaged-runner", "packaged-cross-target"):
            with self.subTest(name=name):
                self.assertFalse(tool.gate_evidence(name, b""))
        self.assertFalse(tool.gate_evidence("packaged-runner", b'{"format":"SLCPRUN1","result":"PASS","cases":0,"inputs":0}\n'))
        self.assertTrue(tool.gate_evidence("packaged-runner", b'{"format":"SLCPRUN1","result":"PASS","cases":4,"inputs":8}\n'))
        self.assertTrue(tool.gate_evidence("vectors", b"Build Summary: 3/3 steps succeeded; 9/9 tests passed\n"))

    def test_packaged_cross_target_requires_final_complete_positive_receipt(self):
        def line(value):
            return json.dumps(value).encode() + b"\n"

        receipt = {"format": "SLCPRUN1-CROSS-TARGET", "result": "PASS", "compared_cases": 5,
                   "inputs": 9, "fatal_inputs": 3, "partial_effects": 2, "sticky_inputs": 2,
                   "logical_budget_cases": 1, "driver_handle_isolation": True,
                   "unsupported_wasm1": [{"case": "zero", "reason": "explicit zero"}]}
        self.assertTrue(tool.gate_evidence("packaged-cross-target", line(receipt)))
        for field in ("compared_cases", "inputs", "fatal_inputs", "partial_effects", "sticky_inputs", "logical_budget_cases"):
            for value in (0, True):
                with self.subTest(field=field, value=value):
                    self.assertFalse(tool.gate_evidence("packaged-cross-target", line({**receipt, field: value})))
        for field, value in (("result", "FAIL"), ("driver_handle_isolation", False), ("unsupported_wasm1", [])):
            with self.subTest(field=field):
                self.assertFalse(tool.gate_evidence("packaged-cross-target", line({**receipt, field: value})))
        self.assertFalse(tool.gate_evidence("packaged-cross-target", line(receipt) + b"incomplete later work\n"))

    def test_pack_builds_bundled_tree_without_untracked_source(self):
        repository = self.repository()
        files, _ = self.fixture()
        for name, data in files.items():
            source_name = ("conformance/profile.json" if name == "profile.json" else
                           "conformance/README.md" if name == "README.md" else
                           "tests/wasm/host.mjs" if name == "runner/host.mjs" else
                           "tools/" + name[5:] if name.startswith("pins/capnp-") else
                           name[5:] if name.startswith("pins/") else
                           name if name.startswith("schema/") else None)
            if source_name:
                path = repository / source_name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        (repository / "mise.toml").write_text('zig = "0.17.0"\n')
        tool.invoke(["git", "-C", repository, "add", "."])
        tool.invoke(["git", "-C", repository, "commit", "-m", "artifact inputs"])
        (repository / "untracked-import.zig").write_text("must not influence artifact")
        original_invoke = tool.invoke
        build_directories = []

        def fake_build(argv, **kwargs):
            if str(argv[0]) == "test-zig":
                if argv[1] == "version":
                    return b"0.17.0\n"
                directory = kwargs["cwd"]
                build_directories.append(directory)
                self.assertNotEqual(directory, repository)
                self.assertFalse((directory / "untracked-import.zig").exists())
                binary = directory / "zig-out/bin"
                binary.mkdir(parents=True)
                (binary / "slcp-conformance-runner").write_bytes(b"native executable")
                (binary / "slcp_core.wasm").write_bytes(b"wasm executable")
                return b"build complete\n"
            return original_invoke(argv, **kwargs)

        with mock.patch.dict(os.environ, {"ZIG": "test-zig"}), mock.patch.object(tool, "invoke", side_effect=fake_build):
            result = tool.pack(repository, self.root / "packed.tgz", "HEAD")
        self.assertEqual(len(build_directories), 1)
        tool.read_archive(Path(result["artifact"]), result["sha256"])


if __name__ == "__main__":
    unittest.main()

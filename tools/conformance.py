#!/usr/bin/env python3
"""Build, verify and qualify an independently identified SLCP conformance artifact."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
GATES = (
    ("vectors", ["vector-conformance", "-Dcapnp-wasm-driver=tools/capnp_tool.py"]),
    ("runner", ["runner-conformance"]),
    ("wasm", ["wasm-diff"]),
    ("canonical", ["canonical-reference"]),
)
SUPPORTED_PROFILE_ID = "SLCP-v1-static-strict-default-driver+SLCPRUN1"
REQUIRED_GATES = tuple(steps[0] for _, steps in GATES) + ("packaged-runner", "packaged-cross-target")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def invoke(argv, *, cwd=None, env=None, timeout=900):
    return subprocess.run([str(arg) for arg in argv], cwd=cwd, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout, check=True).stdout


def git(root, *args):
    return invoke(["git", "-C", root, *args]).decode().strip()


def clean_identity(root, revision):
    if git(root, "rev-parse", "--is-shallow-repository") == "true":
        raise ValueError("shallow reference cannot supply a self-contained source bundle; fetch full history first")
    commit = git(root, "rev-parse", "--verify", revision + "^{commit}")
    tree = git(root, "rev-parse", commit + "^{tree}")
    if not HEX40.fullmatch(commit) or not HEX40.fullmatch(tree):
        raise ValueError("unsupported Git object identity")
    if git(root, "rev-parse", "HEAD") != commit:
        raise ValueError("reference must be the checked-out commit")
    if git(root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("reference has tracked changes; commit the intended source first")
    return {"url": git(root, "remote", "get-url", "origin"),
            "commit": commit, "tree": tree, "dirty": False}


def safe_name(name):
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("invalid artifact path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")):
        raise ValueError("unsafe artifact path: " + name)
    return name


def source_blob(root, commit, path):
    return invoke(["git", "-C", root, "show", commit + ":" + path])


def read_archive(archive, expected_sha256):
    if not HEX64.fullmatch(expected_sha256):
        raise ValueError("an external SHA-256 digest is required")
    if archive.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact exceeds byte bound")
    raw = archive.read_bytes()
    if digest(raw) != expected_sha256:
        raise ValueError("artifact SHA-256 mismatch")
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
        for member in tar:
            name = safe_name(member.name)
            if not member.isfile() or name in files:
                raise ValueError("nonregular or duplicate archive entry: " + name)
            total += member.size
            if member.size < 0 or total > MAX_ARTIFACT_BYTES:
                raise ValueError("expanded artifact exceeds byte bound")
            with tar.extractfile(member) as stream:
                files[name] = stream.read()
    if "manifest.json" not in files:
        raise ValueError("missing artifact manifest")
    manifest = json.loads(files["manifest.json"])
    verify_inventory(files, manifest)
    return files, manifest


def verify_inventory(files, manifest):
    if manifest.get("format") != "SLCP-CONFORMANCE-1":
        raise ValueError("unsupported conformance artifact")
    source = manifest["source"]
    if (source.get("dirty") is not False or
            not HEX40.fullmatch(source.get("commit", "")) or
            not HEX40.fullmatch(source.get("tree", ""))):
        raise ValueError("invalid or dirty reference identity")
    expected = {"manifest.json"}
    for entry in manifest["files"]:
        name = safe_name(entry["path"])
        if name in expected:
            raise ValueError("duplicate manifest path: " + name)
        expected.add(name)
        data = files.get(name)
        if data is None or len(data) != entry["bytes"] or digest(data) != entry["sha256"]:
            raise ValueError("artifact integrity mismatch: " + name)
    if set(files) != expected:
        raise ValueError("artifact inventory mismatch")
    required = {"reference.bundle", "profile.json", "README.md",
                "bin/slcp-conformance-runner", "wasm/slcp_core.wasm", "runner/host.mjs",
                "pins/build.zig.zon", "pins/mise.toml", "pins/capnp-toolchain.json",
                "pins/capnp-generation.json"}
    if not required <= expected:
        raise ValueError("missing required artifact inputs")
    profile = json.loads(files["profile.json"])
    if (profile.get("format") != "SLCP-CONFORMANCE-PROFILE-1" or
            profile.get("id") != SUPPORTED_PROFILE_ID):
        raise ValueError("unsupported conformance profile")
    if manifest.get("profile") != profile.get("id"):
        raise ValueError("artifact profile identity mismatch")
    gates = profile.get("requiredGates")
    if (not isinstance(gates, list) or not all(isinstance(gate, str) for gate in gates) or
            len(gates) != len(REQUIRED_GATES) or set(gates) != set(REQUIRED_GATES)):
        raise ValueError("unsupported required conformance gates")
    for name in profile["requiredFiles"]:
        if safe_name(name) not in files:
            raise ValueError("missing profile fixture: " + name)


def write_archive(path, files):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as tar:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(safe_name(name))
                info.size = len(data)
                info.mode = 0o755 if name.startswith("bin/") else 0o644
                info.mtime = 0
                tar.addfile(info, io.BytesIO(data))


def pack(root, output, revision):
    source = clean_identity(root, revision)
    commit = source["commit"]
    zig = os.environ.get("ZIG", "zig")
    if invoke([zig, "version"]).decode().strip() != pin_from_mise(root, "zig"):
        raise ValueError("packing Zig version differs from source pin")
    files = {
        "profile.json": source_blob(root, commit, "conformance/profile.json"),
        "README.md": source_blob(root, commit, "conformance/README.md"),
        "runner/host.mjs": source_blob(root, commit, "tests/wasm/host.mjs"),
    }
    source_paths = git(root, "ls-tree", "-r", "--name-only", commit).splitlines()
    for name in source_paths:
        if name.startswith(("schema/", "vectors/")):
            files[name] = source_blob(root, commit, name)
    for name in ("build.zig.zon", "mise.toml", "tools/capnp-toolchain.json", "tools/capnp-generation.json"):
        files["pins/" + Path(name).name] = source_blob(root, commit, name)
    with tempfile.TemporaryDirectory(prefix="slcp-source-bundle-") as temporary:
        bundle = Path(temporary) / "reference.bundle"
        invoke(["git", "-C", root, "-c", "pack.threads=1", "bundle", "create", bundle, "HEAD"])
        files["reference.bundle"] = bundle.read_bytes()
        # Build the bundled tree, so untracked source/imports in the author's
        # workspace cannot influence an executable excluded from that bundle.
        reference = Path(temporary) / "reference"
        invoke(["git", "clone", "--no-checkout", bundle, reference])
        invoke(["git", "-C", reference, "checkout", "--detach", commit])
        check_checkout(reference, source)
        invoke([zig, "build", "wasm", "conformance-runner", "--summary", "all"], cwd=reference)
        files["bin/slcp-conformance-runner"] = (reference / "zig-out/bin/slcp-conformance-runner").read_bytes()
        files["wasm/slcp_core.wasm"] = (reference / "zig-out/bin/slcp_core.wasm").read_bytes()
        check_checkout(reference, source)
    if clean_identity(root, revision) != source:
        raise ValueError("reference changed while packing")
    manifest = {
        "format": "SLCP-CONFORMANCE-1", "source": source,
        "profile": json.loads(files["profile.json"])["id"],
        "builtWith": {"zig": invoke([zig, "version"]).decode().strip(),
                      "node": invoke(["node", "--version"]).decode().strip(),
                      "python": platform.python_version(),
                      "nativeTarget": {"system": platform.system(), "machine": platform.machine()}},
        "files": [{"path": name, "bytes": len(data), "sha256": digest(data)}
                  for name, data in sorted(files.items())],
    }
    files["manifest.json"] = json_bytes(manifest)
    verify_inventory(files, manifest)
    write_archive(output, files)
    return {"artifact": str(output), "bytes": output.stat().st_size,
            "sha256": digest(output.read_bytes()), "source": source}


def check_checkout(destination, source):
    if git(destination, "rev-parse", "HEAD") != source["commit"]:
        raise ValueError("restored reference commit mismatch")
    if git(destination, "rev-parse", "HEAD^{tree}") != source["tree"]:
        raise ValueError("restored reference tree mismatch")
    if git(destination, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("restored reference has tracked changes")


def restore(archive, expected_sha256, destination):
    files, manifest = read_archive(archive, expected_sha256)
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if name.startswith("bin/"):
            path.chmod(0o755)
    reference = destination / "reference"
    invoke(["git", "clone", "--no-checkout", destination / "reference.bundle", reference])
    invoke(["git", "-C", reference, "checkout", "--detach", manifest["source"]["commit"]])
    check_checkout(reference, manifest["source"])
    invoke(["git", "-C", reference, "fsck", "--no-reflogs"])
    # Duplicate portable inputs must be the exact files in the asserted source.
    for name, data in files.items():
        source_name = ("conformance/profile.json" if name == "profile.json" else
                       "conformance/README.md" if name == "README.md" else
                       "tests/wasm/host.mjs" if name == "runner/host.mjs" else
                       "tools/" + name[5:] if name.startswith("pins/capnp-") else
                       name[5:] if name.startswith("pins/") else
                       name if name.startswith(("schema/", "vectors/")) else None)
        if source_name and (reference / source_name).read_bytes() != data:
            raise ValueError("portable input differs from reference: " + name)
    return manifest


def pin_from_mise(reference, tool):
    text = (reference / "mise.toml").read_text()
    match = re.search(r'^' + re.escape(tool) + r'\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise ValueError("missing tool pin: " + tool)
    return match[1]


def gate_evidence(name, output):
    """A zero exit without the expected completed work is not qualification."""
    if name == "bootstrap":
        return b"capnp-wasm: verified " in output
    if name == "wasm":
        return b"[wasm-diff] traces=4 " in output and b"[wasm-diff] fuzz iters=300 " in output
    if name == "canonical":
        return b"canonical-reference: 2 statements and 4 quorum sets verified through capnp-wasm" in output
    if name == "packaged-cross-target":
        lines = output.splitlines()
        if not lines:
            return False
        try:
            value = json.loads(lines[-1])
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        counts = ("compared_cases", "inputs", "fatal_inputs", "partial_effects",
                  "sticky_inputs", "logical_budget_cases")
        return (isinstance(value, dict) and value.get("format") == "SLCPRUN1-CROSS-TARGET" and
                value.get("result") == "PASS" and
                all(type(value.get(key)) is int and value[key] > 0 for key in counts) and
                value.get("driver_handle_isolation") is True and
                isinstance(value.get("unsupported_wasm1"), list) and bool(value["unsupported_wasm1"]))
    if name == "packaged-runner":
        for line in output.splitlines():
            try:
                value = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if (isinstance(value, dict) and value.get("format") == "SLCPRUN1" and
                    value.get("result") == "PASS" and isinstance(value.get("cases"), int) and
                    value["cases"] > 0 and isinstance(value.get("inputs"), int) and value["inputs"] > 0):
                return True
        return False
    return bool(re.search(rb"\b[1-9][0-9]*/[1-9][0-9]* tests passed\b", output))


def qualification_environment(cache):
    return dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(cache / "global"),
                ZIG_LOCAL_CACHE_DIR=str(cache / "local"),
                ZIG_LOCAL_PKG_DIR=str(cache / "packages"),
                CAPNP_WASM_CACHE=str(cache / "capnp"), GIT_TERMINAL_PROMPT="0")


def qualification_build_command(zig, steps, cache):
    # Zig 0.17's build frontend accepts --cache-dir. Its global cache is
    # selected through ZIG_GLOBAL_CACHE_DIR, not --global-cache-dir.
    return [zig, "build", *steps, "--cache-dir", cache / "local", "--summary", "all"]


def qualify(archive, expected_sha256, destination):
    manifest = restore(archive, expected_sha256, destination)
    reference = destination / "reference"
    zig = os.environ.get("ZIG", "zig")
    versions = {"zig": invoke([zig, "version"]).decode().strip(),
                "node": invoke(["node", "--version"]).decode().strip(),
                "python": platform.python_version(),
                "wasmtime": invoke(["wasmtime", "--version"]).decode().strip()}
    if versions["zig"] != pin_from_mise(reference, "zig"):
        raise ValueError("qualification Zig version differs from source pin")
    if versions["node"] != manifest["builtWith"]["node"]:
        raise ValueError("qualification Node version differs from artifact runtime identity")
    if not re.match(r"^wasmtime(?:-cli)? " + re.escape(pin_from_mise(reference, "wasmtime")) + r"(?:\s|$)", versions["wasmtime"]):
        raise ValueError("qualification Wasmtime version differs from source pin")
    target = {"system": platform.system(), "machine": platform.machine()}
    if target != manifest["builtWith"]["nativeTarget"]:
        raise ValueError("packaged native runner target mismatch; build an artifact for this target")
    cache = destination / "qualification-cache"
    env = qualification_environment(cache)
    receipts = []
    receipt = {"format": "SLCP-CONFORMANCE-RECEIPT-1", "source": manifest["source"],
               "artifactSha256": expected_sha256, "versions": versions,
               "nativeTarget": target, "gates": receipts, "passed": False}
    receipt_path = destination / "qualification.json"
    logs = destination / "logs"
    logs.mkdir()
    commands = [("bootstrap", [sys.executable, "tools/capnp_tool.py", "bootstrap"])]
    commands += [(name, qualification_build_command(zig, steps, cache))
                 for name, steps in GATES]
    commands.append(("packaged-runner", [destination / "bin/slcp-conformance-runner",
                                         "vectors/runner/SLCPRUN1.json"]))
    commands.append(("packaged-cross-target", [sys.executable, "tools/test_runner_conformance.py",
                     "--runner", destination / "bin/slcp-conformance-runner",
                     "--wasm", destination / "wasm/slcp_core.wasm",
                     "--host", destination / "runner/host.mjs",
                     "--fixture", reference / "vectors/runner/SLCPRUN1.json"]))
    try:
        for name, command in commands:
            print("conformance: running " + name, file=sys.stderr, flush=True)
            result = subprocess.run([str(arg) for arg in command], cwd=reference, env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
            log = result.stdout
            (logs / (name + ".log")).write_bytes(log)
            skipped = bool(re.search(rb"\b[1-9][0-9]* skipped\b|SkipZigTest|\bSKIP\b", log))
            evidence = gate_evidence(name, log)
            entry = {"gate": name, "command": [str(arg) for arg in command],
                     "exitCode": result.returncode, "logSha256": digest(log),
                     "skipped": skipped, "completedWork": evidence}
            receipts.append(entry)
            receipt_path.write_bytes(json_bytes(receipt))
            if result.returncode != 0 or skipped or not evidence:
                raise ValueError("required gate failed, skipped or produced no evidence: " + name + "; see " + str(logs / (name + ".log")))
        check_checkout(reference, manifest["source"])
        receipt["passed"] = True
    finally:
        receipt_path.write_bytes(json_bytes(receipt))
    return {"receipt": str(receipt_path), "passed": True, "source": manifest["source"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    packing = commands.add_parser("pack", help="build and bundle the exact clean checked-out commit")
    packing.add_argument("--output", type=Path, required=True)
    packing.add_argument("--reference", default="HEAD")
    for name in ("verify", "restore", "qualify"):
        command = commands.add_parser(name)
        command.add_argument("artifact", type=Path)
        command.add_argument("--sha256", required=True)
        if name != "verify":
            command.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "pack":
            result = pack(ROOT, args.output.resolve(), args.reference)
        elif args.command == "verify":
            _, manifest = read_archive(args.artifact, args.sha256)
            result = {"verified": True, "sha256": args.sha256, "source": manifest["source"]}
        else:
            action = restore if args.command == "restore" else qualify
            result = action(args.artifact.resolve(), args.sha256, args.destination.resolve())
        print(json.dumps(result, sort_keys=True))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        print("conformance: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()

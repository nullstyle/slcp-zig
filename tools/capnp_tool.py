#!/usr/bin/env python3
"""Verified WASM schema tooling. Kept identical in SLCP and bucketlist."""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def safe_path(name):
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("invalid relative path: " + repr(name))
    if name.startswith("/") or any(p in ("", ".", "..") for p in name.split("/")):
        raise ValueError("invalid relative path: " + repr(name))
    return PurePosixPath(name)


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in tool inputs: " + str(path))
        if path.is_file():
            result[path.relative_to(root).as_posix()] = path.read_bytes()
        elif not path.is_dir():
            raise ValueError("unsupported tool input: " + str(path))
    return result


def includes_digest(files):
    return digest("".join(digest(data) + "  " + name + "\n"
                          for name, data in sorted(files.items())
                          if name.startswith("include/")).encode())


def extract_archive(archive, destination):
    """Extract regular files/directories only; validate the entire archive first."""
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        seen = set()
        for member in members:
            name = member.name.rstrip("/")
            safe_path(name)
            if name in seen or not (member.isfile() or member.isdir()):
                raise ValueError("unsafe or duplicate archive member: " + name)
            seen.add(name)
        for member in members:
            target = destination.joinpath(*safe_path(member.name.rstrip("/")).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)


def verify_package(package, pin):
    if package.is_symlink():
        raise ValueError("tool package must not be a symlink")
    files = inventory(package)
    raw_manifest = files.get("manifest.json", b"")
    if digest(raw_manifest) != pin["manifest_sha256"]:
        raise ValueError("tool package manifest digest mismatch")
    manifest = json.loads(raw_manifest)
    if manifest["source"]["commit"] != pin["source_commit"] or manifest["source"]["dirty"]:
        raise ValueError("tool package source identity mismatch")
    expected = {"manifest.json"}
    for entry in manifest["files"]:
        name = str(safe_path(entry["path"]))
        if name in expected:
            raise ValueError("duplicate manifest entry: " + name)
        expected.add(name)
        data = files.get(name)
        if data is None or len(data) != entry["bytes"] or digest(data) != entry["sha256"]:
            raise ValueError("tool package integrity mismatch: " + name)
    if set(files) != expected:
        raise ValueError("tool package inventory mismatch")
    if digest(files["wasm/capnp.wasm"]) != pin["compiler_sha256"]:
        raise ValueError("compiler digest mismatch")
    if includes_digest(files) != pin["include_sha256"]:
        raise ValueError("standard includes digest mismatch")
    return package


def cache_root(root):
    return Path(os.environ.get("CAPNP_WASM_CACHE", root / ".zig-cache/capnp-wasm")).resolve()


def tool_pin(root):
    pin = read_json(root / "tools/capnp-toolchain.json")
    if pin.get("format") != 1:
        raise ValueError("unsupported compiler lock format")
    for field in ("sha256", "manifest_sha256", "compiler_sha256", "include_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", pin[field]):
            raise ValueError("invalid compiler lock digest: " + field)
    return pin


def package_path(root, pin):
    return cache_root(root) / "artifacts" / pin["sha256"] / "package"


def installed_package(root):
    pin = tool_pin(root)
    package = package_path(root, pin)
    if not package.exists():
        raise ValueError("WASM compiler is not installed; run just bootstrap-toolchain")
    return verify_package(package, pin)


def invoke(argv, **kwargs):
    return subprocess.run([str(arg) for arg in argv], check=True, **kwargs)


def launcher(package, operation, directory, args, module=None, **kwargs):
    argv = ["bash", package / "bin/capnp-wasm", operation]
    if operation == "compiler":
        argv += ["--workspace", directory]
    else:
        argv += ["--module", module, "--output", directory]
    return invoke(argv + ["--"] + list(args), **kwargs)


def bootstrap(root, archive_override=None):
    pin = tool_pin(root)
    destination = package_path(root, pin)
    destination.parent.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        verify_package(destination, pin)
    else:
        with tempfile.TemporaryDirectory(prefix="install-", dir=destination.parent.parent) as temp:
            temp = Path(temp)
            archive = temp / "tools.tgz"
            if archive_override:
                shutil.copyfile(archive_override, archive)
            elif "archive" in pin:
                shutil.copyfile(root.joinpath(*safe_path(pin["archive"]).parts), archive)
            else:
                with urllib.request.urlopen(pin["url"], timeout=60) as response, archive.open("wb") as output:
                    shutil.copyfileobj(response, output)
            if digest(archive.read_bytes()) != pin["sha256"]:
                raise ValueError("tool archive digest mismatch")
            unpacked = temp / "unpacked"
            unpacked.mkdir()
            extract_archive(archive, unpacked)
            verify_package(unpacked / "package", pin)
            if set(p.name for p in unpacked.iterdir()) != {"package"}:
                raise ValueError("unexpected tool archive root")
            destination.parent.mkdir(exist_ok=True)
            (unpacked / "package").rename(destination)
    with tempfile.TemporaryDirectory(prefix="version-", dir=cache_root(root)) as temp:
        launcher(destination, "compiler", Path(temp), ["--version"], stdout=sys.stderr)
    print("capnp-wasm: verified " + pin["source_commit"] + " (" + pin["sha256"] + ")", file=sys.stderr)


def mise_pin(root, name):
    match = re.search(r"^" + re.escape(name) + r'\s*=\s*"([^"]+)"',
                      (root / "mise.toml").read_text(), re.MULTILINE)
    if not match:
        raise ValueError("missing mise tool pin: " + name)
    return match[1]


def dependency(root, name):
    match = re.search(r"\." + re.escape(name) + r"\s*=\s*\.\{([^}]+)\}",
                      (root / "build.zig.zon").read_text())
    if not match:
        raise ValueError("missing generator dependency: " + name)
    fields = dict(re.findall(r'\.(url|hash)\s*=\s*"([^"]+)"', match[1]))
    if set(fields) != {"url", "hash"}:
        raise ValueError("generator dependency must have a URL and package hash")
    return fields


def generator(root, config):
    zig = os.environ.get("ZIG", "zig")
    version = invoke([zig, "version"], stdout=subprocess.PIPE).stdout.decode().strip()
    if version != mise_pin(root, "zig"):
        raise ValueError("Zig differs from mise.toml; run through mise exec")
    dep = dependency(root, config["dependency"])
    flags = ["-target", "wasm32-wasi", "-O", "ReleaseSafe", "-fstrip", "--stack", "8388608"]
    key = digest(json.dumps([dep, version, flags], sort_keys=True).encode())
    cache = cache_root(root) / "generators" / key
    binary = cache / "capnpc-zig.wasm"
    stamp = cache / "sha256"
    if binary.exists() and stamp.exists() and digest(binary.read_bytes()) == stamp.read_text().strip():
        return binary
    cache.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="generator-", dir=cache.parent) as temp:
        temp = Path(temp)
        # This Zig has a tarball cache nesting bug. Fetch in an isolated cache;
        # never modify the application's normal package cache.
        env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(temp / "fetch"))
        result = invoke([zig, "fetch", dep["url"]], env=env, stdout=subprocess.PIPE)
        if result.stdout.decode().strip() != dep["hash"]:
            raise ValueError("generator source package hash mismatch")
        archive = temp / "fetch/p" / (dep["hash"] + ".tar.gz")
        if not archive.is_file():
            raise ValueError("Zig did not produce the expected verified package archive")
        unpacked = temp / "source"
        unpacked.mkdir()
        extract_archive(archive, unpacked)
        source = unpacked
        for _ in range(4):
            if (source / "src/main.zig").is_file():
                break
            children = list(source.iterdir())
            if len(children) != 1 or not children[0].is_dir():
                raise ValueError("unexpected generator source archive layout")
            source = children[0]
        output = temp / "capnpc-zig.wasm"
        invoke([zig, "build-exe", source / "src/main.zig"] + flags +
               ["--cache-dir", temp / "build-cache", "-femit-bin=" + str(output)])
        cache.mkdir(exist_ok=True)
        os.replace(output, binary)
        stamp.write_text(digest(binary.read_bytes()))
    print("capnp-wasm: built generator " + dep["hash"], file=sys.stderr)
    return binary


def snapshot(root, package, config, workspace):
    source = root.joinpath(*safe_path(config["schemas_root"]).parts)
    if source.is_symlink() or not source.is_dir():
        raise ValueError("schema root must be a directory")
    files = inventory(source)
    for name in config["entrypoints"]:
        safe_path(name)
        if name not in files:
            raise ValueError("missing schema entrypoint: " + name)
    for name, data in files.items():
        target = workspace / "src" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    shutil.copytree(package / "include", workspace / "include")


def publish(root, staged, outputs, check):
    expected = {str(safe_path(name)) for name in outputs}
    actual = inventory(staged)
    if set(actual) != expected:
        raise ValueError("unexpected generated output set: " + repr(sorted(actual)))
    destinations = [str(safe_path(name)) for name in outputs.values()]
    if len(set(destinations)) != len(destinations):
        raise ValueError("duplicate generated destination")
    changed = []
    for name, relative in outputs.items():
        target = root / relative
        parts = safe_path(relative).parts
        if any(root.joinpath(*parts[:i]).is_symlink() for i in range(1, len(parts) + 1)):
            raise ValueError("symlink in generated destination: " + relative)
        old = target.read_bytes() if target.exists() else b""
        if old != actual[name]:
            changed.append((target, actual[name]))
            if check:
                sys.stderr.writelines(difflib.unified_diff(
                    old.decode().splitlines(True), actual[name].decode().splitlines(True),
                    fromfile=relative, tofile="generated/" + name))
    if check and changed:
        raise ValueError("generated code drift; run just gen and review the changes")
    if not check:
        for target, data in changed:
            target.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".capnp-", delete=False) as tmp:
                tmp.write(data)
                temporary = Path(tmp.name)
            try:
                temporary.chmod(0o644)
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)


def generate(root, check):
    package = installed_package(root)
    config = read_json(root / "tools/capnp-generation.json")
    if "owned_output_directory" in config:
        directory = str(safe_path(config["owned_output_directory"]))
        existing = {directory + "/" + name for name in inventory(root / directory)}
        extra = existing - set(config["outputs"].values())
        if extra:
            raise ValueError("unexpected existing generated files: " + repr(sorted(extra)))
    module = generator(root, config)
    with tempfile.TemporaryDirectory(prefix="generation-", dir=cache_root(root)) as temp:
        temp = Path(temp)
        workspace, output = temp / "input", temp / "output"
        workspace.mkdir()
        output.mkdir()
        snapshot(root, package, config, workspace)
        request = temp / "request.bin"
        with request.open("wb") as stream:
            launcher(package, "compiler", workspace,
                     ["compile", "--no-standard-import", "-I/include", "--src-prefix=/src", "-o-"] +
                     ["/src/" + name for name in config["entrypoints"]], stdout=stream)
        with request.open("rb") as stream:
            launcher(package, "generator", output, [], module=module, stdin=stream)
        if config.get("format", False):
            invoke([os.environ.get("ZIG", "zig"), "fmt"] + [output / name for name in config["outputs"]],
                   stdout=sys.stderr)
        publish(root, output, config["outputs"], check)
    print("capnp-wasm: " + ("no generated drift" if check else "generated files updated"), file=sys.stderr)


def canonical(root, type_name):
    if type_name not in ("Statement", "QuorumSet"):
        raise ValueError("unsupported SLCP canonical type")
    package = installed_package(root)
    config = read_json(root / "tools/capnp-generation.json")
    with tempfile.TemporaryDirectory(prefix="canonical-", dir=cache_root(root)) as temp:
        workspace = Path(temp)
        snapshot(root, package, config, workspace)
        launcher(package, "compiler", workspace,
                 ["convert", "--no-standard-import", "-I/include", "binary:canonical",
                  "/src/slcp.capnp", type_name])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    boot = sub.add_parser("bootstrap")
    boot.add_argument("--archive", type=Path, help="Verify and install this local copy of the locked archive")
    for name in ("gen", "check"):
        sub.add_parser(name)
    convert = sub.add_parser("canonical")
    convert.add_argument("type", choices=("Statement", "QuorumSet"))
    args = parser.parse_args()
    try:
        if args.operation == "bootstrap":
            bootstrap(ROOT, args.archive)
        elif args.operation in ("gen", "check"):
            generate(ROOT, args.operation == "check")
        else:
            canonical(ROOT, args.type)
    except (ValueError, OSError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print("capnp-wasm: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

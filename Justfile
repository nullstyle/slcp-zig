# CAPNPC_ZIG = path to the plugin binary (CI builds it from the fetched
# capnp-zig package and points here). Unset, the default `zig` makes `capnp`
# search $PATH for `capnpc-zig` — that is capnp's `-o<lang>` rule: a bare
# word means "the plugin capnpc-<lang> on PATH", a path with a slash is the
# exact executable. (`-ocapnpc-zig` would look for `capnpc-capnpc-zig`.)
# Regenerate src/gen/*.zig from schema/*.capnp using the capnpc-zig plugin.
gen:
    capnp compile -o${CAPNPC_ZIG:-zig}:src/gen --src-prefix=schema schema/slcp.capnp schema/overlay.capnp schema/host.capnp

# Run all tests (unit + conformance vectors).
test:
    zig build test

# Regenerate conformance vectors into vectors/.
vectors:
    zig build vectors

# CI drift check: regenerate and fail if checked-in gen/ differs.
gen-check: gen
    git diff --exit-code src/gen

# The §14-M5 gate: 4 nodes over real loopback TCP, 200 slots, kill/restart,
# partition/heal, one equivocator (design §13.6). Minutes-scale.
e2e:
    zig build e2e

# ===== M6:quorum =====
# M6 stage anchor (quorum): cli / lint-quorum / vectors-sweep recipes go here.

# Build the `slcp` CLI (lint-quorum, key new, key show) into zig-out/bin/slcp.
cli:
    zig build cli

# Lint a quorum spec JSON file (docs/recipes/*.json are the copy-paste examples).
lint-quorum FILE:
    zig build cli && ./zig-out/bin/slcp lint-quorum {{FILE}}

# The stale-wasm red guard: regenerate the vectors, rebuild the wasm, then run
# every gate that pins qset/lint bytes (native mirrors AND the wasm export).
vectors-sweep:
    zig build vectors && zig build wasm && zig build test && zig build wasm-diff

# ===== M6:appnode =====
# M6 stage anchor (appnode).

# Expected-fail compile of every AppNode / auto-codec teaching error
# (tests/appnode_errors/, 20 cases; also part of `zig build test`).
appnode-errors:
    zig build appnode-errors --summary all

# ===== M6:example =====
# M6 stage anchor (example): example-smoke / example-build recipes go here.

# Build examples/counter three times as a consumer package, run the three
# counters over loopback (ports 47311-47313), kill -9 node0 at count 8 and
# restart it, until every node prints 20 slots. Evidence line:
# `[example-smoke] nodes=3 slots=20 count=20`. Extra args pass through:
# `just example-smoke --slots 40 --keep`.
example-smoke *ARGS:
    zig build example-smoke -- {{ARGS}}

# Only the nested consumer build of examples/counter (exit 0 iff it builds).
example-build:
    zig build example-build

# ===== M6:docs =====
# M6 stage anchor (docs): docs-smoke recipe goes here.

# The docs gate (part of `zig build test`): README/docs snippets byte-equal
# to the sources they quote, recipe outputs byte-equal to the real CLI,
# every documented `zig build X` / `just X` / `slcp <verb>` exists, enum arms
# and version pins match the code. Evidence line: `[docs-smoke] checks=N failures=M`.
docs-smoke:
    zig build docs-smoke --summary all

# ===== M6:apisnap_ci =====
# M6 stage anchor (apisnap_ci): fmt / fmt-check / ci-lint / api-snapshot / check-api go here.

# src/gen is deliberately NOT listed: capnpc-zig output is not fmt-clean (R10;
# docs/upstream/06). `examples` covers examples/counter (build.zig + src) and
# examples/bytes_node.zig — both are quoted verbatim by the README, so a
# formatting drift there is a docs-smoke red too. `src/*.zig` is a glob over
# top-level FILES, so every hand-written src/<dir> must be named here
# explicitly — docs-smoke checks that each one is (only src/gen is exempt),
# after src/cli shipped unformatted-checkable through S2–S7 (S8 finding 20).
# Format the hand-written trees.
fmt:
    zig fmt build.zig src/*.zig src/cli src/node src/engine src/wasm sim tests tools examples

# CI twin of `fmt`: same paths, --check.
fmt-check:
    zig fmt --check build.zig src/*.zig src/cli src/node src/engine src/wasm sim tests tools examples

# Lint the GitHub Actions workflows (brew install actionlint).
ci-lint:
    actionlint .github/workflows/*.yml

# Regenerate BOTH API snapshots (docs/api-snapshot*.txt) from the live surface.
api-snapshot:
    zig build api-snapshot

# docs/stability.md is the review reference. Add -Dstrict-experimental=true to
# also gate the experimental file, as both CI test legs do (since fc351a5).
# Fail when the STABLE public API drifts from docs/api-snapshot.txt.
check-api:
    zig build check-api

# ===== M6:release =====
# M6 stage anchor (release): preflight / package-preflight / release-hash / release-tag / verify-release-hash go here.


# The package-completeness proof (design §13.9; HANDOFF §6 ".paths rule"): a
# path dependency (example-smoke's in-tree copies) does NOT apply `.paths`,
# only a tarball fetch does. So: `git archive HEAD` → a scratch consumer made
# from examples/counter with its `.path = "../.."` dep REMOVED → `zig fetch
# --save=slcp ../slcp.tgz` (writes `.url` + `.hash`) → assert the extracted
# package's contents → consumer build → the loopback smoke (`example-smoke
# --counter-src`) against the fetched package. Shape pinned by the S8 D9
# finding on Zig 0.17.0-dev.1786: `--save`/`--save-exact` over an existing
# `.path` dep keeps the PATH form (`.path = "<tarball>"` → "expected path
# relative to build root" / NotDir); a `file://` URL segfaults `zig fetch`;
# the global cache `p/` holds only the tarball — the extracted package lands
# in the consumer's `zig-pkg/` (ZIG_LOCAL_PKG_DIR, set explicitly so the
# caller's shared package dir is never consulted). Network once (capnp-zig).
package-preflight:
    #!/usr/bin/env bash
    set -euo pipefail
    root=$(pwd)
    tmp=$(mktemp -d)
    ver=$(sed -n 's/^ *\.version = "\([^"]*\)",$/\1/p' build.zig.zon)
    [ -n "$ver" ] || { echo "package-preflight: no .version in build.zig.zon"; exit 1; }
    # HEAD is what gets tagged; uncommitted edits are NOT in the package.
    [ -z "$(git status --porcelain)" ] || echo "package-preflight: note: tree is dirty; archiving HEAD, not the working tree"
    git archive --format=tar.gz -o "$tmp/slcp.tgz" HEAD
    mkdir -p "$tmp/counter/src"
    cp examples/counter/build.zig "$tmp/counter/build.zig"
    cp examples/counter/src/main.zig "$tmp/counter/src/main.zig"
    # The consumer manifest is the example's minus its in-tree path dep: a
    # `.path` entry left in place is what `zig fetch --save` would preserve.
    grep -v '\.slcp = \.{ \.path = "\.\./\.\." },' examples/counter/build.zig.zon > "$tmp/counter/build.zig.zon"
    if grep -q '\.path = ' "$tmp/counter/build.zig.zon"; then echo "package-preflight: scratch build.zig.zon still carries a .path dep"; exit 1; fi
    export ZIG_GLOBAL_CACHE_DIR="$tmp/gc" ZIG_LOCAL_PKG_DIR="$tmp/counter/zig-pkg"
    cd "$tmp/counter"
    zig fetch --save=slcp ../slcp.tgz
    grep -q '\.url = "\.\./slcp\.tgz"' build.zig.zon || { echo "package-preflight: fetch did not record a .url dep:"; cat build.zig.zon; exit 1; }
    grep -q "\.hash = \"slcp-$ver-" build.zig.zon || { echo "package-preflight: fetch did not record a slcp-$ver hash:"; cat build.zig.zon; exit 1; }
    pkgs=( "$ZIG_LOCAL_PKG_DIR"/slcp-"$ver"-* )
    if [ "${#pkgs[@]}" -ne 1 ] || [ ! -d "${pkgs[0]}" ]; then echo "package-preflight: expected exactly one extracted slcp-$ver-* under $ZIG_LOCAL_PKG_DIR:"; ls -la "$ZIG_LOCAL_PKG_DIR" || true; exit 1; fi
    pkg=${pkgs[0]}
    for f in build.zig build.zig.zon src/gen/host.zig schema/host.capnp; do
        [ -f "$pkg/$f" ] || { echo "package-preflight: package is missing $f (.paths filter?)"; exit 1; }
    done
    for f in tests sim tools vectors docs examples README.md CHANGELOG.md; do
        [ ! -e "$pkg/$f" ] || { echo "package-preflight: package ships $f (.paths too wide)"; exit 1; }
    done
    zig build -Doptimize=ReleaseSafe
    [ -x zig-out/bin/counter ] && [ -x zig-out/bin/slcp ] || { echo "package-preflight: consumer build installed no counter/slcp"; exit 1; }
    cd "$root"
    zig build example-smoke -- --counter-src "$tmp/counter"
    echo "package-preflight: OK $(basename "$pkg")"
    rm -rf "$tmp"

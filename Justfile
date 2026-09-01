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
# docs/upstream/06). `examples` joins the list in S6, once the example stage has
# created the directory (zig fmt fails on a missing path, and CI must be green
# from its first run).
# Format the hand-written trees.
fmt:
    zig fmt build.zig src/*.zig src/node src/engine src/wasm sim tests tools

# CI twin of `fmt`: same paths, --check.
fmt-check:
    zig fmt --check build.zig src/*.zig src/node src/engine src/wasm sim tests tools

# Lint the GitHub Actions workflows (brew install actionlint).
ci-lint:
    actionlint .github/workflows/*.yml

# Regenerate BOTH API snapshots (docs/api-snapshot*.txt) from the live surface.
api-snapshot:
    zig build api-snapshot

# docs/stability.md is the review reference. Add -Dstrict-experimental=true to
# also gate the experimental file, as CI's ubuntu job does.
# Fail when the STABLE public API drifts from docs/api-snapshot.txt.
check-api:
    zig build check-api

# ===== M6:release =====
# M6 stage anchor (release): preflight / package-preflight / release-hash / release-tag / verify-release-hash go here.

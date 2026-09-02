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
# (tests/appnode_errors/, 23 cases; also part of `zig build test`).
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

# The cold pre-tag gate (design §13.9; RELEASING.md step 1). Runs the
# `preflight` aggregate step (test, e2e, wasm-diff, byz-matrix, sim-matrix,
# example-smoke) from a FRESH --cache-dir so nothing is answered from cache,
# keeps the `--summary all` log in preflight.log (gitignored), then greps the
# evidence line of every gate out of it — a gate that was skipped, cached or
# printed nothing is red here even if the build exited 0. Prefixes only:
# `count=` may exceed `slots=` on a fast box, and check-api's OK tail reads
# `refreshed)` locally vs `verified)` under -Dstrict-experimental=true.
# NEVER grep for `failed command`: the build runner prints that line for
# PASSING steps that wrote to stderr (wasm-diff, node-tests, api-snapshot).
# Then the gates outside the build graph: fmt-check, ci-lint, gen-check via
# the pinned plugin, pkg-hash-check, package-preflight. ~15 min cold.
preflight:
    #!/usr/bin/env bash
    set -euo pipefail
    start=$(date +%s)
    cache=$(mktemp -d "${TMPDIR:-/tmp}/slcp-preflight-cache.XXXXXX")
    echo "preflight: fresh --cache-dir $cache"
    if ! zig build preflight --cache-dir "$cache" --summary all 2>&1 | tee preflight.log; then
        echo "preflight: RED — zig build preflight failed (see preflight.log)"
        exit 1
    fi
    missing=0
    need() {
        if grep -qE -- "$1" preflight.log; then
            echo "preflight: evidence  $(grep -E -m1 -- "$1" preflight.log | sed 's/^[[:space:]]*//')"
        else
            echo "preflight: MISSING evidence line matching /$1/"
            missing=1
        fi
    }
    need 'Build Summary: [0-9]+/[0-9]+ steps succeeded'
    need 'sim-matrix: 15000 cells green'
    need 'byz-matrix: 1000 seeds x 2 actors green'
    need '\[wasm-diff\] traces=4 '
    need '\[wasm-diff\] fuzz iters=300 '
    need '\[example-smoke\] nodes=3 slots='
    need '\[docs-smoke\] checks=[0-9]+ failures=0'
    need 'api-snapshot: OK \('
    # The summary block is everything from `Build Summary:` on; a ` cached`
    # step there means the fresh cache dir was not honoured.
    if sed -n '/^Build Summary:/,$p' preflight.log | grep -q ' cached'; then
        echo "preflight: a step in the summary block was served from cache:"
        sed -n '/^Build Summary:/,$p' preflight.log | grep ' cached'
        missing=1
    fi
    [ "$missing" -eq 0 ] || { echo "preflight: RED — evidence missing (see preflight.log)"; exit 1; }
    just fmt-check
    just ci-lint
    just gen-check-pinned
    just pkg-hash-check
    just package-preflight
    rm -rf "$cache"
    echo "preflight: GREEN in $(( $(date +%s) - start )) s (log: preflight.log)"

# gen-check with the plugin built from the capnp-zig package build.zig.zon
# PINS (HANDOFF §6 "the pinned-plugin rule"; what CI's gen-check job does).
# A capnpc-zig on PATH is never used: S6 found the checked-in src/gen had
# been produced by a stale ~/.local/bin/capnpc-zig. Needs `capnp` (the C++
# driver: brew/apt) and the package extracted under zig-pkg/ (any prior
# `zig build` did that; `--fetch=all` is the fallback).
gen-check-pinned:
    #!/usr/bin/env bash
    set -euo pipefail
    root=$(pwd)
    hash=$(sed -n 's/.*\.hash = "\(capnpc_zig-[^"]*\)".*/\1/p' build.zig.zon | head -n 1)
    [ -n "$hash" ] || { echo "gen-check-pinned: build.zig.zon has no capnpc_zig hash line"; exit 1; }
    pkgdir="${ZIG_LOCAL_PKG_DIR:-$root/zig-pkg}"
    [ -d "$pkgdir/$hash" ] || zig build --fetch=all
    [ -d "$pkgdir/$hash" ] || { echo "gen-check-pinned: pinned package $hash not under $pkgdir"; exit 1; }
    prefix=$(mktemp -d "${TMPDIR:-/tmp}/slcp-capnpc.XXXXXX")
    (cd "$pkgdir/$hash" && ZIG_LOCAL_PKG_DIR="$pkgdir" zig build -p "$prefix/capnpc")
    test -x "$prefix/capnpc/bin/capnpc-zig" || { echo "gen-check-pinned: the package build produced no capnpc-zig"; exit 1; }
    CAPNPC_ZIG="$prefix/capnpc/bin/capnpc-zig" just gen-check
    echo "gen-check-pinned: OK ($hash; capnp $(capnp --version))"
    rm -rf "$prefix"

# Advisory long fuzz (R21): the limit is ITERATIONS (K/M/G suffixes), not
# minutes. Record the outcome in RELEASING.md's run log; it never blocks the
# tag. `zig build --fuzz` exits 0 even when a target FAILS (it prints
# `failed with error.X`, `exited with code 1; input saved to
# .zig-cache/f/crash` and still reports) — the v0.1.0 run found
# error.OwnStatementNotMonotonic that way — so the log is grepped here.
fuzz-long ITERS="1M":
    #!/usr/bin/env bash
    set -euo pipefail
    log=$(mktemp "${TMPDIR:-/tmp}/slcp-fuzz-long.XXXXXX")
    zig build fuzz --fuzz={{ITERS}} 2>&1 | tee "$log"
    if grep -qE '^failed with |exited with code [0-9]+; input saved to|^\+- run test .* failure$' "$log"; then
        echo "fuzz-long: a fuzz target FAILED (see above; the input is under .zig-cache/f/crash)"
        rm -f "$log"; exit 1
    fi
    rm -f "$log"
    echo "fuzz-long: {{ITERS}} iterations, no failure"

# The package hash of HEAD, the value README's pin block and CHANGELOG.md
# record BEFORE the tag (both files are outside `.paths`, so recording it is
# hash-neutral — HANDOFF §6 "README-hash rule"). Not `zig fetch .`: that
# copies the whole tree (worktrees, caches) into the cache first and a bare
# fetch can poison it (see pkg-hash). `git archive HEAD` WITHOUT --prefix,
# hashed through a throwaway cache, gives the tag tarball's hash in seconds.
release-hash:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -z "$(git status --porcelain)" ] || { echo "release-hash: worktree is dirty — the hash is HEAD's, commit first"; exit 1; }
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/slcp-release-hash.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    git archive --format=tar.gz -o "$tmp/slcp.tgz" HEAD
    tools/pkg_hash.sh "$tmp/slcp.tgz"

# Everything `release-tag` refuses on, as a dry run (no tag, no push): clean
# tree; `.version` == VERSION; the dated CHANGELOG section + link footer; the
# package hash recorded in README.md AND CHANGELOG.md; the tag does not exist
# yet; docs-smoke green; HEAD on origin/main with EVERY CI run for it green
# ("tag only on green CI" — the preventive half; release.yml is the
# detective half).
release-tag-check VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -z "$(git status --porcelain)" ] || { echo "ERROR: worktree is dirty — commit or stash first"; exit 1; }
    ver=$(sed -n 's/^ *\.version = "\([^"]*\)",$/\1/p' build.zig.zon)
    [ "$ver" = "{{VERSION}}" ] || { echo "ERROR: build.zig.zon .version is '$ver', not {{VERSION}} — run the RELEASING.md version sweep first"; exit 1; }
    grep -q '^## \[{{VERSION}}\] - ' CHANGELOG.md || { echo "ERROR: CHANGELOG.md has no dated '## [{{VERSION}}] - YYYY-MM-DD' section"; exit 1; }
    grep -q '^\[{{VERSION}}\]: ' CHANGELOG.md || { echo "ERROR: CHANGELOG.md link footer does not define [{{VERSION}}]"; exit 1; }
    hash=$(grep -oE 'slcp-{{VERSION}}-[A-Za-z0-9_-]{20,}' README.md | head -n 1 || true)
    [ -n "$hash" ] || { echo "ERROR: README.md does not record the slcp-{{VERSION}}-<hash> package hash (just release-hash)"; exit 1; }
    grep -qF "$hash" CHANGELOG.md || { echo "ERROR: CHANGELOG.md does not carry README's hash $hash"; exit 1; }
    ! git rev-parse -q --verify "refs/tags/v{{VERSION}}" >/dev/null || { echo "ERROR: tag v{{VERSION}} already exists"; exit 1; }
    zig build docs-smoke
    git fetch -q origin main
    git merge-base --is-ancestor HEAD origin/main || { echo "ERROR: HEAD is not on origin/main — push first and wait for CI"; exit 1; }
    verdict=$(gh api "repos/:owner/:repo/actions/runs?head_sha=$(git rev-parse HEAD)" --jq '[.workflow_runs[] | select(.name == "CI")] | if length == 0 then "NO_RUN" elif all(.conclusion == "success") then "GREEN" else "RED" end')
    [ "$verdict" = "GREEN" ] || { echo "ERROR: CI for HEAD is $verdict — push and wait for every CI job to conclude successfully before tagging (RELEASING.md)"; exit 1; }
    echo "release-tag-check: v{{VERSION}} may be tagged from $(git rev-parse --short HEAD) ($hash; CI GREEN)"

# Create and push the annotated tag — only through release-tag-check.
# Usage: just release-tag 0.1.0 "one-line theme"
release-tag VERSION THEME="":
    just release-tag-check {{VERSION}}
    git tag -a "v{{VERSION}}" -m "$(test -n "{{THEME}}" && echo "v{{VERSION}} — {{THEME}}" || echo "v{{VERSION}}")"
    git push origin "v{{VERSION}}"
    @echo "Tagged v{{VERSION}}. Next (RELEASING.md): just verify-release-hash {{VERSION}}, then the GitHub Release from CHANGELOG.md."

# Post-tag: fetch the PUBLISHED tag tarball into a scratch `zig init`
# consumer exactly as README tells users to (`zig fetch --save`, a throwaway
# global cache) and assert the hash it records is the one README.md and
# CHANGELOG.md carry. Prints the real hash either way. A mismatch is a
# docs-only follow-up commit (both files are outside `.paths`), never a
# re-tag. SRC overrides the tarball URL for a pre-tag dry run against
# `git archive HEAD` output.
verify-release-hash VERSION SRC="":
    #!/usr/bin/env bash
    set -euo pipefail
    repo="{{justfile_directory()}}"
    src="{{SRC}}"
    [ -n "$src" ] || src="https://github.com/nullstyle/slcp-zig/archive/refs/tags/v{{VERSION}}.tar.gz"
    case "$src" in /*|*://*) ;; *) src="$(pwd)/$src" ;; esac
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/slcp-verify-hash.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    export ZIG_GLOBAL_CACHE_DIR="$tmp/gc"
    mkdir "$tmp/consumer" && cd "$tmp/consumer" && zig init >/dev/null 2>&1
    zig fetch --save=slcp "$src" >/dev/null
    hash=$(sed -n 's/.*\.hash = "\(slcp-[^"]*\)".*/\1/p' build.zig.zon | head -n 1)
    [ -n "$hash" ] || { echo "ERROR: no slcp hash in the consumer's build.zig.zon after the fetch"; exit 1; }
    echo "published v{{VERSION}} hash: $hash ($src)"
    case "$hash" in slcp-{{VERSION}}-*) ;; *) echo "ERROR: the fetched package is not version {{VERSION}}"; exit 1 ;; esac
    ok=0
    for f in README.md CHANGELOG.md; do
        if grep -qF "$hash" "$repo/$f"; then echo "$f carries $hash"; else echo "ERROR: $f does not carry $hash — record it (docs-only commit)"; ok=1; fi
    done
    exit "$ok"

# The §14 accept procedure for three real machines (not automatable here).
two-machine:
    #!/usr/bin/env bash
    ver=$(sed -n 's/^ *\.version = "\([^"]*\)",$/\1/p' build.zig.zon)
    cat <<EOF
    two-machine run (design §14 accept; examples/counter/README.md is the long form)
    On EACH machine (three of them, or two plus this one), with the mise-pinned Zig:
      1. mkdir counter && cd counter && zig init
      2. copy examples/counter/build.zig over the generated build.zig
      3. zig fetch --save=slcp https://github.com/nullstyle/slcp-zig/archive/refs/tags/v${ver}.tar.gz
      4. paste examples/counter/src/main.zig over src/main.zig (delete src/root.zig)
      5. zig build && ./zig-out/bin/slcp key new slcp.key   # prints 'public key: <hex>'
      6. exchange the three hexes; edit the five deployment lines in src/main.zig:
         the three 'const pk_x = slcp.nodeId("…")', '.listen_port = …', '.peers = &.{ … }'
      7. zig build -Doptimize=ReleaseSafe run
    Evidence for HANDOFF §4: the three 'public key:' lines, the three five-line blocks,
    20 consecutive 'slot N: count = N' lines from each machine, and the tag hash
    (just verify-release-hash ${ver}). A failure ships as v0.1.1.
    EOF


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
    for f in build.zig build.zig.zon src/gen/host.zig schema/host.capnp tests/appnode_errors/cases.zig; do
        [ -f "$pkg/$f" ] || { echo "package-preflight: package is missing $f (.paths filter?)"; exit 1; }
    done
    # tests/ ships exactly ONE file: the appnode-errors case table build.zig
    # `@import`s (a build.zig import outside the package broke every tarball
    # consumer's `zig build` at v0.1.0 — the reason this recipe exists).
    ntests=$(find "$pkg/tests" -type f | wc -l | tr -d ' ')
    [ "$ntests" = "1" ] || { echo "package-preflight: package ships $ntests files under tests/, expected only appnode_errors/cases.zig:"; find "$pkg/tests" -type f; exit 1; }
    for f in sim tools vectors docs examples README.md CHANGELOG.md RELEASING.md Justfile; do
        [ ! -e "$pkg/$f" ] || { echo "package-preflight: package ships $f (.paths too wide)"; exit 1; }
    done
    zig build -Doptimize=ReleaseSafe
    [ -x zig-out/bin/counter ] && [ -x zig-out/bin/slcp ] || { echo "package-preflight: consumer build installed no counter/slcp"; exit 1; }
    cd "$root"
    zig build example-smoke -- --counter-src "$tmp/counter"
    echo "package-preflight: OK $(basename "$pkg")"
    rm -rf "$tmp"

# A bare `zig fetch <archive>` (no --save*) on this Zig rewrites
# ~/.cache/zig/p/<hash>.tar.gz double-nested when the archive has a single
# root directory (any GitHub archive, any `git archive --prefix`), and every
# later build-time fetch of that hash from a project whose zig-pkg/ lacks it
# fails with `hash mismatch … N-V-…` (S8 finding 23; HANDOFF §6).
# release-hash / verify-release-hash must hash through this recipe.
# Print the package hash of SRC (tarball, dir or URL) without touching the real global cache.
pkg-hash SRC:
    tools/pkg_hash.sh {{SRC}}

# A scratch cache stands in for ~/.cache/zig; a bare fetch of a --prefix
# tarball must poison it (the control — red on purpose if a newer Zig stops
# doing that) and `pkg-hash` must not. Also a CI step. ~1 min.
# The pinning check for `pkg-hash`. Evidence line: `[pkg-hash-check] checks=N failures=0`.
pkg-hash-check:
    tools/pkg_hash_check.sh

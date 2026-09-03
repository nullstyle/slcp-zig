#!/bin/sh
# The pinning check for `tools/pkg_hash.sh` (`just pkg-hash-check`).
#
# On Zig 0.17.0-dev.1786 a BARE `zig fetch <archive>` (no --save*) of an
# archive with a single root directory — a `git archive --prefix=…` tarball, a
# GitHub `/archive/…tar.gz` — prints the correct hash but rewrites the global
# cache tarball `$ZIG_GLOBAL_CACHE_DIR/p/<hash>.tar.gz` double-nested
# (`<hash>/<root-dir>/build.zig`). Every later build-time fetch of that hash
# from a project whose zig-pkg/ lacks it then fails with
# `hash mismatch: manifest declares <hash> but the fetched package has N-V-…`.
# (v0.1.0 RELEASING.md run log, "the poisoned-cache fetch".)
#
# A scratch cache stands in for ~/.cache/zig. Three things are asserted:
#   1. the control: a bare fetch of a --prefix tarball poisons the scratch
#      cache (if a newer Zig stops doing that, this check goes red on purpose
#      so the workaround in pkg_hash.sh can be retired);
#   2. `tools/pkg_hash.sh <prefixed tarball>` prints the same hash;
#   3. it leaves the (repaired) cache entry intact and adds nothing to p/.
# Evidence line: `[pkg-hash-check] checks=N failures=M`; exit 1 on any failure.
set -u

repo=$(cd "$(dirname "$0")/.." && pwd)
zig=${ZIG:-zig}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/slcp-pkg-hash-check.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

checks=0
failures=0
pass() { checks=$((checks + 1)); }
fail() {
    checks=$((checks + 1))
    failures=$((failures + 1))
    echo "[FAIL] $1"
}

git -C "$repo" archive --format=tar.gz -o "$tmp/flat.tgz" HEAD
git -C "$repo" archive --format=tar.gz --prefix=slcp-zig-0.1.0/ -o "$tmp/prefixed.tgz" HEAD

# The stand-in for the real global cache. Exported: the helper under test must
# NOT use it.
gc="$tmp/gc"
export ZIG_GLOBAL_CACHE_DIR="$gc"

# Seed a healthy entry the way a build-time fetch would store it.
h=$("$zig" fetch "$tmp/flat.tgz") || { echo "[FAIL] seed fetch failed"; exit 1; }
tarball="$gc/p/$h.tar.gz"
healthy() { tar tzf "$tarball" 2>/dev/null | grep -qx "$h/build.zig.zon"; }

if healthy; then pass; else fail "seed: $tarball does not list $h/build.zig.zon"; fi

# Control: the bare fetch of the prefixed tarball must poison the entry.
h2=$("$zig" fetch "$tmp/prefixed.tgz" 2>/dev/null)
if [ "$h2" = "$h" ]; then pass; else fail "control: bare fetch printed '$h2', expected '$h'"; fi
if healthy; then
    fail "control: bare fetch of the --prefix tarball did NOT poison the cache entry (toolchain changed? retire the workaround documented in tools/pkg_hash.sh and RELEASING.md)"
else
    pass
fi

# Repair A: a bare fetch of the flat tarball restores the entry.
"$zig" fetch "$tmp/flat.tgz" >/dev/null 2>&1
if healthy; then pass; else fail "repair: re-fetching the flat tarball did not restore $tarball"; fi
before=$(ls "$gc/p" | sort)

# The helper under test: same hash, cache untouched.
h3=$("$repo/tools/pkg_hash.sh" "$tmp/prefixed.tgz") || fail "pkg_hash.sh exited non-zero"
if [ "$h3" = "$h" ]; then pass; else fail "pkg_hash.sh printed '$h3', expected '$h'"; fi
if healthy; then pass; else fail "pkg_hash.sh poisoned $tarball (first entry: $(tar tzf "$tarball" | head -1))"; fi
after=$(ls "$gc/p" | sort)
if [ "$before" = "$after" ]; then pass; else fail "pkg_hash.sh added entries to the global cache p/: $(echo "$after" | tr '\n' ' ')"; fi

echo "[pkg-hash-check] checks=$checks failures=$failures"
[ "$failures" -eq 0 ]

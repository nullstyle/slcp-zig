#!/bin/sh
# Print the Zig package hash of SRC (a tarball, a directory or a URL) WITHOUT
# touching the real global cache (`just pkg-hash SRC`).
#
# Why not a bare `zig fetch SRC`: on Zig 0.17.0-dev.1786 a bare fetch (no
# --save*) of an archive with a single root directory — `git archive
# --prefix=…`, any GitHub `/archive/….tar.gz` — prints the right hash but
# rewrites `$ZIG_GLOBAL_CACHE_DIR/p/<hash>.tar.gz` double-nested, and every
# later build-time fetch of that hash from a project whose zig-pkg/ lacks it
# fails with `hash mismatch … N-V-…` (S8 finding 23; HANDOFF §6). The fetch
# below runs against a throwaway ZIG_GLOBAL_CACHE_DIR, so the real cache is
# never written. `tools/pkg_hash_check.sh` pins this.
#
# Directories: `zig fetch <dir>` copies the WHOLE directory (ignored files,
# zig-out/, .zig-cache/, worktrees …) into the cache before applying `.paths`
# — 16 GB and minutes from a tree with worktrees. Prefer a `git archive HEAD`
# tarball: same hash, seconds.
set -eu
[ $# -eq 1 ] || { echo "usage: $0 <tarball|dir|url>" >&2; exit 2; }
src=$1
case $src in
    -*) echo "usage: $0 <tarball|dir|url>" >&2; exit 2 ;;
    /* | *://*) ;;
    *) src=$(pwd)/$src ;;
esac
tmp=$(mktemp -d "${TMPDIR:-/tmp}/slcp-pkg-hash.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
ZIG_GLOBAL_CACHE_DIR="$tmp/gc" "${ZIG:-zig}" fetch "$src" 2>"$tmp/stderr" || {
    cat "$tmp/stderr" >&2
    exit 1
}

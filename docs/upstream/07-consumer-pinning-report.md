# M6 upstream report: pinning capnp-zig from a consumer-of-a-consumer, and what we copied instead of importing

*From: slcp-zig M6 (omakase polish + release, v0.1.0), 2026-09-01.*
*This is the §15 M6 signal: a report from the far end of the dependency
chain (`examples/counter` → `slcp` → `capnp-zig`), written while cutting our
first tag. Two findings are asks (F5, F6); the rest is what a downstream sees
when it pins you, so you can decide what to document versus what to ship.*

## Finding 1: the pinning workflow, seen from two hops down

slcp-zig pins `capnpc_zig-0.16.0-nUduFXLZNgAmDvsQZOn7lNOEtNbRBYquaALRB24zUAvS`
by tag URL (`archive/refs/tags/v0.16.0.tar.gz`). Our own consumer,
`examples/counter`, pins slcp-zig the same way, and we ship it three times per
CI run (as an in-tree path dependency, as a tarball consumer in
`just package-preflight`, and on the user's machine). What the chain taught
us, in the order it hurt:

- **`ZIG_LOCAL_PKG_DIR` is per build root.** Zig 0.17.0-dev.1786 extracts
  packages into `<build root>/zig-pkg` (`Maker.zig:636`), not the global
  cache (`$ZIG_GLOBAL_CACHE_DIR/p/` holds only tarballs). A nested `zig build`
  in `examples/counter` therefore re-fetches your whole tree — capnp-zig,
  boringssl, and with `--fetch=all` the lazy quic dep — under its own root
  unless `ZIG_LOCAL_PKG_DIR` points at the parent's `zig-pkg/`. Our
  `example-smoke` tool exports it; our CI comments explain it; nobody
  discovers it from an error message. Worth one paragraph in your
  build-integration doc: "consumers of consumers set `ZIG_LOCAL_PKG_DIR`".
- **The boringssl local-cache poisoning.** A bare `zig fetch <archive>`
  (no `--save*`) of any single-root-directory archive — every GitHub
  `/archive/….tar.gz`, every `git archive --prefix=…` — prints the right hash
  but rewrites `$ZIG_GLOBAL_CACHE_DIR/p/<hash>.tar.gz` double-nested. Every
  later build-time fetch of that hash from a project whose `zig-pkg/` lacks
  it then fails with `hash mismatch: manifest declares <hash> but the fetched
  package has N-V-…`. We hit it on your transitive `boringssl-0.6.5`
  (a fresh worktree could not build until the entry was deleted), spent a
  review-wave finding on it (S8 #23), and now hash only through a throwaway
  `ZIG_GLOBAL_CACHE_DIR` (`tools/pkg_hash.sh`) with a CI check that goes red
  on purpose the day a Zig stops poisoning. It is a Zig bug, not yours, but
  your README's `zig fetch` examples are the first place a user will type a
  bare fetch; consider `--save` in every snippet.
- **The core/full module collision, two hops down.** `capnpc-zig-core` and
  the full `capnpc-zig` share source files and cannot coexist in one
  compilation. slcp-zig binds `slcp-core` to `core` and the node to `full`,
  so we carry a second `slcp-core` module instance bound to `capnpc_full`
  (`slcp_core_native`) purely so a consumer that imports `slcp` gets one
  copy of every capnp type. A downstream that also depends on capnp-zig
  directly (for its own schemas) would hit the same wall with no error
  message that names it. Ask: document the pattern ("one of core/full per
  compilation; bind everything to the same one") or ship a build helper that
  returns the right module for a given `(target, optimize, tier)` so the
  choice is made once.
- **Floor vs pin.** `minimum_zig_version` in a zon is advisory on this
  toolchain (the build runner parses it and never compares it). We enforce
  ours from `build.zig` at comptime by reading `@import("build.zig.zon")`;
  your consumers who rely on your floor get a deep `std.Io` compile error
  instead. Cheap to copy.

## Finding 2: two tools copied instead of imported, and a ceremony

We could not depend on your tooling as a package, so we copied it and it
diverged:

| Ours | Yours | Divergence |
|---|---|---|
| `tools/api_snapshot.zig` (1982 lines) | `tools/api_snapshot.zig` (1091 lines) | `diff` = 1805 changed lines: two-tier Stable/Experimental files, `experimental_overrides`, a rule-liveness comptime check, an `anyerror` scan, the ABI text parser, `platform_type_aliases` |
| `tools/docs_smoke.zig` (1709 lines) | `tools/docs_examples_smoke.zig` (481 lines) | same idea (`version_needles`, pin markers), rewritten: snippet/output markers, `zig build X` / `just X` / CLI-verb scans, two-way option-table check, a stale-pin scan |
| `RELEASING.md`, `just release-tag` / `verify-release-hash`, `.github/workflows/release.yml` | the same three | adapted: hash recorded BEFORE the tag (README/CHANGELOG are outside `.paths`), tarball-URL pins, the `pkg-hash` throwaway-cache rule |

Both tools were 100% worth copying and 0% reusable as-is: each imports the
project it audits (`@import("slcp")` for the comptime option list) and hard-
codes its paths. **Ask:** publish the generic halves — the declaration
walker + error-set renderer + line normalizer of `api_snapshot`, the
marker/needle scanner of the docs smoke, and the release recipes — as a
small build-helper package (`capnp-zig-devtools`?) that a downstream adds as
a dev dependency and configures with a table, so the next consumer does not
fork 3,700 lines. The tiering and the comptime rule-liveness check are the
parts we would most like to stop maintaining alone.

## Finding 3: what `examples/counter` hand-rolled

`grep -r '@import("capnpc-zig")' examples/` = **0** (verified at v0.1.0; the
only import is `@import("slcp")`). The omakase promise holds: a consumer
never sees Cap'n Proto. What the example hand-rolls that is *not* capnp:
`slcp.nodeId("<hex>")` (hex public-key parsing, ours), the five deployment
lines edited per machine (three keys, `.listen_port`, `.peers`), and
nothing else — no args parsing, no config file. Nothing to ask for here;
recorded for honesty.

## Finding 4: the `tcp.stream.Transport` reuse verdict (closes draft 05)

Kept ours. `src/node/overlay.zig` reuses only `rpc.wire.framing.Framer`
(zero findings against it through M5's two review waves and M6's) and drives
`std.Io.net.{Server,Stream}` directly. What would have flipped it at v0.1.0:
a `Transport` that (a) compiles on the pinned Zig (draft 05 F1: `io.vtable.
netWrite` / `netRead` no longer exist), (b) accepts an already-accepted
socket (`acceptFd`-style entry point) so our accept thread can hand it a
connection after the unauthenticated Hello handshake, and (c) exposes a read
deadline that does not go through `SO_RCVTIMEO` + EAGAIN (draft 05 F2). With
those three the per-connection reader/writer thread pair in overlay.zig
(~150 lines) would go away. Without them the reuse would cost a fork of the
transport, which is worse than owning 150 lines.

## Finding 5 (ask): a versioned plugin artifact — the hand-installed `capnpc-zig` drifted from the pinned package

S6 found that our checked-in `src/gen/*.zig` had been produced by a
`~/.local/bin/capnpc-zig` built from some pre-v0.16.0 checkout. Regenerating
with the plugin built **from the package `build.zig.zon` pins** changed 507
lines (+507/−5; commit `fee0853`): the pinned plugin emits `hasX()` pointer
presence accessors, `whichOrdinal()` on unions, and `!void` setters that the
stale one did not. Nothing had failed — the old output compiled and every
gate was green — which is exactly the problem: the plugin is part of the
pinned surface and nothing pins it.

What we do now (and what our CI does): extract the pinned package, `cd
zig-pkg/capnpc_zig-0.16.0-<hash>/ && ZIG_LOCAL_PKG_DIR=<repo>/zig-pkg zig
build -p <scratch>`, then `capnp compile -o<scratch>/bin/capnpc-zig:src/gen`
and `git diff --exit-code src/gen` (`just gen-check-pinned`). It works, it
is 8 lines of shell, and every consumer will have to rediscover it.

**Ask:** one of (a) a per-tag release asset `capnpc-zig-<os>-<arch>` with
its sha256 in the release notes, so a consumer's `gen-check` can pin a
binary; or (b) a documented `zig build` recipe consumers can pin — a step in
your `build.zig` that a dependency can reach as
`b.dependency("capnpc_zig", …).artifact("capnpc-zig")` (it must be
installed by your default `install` step: `Dependency.artifact` searches
only the top-level install step, `lib/std/Build.zig:1857-1873`) — plus a
line in the docs saying "regenerate with THIS, never a PATH binary". (b) is
what we would use tomorrow: `installArtifact(dep.artifact("capnpc-zig"))`
in the consumer's `build.zig` and a `gen-check` that runs it.

## Finding 6 (ask): explicit error sets on the builder API

`QuorumSet.Builder.initValidators` (`src/gen/slcp.zig`, generated) is
`fn (self: *Builder, element_count: u32) !DataListBuilder` — an inferred
error set that resolves, through `writePointerList`, to `anyerror`. Our
`qset.canonicalBytes` `try`s it, so its own inferred set is `anyerror` too,
and our API-snapshot tool renders the line as `anyerror!` — a frozen
Stable line that pins no error contract. We therefore hold
`qset.canonicalBytes` (and `validateAndNormalize`, `hashNormalized`,
`Engine.init`, which reach it) **out of the Stable tier** by an explicit
override, with a test that fails if any Stable function line ever renders
`anyerror`. That is the whole reason those four entry points are not Stable
at v0.1.0.

**Ask:** give the generated builder methods (and the `Builder`/`Message`
primitives they call) explicit error sets — `error{OutOfMemory,
SegmentFull, …}`, whatever the real set is — so a downstream can name them
in a `||` union and freeze the result. Additive for you (an explicit set is
a subtype of the inferred one), and it unblocks four Stable lines for us at
the next minor bump.

## Context for prioritization

F5 and F6 are the asks; F5 is the one that bit us silently. F1's
`ZIG_LOCAL_PKG_DIR` and core/full paragraphs are documentation. F2 is a
wish, not a blocker — we will keep maintaining the forks until there is
something to import. F3 and F4 close items from drafts 04/05 and need no
action. slcp-zig v0.1.0 is tagged against capnp-zig v0.16.0; the next slcp
minor is where a builder error set or a pinnable plugin would land.

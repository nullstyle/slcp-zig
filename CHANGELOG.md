# Changelog

All notable changes to slcp-zig are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project is
pre-1.0 and uses [semver](https://semver.org/) as `RELEASING.md` classifies it
(a Stable-surface change is a minor bump; fixes and docs are patches).

> **This is a vibe-coded project. Do not use it.** Every line in this
> repository was written by an AI coding agent under the direction of one
> person, as an experiment, and has not been reviewed or validated for
> anyone else's use. The release below exists so the experiment can be
> pinned and reproduced, not because it is fit for anything.

## [Unreleased]

## [0.2.0] - 2026-09-03

**Candidate package hash placeholder** (replace with `just release-hash`
before the tag; afterward it is what `zig fetch --save=slcp
https://github.com/nullstyle/slcp-zig/archive/refs/tags/v0.2.0.tar.gz`
records):

```
slcp-0.2.0-PLACEHOLDER0000000000000000000000000000000000000000
```

### Breaking

- The Experimental `slcp.store.Store.putQset` and `Store.getQset` methods
  were removed. Quorum-set answering now belongs to Node's private bounded
  cache instead of the safety-critical consensus-log Store.

**Migration:** consumers that called those Experimental Store methods should
use the native Node's normal `request_qset` / `getQset` exchange and inspect
`Node.storageStats()`, or own a separate application cache if they drive the
sans-I/O Engine directly. No Stable declaration changed.

### Added

- **`examples/registry`** — the second example and step E1 of the examples
  roadmap: a replicated name registry with stellar-core's shape and no
  money. Ed25519-signed transactions with per-account sequence numbers,
  transaction sets as the consensus value (a custom codec and a `combine`
  that unions candidates), a ledger header hash chain, an atomically
  written snapshot after every applied slot (`initialState` +
  `initialSlot`), a localhost line-protocol RPC (`head`, `get`, `account`,
  `submit`) and a CLI (`registry node | submit | get | account | head`).
  Library-neutral: it uses only the v0.1.0 Stable API and records the gaps
  it hits (no transaction flooding, the fixed 16-slot answering window, the
  typed layer's per-slot state copy) for the next step.
- `zig build registry-tests` (in `test`): the example's pure state machine,
  its RPC, and a live 2-of-2 pair with a restart from a snapshot;
  `registry-intree` compiles the program against the in-tree module.
- `zig build registry-smoke` / `registry-build` (`tools/registry_smoke.zig`;
  CI on ubuntu + macOS in the `example-smoke` job): one nested consumer
  build, three nodes over loopback (ports 47411–47413, RPC 47421–47423),
  conflicting claims, `set` / `transfer` / `release`, identical heads,
  `SIGKILL` + restart of one node and a transaction through the restarted
  node. Evidence: `[registry-smoke] nodes=3 txs=7 slots=N head=<hex16>`.
- Experimental native-node ingress statistics, a bounded priority purge lane,
  and `-De2e-filter` for focused real-socket regression runs.
- A bounded, restart-aware native quorum-set answering cache: 1,024 managed
  entries including the pinned local set, 64 MiB logical payload bytes, 1 MiB
  per entry, FIFO runtime eviction, deterministic restart reconciliation,
  atomic replacement, capped reads, lazy semantic hash verification, and
  fail-closed write degradation. Experimental `Node.storageStats()` reports
  logical usage, removals, failures, and the sticky degraded state.
- `-Dnode-filter` for focused native-node and cache regression runs.
- Canonical `CONTEXT.md`, `DESIGN.md`, `STATUS.md`, and
  `docs/examples-roadmap.md` project-state documents.

### Changed

- Quorum-set evaluation now follows the exact qset advertised by each live
  non-EXTERNALIZE statement. Live-statement references, the permanent local
  pin, and short-lived fetched-response replay leases make cache residency
  explicit; graph reachability is checkpointed across bounded generations.
  EXTERNALIZE continues to use its protocol-defined sender singleton.
- Native Engine ingress is bounded to 1,024 items / 16 MiB with reserved local
  capacity. Purges overtake ordinary work, stale work is rejected again at
  application time, and restart reconstructs a monotonic floor before replay.
- Engine-derived node statistics publish only at complete input/effect-drain
  boundaries. Input-sequence fuzzing now generates diverse valid typed streams,
  and restart E2E evidence requires fresh post-restart participation.
- Quorum-set disk persistence is separated from the consensus-log Store.
  Only requested, validated, successfully queued remote responses are cached;
  cache I/O failure becomes a miss and never makes consensus inert.

### Fixed

- Prevented an overtaken local nomination, retained journal prefix, lowered
  explicit start floor, or metadata-decoding OOM from recreating retired slots.
- Rejecting an incompatible newer peer ballot no longer destroys that peer's
  previous valid statement or releases its qset reference.
- Quorum-set responses are correlated to outstanding requests and remain
  retryable when native ingress is under pressure.
- Node qset correlation now applies the same 1 MiB frame, nesting, and
  traversal limits as Engine ingestion, so an oversized parseable response
  cannot consume a request that the Engine would reject.
- Qset-cache startup uses memory proportional to its entry cap even when
  pruning an old unbounded directory. Same-sized corrupt/wrong-hash files,
  mixed-case path aliases, symlinks, atomic-write failures, OOM, concurrent
  access, churn, and restart are covered by regression tests.

## [0.1.0] - 2026-09-01

The first tag. Everything below is new to a reader who has never seen the
repository; the milestones M0–M6 are the order it was built in.

**Package hash** (what `zig fetch --save=slcp
https://github.com/nullstyle/slcp-zig/archive/refs/tags/v0.1.0.tar.gz`
records in a consumer's `build.zig.zon`; computed with `just release-hash`
from the tagged tree — README.md and this file are outside `.paths`, so
recording it here does not change it):

```
slcp-0.1.0-p1Kf2iJtEwBe2gyU1SFRaJQ3tqSh-XMOTSwxmp4pxgKz
```

### Added

- **`slcp-core` (M0–M3):** a sans-io, deterministic SCP-style federated
  Byzantine agreement engine — inputs in, effects out, no clock, no sockets.
  Cap'n Proto wire format (`schema/slcp.capnp`), canonical encoding and
  domain-separated Ed25519 signing, quorum-set normalization and hashing,
  quorum-slice math and federated voting, nomination + ballot protocols with
  stellar-core as the line-level oracle, statement sanity checks, leader
  election, a deterministic multi-node simulator with a 15000-cell matrix
  (`zig build sim-matrix`), a 1000-seed × 2-actor Byzantine matrix
  (`zig build byz-matrix`), decode / input-sequence / codec fuzz targets
  (`zig build fuzz`), and frozen cross-implementation conformance vectors
  under `vectors/` (`zig build vectors` regenerates them; a protocol event).
- **WASM host ABI (M4):** `slcp_core.wasm` (`zig build wasm`,
  wasm32-freestanding) exporting the `slcp-abi.*` surface, an ABI
  conformance suite, and a differential native-vs-wasm replay of the trace
  vectors plus 300 differential fuzz iterations (`zig build wasm-diff`).
- **`slcp` node (M5):** the native "omakase" node over the engine — a TCP
  flood-gossip overlay over `std.Io.net` reusing capnp-zig's frozen segment
  framer, Ed25519 keys (`slcp.key`, created 0600 atomically), a write-ahead
  journal + own-statement log with torn-tail repair and compaction, restart
  recovery with gap-jump, anti-entropy resync, per-connection frame / queue /
  request budgets, and the 4-node real-socket end-to-end cluster
  (`zig build e2e`: 200 slots, kill/restart, partition/heal, an equivocator,
  two nodes restarting together three times).
- **Typed application layer (M6):** `slcp.AppNode(App)` — a comptime contract
  (`State`, `Command`, `validate`, `apply`, optional `initialState` /
  `initialSlot` / codec) with 23 teaching compile errors
  (`zig build appnode-errors`), the deterministic auto-codec `slcp.Codec(T)`
  (strict decode, bijective on the accepted set, numeric order = byte
  order, signed-tag enums sign-bit-biased), `waitApplied` / `haltError`, and
  the delivery hook it is built on (`slcp.DeliveryHook`, slot-ordered
  delivery at the frontier, journal-tail replay before the threads start).
- **Quorum UX (M6):** the `slcp.Quorum` spec (flat and nested, JSON or Zig),
  four lint codes incl. `critical_node`, `minBlockingSize`, the
  human-readable `slcp.lint_report`, the `Node.CreateError` taxonomy with
  actionable one-line messages (`Node.explain`, `Diagnostic`), and the
  `slcp` CLI: `slcp lint-quorum <file> [--self HEX]`, `slcp key new`,
  `slcp key show`, per-verb `--help`, `--version`. Three copy-paste recipes
  under `docs/recipes/`.
- **Operator surface (M6):** hostname peer specs (`host:port`, bracketed
  IPv6), `peer N up|down` / "waiting for a quorum" info logs, the
  `data_dir/identity` marker (`DataDirOtherNetwork` / `DataDirOtherNode`),
  a data_dir lock (`DataDirBusy`), `PeerIsSelf`, `ListenPortInUse` /
  `ListenPortPrivileged`, and a world-readable key file refused at create
  (`KeyFileTooPermissive`, ssh-style).
- **The §0 program:** `examples/counter` — a three-node replicated counter
  that is byte-identical in README.md, builds as a consumer package, and
  is run over loopback with a `SIGKILL` + restart by `zig build
  example-smoke`. `examples/bytes_node.zig` is the raw-bytes twin.
- **Docs (M6):** `docs/protocol.md`, `docs/threat-model.md`,
  `docs/quorum-recipes.md`, `docs/driver-upgrade.md`, `docs/determinism.md`,
  `docs/stability.md`, all behind the docs-smoke gate (`zig build
  docs-smoke`: snippets byte-equal to the sources they quote, recipe output
  byte-equal to the real CLI, every documented step / recipe / verb exists,
  version pins match the manifest).
- **API freeze (M6):** two-tier snapshots — `docs/api-snapshot.txt` (Stable,
  frozen: drift is red) and `docs/api-snapshot-experimental.txt` — with
  `check-api` + `api-closure` inside `zig build test`, and `docs/stability.md`
  as the rule book.
- **Release machinery (M6):** `.github/workflows/ci.yml` (test on ubuntu +
  macOS, e2e, example-smoke on both, fmt-check + pkg-hash-check, gen-check
  with the plugin built from the pinned capnp-zig package), the `preflight`
  build step and `just preflight` (every mandatory gate from a fresh cache,
  evidence lines grepped), `just package-preflight` (the `.paths`-filtered
  tarball rebuilt by a real consumer), `just release-hash` /
  `release-tag` / `verify-release-hash`, `RELEASING.md`, this file, and the
  tag-audit workflow `.github/workflows/release.yml`.

### Changed

- **Inbound statements are gated by the delivery frontier (S8 review, D1).**
  The host holds every statement — EXTERNALIZE included — for a slot above
  `next_deliver` from a signer inside the quorum graph (signature-verified,
  window 64, 1024 entries / 8 MiB, deduplicated per slot/signer/kind) and
  releases slots ascending as the frontier advances; the only early release
  is a slot whose held EXTERNALIZEs come from a v-blocking set (catch-up).
  Without it, a node one slot behind that saw the next slot's nomination
  cached `.maybe_valid` and went mute on that slot forever: two nodes
  restarting mid-slot at 2-of-3 halted the network with everyone live.
  Pinned by `tests/liveness_test.zig` and an e2e scenario.
- `.paths` is `build.zig`, `build.zig.zon`, `src`, `schema` plus the one
  `tests/appnode_errors/cases.zig` that `build.zig` imports — the package
  ships the checked-in generated code and the schemas, nothing else
  (`just package-preflight` rebuilds a real tarball consumer to prove it;
  it caught `build.zig` importing an unpackaged file before this tag).
  `minimum_zig_version` is `0.17.0-dev.1786`, enforced by `build.zig` at
  comptime (the build runner never compares the zon floor).
- capnp-zig is pinned at v0.16.0 by tag URL; `src/gen` is regenerated only
  with the plugin built from that pinned package (the checked-in code had
  been produced by a stale hand-installed plugin — +507/−5 lines).
- Compaction runs whenever the delivered frontier crosses a 64-slot bucket;
  re-flood and `getSlotState` answers are in ascending slot order.
- `keys.load` / `createNew` / `loadOrCreate` carry named error sets;
  `modeOf` / `modeTooOpen` use `u32`, never the OS `mode_t`.

### Fixed

The S8 adversarial review wave (202 agents, 79 findings, 68 confirmed by two
independent skeptics, 63 fixed with a red-then-green pinning test each) and
the S8b liveness follow-up. The five findings rated critical (the two engine double frees share one bullet):

- **Engine double free on OOM:** `storeLatest` freed a failed self-record
  and its callers in `nomination.zig` / `ballot.zig` freed it again. One
  ownership rule now.
- **Ballot timer at counter ∞:** a stale `timer_fired` for a slot whose
  ballot counter was already ∞ (after EXTERNALIZE or a restore) overflowed
  the `u32` counter and aborted the engine thread; the "harmless stale fire"
  comment was false. The bump is refused.
- **`AppNode.deinit` / `Node.deinit` while a caller was parked in
  `waitApplied` / `waitExternalized`:** hang or use-after-free. deinit now
  drains the waiters before freeing.
- **The mute-node liveness halt** described under *Changed* (the hold
  buffer).

Also fixed: `Node.create`'s unwind leaked the replay/restore buffers and a
latch during the own.log restore left an inert node instead of failing;
best-effort dispatch OOMs were swallowed; a failed nomination enqueue
dropped the proposal; an empty inner quorum level was not `QuorumEmpty`;
`Store.open` hid the real filesystem error; the request budget was not
enforced (flooders are now disconnected after 32 strikes) and `stop()`
could block on a black-holed dial; a bracketed IPv6 peer spec without a
port was misreported; the CLI's positional `File.writer` overwrote earlier
bytes of a redirected stdout, and a flush failure exited 0; unknown JSON
keys in a quorum spec were ignored (now `UnknownField`, named); the
delta-app recipe was unimplementable (`initialSlot()` seeds the replay
floor; a snapshot outside the journal is refused); the store leaked the
journal payload when `tail_map.getOrPut` failed; `engine/pipeline.zig`'s 17
tests had not been compiled since M4; `src/cli` was outside `fmt-check`;
the enum-tag codec ignored the tag type's signedness; a load-flaky DELTA
test; and a dozen documentation claims that disagreed with the code
(compaction trigger, strike semantics, "double-apply", per-level lint,
`Node.explain` on AppNode errors).

### Security

- **No transport authentication in v1.** Only envelope signatures are
  authenticated; Hello fields are unauthenticated hints; a wrong network
  prefix disconnects. Run the overlay inside WireGuard or equivalent
  (`docs/threat-model.md` §2).
- Statements are signature-verified before they are held or relayed; only
  signers inside the quorum graph are held; strangers are dropped
  statelessly.
- Per-connection frame cap, queue caps, inbound cap, a 10 s handshake
  deadline, and a request budget with lifetime strikes ⇒ disconnect.
- A key file readable by group or other is refused at create; `slcp key
  show` warns.

### Known limitations

- **`State` is not persisted.** On restart an `AppNode` is
  `initialState()` plus the replayed journal tail (compaction keeps only
  the recent slots), so commands must be full values; delta applications
  persist their own state and seed `initialSlot()`.
- **No transport authentication** (above).
- **Own proposals follow `current_slot`** (the raw externalized frontier)
  during out-of-order catch-up: a stale own nomination costs one round and
  is never accepted; held-entry dedup is arrival-order.
- **Fixed e2e ports** (39100–39504) and fixed example-smoke ports
  (47311–47313): run `zig build e2e` alone. On macOS `reuse_address` also
  sets `SO_REUSEPORT`, so two slcp nodes can bind one port
  (`ListenPortInUse` is Linux-only for slcp-vs-slcp collisions).
- The `Engine.init` and `qset.validateAndNormalize` / `hashNormalized` /
  `canonicalBytes` entry points are held out of the Stable tier: their
  inferred error sets resolve to `anyerror` through capnp-zig's builders.
- Long fuzzing is advisory: the release ran what `RELEASING.md`'s run log
  says it ran, nothing more. The long runs before this tag (200K, then
  50K, then a re-run) failed the input-sequence target three times
  (`error.OwnStatementNotMonotonic`, the §13.1 harness invariant). Settled
  before the tag as a **harness
  artifact**, not an engine bug: the target nominated for a slot it had
  already purged (`purge_slots`), the engine re-created the slot from
  empty state — exactly what stellar-core's `SCP::getSlot(create=true)`
  does after `purgeSlotsOutsideRange` — and the checker compared the fresh
  slot's first NOMINATE against the forgotten one. The sim invariants
  tracker now forgets purged slots with the engine and judges own
  EXTERNALIZE pairs by committed value (as the e2e watchdog already did);
  the three saved inputs are a committed regression corpus
  (`tests/fuzz/crash/`, replayed inside `zig build test`, traced by
  `zig build fuzz-replay`). No `src/` change; the package hash above moved
  only because `build.zig` (inside `.paths`) gained the `sim-tests` and
  `fuzz-replay` steps.
- A watcher (no key) skips the identity node-id comparison; `Hello.listenPort`
  is sent but never used for dialing.
- No license is granted.

[Unreleased]: https://github.com/nullstyle/slcp-zig/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/nullstyle/slcp-zig/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nullstyle/slcp-zig/releases/tag/v0.1.0

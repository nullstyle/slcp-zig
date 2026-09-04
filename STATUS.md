# Project Status

**Snapshot date:** 2026-09-04

This file distinguishes released code, the prior v0.2.0 candidate, and current
feature work. It is a snapshot, not a guarantee of fitness: this remains an
experimental project, no production use is recommended, and no license is
granted.

## Repository baseline

| State | Revision | What it contains |
|---|---|---|
| Released | `v0.1.0` at `916907a` (2026-09-01) | First engine, native node, typed application layer, CLI, examples/counter, protocol docs, conformance and release gates. |
| Pre-sprint `main` baseline | `cf3b84b` (2026-09-02), two commits after the tag | Post-tag documentation corrections plus E1 of the examples track: `examples/registry`. |
| Hardening baseline | local `main` at `87d7083` (2026-09-03) | Exact qset lifecycle, bounded native ingress, restart/purge hardening, stronger fuzz/E2E evidence, canonical project state, and its recorded proof. |
| Package payload freeze | `1b68041` (not pushed or tagged) | Adds the bounded best-effort on-disk qset answering cache and its Experimental diagnostics on top of the hardening baseline. |
| Local repository candidate | code tip `0f39869` plus hash-neutral release records (not pushed or tagged) | Retains the frozen package payload and fixes the example registry's detached RPC-handler teardown race found during release ablation. |
| E2a implementation and proof | `50456f7` through `0932a83` (including smoke `6899855`, legacy-Hello test `2051f5b`, and waiter/FIFO hardening `0932a83`) | Adds negotiated, bounded Experimental application-message transport, registry-controlled flooding, deterministic source-death proof, outbound isolation, and race-safe inbox teardown. |
| E2b implementation and proof | `c66b450` through `35ad39b` (registry feature `f77e01c`, exact-current smoke `35ad39b`) | Adds application-owned quorum-authenticated registry checkpoints, durable local signing fences, hostile-archive handling, exact-successor `AppNode` recovery, CLI integration, and a proved long-outage rejoin. |
| E2c implementation and proof | `77ac9b1` through `83d66f7` | Adds typed `ValueContext`, phase-separated validation caching, deterministic registry close time, G-anchored restored-state checks, a hard network/storage epoch, exact timed checkpoint recovery, closed-slot restart rejection, and a strengthened long-outage temporal-chain smoke. |
| E2d implementation and proof | `422b479` (registry feature), `d2324e6` (peerless-recovery smoke) | Replaces registry checkpoint-only recovery with per-slot immutable ledger records, quorum-certified history tips, bounded strict replay, crash-durable ordered publication, and peerless recovery proof. |
| Native answering-window control and proof | `327e614` (feature), `cb052c0` (real-socket proof), `636af81` (boundary hardening), `7bc2cb6` (Stable API acceptance), `d9880d7` and `4bf729e` (capacity and telemetry corrections) | Adds Stable per-node `answering_window_slots`, Experimental local catch-up telemetry, a configured-window exact-recovery/voting witness, and maximum-capacity recovery hardening. |
| Package manifest | version `0.2.0` | `v0.1.0` remains the latest release until the candidate is pushed, passes CI on its exact commit, and is tagged. |

The v0.1.0 evidence and limitations are recorded in
[`CHANGELOG.md`](CHANGELOG.md). The committed E1 scope is summarized in
[`docs/examples-roadmap.md`](docs/examples-roadmap.md).

## Current feature work: archive retention

Both sides of the registry's history are now garbage-collected
([ADR 0004](docs/adr/0004-registry-capacity-epoch.md) closed the state-growth
half; [ADR 0005](docs/adr/0005-archive-retention.md) closes the disk-growth
half). The publisher prunes at each anchor boundary, and startup runs one
pass before RPC binds. The safety rule: for every assertion the validators'
latest pointers expose — certified or not — retention keeps its anchor
snapshot, its complete verified ledger chain to the anchor, and every vote
naming its digest; everything else in this module's exact canonical spelling
is unreachable by any recovery this archive can perform and is deleted. On
the trusted side, the watermark-referenced frontiers and live staged backlog
survive; per-slot signing votes below the published watermark are inert
behind the high-water fence and are collected. Deletion candidates must
match the exact canonical name (mixed-case aliases, unrelated files, and
directories are untouched — the qset-cache discipline); keep-sets are
computed before any delete, deletes happen after iteration, and an
incomplete pointer chain aborts the pass with zero deletions, so retention
is idempotent, crash-safe, and nonfatal. Four focused tests prove: recovery
to the pointer-exposed tip stays byte-exact after pruning and a second pass
removes nothing; a broken pointer chain aborts untouched; hostile and
unrelated objects survive while stale temps collect; and the trusted GC
keeps watermark frontiers, collects an orphaned staged file and old signing
votes, and the archive reopens on its published frontier. A side fix frees
the publisher worker's per-slot staged state (a slow leak only the real
process hit).

### Current retention verification

- Registry suite: **PASS** — 104/104 (four new retention tests), zero leaks.
- Docs-smoke: **PASS** — 436 checks, 0 failures.
- Full three-process registry smoke: **PASS** (4 min) — the ReleaseSafe
  consumer build compiles the startup prune path, and the live line's
  flooding, close-time chain, restart, ≥201-slot outage with peerless
  anchor-to-certified-tip replay, and hard-epoch probe all pass with
  retention active.
- Repository gate: **PASS** — 113/113 steps, 208/208 tests; strict API gate
  green (no library surface changed this sprint).

## Historical feature record: registry heap-state migration (capacity epoch)

The registry example now runs on the heap-sized state seam end to end. On top
of the Experimental `slcp.OwnedAppNode` adapter (ADR 0003, below), the
example's state became unbounded heap storage: sorted `ArrayListUnmanaged`
accounts and names with explicit `deinit`/`clone`, an allocating `apply`
(only `OutOfMemory` can fail it, which halts the node), and Snapshot V4
state encodings with u32 counts and dynamic lengths. The 64-account/128-name
caps and the `registry_full` result no longer exist; 32 transactions per
slot still bound the consensus VALUE. The REGISTRY-NET-V3 network tag makes
the snapshot format change a loud application epoch (V3 snapshots fail the
magic check; old data directories fail as `DataDirOtherNetwork), following
the E2c mixed-version rule. The boot snapshot reaches `initState` as the
create context — the process-global `boot` is gone — and applied
observations are owned clones: the cadence loop borrows them for the
snapshot write and history staging, then moves each into the RPC shared
state, freeing its predecessor. The history archive clones into its
frontier/ready/inflight/proof fields and frees on every rejection path.
Ledger records, tip assertions, and the LedgerValue encoding are
byte-identical; the genesis state root moved with the empty-state encoding
(the format goldens moved with it). See
[`ADR 0004`](docs/adr/0004-registry-capacity-epoch.md).

### Current registry-capacity verification

- Registry suite: **PASS** — 100/100 (99 migrated plus the cap-removal
  proofs: 500 accounts and 300 names validate/apply/sort correctly, and a
  V4 snapshot round-trips byte-identically far beyond both old caps), with
  **zero leaks** under the testing allocator.
- Docs-smoke: **PASS** — 436 checks, 0 failures.
- Full three-process registry smoke: **PASS** — the ReleaseSafe consumer
  build plus the live quorum line, transaction flooding across hops, the
  deterministic close-time chain, ordinary restart, the ≥201-slot outage
  with peerless anchor-to-certified-tip replay, the necessary recovered
  vote, and the hard-epoch data-dir probe, all on the heap-backed state.

## Historical feature record: heap-sized application state seam

Experimental `slcp.OwnedAppNode(App)` (ADR 0003) is the opt-in sibling of the
typed `AppNode` for state that does not fit by-value copies: one adapter owns
allocation, initialization, mutation, observation, and cleanup.
`initState(context, gpa)` loads a durable snapshot or builds genesis on the
creating thread before any engine exists — the caller-supplied context is the
explicit snapshot handoff, replacing the registry example's process-global
`boot`. `validate` and `combine` read `*const State` with no allocator;
`apply` mutates in place and may allocate, with `OutOfMemory` as its only
expressible failure (the signature enforces it) — the delivery hook
propagates it and the node latches inert, so engine-thread allocation failure
is fail-stop liveness loss, never a consensus divergence, and a partially
applied state is never consulted again. `observe` produces an
application-defined observation on the engine thread after each applied slot;
plain data needs no cleanup, while an observation that owns memory declares
`deinitObs` and every taken `Applied` returns through `release`.
`deinitState` frees everything after the engine thread joins, including
queued-but-unconsumed observations. Restart continuity keeps `AppNode`'s
rules: `initialSlot`/`initialCommand` read from the loaded state, journal-tail
replay through `apply` on the creating thread (its observations queue for
`waitApplied` like live ones), and the exact-successor external-checkpoint
start with its preceding command. The contract is comptime-checked with 25
teaching errors, each pinned by a `tests/appnode_errors/owned_*.zig`
expected-fail object behind the new `owned-appnode-errors` build step, with a
docs-smoke liveness count. Thirteen tests prove the lifecycle, including zero
allocations per applied slot over a 100,000-entry heap state (a deep-copy
notification path would allocate ~800 KB per slot), observation immunity to
later mutation, complete unwinding of `initState` and replay-OOM failures
with nothing started, and a 2-of-2 loopback restart whose snapshot travels
through the context. The Stable `AppNode(Counter)` surface is byte-identical.

Migrating the registry example onto this seam is the next E2-remainder step
and is its own application storage epoch: Snapshot V3 and the replayable
history formats carry fixed-width counts and entry widths, so removing the
64-account/128-name caps requires a V4 snapshot and anchor/history format
decision with E2d-grade migration care (`docs/examples-roadmap.md`).

### Current owned-state verification

- Repository gate: **PASS** — 113/113 build steps; 203/203 tests passed in
  the recorded run (the gate includes the 25 new expected-fail compile
  objects and the new liveness test).
- Native node suite: **PASS** — 206 passed plus 1 expected platform skip out
  of 207 (193 before; the 13 new owned-adapter tests include the 2-of-2
  loopback restart).
- API gate: **PASS** — the 292 Stable declarations are byte-identical;
  1,574 Experimental declarations verified, now including a reference
  instantiation of `OwnedAppNode` over a heap counter so the Experimental
  file tracks the real surface.
- Docs-smoke: **PASS** — 436 checks plus 18/18 tests (one new
  owned-appnode-errors liveness test).
- The real-socket E2E suite is unchanged by this seam (no Node behavior
  touched) and is rerun as part of the final gate below.

## Historical feature record: configurable native answering window

Each native Node now accepts an `answering_window_slots` value from 1 through
62, defaulting to 16. That window bounds retained own statements used to help
a recently lagging live peer and the slot-distance at which the local node may
abandon an unavailable gap. Experimental `catchupStats()` reports coherent
node-local cached-own-statement count and bounds for slots at or below the
ordered-delivery frontier, buffered work, drop counters, and gap jumps. Cached
slots may include locally abandoned slots or holes, and the snapshot is not a
peer or quorum view. The registry intentionally keeps the default 16-slot live
window and uses its application-owned replayable archive for long outages.

### Current answering-window verification

- Repository gate: **PASS** — 87/87 build steps; the latest cached invocation
  executed 627 passing tests plus 1 expected platform skip.
- Native node suite: **PASS** — 193 passed plus 1 expected platform skip out
  of 194.
- Full real-socket E2E suite: **PASS** — 8/8, including configured-window
  exact contiguous catch-up beyond 16 slots and subsequent voting.
- API gate: **PASS** — 292 Stable declarations frozen and 1,497 Experimental
  declarations verified.
- Docs-smoke: **PASS** — 436 checks plus 17/17 tests.

## Historical feature record: E2d replayable registry history

E2d is implemented and verified in the registry example. Every applied
non-genesis slot produces an immutable, cadence-independent ledger record
containing the exact canonical `LedgerValue` and complete resulting Header V2.
Slot 1 and every configured `--checkpoint-every N` boundary are Snapshot V3
anchors, with N defaulting to 8 and accepted from 1 through 64. Once a newly
applied state reaches a
deterministic anchor, each validator signs a `REGISTRY-HIST-V1` assertion at
that slot and every subsequent slot, binding the exact tip slot/head, anchor
slot/head/snapshot digest, and N.
Unique votes certify that exact history tip only under the importing node's
normalized local quorum policy. On every fresh non-genesis signing-tree
activation, the existing base is not republished or treated as
continuity-proven, even at slot 1 or an N boundary. Successor ledger recording
starts immediately; tip attestation starts only when a newly applied successor
reaches the next deterministic anchor, then continues at every slot.

Recovery selects an eligible quorum-certified tip, loads its Snapshot V3
anchor, and strictly replays each later immutable record in exact slot context.
Canonical decoding, contiguous hashes, application validation and application,
the complete resulting header, exact last value, and final signed tip hash must
all agree. Startup materialization is bounded to `N-1` applications—at most
63—and reaches the exact tip before a peer is needed. Anchors are not
continuity resets: before signing an anchor-slot tip assertion, publication
reconstructs and validates that anchor's own transition from the preceding
segment. End-to-end ancestry therefore combines the immutable header/value
chain with enforced publisher continuity under the configured quorum-safety
assumption.

Publication is ordered and crash-durable. Before the ordinary local snapshot
advances, the full pending Snapshot V3 state is staged and the admitted
watermark synchronized in the trusted history outbox. The sole worker retries
the oldest entry, advances a durable published watermark, and removes the
entry only after success. Before creating the real peer-connected Node, startup
drains older admitted work before considering a newer shared proof. A
persisted trusted adoption target T instead takes precedence over mutable proof
U before the operator floor is applied; the floor is then enforced against T.
An isolated no-peer AppNode installs and confirms T, stages and snapshots its
exact journal continuation, and synchronously publishes that continuation.
Startup then
reruns certified recovery from the installed frontier, may prepare a newer U,
and only creates the real peer-connected Node from that final selection. During
either startup journal replay only, a full outbox may publish one oldest entry
synchronously to make room; a full runtime backlog, trusted publication gap or
outbox/fence failure, invalid state, or certified fork is fail-stop. The
background publisher starts only after RPC binds.

Confirmation persists separate trusted boot provenance before clearing an
adoption marker and advances it only after exact successor snapshots are
durable. This preserves the external successor handoff across later crashes
and shared withholding; fresh history activation does not gain that provenance
without an exact certificate.

The shared archive remains hostile input and never supplies quorum policy or a
freshness guarantee. After any trusted adoption has completed, startup reads
one latest pointer per configured validator, considers at most 16 distinct
valid candidates, and can lose discovery of an older certificate when pointers
advance. Withholding an anchor, ledger, or vote can deny recovery of that
candidate; a lower replayable certified candidate may still be selected if it
reaches the operator floor. Same-slot fork detection covers simultaneously
discoverable candidates, and replay from an anchor does not prove that anchor
descends from an unrelated lower local head. Those limits retain the same
current-quorum safety assumption as live consensus.

Both shared and trusted storage use a new `history-v1` namespace. The trusted
side also persists the anchor policy and durable outbox, so checkpoint-only
archive objects, old fences, and a silent cadence change are rejected rather
than reinterpreted. This is an application-storage migration boundary, not a
new SLCP network epoch: the E2c network descriptor, LedgerValue, Header V2,
Snapshot V3, consensus schema, and Stable library surface remain unchanged.
The shared archive and immutable trusted per-slot signing/frontier evidence grow
until an explicit retention policy exists. See
[`ADR 0002`](docs/adr/0002-registry-replayable-history.md).

The updated smoke uses 64-slot anchors, keeps node2 away for at least 201
slots, and requires an exact non-anchor certified tip at least 17 ledger
records beyond its anchor. Both certifying peers then stop; node2 must replay
alone to that exact slot/hash/time and expose it before either peer returns.
Node1 then returns, and node2 is required with it to externalize transaction 8
in the first later transaction-bearing ledger before node0 rejoins.

### E2d verification

The final integrated graph passed all 87 build steps and 620/621 tests, with one
expected platform skip. Its focused suites passed 99/99 registry tests and
25/25 smoke-harness tests. Formatting and whitespace checks passed. The API
gate retained all 290 Stable declarations and verified 1,469 Experimental
declarations. Docs-smoke passed 432 checks plus 17 tests.

The real three-process consumer smoke passed in 254,981 ms. With genesis time
G=1788542443, node2's durable outage origin was S=9. Node0 and node1 certified
the exact non-anchor tip H=210 from anchor A=192, proving H-S=201 and an 18-ledger
replay. Both certifiers then stopped. Node2 alone replayed A through H and
exposed H's exact hash and close time; after node1 returned, those two nodes
certified transaction 8 at slot 211 while node0 remained down. All three
converged, the mismatched G+1 data-dir probe failed closed, and the final
evidence line was:

```text
[registry-smoke] nodes=3 txs=8 slots=214 head=9e39723aaa35631a
```

No earlier E2c result is reused as E2d proof.

### E2c foundation and historical proof

E2c makes each registry consensus value a canonical
`LedgerValue { close_time, txs }`. For local head `(H,T)` and checked slot S,
typed validation receives `slcp.ValueContext`, derives `d = S-H`, and permits
time only in `[T+d,T+60d]`; the immediate successor must also be fully valid
on current transaction state. Proposal construction is the sole wall-clock
boundary and clamps Unix time to `[T+1,T+60]`. Combination chooses the minimum
candidate time plus deterministic transaction union, and application accepts
only an exact successor advancing 1..60 seconds. Consensus therefore agrees
on bounded logical time, not truthful UTC.

The operator-supplied genesis close time G joins the human passphrase in the
canonical binary Node/registry network descriptor. Genesis is a real hashed
header committing to G and empty state. Header V2 binds network id and close
time; Snapshot V3 stores the exact final timed value; checkpoint assertions
use their V2 domain. This is a hard epoch with no silent migration of old
snapshots, bare-TxSet journals, checkpoints, or signing fences. Changing G
under the same passphrase produces a different Node identity and requires a
fresh private data directory.

E2b builds on the delivered E2a transport slice. E2a added append-only
application-message negotiation, bounded Experimental native Node send/receive
entry points, and registry-owned transaction authentication, relay, reflood,
and admission. Delivery remains best-effort and non-durable; the generic Node
does not authenticate or auto-relay application bytes. The three-node smoke
still proves that a transaction crosses one and two overlay hops before
consensus, survives the submitting node's death, and lands in the next
eligible slot.

At the pinned E2c tip, the registry still used periodic quorum-authenticated
Snapshot V3 checkpoints and the checked H-to-H+1 `AppNode` handoff, then relied
on a live peer for the remaining recent suffix. That checkpoint-only format
and its publication policy are historical E2c provenance, not the current E2d
architecture. E2d preserves the hostile/shared versus trusted/private custody
split, signing rollback and equivocation fences, explicit operator floor,
candidate-discovery caveats, and exact predecessor-value handoff while adding
the replayable chain and durable ordered outbox described above.

The historical E2b checkpoint proof is pinned at `35ad39b` (66 focused tests
and its exact-successor smoke). At final E2c code tip `83d66f7`, the focused
suites passed 163/163 core tests, 187 native-node tests with one platform
skip, 80/80 registry tests, and 18/18 smoke-tool tests. The strict full test
graph passed all 87 build steps; its API gate verified 290 Stable and 1,469
Experimental declarations, and docs-smoke passed 432 checks plus 17 tests.

The strengthened integrated smoke then passed in 291,323 ms against that code
tip: G=1788510951; outage S=11; certified and selected checkpoint C=B=208;
stable sole-survivor head H=212; H-S=201 and H-C=4. The recovered validator
caught the exact H/hash/time, was necessary for quorum, and transaction 8
appeared in the first later transaction-bearing ledger at slot 213. Every
intermediate and outage ledger formed one contiguous 1..60-second time chain,
the third validator rejoined, and all three converged at slot 233 with head
`e76ea6d8b56536c9`. A process-level probe changed only G to 1788510952 and
proved the existing data directory fails closed as `DataDirOtherNetwork`.

No Stable declaration changed. `slcp.ValueContext` and the registry-specific
archive are Experimental; the archive is not exported by the library.
`slcp.node.Node.createWithRecovery`, `RecoveryOptions`,
`RecoveryHook`, `RecoveryView`, `RecoveryJournalTail`, and `RecoveryValue` are
new Experimental recovery surface. The signed consensus schema and sans-I/O
Engine remain unchanged.

## Prior v0.2.0 candidate record

The candidate combines the completed correctness and boundedness sprint with
a second storage-boundary sprint. This is still not a release or deployment
claim.

The sprint scope is:

- make quorum-set cache lifetime follow live non-EXTERNALIZE statement
  references and evaluate each such statement against the exact quorum set it
  advertises; EXTERNALIZE keeps its protocol-defined sender singleton;
- publish Engine-derived node statistics only at completed engine-input
  boundaries, while keeping the independent fatal-failure latch immediate;
- bound native engine ingress by item and byte budgets while reserving room
  for local progress inputs, and expose drop/pressure counters as
  Experimental diagnostics;
- reject peer statements below the host purge floor, including statements
  that were held before the floor advanced, and reject local nominations that
  a priority purge overtook in the ordinary queue; reconstruct that floor
  before restart restoration from both the journal frontier and explicit
  `start_slot`, skip retired own-log records, and advance the floor only
  monotonically;
- fail closed when hold-gate metadata allocation is unavailable, so pressure
  cannot turn stale network work into a second Engine parse attempt;
- reject a peer ballot incompatible with a local EXTERNALIZE before replacing
  the peer's previous valid statement or releasing its quorum-set reference;
- accept quorum-set responses only for outstanding requests while preserving
  retry behavior under queue pressure;
- persist only validated, requested remote quorum sets whose response entered
  the bounded engine queue; keep the local quorum set pinned in memory, and
  cap the complete answering cache at 1,024 entries, 64 MiB of logical payload
  bytes, and 1 MiB per entry;
- reconcile the cache with memory proportional to the entry cap, use FIFO
  eviction during a run and `(mtime, hash)` order after restart, write through
  same-directory temporary files plus rename, and revalidate a cached frame's
  normalized quorum-set hash before serving it;
- keep cache failure outside the consensus-critical `Store`: storage damage
  becomes a miss plus sticky `Node.storageStats()` diagnostics, the local
  answer remains available, and a mutation failure disables later writes for
  that process;
- treat only exact lowercase cache names as owned, preserve unrelated names,
  mixed-case aliases, and directories, and use no-follow/beneath-constrained
  filesystem operations so cleanup removes exact symlinks rather than their
  targets;
- strengthen input-sequence fuzz diversity and retain deterministic smoke
  coverage;
- keep the example registry RPC server and its allocator alive until every
  detached handler finishes teardown, while counting teardown-in-progress
  handlers against the 64-connection cap;
- replace external milestone/session notes with concise canonical repository
  context (`CONTEXT.md`, `DESIGN.md`, this file, and the examples roadmap).

Workspace hygiene completed alongside the sprint: 213 legacy
`.claude/worktrees/*` checkouts and 212 merged local branches were removed
after a verified recovery archive was written outside the repository. Ten
unmerged branches and one unrelated external detached worktree were preserved.
Loose milestone-era planning files were moved to a named historical archive;
active source and docs no longer depend on them.

No Stable interface changed: the 290-declaration Stable snapshot is byte-for-
byte unchanged. The 1,409-declaration Experimental snapshot was regenerated
and reviewed. The removal of Experimental `Store.putQset` / `Store.getQset`
and the addition of `Node.storageStats()` make this a pre-1.0 minor release;
the migration is recorded in `CHANGELOG.md`.

## Prior v0.2.0 verification ledger

These fields intentionally describe the integrated candidate tree, not the
v0.1.0 release run. Before the package freeze, the ordinary full graph was
green at 84/84 steps and 485/486 tests, with one expected platform skip. A
first clean cold preflight passed at `e529dcc` under an unprescribed shell Zig,
but its following ablation exposed a pre-existing registry RPC teardown race,
so that run was superseded by the code fix. A post-fix cold run at `472f0a2`
passed under another unprescribed shell Zig and remains supplemental evidence.
The final cold preflight passed at clean `0f52660` under the Zig prescribed by
`mise.toml`.

| Gate | Pinned candidate result |
|---|---|
| Package payload freeze | PASS — `1b68041`; tree clean before hashing |
| Repository code candidate | PASS — `0f39869`; focused lifecycle fix committed separately from the cache sprint |
| Formatting and whitespace (`zig fmt`, `git diff --check`) | PASS |
| Focused engine tests | PASS — 162 core, 13 vector, 4 framing-vector, and 1 engine end-to-end test |
| Focused qset-cache tests | PASS — 21/21, including capacity/byte churn, restart, corruption, allocation failure, case aliases, and root/final/temp symlinks |
| Full node tests | PASS — 151 passed, 1 expected platform skip |
| Fuzz smoke and saved-input replay | PASS — 8 smoke tests; all 3 saved streams replayed to exhaustion (14/8/13 inputs) |
| Stable/Experimental API snapshot review | PASS — 290 Stable unchanged; 1,409 Experimental verified; API closure green |
| Registry RPC lifecycle | PASS — 20/20 in the pinned cold graph and 20 consecutive focused repetitions; one-line cap and stop-wait ablations failed at their exact assertions before the pinned preflight |
| Full strict test gate | PASS — clean pinned cold preflight at `0f52660`: 100/100 steps, 497/498 tests, 1 expected platform skip, zero cached summary steps; GREEN in 682 s |
| WASM build and native/WASM differential replay | PASS — 4 traces / 32 normative / 9 observable effects; 300 fuzz iterations, 4,277 inputs, 9,616 effects |
| Deterministic and Byzantine matrices | PASS — 15,000 simulation cells in 411,250 ms; 1,000 seeds × 2 Byzantine actors |
| Real-socket end-to-end cluster | PASS — 7/7 in 2 minutes, including restart and gap recovery cases |
| Counter consumer smoke | PASS — 3 nodes, 20 slots, count 20; fetched-package repeat also green |
| Registry consumer smoke | PASS — 3 nodes, 7 transactions, 13 slots, kill/restart/catch-up, agreed head `706d31eb6eef28d3` |
| Release ablations | PASS — all five prescribed one-file mutations produced their intended red under `mise exec` and were restored; docs-smoke and check-api then reran green |
| Long fuzz run | NOT RUN for v0.2.0 — advisory |
| Release/package preflight | PASS — pinned cold run passed 7/7 hash self-tests and archive consumer build/smoke; pinned release-hash and local Git-archive verification agree on `slcp-0.2.0-p1Kf2gxUFgBmvfCp_MHA1hyQKEsMH9lovB-4R4TKoR-_` |
| Candidate CI / tag | NOT RUN / NOT CUT — local work has not been pushed |
| Three-machine deployment acceptance | NOT RUN — requires external machines |

The first fresh-cache run exposed a real restart race: a priority purge could
overtake a queued local nomination, which could then recreate a purged engine
slot. Further red/green probes found that an oldest-first retained journal
could refill the bounded live set before reaching its useful tail, the first
post-restart delivery could lower an explicit `start_slot` floor, and metadata
allocation failure could bypass the host's stale-envelope gate. Each path now
has a failing-before/passing-after regression.

A statement-level probe also found that a newer incompatible peer ballot could
replace an older valid statement before being rejected, losing both prior
evidence and its qset reference. Compatibility is now checked before storage,
and the previous statement survives rejection. The restart end-to-end witness
was made deterministic and proves fresh participation by externalizing a value
introduced only after the restarted node becomes necessary for quorum. Those
findings and their full preflight/long-fuzz proof belong to the committed
`9d21b00` / `87d7083` hardening baseline; the candidate ledger above does not
reuse those release-gate results.

The first v0.2.0 ablation run exposed an independent registry-example race:
`Server.stop` could observe an empty socket list and free its allocator while
the last detached handler was still closing and destroying its `Conn`.
`active_conn_threads` is now the lifetime barrier and the admission bound. A
test-only scheduler gate makes both old conditions deterministically red; the
focused registry suite passed 20 consecutive repetitions before the
post-fix cold runs, and the integrated suite passes under the prescribed Zig.

## Known boundaries after E2d

- Transport remains unauthenticated and unencrypted; deploy behind a private
  network or authenticated tunnel.
- Quorum linting cannot prove intersection across independently configured
  nodes.
- The native node retains a bounded answering window configurable from 1
  through 62 slots (default 16) and has no generic state-transfer or archival
  protocol. Different local windows affect availability, not consensus
  safety. The registry crosses a long outage through its application-owned
  anchor-to-certified-tip replay, including without a live peer; that remains
  a separate mechanism rather than an enlarged native window.
- The qset cache bounds owned logical payloads, not filesystem allocation:
  directory metadata, block rounding, operator-owned unrelated/mixed-case
  names, and at most one newly stranded atomic-write temp per Node lifetime
  after a live failure are outside the 64 MiB counter. Cache writes are
  atomically renamed but not fsync'd, so a crash can lose or corrupt an entry;
  this becomes a miss, not consensus-log damage. Startup scan time is
  proportional to all directory entries and cleanup may rescan after deletion.
  Do not co-locate other data in `qsets/`, and monitor the filesystem as well
  as `Node.storageStats()`.
- Typed application restart still depends on an application snapshot plus the
  retained journal tail for delta-like state.
- Registry history is replayable but application-owned and availability-bound.
  A hostile archive can withhold a required anchor, ledger, or vote; replay an
  older valid view when the operator has not set a higher floor; hide older
  certificates behind newer latest pointers; or exceed the 16-candidate
  startup bound and deny recovery. The private signing/outbox tree must remain
  durable and paired with its validator key; a full 64-state runtime backlog
  or trusted corruption is fail-stop. Boot-time journal replay may publish one
  oldest staged state to admit the exact next successor. The shared archive
  may contain neither the private data tree nor the key's pinned parent, and
  the configured roots' immediate parents must pre-exist on durable storage.
  Both shared immutable history and trusted per-slot signing/frontier evidence
  grow until retention exists.
  History mode currently supports Linux and macOS only.
- Fixed ports in some smoke and end-to-end harnesses require those suites to
  run without competing copies, especially on macOS.
- One identity must never run on two machines; local locking cannot detect a
  copied key or data directory.
- E2a transaction flooding, E2b application checkpoint recovery, E2c
  deterministic close time, and E2d application-owned replayable history are
  delivered. The post-E2d native answering-window control, local catch-up
  snapshot, and the Experimental heap-state application seam
  (`slcp.OwnedAppNode`, ADR 0003) are also delivered. Migrating the registry
  example onto that seam (a snapshot/history storage epoch), explicit archive
  retention, and richer per-peer visibility remain future work; E3 remains
  planned.
- Licensing remains an explicit owner decision; this repository grants none.

## Reading order

1. [`README.md`](README.md) for user-facing setup and warnings.
2. [`CONTEXT.md`](CONTEXT.md) for the shared vocabulary.
3. [`DESIGN.md`](DESIGN.md) for architecture and invariants.
4. [`docs/protocol.md`](docs/protocol.md) for normative protocol details.
5. [`docs/threat-model.md`](docs/threat-model.md) before deployment.
6. [`docs/stability.md`](docs/stability.md) before changing public symbols.

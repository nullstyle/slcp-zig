# Examples Roadmap

This track grows one non-financial application toward the architectural
complexity of Stellar Core. It is a direction-setting document, not a promise
that a future Stable interface already exists.

**Status as of 2026-09-03:** E1, E2a transaction flooding, and E2b
authenticated checkpoint catch-up are implemented. Heap state, complete
replayable history, close time, and E3 remain designs only.

## Direction

The application is a replicated name registry. Principals hold Ed25519 keys,
sign sequenced transactions, and agree on transaction sets one slot at a time.
The domain contains ownership, updates, transfers, and releases, but no money,
assets, fees, or smart contracts.

| Step | Application capability | Library pressure it exposes |
|---|---|---|
| E1: registry | Signed transactions, sequence numbers, transaction-set consensus values, header hash chain, snapshots, local RPC and CLI | Records limitations without changing the library interface. |
| E2a: transaction flooding | Authenticated registry transactions propagate before nomination and survive loss of their submission node once another validator has admitted them | Experimental app-message transport with bounded opt-in retention and application-owned trust, relay, and retry policy. |
| E2b: checkpoint catch-up | A validator absent for hundreds of slots authenticates recent state and rejoins voting | Application-owned quorum attestations plus the typed node's checked state/previous-value recovery seam. |
| E2 remainder: history and state | Heap state, complete replayable history, close time | Configurable retained history, a heap-state application path, and slot/time context. |
| E3: upgrades and operations | Voted upgrades, quotas, atomic operation sets, invariants, close metadata, watchers, HTTP | Richer typed-driver hooks, watcher delivery, and operational statistics. |

## E1 — Registry (implemented)

[`examples/registry/`](../examples/registry/) is a standalone consumer package
built on `AppNode`. It deliberately uses a bounded plain-data state so it can
exercise the existing typed application interface without adding a library
feature.

The shipped shape includes:

- client-signed transactions with per-account sequence numbers;
- `claim`, `set`, `transfer`, and `release` operations;
- a canonical transaction set as each consensus value;
- deterministic candidate union through a custom codec and `combine`;
- a ledger-style header hash chain and deterministic state root;
- an atomically written application snapshot after each applied slot;
- a localhost line-protocol RPC and a CLI client;
- pure state-machine tests, a live restart test, and a three-process smoke
  harness.

E1 makes three deliberate choices: the registry domain instead of a generic
key/value store, the typed `AppNode` interface instead of a raw driver, and a
localhost RPC instead of process stdin. Together they exercise application
semantics while keeping transport and operational complexity understandable.

### Gaps recorded by E1

1. Typed applied state is copied per slot, and initialization has no I/O
   parameter. A large ledger needs heap-owned state and durable loading.
2. Recent-slot answering is bounded and not configurable. E2b now lets the
   registry cross a long outage through an authenticated checkpoint plus a
   short live tail; complete replayable history remains absent.
3. The original overlay carried consensus traffic but no application
   messages, so a transaction waited for its submission node to influence a
   nomination. E2a resolves this gap for the registry with bounded,
   best-effort transaction flooding.
4. Typed validation does not receive the slot number. Close-time policy would
   need it, or would need to use the raw driver.
5. Catch-up and missing-quorum stalls need richer operator visibility.

Historical acceptance evidence for E1 is recorded in
[`CHANGELOG.md`](../CHANGELOG.md) and the example's
[`README.md`](../examples/registry/README.md). Current-worktree verification
is recorded separately in [`STATUS.md`](../STATUS.md).

## E2a — Transaction flooding (implemented)

E2a adds an append-only overlay capability without changing the signed
consensus schema: Hello `featureFlags` bit 0 advertises support and Frame arm
10 carries an opaque application message. The Experimental native Node seam
is `publishAppMessage`, `waitAppMessage`, and `appMessageStats`. Reception is
lazy opt-in; an app frame from a peer that did not advertise bit 0 is dropped;
each payload is capped at 64 KiB; and the FIFO is bounded to 1,024 items /
16 MiB. SHA-256 deduplication lasts only while a copy remains queued. Per
connection, outbound app traffic has a 256-item / 1 MiB subset of the unchanged
1,024-item / 16 MiB writer queue and cannot consume its 256-item / 4 MiB
ordinary reserve; app pressure drops the app frame without disconnecting the
peer. The transport is best-effort and non-durable; generic Node receipt never
implies relay. Applications authenticate and validate input before explicitly
republishing it and own any retry or history policy.

The registry routes RPC and gossip bytes through one admission boundary:
exact 235-byte canonical encoding, signature for this registry network,
next sequence number, duplicate rejection, and the 256-item pending cap.
Acceptance triggers an immediate flood outside the shared-state lock. Every
node that admits the transaction does the same, forming application-controlled
multi-hop flooding, and pending transactions are reflooded every second until
application removes them. The main loop drains at most 64 owned gossip
messages per tick so peer traffic cannot monopolize application progress.

The E2a smoke witness uses a three-node line and a nomination-disabled source.
It observes the one submitted transaction in both survivors' pending queues
while all heads are still at slot S, kills the only submission node, and then
requires both survivors to externalize exactly one transaction in S+1. Thus a
transaction reaches the next eligible slot and survives submitting-node death
once it has propagated. It does not promise delivery when the source dies
before any peer admits the message, nor does it provide durable replay.

## E2b — Authenticated checkpoint catch-up (implemented)

The registry now owns a filesystem checkpoint archive above SLCP. At a
configurable cadence of 1..16 slots (default 8), each validator serializes the
already-durable application state and signs a domain-separated assertion over
the registry network id, slot, ledger head, and exact snapshot digest. A
recovering process accepts a candidate only when unique valid signers satisfy
its current, locally configured quorum set. Quorum policy never comes from the
archive. The shared archive is treated as hostile; malformed objects,
signature/path mismatches, wrong-network data, torn files, and non-quorum
candidates cannot become boot state. A separate trusted per-node signing fence
rejects same-slot equivocation and signing rollback before publication.
Snapshot V2 retains the exact transaction set externalized at the checkpoint
slot as authenticated context; it remains outside the replicated state root
but is bound to the header's transaction-set hash.

`AppNode` gained the narrow library seam this needs without becoming a history
system. Ordinarily `initialSlot()` must still be continued by a gap-free suffix
of the local journal. Once the application independently verifies a checkpoint
through H, it may set `initialSlot()` to H and `.start_slot` to exactly H + 1.
It also returns the exact command at H from `initialCommand()`, preserving the
previous-value input to nomination. This checked handoff lets stale or empty
local journals be left behind. A later start is valid only when the journal
itself supplies every intervening slot, and a newer journal value supersedes
the checkpoint command. Live peers then supply only H+1 through the current
frontier, so the chosen checkpoint must still be inside their 16-slot
answering window.

The CLI flags are `--history-dir`, `--checkpoint-every`, and the explicit
anti-rollback floor `--history-min-slot`. The archive path is shared or
mirrored storage and is untrusted; the signing fence stays under each
validator's own data directory and must remain private, durable, and paired
with its signing key. The two roots must have durable existing parents and be
canonically disjoint. The immediate parents of `--history-dir` and
`--data-dir` must pre-exist on durable storage; the CLI creates or opens the
final components and synchronizes their parent entries. Linux and macOS are
the supported durability targets. The archive must be disjoint from the whole
private data root, including aliases and ancestor/descendant layouts, and may
not contain the pinned parent of the validator key. History mode requires the
key itself to be a regular file and binds Node's later read to the identity
already used by the history signer.
Post-start publication runs on a dedicated worker with one newest-wins pending
mailbox entry in addition to its in-flight checkpoint: storage latency and
availability failures do not block consensus, and failed work is retried or
superseded. Startup cannot recover when the archive
withholds every eligible certificate, and trusted-fence corruption, signing
equivocation/rollback, trusted-fence I/O, or invalid state stops the node.
Node-halt, history, and snapshot-write fatal paths drain RPC handlers, stop
consensus, and hard-exit without voluntarily joining the publisher. This
avoids a userspace shutdown wait, although the OS may still delay final reaping
of a kernel-stuck call. Ordinary cleanup stops the node before joining the
worker.

At slot 0, Snapshot V2 accepts only canonical empty genesis and no history vote
is valid. Non-genesis Snapshot V1 remains readable only as a local,
journal-backed restart format. The external history importer requires V2 so
the selected state always includes the exact final transaction set and can be
installed without a trapping migration.

Startup reads one latest pointer for each locally configured validator and
accepts at most 16 distinct valid candidate assertions. More candidates fail
closed instead of causing unbounded cross-reads. That bound, and a latest
pointer advancing past an older certificate, can cost availability under a
hostile or staggered archive. `--history-min-slot` rejects a replay below an
operator floor but cannot force newer data to appear. Two certified heads at
one slot are rejected only when both are simultaneously discoverable during
startup; this is not arbitrary or continuous runtime fork detection.

A higher isolated checkpoint does not carry a proof chain back to a lower
local head. Accepting it therefore relies on the same configured-quorum safety
assumption as consensus itself: a quorum that can certify conflicting registry
histories has already broken the trust model. A future replayable history
segment could make that ancestry independently checkable.

The strengthened smoke keeps one validator absent while the survivors
externalize at least 201 new durable slots. It then kills node0, lets buffered
work drain, freezes node1's exact head H, and recomputes the newest checkpoint
both survivors signed no more than 15 slots behind H. The restored validator
boots explicitly from that Snapshot V2, catches the sole remaining peer's
exact H/hash, and is necessary to externalize transaction 8 in exactly H+1;
the third validator then restarts and all three agree. The earlier E1 and E2a
source-death assertions remain in the same run.

## E2 remainder — History and state (planned)

E2b is checkpoint state transfer, not a complete ledger archive: it stores no
intermediate transaction sets or header sequence and still needs a live peer
for the short post-checkpoint tail. Remaining work includes:

- heap-sized account and name state;
- complete replayable history containing headers and transaction sets;
- configurable Node answering history;
- close time in the consensus value, with deterministic combination and a
  carefully defined local-clock policy;
- either a heap-aware typed application interface or a first-class raw-driver
  recipe;
- opt-in slot context for typed validation;
- explicit visibility into dropped far-ahead statements and peer state.

## E3 — Upgrades and operations (planned)

E3 adds operational machinery associated with a mature replicated state
machine while keeping the domain non-financial:

- in-band, validator-voted protocol and limit upgrades;
- deterministic per-account quotas under load;
- atomic multi-operation transactions with per-operation results;
- post-apply invariants that halt on divergence;
- a close-metadata stream containing headers, values, results, and deltas;
- watcher nodes serving queries;
- an HTTP administration and query surface;
- an incremental authenticated state root.

Expected library pressure: typed access to valid-value extraction, delivery to
watchers, and richer node statistics such as peer state and slot timing.

Acceptance target: a two-of-three armed upgrade applies while a one-of-three
upgrade does not; a deliberately broken invariant halts; metadata replay
reconstructs the same head; earlier smoke suites remain green.

## Track rules

- Examples remain consumer packages and use only interfaces available in the
  release they claim to demonstrate.
- A library need is documented before it becomes a Stable surface change.
- Stable surface changes require the release process and an appropriate
  pre-1.0 minor version.
- Every runnable smoke emits a compact evidence line; recorded historical
  evidence is never substituted for a fresh verification run.

## Legacy citation map

Older example comments cite the former external `examples-roadmap.md` by
section number. The equivalent repository-local headings are:

| Legacy section | Current heading |
|---|---|
| §2.1 | “E1 — Registry” and “Gaps recorded by E1” |
| §3 | “E1 — Registry” in full |
| §3.1 | E1 constants and domain types in `examples/registry` |
| §3.2 | E1 signed transaction model |
| §3.3 | E1 canonical transaction-set value |
| §3.4 | E1 application state |
| §3.5 | E1 deterministic validation |
| §3.6 | E1 deterministic candidate combination |
| §3.7 | E1 application and ledger-header transition |
| §3.8 | E1 persistence and restart behavior |
| §3.9 | E1 nomination cadence |
| §3.10 | E1 localhost RPC |
| §3.11 | E1 command-line client |
| §3.12 | E1 acceptance gates and evidence |

New citations should name this file and the relevant heading rather than a
legacy section number.

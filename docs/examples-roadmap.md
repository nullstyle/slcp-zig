# Examples Roadmap

This track grows one non-financial application toward the architectural
complexity of Stellar Core. It is a direction-setting document, not a promise
that a future Stable interface already exists.

**Status as of 2026-09-04:** E1, E2a transaction flooding, E2b authenticated
checkpoint catch-up, E2c deterministic ledger close time, and E2d replayable
registry history are implemented. Heap state, configurable core answering
history, archive retention, and E3 remain designs only.

## Direction

The application is a replicated name registry. Principals hold Ed25519 keys,
sign sequenced transactions, and agree on ledger values containing close time
and a transaction set one slot at a time.
The domain contains ownership, updates, transfers, and releases, but no money,
assets, fees, or smart contracts.

| Step | Application capability | Library pressure it exposes |
|---|---|---|
| E1: registry | Signed transactions, sequence numbers, transaction-set consensus values, header hash chain, snapshots, local RPC and CLI | Records limitations without changing the library interface. |
| E2a: transaction flooding | Authenticated registry transactions propagate before nomination and survive loss of their submission node once another validator has admitted them | Experimental app-message transport with bounded opt-in retention and application-owned trust, relay, and retry policy. |
| E2b: checkpoint catch-up | A validator absent for hundreds of slots authenticates recent state and rejoins voting | Application-owned quorum attestations plus the typed node's checked state/previous-value recovery seam. |
| E2c: deterministic close time | Every agreed ledger carries a bounded logical timestamp and recovery preserves its exact temporal context | Optional typed `ValueContext`, a coordinated application network/storage epoch, and an explicit proposal-clock boundary. |
| E2d: replayable registry history | Every applied slot is archived, and a validator can strictly replay from a periodic anchor to an exact certified tip without peers | An application-owned history layer, ordered bounded publication, and explicit retention/freshness limits without changing core consensus. |
| E2 remainder: state and retention | Heap state, archive retention, and configurable core answering history | A heap-state application path, pruning policy, and configurable native retention. |
| E3: upgrades and operations | Voted upgrades, quotas, atomic operation sets, invariants, close metadata, watchers, HTTP | Richer typed-driver hooks, watcher delivery, and operational statistics. |

## E1 — Registry (implemented)

[`examples/registry/`](../examples/registry/) is a standalone consumer package
built on `AppNode`. It deliberately uses a bounded plain-data state so it can
exercise the existing typed application interface without adding a library
feature.

The shipped shape includes:

- client-signed transactions with per-account sequence numbers;
- `claim`, `set`, `transfer`, and `release` operations;
- a canonical ledger value containing close time and a transaction set;
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
2. Recent-slot answering in the generic Node is bounded and not configurable.
   E2d now lets the registry cross a long outage through its application-owned
   replayable archive without a live peer; configurable core history remains
   absent.
3. The original overlay carried consensus traffic but no application
   messages, so a transaction waited for its submission node to influence a
   nomination. E2a resolves this gap for the registry with bounded,
   best-effort transaction flooding.
4. E2c resolves the typed-context gap: validation may opt into
   `slcp.ValueContext` for the slot and nomination/ballot phase.
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

## E2b — Authenticated checkpoint catch-up (implemented, then superseded)

E2b established the application-owned trust boundary above SLCP: a hostile
shared archive, locally evaluated quorum attestations, a private durable
per-validator signing fence, an operator anti-rollback floor, and a checked
`AppNode` handoff at exactly H+1 with the command at H. It also established the
filesystem constraints that remain in force: archive and private data roots
must be canonically disjoint, the archive may not contain the validator key's
pinned parent, configured roots need durable existing parents, and history
mode supports the required durability barriers on Linux and macOS.

At that milestone, periodic state checkpoints bridged only to a live peer's
recent answering window. E2c later introduced the timed Snapshot V3 and
checkpoint V2 domains as part of its hard application epoch. E2d now replaces
that checkpoint-only archive and publication policy with replayable
`history-v1`; it keeps E2b's custody model, signing safety, candidate bound,
freshness caveats, CLI flag names, and checked recovery seam. The historical
E2b proof remains recorded in [`STATUS.md`](../STATUS.md); it is not a
description of the current archive format.

## E2c — Deterministic ledger close time (implemented)

The consensus value is now `LedgerValue { close_time, txs }`, encoded as
`"REGISTRY-VALUE-V1\n" || close_time:u64be || TxSet`. For a local head
`(H,T)`, validation of target slot `S` uses `d = S - H` and accepts time only
inside `[T+d, T+60d]`; `S <= H` or an unrepresentable lower bound is invalid,
while the upper bound saturates at `u64` maximum. The
immediate successor must also have a transaction set valid on current state.
A structurally sound later value is only `.maybe_valid`, because intervening
state is not known yet. This is implemented through the optional typed
`ValueContext` rather than a registry-specific raw driver. The engine caches
the same value independently in nomination and ballot, so phase-sensitive
policy does not depend on envelope arrival order.

Only proposal construction reads the local Unix/POSIX clock. It clamps that
sample to `[T+1,T+60]`; the pure driver reads no clock. Candidate combination
chooses the minimum proposed close time and the deterministic bounded
transaction union. The implementation proves invariance over the complete
n-ary candidate set under permutation and duplicate candidates; it does not
claim recursive pairwise associativity for a bounded merge pool. Application
accepts only an immediate successor whose agreed time advances by 1..60.

The operator supplies a shared genesis close time `G`. The descriptor
`"REGISTRY-NET-V2" || G:u64be || passphrase` is both hashed for registry
transactions and passed as the raw SLCP network configuration, so changing G
changes the network even when the human passphrase is unchanged. Genesis is a
real network-bound header committing to G and the empty state root. Header V2
also commits to network id and close time; Snapshot V3 stores the exact final
LedgerValue; checkpoint assertions use their V2 domain. These formats form a
hard epoch: old snapshots and bare-TxSet journals are not migrated, and nodes
must use fresh private data/signing state. Boot selection checks both local and
authenticated heads against G's cumulative interval before installation. See
[`ADR 0001`](adr/0001-registry-close-time-network-epoch.md).

The guarantee is deliberately narrow. Consensus agrees on a monotonic logical
time with 1..60 seconds per sequential ledger, and therefore slot `S` remains
inside `[G+S,G+60S]`. It does not prove truthful UTC: validator proposal clocks
are untrusted, the minimum combine biases toward the earliest legal proposal,
and a Byzantine quorum can choose any legal chain.

The historical E2c smoke ran validators with -30/0/+30-second proposal
offsets, required RPC and durable logs to agree on every observed close time,
checked a complete contiguous time chain across its long-outage checkpoint
restore, and proved same-passphrase/different-G startup was rejected as
`DataDirOtherNetwork`. Its pinned counts and result remain in
[`STATUS.md`](../STATUS.md). E2d preserves that temporal proof while changing
how the long outage is recovered.

## E2d — Replayable registry history (implemented)

Every applied non-genesis slot now gets an immutable, cadence-independent
ledger record containing the exact canonical `LedgerValue` and the complete
resulting Header V2. Slot 1 and each configured `--checkpoint-every N`
boundary are Snapshot V3 anchor slots; the flag retains its name and default
of 8, but its accepted anchor interval is now 1..64. Once a newly applied state
reaches a deterministic anchor, every validator publishes a signed
`REGISTRY-HIST-V1` tip assertion at that slot and each subsequent slot that
binds the exact slot/head to its anchor slot/head/snapshot digest and N. Unique
valid votes form a certified history tip only when they satisfy the importing
node's normalized local quorum set. A fresh non-genesis signing tree never
republishes or treats its existing base as continuity-proven, even at slot 1 or
an N boundary. It records every newly applied successor immediately but waits
until one reaches the next anchor to begin tip attestation; thereafter it
attests every slot.

Recovery loads an eligible anchor and verifies a strict, contiguous ancestry
to the selected tip. It checks each immutable record's encoding and anchor
metadata, validates the value for that exact slot, applies it, and requires the
entire resulting header and exact last value to match before accepting the next
link. Replay ends only at the signed tip hash. The anchor interval bounds this
to `N-1` applications—at most 63—so a node can reconstruct the exact certified
tip and serve it before any peer returns. This is application-owned history;
the native Node still has its fixed 16-slot answering window and no generic
state-transfer protocol.

Anchors accelerate startup but do not reset continuity. Before signing an
anchor-slot tip assertion, the publisher reconstructs and validates that
anchor's own transition from the preceding segment, including its complete
header, exact last value, and Snapshot V3. Startup need only materialize the
latest signed anchor plus at most `N-1` later applications; certification and
publisher validation preserve continuity across the anchor boundary under
quorum trust.

Publication runs outside the cadence loop through a crash-durable trusted
ordered outbox. After an application transition, its full pending Snapshot V3
state and the admitted watermark are synchronized before the ordinary local
snapshot advances. A sole worker publishes the oldest state, advances the
durable published watermark, and removes it only on success. A retryable
shared-history failure remains at the head, so later slots cannot overtake or
replace it. Before creating the real peer-connected Node, startup synchronously
drains this backlog before considering a newer shared proof. The exception is
a persisted trusted adoption target T: startup selects T ahead of mutable
proof U and applies the operator floor to T. It then uses an isolated no-peer
AppNode to install T as
the ordinary snapshot, confirm it, and stage and snapshot the exact local
journal continuation. After synchronously publishing that continuation,
startup reruns certified recovery from the installed frontier, may prepare a
newer U, and only then creates the real peer-connected Node. During either
startup journal replay only, a full outbox may publish one oldest entry
synchronously to admit the exact next successor; a full runtime backlog,
trusted gap/outbox/signing-fence error, invalid state, or certified fork stops
the registry rather than silently losing history. The background worker starts
only after RPC binds.

Before an adoption marker is removed, a separate trusted boot-provenance
watermark records the exact certified ordinary snapshot. It advances only
after later represented states are durable in that snapshot store. This keeps
the external successor handoff recoverable across later crashes and shared
withholding; fresh activation without a certificate remains ordinary local
state and still needs journal continuity.

The shared archive remains hostile input and is not a freshness oracle. After
any pending adoption has completed, recovery discovers only one latest pointer
per configured validator, considers at most 16 distinct valid candidate
assertions, and may lose access to an older certificate when pointers advance
unevenly.
Withholding any required anchor, ledger, or vote can deny recovery of that
candidate, and an operator floor cannot make absent data appear. Replay proves
ancestry only from the signed anchor to the tip; accepting that anchor over an
unrelated older local head still relies on the current quorum's safety.
Same-slot fork detection covers simultaneously discoverable certificates, not
hidden or continuously monitored history.

Both shared and trusted storage move into a new `history-v1` namespace, so old
checkpoint-only objects and fences are not reinterpreted. This is a storage
migration boundary, not another network epoch: the E2c network descriptor,
LedgerValue, Header V2, Snapshot V3, and SLCP protocol remain unchanged. The
trusted namespace also persists the anchor policy and ordered outbox. The
shared archive and immutable trusted signing/frontier evidence grow with
publication until an explicit retention design exists. See
[`ADR 0002`](adr/0002-registry-replayable-history.md).

The updated smoke uses 64-slot anchors and keeps node2 absent for at least 201
slots. The survivors certify an exact non-anchor tip at least 17 ledger records
past its anchor, then both stop. Node2 restarts alone, strictly replays to that
exact slot/hash/time, and exposes it over RPC before a peer returns. Only then
does node1 return; node2 is required with it to externalize transaction 8 in
the first later transaction-bearing ledger, after which node0 returns and all
three converge. The exact E2d verification counts and process evidence are
recorded in [`STATUS.md`](../STATUS.md).

## E2 remainder — State and retention (planned)

Remaining work includes:

- heap-sized account and name state;
- configurable Node answering history;
- explicit archive retention, pruning, and operational sizing policy;
- either a heap-aware typed application interface or a first-class raw-driver
  recipe;
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

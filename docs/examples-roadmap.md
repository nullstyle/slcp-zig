# Examples Roadmap

This track grows one non-financial application toward the architectural
complexity of Stellar Core. It is a direction-setting document, not a promise
that a future Stable interface already exists.

**Status as of 2026-09-03:** E1 is implemented on `main` at `cf3b84b`; E2 and
E3 are designs only. E1 is after the `v0.1.0` tag and remains part of the
unreleased repository state.

## Direction

The application is a replicated name registry. Principals hold Ed25519 keys,
sign sequenced transactions, and agree on transaction sets one slot at a time.
The domain contains ownership, updates, transfers, and releases, but no money,
assets, fees, or smart contracts.

| Step | Application capability | Library pressure it exposes |
|---|---|---|
| E1: registry | Signed transactions, sequence numbers, transaction-set consensus values, header hash chain, snapshots, local RPC and CLI | Records limitations without changing the library interface. |
| E2: history and flooding | Transaction gossip, heap state, checkpoints, catch-up, close time | App-message transport, configurable history, external snapshot start, and a heap-state application path. |
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
2. Recent-slot answering is bounded and not configurable. A node outside the
   retained window needs verified history catch-up rather than a gap jump.
3. The overlay carries consensus traffic but no application messages. A
   transaction submitted to one node waits for that node to influence a
   nomination.
4. Typed validation does not receive the slot number. Close-time policy would
   need it, or would need to use the raw driver.
5. Catch-up and missing-quorum stalls need richer operator visibility.

Historical acceptance evidence for E1 is recorded in
[`CHANGELOG.md`](../CHANGELOG.md) and the example's
[`README.md`](../examples/registry/README.md). Current-worktree verification
is recorded separately in [`STATUS.md`](../STATUS.md).

## E2 — History and flooding (planned)

E2 extends the same application with:

- transaction flooding so every validator can propose the transactions it
  knows;
- heap-sized account and name state;
- checkpointed history containing headers, transaction sets, and snapshots;
- verified catch-up from an archive after a node falls outside recent history;
- close time in the consensus value, with deterministic combination and a
  carefully defined local-clock policy.

Likely library work, each requiring separate interface and compatibility
review:

- a budgeted application-message overlay frame and broadcast/receive seam;
- configurable answering history;
- a verified external-snapshot starting point;
- either a heap-aware typed application interface or a first-class raw-driver
  recipe;
- opt-in slot context for typed validation;
- explicit visibility into dropped far-ahead statements and peer state.

Acceptance target: a node absent for 200 slots rebuilds from a checkpoint and
rejoins voting; all nodes reach the same head; a transaction submitted to any
node lands in the next slot; the E1 smoke remains green.

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

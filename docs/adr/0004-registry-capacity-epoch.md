# Registry capacity epoch: heap state, Snapshot V4, REGISTRY-NET-V3

Status: accepted
Date: 2026-09-04

The registry example's state was fixed-capacity inline data: 64 accounts and
128 names inside a ~27 KB struct, u8 counts in the snapshot encoding, and a
`registry_full` result for the claim that did not fit. That shape existed
because the by-value typed adapter could not express anything larger: every
applied slot copied the whole struct, `initialState()` could not receive a
loaded snapshot (hence the process-global `boot`), and nothing was ever
freed. ADR 0003's `slcp.OwnedAppNode` removed those constraints; this
decision is the registry consuming them.

## The change

- **State owns heap storage.** Accounts and names are sorted
  `ArrayListUnmanaged` storage with `deinit`/`clone`; `apply` takes an
  allocator and grows on demand (the signature makes `OutOfMemory` the only
  expressible failure, which halts the node rather than the agreed value).
  `validate`/`combine` remain allocation-free reads over `*const State`, so
  verdicts still cannot depend on available memory. The caps and the
  `registry_full` result are gone; 32 transactions per slot still bound the
  consensus VALUE, which is a protocol limit, not a state limit.
- **Ownership is explicit end to end.** `initState` clones the boot state
  handed to `create` as its context (the global is deleted); the observation
  is an owned clone released by the cadence loop after the snapshot write
  and history staging borrow it and before it moves into the RPC shared
  state; the history archive clones into its frontier/ready/inflight/proof
  fields and frees on every rejection path; `recoverLatest` returns clones
  so the archive and the caller never share storage. The pure suite runs
  under the leak detector: 100/100 with zero leaks, including the
  cap-removal proofs (500 accounts, 300 names, a V4 round-trip beyond both
  old caps).
- **Snapshot V4** embeds the new state encoding (u32 counts, dynamic length)
  inside the unchanged V3 framing; `readSnapshot` is strictly V4 and V3/V2
  bytes fail the magic check rather than being reinterpreted.
- **REGISTRY-NET-V3** is the network descriptor tag. This is the loud-epoch
  rule E2c established: mixed-version validators would otherwise sign tip
  assertions whose anchor snapshots the other version cannot parse — a
  silent recovery-availability loss. With the tag bump, an old data
  directory fails as `DataDirOtherNetwork` and an old transaction signature
  fails verification; there is no migration path and none is pretended.
- The genesis state root changes with the empty-state encoding (eight zero
  bytes instead of two), so the genesis and post-ledger header goldens move;
  the LedgerValue and transaction-set goldens stay byte-identical, evidence
  that consensus values were untouched.

## Considered options

- Keeping fixed caps and only enlarging them (e.g. 250 accounts) was
  rejected: u8 counts and fixed buffers would still bound the state, the
  snapshot format would still be capacity-shaped, and the claim limit would
  still exist under another number.
- Migrating V3 snapshots (read-and-rewrite on first boot) was rejected: the
  snapshot is trusted local state, and silently rewriting it during a
  version transition adds a crash window for no benefit an operator cannot
  get by exporting state through the history archive instead.
- Bumping only the snapshot magic without the network tag was rejected as
  the silent mixed-version hazard described above.

## Consequences

Deployments restart from fresh data directories and re-mint transactions for
the new signing domain; the example never promised migration. The archive's
`history-v1` namespace is unchanged (ledger records and tip assertions do
not embed state), but anchors written by V3-tag nodes are unreadable by
V4-tag nodes and vice versa, which the tag bump makes loud. State growth is
now bounded by memory and disk alone, so quota-style admission control
(E3) becomes the real future limit on registry size, and explicit archive
retention remains the limit on history size.

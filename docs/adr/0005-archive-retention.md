# Archive retention: keep what discovery can still reach

Status: accepted
Date: 2026-09-04

Both sides of the registry's history grew without bound from E2d onward: the
shared archive accumulated one ledger record per slot, one anchor snapshot
per anchor era, and one vote per (tip, validator); the trusted tree
accumulated one frontier snapshot per published slot and one per-slot signing
vote. Nothing ever deleted them. This decision defines the retention policy
that bounds both, without weakening exact certified replay.

## The safety rule

Recovery reads only what the validators' latest pointers expose. Retention
therefore preserves, for **every assertion those pointers name — certified or
not** — its anchor snapshot, its complete ledger chain from tip down to and
including the anchor (each link verified to sit at its slot and to hash to
its own name), and **every vote naming its digest** (not just votes from this
node's configured validators: the shared archive serves readers with other
quorum configurations). Everything else under `ledgers/`, `snapshots/`, and
`votes/` in this module's exact canonical spelling is unreachable by any
recovery this archive can perform and is deleted. `latest/` pointers are
never touched — a pointer that advances past pruned objects stops naming
them, which is discovery's normal behavior, not a gap retention created.

A pointer-named candidate whose chain cannot be fully walked is a
publication still in flight; the pass **aborts having deleted nothing**
rather than prune around a gap it cannot see through. Retention never widens
an availability gap.

On the trusted side, everything the durable watermarks can reference
survives: the activation, published, admitted, pending-adoption,
boot-provenance, and in-flight frontiers (by head hash), and every staged
state above the published watermark (live backlog). Per-slot signing votes
below the published watermark are inert — the high-water fence rejects any
attempt to re-sign an older slot — so they are collected while the
high-water vote and newer slots stay.

## Discipline

- **Canonical names only.** A deletion candidate must match the exact
  lowercase spelling this module generates (`<64hex>.ledger`,
  `<64hex>.snap`, `<digest hex>-<signer hex>.vote`,
  `frontier-<64hex>.snap`, `staged-<slot>.snap`, `<slot>.vote`).
  Mixed-case aliases, near-misses, unrelated files, and directories are not
  ours and are left in place — the qset-cache discipline applied to the
  archive, on both the hostile shared side and the private trusted side.
- **Interrupted-write orphans** (`<name>.tmp.<hex>`) are collected when their
  base name is one of ours (trusted temps are always ours: every trusted
  write holds the archive mutex).
- **Crash-safe by construction.** Keep-sets are computed in full before any
  delete; deletes happen after directory iteration; each deleted object was
  independently unreachable. An interruption leaves a smaller pass, never a
  broken one, and the next pass finishes (idempotent GC).
- **Nonfatal.** Retention is garbage collection: a failed pass logs, leaves
  disk use growing, and retries at the next cadence point. It can never
  make the node fail-stop — that is reserved for the ordered outbox, whose
  backlog semantics are unchanged.

## Cadence

The publisher worker prunes both sides each time the published slot lands on
an anchor boundary — the moment a new era completes — bounding the shared
archive to roughly one era of stale objects between passes. Startup runs one
pass after boot selection and before RPC binds, collecting what previous
runs left behind. `PruneStats` reports what each pass removed.

## Consequences

Bounded disk use: the shared archive holds the current pointer-exposed
candidates' eras plus at most one stale era between passes; the trusted tree
holds the watermark-referenced frontiers plus the live backlog. A node whose
operator floor or local head is older than every retained candidate still
recovers exactly as it could before pruning — from the newest pointer-exposed
tip — because that is the only recovery discovery ever offered. What
retention deliberately does not provide: recovery to tips no pointer names
(any node could have pruned them), an archive-wide history export, or an
operator knob — the floors are derived, and the natural knob is the anchor
cadence already in `--checkpoint-every`.

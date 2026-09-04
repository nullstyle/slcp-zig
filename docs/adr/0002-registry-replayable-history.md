# Keep replayable registry history above SLCP

Status: accepted
Date: 2026-09-04

The registry owns its replayable history rather than extending SLCP's Stable
interface or native answering window. It publishes one immutable ledger record
containing the exact Header V2 and LedgerValue for every applied slot. Once a
newly applied state reaches a deterministic anchor, validators quorum-certify
that history tip and every subsequent tip. Snapshot V3 anchor slots occur at
slot 1 and each configured 1-through-64-slot interval; replay begins at an
eligible published anchor and applies at most `N-1` ledger records (63 when
`N=64`) to reach a certified tip.

A fresh non-genesis signing tree does not republish or treat its existing base
as continuity-proven, even when that base is slot 1 or an N boundary. It
records successors immediately but waits for a newly applied state to reach
the next deterministic anchor before its first attestation.

Replay is strict and bounded. It requires a contiguous header-hash ancestry,
checks every LedgerValue with its slot context, applies it to the preceding
state, and requires the complete resulting header and state root to match the
archived record at each step. A publisher also validates every anchor's own
transition from its predecessor; slot 1 is validated from canonical genesis.

Publication is ordered, bounded, asynchronous after admission, and
non-coalescing: omitting an intermediate applied state is never exchanged for
keeping a newer one. Before advancing its ordinary snapshot, the registry
writes the full applied Snapshot V3 into a trusted outbox, synchronizes the
entry, and synchronizes an admitted watermark. The worker publishes only
`published+1`; after shared publication, it synchronizes the published
watermark before removing that staged entry. Reopening the outbox verifies its
watermarks and exact stored transitions, then resumes its oldest pending item.

Certified-frontier adoption is also a durable transaction. Before replacing a
quiescent local frontier with certified T, the registry persists a trusted
adoption marker and T's full frontier state. On restart that marker outranks a
newer shared proof U for the first selection and remains subject to the
operator floor. An isolated no-peer AppNode must accept T; the registry then
writes T as its ordinary snapshot, confirms the marker, stages and snapshots
any exact local-journal continuation, and synchronously publishes that
continuation. Only after T is complete does startup recover and optionally
prepare newer U. The configured peer-connected Node is created from that final
selection, so crash safety at T cannot strand the process outside live history.
Before removing T's marker, confirmation synchronizes a domain-separated boot
provenance watermark. It may advance only to exact represented successors
after their ordinary snapshots are durable. That persistent fact preserves the
explicit successor handoff on every later restart even when shared pointers
are withheld; fresh activation from a local snapshot does not establish it.

Ledger records are canonical across validators and contain no local cadence.
The signed tip assertion carries `anchor_every`, and each validator persists
its chosen cadence beside the signing fence so a reused signing tree cannot
silently change policy. New `history-v1` namespaces keep both shared objects
and trusted signing/outbox state disjoint from the checkpoint-only format,
while the registry network descriptor, Header V2, LedgerValue, Snapshot V3,
and SLCP Stable interface remain unchanged.

## Considered options

- Using a larger or configurable SLCP answering window *as the registry's
  recovery design* was rejected because application state replay, snapshot
  policy, and history transport do not belong in the consensus library. The
  later native 1..62-slot control tunes bounded live-peer assistance only; it
  does not replace this archive or change the decision above.
- Continuing to certify only periodic snapshots was rejected because it leaves
  an unauthenticated suffix and still requires a live peer to supply it.
- Coalescing publication work to the newest state was rejected because a
  missing ledger record destroys both ancestry proof and deterministic replay.

## Consequences

The shared archive grows without bound until a separate, explicit retention
design exists; the trusted per-slot signing/frontier evidence likewise needs
an explicit pruning design before operators can assume bounded disk use. A
hostile archive can withhold, remove, or corrupt objects and thereby deny
publication or recovery, but cannot make malformed history pass the
certificate, ancestry, and state-transition checks. Replay from one snapshot
anchor is deliberately capped at `N-1` applications, so an unavailable
required anchor or record prevents recovery rather than causing unbounded
work.

The durable outbox admits at most 64 unpublished states. Prolonged archive
blockage that fills it makes the validator fail-stop instead of dropping,
reordering, or coalescing history. A fresh E2d signing tree may activate from
the node's validated local state, but a non-genesis activation base is never
republished or treated as continuity-proven, even at slot 1 or an N boundary.
The tree records every newly applied successor immediately and waits until one
reaches the next deterministic anchor before attesting a tip. Thereafter,
changing cadence for that signing tree or adopting an unrelated local frontier
fails closed; only the exact quorum-certified state just recovered from the
archive may advance a quiescent trusted frontier.

The `history-v1` shared and trusted namespaces are a format migration boundary:
checkpoint-only archive objects and signing fences are not reinterpreted as
replayable history, even though adopting E2d does not create a new SLCP network
epoch.

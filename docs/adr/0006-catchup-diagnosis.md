# Catch-up diagnosis: local evidence, honestly labeled

Status: accepted
Date: 2026-09-04

Before this decision, a quiet registry node could only say "either the
network has no quorum, or needed retained statements are not arriving" — the
stall warning could not tell an operator whether to start more validators,
fix transport, or restore from a certified history tip. The E1 roadmap gap
asked for "per-peer retained coverage and quorum-level stall diagnosis," and
the hard part is epistemic, not mechanical: a node cannot see the network.

## The decision

**Per-peer link evidence.** Every established overlay connection records,
with atomic counters owned by its reader thread: post-handshake frames
received, envelopes received, slot-state responses received, catch-up asks
received and envelopes answered, plus monotonic establishment and
last-frame timestamps. `Node.catchupDiagnosis(silent_after_ns, buf)`
snapshots those into `PeerLink` values alongside the catch-up counters,
the delivery-frontier age, and one classification.

**A pure classifier with three labels, all statements about local
evidence.** `no_quorum`: self plus the live connections' *advertised* ids
do not contain a local quorum slice — nothing that arrives can close
slots. `quorum_silent`: the slice is satisfied by connectivity, but no
live connection delivered a frame inside the silence window — a transport
stall or wedged peers, not retention. `missing_statements`: the slice is
satisfied and traffic flows, yet the frontier is stuck with held or
pending work — the statements needed to close the gap are not coming from
these peers. Null — no label — is itself honest: nothing looks wrong from
this seat, which is not a network health claim; the delay may be remote.

**Honesty rules that keep it from pretending to be a network oracle.**

- The quorum check uses unauthenticated Hello advertisements: connectivity
  evidence for diagnosis, never identity proof, and never consensus input.
- Labels are ordered so absence of connectivity wins over silence wins
  over retention: the cheapest certain fact is reported first.
- Silence is defined by the caller's window against a monotonic clock,
  not by an internal guess; a peer that never sent a post-handshake frame
  counts as silent since establishment.
- No label asserts why a remote validator misbehaves — only what this
  node can observe about its own connections, its own queue, and its own
  slice math over advertised ids.

## Consumption

The registry's stall warning switches on the classification and prints the
concrete next action per label (start validators / fix transport / restore
from a certified tip), and a `diag` RPC verb exposes the same line plus
per-link counters for operators. The library surface is Experimental:
`Node.catchupDiagnosis`, `CatchupDiagnosis`, `StallKind`, and
`overlay.Overlay.PeerLink`.

## Consequences

Operators distinguish the three stall classes from one line per node.
The classifier cannot name a fork or a remote wedge, and `null` never
means healthy; documents and messages say so. Per-connection counters are
two atomic increments per received frame — measured noise on the flood
path. Future work may add per-peer answer-window disclosure (a peer
stating what it can still serve), which would sharpen
`missing_statements` from "these peers are not supplying it" to "these
peers say they no longer hold it" — still as advertised, unauthenticated
evidence.

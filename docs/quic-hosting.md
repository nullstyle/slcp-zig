# Hosting SLCP over QUIC

SLCP's sans-I/O Engine already accepts complete framed envelopes and emits
borrowed effects. It needs no QUIC dependency. `slcp-core.host` now exports the
same `InputItem`, `HoldBuffer`, and `envelopeMeta` implementation used by native
Node, so an embedded qmsg/QUIC event loop can reuse bounded ingress, verified
deduplication and application-frontier gating. `source_peer` is an opaque host
route token, not a socket or validator identity. Native Node retains aliases.

`zig build host-ingress-wasm` compiles an actual freestanding consumer that
decodes metadata, checks signatures and exercises buffer admission/release.
Single-threaded targets use serialized observation counters; threaded native
hosts retain atomic counters. This verifies the dependency boundary without
claiming a completed qmsg transport or browser networking integration.

## Host contract

1. Deliver complete length-bounded frames. QUIC streams carry byte sequences;
   reads may split or combine SLCP frames. Preserve the existing Cap'n Proto
   framing and enforce limits before allocating a declared payload.
2. Serialize each Engine or managed Session. Finish every effect drain before
   another input. QUIC callbacks should enqueue bounded owned input rather than
   reenter consensus. Borrowed effect bytes must be copied before asynchronous
   transport use; committing the effect ends their lifetime.
3. Finish durable own-envelope writes before releasing broadcasts. Apply and
   durably checkpoint application state before advancing a managed Session.
   QUIC delivery acknowledgment supplies neither application nor disk durability.
4. Authenticate transport peers and bind their authorization to the expected
   SLCP domain. A QUIC connection identity, TLS certificate identity and SLCP
   Ed25519 Node ID are distinct. Connection migration changes a path, not trust
   membership. Keep per-connection, per-domain and global budgets.
5. Provide anti-entropy/retransmission for rejected or held work. Admission caps,
   disconnects and stream resets can discard work even on reliable streams.
   Serve historical quorum bytes for retained statements, including revisions
   predating the currently selected quorum.

The general `HoldBuffer` preserves native Node's v-blocking future-slot catch-up
rule. The migration-capable Session is stricter: it admits only its current
slot. Do not release a future slot into a Session because the general helper
reports it ready. A future decision may otherwise bypass the terminal decision
that retires the old domain. Replaying an authenticated application checkpoint
is a separate recovery operation.

## Traffic separation

Use reliable framed streams for consensus, quorum requests/responses and
migration certificates. Keep bulk payload replication/checkpoint transfer in
separate streams with explicit scheduling and bounded queues. QUIC avoids
cross-stream delivery ordering, but streams still share connection flow control
and congestion resources; stream priority requires an application scheduling
policy. [RFC 9000 §§2–4](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.3)
defines these constraints.

The unreliable DATAGRAM extension has no retransmission guarantee. Using it
for consensus would require a separately tested repair protocol; it is not the
default mapping. [RFC 9221 §5](https://www.rfc-editor.org/rfc/rfc9221.html#section-5)
defines DATAGRAM behavior.

Disable early-data use for activation, application proposals and migration
administration until the host has a replay-safe authenticated application
contract. QUIC 0-RTT can be replayed, including across connections.
[RFC 9001 §9.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-9.2)
explains the application responsibility. Signature verification alone does not
make an administration request safe to replay.

## Deployment profiles

One-operator multi-region deployments map anchor keys to correlated regional
failures and provision control capacity during payload recovery. Independently
operated brokers additionally need explicit operator authorization, identity
rotation and limits on peer resource use. The current policy verifier counts
keys; it does not discover operator independence from certificates or latency.
Both profiles scale through bounded domains. Connection pooling, qmsg routing,
broker admission and replicated-payload acknowledgment remain broker work.

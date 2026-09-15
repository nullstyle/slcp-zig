# Quorum adaptivity and trust-pool migration

The Experimental `slcp-core.adaptivity` interfaces support application-driven
quorum selection and certified authority replacement. They are reusable by
native and foreign event-loop hosts; they do not require qhub or QUIC. The
existing static `Node` and Stable Engine/host ABI remain available. A static
Node does not gain runtime migration by changing its startup options.

## Choose a trust floor

`policy.Policy` owns a canonical anchor roster and assesses candidate quorum
sets. Configure `n` anchor identities, at most `f` faulty anchors, and at least
`t` anchors in every satisfying slice, where `2*t > n + f`. The fingerprint
identifies the sorted roster, fault budget, slice floor and availability flag.
All conforming participants in that domain must enforce the same floor.

The minimum slice cost sums the cheapest threshold children: an anchor costs
one, an outsider zero. The minimum blocking cost sums the cheapest number of
children whose failure blocks a threshold. Outsiders again cost zero, so an
availability claim never assumes an untrusted outsider stays reachable.
`assess` validates the complete duplicate-free bounded tree before using these
calculations. Availability requires a blocking cost greater than `f` by default.

For example, with seven anchors, `f=1`, and `t=5`:

| Selected rule | Safe under the floor | Survives any one anchor failure |
| --- | --- | --- |
| 5 of all 7 anchors | Yes | Yes |
| 5 of a preferred 6 | Yes | Yes |
| 5 of a preferred 5 | Yes | No |
| 4 of all 7 | No | Yes |

Disabling `require_availability` explicitly allows structurally fragile sets;
it never relaxes the intersection floor. The algorithm counts signing keys,
not machines, regions or organizations. A deployment must translate correlated
failures into that key budget or choose a stronger application policy.

Removing up to `f` Byzantine anchors leaves any two admitted slices with an
intersection of at least `2*t - n - f > 0` honest anchors. This applies to the
union of allowed revisions, including different local activation histories.
The evolving-configuration condition is motivated by
[SCP §6.3, Theorem 13](https://stellar.org/papers/stellar-consensus-protocol.pdf);
the cost calculation and managed migration protocol are this implementation's
own design. Structural safety does not prove progress under arbitrary network
delays, application invalidity or undeclared correlated failures.

## Change a local quorum at runtime

For a bare Engine:

1. Call `enableQuorumAdaptivity` while pristine, with the durable trust floor,
   an admission floor and a bounded revision budget (default 64).
2. Select a quorum with application/operator policy. Call `prepareQuorumChange`
   with a strictly increasing first slot beyond every admitted or parked slot.
   The Engine validates and copies the proposal and returns canonical quorum
   bytes, their hash, the policy fingerprint and the first eligible slot.
3. Persist that record. While prepared, feed no inputs. Commit only after the
   write is durable; abort only a proposal that was never made durable.
4. On restart, reconstruct the durable revision timeline before restoring own
   envelopes or accepting network/timer/proposal inputs. A restored statement
   must advertise the exact local quorum hash assigned to its slot.

Each slot retains its revision for nomination, leader selection, ballot quorum
checks and emitted hashes. Purging advances a permanent admission floor and
retires unused local cache pins/graph roots. It cannot reopen a retired slot.
A full revision budget rejects another proposal. Resource failure after a
durable commit must stop the instance and recover; it cannot continue under
the previous revision. Older quorum bytes remain required for answering peers.

A future revision cannot rescue an already stalled slot whose original fault
budget was exceeded. Neither a timeout nor an observed partition authorizes
weakening the trust floor. The first selector is application-driven: automatic
latency/health selection can use the same assessment and activation interfaces,
but an autonomous controller is not included in this implementation.

## Migrate the trust pool

`migration.Manifest` identifies the parent domain, next generation, terminal
old slot, exact checkpoint digest and complete successor trust floor. Its
canonical bytes are the terminal consensus value. A derived successor network
ID binds all those fields. A migration can replace every anchor.

`migration.verifyCertificate` requires at least the **old** slice floor of
distinct old-anchor EXTERNALIZE signatures for the exact terminal value and
slot in the old signing domain. Entries must be sorted by signer; malformed,
duplicate, foreign, stale-generation and conflicting entries fail verification.
The successor policy cannot lower the old authorization requirement.

The managed `session.Session` makes that certificate meaningful:

- It wraps application payloads and migration values distinctly. Applications
  authorize migration against their current state; a well-formed manifest alone
  is not approval to change authorities.
- Only the current sequential slot reaches the Engine. Exact previous-value
  bytes and application checkpoint acknowledgments govern advancement. Future
  EXTERNALIZE statements cannot use native Node's gap-jump exception.
- A terminal own EXTERNALIZE introduces a durable retirement barrier before
  broadcast. The old session cannot sign subsequent old-domain slots.
- A successor validates the old certificate and actual checkpoint bytes and
  presents an installation persistence barrier before creating a signing Engine.
  Removed identities cannot sign as successor anchors. Joining validators use
  the authenticated checkpoint and exact terminal predecessor value.
- Recovery inspects all persisted own envelopes before any effect is released.
  A terminal EXTERNALIZE forces retirement even if the externalized/application
  record was never written. Ordinary old statements restore only under their
  original quorum revision.

The certificate's old anchors intersect every continuing old quorum in more
than `f` anchors. At least one honest intersection signer has durably retired,
so a continuing old quorum cannot form. Sequential admission prevents honest
signers from voting on later old slots before learning the terminal decision.
Without these host constraints, collecting signatures and changing network IDs
does not establish unique succession.

Lost old quorum can prevent migration. Subsequent compromise of enough retired
old keys can forge alternative historical certificates; retention of trusted
checkpoints and key protection/erasure are operational assumptions. This
protocol does not claim protection against copied signing state or historical
quorum compromise. Application authorization, snapshot validity and archive
availability remain application responsibilities.

## Durability and integration

`slcp.managed_store.Store` supplies the native persistence bridge for a
`Session`. Use one durably provisioned directory per signing identity and
epoch. Create a new store only for a session whose activation is pending; open
an existing store for recovery. Creating an existing journal fails instead of
discarding signing history.

During effect draining, `persistEffect` writes and syncs activation, own-envelope
and retirement records before committing their session effects. A `false`
result leaves the current transport, timer or application effect for the host
to handle. For an application effect, apply the value and call
`checkpointApplication` with complete recoverable state bytes. Finish draining
effects, then call the store's `acknowledgeApplied` to admit the next slot.
`changeQuorum` combines assessment, durable revision recording and activation.
Stop and reopen after an uncertain persistence failure.

On restart, call the store's `recover`, restore `Recovered.checkpoint` into the
application's driver context, then call `restoreGenesis` or `restoreSuccessor`.
The caller pins the genesis configuration or parent epoch; the stored history
does not get to select its own trust authority. Keep the recovered record alive
while reading its borrowed snapshot bytes. Recovery validates journal order,
the complete signed quorum history and the application frontier before a
session can release effects.

`slcp.adaptivity_journal` supplies an exclusive-writer native journal bound to a
node and root domain. Records are ordered, bounded and hash chained, with a
separate checksum for length metadata. Append completes after file sync and a
macOS media-flush upgrade. A new journal also syncs its directory entry.
Reopen requires existing state and successful recovery before another append.
An incomplete final write is repaired; complete corruption, reordering, wrong
identity or a missing file fails closed. An uncertain append stops that journal
instance. Capacity exhaustion does not silently discard trust/signing history.

Retain old epoch journals after migration. A configuration file, snapshot digest
or reconstructed new Engine cannot replace durable signing and retirement
history. The host must persist complete application checkpoint bytes or an
equally durable application-owned reference before acknowledging application
progress. A false durability acknowledgment violates the protocol contract.

The [implementation plan](plans/quorum-adaptivity.md) records scope and
verification. The [broker substrate plan](plans/broker-network-substrate.md)
must integrate these contracts with payload replication and both operator
profiles before claiming broker maintenance or migration support.

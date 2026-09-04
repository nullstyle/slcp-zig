# SLCP Consensus Context

This glossary is the shared language for the protocol, node, and application
layers in this repository. It defines terms only; behavior and implementation
belong in `DESIGN.md` and the documents under `docs/`.

## Network and identity

**SLCP**:
Stellar-Like Consensus Protocol, the protocol in this project for reaching
federated Byzantine agreement on application-defined values. It is SCP-shaped
but is not the Stellar protocol and is not wire-compatible with Stellar.
_Avoid_: SCP

**Network**:
The set of nodes that share one network identity and one consensus profile.
Statements from a different network are outside that consensus domain.

**Node ID**:
The public identity by which a node's signed statements are attributed.
_Avoid_: Peer ID, account ID

**Node**:
A participant that follows SLCP statements and externalized values.

**Validator**:
A node whose statements can satisfy quorum rules and that may sign its own
consensus statements.
_Avoid_: Voter

**Watcher**:
A non-validating node that follows consensus without signing statements or
proposing values.
_Avoid_: Validator, observer process

**Peer**:
A remote node as seen across one network connection. Peer describes a
relationship, not a separate kind of node.

## Federated trust

**Quorum set**:
A recursive threshold rule naming validators and nested threshold rules. It
states whose agreement is sufficient from one node's point of view.
_Avoid_: Quorum configuration, validator list

**Quorum-set hash**:
The identity of a normalized quorum set. Statements name their quorum set by
this identity.

**Quorum slice**:
A set of nodes sufficient to satisfy one node's quorum-set rule.

**Quorum**:
A non-empty set of nodes that contains a quorum slice for every node in the
set.
_Avoid_: Majority

**V-blocking set**:
A set of validators that intersects every quorum slice available to a given
node. Such a set can prevent that node from reaching agreement without them.
_Avoid_: Blocking quorum

**Quorum intersection**:
The property that every two quorums overlap. Safety depends on the overlap
including an intact node.

**Intact node**:
A non-Byzantine node that remains inside the well-behaved part of the
federated trust graph.
_Avoid_: Merely online node

**Byzantine node**:
A node that may deviate arbitrarily, including lying, equivocating, or
coordinating with other faulty nodes.
_Avoid_: Offline node

## Consensus

**Slot**:
One indexed instance of agreement in an ordered application history.
_Avoid_: Round, block height

**Value**:
The opaque application datum on which a slot reaches agreement. A value
represents resulting intent or state, not an instruction that depends on being
applied exactly once.
_Avoid_: Operation, delta

**Statement**:
A node's consensus claim for one slot, expressed as a nomination, preparation,
confirmation, or externalization pledge.
_Avoid_: Envelope, transport frame

**Envelope**:
A statement's canonical bytes together with the signature that attributes
them to a node.
_Avoid_: Statement

**Nomination**:
The phase in which nodes propose and ratify values until one or more candidates
are available for balloting.

**Candidate**:
A nominated value eligible to seed a ballot.

**Ballot**:
A counter and value considered together during preparation and confirmation.

**Preparation**:
Evidence that a ballot is safe to advance toward commitment.

**Confirmation**:
Evidence that a commit range has enough support to become final.

**Externalization**:
A node's final decision of a value for a slot.
_Avoid_: Nomination, delivery

**Previous value**:
The exact value externalized in the slot immediately before a nomination.
Leader selection hashes it, so a recovered node must restore the same bytes
incumbent validators use.
_Avoid_: Application snapshot, state root

**Equivocation**:
One node issuing incompatible statements for the same slot.

## Application and delivery

**Driver**:
The application policy that judges values and combines candidate values for
consensus.
_Avoid_: State machine, transport adapter

**Valid value**:
A value the local application can accept now.

**Maybe-valid value**:
A value the local application cannot accept from its present state but may
accept after catching up.
_Avoid_: Invalid value

**Invalid value**:
A value the local application rejects regardless of catch-up.

**Delivery frontier**:
The highest contiguous slot whose externalized value has been delivered to the
application.
_Avoid_: Consensus frontier

**Application snapshot**:
A durable encoding of application state at one delivery frontier. Its local
integrity does not establish that another node should trust its contents.
_Avoid_: History checkpoint

**Snapshot anchor**:
An application snapshot chosen as the starting state for a bounded replay of
later ledger records. It anchors application state, not validator agreement.
_Avoid_: History tip

**Ledger record**:
The exact value externalized at one slot paired with the resulting ledger
header. A contiguous sequence can reexecute state transitions and verify
header ancestry.
_Avoid_: Statement, application snapshot

**History tip**:
A ledger head attested by validators satisfying the importing node's quorum
set. It authenticates the end of a history prefix whether or not that slot is
a snapshot anchor.
_Avoid_: Delivery frontier, history checkpoint

**History checkpoint**:
An application snapshot whose ledger head is attested by validators satisfying
the importing node's quorum set, making it an authenticated external starting
point.
_Avoid_: Snapshot, answering window

**History archive**:
An application-owned durable collection of ledger records, snapshot anchors,
history tips, and their validator attestations, used when the live answering
window is insufficient.
_Avoid_: Answering window

**History signing fence**:
Trusted per-validator state that records immutable history-tip decisions and
a monotonic high-water mark before any attestation enters a shared history
archive. It prevents one retained validator key from signing a rollback or
same-slot fork across crashes and retries.
_Avoid_: History archive, application snapshot

**History outbox**:
A trusted, crash-durable, per-validator sequence of full applied application
states admitted for history publication but not yet acknowledged as published.
Its admitted and published frontiers preserve publication order across crashes.
_Avoid_: History archive, application snapshot, message queue

**Certified-adoption marker**:
A trusted local record of the exact quorum-certified application state whose
installation has begun but has not yet been confirmed in the ordinary
application snapshot. It makes certified history adoption resumable across
crashes.
_Avoid_: History tip, latest pointer, history outbox

**Trusted boot provenance**:
A durable local record that the exact ordinary application snapshot descends
from independently certified history. It is established only by a confirmed
certificate or certified adoption, then may advance across exact outbox states
after their ordinary snapshots are durable. Fresh history activation does not
establish it.
_Avoid_: Certified-adoption marker, application snapshot

**Answering window**:
The recent span of externalized slots for which a node can still answer a
lagging peer from local history.
_Avoid_: History archive

**Answer floor**:
The oldest slot whose own statements a node retains for answering lagging
peers. It may be older than the purge floor after restart.
_Avoid_: Delivery frontier

**Purge floor**:
The first slot the native host and engine admit for consensus processing.
Inputs for lower slots are closed and must not recreate consensus state, even
when their own statements remain inside the answering window.
_Avoid_: Delivery frontier

**Value context**:
Deterministic metadata about one value check, currently its slot and protocol
phase, supplied by the host to an application driver.
_Avoid_: Local clock, application state

**Close time**:
The registry's agreed logical timestamp for a ledger. It advances within
deterministic bounds but is not proof of truthful wall-clock time.
_Avoid_: Block time, trusted timestamp

**Genesis close time**:
The operator-chosen close-time anchor for registry slot zero. It is part of
the registry network identity and must be identical at every node.
_Avoid_: Node start time

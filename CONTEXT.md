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

**Answering window**:
The recent span of externalized slots for which a node can still answer a
lagging peer from local history.
_Avoid_: History archive

**Purge floor**:
The first slot retained by the native host and engine after garbage
collection. Inputs for lower slots are stale and must not recreate consensus
state.
_Avoid_: Delivery frontier

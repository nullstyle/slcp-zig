# SLCP Design Guide

This is the enduring architectural map for `slcp-zig`: where behavior lives,
which interfaces carry the important contracts, and which invariants a change
must preserve. It deliberately omits milestone history and work-session notes.

Normative details have narrower authorities:

- [`docs/protocol.md`](docs/protocol.md) defines protocol and byte-level
  behavior.
- [`vectors/`](vectors/) defines cross-implementation examples; when prose and
  vectors disagree, the vectors win.
- [`docs/stability.md`](docs/stability.md) defines the public compatibility
  promise.
- [`docs/threat-model.md`](docs/threat-model.md) defines the security boundary
  and deployment assumptions.
- [`CONTEXT.md`](CONTEXT.md) defines project vocabulary.

## Design center

SLCP is a clean-room, SCP-shaped federated Byzantine agreement system for
small applications. The design starts from a three-node application in which
two live validators must keep making progress and one survivor must halt. The
project optimizes for an honest, compact application interface without hiding
the safety, liveness, and operational constraints underneath it.

The v1 profile is intentionally narrow:

- Ed25519 signatures and SHA-256 digests;
- Cap'n Proto messages with a project-specific wire protocol;
- small inline application values;
- static peers and quorum configuration;
- a TCP flood overlay with no transport authentication or confidentiality;
- bounded recent history, not an archive or state-transfer protocol.

Stellar Core is a behavioral oracle for the consensus state-machine shapes,
not a protocol peer. SLCP has different wire bytes, signature preimages, and
network identity.

## Architecture

```text
typed application
      |
      v
AppNode(App) ---- application state and codec
      |
      v
Node -------- overlay / timers / persistence / keys
      |                    |
      | Input              | Effect dispatch
      v                    v
Engine <---------------> Driver
      |
      +---- native Zig host
      +---- WASM host ABI
```

The architecture has one consensus engine and multiple possible hosts. The
native node drives the engine directly. A different host can drive the same
engine through the WASM interface. Networking, clocks, durable storage, and
key handling remain host responsibilities.

### Engine module

The `slcp-core` module is the deepest module in the repository. Its external
interface is the `Input`/`Effect` protocol in
[`src/engine/engine.zig`](src/engine/engine.zig): a host pushes one input,
drains every resulting effect, and commits borrowed effect payloads before
pushing the next input.

Behind that interface, the engine owns nomination, ballot progression,
statement freshness, federated voting, quorum-set resolution, pending
envelopes, validation caches, and resource accounting. It has no I/O, clock,
or random source. Given the same configuration, driver answers, and input
sequence, it must produce the same effect sequence.

Important effect-order contract:

1. an own envelope is offered for durable persistence;
2. only after persistence succeeds may it be broadcast;
3. every input drain ends with exactly one input-status effect.

The interface is also the primary test seam: simulator, vector replay,
native execution, and WASM differential replay all exercise the engine through
the same input/effect vocabulary.

### Driver seam

[`src/driver.zig`](src/driver.zig) is the application-policy seam. A driver
answers whether a value is valid, maybe valid, or invalid; combines a
candidate set deterministically; and may extract a valid value from an invalid
one. These calls are synchronous inside consensus processing.

Driver purity is a consensus requirement. Results must not depend on clock,
I/O, random data, address values, unordered iteration, or mutable process
state. [`docs/determinism.md`](docs/determinism.md) is the operational
checklist.

### Native Node module

[`src/node/node.zig`](src/node/node.zig) is the native host. Its public
interface hides the engine pump, TCP overlay, timer wheel, consensus-log
persistence, the bounded best-effort quorum-set answering cache, restart
recovery, input serialization, slot-ordered delivery, and the bounded
Engine-ingress, future-slot hold, and application-message queues.

One engine thread owns all engine state. Overlay readers, timers, and
application callers enqueue inputs; they do not call the engine directly.
The engine thread pushes one input, drains all effects, dispatches those
effects, then advances to the next input.

That ingress queue has explicit item and byte bounds, with reserved capacity
for local progress and a coalesced priority lane for the monotonic purge
watermark. Because the purge can overtake ordinary work, admission is checked
again when an item is applied: peer and held envelopes, plus already-queued
local nominations, cannot recreate a slot below the host's purge floor. The
network gate fails closed if allocating its envelope metadata fails, preserving
that floor instead of retrying the same stale statement inside the Engine. The
floor is reconstructed from the journal frontier and explicit `start_slot`
before restart restoration, and retired own-log records below it are skipped;
an uncompacted disk tail therefore cannot crowd current slots out of the
Engine's bounded live set. Subsequent delivery advances this floor
monotonically and never lowers an explicit `start_slot` boundary.

Inbound statements are gated by the delivery frontier. Eligible future
statements inside the bounded hold window wait until prior application state
has been delivered, except when a v-blocking set of externalizations
establishes that a later slot is already decided. Statements beyond the
window or its item/byte caps are dropped for later resynchronization. This
ordering protects state-dependent validation from caching an out-of-date
verdict for a slot that still needs the node's vote.

Opaque application messages stay outside the Engine and its signed consensus
schema. The Experimental `Node.publishAppMessage`, `waitAppMessage`, and
`appMessageStats` seam is a best-effort native-host facility: an appended
Hello capability bit prevents sending its appended frame arm to older peers,
while an inbound app frame without that negotiated bit is dropped. The first
wait lazily opts the process into payload retention. The inbox accepts payloads
through 64 KiB and is bounded to 1,024 items / 16 MiB, with SHA-256 payload
deduplication only while a copy remains queued. On each connection, app frames
may occupy at most 256 writer items / 1 MiB inside the unchanged 1,024-item /
16 MiB aggregate, while 256 items / 4 MiB remain reserved for ordinary and
consensus traffic. App pressure drops only the opportunistic frame instead of
disconnecting the peer. The writer reserve preserves explicit consensus
headroom; it does not reorder already-queued application frames ahead of
consensus output. Inbox removal is amortized O(1), and shutdown closes waiter
admission before draining every admitted waiter. This is not a durable message
log. Receipt never implies relay; an application must authenticate and validate
a payload, then explicitly publish accepted bytes and retry them according to
its own policy. This keeps untrusted overlay input from acquiring a generic
amplification path inside `Node` or consuming the writer's consensus reserve.

### Typed application module

[`src/node/app_node.zig`](src/node/app_node.zig) adapts an application with
`State`, `Command`, `validate`, and `apply` into a `Node` driver and delivery
hook. `Codec(Command)` provides a deterministic encoding for supported plain
data, while an application may supply a custom strict codec and combination
rule.

`apply` runs in the engine's serialized flow after the externalized journal
append and before the next input. This gives validation and application one
ordered view of state. Application work that is slow, blocking, or external
belongs after the applied-value handoff, not inside the hook.

Normally a nonzero `initialSlot()` must be continued by a gap-free suffix of
the retained local journal. An application that has independently
authenticated an external checkpoint through slot H may instead leave the
local journal behind by pairing that state with the exact
`.start_slot = H + 1` and returning the exact value agreed at H from
`initialCommand()`. That value preserves the nomination predecessor used by
incumbent validators. A newer continuing journal supersedes it; a same-slot
byte mismatch fails before the node goes live. `AppNode` installs an
Experimental pre-live recovery hook for these checks, while the Stable
delivery hook remains the post-journal application boundary. `AppNode` does
not authenticate the checkpoint; that trust decision remains above the
generic adapter.

### WASM module

[`src/wasm/slcp_host_abi.zig`](src/wasm/slcp_host_abi.zig) exposes the engine
through a versioned, buffer-oriented ABI. Inputs and effects use the shared
host schema; driver calls cross back into the host synchronously. Borrowed and
owned buffers have explicit lifetimes, and effect popping remains a two-phase
operation.

## Protocol data and evolution

The three schemas have distinct compatibility rules:

| Schema | Role | Evolution rule |
|---|---|---|
| [`schema/slcp.capnp`](schema/slcp.capnp) | Signed consensus statements | A reachable field change is a consensus-version event. |
| [`schema/overlay.capnp`](schema/overlay.capnp) | Unsigned transport frames | Append-only evolution unless the overlay protocol version changes. |
| [`schema/host.capnp`](schema/host.capnp) | Engine/host and WASM payloads | Evolves with ABI negotiation. |

Signatures cover canonical statement bytes with domain separation and the
untransmitted network identity. The envelope carries those exact statement
bytes plus the signature; a receiver verifies the transmitted bytes rather
than reconstructing a signing object.

NOMINATE, PREPARE, and CONFIRM name a quorum set by hash. That exact set is
part of the statement's meaning: federated voting evaluates the statement
against the set it advertised, not whichever set the signer advertised most
recently. EXTERNALIZE instead uses the protocol-defined singleton containing
its sender; its commit-qset hash is audit metadata. Normalized quorum sets give
logically equivalent rules one identity.

Application command encoding is also consensus surface. Changing field order,
width, strict-decoding rules, or custom codec behavior requires coordinated
network evolution as described in
[`docs/driver-upgrade.md`](docs/driver-upgrade.md).

## Safety and liveness invariants

Changes should preserve these system-level invariants:

1. **Persist before broadcast.** A node must never broadcast an own statement
   it cannot recover after a crash.
2. **One serialized engine.** No thread other than the engine owner observes
   or mutates live engine state.
3. **Drain before the next input.** Effects from one input remain ordered and
   complete.
4. **Exact statement trust.** Signature verification, canonicality, sanity,
   relevance, freshness, and the statement's own quorum-set identity all
   participate in admission.
5. **Apply before next-slot validation.** Normal host delivery keeps
   state-dependent validation from judging a live slot against stale state.
6. **Bound adversary-controlled retention.** Frames, input and effect queues,
   application messages, held statements, pending envelopes, stored
   statements, quorum sets, slots, value caches, and managed quorum-set files
   all have explicit memory or disk limits and defined overflow behavior.
7. **Consensus-critical failure becomes silence.** Consensus-log write
   failure, driver fault, or a sticky engine failure makes the node inert
   instead of continuing with ambiguous state. An answering-cache failure is
   observable but nonfatal: it becomes a cache miss, never unsafe progress.
8. **Externalization is immutable.** Intact nodes do not decide two different
   values for one slot.
9. **Halting is preferable to guessing.** A node without the required quorum
   does not manufacture progress.
10. **Deterministic application policy.** Equivalent nodes decide and apply
    equivalent bytes identically.

Quorum intersection is a deployment property across all nodes, not something
local linting proves. The lint catches important local hazards but cannot turn
arbitrary independently chosen quorum sets into a safe federation.

## Persistence and recovery

Durable and best-effort state have separate owners. [`src/node/store.zig`](src/node/store.zig)
owns the safety-critical logs and process lock; `Node` owns the identity
marker; [`src/node/qset_disk_cache.zig`](src/node/qset_disk_cache.zig) owns the
bounded answering cache:

- `own.log` records the latest own statements needed to avoid post-crash
  equivocation;
- `externalized.log` is the recent application-visible journal;
- `identity` binds a data directory to its network and node identity;
- `lock` prevents two live processes from sharing one data directory;
- `qsets/` caches the pinned local set and requested, validated remote sets
  under a 1,024-entry / 64 MiB logical payload budget.

Recovery treats an incomplete final record as a torn tail and truncates to the
valid prefix. A structurally complete record with a bad checksum is corruption,
not a partial write. A validator whose own-statement history is untrustworthy
must not continue signing. Recovery replays the retained externalized journal
tail to the application, but restores protocol state only from own statements
at or above the later of `start_slot` and the delivered frontier's 16-slot
answering-window floor. This prevents up to ~80 pre-compaction slots from
exhausting the Engine's 64-slot budget oldest-first.

The journal is a bounded answering window, not complete application state.
Applications with delta-like commands must persist their own snapshot and
reconstruct state from that snapshot plus the retained journal tail. Long-gap
catch-up requires an application-level archive or a future state-transfer
interface. The registry example demonstrates the application-level path: a
quorum-authenticated checkpoint supplies state through H, the exact-successor
cutover starts at H + 1 with the exact value agreed at H as nomination
context, and live peers supply only the short tail that still fits the
answering window. This does not turn the Node journal into an archive.

The qset cache is not write-ahead state. Remote entries use FIFO eviction;
startup reconstructs a deterministic `(mtime, hash)` order, prunes owned
overflow and stale temp files with memory proportional to the entry cap, and
checks a remote file's semantic hash lazily before serving it. Atomic
same-directory rename prevents a successful write from exposing a partial
file, but cache writes are not fsync'd. Cache I/O or allocation failure latches
Experimental degradation counters and may disable further cache writes while
the local quorum set remains answerable from memory.

## Trust and operations

Envelope signatures authenticate statements, not connections. `Hello` fields
are hints, and transport is plaintext. A deployment must place the listener on
a private or authenticated network such as WireGuard and restrict peer access.
See [`docs/threat-model.md`](docs/threat-model.md) before exposing a node.
Opaque application messages have no library-level signature or authorization;
the receiving application owns that trust boundary and must not republish a
message merely because it arrived from an overlay peer.

One signing identity must correspond to one live validator. The data-directory
lock prevents duplicate use of one directory, but no local mechanism can stop
a copied seed from running elsewhere.

Quorum configuration governs both safety and availability. A 2-of-3 network
can continue with one node offline and must halt with two offline. Symmetric,
small configurations are the easiest to reason about; the copyable starting
points live in [`docs/quorum-recipes.md`](docs/quorum-recipes.md).

## Code map

| Path | Responsibility |
|---|---|
| [`src/lib_core.zig`](src/lib_core.zig) | Public root of the sans-I/O engine. |
| [`src/lib.zig`](src/lib.zig) | Public root of the native node and typed layer. |
| [`src/engine/`](src/engine/) | Engine shell, slot protocols, quorum math, qset storage, pending inputs, and limits. |
| [`src/node/`](src/node/) | Native host: node orchestration, application adapter, overlay, timers, store, keys, and wire codec. |
| [`src/wasm/`](src/wasm/) | Freestanding host interface for the same engine. |
| [`schema/`](schema/) | Consensus, overlay, and host message definitions. |
| [`sim/`](sim/) | Deterministic network simulation and Byzantine actors. |
| [`tests/`](tests/) | Cross-module, ABI, fuzz, liveness, and real-socket tests. |
| [`vectors/`](vectors/) | Frozen conformance cases and trace inputs. |
| [`tools/`](tools/) | Generation, snapshots, documentation checks, release checks, and smoke harnesses. |
| [`examples/`](examples/) | Consumer-shaped applications over the stable interface. |

## Verification model

Verification is layered so each important seam has an independent witness:

- unit and engine tests exercise local transition rules;
- conformance vectors pin canonical bytes and input/effect traces;
- deterministic simulation checks safety and liveness across schedules;
- Byzantine matrices inject controlled malicious behavior;
- fuzz targets explore decoding and input sequences;
- native/WASM differential replay checks host-independent engine behavior;
- real-socket tests cover overlay, persistence, restart, and partitions;
- API snapshots protect Stable compatibility;
- docs-smoke checks that copied examples and protocol literals match source.

The exact current verification state belongs in [`STATUS.md`](STATUS.md), not
in this design guide.

## Legacy citation map

Older source comments use `design §N` to cite the former external design
notebook. Those citations remain interpretable through this map; new citations
should name a repository document and heading directly.

Labels such as `M6`, `S8`, `D#`, and `R#` in older implementation and test
comments record the milestone or audit that introduced a guard. They are
provenance, not an external specification: the adjacent comment, executable
test, and repository documents are the authority. New code should explain the
invariant directly instead of adding another milestone label.

| Legacy section | Current authority |
|---|---|
| §0, north-star counter | [`README.md`](README.md) and [`examples/counter/README.md`](examples/counter/README.md) |
| §1, goals and non-goals | “Design center” above and [`STATUS.md`](STATUS.md) “Known boundaries” |
| §2, architecture | “Architecture” above |
| §3, repository layout | “Code map” above |
| §4, wire format | “Protocol data and evolution” above; [`docs/protocol.md`](docs/protocol.md) §§3–5 and §9 |
| §5, consensus engine | “Engine module” above and [`docs/protocol.md`](docs/protocol.md) §11 |
| §6, cryptography | “Protocol data and evolution” above and [`src/crypto.zig`](src/crypto.zig) |
| §7, WASM ABI | “WASM module” above and [`docs/protocol.md`](docs/protocol.md) §14 |
| §8, application driver | “Driver seam” and “Typed application module” above; [`docs/driver-upgrade.md`](docs/driver-upgrade.md) and [`docs/determinism.md`](docs/determinism.md) |
| §9, overlay | “Native Node module” and “Trust and operations” above; [`docs/protocol.md`](docs/protocol.md) §12 and [`docs/threat-model.md`](docs/threat-model.md) |
| §10, persistence | “Persistence and recovery” above and [`docs/protocol.md`](docs/protocol.md) §13 |
| §11, public APIs | [`README.md`](README.md), “Native Node module,” and “Typed application module” above |
| §12, quorum UX | [`docs/quorum-recipes.md`](docs/quorum-recipes.md) and [`docs/threat-model.md`](docs/threat-model.md) |
| §13, testing | “Verification model” above |
| §14, milestones | [`STATUS.md`](STATUS.md) and [`CHANGELOG.md`](CHANGELOG.md) |
| §15, signal generation | [`STATUS.md`](STATUS.md) and the verification documents linked above |
| §16, risks | [`STATUS.md`](STATUS.md) “Known boundaries” and [`docs/threat-model.md`](docs/threat-model.md) |

# slcp-rs planning: native host, application and recovery findings

Historical planning evidence from 2026-11-02. Inspected SLCP Zig commit
`346d3ec67f5917f579e4d7505b3b1abb3194d898`. No implementation or runtime
qualification was performed. Findings below distinguish present source behavior
from proposed Rust design and audit hypotheses.
They describe the inspected planning baseline; subsequent work is recorded in
the [2026-11-04 implementation report](rust-feedback-implementation-2026-11-04.md).

## Recommendation and initial scope

Build an independent Rust sans-I/O consensus implementation, then a native
static-quorum TCP node and a small typed counter. A Rust wrapper around the Zig
WASM ABI can be a useful comparison harness or an independently named hosting
adapter, but it would not supply implementation diversity in consensus. The
existing architecture already separates the bytes-only Engine from native Node
and typed adapters; the Engine has no QUIC dependency. Sources:
[DESIGN.md](../../DESIGN.md), “Architecture”;
[app_node.zig](../../src/node/app_node.zig), lines 1–8;
[QUIC hosting](../quic-hosting.md), lines 3–14.

For the first Rust node, match the baseline v1 overlay and static host behavior.
Defer application messaging, trust-floor revisions, managed trust-pool migration,
registry history, QUIC hosting, and BucketList integration to separately accepted
profiles. These are not cosmetic extras: managed Session replaces the ordinary
future-slot/gap behavior with one-slot admission plus durable activation,
application checkpoint and retirement barriers. Static `Node` does not acquire
migration by changing startup configuration. Sources:
[stability](../stability.md), lines 245–280;
[quorum adaptivity](../quorum-adaptivity.md), lines 3–7 and 89–113;
[QUIC hosting](../quic-hosting.md), lines 37–42.

This scope should be written as a compatibility matrix: signed consensus,
deterministic Engine effects, baseline overlay, local persistence/import,
application codec, and optional extensions are separate promises. The current
protocol calls overlay **and persistence** host-normative for v1, so a decision to
use a Rust-specific disk format must be an explicit SLCP profile clarification,
not an unannounced assumption. Source: [protocol](../protocol.md), §0.

## Obligations the Rust host must preserve

| Obligation | Current owning source | Rust planning consequence |
| --- | --- | --- |
| Serialize one Engine; finish all effects before another input; borrowed effects die at commit. | [QUIC hosting](../quic-hosting.md), lines 18–26; [node.zig](../../src/node/node.zig), lines 2365–2384. | One actor/event-loop owner; network callbacks enqueue owned inputs. Own bytes before crossing an async seam. Avoid holding a borrowed effect across arbitrary callback reentry. |
| Own-envelope durable append precedes its paired broadcast. A failed append suppresses all remaining effects and latches the node inert. | [node.zig](../../src/node/node.zig), lines 2374–2427. | Storage completion means the required durability barrier completed; a task/channel acceptance is insufficient. Cancellation or uncertain write completion cannot resume signing on the prior in-memory state. |
| Externalized value is journaled before application delivery. | [node.zig](../../src/node/node.zig), lines 2452–2458. | Once consensus decides, application rejection cannot undo agreement. Application or notification failure must stop this node rather than skip that delivery. |
| Startup validates checkpoint/journal continuity and exact predecessor value before becoming live. Same-slot predecessor disagreement refuses startup. | [protocol](../protocol.md), §13, lines 1037–1063; [app_common.zig](../../src/node/app_common.zig), lines 102–126. | Model recovered state as a slot plus exact preceding consensus bytes. An application state root alone cannot seed nomination. |
| Retained own answers may be below the admission/purge floor, but must not recreate local consensus state. | [node.zig](../../src/node/node.zig), lines 1590–1638; [threat model](../threat-model.md), lines 85–103. | Separate answer floor, delivery frontier, journal HWM and admission floor in types/invariants. Recheck admission when dequeuing, not only at enqueue. |
| Typed application state changes only through serialized apply. Observation never aliases live state. | [owned_app_node.zig](../../src/node/owned_app_node.zig), lines 23–56. | `State` can be owned and non-`Clone`; the engine task owns it, callbacks take shared/exclusive references, notifications own an independent observation. |
| Native answering window is bounded local availability policy; local logs are not complete application history. | [protocol](../protocol.md), §13; [driver upgrade](../driver-upgrade.md), lines 109–152. | Start with the same default W=16 and range 1..62. Test restart after compaction; do not demonstrate only pre-compaction counter restarts. |

The signed protocol and deterministic effect contract are compatibility targets;
Zig thread arrangement, vtable spelling, manual allocation/free functions, and
API snapshot machinery are not requirements on Rust's interface. The Zig
stability document specifically says generated accessor names and Node fields
are not the wire contract. Source: [stability](../stability.md), lines 281–294.

## Rust interface choices that improve depth

Use one owned typed application adapter instead of copying the distinction
between by-value `AppNode` and Experimental `OwnedAppNode`. A small trait can
provide deterministic validation/combination, exclusive application, and an
owned observation; constructing the adapter should accept already recovered
state and its checkpoint metadata. Rust move/Drop ownership can remove the
manual `release(applied)`/double-free rule without making state cloning a
requirement. This is a proposed interface, not a claim that borrowing proves
determinism. The original two-adapter split exists partly because changing the
frozen by-value Zig contract was rejected. Sources:
[owned-state ADR](../adr/0003-owned-application-state.md), lines 16–47, 49–84;
[owned_app_node.zig](../../src/node/owned_app_node.zig), lines 23–60.

Keep application serialization explicit initially. The Zig auto-codec is a
special order-preserving fixed-size format: declaration-order fields, big-endian
integers, sign-bit-biased signed integers, strict booleans/enums and zero unused
bits. It is not merely a convenient equivalent to arbitrary Rust serialization.
Rust lacks Zig's arbitrary-width integer types as built-ins; derived codec
parity across every accepted Zig type is a separate project. First interop
should use a hand-specified u64 counter encoding and vectors. A later derive
macro should implement an independently documented common subset and require
explicit widths/enum tags where language defaults differ. Source:
[app_node.zig](../../src/node/app_node.zig), lines 18–29, 70–85 and 283–320.

Use shared references for validate/combine and keep application I/O outside the
consensus owner. Shared references do not prohibit clocks, random data, interior
mutability, or unordered iteration, so preserve the driver determinism contract
and cross-language application vectors. The raw driver also has optional
`extract_valid_value`; omitting it silently from the Rust bytes-level interface
would narrow capability. Source: [driver.zig](../../src/driver.zig), lines 1–29;
[determinism checklist](../determinism.md), §2.

Define failure and cancellation explicitly. Zig owned apply/observe permits
`OutOfMemory` and latches the node inert, retaining partially mutated state only
for destruction. A Rust design should aim at the same safety outcome without
promising recoverable allocation failures unless its chosen collections and
allocation paths actually support them. In particular, an ordinary allocating
trait method is not a fallible-allocation guarantee. A callback panic must not
be caught and followed by continued use of partially applied state. Source for
the existing semantic requirement:
[owned_app_node.zig](../../src/node/owned_app_node.zig), lines 42–51;
[owned-state ADR](../adr/0003-owned-application-state.md), lines 70–84.

Specify slow-consumer behavior before choosing channels. The current raw
externalization queue appends without a fixed bound, and the determinism guide
describes slow draining as queue growth. Replacing this with a bounded Rust
stream is sensible, but silently dropping agreed deliveries is not. Choose and
test explicit fail-stop/recover behavior, or a durable pull cursor; blocking a
full notification channel on the consensus owner can prevent timers and input
processing. Sources: [node.zig](../../src/node/node.zig), lines 2607–2622;
[determinism checklist](../determinism.md), §3.

## Actionable feedback to SLCP

### H1. Publish a language-neutral host/recovery conformance suite

**Confirmed gap.** Protocol §13 explicitly says there are no cross-language
persistence vectors yet; its tests currently pin format and recovery behavior
inside Zig. Add frozen fixtures for record byte order and CRC, nom/ballot-family
dedup, torn final header/payload/checksum, corruption, compaction interruption,
checkpoint overlap, journal gaps, exact previous-value restoration, answer vs
admission floors, and failed write suppressing broadcast. A two-way import test
should operate only with the signer stopped and use a clone of its entire
signing state; copying a live key or only application state is not a supported
handover. Sources: [protocol](../protocol.md), §13, lines 955–1089;
[store.zig](../../src/node/store.zig), lines 94–129 and 318–366.

### H2. Reconcile durability profiles and corruption assumptions

**Verified implementation difference; suspected safety edge, not reproduced.**
The base Store CRC includes its length metadata, but checks `declared end > EOF`
before reaching that CRC and classifies that case as a safe torn tail. A bit
corruption in the length of a formerly durable own record could therefore be
indistinguishable from an unfinished append under this format, potentially
truncating signing history while `own_log_corrupt` remains false. Make an
explicit adversarial fixture before classifying severity or changing v1 bytes.
The adaptivity journal already documents a separate length-metadata checksum.
Sources: [store.zig](../../src/node/store.zig), lines 484–510 and 300–305;
[quorum adaptivity](../quorum-adaptivity.md), lines 147–154.

Base Store also intentionally ignores macOS `F_FULLFSYNC` failure after ordinary
sync, while registry signing/history uses checked media flush and directory
barriers. Base compaction re-syncs its renamed file rather than explicitly
syncing the directory, and initial identity marker sync errors are swallowed.
These are confirmed source differences, not proof of a reproduced power-loss
failure. A Rust port needs a named required durability level and supported
filesystem/platform contract; uniform “crash-safe” wording is too coarse.
Sources: [store.zig](../../src/node/store.zig), lines 420–454;
[node.zig](../../src/node/node.zig), lines 1773–1782;
[registry README](../../examples/registry/README.md), lines 536–570.

Likewise, lack of filesystem locking currently logs a warning and starts
unguarded. Decide whether a signer in the durable profile must refuse that
filesystem or require an explicit operator override. Source:
[store.zig](../../src/node/store.zig), lines 154–169;
[protocol](../protocol.md), lines 1015–1022.

### H3. Separate interoperability from local storage compatibility

**Specification/product decision.** Native overlay §12 combines wire behavior
with detailed local flooding, queue and catch-up policies; §13 makes disk layout
part of host conformance. Publish separate named conformance levels, with
machine-readable manifests of optional capabilities. Otherwise Rust risks
either porting Zig-specific internals unnecessarily or claiming interoperability
while leaving safety/liveness-critical host behavior out. A new Rust disk
format can preserve safety, but it needs an explicit migration/import contract
if disk compatibility is promised. Sources:
[protocol](../protocol.md), §§0, 12–13;
[stability](../stability.md), lines 237–280.

### H4. Promote recovery and durable progress as application concepts

**Usability impedance.** Stable by-value application entry points rely on
Experimental recovery machinery, and asynchronous publication relies on an
Experimental retention/watermark interface. Expose a language-neutral
application lifecycle document distinguishing externalized, delivered,
application-applied and durably recoverable state. Success of
`acknowledgeDurable` means admission, not engine application; a publisher can
finish before its delivery callback returns and must retry `AheadOfDelivery`.
Watermark protection keeps local replay data, not peer history, and a stalled
publisher can grow logs. Sources: [stability](../stability.md), lines 252–263;
[application durability](../application-durability.md), lines 13–42.

### H5. Publish the application codec independently of language reflection

**Cross-language integration requirement.** A mixed Rust/Zig application must
agree on command bytes and deterministic policy, not its language type layout
or binary identity. Publish common codec schemas/vectors for signed integer
extremes, enum tags, nested structs and fixed arrays. Reword the determinism
guide's “same binary on every node” advice for independent conforming
implementations as the requirement to share one application protocol and
replicated configuration. Source:
[app_node.zig](../../src/node/app_node.zig), lines 18–29;
[determinism checklist](../determinism.md), §2 rule 8 and §5(d).

## Registry and BucketList scope

Registry is a separate application protocol, not SLCP's required execution or
storage implementation. It already uses heap-owned state and an explicit boot
context; its current README records removed account/name inline caps and a
Snapshot V4/application network epoch. Older owned-adapter headers and the ADR
retain historical 64/128/global-boot descriptions. Treat those as motivation,
not current registry limitations. Sources:
[registry README](../../examples/registry/README.md), lines 479–492;
[registry app](../../examples/registry/src/app.zig), lines 1–12;
[owned-state ADR](../adr/0003-owned-application-state.md), lines 6–14 and 86–91.

Registry history has distinct hostile archive and trusted signing-fence/outbox
domains. It verifies/reexecutes bounded anchor-to-tip history and keeps signing,
adoption and publication barriers that ordinary Node recovery does not provide.
Porting it in the first milestone would add an application authentication and
durable-publication project, not just a richer counter. Sources:
[registry README](../../examples/registry/README.md), lines 452–478 and 522–570.

BucketList is independently reusable; its SLCP consumers are optional and pinned
to earlier exact SLCP commits, not the inspected current head. The directory
consumer demonstrates owned observations/checkpoint replay; the disk consumer
demonstrates bounded asynchronous publication and fail-stop backpressure. They
are valuable later acceptance experiments without requiring a Rust BucketList
port before slcp-rs can interoperate. Workspace-only sources in the sibling
BucketList checkout are
`bucketlist-zig/examples/slcp-directory/README.md`, lines 3–22 and 33–81, and
`bucketlist-zig/examples/slcp-disk/README.md`, lines 21–76. These are local
source references, not links available from this repository. Consumer-reported
process tests do not establish current-head or
power-loss qualification.

## Proposed host qualification gates

1. Use explicit counter command bytes over a mixed Rust/Zig static quorum;
   require matching externalizations and applied state, then reverse the
   language majority. Test watcher participation separately.
2. Fault-inject each durable append stage; assert no paired broadcast after a
   failed/uncertain own write and no application delivery after failed journal
   append. Kill/restart both language hosts after journal-before-delivery.
3. Run beyond multiple compaction buckets, restart with both current and stale
   application checkpoints, and verify exact previous bytes, replay dedup and
   permanent admission floors.
4. Exercise packet loss via disconnects, partition/heal without reconnect,
   qset request races, future-slot holding, queue pressure and stale queued
   inputs overtaken by purge. Check per-source routing tokens never become
   validator identities.
5. Only then add heap-owned application observations and slow publishers; prove
   that backpressure/recovery cannot discard a journaled value. Add durable
   watermark protection before an asynchronous storage example.
6. If a later profile includes managed migration, implement its own activation,
   exact checkpoint, old-domain retirement, successor installation and recovery
   gates. Passing static host tests does not qualify that profile.

These gates are proposed work, not executed results. Relevant existing witnesses
and constraints are [QUIC hosting](../quic-hosting.md), “Host contract”;
[protocol](../protocol.md), §§12–13;
[application durability](../application-durability.md);
[quorum adaptivity](../quorum-adaptivity.md), “Durability and integration”.

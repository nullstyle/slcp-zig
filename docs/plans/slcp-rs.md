# Plan: an independent Rust implementation of SLCP

Historical plan from 2026-11-02, retained as planning evidence. The Rust
implementation was subsequently created, and the initial compatibility and
durability follow-ups were implemented on 2026-11-04. Statements below about
unstarted work and the absent Rust tree describe the planning baseline, not
current status. See the [implementation report](../research/rust-feedback-implementation-2026-11-04.md)
for the completed work and remaining acceptance boundaries.

Status: proposed, implementation not started. Prepared 2026-11-02 against
`slcp-zig` `346d3ec67f5917f579e4d7505b3b1abb3194d898`.
This is a planning artifact; it does not change the SLCP protocol or authorize
a release. Proposed project location: sibling `../slcp-rs/` in the enclosing
SLCP workspace, with its own repository and Rust release lifecycle.

## Recommendation and first useful result

Build an independent, native Rust consensus engine, followed by a Rust TCP
node and a small typed application layer. Use the Zig implementation as a
pinned differential reference and the SLCP schemas/vectors as the initial
contract. A Rust wrapper around the Zig WASM engine would be useful for host
integration, but would not supply the independent implementation this project
is intended to produce.

The first useful result is a Rust fixture runner, before nomination or ballot
work. The first end-to-end result is a mixed Rust/Zig counter network under a
static quorum profile, including restart and renewed voting. Complete core
conformance, native interoperability and storage compatibility are separate
claims, each with its own gate.

Use the port as a specification exercise: retain each discrepancy as a small
fixture and propose an SLCP ruling. Do not quietly change either implementation
to agree with the other when that would alter protocol behavior. In particular,
agreement with Zig is evidence of parity, not independent proof of safety.

## Observed baseline and assumptions

- SLCP is Stellar-like federated Byzantine agreement with a new Cap'n Proto
  wire format. Stellar nodes are not interoperability peers. `stellar-core`
  is an algorithmic reference, with deliberate SLCP sanity-rule differences.
- The current tree has a sans-I/O engine, native TCP host, typed applications,
  static-quorum traces and Experimental managed quorum/migration machinery.
  The manifest is `0.2.0`; documentation identifies `v0.1.0` as the latest
  released tag. Target the pinned commit, not the ambiguous label “v0.2.”
- There is no `slcp-rs` tree in this workspace. Planning changes belong here
  until the Rust repository exists. No existing application migration is
  assumed.
- Initial platforms: Linux and macOS; `std` Rust. Keep the engine independent
  of clocks, sockets and async runtimes. WASM and `no_std` are later targets,
  not prerequisites for the first independent implementation.
- Initial interoperability profile: strict canonical statements, static quorum
  sets, default driver, explicitly agreed limits, unchanged SLCP v1 domain tags
  and overlay version, and a hand-specified counter codec/network descriptor.
- Stable/Experimental in Zig describes its public declarations. It does not
  define which behavior a safe Rust host may omit. Recovery and exact previous
  value handling remain necessary even where their Zig interfaces are
  Experimental.

Sources: [project introduction](../../README.md#what-slcp-is),
[current status](../../STATUS.md#repository-baseline),
[normative tiers](../protocol.md#0-status-and-scope),
[stability policy](../stability.md), [design](../../DESIGN.md).
Historical test results in those documents were not rerun for this plan.

## Feasibility checked during planning

A temporary Rust program generated readers/builders from the current schemas,
read the existing fixtures, and produced these results:

| Probe | Result | What it establishes |
|---|---|---|
| Both crypto statement fixtures | 2/2 canonicality checks, canonicalization identities, SHA-256 digests, deterministic signatures and strict verification passed | Ordinary signed bytes can be reproduced with existing Rust libraries. |
| Reconstruct every normative effect in the four frozen traces with generated builders | 32/32 framed messages byte-identical: 14 + 6 + 4 + 8 | Current small host-effect frames do not require a custom Rust serializer. |

Versions: Rust `1.99.1`, `capnp = 0.27.2` with `unaligned`,
`capnpc = 0.27.0`, native compiler `capnp 1.5.0`,
`ed25519-dalek = 3.0.0`, `sha2 = 0.10.9`.
These are probe versions, not a decided MSRV or production dependency lock.
This program did not run a Rust engine, replay consensus transitions, test
hostile signature acceptance, qualify parser limits, or prove general encoding
equivalence. See the [probe record](../research/slcp-rs-planning-probe.md).

## Compatibility decisions to make explicit

| Claim | Required evidence | Planned first scope |
|---|---|---|
| Consensus/wire interoperability | Same accepted signed bytes, qset hashes, leader results and SLCP rules; live mixed implementation agreement | Required. |
| Engine conformance | Same normative effects, ordering, status classifications and configured budgets for the same inputs/driver | Required for the static profile; broader traces must be added. |
| Native host interoperability | Hello/framing, bounded ingress, timers, answering, ordered application delivery, restart safety | Required for the first usable node. |
| Zig data-directory interchange | Exact identity/record formats, restore/compaction/corruption rules and two-way recovery fixtures | Separate gate. Protocol §13 currently calls disk formats host-normative; obtain a ruling before advertising full v1 host conformance. |
| Experimental managed sessions and migration | Policy/revision identity, durable activation/application/retirement barriers and certificates | Later phase with an explicit contract; not represented by today's static host traces. |
| Application/history interoperability | Identical command codec, driver/state rules, network identity, checkpoint authentication and replay | Counter first. Registry/history later, as a separately scoped consumer. |

Default storage proposal: Rust-owned data directories, preserving all signing
and recovery obligations from the first node milestone. Do not open a Zig data
directory accidentally or silently turn it into a Rust directory. Implement
Zig-compatible import/export or shared formats only against the explicit
storage ruling and fixtures. This proposes a scope distinction; it does not
override the existing normative wording.

## Rust module design

Start with two library crates and a small tools crate. Keep most implementation
details private; split additional crates only when a real consumer needs them.

| Module | Interface and responsibility |
|---|---|
| `slcp-core::wire` | Own framing versus bare canonical bytes, schema readers, bounded decoding, crypto preimages, signature policy, semantic sanity and normalized qsets. Preserve received signed bytes. Generated Cap'n Proto types stay behind this interface. |
| `slcp-core::Engine<D>` | Serial deterministic input → acknowledged effect queue, with a driver supplied at the application seam. No I/O, time sampling, randomness or runtime types. Own retained statement/value bytes and freeze failed state. |
| Internal consensus modules | Quorum predicates, self-excision/leader selection, nomination, ballots, exact qset references, parking, freshness and limits. These are implementation modules, not a public mirror of every Zig file. |
| `slcp::Node<A>` | One serial owner of engine and application; orchestrates ingress, effect drain, persistence, timers, application progress and shutdown. Presents proposal, owned observation, status and shutdown operations. |
| Host adapters | TCP transport and durable store satisfy real seams: deterministic simulation versus sockets, and injected crash storage versus filesystem. Keep transport/runtime specifics out of the engine. |
| Application adapter | Explicit command codec plus deterministic validation/combine/apply and recovery checkpoint. Own application state and observations; do not require `Copy`, `Clone` or `Sync` state. |
| `slcp-tools` | Fixture/trace runner, differential runner and key/quorum diagnostics. Conformance is usable without booting a network. |

Use a Tokio-backed native host as the initial runtime adapter. Process engine
work serially; blocking durability work runs on a bounded storage worker. Await
the durable acknowledgement before releasing dependent effects or processing
another engine input. Avoid a general runtime abstraction until a second real
runtime is needed. Runtime choice and thread count are local implementation
choices, not protocol changes.

Important interface rules:

1. Inputs borrow for a call; retained state owns its bytes. Cap'n Proto readers
   cannot escape the lifetime of their message storage. Avoid self-referential
   reader/state structures; decode compact owned consensus types as needed.
2. Do not accept the next input until the previous effect queue is drained in
   order. Own or copy an effect before an async operation; acknowledge it only
   when its required action succeeds. The current `persist → broadcast` order
   must survive cancellation, write errors and shutdown.
3. Iteration affecting decisions or effects must be ordered explicitly. Use
   bytewise value/Node ID ordering and prescribed tie rules. A `HashMap` may be
   used for lookup, never as an implicit protocol iteration order.
4. Driver validation/combine stays synchronous, total and deterministic.
   Preserve the raw driver's optional valid-value extraction operation too.
   Borrowing rules do not prevent interior mutability, clock reads or platform
   dependence. Application apply failures halt the node; recovery must restore
   state coherently before voting resumes.
5. Preserve the stateful host hold rule and its v-blocking EXTERNALIZE catch-up
   exception. Apply
   the preceding slot before admitting next-slot validations that depend on
   state; otherwise cached `maybe_valid` results can prevent voting.
6. Notifications may be bounded, but agreed deliveries cannot be dropped.
   Define the exact halt/backpressure/replay behavior on a full queue. Preserve
   sequential apply and any enabled durable application watermark.
7. Name logical resource-budget rejection separately from allocation failure.
   Use fallible reservations where the contract needs recoverable refusal;
   ordinary Rust allocation failure may abort the process. Do not claim Zig's
   sticky-OOM/error parity without qualifying all allocations on that path.

Sources: [engine audit](../research/slcp-rs-engine-conformance.md),
[host/application audit](../research/slcp-rs-host-app-audit.md),
[determinism contract](../determinism.md),
[application durability](../application-durability.md).

## Implementation sequence and completion gates

Each milestone produces a reviewable result and a discrepancy log. A failed
compatibility gate creates a minimized shared fixture and an SLCP decision;
regenerating goldens to make the gate green is not a resolution.

| Milestone | Work | Completion gate |
|---|---|---|
| M0 — freeze the target | Record source/schema/vector hashes, selected static profile, Rust toolchain/MSRV and crate lock. Make the Ed25519, parser, effect-encoding and storage scope decisions below explicit. Establish an issue/discrepancy template with input, expected/actual behavior, source and proposed ruling. | A fresh checkout can acquire the same inputs without sibling paths or a Zig package cache. No unresolved acceptance-rule choice is hidden in a Rust dependency default. |
| M1 — wire and primitives | Generate bindings; implement canonical/framed codecs, exact crypto preimages, signature verification policy, sanity, qset normalization/lint, leader hash/self-excision/weights. Build the CLI fixture runner. | All existing crypto/qset/sanity/lint/leader/framing cases pass; new hostile parser/signature and pointer-presence fixtures agree. Rust-generated positive cases are accepted by pinned Zig. |
| M2 — engine shell | Input/effect queue discipline, limits, sticky failure, timers as inputs/effects, value validation cache keyed by slot, phase and value, statement freshness, pending qsets, exact per-statement qset references and purge. | Focused codec/shell tests cover budgets, parking/eviction, malformed inputs, queue order and fatal-step handling. No new input enters an undrained or failed engine. Complete protocol-driven replay/restore traces are gated in M3. |
| M3 — consensus | Port nomination and balloting as separate reviewed modules, including integer/tie/partial-order rules and externalize singleton semantics. Nomination-only tests precede complete ballot progression. | All frozen traces pass, plus multi-node prepare/confirm/externalize transitions, incompatible prepared ballots, v-blocking progress, qset replay, restore/purge and a node rejoining with restored signing history. Expanded traces cover status and effect ordering through those paths. |
| M4 — independent qualification | Run Rust and Zig under the same deterministic scheduler and event script; add mixed-engine simulation and minimized fuzz/regression exchange. Include a portable stateful custom driver. | No conflicting externalizations among intact nodes under stated quorum/fault assumptions; deterministic repeatability; eventual progress after prescribed network recovery and required proposals. Record seeds/configs/artifact hashes. Differential discrepancies are resolved, not normalized away. |
| M5 — durable native node | TCP Hello/framing, reconnect/flooding, bounded peer queues, qset serving, real timers, own/externalized journals, lock/identity marker, compaction/recovery, answering window and stateful ingress holds. | Mixed Rust/Zig 2-of-3 and 3-of-4 counter clusters progress with tolerated loss, halt without a slice, and resume after kill/restart and partition/heal. The restarted Rust validator must vote on later slots. A separate shared stateful driver/descriptor proves future-slot holding and v-blocking catch-up with a lagging node. Crash points prove persistence before broadcast and journal before delivery. |
| M6 — usable Rust application | Owned application adapter, explicit counter codec, checkpoint slot plus exact previous value, owned observation stream, durable watermark where enabled, clear halted/shutdown errors, standalone example and operator diagnostics. | A standalone Cargo consumer builds without Zig/native `capnp`; mixed counter state and agreed bytes match across Debug/Release and Linux/macOS. Snapshot+tail continuity failures are refused before networking/signing. |
| M7 — release candidate | Publish exact conformance results, implementation/profile compatibility matrix, limitations, package/build reproduction and license decision. Keep experimental Rust interfaces unfrozen until exercised. | Extracted Cargo package builds/tests; required CI cannot pass via skipped oracle/network/tooling gates. Release claims name the source and artifact tested, storage scope and excluded features. |

Critical path: M0 → M1 → M2 → M3 → M4, then M5/M6 integration → M7.
After M1, native transport/storage work can proceed against an effect-driven
fake engine while consensus work continues. Nomination and ballot work can be
reviewed independently, but their integration is sequential. Defer calendar
estimates until M1/M2 reveal the cost of parser parity, conformance expansion
and failure handling; this is a protocol implementation, not a mechanical
syntax translation.

Beyond M7, make separate plans for managed quorum revisions/trust-pool
migration, QUIC/qmsg hosting, Rust WASM ABI support, authenticated history
transfer and a registry/BucketList consumer. The larger broker-network effort
can consume the core later; broker replication/durability and internet-scale
capacity remain separate acceptance work.

## Qualification matrix

| Layer | Required cases beyond today's small frozen corpus |
|---|---|
| Parsing/crypto | Absent versus present-empty/default pointers; trailing words; multi-segment/far pointers; unknown pointers/unions; cycles/amplification; exact cap edges; malformed combinations establishing error precedence; identity/torsion/noncanonical Ed25519 points and scalars; wrong network/tampering. |
| Qsets/engine | Pre-normalization depth, duplicates across levels, permutations and singleton flattening; leader ties and counter overflow; distinct historical qsets from one signer; unknown-qset replay; exact cache rotation/reference limits; relevance checkpoint generation; budget saturation; restore and purge. |
| Consensus | Watcher and validator; conflicting nominations; maybe-valid catch-up; prepared/prime ordering; confirm ranges; stale/incompatible/equivocating messages; duplicate/delayed/reordered input; lost timers, re-arming and counter saturation; partition/heal and crash/restart. |
| Host/storage | Every write/flush/rename/directory-sync interruption; complete bad checksums versus torn tails; record-header corruption; wrong network/key/directory; duplicate process; future externalizations and delivery gaps; W = 1/default/62 and changed W; slow disk, peer or observer; exact predecessor restoration and retained replay. |
| Cross-implementation | Rust-only/Zig-only/mixed engines under one schedule; both peer directions; ordinary and stateful drivers; same application data in multiple builds/platforms; bidirectional disk fixtures only if disk compatibility is claimed. |

Liveness cases must state fairness, eventual delivery and proposer assumptions.
Do not require progress under a partition without the needed quorum slice.
Native-versus-WASM Zig replay remains valuable platform evidence but shares
one algorithm implementation; it does not replace Rust-versus-Zig tests.

## Feedback backlog for the wider SLCP effort

Priorities below indicate when a decision affects this port, not confirmed
vulnerabilities. “Observed” means supported by current source; “risk” needs a
new executable fixture. Detailed sources and qualifications are in the three
linked audits.

| ID / priority | Pain point and evidence | Proposed SLCP feedback / exit condition |
|---|---|---|
| F01 / before M1 acceptance | **Observed:** protocol says Ed25519/RFC 8032 but delegates its accepted signature set to Zig std; existing crypto signatures are ordinary positives. The pinned Zig has distinct cofactored and strict verifiers. | Publish the precise accepted key/point/scalar encodings and verification equation, with adversarial accepted/rejected fixtures. Decide whether existing acceptance is preserved or changed through a version event. Do not assume dalek `verify_strict` is a drop-in replacement. |
| F02 / before M1 acceptance | **Observed:** Zig eagerly validates raw Cap'n Proto graphs before signature/canonicality; Rust's normal typed readers do not establish that same check. Budget accounting and multi-fault precedence can diverge. | Define the intended whole-message validation/acceptance contract and portable adversarial corpus, including unknown pointers. Specify which limits count bytes/words/elements and when. Avoid making incidental parser internals the only specification. |
| F03 / M0–M4 | **Observed:** vectors are declared authoritative but omitted from the normal package, generated by Zig, and only four engine scenarios are frozen. Most hard regressions remain in Zig tests. | Publish a content-addressed conformance bundle with schemas, profile/version manifest, provenance and language-neutral runner format. Promote regression cases, stateful driver behavior and multi-node ballot histories into shared fixtures. Preserve existing goldens and use independent inputs/oracles. |
| F04 / M1–M3 | **Observed:** ordinary framed effect bytes are normative although generic Cap'n Proto encoding is not unique. Today's 32 frames passed the Rust probe; larger shapes/presence choices remain unqualified. | Specify deterministic emit layout/allocation/presence rules or approve a versioned semantic comparison for unsigned wrappers. Keep signed payload bytes exact under either choice. Add large/multi-segment/empty-field cases; do not unilaterally relax existing trace checks. |
| F05 / M2 | **Observed:** fatal pushes can leave queued effects without the usual final status, and SLCPTRC1 has no explicit fatal-result record. `host.capnp` zero=default also cannot express the direct-engine local-only `max_cached_qsets = 0` profile. | Version the harness to represent fatal results, partial-effect handling and supported exact configurations. Distinguish absence/default from explicit zero. Define Rust allocation/fail-stop equivalence separately from deterministic budget rejection. |
| F06 / M0, M5 | **Observed:** protocol calls disk format host-normative, while shared recovery fixtures remain future work in Store comments. Core, overlay, application, engine/ABI and storage versions are different axes. | Decide and document wire/engine/storage conformance profiles. Publish two-way restore/compaction/corruption fixtures and explicit format/version identifiers before claiming data-directory interchange. |
| F07 / M5 | **Observed:** safe host operation requires durable-write-before-broadcast, journal-before-apply, exact previous bytes, separate answer/purge floors and a stateful hold rule. Engine-only traces do not test all of this. | Publish a transport-neutral host state machine plus crash/scheduling fixtures. Model durable acknowledgements explicitly, including application watermarks and cancellation. This benefits every foreign host and the broker effort. |
| F08 / M1, M6 | **Observed:** typed codec and application contract are documented through Zig reflection/types; the determinism checklist assumes identical binaries. Counter parity across languages needs more than generic Serde serialization. | Publish a language-neutral application codec/profile contract: declaration order, widths, big endian, signed bias, enum validity, padding, decode rejection, combine order and recovery semantics. Replace identical-binary guidance with explicit equivalent-semantics qualification for mixed fleets. |
| F09 / M2–M4 | **Observed:** conservative transitive relevance and its periodic exact checkpoint affect ignored/parked effects and bounded work, despite exact quorum predicates remaining separate. | Decide which cache/checkpoint behavior belongs to exact engine conformance and publish traces accordingly. Allow a simpler internal Rust implementation only if its stated compatibility target permits it. |
| F10 / M0, later evolution | **Observed:** Hello advertises overlay version, not a complete consensus/application/acceptance profile; some configurable limits reject values that other configurations accept. Experimental migration is not carried by the static host schema. | Define profile identity and compatibility checks; decide what binds network identity versus negotiated capabilities versus local policy. Version managed lifecycle conformance separately. Do not equate successful Hello with compatible application semantics. |
| F11 / M5 storage review | **Risk, not reproduced:** base Store's unprotected length can classify an over-EOF declaration as a torn tail before checksum validation. Base Store and newer history/adaptivity paths also have different sync/barrier behavior. | Add record-length corruption fixtures and state power-loss/filesystem assumptions precisely. Decide whether a format revision or stronger durability behavior is warranted; evaluate signing-history safety before accepting a silent tail truncation. See the host audit for exact scope. |
| F12 / M7 | **Observed:** current repository explicitly grants no license; Rust release expectations and public stability should not be inferred from Zig's manifest version. | Owner decides licensing/distribution and independent Rust version policy before public publication. This does not block local design or fixture work. |

Detailed evidence:
[protocol audit](../research/slcp-rs-protocol-audit.md),
[engine/conformance audit](../research/slcp-rs-engine-conformance.md),
[host/application audit](../research/slcp-rs-host-app-audit.md).

## First implementation packet

When implementation begins, create the sibling Rust repository and do M0/M1
first: pin the conformance inputs, check in reproducible generated bindings,
provide a fixture runner, and add the missing signature/parser acceptance
fixtures with explicit rulings. Reuse the existing Rust Cap'n Proto library;
do not start by building a new canonicalizer, deriving a broad typed codec or
porting registry history. The resulting runner and discrepancy fixtures should
be reviewable before consensus implementation expands the debugging surface.

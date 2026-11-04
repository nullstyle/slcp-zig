# Maintainer assessment of the Rust implementation feedback

Historical assessment recorded before the implementation work on 2026-11-04.
The source behavior, remote state, proposed work and test scope below describe
the pinned review baseline. They are not current-head claims. Subsequent
changes and qualification are recorded in the [implementation report](rust-feedback-implementation-2026-11-04.md),
[native durability profile](../native-durability.md),
[signature acceptance contract](../signature-acceptance.md),
[wire compatibility contract](../wire-compatibility.md) and
[runner controls](../runner-conformance.md).

Reviewed 2026-11-04 against local `slcp-zig`
`346d3ec67f5917f579e4d7505b3b1abb3194d898`, Zig 0.17.0 and
capnp-zig v0.21.0. The public review tracker is
[#2](https://github.com/nullstyle/slcp-zig/issues/2); its source baseline is
`2524ee48cbc19d538bcfc9f01132b8676ed018ac`. These are different revisions.
The durability/recovery files cited below have no diff between those revisions;
generated bindings and some transport sources do differ. This document is a
source assessment and proposed maintainer disposition, not acceptance of a new
protocol profile or evidence of physical power-loss qualification.

## Overall disposition

The feedback is well founded as a request for portable contracts and executable
qualification. Its evidence has several different strengths: a directly
verified acknowledgement/documentation mismatch, demonstrated porting
impedances, Rust-specific recovery failures, and optional extension proposals.
It does not justify treating all twenty findings as reproduced Zig defects.

Recommended order, subject to maintainer decisions:

| Issue | Recommended disposition | First useful deliverable |
|---|---|---|
| [#3](https://github.com/nullstyle/slcp-zig/issues/3) | First compatibility batch | Record existing Ed25519 acceptance and import provider/envelope fixtures. |
| [#4](https://github.com/nullstyle/slcp-zig/issues/4) | First compatibility batch | Freeze wrapper construction and publish legacy/adversarial decoder cases. |
| [#9](https://github.com/nullstyle/slcp-zig/issues/9) | First durability batch | Choose and enforce the exact sync acknowledgement guarantee. |
| [#10](https://github.com/nullstyle/slcp-zig/issues/10) | First recovery batch | Reproduce emitted-effect/journal cuts and specify restart work. |
| [#6](https://github.com/nullstyle/slcp-zig/issues/6) | Parallel distribution work | Publish a separately identified conformance bundle and exact runnable reference. |
| [#5](https://github.com/nullstyle/slcp-zig/issues/5) | Runner/profile work | Specify fatal outcomes, explicit zero and target memory limits without reinterpreting v1. |
| [#8](https://github.com/nullstyle/slcp-zig/issues/8) | Managed qualification work | Turn existing admission, ordered recovery and catch-up rules into portable transcripts. |
| [#7](https://github.com/nullstyle/slcp-zig/issues/7) | Optional versioned extension | Decide a managed carrier/profile and its negotiation rules. |
| [#11](https://github.com/nullstyle/slcp-zig/issues/11) | Optional versioned extension | Decide generic checkpoint authority and bounded artifact transfer. |
| [#12](https://github.com/nullstyle/slcp-zig/issues/12) | Required before introducing generic managed compaction | Preserve private signing obligations and durable public catch-up evidence independently. |

These dispositions recommend accepting work, not ratifying the proposed byte
layouts, new APIs, capability numbers or timing allocations. Existing v1 signed
bytes, accepted inputs, defaults and trace results remain the compatibility
baseline. This assessment keeps wire, engine, application and storage
qualification claims separate. Existing v1 host normativity combines overlay
and persistence, so claiming full v1 host conformance still requires matching
its storage contract unless an explicit profile ruling changes that obligation.
Source: [existing normative tiers](../protocol.md#L23).

## Compatibility and executable reference

### #3 / F01: specify the existing verifier before choosing another provider

The protocol names Ed25519, but delegates the accepted input set to Zig's
provider. That leaves an independent implementation without a complete rule
for hostile scalar/point encodings and small/mixed-order points. The current
provider uses a cofactored verification equation; selecting another provider's
strict mode solely by algorithm name can change acceptance. Sources:
[protocol description](../protocol.md#L192),
[verification delegation](../../src/crypto.zig#L82), and the provider inputs in
[#3](https://github.com/nullstyle/slcp-zig/issues/3).

Fresh verification on the installed Zig 0.17.0 reproduced all twelve submitted
provider outcomes: four accepts and eight rejects. Its
`lib/std/crypto/25519/ed25519.zig` SHA-256 is
`2282a3629c14d498e25116dafc501c183de55fb6aa576764c36c9cb103878c4d`,
matching the submission. This is a finite provider check; it does not establish
full-envelope parity or a cryptographic audit. Preserve existing acceptance,
document the exact equation/rejection rules, and add full signed-envelope
valid/tampered/wrong-network cases. Tightening acceptance requires a deliberate
compatibility/version decision.

### #4 / F02–F04: preserve exact effects and distinguish decoding from emission

The exact-byte host effect contract already exists, and effects use ordinary
builder allocation and setter order. A large unsigned wrapper is therefore a
useful missing fixture even when signed statements are canonical. Prefer a
specified construction profile and large fixture as the first deliverable;
semantic effect comparison is a separate versioned option. Sources:
[host codec contract](../../src/engine/host_codec.zig#L1),
[effect builder](../../src/engine/host_codec.zig#L173),
[trace records](../../vectors/traces/FORMAT.md#L20), and
[#4](https://github.com/nullstyle/slcp-zig/issues/4).

Ordinary receive already has a specified validation order, and the canonical
decode entry point performs bounded eager graph validation. Add hostile
unknown-field, pointer-presence, alias/work-budget and multi-fault fixtures
against those existing rules. Do not normalize received signed statement bytes.
The reported legacy double-far qset acceptance remains specific to capnp-zig
v0.21.0; accepting historical input and emitting canonical output are distinct
decisions. Sources: [receive contract](../protocol.md#L198),
[pipeline](../../src/engine/pipeline.zig#L179),
[eager decoder](../../src/canonical.zig#L42).

### #5 / F05, F07: preserve v1 defaults and extend the runner separately

Direct Engine configuration intentionally permits a zero qset-cache budget,
while v1 framed configuration intentionally interprets zero as default. This
is an expressiveness gap between interfaces, not evidence that either currently
violates its specified default rule. Add presence/versioning to a new runner
or control profile rather than changing existing zero semantics. Sources:
[direct-zero regression](../../src/engine/pipeline.zig#L1148),
[wire defaults](../../schema/host.capnp#L18),
[config decoder](../../src/engine/host_codec.zig#L365).

Sticky fatal handling also already exists. SLCPTRC1 has no record for a failed
push or its retained partial effects; a portable runner must define that
outcome explicitly. Distinguish Engine payload budgets from allocator/process
limits and WASM linear memory: the default effect byte budget is 16 MiB, while
the current WASM build starts at 4 MiB and caps linear memory at 64 MiB. Sources:
[sticky failure](../../src/engine/pipeline.zig#L65),
[existing trace vocabulary](../../vectors/traces/FORMAT.md#L20),
[WASM queue commit boundary](../../src/wasm/slcp_host_abi.zig#L286),
[logical budget](../../src/engine/engine.zig#L113),
[WASM memory](../../build.zig#L535), and
[#5](https://github.com/nullstyle/slcp-zig/issues/5).

### #6 / F06, F19: distribute conformance independently of the dependency package

The dependency package deliberately excludes developer tools and vectors; that
is consistent with keeping normal consumers small, but does not provide the
separate conformance artifact requested here. A public source checkout has
those files; the exact local comparison revision still needs an independently
obtainable identity. Live `git ls-remote origin refs/heads/main` during this
review returned `2524ee48cbc19d538bcfc9f01132b8676ed018ac`; local HEAD is two
commits ahead. The differences include generated code and Zig I/O adaptations,
so public main must not silently substitute for the port's reference. Sources:
[package inventory](../../build.zig.zon#L11),
[authoritative vectors](../protocol.md#L15),
[distribution request](https://github.com/nullstyle/slcp-zig/issues/6).

Reuse the existing line-protocol WASM runner and differential gates. The runner
already exposes typed ABI refusals. Ordinary `zig build test` can skip its
soft differential check, while `zig build wasm-diff` depends on the actual WASM
artifact. Both use a test binary that can still skip missing Node, runner script
or trace inputs. CI checks Node first and invokes the artifact-building step;
the distributed required runner still needs explicit no-skip enforcement.
Release packaging and fresh reproduction should build on these existing tools.
Sources:
[runner protocol](../../tests/wasm/host.mjs#L23),
[soft versus required gates](../../build.zig#L454),
[required build](../../build.zig#L557),
[runtime/script skips](../../tests/wasm/differential_test.zig#L130),
[trace skip](../../tests/wasm/differential_test.zig#L474),
[CI Node check and invocation](../../.github/workflows/ci.yml#L58).

Publish a manifest for schemas/profile versions, fixtures and expectations,
runner protocol, exact source/artifact identities and tool/dependency pins.
Demonstrate restoration and execution in an isolated environment without
sibling repositories or warm caches, and fail when required gates cannot run.
The Rust repository's existing hashed corpus and immutable Git bundle offer a
local precedent, but do not by themselves close the upstream distribution
request. Workspace-only sources in the private sibling Rust checkout are
`slcp-rs/conformance/manifest.json`,
`slcp-rs/conformance/oracle/manifest.json` and
`slcp-rs/scripts/restore-oracle.py:16`. These are local provenance references,
not links available from this repository. The corresponding public source and
acceptance-request mapping is [issue #6](https://github.com/nullstyle/slcp-zig/issues/6);
reviewing that request does not require the private checkout.

## Managed contracts and checkpoint scope

### #7 / F08, F13: a missing portable carrier, with direct controls already present

The direct managed API already exposes activation, application acknowledgement,
quorum prepare/commit/abort, retirement and successor installation. The gap is
their portable carrier and compatibility profile: the current host schema
carries static Engine inputs/effects only, and overlay Hello provides an
unauthenticated eight-byte network prefix and advisory feature bits. It cannot
establish a full epoch, trust floor or application acceptance profile. Sources:
[Session controls](../../src/adaptivity/session.zig#L128),
[host schema](../../schema/host.capnp#L25),
[Hello fields and trust warning](../../schema/overlay.capnp#L23), and
[#7](https://github.com/nullstyle/slcp-zig/issues/7).

Recommended disposition: design a separate opt-in managed carrier/profile,
preserving existing static schemas, framing and domain tags. Profile admission
should bind the full domain/generation, immutable policy and explicit
application codec/limits without requiring identical local quorum hashes.
Allocate capability/version values explicitly; the Rust local prelude and
assignments have not established an upstream allocation. Compatibility metadata
also cannot replace authentication or caller-pinned trust. Closure requires
direct-control transcripts and actual mixed-language sockets covering missing,
misordered, duplicate and timed-out preludes, mismatch refusal without mutation,
activation, revisions, application acknowledgement, retirement and successor
installation. Current managed cluster tests use in-memory routing and
persistence acknowledgements, not this network carrier:
[test boundary](../../tests/adaptivity_test.zig#L1).

### #8 / F09–F11, F14: export existing safeguards as independent transcripts

This request accurately credits substantial existing Zig behavior. Session
checks current-slot metadata before Engine admission, so future inputs cannot
create parked/cache/timer state. It blocks N+1 until application acknowledgement,
and successor creation authenticates the old certificate, hashes actual
checkpoint bytes and uses the terminal manifest as the exact predecessor.
Sources: [admission](../../src/adaptivity/session.zig#L220),
[application gate](../../src/adaptivity/session.zig#L295),
[successor creation](../../src/adaptivity/session.zig#L136).

Recovery preserves journal ordering before producing separate revision and
envelope lists. It rejects a revision recorded after its first signed slot,
checks every historical own quorum hash before reducing live state, bounds the
live revision window, and retires from terminal own evidence before constructing
an Engine. Caller-pinned genesis/parent authority is checked again during
restore. Sources: [journal-order validation](../../src/node/managed_store.zig#L198),
[full history and terminal preflight](../../src/adaptivity/session.zig#L565),
[activation/parent checks](../../src/node/managed_store.zig#L277).

Recommended disposition: accept portable transcript and qualification work,
without classifying these guarantees as missing Zig fixes. Cover the existing
late-revision rejection, superseded invalid envelope, history beyond live
capacity, terminal-own-only retirement and wrong-parent cases; retain their
side-effect expectations. Add the migration-at-slot-3 application sequence and
sequential laggard trace with historical qsets and renewed successor voting.
An individual terminal EXTERNALIZE is not a full migration certificate:
verification requires the old-policy anchor threshold and already checks entry
count, per-envelope and aggregate byte limits. A network collector must enforce
corresponding limits before retention, independently of verification:
[certificate verifier](../../src/adaptivity/migration.zig#L211).
Existing regression bodies include
[long-epoch durable restart](../../src/node/managed_store.zig#L381),
[retirement and successor restart](../../src/node/managed_store.zig#L435), and
[late revision rejection](../../src/node/managed_store.zig#L549).

### #11 / F16, F18: keep generic checkpoint transfer opt-in and application-owned

SLCP expressly leaves state authentication and history above the consensus
layer. Registry already supplies a concrete application-owned history design:
the importer evaluates its own pinned quorum tree, rather than trusting an
authority advertised by the archive. That is useful precedent, not a generic
managed checkpoint contract. Sources:
[accepted history ownership decision](../adr/0002-registry-replayable-history.md#L6),
[scope rationale](../adr/0002-registry-replayable-history.md#L61),
[registry importing authority](../threat-model.md#L507), and
[#11](https://github.com/nullstyle/slcp-zig/issues/11).

Recommended disposition: either retain explicit application ownership or design
a separately versioned optional checkpoint/history profile. Decide its pinned
authority, application identity, complete state commitment, exact predecessor,
ancestry/replay and attestation fence rules before choosing a transfer codec.
Ordinary EXTERNALIZE authenticates its consensus value; the special migration
certificate additionally binds the manifest's checkpoint digest. Neither grants
arbitrary snapshot authority. Keep freshness/withholding and public availability
separate from certificate validity.

The combined-size concern is concrete: a maximum 64 KiB predecessor alone
consumes the current appMessage payload bound before descriptors or signatures
are added. Transfer therefore needs a bounded multi-object/chunk design or a
deliberately smaller profile. Bilateral app-message gating and native request
rate enforcement already exist; a new transfer client must fit them, rather
than treating an object-count bound as a request/work bound. The Rust 20 ms
spacing is a proposal, not an upstream timing allocation. Closure requires
wrong-authority/profile, rollback, conflicting state, incomplete newer
certificate and malformed/chunk-offset fixtures; combined maximum geometry and
paced real-socket tests; and bounded bytes, work, candidates, requests and time.
Sources: [appMessage bound](../../schema/overlay.capnp#L20),
[bilateral gate](../../src/node/overlay.zig#L1164),
[request budget](../../src/node/overlay.zig#L1262).

## Durability and recovery review

### #9 / F12: confirm the acknowledgement mismatch and make the profile explicit

This is a directly verified source/documentation mismatch deserving early work.
The managed journal calls `file.sync`, then discards the return value of macOS
`F_FULLFSYNC`; it can acknowledge an append after ordinary file sync even when
the media-flush request fails. The native Store deliberately implements the
same fallback. In contrast, the managed documentation says append completes
after file sync and a macOS media-flush upgrade. The source establishes the
weaker acknowledgement; it does not establish any observed physical data loss.
Sources: [journal sync](../../src/node/adaptivity_journal.zig#L227),
[Store fallback](../../src/node/store.zig#L445),
[public promise](../quorum-adaptivity.md#L147).

Preserve credit for existing safeguards: ordinary write/sync failures already
propagate. The journal latches itself unusable for uncertain append failures;
capacity/record-size refusal occurs before that uncertain I/O region. It
checks length metadata before deciding a final append is torn, and refuses
complete corruption. The native Node stops on failed own-envelope persistence
before allowing dependent broadcasts. Sources:
[journal append](../../src/node/adaptivity_journal.zig#L191),
[recovery scan](../../src/node/adaptivity_journal.zig#L149),
[Node dispatch](../../src/node/node.zig#L2410).

Recommended disposition: accept the need for a precise durability profile.
For a profile promising successful macOS media flush, check and propagate
FULLFSYNC failure through the existing fail-stop path. If retaining best-effort
fallback, expose that weaker profile explicitly and narrow the promise. There
is already a checked FULLFSYNC precedent in
[registry history](../../examples/registry/src/history.zig#L1956). Specify file
creation, replacement and directory barriers separately; file-content sync is
not a complete description of a generation-selection transaction.

Closure gate: inject ordinary sync, FULLFSYNC and directory-barrier failures;
assert no dependent acknowledgement/broadcast/application effect escapes the
selected profile and that uncertain writers require reopen/recovery. Retain
the existing [torn-write and corruption cases](../../src/node/adaptivity_journal.zig#L270).
These are software failure tests. Actual controlled power cuts remain a
separate, pending qualification.

### #10 / F15: accept recovery fixtures; do not label the Rust witness a Zig bug

The report correctly attributes its callback-panic failure to the Rust host.
The public Zig native Node already journals an externalized value before
application delivery, and replays retained journal values on restart.
Sources: [externalization dispatch](../../src/node/node.zig#L2452),
[restart replay](../../src/node/node.zig#L1613),
[protocol write path](../protocol.md#L1065).

The managed path has a different boundary: `checkpointApplication` records the
outcome and resulting checkpoint after the host has applied the value. Session
recovery can reconstruct pending application work from a retained original
own EXTERNALIZE at the current frontier. It verifies the complete signed
history, its historical quorum revisions and permanent retirement before
constructing the live engine. Those are substantial existing protections.
Sources: [managed apply/checkpoint](../../src/node/managed_store.zig#L91),
[full recovery preflight](../../src/adaptivity/session.zig#L565),
[pending application reconstruction](../../src/adaptivity/session.zig#L629).

There is nevertheless a concrete contract boundary to exercise. Ballot
self-processing can defer own emission until recursion unwinds, while
externalization enqueues application work. An emitted-effect/journal-cut
fixture is needed to establish which original proof is durable when a host
callback fails; source ordering alone does not reproduce the reported Zig
failure. Sources: [deferred ballot emission](../../src/engine/ballot.zig#L582),
[local externalization](../../src/engine/ballot.zig#L1440),
[Session effect collection](../../src/adaptivity/session.zig#L496).

Nomination-only restore deliberately restores signed votes/accepted sets with
no timer, leader schedule, last proposal or candidate processing. Merely
injecting a timer is insufficient because its handler requires the missing
last proposal and previous value. An unchanged re-proposal need not emit a new
nomination and therefore need not rerun self-promotion. Ballot restore rebuilds
locks but does not run quorum/timer processing. These source facts support
portable progress fixtures and an explicit host resume obligation; they do
not by themselves select a new resume API. Sources:
[nomination restore](../../src/engine/nomination.zig#L1066),
[nominate/timer behavior](../../src/engine/nomination.zig#L982),
[ballot restore](../../src/engine/ballot.zig#L1598),
[ordinary timer arming](../../src/engine/ballot.zig#L1561),
[restore pipeline](../../src/engine/pipeline.zig#L591).

Recommended disposition: prioritize a local-decision durability and restart
work contract plus executable cuts before accepting an implementation design.
Keep trusted local decision evidence distinct from ordinary signed proof and
migration certificates; preserve original generated signatures, never invent
historical proof. Gates should cover nomination-only singleton restart without
new input, halt below quorum and progress after healing, Prepare/Confirm
timers, failure before application checkpoint, and two remaining validators
in a 2-of-3 pool supplying an original closed-slot proof to a laggard and then
voting in a later slot.

### #12 / F17, F20: useful new managed profile; existing answering already separates floors

The reported A-at-3/B-C-compacted-to-5 stall was reproduced in Rust, not Zig.
Zig's native Node already distinguishes the answer floor from the inbound
admission floor, restores retained own statements for answering, and compacts
according to its answering horizon. It reports actual cached coverage after a
larger window is configured instead of claiming deleted records reappeared.
Sources: [restart floors](../../src/node/node.zig#L1590),
[retention and compaction](../../src/node/node.zig#L2550),
[coverage regression case](../../src/node/node.zig#L4113),
[published contract](../protocol.md#L1071).

The optional durable application watermark constrains private journal
compaction, while explicitly leaving peer answering, Engine retention and gap
policy unchanged. Therefore a recoverable local application prefix is already
documented as a different guarantee from serving peers. Sources:
[durability scope](../application-durability.md#L28),
[compaction floor](../../src/node/node.zig#L2575).

The generic managed generation/base-selector transaction and separate durable
public reply store requested by this issue are extensions, not fixes to an
existing generic Zig compactor: the managed journal is append-only and refuses
capacity exhaustion. Registry archive retention is application-owned and
already preserves everything discovery can reach; this report supplies no
reproduction overturning that design. Sources:
[managed journal capacity](../../src/node/adaptivity_journal.zig#L193),
[registry retention decision](../adr/0005-archive-retention.md).

Recommended disposition: accept the invariants for any future generic managed
checkpoint/compaction profile, while retaining the native answering contract
and registry scope. A certified remote application snapshot cannot erase newer
local signing locks, effective/future revisions, activation authority,
attestation fences or retirement. Before pruning private records needed for
peer catch-up, the new profile must durably publish original own EXTERNALIZE
bytes and historical qsets, or provide an explicitly authenticated checkpoint
recovery route. A configured floor does not prove continuous availability.

Closure gates for that extension: same-slot newer locks and stale embedded
fences; selector/base corruption and interrupted generation selection;
canonical-name cleanup and downgrade exclusion; bounded-capacity refusal;
full public object/index/reply publication cuts; and the short-outage witness
with both sources restarted and a superseded qset. Test legacy directories
whose old proofs were already discarded, since an upgrade cannot regenerate
their original signatures.

## Verification scope and fresh results

Read the issue bodies retained in the sibling Rust repository and inspected
the owning Zig source and documented contracts. Compared the public baseline
with local HEAD for the cited handwritten durability/recovery files. Those
paths and the cited handwritten compatibility paths are unchanged between the
two revisions. Dependency-sensitive provider and legacy-qset results retain
their exact local pin; this is not a claim of whole-tree equivalence.

Fresh, bounded warm-workspace checks performed for this assessment:

Rust checks used the clean `slcp-rs` HEAD
`84d5d1ce4a1b534854d672fdd9b7beff0b4ad895`; Zig checks used the local reference
revision recorded at the start of this note.

| Check | Observed result | Limit |
|---|---|---|
| Temporary provider harness calling Zig 0.17.0 `Ed25519.PublicKey.fromBytes` and `Signature.verify` on all twelve submitted inputs | 12/12 expected outcomes; four accepts, eight rejects; provider source hash matched | Provider cases only; the temporary harness was removed, so import shared fixtures for durable regression evidence. |
| `zig build wasm-diff --summary all` in `slcp-zig` | Exit 0; 7/7 build steps and 4/4 tests; four traces, 32 normative and nine observable effects; 300 fuzz iterations, 4,277 inputs and 9,616 effects | Zig native/WASM parity within this suite; no independent consensus safety conclusion. |
| `cargo run --locked -p slcp-tools --bin slcp-tools -- verify-bundle` in `slcp-rs` | Exit 0; conformance bundle hashes PASS | Listed corpus file hashes, not fresh remote distribution or a full package audit. |
| `cargo run --locked -p slcp-tools --bin slcp-tools -- replay` in `slcp-rs` | Exit 0; all four traces, 11 inputs and 32 computed normative effects PASS | Frozen static engine traces only. |

The Zig command printed a `failed command:` diagnostic line despite its zero
exit and successful build/test summary; the reported result above follows the
observed exit status and summary. No new durability fault injection, managed
network lifecycle, full Rust/Zig network qualification, fresh isolated install,
or physical power-loss tests were run. Existing test bodies cited elsewhere in
this assessment establish the presence of safeguards/tests, not fresh passing
results for them. The only repository change from this assessment is this note.

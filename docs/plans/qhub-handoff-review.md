# qhub handoff accuracy review

Reviewed 2026-09-11 against `slcp-zig` commit
`53dafd60fd8493f424cef1c5089632302a59e472`. This review revises the task; it
does not implement the proposed changes. The replacement brief is
[Broker-network substrate task](broker-network-substrate.md).

## Conclusion and corrected scope

The handoff is useful as a source map, but several proposed completion criteria
would establish weaker guarantees than a durable broker network needs. The user
has clarified that the eventual objective is an **internet-scale broker network
built on SLCP, qmsg, and QUIC**, supporting two distinct deployment profiles:

- One operator deploying across regions.
- Independently operated brokers with explicit federated trust assumptions.

The hobby-scale description reflects existing documentation, not the clarified
product objective: `DESIGN.md:19-34` describes small applications, and
`docs/quorum-recipes.md:138-140` calls its three-machine example a hobbyist default.
Those descriptions should distinguish today's implementation envelope from the
future direction. The current production warning remains justified by unclosed
gaps; a larger ambition does not establish deployment readiness.

Internet scale should be evaluated as aggregate capacity across bounded
consensus domains. Replica count, geographical placement, per-log versus grouped
log engines, and reactor count remain design choices. Neither profile requires
every broker to participate in every log. A single hot ordered log still needs
its own throughput budget.

## Corrections that change the task

### Agreement and replicated payload durability are different guarantees

The Engine externalizes opaque value bytes (`src/engine/engine.zig:68-79`). If
those bytes describe payload digests, consensus does not establish where the
payloads are stored or whether they survive losing the acknowledging broker.
Externalization plus one local payload fsync therefore proves less than the
replicated PubAck implied by the brief.

The task must define the required durable-copy evidence under each failure
profile, its binding to the agreed descriptors, and crash behavior around payload
storage, own-statement persistence, externalization, application commit, and
acknowledgement. PubAck latency includes admission, batching, data distribution,
consensus, and durability work; stages can overlap, so it is not generally equal
to slot-close latency. Own-statement fsyncs also occur before broadcasts
(`src/node/node.zig:2744-2752`).

### The proposed missing-payload validation pattern can silence a validator

G2 faithfully repeats `docs/driver-upgrade.md:395-403`, but that advice conflicts
with the present caching behavior. Validation is cached per slot, value, and
phase (`src/engine/values.zig:96-122`); `fully_validated` can become permanently
false for a slot. The repository already documents and tests the resulting
mute-node failure (`docs/threat-model.md:394-413`). Receiving payload bytes later
does not itself trigger revalidation through the current Input API
(`src/engine/engine.zig:30-43`). Enough silenced validators can halt a live slot.

Replace the example with a tested availability/admission contract. Candidate
approaches include holding undecided statements until required data is ready or
designing an explicit revalidation mechanism. Neither should be presented as a
one-line fix: withholding, bounded queues, combined candidates, and progress of
unaffected proposals must be covered.

### Multiple engines need cryptographic domain isolation

Statements contain an Ed25519 Node ID and slot index, but no log identifier
(`schema/slcp.capnp:61-70`). Signatures bind `network_id` and statement bytes
(`src/crypto.zig:25-31`). Reusing the same domain, keys, quorum sets, and slot
numbers across logs permits cross-log replay unless an additional validated
domain binding exists. QUIC stream routing alone provides no such signature
binding.

Add a canonical per-log or per-consensus-group domain construction, durable
identity binding, and cross-domain replay tests before the multi-engine example.
Also distinguish SHA-256(SPKI) transport identities from SLCP's Ed25519 public-key
Node IDs. Their authorization mapping and rotation behavior need an explicit
contract.

### Three replicas do not imply Byzantine fault tolerance

The repository explicitly states that 2-of-3 tolerates one crash and **zero
Byzantine failures** (`docs/quorum-recipes.md:118-122`). It can be a deliberately
limited crash-fault test profile. Independently operated brokers require an
explicit compromised-operator budget and quorum-intersection analysis across
operator and region failures. One operator can also choose a Byzantine profile.

For identical flat threshold sets, honest intersection requires `2t - n > f`
and availability with `f` unavailable members requires `t <= n - f`. These
conditions do not replace analysis of nested or independently chosen quorum
sets. The implementation's local lint cannot prove global intersection
(`DESIGN.md`, Safety and liveness invariants). The
[SCP paper](https://stellar.org/papers/stellar-consensus-protocol.pdf) provides
the underlying federated-trust framework; its correctness results are not a
proof of this implementation or a proposed membership transition.

### Engine recreation is not a membership-transition protocol

G8's static-configuration observation is correct. Its proposed same-network
recreation recipe is not established safe. The Engine starts with empty slot
state and has no membership-transition or fencing input
(`src/engine/engine.zig:30-43,170-179,251-300`). An application announcement alone
does not preserve signing commitments, stop stale incarnations, or prove safe
continuation across old/new partitions.

Replace G8 with a correctness task covering authenticated transition authority,
old/new quorum conditions, state transfer, durable retirement boundaries,
rollback, and restart. Changing the network ID isolates signatures but does not
alone authorize a unique successor history. Simulation is necessary evidence,
not a general proof. The handoff's blanket “no epoch” constraint should not
preclude a justified configuration generation; SLCP's nomination leaders also
already exist (`docs/protocol.md:439-446`).

### A contiguous log must not inherit native gap abandonment

G7 correctly identifies application archives, but misses a critical host-policy
difference. Native Node can advance delivery past missing slots when its local
answering horizon is exhausted (`src/node/node.zig:2836-2855`). The durable
application watermark does not change that policy
(`docs/application-durability.md:37-42`).

A broker log needs explicit continuity: recover and verify missing history, or
remain unavailable until an authorized retention/recovery boundary is established.
Preserve exact predecessor bytes and a durable admission floor as well as
application state. Move this work ahead of performance tuning and API freezing.

## Audit of the original gaps

| Gap | Finding and revision |
| --- | --- |
| G1 | Real gap. `Engine.init` and qset setup helpers are held out because builder errors propagate as `anyerror` (`docs/stability.md:185-201`). The Stable surface is broader than the brief lists: it includes lifecycle, stats, and `timeoutMs` (`138-150`). A foreign-host kit should expose a narrow, exercised contract; promoting Node storage, timers, or all helpers is unnecessary. Include explicit error mapping and ownership, input bounds, async persistence suspension, recovery floors, stale-timer handling, and process-level budgets. |
| G2 | Real outgoing-size gap, but the proposed arithmetic is insufficient: votes and accepted each have their own limit, and encoding adds overhead (`src/engine/limits.zig:8-13`; `src/engine/emit.zig:147-175`). Defaults already allow `2 × 64 × 4096` payload bytes before overhead, beyond 256 KiB. Enforce actual encoded bounds with a defined monotonicity-preserving overflow policy, or prove a conservative configuration envelope. Bound deterministic combine output too. Use stable record IDs before agreement; assign final log sequence numbers from agreed order, rather than assuming concurrent proposers know final `seq` values. |
| G3 | Measurement gap and 1000 ms literal are real. The schedule is normative in protocol §7 (`docs/protocol.md:451-453`), and `timeoutMs` is Stable. A configurable base needs a compatibility ruling covering traces, ABI, and mixed configurations; a domain/version bump is not established merely by finding the literal. Timeouts are not a compulsory delay on every healthy slot. Benchmark WAN and disk/scheduler delay, then evaluate tuning. |
| G4 | Several live slots do not establish speculative nomination support. The current contract requires the exact preceding externalized value and frontier-gated validation (`CONTEXT.md`, Previous value; `docs/protocol.md:589-600`). Use sequential nomination within a domain initially; overlap payload preparation and work across domains. Treat speculative same-log pipelining as separate protocol research. |
| G5 | “Every validator” is false: the documented requirement is a **quorum** of proposing validators (`docs/threat-model.md:415-421`). A nonleader can initially emit nothing (`src/engine/nomination.zig:1410-1428`), so waking idle replicas only upon a statement can introduce timeout delay. Test an authenticated demand/wakeup pattern with retries, bounded empty batches, competing publishers, and publisher failure. Union combine alone does not guarantee eventual inclusion, deduplication across slots, or bounded output. |
| G6 | Accurate adapter gap (`src/node/app_node.zig:635-650`; `src/node/owned_app_node.zig:446-462`). Lower priority for a bare-Engine consumer. If addressed, expose the enable/acknowledge/observe lifecycle together. This is local replay retention, not replicated payload durability. |
| G7 | Accurate archive/host-boundary gap; strengthen with the continuity and signing-history obligations above. Specify startup replay separately from live answering: `get_slot_state(0)` sends at most one own envelope per slot, ballot preferred, while re-flooding sends both nomination and ballot (`src/node/node.zig:3064-3081,3174-3198`). |
| G8 | Static sets confirmed; replace the proposed recipe with the transition correctness task above. |
| G9 | Real measurement gap. The quoted queue budgets are ceilings, not idle allocations; effects and slot maps start empty (`src/engine/engine.zig:111-117,251`). Also, 64 live slots is the default, not a frozen protocol maximum (`src/engine/limits.zig:20-38`). Measure allocator live/peak bytes, retained capacity, process RSS, timer lateness, fairness, and aggregate bounds under mixed hot/idle/recovering logs. 100 engines is a smoke test, not internet-scale validation. |
| G10 | The version facts mostly hold, but the claimed build blocker and prescribed fix are overstatements. See the integration correction below. Release belongs after the chosen scope is verified, not first. |

## Dependency and release correction

At review time, local and remote SLCP main were `53dafd6`, with only tag `v0.1.0`
and 67 later commits. The working tree was initially clean. The manifest says
0.2.0. Snapshot files have 299 and 1,631 lines, representing **292 Stable** and
**1,625 Experimental declarations**, respectively.

SLCP pins capnp-zig v0.16.0. At qmsg HEAD `37a6fb7`, its manifest pins capnp-zig
v0.17.0 and quic-zig v0.21.1 (`/Users/nullstyle/prj/zig/qmsg/build.zig.zon`).
Its README's older QUIC release number is stale. qmsg's certificate enforcement
is optional (`/Users/nullstyle/prj/zig/qmsg/AUTH.md:133-165`), so an authenticated
broker profile must enable and verify it explicitly. The upstream GitHub API reports
[capnp-zig v0.18.0](https://github.com/nullstyle/capnp-zig/releases/tag/v0.18.0)
as latest, published 2026-09-04. Recheck releases when implementing.

A small source-level probe under the pinned Zig compiled the Engine type and
roundtripped bytes through qmsg's codec with SLCP's v0.16.0 core root and qmsg's
v0.17.0 full root. Aligning the probe to the same v0.17.0 package while retaining
separate core/full roots failed with `file exists in modules`; sharing one full
module passed. This disproves the stated inevitable module collision for the
current mixed versions. It does not execute a full Engine lifecycle or establish
that a complete packaged qhub builds. The probe source is retained in
`/private/tmp/slcp-integration-audit/` for this review session.

Package hash and dependency option equality affect dependency reuse, but module
root identity also matters. SLCP already explains why core/full roots cannot
share one graph (`build.zig:62-69`). Upgrading only SLCP to v0.18.0 does not align
qmsg's v0.17.0 pin. Blindly removing `optimize` also discards intentionally
different modes for simulation, WASM, and E2E (`build.zig:200-210,444-449,538-542`).

Replace the mechanical bump with a downstream build fixture that exercises the
actual qmsg codec and bare SLCP Engine in one graph, including documented
optimization modes. Establish a shared-module composition strategy, then choose
and pin versions. Derive the package hash using the prescribed toolchain and
the existing `tools/pkg_hash.sh` workflow; verify the fetched artifact rather
than manufacturing a hash string. Regenerate checked-in code only through the
generator when needed.

## Verification performed

- `mise exec -- zig build test --summary all`: PASS, exit 0. The captured
  aggregate output was truncated; this review does not claim the older
  STATUS.md test counts as a fresh count. The run included docs smoke
  (436 checks, zero failures) and the existing liveness counterexamples.
- `mise exec -- zig build check-api -Dstrict-experimental=true --summary all`:
  PASS, 3/3 steps; 292 Stable declarations frozen, 1,625 Experimental verified.
- `mise exec -- zig build e2e --summary all`: PASS, 3/3 steps, 8/8 tests,
  ReleaseSafe, zero skips. Log: `/private/tmp/slcp-handoff-e2e.log`.
- After adding these documents, `mise exec -- zig build docs-smoke --summary all`:
  PASS, 9/9 steps, 18/18 tests; 436 checks, zero failures.
  Log: `/private/tmp/slcp-handoff-docs-smoke.log`. `git diff --check` also passed.
- Small dependency probe: current mixed versions passed; same-package separate
  roots failed; one shared root passed. This was a source-level integration probe.
- Release preflight, full simulation matrices, WAN/multi-machine load tests,
  and new protocol behavior: not run or implemented for this review.

No source behavior, API snapshot, dependency pin, tag, or release was changed.

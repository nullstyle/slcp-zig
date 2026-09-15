# Broker-network substrate task

Status: proposed replacement for the 2026-09-11 qhub handoff. This brief defines
future implementation work; the review that created it changed documentation
only. Consult [the accuracy review](qhub-handoff-review.md) when evaluating an
original G1–G10 claim or its source evidence.

## Mission and boundaries

Prepare SLCP's foreign-host boundary for an eventual internet-scale broker
network built on **SLCP, qmsg, and QUIC**. qhub is the downstream broker/log
consumer. Support two separately specified deployment profiles: one operator
across regions, and independently operated brokers.

The first deliverable is a bounded, correct, measurable replication substrate
and reference host. Production readiness is a later acceptance decision backed
by deployment evidence. Keep broker routing, discovery, placement, consumer
semantics, retention products, and public service APIs in qhub; record the
contracts SLCP needs from them.

Preserve SLCP as the consensus mechanism. Scale through bounded consensus
domains distributed across brokers, with membership and fault assumptions
specified per domain. Evaluate one engine per log against grouping compatible
logs into a replication domain; the mapping is not settled by this brief.
Similarly, demonstrate one-thread embedding without freezing the entire broker
network to one reactor per process. State whether ordering is per log or group;
cross-domain ordering requires a separate contract.

Use repository terminology from `CONTEXT.md`. “Log” means the application's
persistent sequenced message history; “stream” means a QUIC stream. Distinguish
SLCP Node ID, transport identity, application record ID, slot, and final record
sequence number. Distinguish a broker replication leader from SLCP's existing
nomination-round leaders. Configuration generations, if needed for migration,
must be defined by their actual safety role.

## First decisions and acceptance profile

Read `STATUS.md`, `DESIGN.md`, `docs/protocol.md`, `docs/threat-model.md`, and
`docs/stability.md`; verify current HEAD, tree, toolchain, and dependency graph.
Historical status counts are context, not current verification.

Prepare a concise proposed profile before implementing behavior that depends
on it. Cover both deployments:

| Decision | Required content |
| --- | --- |
| Trust and failures | Crash, disk-loss, compromised-validator/operator, and correlated region/operator assumptions; replica placement; quorum-intersection and availability conditions. Select replica count from these requirements. |
| Acknowledgement | Exact durable payload and agreement evidence required before PubAck, the failures an acknowledged record survives, and handling of unknown outcomes/retries. |
| Consensus domains | Stable identity encoding, per-log or grouped-log mapping, signer ownership, deployment/tenant separation, and eventual migration needs. |
| Capacity | Concurrent domains, active fraction, records/bytes per second per domain and aggregate, payload distribution, batch limits, regions/RTT/loss, disk latency, recovery backlog, and p50/p99/p99.9 latency objectives. Mark proposed targets as proposals. |
| Scope of initial support | Named deployment profiles, supported recovery boundary, Experimental API policy, and integration of the reusable quorum revision and trust-pool migration contracts. |

The original 1 MiB message and 32-header/16 KiB header limits are carried-forward
requirements awaiting verification against qhub. Exactly three replicas, union
combine, a single reactor, and the PubAck rule were tentative replication
choices. Revalidate those choices. Use 2-of-3 only with its
explicit zero-Byzantine budget; separately analyze the independent-operator
profile. Multi-region is a failure-domain requirement as well as a latency test.

Completion: select an explicit initial profile for each deployment claimed
as supported, resolving its failure and durability assumptions before dependent
behavior is implemented. Record remaining choices as open or deferred, and name
the profile for every safety/availability claim. Present consequential
alternatives with a recommendation and concrete implications; continue
independent research, fixtures, and baseline work while decisions are pending.

## Implementation sequence

Prerequisite: complete [reusable quorum adaptivity](quorum-adaptivity.md),
including certified trust-pool migration, before starting qhub. Application
health/placement policy may propose changes but must use the shared verifier,
durable revision boundary and managed migration lifecycle. The broker must
define its checkpoint and authorization semantics and exercise both deployment
profiles. This prerequisite supersedes the earlier static-first milestone.

### 1. Establish a downstream integration witness

Create a small consumer fixture that builds the real qmsg Cap'n Proto codec and
bare SLCP Engine together and exercises both. Inspect package hashes, forwarded
options, and module roots. Choose a shared-module composition strategy and
compatible released versions using evidence from that fixture. Preserve intended
optimization modes and core-only/WASM use cases. Generate and verify hashes with
the pinned toolchain; use the generator for `src/gen` changes.

Completion: the fixture passes from fetched package inputs in supported modes;
the integration strategy and any coordinated qmsg change are recorded. An exact
development revision can support subsequent work before a release tag exists.

### 2. Specify and exercise the foreign-host safety contract

Build a reference host around injected transport, clock, and asynchronous
durability interfaces. Give each engine a serialized owner, a deadline heap
with stale-callback protection, and bounded queues. The reference must drive
multiple independent consensus domains, each with enough replica engines to
exercise its declared quorum profile.

The contract must cover:

- Canonical signed domain separation and transport-to-Ed25519 authorization.
  Test a valid envelope replayed into a different log, tenant, or deployment.
- Config ownership, normalized qsets, key/Node-ID consistency, typed errors,
  borrowed effect lifetimes, local-input bounds, and sticky failure behavior.
- One input followed by its complete ordered effect drain. Suspend that engine
  while own-statement persistence is pending; keep other engines serviceable.
  Broadcast only after the corresponding durable completion. On persistence
  failure, suppress remaining effects and stop the affected signing engine.
- Verified qset resolution and forwarding, the frontier+1 hold rule with its
  precise v-blocking externalization exception, exact predecessor bytes,
  cancellation, bounded catch-up, and monotonic purge/admission floors.
- Startup-only restoration of required own nomination and ballot statements,
  durable signer exclusivity, crash recovery, and rejection of work below the
  closed-slot boundary. Keep normal transport/timer inputs and outward traffic
  quiescent until recovery completes, handling restore effects explicitly.
  A copied key/data directory needs a stated operational or protocol defense;
  a local file lock is insufficient.
- Per-engine and process-wide budgets, overload policy, queue accounting, and
  fair scheduling of active, idle, and recovering domains.

Completion: deterministic tests exercise delayed/failed persistence, crash at
each durable boundary, replay, stale timers, full queues, and continued progress
of unrelated domains. Essential tests belong in `zig build test`; large stress
runs may have a separate build step. Specify the kit before selecting which
existing Node internals, if any, should be extracted.

### 3. Close descriptor, payload, and continuity gaps

Define a bounded canonical batch descriptor using stable record/proposal IDs,
digests, and lengths. Assign final sequence numbers from agreed deterministic
order. Specify duplicate/conflict handling, retry identity, combine output
bounds, overflow, and fairness under concurrent producers. An empty batch must
have a valid nonempty encoding under the current value contract.

Separate payload verification, local persistence, replicated durability
evidence, descriptor consensus, contiguous application commit, and PubAck. Bind
evidence to exact bytes, domain, and configuration. Define retention of staged
payloads, reconstruction after the proposer dies, and when garbage collection
becomes safe under the profile.

Resolve the cached `.maybe_valid` trap before publishing a digest example.
Choose and test host-side availability admission or an explicitly designed
revalidation mechanism. Drivers remain bounded and synchronous. Test missing,
late, invalid, and withheld payloads, combined candidates, recovery, and how
unaffected proposals continue without unbounded memory growth.

Enforce encoded statement/frame limits on local emission and bound inputs and
combined values. Account for both NOMINATE lists, Cap'n Proto overhead, and
monotonic statement rules. Test maximum legal values and multiple proposers;
arbitrary truncation of previously advertised votes is not an acceptable fix.

Define no-gap application recovery using authenticated checkpoints/archive
history, exact predecessor bytes, own-statement continuity, and durable floors.
Specify recent slot-state answering separately from full history transfer.
Native Node's gap-jump policy is not suitable as an implicit contiguous-log
policy. Test long outages beyond peer compaction, corrupt/missing history,
checkpoint rollback, interrupted publication, and disk loss within the supported
failure budget.

Completion: the reference demonstrates the promised PubAck survival property
under injected failures and never silently skips required records. Late-arriving
valid data must not permanently mute a healthy validator; progress resumes once
the profile's quorum and data-availability conditions hold.

### 4. Measure scheduling, batching, and consensus latency

Use sequential same-domain nomination under the current predecessor/hold
contract. Overlap payload preparation and independent domains. Keep speculative
same-log pipelining as separate research requiring an explicit protocol contract.

Exercise an idle-demand pattern that activates a quorum, handles a sole
publisher that is initially not a nomination leader, retries omitted records,
and returns to quiescence. Distinguish empty encoded proposals from zero bytes.
Test concurrent publishers, source death, wakeup loss, and sustained load.

Benchmark the current timer schedule before proposing changes. Report consensus
latency separately from publish-to-PubAck latency, including batching, data
transfer, own-journal flushes, payload durability, scheduling delay, and recovery.
Use 100 B/4 KiB/64 KiB descriptor cases where supported; classify cap rejection
as a result rather than hiding it. Include representative payload sizes.

Run LAN, regional, and WAN-shaped delay/loss/partition profiles; slow disks;
concurrent recovery; hot and idle domains; and hostile-but-authenticated peers.
Measure throughput, tails, bytes and statements per record, CPU, fsync count,
allocator live/peak bytes, retained memory after bursts, RSS deltas, timer
lateness, starvation, and bounded overload. Start with 100 domains, then 1,000
and higher where the machine permits, recording saturation and hardware limits.

If timer tuning is justified, document compatibility with the normative
schedule, Stable `timeoutMs`, host ABI, deterministic traces, and mixed settings.
Do not silently reinterpret requested timer delays in the host. Preserve an
explicit default profile and test loss/recovery as well as the happy path.

Completion: reproducible results identify the limiting resource and support the
chosen initial capacity/latency targets. Finite simulation runs establish
regression evidence, not a general liveness proof or internet-scale readiness.

### 5. Integrate and exercise safe membership evolution

Before enabling replica movement or retirement, specify authenticated transition
authority, configuration identity, old/new safety conditions, exact transfer
state, durable retirement/fencing, delayed old messages, stale boot configuration,
and crash/retry behavior. Provide a written safety argument and adversarial
simulations across the boundary, including partitions and insufficient overlap.

Use the implemented [managed quorum and migration profile](../quorum-adaptivity.md).
An agreed “switch at slot S” followed by engine recreation is not sufficient on
its own. Neither is changing network IDs. The broker's migration checkpoint must
bind payload availability, replicated state and its archive/replay boundary;
the generic SLCP certificate cannot establish those application facts itself.

Completion: exercised broker integration with rejected unsafe revisions,
repeated certified migrations, old-domain retirement, joining/removed brokers,
and crash/partition tests under each supported profile. Do not claim G8 closed
by a happy-path restart test or solely by the generic library implementation.

### 6. Stabilize the exercised surface and prepare a release

Promote only the foreign-host API needed by the exercised consumer, with typed
errors and ownership documented. Avoid freezing broad storage/timer internals
solely because Node uses them. Keep adapter durable-watermark work lower
priority unless a native-Node consumer requires it.

Update design-center documentation to state both the eventual broker-network
objective and current verified limits. Maintain production-readiness statements
according to evidence. Prepare version/changelog/package changes after the
selected milestone is complete. Preserve the owner's license and publishing
decisions for explicit action; none is authorized by this review.

Completion: fetched consumer, strict API checks, applicable full gates, release
notes, and package hash agree on the candidate revision. Tag/push/publication
occur only when authorized. Keep coherent implementation changes independently
reviewable; the dependency fix need not ship as a premature release.

## Verification and reporting

Run builds from the SLCP repository root through
`mise exec -- zig ...`, using the current repository pin. Record commands,
revision, optimization mode, hardware/network assumptions, seeds, pass/fail/skip
counts, and logs. Run socket suites serially because some fixtures use fixed
ports.

Baseline: `zig build test`, strict `check-api`, and `zig build e2e`, all through
mise. For engine/host changes add focused failure tests, simulation and Byzantine
matrices, E2E, and applicable native/WASM differential checks. Use `RELEASING.md`
and the Justfile for the current complete release/package gates rather than
copying stale historical counts. Never hand-edit generated schemas or silently
accept snapshot drift as an API promotion.

Keep protocol-specific host mechanics in SLCP and production transport policy
in qmsg/qhub. QUIC multiplexing does not choose application scheduling priority;
the host must protect consensus and recovery traffic from bulk-data pressure
([RFC 9000 §2.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.3)).
Authenticated links also need explicit authorization and replay handling;
0-RTT requires a deliberate application policy
([RFC 9001 §9.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-9.2)).

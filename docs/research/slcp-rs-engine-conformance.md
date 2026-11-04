# slcp-rs: engine and conformance planning findings

Planning research, 2026-11-02 (America/Anchorage). Reviewed SLCP Zig commit
`346d3ec67f5917f579e4d7505b3b1abb3194d898`. No engine changes or qualification
runs were performed. Paths below are relative to the `slcp-zig` repository;
line references identify this reviewed revision. Recommendations are proposals,
not claims that the Rust implementation already exists or conforms. The parent
planning task separately ran a temporary Rust codec spike; its limited result
is recorded under E1 and should be read with that task's experiment evidence.

## Recommended initial target

Build an independent Rust implementation of the **static-quorum v1 sans-I/O
engine**, then a native host. Keep experimental quorum revision, trust-pool
migration, application messaging, owned application state, and registry history
outside the initial parity claim. The static engine already has an explicit
input/effect seam and a serialized conformance carrier. Experimental adaptivity
adds a different lifecycle with prepare, durable persistence, commit/abort and
admitted-slot rules; it is not represented in the current `host.capnp` config or
input schema. A Rust implementation cannot claim experimental parity merely by
passing the existing host traces. [Sources: `src/engine/engine.zig:369–440`;
`schema/host.capnp:9–46`.]

Rust should preserve observable semantics while replacing Zig-specific storage
and borrowing machinery. In particular, do not translate the self-referential
`Ctx` literally: the current implementation repairs internal pointers before
every push because `Engine.init` returns a movable value. Pass scoped borrows of
engine-owned stores/state into transition functions, or use stable IDs and
explicit state access. Boxed quorum-set pointers and singleton caches are
implementation choices; exact statement-to-quorum-set lookup is the required
behavior. [Sources: `src/engine/pipeline.zig:85–96`;
`src/engine/qset_store.zig:16–19,44–57`; `src/engine/ballot.zig:60–65`.]

## What must match, and what can change

| Obligation | Rust design consequence |
|---|---|
| One input followed by a full ordered drain; own persist precedes broadcast | One engine owner; prevent hosts from re-entering the engine during a drain; keep the persistence action visible until the host has completed it. |
| Exactly one final status on a successful push | Include accepted no-ops, stale timers and malformed inputs in replay tests; distinguish fatal errors from ordinary `InputStatus`. |
| Opaque byte ordering and sorted unique value sets | Use byte-lexicographic comparison explicitly; do not let randomized hash iteration determine emitted values or effects. |
| Per-slot, per-phase driver verdicts; synchronous driver calls | No asynchronous callback inside a transition; do not invalidate verdicts according to local wall time or mutable background state. |
| Latest statement freshness is a partial order | Port `stored.isNewerOwned`, rather than deriving ordinary Rust enum/struct order. |
| Exact qset references on every live statement, deterministic parking and eviction | Quorum lookup cannot use one “latest qset per signer”; preserve required FIFO policy and observable statuses. |
| Logical budgets and sticky failures | Count the specified payloads, not Rust allocation size or `size_of` values. Resource rejection must not depend on container overhead. |

Sources: `src/engine/engine.zig:1–10,35–58,73–98,110–169`;
`src/engine/values.zig:1–4,18–20,72–79`; `src/driver.zig:1–19`;
`src/engine/stored.zig:225–320,323–337`;
`src/engine/pending.zig:1–6,47–97`; `src/engine/qset_store.zig:1–19`.

The Rust crate/module split can remain small: a core module owns slots,
freshness, quorum math, parking, limits and emission; a protocol codec module
owns Cap'n Proto representations and signed bytes; a native host owns clocks,
connections, journal persistence and application delivery. Private transition
functions and state types do not need public traits. Real adapter variation
already exists at the driver and native-versus-simulation host seams. Tests
should normally cross those same seams, with invariant inspection kept private
to each implementation.

## Concrete impedances and feedback candidates

### E1. Unsigned host frames are byte-normative without a language-neutral construction profile

The trace contract requires exact bytes for every normative effect, including
the ordinary framed `host.capnp` wrapper. The Zig codec builds structs in a
particular allocation/setter order and uses `MessageBuilder.toBytes`, not
canonicalization. Empty Data is explicitly encoded with a present zero-length
pointer. This is stricter than equality of the decoded effect and stricter than
equality of signed Statement bytes. A different builder can potentially produce
an equivalent Cap'n Proto frame that fails the trace check. This is a verified
contract/implementation dependency, rather than a demonstrated incompatibility.
The parent task's temporary probe used Rust `capnp 0.27.2` (unaligned),
`capnpc 0.27.0`, native `capnp 1.5.0`, and Rust `1.99.1`. With the same field
write order, all 32 kind-2 effects in the four committed traces matched
byte-for-byte (14/6/4/8 by trace). This removes an immediate blocker for those
fixtures; it does not define all legal builder output or cover larger,
multi-segment effects. [Sources: `src/engine/host_codec.zig:1–35,181–226`;
`tests/vectors_test.zig:479–488,539–555`; `vectors/traces/FORMAT.md`, “File
format” and “Record kinds”.]

Feedback: publish an explicit host encoding profile if exact wrapper bytes are
intentional, and add encodings from at least two builders. Alternatively adopt
canonical host records or semantic comparison in a **new, explicitly versioned**
trace format, retaining exact comparison of signed statement bytes. Do not
silently weaken the existing SLCPTRC1 acceptance rule.

### E2. Four frozen traces underrepresent the current engine

The committed frozen trace set has only `single-node-1of1`,
`insane-and-stale`, `qset-park-resume`, and `timer-bump`. Other regression cases
live in Zig unit tests, simulator logic or implementation-state assertions.
Native/WASM differential testing runs the same engine source in two targets:
it is valuable target/ABI coverage, not an independent algorithm witness.
The harness uses the default driver; custom validity/extraction/combine
behaviors are absent from the frozen trace configuration. [Sources:
`tests/vectors_test.zig:495–501,523–527`;
`tools/gen_vectors.zig:1169–1177,1436–1442`;
`tests/wasm/differential_test.zig:1–8,21–26,39–52`;
`sim/oracle_scenarios.zig:1–12`; `schema/host.capnp:9–16`.]

Feedback: maintain a language-neutral case catalog and promote regressions into
portable traces. Priorities are prepared/prepared-prime replacement, commit
intervals, v-blocking counter jumps, EXTERNALIZE catch-up, invalid versus
maybe-valid phase behavior, watcher suppression, restore and purge,
qset-reference changes, per-node parking caps, cached-qset pressure and
stored-bytes rejection. Add named deterministic drivers or callback
transcripts that cover every driver operation and all three validity levels.

The existing simulator checks useful invariants after every input: ballot and
phase monotonicity, commit/prepared relationships, at-most-once externalization,
strict own-statement progress and effect bounds. Its checks directly inspect
Zig state, so they cannot be attached unchanged to a Rust engine. Reuse the
scenario definitions, observable safety assertions and event schedule, and
implement private Rust state invariants locally. [Sources:
`sim/invariants.zig:1–27`; `sim/sim.zig:424–438`;
`sim/sim_test.zig:1–9,45–55,105–129`.]

### E3. Fatal input results and pending effects need a portable acceptance rule

The prose says every input gets a final status. In actual `pushInput`, an error
from transition processing marks the engine failed and returns before appending
the final `input_status`; previously enqueued effects are not cleared there.
All later pushes fail. The current trace generator and replayer use `try` on
push, and the file format has no record for the push result. Native/WASM fuzz
compares fatal success/refusal outside the trace carrier. This is a verified
representation gap, not a demonstrated consensus bug. [Sources:
`docs/protocol.md:589–606,722–725`;
`src/engine/pipeline.zig:64–82`;
`tools/gen_vectors.zig:1188–1206`;
`tests/vectors_test.zig:530–558`;
`tests/wasm/differential_test.zig:34–37`.]

Feedback: state that the final-status rule covers successful pushes; specify
whether and how a host may execute or discard partial effects after a fatal
push; add fatal-result/error records to the future portable runner contract.
Require no further signing after failure. Rust panic and allocation policies
also need an explicit project decision: exact physical OOM locations cannot be
portable across implementations, while logical budget failures can be.

### E4. Zero is overloaded in limit configuration

`host.capnp` defines zero limit fields as engine defaults. The direct engine
allows `max_cached_qsets = 0` to mean a local-only cache; its source documents
the discrepancy. The host codec therefore cannot round-trip every direct
engine configuration. [Sources: `schema/host.capnp:18–23`;
`src/engine/host_codec.zig:23–26`;
`src/engine/limits.zig:17–29`;
`src/engine/qset_store.zig:76–84`.]

Feedback: document which configurations belong to the portable v1 profile;
eventually use explicit presence or a tagged default/explicit value in a new
host schema version. Rust's `Option` can model the distinction internally but
cannot recover information absent from a v1 frame.

### E5. Relevance optimization is observable, so alternative algorithms need a compatibility decision

The current engine exposes a conservative reachability graph after removals,
then makes it exact at the 64th qualifying update, replay-batch end or purge.
Unknown-qset input can trigger that checkpoint before slot admission. A Rust
engine that simply recalculates exact relevance on every input may have the
same quorum truth but different ignored/parked/status/relay behavior. This
optimization is now described by the normative protocol receive order, so it
cannot be casually replaced while claiming exact engine parity. [Sources:
`src/engine/qset_store.zig:1–14,61–73,233–257`;
`src/engine/pipeline.zig:19–36`; `docs/protocol.md`, “Statement identity and
relevance”.]

Feedback: make explicit whether exact engine parity is a single reference
execution profile or the minimum requirement for any conforming peer. Preserve
the current profile for Rust's first differential milestone; explore a separate
wire-interoperable profile only under an agreed conformance policy.

### E6. Stateful applications require host scheduling rules beyond engine parity

The host must normally withhold statements above delivery frontier + 1, with a
specific v-blocking EXTERNALIZE catch-up exception. Otherwise the engine can
cache a behind-state `maybe_valid` verdict for a slot it later needs to vote on.
The driver cache has no automatic “application state caught up” invalidation.
Recovered nomination also needs the exact previous value bytes. Default-driver
traces cannot establish that a stateful Rust host follows these rules.
[Sources: `docs/protocol.md:589–600`;
`src/engine/values.zig:72–79,96–105`;
`src/engine/engine.zig:40–41`;
`src/engine/nomination.zig:39–45,66–83`.]

Feedback: extract a portable host-ingress scheduling contract and executable
stateful-driver scenarios; include held future messages, delayed application
delivery, exact previous-value recovery, and v-blocking catch-up.

## Suggested qualification sequence

1. **Freeze the target and carrier.** Pin Zig source/schema/vector hashes;
   inventory unsupported experimental interfaces; specify exact host wrapper
   bytes and successful/fatal step behavior before porting state transitions.
2. **Build the codec and runner first.** Decode and re-encode every host union;
   prove default/empty/presence behavior and byte counts against a Zig runner.
   The existing Node script's JSON-line request/response protocol is a usable
   prototype, but its 4 MiB line limit is smaller than the engine's 16 MiB
   payload budget. A shared runner should support the full accepted output.
   [Sources: `tests/wasm/host.mjs:23–62`;
   `src/engine/engine.zig:110–114`.]
3. **Implement static core bottom-up.** Quorum math, freshness, values and
   limits; nomination; ballot transitions; integration pipeline; restore and
   purge. Keep SLCP divergences from Stellar explicit, including single-leader
   tie selection and invalid CONFIRM/EXTERNALIZE collapse to maybe-valid.
   [Sources: `src/engine/nomination.zig:18–30,115–137,191–217`;
   `src/engine/ballot.zig:1–28`.]
4. **Qualify independently.** Existing frozen traces pass byte-exactly; expand
   the portable corpus; run native Zig/Rust lockstep on the same explicit
   inputs and driver results; minimize divergences into committed cases.
   Separate observability effects before comparing normative sequences.
5. **Run mixed engines in simulation.** Same explicit schedule, signer keys,
   quorum sets and proposal bytes; compare externalized values and invariant
   evidence under delay, duplication, loss, partition/heal and Byzantine
   inputs. Schedule equality must not be accidentally derived from one
   implementation's hash iteration or wall clock.
6. **Only then qualify the native host.** Mixed Zig/Rust socket fleets, durable
   persist-before-broadcast, kill/restart, held future slots, long gaps and
   application catch-up. Engine conformance alone does not establish native
   recovery correctness or application determinism.

These gates establish progressively stronger local evidence. They do not
establish production readiness, arbitrary Byzantine safety or acceptance by
real application operators.

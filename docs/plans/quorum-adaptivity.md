# Reusable quorum adaptivity

Status: implemented, 2026-09-14. This work precedes
qhub. It supersedes the static-first ordering in
[the broker substrate plan](broker-network-substrate.md) for quorum evolution.

## Implementation result

- Added trust-floor assessment, per-slot quorum revisions and durable
  activation/recovery boundaries. Mixed revision schedules preserve the
  quorum rule and emitted hash of each admitted slot.
- Added managed sequential sessions, old-domain retirement and certified
  successor installation. Integration tests exercise two application drivers,
  disjoint successor pools, different local revision boundaries and loss of
  the authorizing quorum.
- Added an ordered native journal and `managed_store` bridge. Recovery rejects
  revisions recorded after signing began, validates the full signed quorum
  history, and binds a terminal envelope to the exact migration slot.
- Shared the native hold-buffer implementation through `slcp-core.host`,
  retaining Node aliases. A real freestanding WASM consumer exercises ingress,
  session recovery and successor installation.
- Fixed a checkpoint-acknowledgement lifetime bug found during completion
  review. Checkpoint bytes may safely borrow the session's previous value.
- Included the new source directories in formatting gates and refreshed only
  the Experimental API snapshot. All 292 Stable declarations are unchanged.

Focused core and application integration verification passes 204 tests,
including failure-injection, full-history recovery and allocation-failure
regressions. The full macOS graph passes 118 build steps, with 499 tests passed
and two expected skips in its final uncached subsets. Broader platform and
protocol verification is recorded in [project status](../../STATUS.md).

## Objective

Give applications a reusable way to change their local quorum policy at runtime
without changing the meaning of already admitted slots or losing signing
history. Support both one-operator multi-region deployments and independently
operated validators, with explicit failure assumptions. Keep observations,
application authorization, policy assessment, and activation separate.

Also remove native TCP-host coupling from the existing transport-neutral ingress
helpers so QUIC and other event-loop embedders can use the same tested hold rule.
SLCP's core remains sans-I/O; a QUIC transport implementation is not required
merely to carry its already framed envelopes over qmsg.

## Design constraints

- Consensus safety depends on quorum intersection despite the declared faulty
  validators. Separate configurations passing local lint is insufficient.
- Local health observations cannot establish that an unreachable node is dead.
  An adaptive policy must preserve its trust requirements across partitions.
- A slot retains the local quorum under which it began. Changes intended for
  later slots must not reinterpret old statements, timers, or recovery inputs.
- The host durably records the quorum history before using it to sign. Recovery
  restores the policy for each retained slot and rejects inconsistent history.
- An allocation failure or full policy-history budget must reject a proposed
  update transactionally; it must not leave half-installed trust state.
- Existing static-engine users keep their behavior and wire compatibility.
  New interfaces remain Experimental until exercised by real hosts.
- Failure budgets count signing identities. Independent-operator or regional
  guarantees require an explicit mapping to those identities and correlated
  failure assumptions.

## Approaches under comparison

### Bounded adaptation within an immutable trust policy

The application chooses an authorized anchor roster of `n` validator identities,
an allowed Byzantine-anchor budget `f`, and a minimum anchor count `t` for every
permitted quorum slice, with `2t - n > f`. Every local policy admitted for this
domain must satisfy that floor. The floor's identity must be durable and shared
by conforming participants; runtime adaptation cannot silently lower it or
replace its roster.

For the existing duplicate-free quorum-set trees, the minimum anchor count in
a slice is computable: an anchor leaf costs one, an outsider costs zero, and a
threshold node costs the sum of its cheapest threshold children. This provides
a conservative, application-independent family of compatible quorum policies.
After removing at most `f` Byzantine anchors, their aggregate still has honest
quorum intersection. This is the relevant condition for evolving configurations
in [SCP §6.3, Theorem 13](https://stellar.org/papers/stellar-consensus-protocol.pdf).
The library's implementation still needs its own regression evidence.

Assess availability separately. A policy can satisfy the intersection floor
while requiring a single unavailable node. Compute the minimum number of anchor
failures that can block the policy, treating all outsiders as unavailable;
require more than `f` when promising that local failure tolerance. This is a
structural availability check, not unconditional protocol liveness.

This approach supports changing preferred validator subsets and thresholds
inside an authorized pool. It does not replace the trust pool. Freezing each
slot also means a future policy cannot rescue an already stalled slot outside
its original failure budget.

### Coordinated trust-pool migration

Replacing trust authorities requires a separate authenticated transition:
authorization under the prior configuration, exact state/predecessor transfer,
durable old-incarnation retirement, and authenticated successor adoption. An
agreed slot number or engine recreation alone supplies none of these guarantees.
A lost authorizing quorum can legitimately prevent migration.

This is included in this implementation. A managed sequential Session composes
the recovery/control-value contract with application drivers and archives. A
terminal decision binds the exact checkpoint and successor trust policy; a
certificate of distinct prior-policy anchor signatures authorizes adoption in
a derived successor signing domain. Old signers retire before releasing their
terminal EXTERNALIZE statement. Recovery derives retirement from that persisted
statement even when a later externalization journal record is missing.

## Implementation workstreams

1. **Policy assessment.** Implement a bounded, deterministic verifier and policy
   fingerprint. Exhaustively compare small quorum-tree results against explicit
   slice/failure enumeration. Cover malformed trees, duplicate identities,
   outsider dependencies, safe/unsafe threshold boundaries, and allocation
   failure. This module is useful under either activation approach.
2. **Runtime activation and recovery.** Select the smallest interface that
   enforces slot-specific policy, monotonic revision/activation rules, durable
   ordering, bounded retained history, and exact restart reconstruction. Exercise
   repeated updates and mixed old/new nodes, including delayed messages, full
   caches, and crash cuts. Engine and Session provide the selected interfaces.
3. **Transport-neutral ingress.** Extract the existing `HoldBuffer` and verified
   envelope metadata helpers into `slcp-core`, preserving Node compatibility.
   Use them from both native Node and the foreign-host liveness tests; verify a
   core-only consumer and maximum-slot arithmetic.
4. **Application integration.** Demonstrate activation through at least two
   application policies, including state-dependent validation. Keep adaptation
   triggers outside consensus mechanics. Automatic health/latency selection
   remains application policy; this implementation provides its assessment
   and durable activation interfaces.
5. **Documentation and verification.** Record accepted design decisions and
   terminology; update the future broker plan to depend on implemented support.
   Run strict API checks, focused tests, the full test graph, deterministic and
   Byzantine matrices where protocol changes warrant them, native/WASM
   differential tests, and serial real-socket E2E. Record exact results. No
   release is part of this request.

## Completion criteria

The selected scope must provide executable runtime adaptation, not only an
assessment utility or a recipe requiring callers to mutate Engine internals.
Examples must show rejected unsafe changes, accepted useful changes, preservation
of old-slot semantics, and restart with the correct policy. Document which
failures preserve progress and which correctly halt it. Complete the selected
scope before beginning qhub.

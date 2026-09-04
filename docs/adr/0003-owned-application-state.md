# Keep heap-sized application state behind one owned adapter lifecycle

Status: accepted
Date: 2026-09-04

The typed `AppNode(App)` contract assumes application `State` is plain
by-value data: `waitApplied` hands the user thread a copy per applied slot,
`initialState()` takes no argument, and nothing is ever freed. That contract
cannot express a state larger than a stack value or a durable snapshot loaded
at startup. The registry example is the recorded evidence: it fixes inline
capacities (64 accounts, 128 names inside a ~27 KB struct), copies that struct
through the applied-notification path and the RPC shared state, and hands its
boot snapshot to `create` through a process global because `initialState()`
has no way to receive it.

`slcp.OwnedAppNode(App)` (Experimental) is the opt-in sibling for such
applications. One adapter owns the state's whole lifecycle, and the app
implements six call shapes:

- `initState(context, gpa) InitError!State` on the creating thread, before any
  engine, thread, or listener exists. The caller-supplied `Context` is the
  explicit durable-snapshot handoff — no global, no I/O hidden in a callback.
  Failure is `AppInitFailed` with the app error named in the diagnostic and
  nothing started.
- `validate(*const State, Command, ValueContext)` and
  `combine(*const State, []const Command)` on the engine thread, taking the
  state by pointer and no allocator: verdicts cannot depend on available
  memory.
- `apply(*State, Command, gpa) std.mem.Allocator.Error!void` as the state's
  only mutator, inside the delivery hook, after the externalization is
  journaled and before the next engine input — the same serialization
  `validate` sees, so no lock exists. The narrow signature makes OutOfMemory
  the only expressible failure, and an OOM latches the node inert. Consensus
  decided the value before `apply` ran, so the halt cannot fork the network.
- `observe(*const State, gpa) Obs` immediately after each applied slot. The
  `Obs` is the only thing the user thread ever sees of that slot. Plain-data
  `Obs` needs no cleanup; an `Obs` containing a pointer owns that memory,
  declares `deinitObs`, and every taken `Applied` is returned through
  `release`. Unconsumed observations are freed by `deinit`.
- `deinitState(*State, gpa)` once, after the engine thread has joined and
  every waiter has left, freeing any partially applied shape.
- `initialSlot(*const State)` / `initialCommand(*const State)` keep AppNode's
  restart continuity rules unchanged: the dedup floor comes from the loaded
  state, the journal tail replays through `apply` on the creating thread and
  its observations queue for `waitApplied` exactly like live ones, and an
  independently verified external checkpoint starts at its exact successor
  with the exact preceding command.

## Considered options

- Widening `AppNode` with comptime-optional heap hooks was rejected: the
  Stable snapshot pins the `AppNode(Counter)` instantiation, and interleaving
  a second memory model into every hook would risk the frozen by-value
  behavior and tangle the pinned teaching errors. Two contracts with
  different ownership semantics are two adapters sharing one internal module.
- Leaving the app to manage its state around the bytes-level `Node` was
  rejected as the shallow-module trap: every application would reimplement
  the recovery-hook continuity checks, the dedup floor, the gap discipline,
  and a thread-safe notification queue. One adapter hides all four.
- An observation lock shared with the user thread was rejected: the engine
  thread must never block, and `apply`/`validate` already form a serialization
  point. Producing the observation on the engine thread at apply time is the
  only ordering that needs no lock.
- Restricting `Obs` to plain by-value data was rejected: a registry-class
  application legitimately derives heavy artifacts (a full snapshot clone, a
  serialized ledger) per slot. Ownership plus `deinitObs` plus `release`
  expresses that safely; a comptime pointer walk makes the cleanup obligation
  impossible to forget (a pointer-carrying `Obs` without `deinitObs` is a
  compile error, and `deinitObs` on plain data is dead code and rejected).
- Making `apply` transactional (rollback on OOM) was rejected: a rollback can
  itself fail under the same pressure. A failed apply halts the node and the
  partially applied state is never consulted again; a restart rebuilds it
  from the application snapshot plus the retained journal.

## Consequences

Allocation failure on the engine thread is fail-stop liveness loss for one
node, never a consensus divergence. The observation-ownership discipline is
the application's burden: copying an owned `Obs` out of its `Applied` and
releasing both paths is a double free (the adapter's own tests demonstrate
the rule). `deinit` frees observations nobody took but cannot reach ones a
caller still holds; callers release before `deinit`. The durable handoff is
now explicit — an application snapshot is written by the user thread from an
observation and loaded by `initState` from the `Context`.

This seam unblocks heap-backed application state but does not migrate the
registry example by itself: the registry's Snapshot V3 encoding and its
replayable-history formats carry fixed-width counts (u8 account/name counts,
fixed per-entry widths), so growing past them is an application storage epoch
with its own migration decision, recorded as the next step of the E2
remainder in `docs/examples-roadmap.md`.

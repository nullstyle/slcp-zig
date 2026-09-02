# Determinism checklist for `validate` / `apply` / `combine`

## 1. Why

The engine is a pure function of `(config, input sequence)` → effect
sequence (design §5; `src/engine/engine.zig` module doc): zero I/O, zero
clock, zero RNG. The **driver is the only user code in the loop**, and its
calls are deterministic *by contract*, not by construction — the engine
cannot check them. Two failure shapes, neither of which produces a protocol
error, a lint finding, or a log line on its own:

- A nondeterministic `validate` / `combine` **forks the network**: nodes
  vote differently on the same bytes, quorums form around different values,
  and each side externalizes a different value for the same slot with every
  signature valid.
- A nondeterministic `apply` **diverges state silently**: every node
  externalizes the same bytes and computes a different `State` from them.
  Nothing on the wire changes; the divergence shows up as a `.invalid`
  vote on some later slot — or never.

The design's sharpest user-facing edge (§16): mitigations are the default
driver, this checklist, the double-call check, and the sim harness.

## 2. The rules

For `validate`, `apply`, `combine`, a custom `encode` / `decode`, and any raw
`Driver` function:

1. **No clock, no time.** Not `std.time`, not a slot-to-wallclock mapping,
   not "reject if older than an hour". Slots are your only clock.
2. **No floats.** The auto-codec rejects float fields at compile time
   (`src/node/app_node.zig`: "floats are NONDETERMINISTIC across nodes (NaN
   payloads, ±0, platform math differences)"). Do not compute with them
   either; use fixed-point integers (cents as `u64`).
3. **No hash-map iteration order.** `std.HashMap` / `AutoHashMap` iterate in
   an order that depends on insertion history and allocator behaviour. Sort
   before you iterate, or use an ordered structure.
4. **No I/O, no environment, no RNG.** No files, sockets, env vars,
   `std.Random`, process ids, hostnames.
5. **No pointer-value logic.** Never compare, hash, or order by address; do
   not let allocation success or failure change a verdict.
6. **No global mutable state.** A verdict must depend only on `(state,
   value)` — not on how many times you were called, what the previous slot
   was, or a cache warmed by another thread. (Memoization is fine only if it
   cannot change an answer.)
7. **Total functions.** `combine` must succeed on **any** candidate set and
   return something that validates `.valid`. `validate` must return a
   verdict for **any** byte string of legal length — `.invalid` for
   garbage, never a panic or a fault.
8. **Same binary on every node.** Compiler version, target, optimization
   mode and `Command` declaration all shape the bytes; a mixed fleet is a
   version event (`docs/driver-upgrade.md` §5).
9. **`State` changes only via `apply`.** Nothing else writes it — not a
   background thread, not `validate`, not a "fix-up" after a restart.
10. **Values, not ops.** Commands are full values ("count becomes 3"), so a
    journal replay after a restart re-applies them idempotently.

## 3. The hot path

- `apply` runs **on the engine thread** at the externalize effect, after
  the `externalized.log` append and before any later input reaches the
  driver (`src/node/app_node.zig`, `src/node/node.zig` `deliverSlot`).
  While it runs, no envelope is processed and no timer fires. Keep it small.
- `validate` runs on the engine thread **once per distinct value per slot**
  — the engine caches verdicts by `SHA-256(value)` (`src/engine/values.zig`)
  — inside envelope processing. A slow `validate` slows every peer's
  statement you receive.
- `combine` runs on the engine thread each time the candidate set grows
  (`src/engine/nomination.zig`, the `new_candidates` branch), over the
  sorted-unique candidates (≤ 64). An empty or oversized result is a fatal
  driver fault.
- Heavy work belongs **on the user thread after `waitApplied`**: indexing,
  rendering, notifying, writing your own database. The applied stream is a
  queue; draining it slowly does not stall consensus (the queue grows), but
  never block inside `apply` waiting for that thread.

## 4. State copies

- `waitApplied` yields `Applied{ slot, state }` where `state` is a **value
  copy** taken on the engine thread right after `apply`. The engine's own
  `State` moves on immediately.
- **Never keep pointers into `State`** from the user thread: the copy you
  hold is yours; the original is being mutated by the next `apply`. If
  `State` contains pointers (it should not — the copy would alias), the
  copy is shallow.
- Large `State` ⇒ use the pointer-apply shape `fn (state: *State, cmd:
  Command) void` (`apply_in_place`) to avoid copying the whole struct on
  every slot inside the hot path; the `waitApplied` copy is still a value
  copy, so keep `State` a plain data struct sized for that.

## 5. Catching violations

None of these can prove determinism; each catches a class of violation
cheaply.

**(a) The simulator's determinism test.** `sim/sim_test.zig` →
`determinism: same (seed, config) twice gives a byte-identical event log`
runs one scenario twice and compares every logged event and every
externalized value. The simulator constructs each engine with
`driver.Driver.default()` (`sim/sim.zig`, `Sim.init`); to run your driver
through the scenarios, change that one argument to your vtable and re-run
`zig build sim-matrix` (or a single cell with `zig build sim -- --seed=N
--nodes=N --scenario=name`). A driver that depends on anything outside
`(state, value)` breaks the byte-identical replay.

**(b) `slcp.core.driver.Checked`** (`src/driver.zig`, design §7.3 (b)
as-built): a wrapper that forwards every `validate_value` and
`combine_candidates` call to your driver **twice** and compares the answers.

```zig
var checked: slcp.core.driver.Checked = .{ .inner = my_driver };
// panic_on_divergence defaults to true; set false to count instead.
var node = try slcp.Node.create(gpa, io, .{ ..., .driver = checked.driver() });
// later, in a test: try std.testing.expectEqual(0, checked.divergences);
```

On the first divergence it panics with
`slcp: nondeterministic driver: validate_value gave different answers for the same (slot, value)`
or `slcp: nondeterministic driver: combine_candidates gave different bytes for the same candidate set`.
`Checked` must outlive the node (the vtable ctx is its address); it doubles
driver work, so it is for tests, staging and the harnesses, never the
production driver. It catches calls that disagree with *themselves*
(clock, RNG, call counters, map order, uninitialized memory); it cannot see a
function that is consistent on one machine and different on another.
Experimental tier (plan R16).

**(c) `zig build e2e`** (`tests/e2e/cluster_test.zig`): a 4-node TCP
cluster — 200 slots with agreement, kill/restart, partition/heal, an
equivocator. It creates nodes with the default driver; pass `.driver =
checked.driver()` in its `spawnNode` `Node.create` call to run yours under
real threads, real sockets and real restarts. Agreement is asserted by
comparing externalized values across nodes, so a fork shows up as a red
test rather than a puzzled operator.

**(d) What none of these catch.** Different binaries on different machines
(rule 8): a `validate` that is perfectly deterministic per build but was
built with a different `Command` layout, target or optimization on one node.
Ship one artifact and follow `docs/driver-upgrade.md` §5.

## 6. Symptom → violation

| Symptom | Likely violation |
|---|---|
| Nodes externalize **different values** for the same slot, all signatures valid, no `insane` / `invalid_signature` in the logs | nondeterministic `validate` or `combine` (rules 1–6), or a mixed-version fleet (rule 8) |
| Same externalized bytes everywhere, but `State` differs between nodes | nondeterministic `apply`, or something else writing `State` (rules 6, 9) |
| Network **halts** after a restart with a flood of `.invalid` verdicts | ops instead of values (rule 10), or `State` rebuilt from a partial journal — remember `State` is `initialState()` + the replayed tail, not persisted |
| Node **panics** with `slcp: nondeterministic driver: ...` | `Checked` caught rule 1, 4 or 6 in the act |
| Node goes **inert** with `EngineFailed` / `DriverFault` | `combine` not total, or `DriverFault` returned for a mere invalid value (rule 7); under `AppNode`, also a `combine` whose result its own `validate` judges `.invalid` — the log line names the App (`... combine returned a Command that its own validate judges .invalid`) |
| Network **stalls on the first slot**, no halt, no error log, `insane` rising in every node's `stats()` | a bytes-level `combine` whose composite peers reject as invalid (rule 7): each node ballots a value nobody accepts. `AppNode` turns this into `DriverFault` (row above); a hand-written driver must validate its own composite |
| `AppNode.create` fails with `UndecodableExternalizedValue` | `Command` layout changed under an existing `data_dir` (`docs/driver-upgrade.md` §5) |
| Verdicts flip when a peer reconnects or after a long idle | verdict depends on call history or a cache (rule 6); note the engine only asks once per value per slot, so a "second" call is a different slot |
| Slot rate collapses after adding a feature to `apply` | hot-path work that belongs on the user thread (§3) |
| Everything agrees in `zig build sim-matrix` and forks on real hardware | wall clock, hostname, env, or a platform-dependent library call (rules 1, 4) — the simulator has no clock to disagree about |

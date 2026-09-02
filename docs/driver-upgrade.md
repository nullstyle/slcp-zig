# From `Driver.default()` to a real driver

The bytes-level `slcp.Node` ships with a demo-grade default driver. This
guide is the worked upgrade path design §8.4 promised: what the default does,
when it is enough, the typed `AppNode` tier, the raw vtable, and — the part
that bites — what evolving your command type means for a running network.
Signatures are copied from `src/driver.zig`; the halt rule is copied from
`src/node/app_node.zig`.

## 1. What the default does

`Driver.default()` (`src/driver.zig`, design §8.4), as built:

- **validate**: `.valid` iff `value.len > 0`. The engine has already enforced
  `0 < len <= max_value_bytes` before any driver is consulted
  (`engine.zig` `Ctx.driverValidate`), so the composed behaviour is "valid
  iff the length is in range" — the driver alone only refuses the empty
  value.
- **combine**: the lexicographically greatest candidate — "highest proposal
  wins". Total over any non-empty candidate set; an empty set is a
  `DriverFault` (the engine never passes one).
- **extract_valid_value**: none (`null`).

It orders bytes and **checks no meaning**. Any non-empty byte string is a
legal value; nothing relates one slot's value to the previous slot's.

## 2. When it is enough

- With `AppNode` and the auto-codec (§3): `Codec(Command)` encodes fields in
  declaration order, big-endian, signed ints sign-bit-biased, so **byte order
  equals numeric order** and highest-wins is *semantically* right — the
  largest `next`, the highest bid, the latest version number wins (design
  §8.5). Your typed `validate` supplies the meaning the default lacks.
- Rule of thumb from §11.2: **agree on VALUES, not OPS.** "count becomes 3"
  survives highest-wins combine and journal replay; "add 1" does not (two
  proposers both adding 1 collapse to one increment, and a restarted node
  re-applies only the journal tail onto `initialState()`, so every increment
  before the compaction floor is lost — while a snapshot restored from
  `initialState()` gets that tail applied a second time).
- For a bytes-level `Node` where any non-empty value is acceptable and "the
  biggest one wins" is a fine tie-break — a counter of big-endian integers,
  a monotone version stamp — the default is enough as it is.

## 3. Step 1: the typed `AppNode`

`slcp.AppNode(App)` (`src/node/app_node.zig`, design §8.5) compiles a pure
state machine down to the frozen vtable. The App contract, checked at
comptime (every violation is a teaching `@compileError`, pinned by
`zig build appnode-errors`):

```zig
const App = struct {
    pub const State = ...;    // the replicated state; changes ONLY via apply
    pub const Command = ...;  // the value type the network agrees on

    pub fn validate(state: State, cmd: Command) slcp.Validity;  // pure, deterministic
    pub fn apply(state: State, cmd: Command) State;             // pure — no I/O, no clock;
                              // large-state shape: fn (state: *State, cmd: Command) void
    // optional:
    pub fn combine(state: State, cmds: []const Command) Command;  // deterministic, total;
                              // result must self-validate .valid; may synthesize
    pub fn initialState() State;                                  // default: State{}
    pub fn encode(cmd: Command, buf: []u8) []u8;                  // codec override (both or neither)
    pub fn decode(bytes: []const u8) ?Command;
};
```

- `.maybe_valid` means **"I cannot judge from my state"** — the §0 counter
  returns it for `cmd.next > state.count + 1` because *this node may be
  behind*. It is not `.invalid`; returning `.invalid` for values you merely
  have not caught up to would make a lagging node vote against the network.
- **Where each runs**: `validate` and `apply` both execute **on the engine
  thread** — `apply` at the externalize effect, before any later input
  reaches the driver — reading and writing the one `State` without a lock.
  `apply` is in the consensus hot path: keep it small. The user thread only
  ever sees value copies via `waitApplied(.{ .timeout_ms = ... })`, which
  never hangs (null on timeout / `deinit`, `error.NodeHalted` once the node
  latched inert).
- Auto-codec types: ints (any width), bool, exhaustive enums, fixed `[N]T`
  arrays, nested structs. Floats, pointers/slices, optionals, unions and
  non-exhaustive enums are compile errors that name the rule and the
  workaround.
- **State is not persisted** (v1 limitation, plan R17): after a restart
  `State = initialState()` + `apply` over the replayed journal tail (the last
  ≥ 16 slots). That is why commands must be full values; apps with delta
  semantics persist `State` themselves. Expect the first proposal after a
  restart to be stale — the network rejects it and the loop catches up from
  the applied stream.
- `create` reports failures the same way `Node.create` does: pass a
  `slcp.node.Diagnostic` in `.diagnostic` and print `diag.message()` on
  error (`slcp.node.explain(err)` is the static fallback for the bytes-level
  members; `AppNode`'s two extra members — `CommandExceedsMaxValueBytes`,
  `UndecodableExternalizedValue` — always have a diagnostic message):

  ```zig
  var diag: slcp.node.Diagnostic = .{};
  var app = slcp.AppNode(Counter).create(gpa, io, .{ ..., .diagnostic = &diag }) catch |err| {
      std.debug.print("create failed ({t}): {s}\n", .{ err, diag.message() });
      return err;
  };
  ```

## 4. Step 2: the raw `Driver` vtable

When you need the `slot`, `is_nomination`, `extract_valid_value`, or an
encoding shared with a non-Zig peer, implement the vtable directly and pass
it as `Node.Options.driver`. Copied from `src/driver.zig`:

```zig
pub const Validity = enum(u2) { invalid = 0, maybe_valid = 1, valid = 2 };

pub const DriverError = error{ OutOfMemory, DriverFault };

pub const Driver = struct {
    ctx: *anyopaque,
    validate_value: *const fn (ctx: *anyopaque, slot: u64, value: []const u8, is_nomination: bool) Validity,
    combine_candidates: *const fn (ctx: *anyopaque, slot: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!void,
    extract_valid_value: ?*const fn (ctx: *anyopaque, slot: u64, value: []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!bool = null,

    pub fn default() Driver;
};
```

The contract (design §8.1–§8.2, §7.3), identical in every host language:

- **Synchronous, pure, deterministic.** SCP calls the driver *inside*
  envelope processing; the state machine cannot suspend mid-transition.
- `validate_value` is called **at most once per distinct value per slot**
  (the engine caches verdicts by `SHA-256(value)`, `src/engine/values.zig`).
  `is_nomination` tells you whether the value is a nomination candidate
  (may be a composite you will later be asked to combine) or a ballot value.
  Values of length 0 or above `max_value_bytes` never reach you.
- `combine_candidates` receives the **sorted-unique** candidate slice (own
  sets capped at the frozen 64 entries), is called each time the candidate
  set grows (`src/engine/nomination.zig`), and must be **total**: succeed on
  any candidate set, and its result must itself validate `.valid` and stay
  within `max_value_bytes`. Append the result to `out`; an empty or
  oversized result is treated as a `DriverFault` (fatal, below).
- `extract_valid_value` is optional: given an invalid value, return `true`
  and a valid replacement in `out`, or `false` to drop it (stellar-core
  default, mirrored by the `null` slot). Consulted in the leader-value pick
  when a leader's value fails validation; the extracted value is
  length-gated like any other.
- `DriverFault` (or an out-of-range verdict across the WASM boundary) is
  **fatal for the node**: the engine latches failed (`EngineFailed`), the
  node goes inert. Do not use it for "invalid" — that is a verdict, not a
  fault.
- `ctx` must outlive the node; the vtable is copied by value.

## 5. Command evolution is consensus surface

The auto-codec derives bytes from the struct declaration, so **reordering,
widening, or adding a field changes the wire encoding** — and field
declaration order also sets the default-combine priority (design §8.5).
Strict decode makes a mixed-version network *safe* but *not interoperable*:
old and new nodes judge each other's commands `.invalid` (a non-canonical or
wrong-length byte string decodes to `null`), so no fork, but the network
cannot reach a quorum of `.valid` votes either until the versions agree.
Evolving `Command` is a network version event, same rule as the signed
structs in `docs/protocol.md` §15. Two ways to do it:

### Option A: bump `network`

Change the passphrase (`"my-counter-app v1"` → `"my-counter-app v2"`). A new
`networkId` partitions old from new cleanly: every v2 statement fails
`invalid_signature` on a v1 node and vice versa (protocol §1, §4), so the
two versions cannot even see each other's votes. Procedure:

1. Stop every node (a coordinated restart; the old network halts, which is
   correct — see `docs/threat-model.md` §5).
2. Start each node with the new `network` **and a fresh `data_dir`**: the
   `identity` marker refuses the old directory (`DataDirOtherNetwork`), and
   the old journal's values would not decode as the new `Command` anyway.
3. If v2 must start from v1's final state, encode that state into the first
   v2 command (values, not ops) — the journal does not carry over.

Worked example: `Command = struct { next: u64 }` becomes
`struct { next: u64, author: [32]u8 }`. Old nodes decode 40-byte values as
`null` (`.invalid`); new nodes decode 8-byte values as `null`. Under
`"...v2"` neither ever sees the other's statements, and the v2 network
starts at slot 1 with `.{ .next = last_v1_count + 1, .author = me }`.

### Option B: explicit version tag via a custom codec

Own the wire layout with `encode` / `decode` (both or neither) and a leading
version byte. Unknown version ⇒ `null` ⇒ `.invalid`. Because byte order no
longer means numeric order, **supply `combine`** too.

```zig
pub const Command = struct { version: u8, next: u64, author: [32]u8 };

pub fn encode(cmd: Command, buf: []u8) []u8 {
    buf[0] = cmd.version;
    std.mem.writeInt(u64, buf[1..9], cmd.next, .big);
    @memcpy(buf[9..41], &cmd.author);
    return buf[0..41];
}
pub fn decode(bytes: []const u8) ?Command {
    if (bytes.len == 0) return null;
    switch (bytes[0]) {
        1 => { // v1 layout: version byte + next
            if (bytes.len != 9) return null;
            return .{ .version = 1, .next = std.mem.readInt(u64, bytes[1..9], .big), .author = @splat(0) };
        },
        2 => {
            if (bytes.len != 41) return null;
            return .{ .version = 2, .next = std.mem.readInt(u64, bytes[1..9], .big), .author = bytes[9..41].* };
        },
        else => return null, // unknown version: .invalid, never a fork
    }
}
pub fn combine(state: State, cmds: []const Command) Command {
    _ = state;
    var best = cmds[0];
    for (cmds[1..]) |c| {
        if (c.next > best.next or (c.next == best.next and c.version > best.version)) best = c;
    }
    return best;
}
```

`decode` must be **strict-canonical** — exactly one spelling per command
(exact length, no slack bytes), or the codec becomes a value-malleability
source. A custom `encode` that returns zero bytes is `ValueEmpty`; more than
`max_value_bytes` is `ValueTooLarge` (`propose` errors, not silent drops).

### The halt-on-undecodable rule

Copied from `src/node/app_node.zig` (`undecodable_fmt`):

> `slot {d}: journaled value ({d} bytes) does not decode as {s} — the Command type changed since this data_dir was written. Restore the old Command definition, or start a fresh data_dir under a NEW \`network\` passphrase (command evolution is consensus surface, §8.5).`

A decode failure on an **externalized** value is an invariant break: the
network already agreed on bytes this binary cannot read. During `create`
(the journal-tail replay) it is `error.UndecodableExternalizedValue` with
that message in the diagnostic; at runtime the node logs it at error level
and **latches inert** (`waitApplied` → `error.NodeHalted`, `haltError()`
returns the cause). It never diverges silently.

### Rolling upgrade under Option B

The rule above is what a rolling upgrade must avoid: a v1 node that sees a
v2 value *externalized* halts. So:

1. Ship a binary whose `decode` understands **both** layouts (as above) and
   whose `validate` still rejects v2 commands (`if (cmd.version == 2) return
   .invalid;`), and roll it out to every node. Nothing changes on the wire.
2. Once **all** nodes run the dual-decode binary, ship the binary that
   accepts v2 in `validate` and starts proposing v2 commands. Any node still
   on step 1 keeps voting `.invalid` on v2 values — it slows the network if
   it is many, but it never halts, because it can decode what gets
   externalized.
3. Only after every node proposes v2 may a later release drop the v1 arm.

Never let a node that cannot decode a layout coexist with a node that can
externalize it.

## 6. Large values

`max_value_bytes` defaults to `4096` and is capped at the frozen `65536`
(`docs/protocol.md` §8); raising it also raises the parking, storage and
wasm-memory budgets that scale with it (design §16). For anything larger,
use the **digest-in-value** pattern (design §4.4): agree on
`SHA-256(payload)` (plus whatever metadata the validator needs), fetch the
payload out of band, and have `validate_value` return `.maybe_valid` until
the payload is available locally — never block inside the driver.

## 7. Checklist before shipping a driver

- [ ] `validate_value` / `combine` / `apply` are pure: no clock, no floats,
      no map-iteration order, no I/O, no RNG, no global mutable state —
      every item in `docs/determinism.md` §2.
- [ ] `combine` is total and its result self-validates `.valid` within
      `max_value_bytes`.
- [ ] Every node runs the **same binary**; command evolution follows §5.
- [ ] `.maybe_valid`, not `.invalid`, for "I cannot tell yet".
- [ ] `DriverFault` is reserved for genuine faults.
- [ ] You ran it under `slcp.core.driver.Checked` in tests
      (`docs/determinism.md` §5) and through `zig build e2e` with your
      driver plugged into `tests/e2e/cluster_test.zig`.
- [ ] Your `data_dir` migration story for the next `Command` change is
      written down (Option A or B) before the first release.

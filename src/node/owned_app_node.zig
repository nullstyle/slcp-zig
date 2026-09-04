//! owned_app_node.zig — the heap-state typed adapter (Experimental).
//!
//! `AppNode(App)` (app_node.zig) assumes `State` is plain by-value data: it
//! is copied into every applied notification, `initialState()` takes no
//! context, and nothing ever frees anything. That contract cannot express a
//! state larger than a stack value or a durable snapshot loaded at startup —
//! which is why `examples/registry` uses fixed inline capacities (64
//! accounts, 128 names) and a process-global `boot` handoff.
//!
//! `OwnedAppNode(App)` is the opt-in adapter for such applications. It owns
//! the application state's whole lifecycle behind one seam:
//!
//! | Phase | Call | Thread |
//! |---|---|---|
//! | create | `initState(context, gpa)` | creating thread, before any engine/thread |
//! | validate/combine | `validate(*const State, …)` / `combine(*const State, …)` | engine thread (creating thread during journal replay) |
//! | apply | `apply(*State, cmd, gpa)` | engine thread (creating thread during journal replay) |
//! | observe | `observe(*const State, gpa) → Obs` | engine thread, right after each apply |
//! | notify | `waitApplied() → Applied{slot, obs}` | user thread; the queue owns the Obs until then |
//! | release | `release(applied)` | user thread, once done with an Obs that owns memory |
//! | deinit | `deinitState(*State, gpa)` | deinit thread, after the engine thread joined |
//!
//! Lifecycle and concurrency invariants:
//!
//! 1. **One owner.** The adapter holds exactly one `State`, created by
//!    `initState` and destroyed exactly once by `deinitState`. `initState`
//!    runs before the Node exists: a snapshot file is loaded (or genesis
//!    built) with the `Context` the caller passes to `create` — no global.
//!    Failure unwinds completely (`AppInitFailed`, nothing started).
//! 2. **One serialized mutator.** `apply` is the only mutation path and runs
//!    on the engine thread, inside the delivery hook, after the
//!    externalization is journaled and before the next input — the same
//!    serialization `validate` sees, so no lock exists. During `create`'s
//!    journal replay the hook runs on the creating thread before any thread
//!    starts, preserving the same order.
//! 3. **Safe notifications.** The user thread never receives a reference
//!    into `State`. `observe` runs on the engine thread immediately after
//!    each apply and returns an `Obs` by value. Plain-data `Obs` needs no
//!    cleanup; an `Obs` that contains a pointer owns that memory, must
//!    declare `deinitObs`, and every taken `Applied` must be returned via
//!    `release`. Unconsumed observations are freed at `deinit`.
//! 4. **Fail-stop on engine-thread allocation failure.** `apply` and
//!    `observe` may return only `error.OutOfMemory`. The delivery hook
//!    propagates it and the node latches inert (§10 discipline): a partially
//!    applied state is never consulted again, and a restart rebuilds it from
//!    the application snapshot plus the retained journal. Consensus decided
//!    the value before `apply` ran, so an OOM halt cannot fork the network.
//! 5. **Determinism.** `validate` and `combine` take `*const State` and no
//!    allocator: verdicts cannot depend on available memory. `apply` may
//!    allocate, but only its success/failure is observable outside the
//!    process, and failure halts rather than diverges.
//! 6. **Restart continuity unchanged.** `initialSlot`/`initialCommand` are
//!    read from the loaded state and checked by the same recovery rules as
//!    `AppNode` (`InitialSlotOutsideJournal`); the journal tail replays
//!    through `apply` before `create` returns and its observations queue for
//!    `waitApplied` exactly like live ones.
//!
//! The teaching-error and Options-mirror machinery is shared with
//! `app_node.zig` through `app_common.zig`. This module is Experimental: the
//! contract may evolve before promotion, while `AppNode`'s Stable surface
//! stays byte-for-byte.

const std = @import("std");
const core = @import("slcp-core");
const node = @import("node.zig");
const app_node = @import("app_node.zig");
const common = @import("app_common.zig");

const Validity = core.driver.Validity;
const Driver = core.driver.Driver;
const DriverError = core.driver.DriverError;
const ValueContext = app_node.ValueContext;
const Codec = app_node.Codec;
const max_encoded_bytes = app_node.max_encoded_bytes;

const log = std.log.scoped(.slcp_owned_app_node);

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

fn contractError(comptime App: type, comptime msg: []const u8) noreturn {
    @compileError("slcp.OwnedAppNode(" ++ @typeName(App) ++ "): " ++ msg);
}

fn hasCustomCodec(comptime App: type) bool {
    return @hasDecl(App, "encode") or @hasDecl(App, "decode");
}

/// Does `T` carry a pointer anywhere (field, element, optional payload)?
/// An `Obs` that does owns memory and must declare `deinitObs`.
fn containsPointer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => true,
        .optional => |o| containsPointer(o.child),
        .array => |a| containsPointer(a.child),
        .vector => |v| containsPointer(v.child),
        .@"struct" => |s| blk: {
            inline for (s.field_types) |FT| {
                if (containsPointer(FT)) break :blk true;
            }
            break :blk false;
        },
        .@"union" => |u| blk: {
            inline for (u.field_types) |FT| {
                if (containsPointer(FT)) break :blk true;
            }
            break :blk false;
        },
        else => false,
    };
}

/// The comptime contract of the owned adapter, checked in one-violation-
/// one-message order like `app_node.validateAppContract`. Every
/// `contractError` site is pinned by a `tests/appnode_errors/owned_*.zig`
/// expected-fail object; the docs gate counts the sites against the table.
fn validateOwnedContract(comptime App: type) void {
    if (!@hasDecl(App, "State"))
        contractError(App, "missing `pub const State` — the owned replicated state type." ++
            "\n  The node holds ONE State and owns its lifetime: initState creates it," ++
            "\n  apply is its only mutator, deinitState frees it. It may be heap-backed.");
    if (!@hasDecl(App, "Command"))
        contractError(App, "missing `pub const Command` — the value type the network agrees on." ++
            "\n  Same rule as AppNode: agree on VALUES (\"count becomes 3\"), never on OPS" ++
            "\n  (\"add 1\") — ops break under combine and under journal replay (design §11.2).");
    if (!@hasDecl(App, "Obs"))
        contractError(App, "missing `pub const Obs` — the per-slot observation type." ++
            "\n  observe() produces one after every applied slot and waitApplied hands it to" ++
            "\n  the user thread, so State is never copied wholesale nor exposed by reference." ++
            "\n  Prefer small plain data (nothing to free); an Obs that contains a pointer" ++
            "\n  owns that memory and must declare deinitObs.");
    if (!@hasDecl(App, "Context"))
        contractError(App, "missing `pub const Context` — the startup context type." ++
            "\n  initState receives it (`pub const Context = void;` when there is nothing to" ++
            "\n  pass) — this is how a durable snapshot reaches the node without a global.");
    if (!@hasDecl(App, "InitError"))
        contractError(App, "missing `pub const InitError` — the explicit error set initState returns." ++
            "\n  Like slcp.keys: an inferred error set is not a contract. initState failures" ++
            "\n  are reported as AppInitFailed with this error named in the diagnostic.");

    const State = App.State;
    const Command = App.Command;
    const Obs = App.Obs;
    const Context = App.Context;

    if (!@hasDecl(App, "initState"))
        contractError(App, "missing `pub fn initState(context: Context, gpa: std.mem.Allocator) InitError!State`." ++
            "\n  Runs on the creating thread before any engine, thread, or listener exists:" ++
            "\n  load a durable snapshot from the context or build genesis here.");
    if (@TypeOf(App.initState) != fn (Context, std.mem.Allocator) App.InitError!State)
        contractError(App, "initState has the wrong signature." ++
            "\n  want: fn (Context, std.mem.Allocator) InitError!State" ++
            "\n  got:  " ++ @typeName(@TypeOf(App.initState)));

    if (!@hasDecl(App, "deinitState"))
        contractError(App, "missing `pub fn deinitState(state: *State, gpa: std.mem.Allocator) void`." ++
            "\n  The node calls it exactly once, from deinit, after the engine thread has" ++
            "\n  joined — it must free everything initState and apply allocated, from any" ++
            "\n  partially-applied shape (an apply that ran out of memory halts the node," ++
            "\n  and deinit still runs).");
    if (@TypeOf(App.deinitState) != fn (*State, std.mem.Allocator) void)
        contractError(App, "deinitState has the wrong signature." ++
            "\n  want: fn (*State, std.mem.Allocator) void" ++
            "\n  got:  " ++ @typeName(@TypeOf(App.deinitState)));

    if (!@hasDecl(App, "validate"))
        contractError(App, "missing `pub fn validate(state: *const State, cmd: Command, context: slcp.ValueContext) slcp.Validity`." ++
            "\n  The owned shape always takes State BY POINTER (no per-call copy of a large" ++
            "\n  state) and always observes the slot/phase context. Must be pure, allocation-" ++
            "\n  free, and deterministic.");
    if (@TypeOf(App.validate) != fn (*const State, Command, ValueContext) Validity)
        contractError(App, "validate has the wrong signature." ++
            "\n  want: fn (*const State, Command, slcp.ValueContext) slcp.Validity" ++
            "\n  got:  " ++ @typeName(@TypeOf(App.validate)));

    if (!@hasDecl(App, "apply"))
        contractError(App, "missing `pub fn apply(state: *State, cmd: Command, gpa: std.mem.Allocator) std.mem.Allocator.Error!void`." ++
            "\n  The owned shape mutates in place and may allocate; the only legal failure is" ++
            "\n  OutOfMemory (the type enforces it), which halts this node — never the value" ++
            "\n  the network already agreed on.");
    if (@TypeOf(App.apply) != fn (*State, Command, std.mem.Allocator) std.mem.Allocator.Error!void)
        contractError(App, "apply has the wrong signature." ++
            "\n  want: fn (*State, Command, std.mem.Allocator) std.mem.Allocator.Error!void" ++
            "\n  got:  " ++ @typeName(@TypeOf(App.apply)));

    if (!@hasDecl(App, "observe"))
        contractError(App, "missing `pub fn observe(state: *const State, gpa: std.mem.Allocator) std.mem.Allocator.Error!Obs`." ++
            "\n  Runs on the engine thread right after each apply; the Obs it returns is the" ++
            "\n  ONLY thing the user thread sees of that slot. Never return a reference into" ++
            "\n  State — the engine thread keeps mutating it.");
    if (@TypeOf(App.observe) != fn (*const State, std.mem.Allocator) std.mem.Allocator.Error!Obs)
        contractError(App, "observe has the wrong signature." ++
            "\n  want: fn (*const State, std.mem.Allocator) std.mem.Allocator.Error!Obs" ++
            "\n  got:  " ++ @typeName(@TypeOf(App.observe)));

    // Obs ownership: a pointer anywhere means deinitObs is mandatory; plain
    // data means declaring one is dead code and rejected.
    if (containsPointer(Obs)) {
        if (!@hasDecl(App, "deinitObs"))
            contractError(App, "Obs owns memory (it contains a pointer) but has no deinitObs." ++
                "\n  declare `pub fn deinitObs(obs: *Obs, gpa: std.mem.Allocator) void`, or make" ++
                "\n  Obs plain by-value data so there is nothing to free.");
        if (@TypeOf(App.deinitObs) != fn (*Obs, std.mem.Allocator) void)
            contractError(App, "deinitObs has the wrong signature." ++
                "\n  want: fn (*Obs, std.mem.Allocator) void" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.deinitObs)));
    } else if (@hasDecl(App, "deinitObs")) {
        contractError(App, "deinitObs is declared, but Obs is plain by-value data — there is nothing to free." ++
            "\n  Drop deinitObs (release() becomes a no-op), or give Obs owned memory (a" ++
            "\n  pointer field) that deinitObs actually frees.");
    }

    if (@hasDecl(App, "combine")) {
        if (@TypeOf(App.combine) != fn (*const State, []const Command) Command)
            contractError(App, "combine has the wrong signature." ++
                "\n  want: fn (*const State, []const Command) Command" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.combine)) ++
                "\n  combine must be deterministic, total, and allocation-free; its result" ++
                "\n  must not self-validate .invalid.");
    }
    if (@hasDecl(App, "initialSlot")) {
        if (@TypeOf(App.initialSlot) != fn (*const State) u64)
            contractError(App, "initialSlot has the wrong signature." ++
                "\n  want: fn (*const State) u64   (the slot initState's State already includes; 0 = none)" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.initialSlot)));
    }
    if (@hasDecl(App, "initialCommand")) {
        if (!@hasDecl(App, "initialSlot"))
            contractError(App, "initialCommand requires initialSlot." ++
                "\n  The command is the consensus value at initialSlot(); declare that slot so recovery can bind the two.");
        if (@TypeOf(App.initialCommand) != fn (*const State) ?Command)
            contractError(App, "initialCommand has the wrong signature." ++
                "\n  want: fn (*const State) ?Command   (the exact value externalized at initialSlot(); null at genesis)" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.initialCommand)));
    }
    if (hasCustomCodec(App)) {
        if (!@hasDecl(App, "encode") or !@hasDecl(App, "decode"))
            contractError(App, "a custom codec needs BOTH `pub fn encode(cmd: Command, buf: []u8) []u8` and `pub fn decode(bytes: []const u8) ?Command`." ++
                "\n  A lone half cannot round-trip. With a custom codec, strict canonicality (one" ++
                "\n  spelling per command) and numeric order are YOUR job — supply `combine` too.");
        if (@TypeOf(App.encode) != fn (Command, []u8) []u8)
            contractError(App, "encode has the wrong signature." ++
                "\n  want: fn (Command, []u8) []u8   (write into buf, return the encoded bytes — normally buf[0..n])" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.encode)));
        if (@TypeOf(App.decode) != fn ([]const u8) ?Command)
            contractError(App, "decode has the wrong signature." ++
                "\n  want: fn ([]const u8) ?Command   (null = not a canonical command)" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.decode)));
    }

    // The auto-codec's own rules (floats, pointers, …) fire here, after the
    // shape checks, so a bad Command type is reported once and in context.
    if (!hasCustomCodec(App)) _ = Codec(Command);
}

// ---------------------------------------------------------------------------
// OwnedAppNode(App)
// ---------------------------------------------------------------------------

/// The teaching texts for the two engine-thread allocation failures. The
/// narrow `std.mem.Allocator.Error!void` signature makes OutOfMemory the only
/// possible failure; the node treats both exactly like any delivery-hook
/// error: latch inert, drain waiters, then NodeHalted.
const apply_failed_fmt = "{s}.apply ran out of memory applying slot {d}; the node goes inert — the partially applied state is never consulted again and a restart rebuilds it from the application snapshot plus the retained journal.";
const observe_failed_fmt = "{s}.observe ran out of memory at slot {d}; the node goes inert rather than hand out an incomplete observation.";

/// The heap-state typed adapter. `App` declares `State`, `Command`, `Obs`,
/// `Context`, `InitError`, `initState`, `deinitState`, `validate`, `apply`,
/// `observe`, and optionally `combine` / `initialSlot` / `initialCommand` /
/// `deinitObs` / a custom `encode`+`decode` pair; see the module doc for the
/// lifecycle and concurrency invariants. `Command` follows the same codec
/// rules as `AppNode` (auto-codec by default); `State` and `Obs` are the
/// application's to shape.
pub fn OwnedAppNode(comptime App: type) type {
    comptime validateOwnedContract(App);
    return struct {
        const Self = @This();

        pub const State = App.State;
        pub const Command = App.Command;
        pub const Obs = App.Obs;
        pub const Context = App.Context;
        pub const InitError = App.InitError;
        /// `Codec(Command)` (auto, order-preserving) or the app's own
        /// encode/decode pair (custom, `is_custom = true`) — same rules as
        /// `AppNode`.
        pub const codec = blk: {
            const CustomCodec = struct {
                pub const Value = App.Command;
                pub const is_custom = true;

                pub fn encode(v: App.Command, buf: []u8) []u8 {
                    return App.encode(v, buf);
                }
                pub fn decode(bytes: []const u8) ?App.Command {
                    return App.decode(bytes);
                }
            };
            break :blk if (hasCustomCodec(App)) CustomCodec else Codec(App.Command);
        };
        /// true when `Obs` contains a pointer: it owns memory, every taken
        /// `Applied` must be returned through `release`, and `deinitObs`
        /// exists. Plain-data observations make `release` a no-op.
        pub const obs_owns_memory = containsPointer(Obs);
        /// Every `node.Options` field except `driver` and `delivery`
        /// (same types, same defaults; comptime parity-checked). Reified
        /// here so its `@typeName` is this public path (see
        /// `common.mirrorOptionFields`).
        pub const Options = blk: {
            const f = common.mirrorOptionFields();
            break :blk @Struct(.auto, null, f.names, f.types, f.attrs);
        };
        comptime {
            common.checkOptionsParity(Options, "OwnedAppNode.Options");
        }
        pub const WaitOptions = node.Node.WaitOptions;
        /// One applied slot: the observation taken on the engine thread
        /// right after `apply`. When `obs_owns_memory`, the caller owns
        /// `obs` and must return it via `release` (before `deinit`).
        pub const Applied = struct { slot: u64, obs: Obs };
        pub const CreateError = error{ AppInitFailed, CommandExceedsMaxValueBytes, InitialSlotOutsideJournal, UndecodableExternalizedValue } || node.CreateError;
        pub const ProposeError = node.ProposeError;
        pub const WaitError = error{NodeHalted};

        gpa: std.mem.Allocator,
        io: std.Io,
        /// The bytes-level node; null only for a detached (test) instance.
        n: ?*node.Node = null,
        /// Engine-thread-only (and the creating thread during the journal
        /// replay): the replicated state. Created by `initState` before the
        /// errdefers that free it, destroyed in `deinit` after the engine
        /// thread joined.
        state: State,
        /// Engine-thread-only: highest slot applied. A slot at or below it
        /// is a re-delivery (journal overlap) and is a no-op.
        applied_hwm: u64 = 0,
        max_value_bytes: u32,
        /// Set once `create` has returned; the hook logs loudly only then
        /// (inside `create` a failure becomes the diagnostic instead).
        created: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        /// Recorded by the hook for `create`'s codec-mismatch diagnostic.
        undecodable: ?struct { slot: u64, len: usize } = null,
        /// Recorded by the hook when apply/observe ran out of memory during
        /// `create`'s journal replay, so the failure maps to a teaching
        /// diagnostic instead of the Node's generic EngineFailed text.
        apply_failed_slot: ?u64 = null,
        observe_failed_slot: ?u64 = null,
        /// Set by the pre-live recovery hook so `create` can replace Node's
        /// generic hook error with the app-level snapshot/journal diagnostic.
        recovery_rejection: ?node.RecoveryView = null,
        /// An external checkpoint newer than the journal must carry the exact
        /// command agreed at its final slot; otherwise next-slot nomination
        /// would start from the empty predecessor sentinel.
        initial_command_present: bool = false,
        initial_command_missing: bool = false,
        /// The requested consensus start, captured before Node recovery.
        start_slot: u64 = 1,

        // waitApplied queue (same shape as AppNode's applied queue).
        mu: std.Io.Mutex = .init,
        cond: std.Io.Condition = .init,
        queue: std.ArrayList(Applied) = .empty,
        head: usize = 0,
        closed: bool = false,
        halt_err: ?anyerror = null,
        /// Threads currently inside `waitApplied` (under `mu`). `deinit`
        /// wakes them and then waits on `drained` for this to reach zero
        /// BEFORE freeing, so a woken waiter never re-locks a freed `mu`.
        waiters: usize = 0,
        drained: std.Io.Condition = .init,

        /// Allocate the adapter without a Node (the driver / hook can be
        /// exercised directly). `deinit` handles both shapes. `initState`
        /// runs here, so a bad context fails create, never the network.
        fn createDetached(gpa: std.mem.Allocator, io: std.Io, max_value_bytes: u32, context: Context) CreateError!*Self {
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.* = .{ .gpa = gpa, .io = io, .max_value_bytes = max_value_bytes, .state = undefined };
            self.state = App.initState(context, gpa) catch |e| {
                return common.fail(null, error.AppInitFailed, "{s}.initState failed ({t}); nothing was started.", .{ @typeName(App), e });
            };
            errdefer App.deinitState(&self.state, gpa);
            self.applied_hwm = if (comptime @hasDecl(App, "initialSlot")) App.initialSlot(&self.state) else 0;
            return self;
        }

        /// Start the owned node. `context` is borrowed for the `initState`
        /// call only (copy anything it must outlive into `State`). Forwards
        /// `opts` to `node.Node.createWithRecovery` with the compiled driver,
        /// pre-live recovery check, and delivery hook, replaying the journal
        /// tail through `apply` before returning; each replayed slot's
        /// observation queues for `waitApplied` exactly like a live one.
        /// Adds four members to the bytes-level `CreateError`:
        /// `AppInitFailed` (initState failed — diagnostic names the app
        /// error), plus AppNode's `CommandExceedsMaxValueBytes` /
        /// `InitialSlotOutsideJournal` / `UndecodableExternalizedValue` with
        /// the same meanings. An apply/observe OOM during the replay is
        /// `OutOfMemory` with the slot named in the diagnostic.
        pub fn create(gpa: std.mem.Allocator, io: std.Io, opts: Options, context: Context) CreateError!*Self {
            // Same contract as Node.create: a reused Diagnostic never keeps
            // a previous failure's text, and OutOfMemory gets a message too
            // (the adapter allocation fails before Node.create runs).
            if (opts.diagnostic) |d| d.len = 0;
            return createChecked(gpa, io, opts, context);
        }

        fn createChecked(gpa: std.mem.Allocator, io: std.Io, opts: Options, context: Context) CreateError!*Self {
            const diag = opts.diagnostic;
            if (comptime !codec.is_custom) {
                // Only once the range itself is sane: an out-of-range value
                // is the Node's MaxValueBytesOutOfRange, not ours.
                if (opts.max_value_bytes >= 1 and opts.max_value_bytes <= 65536 and codec.size > opts.max_value_bytes) {
                    return common.fail(diag, error.CommandExceedsMaxValueBytes, "Command encodes to {d} bytes but max_value_bytes is {d}; raise max_value_bytes (<= 65536) or shrink Command.", .{ codec.size, opts.max_value_bytes });
                }
            }

            const self = gpa.create(Self) catch
                return common.fail(diag, error.OutOfMemory, "out of memory while creating the node; nothing was started — free memory or raise the process limit and try again.", .{});
            errdefer gpa.destroy(self);
            self.* = .{ .gpa = gpa, .io = io, .max_value_bytes = opts.max_value_bytes, .start_slot = opts.start_slot, .state = undefined };
            // initState BEFORE any errdefer that touches state: a failed
            // init has allocated nothing the adapter owns.
            self.state = App.initState(context, gpa) catch |e| {
                return common.fail(diag, error.AppInitFailed, "{s}.initState failed ({t}); nothing was started — the data_dir was not opened and no listener bound.", .{ @typeName(App), e });
            };
            errdefer App.deinitState(&self.state, gpa);
            self.applied_hwm = if (comptime @hasDecl(App, "initialSlot")) App.initialSlot(&self.state) else 0;
            // Replay may have queued observations before a later create step
            // fails; free them, then the list, then the state (LIFO order).
            errdefer self.queue.deinit(gpa);
            errdefer self.releaseQueued();

            var nopts: node.Options = .{
                .network = opts.network,
                .quorum = opts.quorum,
                .listen_port = opts.listen_port,
                .data_dir = opts.data_dir,
                .driver = self.driver(),
                .delivery = self.hook(),
            };
            inline for (@typeInfo(Options).@"struct".field_names) |name| {
                @field(nopts, name) = @field(opts, name);
            }

            var recovery: node.RecoveryOptions = .{ .hook = self.recoveryHook() };
            var recovery_scratch: ?[]u8 = null;
            defer if (recovery_scratch) |buf| gpa.free(buf);
            if (comptime @hasDecl(App, "initialCommand")) {
                if (App.initialCommand(&self.state)) |cmd| {
                    const scratch = gpa.alloc(u8, max_encoded_bytes) catch
                        return common.fail(diag, error.OutOfMemory, "out of memory while seeding the checkpoint predecessor value; nothing was started.", .{});
                    recovery_scratch = scratch;
                    self.initial_command_present = true;
                    recovery.previous_value = .{
                        .slot = self.applied_hwm,
                        .bytes = codec.encode(cmd, scratch),
                    };
                }
            }

            const n = node.Node.createWithRecovery(gpa, io, nopts, recovery) catch |e| {
                if (self.undecodable) |u| {
                    // The hook refused a journaled value during the tail
                    // replay: report OUR member with the teaching text
                    // (the Node's generic "hook refused" paragraph is
                    // superseded).
                    return common.fail(diag, error.UndecodableExternalizedValue, common.undecodable_fmt, .{ u.slot, u.len, @typeName(Command) });
                }
                if (self.apply_failed_slot) |slot| {
                    return common.fail(diag, error.OutOfMemory, "{s}.apply ran out of memory replaying journal slot {d}; nothing was started — free memory or raise the process limit and retry.", .{ @typeName(App), slot });
                }
                if (self.observe_failed_slot) |slot| {
                    return common.fail(diag, error.OutOfMemory, "{s}.observe ran out of memory replaying journal slot {d}; nothing was started — free memory or raise the process limit and retry.", .{ @typeName(App), slot });
                }
                if (self.recovery_rejection) |view| {
                    const s0 = self.applied_hwm;
                    const successor: ?u64 = std.math.add(u64, s0, 1) catch null;
                    if (successor == null) {
                        return common.fail(diag, error.InitialSlotOutsideJournal, "initialSlot() = {d} has no successor slot, so the node cannot start after that State; use a checkpoint below the maximum u64 slot.", .{s0});
                    }
                    if (view.journal_tail) |tail| {
                        return common.fail(diag, error.InitialSlotOutsideJournal, "initialSlot() = {d} but the journal in {s} retains slots {d}..{d} with a gap-free suffix only from slot {d}, and .start_slot is {d}; restore a State immediately before that suffix, or independently verify an external checkpoint through slot {d} and set .start_slot = {d} exactly. The node did not go live.", .{ s0, opts.data_dir, tail.first, tail.last, tail.contiguous_from, self.start_slot, s0, successor.? });
                    }
                    return common.fail(diag, error.InitialSlotOutsideJournal, "initialSlot() = {d} but the journal in {s} is empty and .start_slot is {d}; start from initialSlot() = 0 with .start_slot = 1, restore the local journal, or independently verify an external checkpoint through slot {d} and set .start_slot = {d} exactly. The node did not go live.", .{ s0, opts.data_dir, self.start_slot, s0, successor.? });
                }
                if (self.initial_command_missing) {
                    return common.fail(diag, error.InitialSlotOutsideJournal, "initialSlot() = {d} is newer than the local journal, but initialCommand() did not provide the exact consensus value at that slot; retain that Command in the authenticated checkpoint so nomination for slot {d} uses the same predecessor as incumbent validators. The node did not go live.", .{ self.applied_hwm, self.start_slot });
                }
                return e;
            };
            self.n = n;
            self.created.store(true, .release);
            return self;
        }

        /// Stop the node (joins the engine thread — no hook call can be in
        /// flight afterwards), wake `waitApplied` callers with null, wait for
        /// every one of them to leave `waitApplied`, free every observation
        /// still queued, free the application state, then free the adapter.
        /// A thread may be parked in `waitApplied` when `deinit` runs; it
        /// must not call anything on the adapter after `waitApplied` returns
        /// null. Observations already handed to a caller are that caller's
        /// to `release` (or leak): deinit cannot reach them.
        pub fn deinit(self: *Self) void {
            if (self.n) |n| n.deinit();
            self.mu.lockUncancelable(self.io);
            self.closed = true;
            self.cond.broadcast(self.io);
            while (self.waiters > 0) self.drained.waitUncancelable(self.io, &self.mu);
            self.mu.unlock(self.io);
            self.releaseQueued();
            const gpa = self.gpa;
            self.queue.deinit(gpa);
            App.deinitState(&self.state, gpa);
            self.* = undefined;
            gpa.destroy(self);
        }

        /// Free every observation the queue still owns (handed to nobody).
        /// Callers own what they took; deinit owns the rest.
        fn releaseQueued(self: *Self) void {
            if (comptime !obs_owns_memory) return;
            for (self.queue.items[self.head..]) |*item| App.deinitObs(&item.obs, self.gpa);
        }

        /// Encode `cmd` with the codec and queue it for nomination. A custom
        /// codec returning zero bytes is `ValueEmpty`; one returning more
        /// than `max_value_bytes` is `ValueTooLarge`.
        pub fn propose(self: *Self, cmd: Command) ProposeError!void {
            const n = self.n orelse return error.WatcherCannotPropose;
            if (comptime codec.is_custom) {
                // Sized to the frozen cap so an oversize custom encoding is
                // reported (ValueTooLarge), not a buffer overrun.
                const buf = try self.gpa.alloc(u8, max_encoded_bytes);
                defer self.gpa.free(buf);
                return n.propose(codec.encode(cmd, buf));
            } else {
                var buf: [codec.size]u8 = undefined;
                return n.propose(codec.encode(cmd, &buf));
            }
        }

        /// Block for the next applied slot in order. Returns null on timeout
        /// or after `deinit`; after the node has halted, the already-applied
        /// items are still drained first, then `error.NodeHalted` —
        /// immediately, even with `timeout_ms = null`. When
        /// `obs_owns_memory`, the caller owns `item.obs` until `release`.
        pub fn waitApplied(self: *Self, wopts: WaitOptions) WaitError!?Applied {
            self.mu.lockUncancelable(self.io);
            defer self.mu.unlock(self.io);
            self.waiters += 1;
            defer { // runs before the unlock above (reverse order)
                self.waiters -= 1;
                if (self.waiters == 0) self.drained.signal(self.io);
            }
            while (self.head >= self.queue.items.len and !self.closed) {
                if (wopts.timeout_ms) |ms| {
                    self.cond.waitTimeout(self.io, &self.mu, node.msTimeout(ms)) catch return null;
                } else {
                    self.cond.waitUncancelable(self.io, &self.mu);
                }
            }
            if (self.head < self.queue.items.len) {
                const item = self.queue.items[self.head];
                self.head += 1;
                if (self.head == self.queue.items.len) {
                    self.queue.clearRetainingCapacity();
                    self.head = 0;
                }
                return item;
            }
            if (self.halt_err != null) return error.NodeHalted;
            return null;
        }

        /// Return one `Applied` taken from `waitApplied`. Required before
        /// `deinit` for every item when `obs_owns_memory`; a no-op for
        /// plain-data observations, so calling it unconditionally is the
        /// simple rule. Must not be called after `deinit`.
        pub fn release(self: *Self, applied: Applied) void {
            if (comptime obs_owns_memory) {
                var a = applied;
                App.deinitObs(&a.obs, self.gpa);
            }
        }

        /// The error the node halted with (after `on_failed`), else null.
        pub fn haltError(self: *Self) ?anyerror {
            self.mu.lockUncancelable(self.io);
            defer self.mu.unlock(self.io);
            return self.halt_err;
        }

        /// The compiled §8.2 driver (ctx = this adapter).
        pub fn driver(self: *Self) Driver {
            return .{
                .ctx = @ptrCast(self),
                .validate_value = driverValidate,
                .combine_candidates = driverCombine,
            };
        }

        /// The bytes-level node underneath (stats, boundPort, …).
        pub fn raw(self: *Self) *node.Node {
            return self.n.?;
        }

        fn hook(self: *Self) node.DeliveryHook {
            return .{
                .ctx = @ptrCast(self),
                .on_externalized = hookExternalized,
                .on_failed = hookFailed,
            };
        }

        fn recoveryHook(self: *Self) node.RecoveryHook {
            return .{ .ctx = @ptrCast(self), .on_recovered = hookRecovered };
        }

        fn hookRecovered(ctx: *anyopaque, view: node.RecoveryView) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            if (comptime @hasDecl(App, "initialSlot")) {
                if (!common.initialSlotCanStart(self.applied_hwm, view.journal_tail, self.start_slot)) {
                    self.recovery_rejection = view;
                    return error.InitialSlotOutsideJournal;
                }
                const journal_hwm = view.externalized_hwm orelse 0;
                if (self.applied_hwm > journal_hwm and !self.initial_command_present) {
                    self.initial_command_missing = true;
                    return error.InitialCommandMissing;
                }
            }
        }

        // ---- driver vtable (engine thread) ----

        fn driverValidate(ctx: *anyopaque, slot: u64, value: []const u8, is_nomination: bool) Validity {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const cmd = codec.decode(value) orelse return .invalid;
            return App.validate(&self.state, cmd, .{
                .slot = slot,
                .phase = if (is_nomination) .nomination else .ballot,
            });
        }

        fn driverCombine(ctx: *anyopaque, slot: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            if (candidates.len == 0) return error.DriverFault;
            if (comptime @hasDecl(App, "combine")) {
                // Sized by the candidate slice (never a fixed array).
                const cmds = try gpa.alloc(Command, candidates.len);
                defer gpa.free(cmds);
                var n: usize = 0;
                for (candidates) |c| {
                    if (codec.decode(c)) |cmd| {
                        cmds[n] = cmd;
                        n += 1;
                    }
                }
                if (n == 0) return error.DriverFault;
                const best = App.combine(&self.state, cmds[0..n]);
                // §8.5: the composite must self-validate. A `.invalid`
                // composite would be balloted by this node and rejected by
                // every peer — a silent stall with only `insane` counters as
                // evidence — so it is the contract violation DriverFault is
                // for (docs/determinism.md §6). `.maybe_valid` stays legal:
                // a node behind on State cannot judge what it combines.
                if (App.validate(&self.state, best, .{ .slot = slot, .phase = .ballot }) == .invalid) {
                    if (self.created.load(.acquire)) log.err(common.bad_composite_fmt, .{ @typeName(App), slot });
                    return error.DriverFault;
                }
                if (comptime codec.is_custom) {
                    // Ship the slice `encode` RETURNS (what `propose` sends),
                    // not a prefix of the scratch: an encoder may return a
                    // window of `buf` or static storage. Sized to the frozen
                    // cap like `propose`'s scratch.
                    const scratch = try gpa.alloc(u8, max_encoded_bytes);
                    defer gpa.free(scratch);
                    const written = codec.encode(best, scratch);
                    out.clearRetainingCapacity();
                    try out.appendSlice(gpa, written);
                } else {
                    try out.resize(gpa, codec.size);
                    const written = codec.encode(best, out.items);
                    std.debug.assert(written.len == codec.size);
                }
            } else {
                // §8.4 default: lexicographic max — numerically the largest
                // under the order-preserving auto-codec ("highest wins").
                var best = candidates[0];
                for (candidates[1..]) |c| {
                    if (std.mem.order(u8, c, best) == .gt) best = c;
                }
                try out.appendSlice(gpa, best);
            }
        }

        // ---- delivery hook (engine thread; creating thread during replay) ----

        fn hookExternalized(ctx: *anyopaque, slot: u64, value: []const u8) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const cmd = codec.decode(value) orelse {
                // §8.5's one fatal rule: bytes the network agreed on must
                // decode. Inside create this becomes the diagnostic; at
                // runtime the node halts loudly (the Node logs + latches).
                self.undecodable = .{ .slot = slot, .len = value.len };
                if (self.created.load(.acquire)) log.err(common.undecodable_fmt, .{ slot, value.len, @typeName(Command) });
                return error.UndecodableExternalizedValue;
            };
            if (slot <= self.applied_hwm) return; // re-delivery: no-op
            if (comptime @hasDecl(App, "initialSlot")) {
                const expected = std.math.add(u64, self.applied_hwm, 1) catch {
                    if (self.created.load(.acquire)) log.err(common.delivery_gap_fmt, .{ slot, self.applied_hwm, @typeName(App) });
                    return error.AppliedSlotGap;
                };
                if (slot != expected) {
                    if (self.created.load(.acquire)) log.err(common.delivery_gap_fmt, .{ slot, self.applied_hwm, @typeName(App) });
                    return error.AppliedSlotGap;
                }
            }
            App.apply(&self.state, cmd, self.gpa) catch |e| {
                // Only OutOfMemory can reach here (the signature forbids the
                // rest): the node latches inert; the partially applied state
                // is never consulted again and deinitState still frees it.
                self.apply_failed_slot = slot;
                if (self.created.load(.acquire)) log.err(apply_failed_fmt, .{ @typeName(App), slot });
                return e;
            };
            self.applied_hwm = slot;
            var obs = App.observe(&self.state, self.gpa) catch |e| {
                self.observe_failed_slot = slot;
                if (self.created.load(.acquire)) log.err(observe_failed_fmt, .{ @typeName(App), slot });
                return e;
            };
            self.mu.lockUncancelable(self.io);
            defer self.mu.unlock(self.io);
            if (self.closed) {
                // Nobody will ever take this observation; it must not leak.
                if (comptime obs_owns_memory) App.deinitObs(&obs, self.gpa);
                return;
            }
            self.queue.append(self.gpa, .{ .slot = slot, .obs = obs }) catch |e| {
                if (comptime obs_owns_memory) App.deinitObs(&obs, self.gpa);
                return e;
            };
            self.cond.signal(self.io);
        }

        fn hookFailed(ctx: *anyopaque, err: anyerror) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.mu.lockUncancelable(self.io);
            defer self.mu.unlock(self.io);
            if (self.halt_err == null) self.halt_err = err;
            self.closed = true;
            self.cond.broadcast(self.io);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const Quorum = core.quorum.Quorum;
const crypto = core.crypto;

/// A tmpDir-backed data_dir path (absolute) for one test.
const TestDir = struct {
    tmp: testing.TmpDir,
    buf: [std.fs.max_path_bytes]u8 = undefined,
    len: usize = 0,

    fn init() !TestDir {
        var d: TestDir = .{ .tmp = testing.tmpDir(.{}) };
        d.len = try d.tmp.dir.realPath(testing.io, &d.buf);
        return d;
    }
    fn path(self: *TestDir) []const u8 {
        return self.buf[0..self.len];
    }
    /// `<tmp>/<name>` into `out`.
    fn sub(self: *TestDir, out: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(out, "{s}/{s}", .{ self.path(), name });
    }
    fn deinit(self: *TestDir) void {
        self.tmp.cleanup();
    }
};

fn seedOf(byte: u8) [32]u8 {
    return @splat(byte);
}

fn loopbackSpec(buf: []u8, port: u16) ![]const u8 {
    return std.fmt.bufPrint(buf, "127.0.0.1:{d}", .{port});
}

// -- the heap applications -----------------------------------------------------

/// An unbounded append-only log: the whole state lives on the heap, the
/// observation is two words of plain data (nothing to free). `Context` seeds
/// a large initial state so tests can measure what the notification path
/// allocates per slot.
const HeapLog = struct {
    pub const State = struct {
        entries: std.ArrayListUnmanaged(u64) = .empty,
    };
    pub const Command = struct { x: u64 };
    pub const Obs = struct { count: u64, last: u64 };
    pub const Context = struct { seed_entries: usize = 0 };
    pub const InitError = error{OutOfMemory};

    pub fn initState(context: Context, gpa: std.mem.Allocator) InitError!State {
        var s: State = .{};
        errdefer s.entries.deinit(gpa);
        // Seed plus slack so the measured test appends never grow the list.
        try s.entries.ensureTotalCapacity(gpa, context.seed_entries + 64);
        s.entries.items.len = context.seed_entries;
        for (s.entries.items) |*e| e.* = 1;
        return s;
    }

    pub fn deinitState(state: *State, gpa: std.mem.Allocator) void {
        state.entries.deinit(gpa);
    }

    pub fn validate(state: *const State, cmd: Command, context: ValueContext) Validity {
        _ = state;
        _ = context;
        return if (cmd.x >= 1) .valid else .invalid;
    }

    pub fn apply(state: *State, cmd: Command, gpa: std.mem.Allocator) std.mem.Allocator.Error!void {
        try state.entries.append(gpa, cmd.x);
    }

    pub fn observe(state: *const State, gpa: std.mem.Allocator) std.mem.Allocator.Error!Obs {
        _ = gpa;
        const items = state.entries.items;
        return .{ .count = items.len, .last = if (items.len > 0) items[items.len - 1] else 0 };
    }
};
const HeapLogNode = OwnedAppNode(HeapLog);

/// The durable-snapshot app: `initialSlot` / `initialCommand` over a state
/// loaded from `Context.snapshot` bytes, and an observation that OWNS a deep
/// copy of the log (so `release` matters). Its snapshot writer runs on the
/// USER thread over an observation — the durable handoff without a global.
const HeapSnap = struct {
    pub const State = struct {
        slot: u64 = 0,
        entries: std.ArrayListUnmanaged(u64) = .empty,
    };
    pub const Command = struct { x: u64 };
    pub const Obs = struct { slot: u64, entries: []u64 };
    pub const Context = struct { snapshot: ?[]const u8 = null };
    pub const InitError = error{ OutOfMemory, SnapshotCorrupt };

    pub fn initState(context: Context, gpa: std.mem.Allocator) InitError!State {
        const bytes = context.snapshot orelse return .{};
        var s: State = .{};
        errdefer s.entries.deinit(gpa);
        if (bytes.len < 12) return error.SnapshotCorrupt;
        s.slot = std.mem.readInt(u64, bytes[0..8], .big);
        const n = std.mem.readInt(u32, bytes[8..12], .big);
        if (s.slot != n or bytes.len != 12 + @as(usize, n) * 8) return error.SnapshotCorrupt;
        try s.entries.ensureTotalCapacity(gpa, n);
        s.entries.items.len = n;
        for (0..n) |i| s.entries.items[i] = std.mem.readInt(u64, bytes[12 + i * 8 ..][0..8], .big);
        return s;
    }

    pub fn deinitState(state: *State, gpa: std.mem.Allocator) void {
        state.entries.deinit(gpa);
    }

    pub fn initialSlot(state: *const State) u64 {
        return state.slot;
    }

    pub fn initialCommand(state: *const State) ?Command {
        const items = state.entries.items;
        return if (items.len > 0) .{ .x = items[items.len - 1] } else null;
    }

    pub fn validate(state: *const State, cmd: Command, context: ValueContext) Validity {
        _ = state;
        _ = context;
        return if (cmd.x >= 1) .valid else .invalid;
    }

    pub fn apply(state: *State, cmd: Command, gpa: std.mem.Allocator) std.mem.Allocator.Error!void {
        try state.entries.append(gpa, cmd.x);
        state.slot += 1;
    }

    pub fn observe(state: *const State, gpa: std.mem.Allocator) std.mem.Allocator.Error!Obs {
        return .{ .slot = state.slot, .entries = try gpa.dupe(u64, state.entries.items) };
    }

    pub fn deinitObs(obs: *Obs, gpa: std.mem.Allocator) void {
        gpa.free(obs.entries);
    }

    /// The app-level snapshot writer a user thread runs over an observation.
    pub fn writeSnapshot(obs: Obs, gpa: std.mem.Allocator) error{OutOfMemory}![]u8 {
        const bytes = try gpa.alloc(u8, 12 + obs.entries.len * 8);
        std.mem.writeInt(u64, bytes[0..8], obs.slot, .big);
        std.mem.writeInt(u32, bytes[8..12], @intCast(obs.entries.len), .big);
        for (obs.entries, 0..) |e, i| std.mem.writeInt(u64, bytes[12 + i * 8 ..][0..8], e, .big);
        return bytes;
    }
};
const HeapSnapNode = OwnedAppNode(HeapSnap);

/// An app whose apply/observe fail OOM at a configured slot — the narrow
/// signature makes OOM the only expressible engine-thread failure.
const FailingApp = struct {
    pub const State = struct {
        slot: u64 = 0,
        fail_apply_at: u64 = 0,
        fail_observe_at: u64 = 0,
    };
    pub const Command = struct { x: u64 };
    pub const Obs = struct { slot: u64 };
    pub const Context = struct { fail_apply_at: u64 = 0, fail_observe_at: u64 = 0 };
    pub const InitError = error{OutOfMemory};

    pub fn initState(context: Context, gpa: std.mem.Allocator) InitError!State {
        _ = gpa;
        return .{ .fail_apply_at = context.fail_apply_at, .fail_observe_at = context.fail_observe_at };
    }

    pub fn deinitState(state: *State, gpa: std.mem.Allocator) void {
        _ = state;
        _ = gpa;
    }

    pub fn validate(state: *const State, cmd: Command, context: ValueContext) Validity {
        _ = state;
        _ = context;
        return if (cmd.x >= 1) .valid else .invalid;
    }

    pub fn apply(state: *State, cmd: Command, gpa: std.mem.Allocator) std.mem.Allocator.Error!void {
        _ = gpa;
        if (state.slot + 1 == state.fail_apply_at) return error.OutOfMemory;
        state.slot += 1;
        _ = cmd;
    }

    pub fn observe(state: *const State, gpa: std.mem.Allocator) std.mem.Allocator.Error!Obs {
        _ = gpa;
        if (state.slot == state.fail_observe_at) return error.OutOfMemory;
        return .{ .slot = state.slot };
    }
};
const FailingNode = OwnedAppNode(FailingApp);

/// A `combine` whose result never self-validates (x = 0): DriverFault, the
/// §8.5 composite rule, through the owned adapter.
const BadCombineOwned = struct {
    pub const State = HeapLog.State;
    pub const Command = HeapLog.Command;
    pub const Obs = HeapLog.Obs;
    pub const Context = HeapLog.Context;
    pub const InitError = HeapLog.InitError;
    pub const initState = HeapLog.initState;
    pub const deinitState = HeapLog.deinitState;
    pub const validate = HeapLog.validate;
    pub const apply = HeapLog.apply;
    pub const observe = HeapLog.observe;
    pub fn combine(state: *const State, cmds: []const Command) Command {
        _ = state;
        _ = cmds;
        return .{ .x = 0 };
    }
};

// -- contract / adapter shape --------------------------------------------------

// Non-vacuity: the ownership flag must follow the Obs shape (dropping the
// containsPointer walk flips both flags); the parity loop catches a mirror
// drift exactly like AppNode's; the @typeName pin keeps the snapshot path
// public.
test "owned contract acceptance: plain and owned observations, Options parity, public @typeName" {
    const LN = HeapLogNode;
    const SN = HeapSnapNode;
    try testing.expect(!LN.obs_owns_memory);
    try testing.expect(SN.obs_owns_memory);
    try testing.expectEqual(HeapLog.Command, LN.Command);
    try testing.expectEqual(HeapSnap.Obs, SN.Obs);
    try testing.expectEqual(@as(usize, 8), LN.codec.size);
    try testing.expect(!LN.codec.is_custom);
    try testing.expect(@hasField(LN.Options, "network"));
    try testing.expect(!@hasField(LN.Options, "driver"));
    try testing.expect(!@hasField(LN.Options, "delivery"));

    const src = @typeInfo(node.Options).@"struct";
    const dst = @typeInfo(LN.Options).@"struct";
    var expected: usize = 0;
    inline for (src.field_names, src.field_types, src.field_attrs) |name, FT, attr| {
        if (comptime common.isOwnedOptionField(name)) {
            try testing.expect(!@hasField(LN.Options, name));
        } else {
            expected += 1;
            try testing.expect(@hasField(LN.Options, name));
            const idx = comptime std.meta.fieldIndex(LN.Options, name).?;
            try testing.expect(dst.field_types[idx] == FT);
            const want = comptime attr.defaultValue(FT);
            const have = comptime dst.field_attrs[idx].defaultValue(FT);
            try testing.expect((want == null) == (have == null));
            if (want) |w| try testing.expect(std.meta.eql(w, have.?));
        }
    }
    try testing.expectEqual(expected, dst.field_names.len);

    // The mirror must reify under the public path, not the helper's
    // (the snapshot pins this spelling on the create line).
    try testing.expect(std.mem.indexOf(u8, @typeName(LN.Options), "OwnedAppNode(") != null);

    // release() is a no-op for plain data: the flag drives the routing.
}

// Non-vacuity: removing the `slot <= applied_hwm` guard queues duplicates;
// decoding after the guard mutates state on junk; skipping the `halt_err`
// check returns null instead of NodeHalted after the drain.
test "owned hook semantics without a Node: ascending applies, re-deliveries are no-ops, junk is UndecodableExternalizedValue, drain then NodeHalted" {
    const gpa = testing.allocator;
    const io = testing.io;
    const n = try HeapLogNode.createDetached(gpa, io, 4096, .{});
    defer n.deinit();
    const ctx: *anyopaque = @ptrCast(n);
    var buf: [8]u8 = undefined;
    const enc = struct {
        fn x(v: u64, b: *[8]u8) []const u8 {
            return HeapLogNode.codec.encode(.{ .x = v }, b);
        }
    };

    try HeapLogNode.hookExternalized(ctx, 1, enc.x(1, &buf));
    try HeapLogNode.hookExternalized(ctx, 2, enc.x(2, &buf));
    try testing.expectEqual(@as(usize, 2), n.state.entries.items.len);
    try testing.expectEqual(@as(u64, 2), n.applied_hwm);
    // Re-delivery (journal overlap) of 2 and of 1: no-ops.
    try HeapLogNode.hookExternalized(ctx, 2, enc.x(2, &buf));
    try HeapLogNode.hookExternalized(ctx, 1, enc.x(1, &buf));
    try testing.expectEqual(@as(usize, 2), n.state.entries.items.len);
    // Junk on the agreed stream: the one fatal rule, state untouched.
    try testing.expectError(error.UndecodableExternalizedValue, HeapLogNode.hookExternalized(ctx, 3, "junk"));
    try testing.expectEqual(@as(usize, 2), n.state.entries.items.len);
    try testing.expectEqual(@as(u64, 3), n.undecodable.?.slot);
    try testing.expect(n.haltError() == null);

    HeapLogNode.hookFailed(ctx, error.DiskFull);
    try testing.expectEqual(@as(?anyerror, error.DiskFull), n.haltError());
    const a1 = (try n.waitApplied(.{ .timeout_ms = null })).?;
    try testing.expectEqual(@as(u64, 1), a1.slot);
    try testing.expectEqual(@as(u64, 1), a1.obs.count);
    const a2 = (try n.waitApplied(.{ .timeout_ms = null })).?;
    try testing.expectEqual(@as(u64, 2), a2.slot);
    try testing.expectEqual(@as(u64, 2), a2.obs.count);
    try testing.expectEqual(@as(u64, 2), a2.obs.last);
    try testing.expectError(error.NodeHalted, n.waitApplied(.{ .timeout_ms = null }));
    try testing.expectError(error.NodeHalted, n.waitApplied(.{ .timeout_ms = 10 }));
}

// Non-vacuity: an apply that returns its error before mutating leaves the
// slot unobserved and `applied_hwm` put; returning success instead of the
// error queues a slot-2 observation.
test "owned apply OOM fails stop: the hook returns OutOfMemory, the slot is not applied, earlier items still drain" {
    const gpa = testing.allocator;
    const io = testing.io;
    const n = try FailingNode.createDetached(gpa, io, 4096, .{ .fail_apply_at = 2 });
    defer n.deinit();
    const ctx: *anyopaque = @ptrCast(n);
    var buf: [8]u8 = undefined;

    try FailingNode.hookExternalized(ctx, 1, FailingNode.codec.encode(.{ .x = 1 }, &buf));
    try testing.expectError(error.OutOfMemory, FailingNode.hookExternalized(ctx, 2, FailingNode.codec.encode(.{ .x = 2 }, &buf)));
    try testing.expectEqual(@as(u64, 1), n.applied_hwm);
    try testing.expectEqual(@as(?u64, 2), n.apply_failed_slot);
    try testing.expectEqual(@as(u64, 1), n.state.slot);
    const a1 = (try n.waitApplied(.{ .timeout_ms = 0 })).?;
    try testing.expectEqual(@as(u64, 1), a1.slot);
    try testing.expect((try n.waitApplied(.{ .timeout_ms = 0 })) == null);
}

// Non-vacuity: observe runs AFTER apply advances the state, so its failure
// leaves the value applied-but-unnotified — exactly the fail-stop split the
// delivery hook already latches on.
test "owned observe OOM: state advanced, no notification for that slot, earlier items still drain" {
    const gpa = testing.allocator;
    const io = testing.io;
    const n = try FailingNode.createDetached(gpa, io, 4096, .{ .fail_observe_at = 2 });
    defer n.deinit();
    const ctx: *anyopaque = @ptrCast(n);
    var buf: [8]u8 = undefined;

    try FailingNode.hookExternalized(ctx, 1, FailingNode.codec.encode(.{ .x = 1 }, &buf));
    try testing.expectError(error.OutOfMemory, FailingNode.hookExternalized(ctx, 2, FailingNode.codec.encode(.{ .x = 2 }, &buf)));
    try testing.expectEqual(@as(u64, 2), n.state.slot); // apply ran
    try testing.expectEqual(@as(u64, 2), n.applied_hwm); // the slot is accounted
    try testing.expectEqual(@as(?u64, 2), n.observe_failed_slot);
    const a1 = (try n.waitApplied(.{ .timeout_ms = 0 })).?;
    try testing.expectEqual(@as(u64, 1), a1.slot);
    try testing.expect((try n.waitApplied(.{ .timeout_ms = 0 })) == null);
}

// Non-vacuity: a per-slot deep copy of State (the AppNode notification path)
// would allocate 100 000 × 8 bytes per applied slot; the owned path queues a
// 16-byte Applied. The two warm-up slots absorb queue growth; the eight
// measured slots must allocate NOTHING (initState seeded 64 slots of slack).
test "owned notification path never copies State: applying over a 100k-entry heap state allocates nothing per slot" {
    var fa = testing.FailingAllocator.init(testing.allocator, .{});
    const gpa = fa.allocator();
    const io = testing.io;
    const n = try HeapLogNode.createDetached(gpa, io, 4096, .{ .seed_entries = 100_000 });
    defer n.deinit();
    const ctx: *anyopaque = @ptrCast(n);
    var buf: [8]u8 = undefined;

    var x: u64 = 1;
    for (0..9) |_| {
        try HeapLogNode.hookExternalized(ctx, x, HeapLogNode.codec.encode(.{ .x = x }, &buf));
        x += 1;
    }
    // Drain the nine warm-up observations so the queue holds its capacity.
    while (try n.waitApplied(.{ .timeout_ms = 0 })) |_| {}
    const before = fa.allocated_bytes;
    for (0..8) |_| {
        try HeapLogNode.hookExternalized(ctx, x, HeapLogNode.codec.encode(.{ .x = x }, &buf));
        x += 1;
    }
    try testing.expectEqual(before, fa.allocated_bytes);
    var last: HeapLogNode.Applied = undefined;
    var drained: usize = 0;
    while (try n.waitApplied(.{ .timeout_ms = 0 })) |item| {
        last = item;
        drained += 1;
    }
    try testing.expectEqual(@as(usize, 8), drained);
    try testing.expectEqual(@as(u64, 100_017), last.obs.count);
    try testing.expectEqual(@as(u64, 17), last.obs.last);
}

// Non-vacuity: handing back a borrowed view instead of a deep copy makes the
// slot-2 observation change (or dangle) once slots 3 and 4 mutate — and a
// list growth can also move the state's own buffer, so aliasing is caught
// even without a free.
test "owned observations are immune to later mutation: an owned Obs is a deep copy taken at apply time" {
    const gpa = testing.allocator;
    const io = testing.io;
    const n = try HeapSnapNode.createDetached(gpa, io, 4096, .{});
    defer n.deinit();
    const ctx: *anyopaque = @ptrCast(n);
    var buf: [8]u8 = undefined;
    const enc = struct {
        fn x(v: u64, b: *[8]u8) []const u8 {
            return HeapSnapNode.codec.encode(.{ .x = v }, b);
        }
    };

    // Apply all four; the later applies mutate (and grow) the state's own
    // buffer BEFORE the earlier observations are read back.
    try HeapSnapNode.hookExternalized(ctx, 1, enc.x(10, &buf));
    try HeapSnapNode.hookExternalized(ctx, 2, enc.x(20, &buf));
    try HeapSnapNode.hookExternalized(ctx, 3, enc.x(30, &buf));
    try HeapSnapNode.hookExternalized(ctx, 4, enc.x(40, &buf));

    const a1 = (try n.waitApplied(.{ .timeout_ms = 0 })).?;
    const a2 = (try n.waitApplied(.{ .timeout_ms = 0 })).?;
    const a3 = (try n.waitApplied(.{ .timeout_ms = 0 })).?;
    const a4 = (try n.waitApplied(.{ .timeout_ms = 0 })).?;
    try testing.expectEqual(@as(u64, 2), a2.obs.slot);
    try testing.expectEqual(@as(usize, 2), a2.obs.entries.len);
    try testing.expectEqualSlices(u64, &.{ 10, 20 }, a2.obs.entries);
    try testing.expectEqualSlices(u64, &.{ 10, 20, 30 }, a3.obs.entries);
    try testing.expectEqualSlices(u64, &.{ 10, 20, 30, 40 }, a4.obs.entries);
    try testing.expectEqualSlices(u64, &.{10}, a1.obs.entries);
    n.release(a1);
    n.release(a2);
    n.release(a3);
    n.release(a4);
}

// Non-vacuity: initState failing must leave nothing open — the failing
// create never reached Node.createWithRecovery, so the same data_dir opens
// cleanly afterwards (a leaked lock or identity file would fail the second
// create with DataDirBusy / DataDirOtherNode).
test "owned initState failure unwinds completely: AppInitFailed names the app error and nothing starts" {
    const gpa = testing.allocator;
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    const seed = seedOf(0x81);
    const me = try crypto.publicKeyFromSeed(seed);
    var diag: node.Diagnostic = .{};
    const opts = HeapSnapNode.Options{
        .network = "owned init failure v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = td.path(),
        .diagnostic = &diag,
    };

    try testing.expectError(error.AppInitFailed, HeapSnapNode.create(gpa, io, opts, .{ .snapshot = "junk" }));
    try testing.expect(std.mem.indexOf(u8, diag.message(), "HeapSnap.initState failed") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message(), "SnapshotCorrupt") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message(), "nothing was started") != null);

    // Nothing was opened: the same data_dir starts cleanly on a good context.
    const n = try HeapSnapNode.create(gpa, io, opts, .{});
    defer n.deinit();
    try testing.expectEqual(@as(u64, 0), n.applied_hwm);
}

// Non-vacuity: without the apply_failed_slot mapping the failure surfaces as
// the Node's generic EngineFailed text; without the unwind errdefers the
// partially replayed observations and state leak.
test "owned create maps replay apply and observe OOM to OutOfMemory naming the replayed slot" {
    const gpa = testing.allocator;
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    const seed = seedOf(0x82);
    const me = try crypto.publicKeyFromSeed(seed);
    var diag: node.Diagnostic = .{};
    const base = FailingNode.Options{
        .network = "owned replay oom v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = td.path(),
        .diagnostic = &diag,
    };

    // Journal one slot, then stop.
    {
        const n = try FailingNode.create(gpa, io, base, .{});
        defer n.deinit();
        try n.propose(.{ .x = 1 });
        const a = (try n.waitApplied(.{ .timeout_ms = 5_000 })) orelse return error.Timeout;
        try testing.expectEqual(@as(u64, 1), a.slot);
    }

    try testing.expectError(error.OutOfMemory, FailingNode.create(gpa, io, base, .{ .fail_apply_at = 1 }));
    try testing.expect(std.mem.indexOf(u8, diag.message(), "replaying journal slot 1") != null);

    try testing.expectError(error.OutOfMemory, FailingNode.create(gpa, io, base, .{ .fail_observe_at = 1 }));
    try testing.expect(std.mem.indexOf(u8, diag.message(), "replaying journal slot 1") != null);

    // A clean restart replays the tail through apply AND queues its
    // observations: the replayed slot is observable without any traffic.
    const n = try FailingNode.create(gpa, io, base, .{});
    defer n.deinit();
    const a = (try n.waitApplied(.{ .timeout_ms = 0 })) orelse return error.ReplayNotObserved;
    try testing.expectEqual(@as(u64, 1), a.slot);
    try testing.expectEqual(@as(u64, 1), a.obs.slot);
    try testing.expect((try n.waitApplied(.{ .timeout_ms = 0 })) == null);
}

// Non-vacuity: with the dedup floor absent (no initialSlot) the whole tail
// replays; skipping the replay queueing makes waitApplied sit empty after a
// restart while the journal plainly advanced.
test "owned plain restart: the journal tail replays through apply and its observations queue for waitApplied" {
    const gpa = testing.allocator;
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    const seed = seedOf(0x83);
    const me = try crypto.publicKeyFromSeed(seed);
    var diag: node.Diagnostic = .{};
    const opts = HeapLogNode.Options{
        .network = "owned plain restart v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = td.path(),
        .diagnostic = &diag,
    };

    {
        const n = try HeapLogNode.create(gpa, io, opts, .{});
        defer n.deinit();
        try n.propose(.{ .x = 7 });
        const a1 = (try n.waitApplied(.{ .timeout_ms = 5_000 })) orelse return error.Timeout;
        try testing.expectEqual(@as(u64, 1), a1.slot);
        try n.propose(.{ .x = 9 });
        const a2 = (try n.waitApplied(.{ .timeout_ms = 5_000 })) orelse return error.Timeout;
        try testing.expectEqual(@as(u64, 2), a2.slot);
        try testing.expectEqual(@as(u64, 9), a2.obs.last);
    }

    // Restart from genesis context: both journal slots replay (empty floor),
    // each producing one observation, then live traffic continues the log.
    const n = try HeapLogNode.create(gpa, io, opts, .{});
    defer n.deinit();
    const r1 = (try n.waitApplied(.{ .timeout_ms = 0 })) orelse return error.ReplayNotObserved;
    try testing.expectEqual(@as(u64, 1), r1.slot);
    try testing.expectEqual(@as(u64, 7), r1.obs.last);
    const r2 = (try n.waitApplied(.{ .timeout_ms = 0 })) orelse return error.ReplayNotObserved;
    try testing.expectEqual(@as(u64, 2), r2.slot);
    try testing.expectEqualSlices(u64, &.{ 7, 9 }, n.state.entries.items);

    try n.propose(.{ .x = 11 });
    const a3 = (try n.waitApplied(.{ .timeout_ms = 5_000 })) orelse return error.Timeout;
    try testing.expectEqual(@as(u64, 3), a3.slot);
    try testing.expectEqual(@as(u64, 11), a3.obs.last);
    try testing.expectEqual(@as(usize, 3), a3.obs.count);
}

/// The latest applied item per node after a pump; each is owned by the
/// caller and must be released through its node.
const PumpResult = struct { a: ?HeapSnapNode.Applied = null, b: ?HeapSnapNode.Applied = null };

/// Pump two HeapSnap nodes ("x = last + 1" after every applied slot) until
/// either applies `target`. Returns each node's latest item (never consumed
/// twice): older items are released by the pump; the returned ones belong to
/// the caller.
fn pumpSnap(a: *HeapSnapNode, b: *HeapSnapNode, target: u64, deadline_ms: u64) !PumpResult {
    var waited: u64 = 0;
    var res: PumpResult = .{};
    errdefer {
        if (res.a) |it| a.release(it);
        if (res.b) |it| b.release(it);
    }
    while (waited < deadline_ms) {
        if (try a.waitApplied(.{ .timeout_ms = 20 })) |item| {
            if (res.a) |old| a.release(old);
            res.a = item;
            if (item.slot < target) try a.propose(.{ .x = item.obs.entries[item.obs.entries.len - 1] + 1 });
        }
        if (try b.waitApplied(.{ .timeout_ms = 20 })) |item| {
            if (res.b) |old| b.release(old);
            res.b = item;
            if (item.slot < target) try b.propose(.{ .x = item.obs.entries[item.obs.entries.len - 1] + 1 });
        }
        if ((res.a != null and res.a.?.slot >= target) or (res.b != null and res.b.?.slot >= target))
            return res;
        waited += 40;
    }
    return error.PumpTimeout;
}

// Non-vacuity: this is the E1 "Gaps recorded by E1" item 1 made concrete —
// the snapshot reaches initState through the Context (no process global),
// the journal tail 1..3 is skipped (initialSlot floor), the first applied
// item after restart is slot 4, and the restarted node converges with its
// live peer on the exact four-entry log.
test "owned restart from a durable snapshot (2-of-2 loopback): Context carries the snapshot, initialSlot skips the tail, convergence" {
    const gpa = testing.allocator;
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    var dir_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var dir_b_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_a = try td.sub(&dir_a_buf, "a");
    const dir_b = try td.sub(&dir_b_buf, "b");
    const network = "owned-appnode restart v1";
    const seed_a = seedOf(0x84);
    const seed_b = seedOf(0x85);
    const ids = [2][32]u8{ try crypto.publicKeyFromSeed(seed_a), try crypto.publicKeyFromSeed(seed_b) };
    var diag: node.Diagnostic = .{};
    var spec_buf: [32]u8 = undefined;

    // Phase 1 — both nodes to slot 3. The snapshot is written on the user
    // thread from the final observation: either node's carries the same
    // log, because consensus applied the same values to both.
    var snapshot_bytes: []u8 = undefined;
    {
        const b = try HeapSnapNode.create(gpa, io, .{
            .network = network,
            .secret_seed = seed_b,
            .quorum = Quorum.of(2, &ids),
            .listen_port = 0,
            .data_dir = dir_b,
            .diagnostic = &diag,
        }, .{});
        defer b.deinit();
        const a = try HeapSnapNode.create(gpa, io, .{
            .network = network,
            .secret_seed = seed_a,
            .quorum = Quorum.of(2, &ids),
            .listen_port = 0,
            .peers = &.{try loopbackSpec(&spec_buf, b.raw().boundPort())},
            .data_dir = dir_a,
            .diagnostic = &diag,
        }, .{});
        defer a.deinit();

        try a.propose(.{ .x = 10 });
        try b.propose(.{ .x = 11 });
        const r3 = try pumpSnap(a, b, 3, 90_000);
        defer {
            if (r3.a) |it| a.release(it);
            if (r3.b) |it| b.release(it);
        }
        // Either observation carries the same log: consensus applied the
        // same values to both nodes. The pump returns when EITHER node
        // reached the target, so prefer a's item only when it did.
        const final = if (r3.a != null and r3.a.?.slot >= 3) r3.a.? else r3.b.?;
        snapshot_bytes = try HeapSnap.writeSnapshot(final.obs, gpa);
    }
    defer gpa.free(snapshot_bytes);

    // Phase 2 — restart a from the snapshot context. The journal tail (1..3)
    // is skipped: no observation queues, and the first live item is slot 4
    // with the exact four-entry log.
    const b2 = try HeapSnapNode.create(gpa, io, .{
        .network = network,
        .secret_seed = seed_b,
        .quorum = Quorum.of(2, &ids),
        .listen_port = 0,
        .data_dir = dir_b,
        .diagnostic = &diag,
    }, .{});
    defer b2.deinit();
    const a2 = try HeapSnapNode.create(gpa, io, .{
        .network = network,
        .secret_seed = seed_a,
        .quorum = Quorum.of(2, &ids),
        .listen_port = 0,
        .peers = &.{try loopbackSpec(&spec_buf, b2.raw().boundPort())},
        .data_dir = dir_a,
        .diagnostic = &diag,
    }, .{ .snapshot = snapshot_bytes });
    defer a2.deinit();
    try testing.expect((try a2.waitApplied(.{ .timeout_ms = 0 })) == null); // tail skipped
    try testing.expectEqual(@as(u64, 3), a2.applied_hwm);

    try a2.propose(.{ .x = 40 });
    try b2.propose(.{ .x = 41 });
    const r4 = try pumpSnap(a2, b2, 4, 90_000);
    // r4.b's observation moves into `b4` below, so only r4.a is released
    // here — copying an owned Obs out and releasing both paths is exactly
    // the double free the ownership rules warn about.
    defer if (r4.a) |it| a2.release(it);
    const a4 = r4.a orelse return error.NodeNeverAppliedSlot4;
    try testing.expectEqual(@as(u64, 4), a4.slot);
    try testing.expectEqual(@as(u64, 4), a4.obs.slot);
    try testing.expectEqual(@as(usize, 4), a4.obs.entries.len);

    // b2 restarted from genesis context, so create replayed its whole tail
    // (1..3) into its queue and slot 4 is its first live item; if the pump
    // returned on a2 first, wait for b2's own slot 4, then compare logs.
    var b4 = r4.b;
    var waited: u64 = 0;
    while ((b4 == null or b4.?.slot < 4) and waited < 30_000) : (waited += 50) {
        if (try b2.waitApplied(.{ .timeout_ms = 50 })) |item| {
            if (b4) |old| b2.release(old);
            b4 = item;
        }
    }
    const got = b4 orelse return error.PeerNeverAppliedSlot4;
    defer b2.release(got);
    try testing.expect(got.slot >= 4);
    try testing.expectEqualSlices(u64, a4.obs.entries, got.obs.entries);
    try testing.expect(a2.haltError() == null);
    try testing.expect(b2.haltError() == null);
}

// Non-vacuity: the exact-successor arm — start_slot must be H+1 and the
// predecessor value seeds nomination (raw().last_ext_value); H+2 is refused
// with the teaching text.
test "owned app starts from a verified external checkpoint at its exact successor" {
    const gpa = testing.allocator;
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    const seed = seedOf(0x86);
    const me = try crypto.publicKeyFromSeed(seed);
    var diag: node.Diagnostic = .{};
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;

    // A "verified checkpoint through slot 200" with a known last value.
    const entries = try gpa.alloc(u64, 200);
    defer gpa.free(entries);
    for (entries, 0..) |*e, i| e.* = @intCast(i + 1);
    const snapshot = try HeapSnap.writeSnapshot(.{ .slot = 200, .entries = entries }, gpa);
    defer gpa.free(snapshot);

    const opts = HeapSnapNode.Options{
        .network = "owned external checkpoint v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = try td.sub(&path_buf, "skip"),
        .start_slot = 202,
        .diagnostic = &diag,
    };
    try testing.expectError(error.InitialSlotOutsideJournal, HeapSnapNode.create(gpa, io, opts, .{ .snapshot = snapshot }));
    try testing.expect(std.mem.indexOf(u8, diag.message(), "start_slot = 201") != null);

    const n = try HeapSnapNode.create(gpa, io, .{
        .network = "owned external checkpoint v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = try td.sub(&path_buf, "exact"),
        .start_slot = 201,
        .diagnostic = &diag,
    }, .{ .snapshot = snapshot });
    defer n.deinit();

    var prev_buf: [HeapSnapNode.codec.size]u8 = undefined;
    try testing.expectEqualSlices(u8, HeapSnapNode.codec.encode(.{ .x = 200 }, &prev_buf), n.raw().last_ext_value);
    try n.propose(.{ .x = 201 });
    const a = (try n.waitApplied(.{ .timeout_ms = 5_000 })) orelse return error.Timeout;
    defer n.release(a);
    try testing.expectEqual(@as(u64, 201), a.slot);
    try testing.expectEqual(@as(usize, 201), a.obs.entries.len);
    try testing.expectEqual(@as(u64, 201), a.obs.entries[200]);
}

// Non-vacuity: without releaseQueued in deinit the three unowned-slot
// observations (each a heap clone) leak; the parked-waiter half pins the
// same drain ordering AppNode has.
test "owned deinit frees unconsumed owned observations and a parked waiter exits" {
    const gpa = testing.allocator;
    const io = testing.io;
    const n = try HeapSnapNode.createDetached(gpa, io, 4096, .{});
    const ctx: *anyopaque = @ptrCast(n);
    var buf: [8]u8 = undefined;
    var slot: u64 = 1;
    while (slot <= 3) : (slot += 1) {
        try HeapSnapNode.hookExternalized(ctx, slot, HeapSnapNode.codec.encode(.{ .x = slot }, &buf));
    }
    // Nobody consumes them: deinit owns all three.
    n.deinit();

    const m = try HeapSnapNode.createDetached(gpa, io, 4096, .{});
    var w: DeinitWaiter = .{ .n = m };
    const t = try std.Thread.spawn(.{}, DeinitWaiter.run, .{&w});
    try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(20), .awake);
    m.deinit();
    var waited_ms: u64 = 0;
    while (!w.done.load(.acquire) and waited_ms < 2000) : (waited_ms += 10) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake);
    }
    if (!w.done.load(.acquire)) return error.WaiterHungAfterDeinit;
    t.join();
    try testing.expect(w.saw_null.load(.acquire));
}

const DeinitWaiter = struct {
    n: *HeapSnapNode,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    saw_null: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(self: *DeinitWaiter) void {
        const item = self.n.waitApplied(.{ .timeout_ms = null }) catch null;
        if (item == null) self.saw_null.store(true, .release);
        self.done.store(true, .release);
    }
};

// Non-vacuity: skipping App.validate in driverValidate fails the verdict
// arms; a combine whose composite self-validates .invalid must be
// DriverFault (the §8.5 rule through the owned path).
test "owned driver: validate reaches all verdicts, junk is invalid, default combine is max, invalid composite is DriverFault" {
    const gpa = testing.allocator;
    const io = testing.io;
    const n = try HeapLogNode.createDetached(gpa, io, 4096, .{});
    defer n.deinit();
    const d = n.driver();
    var buf: [8]u8 = undefined;

    try testing.expectEqual(Validity.valid, d.validate_value(d.ctx, 1, HeapLogNode.codec.encode(.{ .x = 1 }, &buf), true));
    try testing.expectEqual(Validity.invalid, d.validate_value(d.ctx, 1, HeapLogNode.codec.encode(.{ .x = 0 }, &buf), false));
    try testing.expectEqual(Validity.invalid, d.validate_value(d.ctx, 1, "junk", true));

    var cands: [3][8]u8 = undefined;
    const cand_slices = [_][]const u8{
        HeapLogNode.codec.encode(.{ .x = 5 }, &cands[0]),
        HeapLogNode.codec.encode(.{ .x = 9 }, &cands[1]),
        HeapLogNode.codec.encode(.{ .x = 7 }, &cands[2]),
    };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try d.combine_candidates(d.ctx, 1, &cand_slices, gpa, &out);
    try testing.expectEqual(@as(u64, 9), HeapLogNode.codec.decode(out.items).?.x);
    out.clearRetainingCapacity();
    try testing.expectError(error.DriverFault, d.combine_candidates(d.ctx, 1, &.{}, gpa, &out));

    const bad = try OwnedAppNode(BadCombineOwned).createDetached(gpa, io, 4096, .{});
    defer bad.deinit();
    const bd = bad.driver();
    out.clearRetainingCapacity();
    try testing.expectError(error.DriverFault, bd.combine_candidates(bd.ctx, 1, &cand_slices, gpa, &out));
}

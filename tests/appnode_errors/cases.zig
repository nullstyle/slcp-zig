//! The appnode-errors case table: ONE source of truth for every teaching
//! `@compileError` in src/node/app_node.zig.
//!
//! build.zig imports it to build one expected-fail object per row
//! (`tests/appnode_errors/<stem>.zig` with `expect_errors = .{ .contains =
//! needle }`), and tools/docs_smoke.zig's "appnode-errors liveness" test
//! imports it to check the table against the SOURCE: every `src` fragment
//! must appear verbatim in app_node.zig, and the number of teaching-error
//! sites there (`contract_site` + `codec_site` occurrences) must equal
//! `cases.len`. Without the second half another rule could land with no
//! expected-fail object and `zig build test` would stay green (S8 review).
//!
//! `needle` is the TAIL of the compile error's first line after the `<T>` /
//! `<path>` rendering (RELEASING.md "Cold preflight"):
//! `matchCompileError` tries endsWith first,
//! so it holds from any cwd. `src` is a fragment of the message as SPELLED in
//! app_node.zig — the two differ where the message splices a type name or a
//! field name in. Change a message, its needle and its src together.

pub const Case = struct {
    /// tests/appnode_errors/<stem>.zig
    stem: []const u8,
    /// Tail of the emitted error's first line (expect_errors needle).
    needle: []const u8,
    /// Verbatim fragment of the message text in src/node/app_node.zig.
    src: []const u8,
};

/// Every AppNode contract error is raised through `contractError(App, "…")`.
pub const contract_site = "contractError(App, \"";
/// Every auto-codec error starts with this literal (the sized-cap one via
/// `comptimePrint`, which still spells the prefix).
pub const codec_site = "\"slcp auto-codec: ";

pub const cases = [_]Case{
    .{ .stem = "err_missing_state", .needle = "): missing `pub const State` — the replicated state type.", .src = "missing `pub const State` — the replicated state type." },
    .{ .stem = "err_missing_command", .needle = "): missing `pub const Command` — the value type the network agrees on.", .src = "missing `pub const Command` — the value type the network agrees on." },
    .{ .stem = "err_missing_validate", .needle = "): missing `pub fn validate(state: State, cmd: Command) slcp.Validity`.", .src = "missing `pub fn validate(state: State, cmd: Command) slcp.Validity`." },
    .{ .stem = "err_bad_validate_signature", .needle = "): validate has the wrong signature.", .src = "validate has the wrong signature." },
    .{ .stem = "err_bad_validate_context_signature", .needle = "): validate context has the wrong signature.", .src = "validate context has the wrong signature." },
    .{ .stem = "err_missing_apply", .needle = "): missing `pub fn apply(state: State, cmd: Command) State`.", .src = "missing `pub fn apply(state: State, cmd: Command) State`." },
    .{ .stem = "err_bad_apply_signature", .needle = "): apply has the wrong signature.", .src = "apply has the wrong signature." },
    .{ .stem = "err_bad_combine_signature", .needle = "): combine has the wrong signature.", .src = "combine has the wrong signature." },
    .{ .stem = "err_bad_initial_state_signature", .needle = "): initialState has the wrong signature.", .src = "initialState has the wrong signature." },
    .{ .stem = "err_bad_initial_slot_signature", .needle = "): initialSlot has the wrong signature.", .src = "initialSlot has the wrong signature." },
    .{ .stem = "err_initial_command_without_slot", .needle = "): initialCommand requires initialSlot.", .src = "initialCommand requires initialSlot." },
    .{ .stem = "err_bad_initial_command_signature", .needle = "): initialCommand has the wrong signature.", .src = "initialCommand has the wrong signature." },
    .{ .stem = "err_lone_encode", .needle = "): a custom codec needs BOTH `pub fn encode(cmd: Command, buf: []u8) []u8` and `pub fn decode(bytes: []const u8) ?Command`.", .src = "a custom codec needs BOTH `pub fn encode(cmd: Command, buf: []u8) []u8` and `pub fn decode(bytes: []const u8) ?Command`." },
    .{ .stem = "err_bad_encode_signature", .needle = "): encode has the wrong signature.", .src = "encode has the wrong signature." },
    .{ .stem = "err_bad_decode_signature", .needle = "): decode has the wrong signature.", .src = "decode has the wrong signature." },
    .{ .stem = "err_no_default", .needle = "): State field `owner` has no default value.", .src = "` has no default value." },
    .{ .stem = "err_float_command", .needle = " — floats are NONDETERMINISTIC across nodes (NaN payloads, ±0, platform math differences).", .src = " — floats are NONDETERMINISTIC across nodes (NaN payloads, ±0, platform math differences)." },
    .{ .stem = "err_pointer_command", .needle = " is a pointer/slice ([]const u8).", .src = "` is a pointer/slice (" },
    .{ .stem = "err_optional_command", .needle = " is optional (?u8).", .src = "` is optional (" },
    .{ .stem = "err_union_command", .needle = ") — the v1 auto-codec does not encode unions.", .src = ") — the v1 auto-codec does not encode unions." },
    .{ .stem = "err_nonexhaustive_enum", .needle = ") — `_` admits every tag value, so there is no single canonical spelling; make the enum exhaustive.", .src = ") — `_` admits every tag value, so there is no single canonical spelling; make the enum exhaustive." },
    .{ .stem = "err_unsupported_type", .needle = ", which the auto-codec does not cover. Provide your own encode/decode.", .src = ", which the auto-codec does not cover. Provide your own encode/decode." },
    .{ .stem = "err_zero_size_command", .needle = " encodes to 0 bytes; the engine rejects empty values (§8.4) — add a field.", .src = " encodes to 0 bytes; the engine rejects empty values (§8.4) — add a field." },
    .{ .stem = "err_oversized_command", .needle = " bytes, above the frozen 65536-byte value cap (§4.5).", .src = " bytes, above the frozen {d}-byte value cap (§4.5)." },
    .{ .stem = "err_wide_int", .needle = ") is wider than 65528 bits, the widest whole-byte integer the auto-codec can encode.", .src = ") is wider than 65528 bits, the widest whole-byte integer the auto-codec can encode." },
    .{ .stem = "err_comptime_field", .needle = "` is a comptime field — it has one fixed value and no wire representation.", .src = "` is a comptime field — it has one fixed value and no wire representation." },
};

/// Every OwnedAppNode contract error is raised through the same
/// `contractError(App, "…")` site marker, in src/node/owned_app_node.zig.
/// The auto-codec's own rejections fire from app_node.zig's `Codec(T)` and
/// stay pinned by the rows above.
pub const owned_contract_site = "contractError(App, \"";

/// One row per `contractError` site in src/node/owned_app_node.zig.
pub const owned_cases = [_]Case{
    .{ .stem = "owned_err_missing_state", .needle = "): missing `pub const State` — the owned replicated state type.", .src = "missing `pub const State` — the owned replicated state type." },
    .{ .stem = "owned_err_missing_command", .needle = "): missing `pub const Command` — the value type the network agrees on.", .src = "missing `pub const Command` — the value type the network agrees on." },
    .{ .stem = "owned_err_missing_obs", .needle = "): missing `pub const Obs` — the per-slot observation type.", .src = "missing `pub const Obs` — the per-slot observation type." },
    .{ .stem = "owned_err_missing_context", .needle = "): missing `pub const Context` — the startup context type.", .src = "missing `pub const Context` — the startup context type." },
    .{ .stem = "owned_err_missing_init_error", .needle = "): missing `pub const InitError` — the explicit error set initState returns.", .src = "missing `pub const InitError` — the explicit error set initState returns." },
    .{ .stem = "owned_err_missing_init_state", .needle = "): missing `pub fn initState(context: Context, gpa: std.mem.Allocator) InitError!State`.", .src = "missing `pub fn initState(context: Context, gpa: std.mem.Allocator) InitError!State`." },
    .{ .stem = "owned_err_bad_init_state", .needle = "): initState has the wrong signature.", .src = "initState has the wrong signature." },
    .{ .stem = "owned_err_missing_deinit_state", .needle = "): missing `pub fn deinitState(state: *State, gpa: std.mem.Allocator) void`.", .src = "missing `pub fn deinitState(state: *State, gpa: std.mem.Allocator) void`." },
    .{ .stem = "owned_err_bad_deinit_state", .needle = "): deinitState has the wrong signature.", .src = "deinitState has the wrong signature." },
    .{ .stem = "owned_err_missing_validate", .needle = "): missing `pub fn validate(state: *const State, cmd: Command, context: slcp.ValueContext) slcp.Validity`.", .src = "missing `pub fn validate(state: *const State, cmd: Command, context: slcp.ValueContext) slcp.Validity`." },
    .{ .stem = "owned_err_bad_validate", .needle = "): validate has the wrong signature.", .src = "validate has the wrong signature." },
    .{ .stem = "owned_err_missing_apply", .needle = "): missing `pub fn apply(state: *State, cmd: Command, gpa: std.mem.Allocator) std.mem.Allocator.Error!void`.", .src = "missing `pub fn apply(state: *State, cmd: Command, gpa: std.mem.Allocator) std.mem.Allocator.Error!void`." },
    .{ .stem = "owned_err_bad_apply", .needle = "): apply has the wrong signature.", .src = "apply has the wrong signature." },
    .{ .stem = "owned_err_missing_observe", .needle = "): missing `pub fn observe(state: *const State, gpa: std.mem.Allocator) std.mem.Allocator.Error!Obs`.", .src = "missing `pub fn observe(state: *const State, gpa: std.mem.Allocator) std.mem.Allocator.Error!Obs`." },
    .{ .stem = "owned_err_bad_observe", .needle = "): observe has the wrong signature.", .src = "observe has the wrong signature." },
    .{ .stem = "owned_err_obs_owns_no_deinit", .needle = "): Obs owns memory (it contains a pointer) but has no deinitObs.", .src = "Obs owns memory (it contains a pointer) but has no deinitObs." },
    .{ .stem = "owned_err_bad_deinit_obs", .needle = "): deinitObs has the wrong signature.", .src = "deinitObs has the wrong signature." },
    .{ .stem = "owned_err_deinit_obs_plain", .needle = "): deinitObs is declared, but Obs is plain by-value data — there is nothing to free.", .src = "deinitObs is declared, but Obs is plain by-value data — there is nothing to free." },
    .{ .stem = "owned_err_bad_combine", .needle = "): combine has the wrong signature.", .src = "combine has the wrong signature." },
    .{ .stem = "owned_err_bad_initial_slot", .needle = "): initialSlot has the wrong signature.", .src = "initialSlot has the wrong signature." },
    .{ .stem = "owned_err_initial_command_without_slot", .needle = "): initialCommand requires initialSlot.", .src = "initialCommand requires initialSlot." },
    .{ .stem = "owned_err_bad_initial_command", .needle = "): initialCommand has the wrong signature.", .src = "initialCommand has the wrong signature." },
    .{ .stem = "owned_err_lone_encode", .needle = "): a custom codec needs BOTH `pub fn encode(cmd: Command, buf: []u8) []u8` and `pub fn decode(bytes: []const u8) ?Command`.", .src = "a custom codec needs BOTH `pub fn encode(cmd: Command, buf: []u8) []u8` and `pub fn decode(bytes: []const u8) ?Command`." },
    .{ .stem = "owned_err_bad_encode", .needle = "): encode has the wrong signature.", .src = "encode has the wrong signature." },
    .{ .stem = "owned_err_bad_decode", .needle = "): decode has the wrong signature.", .src = "decode has the wrong signature." },
};

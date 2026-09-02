//! The appnode-errors case table: ONE source of truth for every teaching
//! `@compileError` in src/node/app_node.zig.
//!
//! build.zig imports it to build one expected-fail object per row
//! (`tests/appnode_errors/<stem>.zig` with `expect_errors = .{ .contains =
//! needle }`), and tools/docs_smoke.zig's "appnode-errors liveness" test
//! imports it to check the table against the SOURCE: every `src` fragment
//! must appear verbatim in app_node.zig, and the number of teaching-error
//! sites there (`contract_site` + `codec_site` occurrences) must equal
//! `cases.len`. Without the second half a 21st rule could land with no
//! expected-fail object and `zig build test` would stay green (S8 review).
//!
//! `needle` is the TAIL of the compile error's first line after the `<T>` /
//! `<path>` rendering (HANDOFF §6): `matchCompileError` tries endsWith first,
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
    .{ .stem = "err_missing_apply", .needle = "): missing `pub fn apply(state: State, cmd: Command) State`.", .src = "missing `pub fn apply(state: State, cmd: Command) State`." },
    .{ .stem = "err_bad_apply_signature", .needle = "): apply has the wrong signature.", .src = "apply has the wrong signature." },
    .{ .stem = "err_bad_combine_signature", .needle = "): combine has the wrong signature.", .src = "combine has the wrong signature." },
    .{ .stem = "err_bad_initial_state_signature", .needle = "): initialState has the wrong signature.", .src = "initialState has the wrong signature." },
    .{ .stem = "err_bad_initial_slot_signature", .needle = "): initialSlot has the wrong signature.", .src = "initialSlot has the wrong signature." },
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
};

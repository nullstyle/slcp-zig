//! WASM host-ABI conformance suite, part 1: the §7.2 contract exercised
//! WITHOUT a wasm runtime, so it runs in plain `zig build test`.
//!
//! Why this file exists in this shape
//! ----------------------------------
//! `src/wasm/slcp_host_abi.zig` cannot be compiled for a native target: its
//! allocator is `std.heap.wasm_allocator`, which is a `@compileError` off
//! wasm (`WasmAllocator` needs `single_threaded`, and its `BrkAllocator`
//! backing needs an sbrk-like primitive that darwin/most natives lack).
//! `export fn` decls are always analyzed, so merely `@import`-ing the module
//! natively fails to compile — see the report in tests/abi/ for the one-line
//! change that would lift this. So this suite proves the contract two ways:
//!
//!   A. SOURCE-PINNED facts — the frozen numeric/name surface (§7.2 version +
//!      feature words, the 23 exports, the 3 §7.3 imports, the ErrorCode
//!      table, the `errorFor` mapping arms). Parsed out of the ABI source at
//!      test time, so a change to the frozen surface fails the build rather
//!      than silently shipping.
//!   B. RE-DERIVED behavior — every ABI code path that is pure logic is run
//!      natively against the SAME slcp-core entry points the exports call
//!      (host_codec, engine.Engine/EffectQueue, qset). Where the ABI has a
//!      private helper (`decodeNormalizedQset`) or an unreachable-from-native
//!      pub (`encodeLint`), this file carries a MIRROR marked as such; the
//!      mirror's *bytes* are what the wasm differential harness pins.
//!
//! Clause map lives in the report; each test names its clause in its title.

const std = @import("std");
const slcp = @import("slcp-core");

const capnpc = slcp.capnpc;
const crypto = slcp.crypto;
const driver_mod = slcp.driver;
const engine = slcp.engine;
const gen_host = slcp.gen.host;
const gen_slcp = slcp.gen.slcp;
const host_codec = slcp.host_codec;
const qset = slcp.qset;

const Message = capnpc.message.Message;
const MessageBuilder = capnpc.message.MessageBuilder;
const testing = std.testing;

const abi_source_path = "src/wasm/slcp_host_abi.zig";

// ---------------------------------------------------------------------------
// A. Source-pinned surface (§7.2 / §7.3)
//
// The ABI module is not natively compilable (see module docs), so its frozen
// scalar surface is read out of the source instead of `@import`ed. Tests skip
// when the file is absent (out-of-tree runs), never silently pass.
// ---------------------------------------------------------------------------

fn abiSource(gpa: std.mem.Allocator) ![]u8 {
    const io = std.testing.io;
    return std.Io.Dir.cwd().readFileAlloc(io, abi_source_path, gpa, .unlimited) catch
        return error.SkipZigTest;
}

/// Value of `pub const <name>: <type> = <int literal>;`. Accepts any Zig
/// integer literal base (parseInt base 0) including `0b101`.
fn constInt(src: []const u8, comptime name: []const u8) !u64 {
    const needle = "pub const " ++ name ++ ":";
    const at = std.mem.indexOf(u8, src, needle) orelse return error.ConstNotFound;
    const rest = src[at + needle.len ..];
    const eq = std.mem.indexOfScalar(u8, rest, '=') orelse return error.ConstNotFound;
    const semi = std.mem.indexOfScalar(u8, rest, ';') orelse return error.ConstNotFound;
    const lit = std.mem.trim(u8, rest[eq + 1 .. semi], " \t\r\n");
    return std.fmt.parseInt(u64, lit, 0);
}

/// Every identifier introduced by `<prefix>fn <ident>(`, in source order.
fn declNames(gpa: std.mem.Allocator, src: []const u8, prefix: []const u8) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, src, i, prefix)) |at| {
        const rest = src[at + prefix.len ..];
        const paren = std.mem.indexOfScalar(u8, rest, '(') orelse break;
        try out.append(gpa, std.mem.trim(u8, rest[0..paren], " \t"));
        i = at + prefix.len;
    }
    return out.toOwnedSlice(gpa);
}

fn expectContainsName(names: []const []const u8, want: []const u8) !void {
    for (names) |n| {
        if (std.mem.eql(u8, n, want)) return;
    }
    std.debug.print("missing declaration: {s}\n", .{want});
    return error.MissingDeclaration;
}

// §7.2 — the frozen export list, verbatim, in source order. NOTE: this is 23
// entries; the M4 brief says "22 exports", which undercounts by one (the
// alloc/free/buf_free trio reads as two items). The source is the authority.
const frozen_exports = [_][]const u8{
    "slcp_alloc",
    "slcp_free",
    "slcp_buf_free",
    "slcp_abi_version",
    "slcp_abi_min_version",
    "slcp_abi_max_version",
    "slcp_feature_flags_lo",
    "slcp_feature_flags_hi",
    "slcp_version_string",
    "slcp_last_error_code",
    "slcp_last_error_ptr",
    "slcp_last_error_len",
    "slcp_clear_error",
    "slcp_error_take",
    "slcp_engine_new",
    "slcp_engine_free",
    "slcp_engine_push_input",
    "slcp_engine_pop_effect",
    "slcp_engine_pop_commit",
    "slcp_engine_effect_count",
    "slcp_engine_effect_bytes",
    "slcp_qset_hash",
    "slcp_lint_qset",
};

// §7.3 — exactly three imports from module "slcp_driver".
const frozen_imports = [_][]const u8{
    "validate_value",
    "combine_candidates",
    "extract_valid_value",
};

test "§7.2 version negotiation: abi_version=1, min<=version<=max" {
    const gpa = testing.allocator;
    const src = try abiSource(gpa);
    defer gpa.free(src);

    const v = try constInt(src, "abi_version");
    const lo = try constInt(src, "abi_min_version");
    const hi = try constInt(src, "abi_max_version");

    try testing.expectEqual(@as(u64, 1), v);
    try testing.expectEqual(@as(u64, 1), lo);
    try testing.expectEqual(@as(u64, 1), hi);
    try testing.expect(lo <= v and v <= hi);
}

test "§7.2 feature flags: bit0 set (driver imports), bit1 clear (no external_signer), bit2 set (lint)" {
    const gpa = testing.allocator;
    const src = try abiSource(gpa);
    defer gpa.free(src);

    const flags = try constInt(src, "feature_flags");
    try testing.expectEqual(@as(u64, 0b101), flags);
    try testing.expect(flags & (1 << 0) != 0); // driver imports required (§7.3)
    try testing.expect(flags & (1 << 1) == 0); // external_signer absent in v1 (§6)
    try testing.expect(flags & (1 << 2) != 0); // lint exports present (§12)

    // The lo/hi split the two exports perform is lossless.
    const flo: u32 = @truncate(flags);
    const fhi: u32 = @truncate(flags >> 32);
    try testing.expectEqual(@as(u32, 0b101), flo);
    try testing.expectEqual(@as(u32, 0), fhi);
    try testing.expectEqual(flags, (@as(u64, fhi) << 32) | flo);
}

test "§7.2 export surface is frozen: exactly these 23 exports, no more" {
    const gpa = testing.allocator;
    const src = try abiSource(gpa);
    defer gpa.free(src);

    const names = try declNames(gpa, src, "export fn ");
    defer gpa.free(names);

    try testing.expectEqual(frozen_exports.len, names.len);
    for (frozen_exports) |want| try expectContainsName(names, want);
}

test "§7.3 import surface is frozen: exactly 3 imports from module slcp_driver" {
    const gpa = testing.allocator;
    const src = try abiSource(gpa);
    defer gpa.free(src);

    const names = try declNames(gpa, src, "extern \"slcp_driver\" fn ");
    defer gpa.free(names);

    try testing.expectEqual(frozen_imports.len, names.len);
    for (frozen_imports) |want| try expectContainsName(names, want);

    // No other extern module may sneak in: every `extern "..."` is slcp_driver.
    var i: usize = 0;
    var total_externs: usize = 0;
    while (std.mem.indexOfPos(u8, src, i, "extern \"")) |at| {
        total_externs += 1;
        i = at + 8;
    }
    try testing.expectEqual(frozen_imports.len, total_externs);
}

test "§7.2 ErrorCode table is stable and distinct" {
    const gpa = testing.allocator;
    const src = try abiSource(gpa);
    defer gpa.free(src);

    const head = "pub const ErrorCode = enum(u32) {";
    const at = std.mem.indexOf(u8, src, head) orelse return error.ConstNotFound;
    const body_start = at + head.len;
    const body_end = body_start + (std.mem.indexOfScalar(u8, src[body_start..], '}') orelse
        return error.ConstNotFound);
    const body = src[body_start..body_end];

    const table = [_]struct { name: []const u8, code: u32 }{
        .{ .name = "none", .code = 0 },
        .{ .name = "out_of_memory", .code = 1 },
        .{ .name = "bad_handle", .code = 2 },
        .{ .name = "decode_failed", .code = 3 },
        .{ .name = "engine_failed", .code = 4 },
        .{ .name = "invalid_config", .code = 5 },
        .{ .name = "invalid_qset", .code = 6 },
        .{ .name = "effect_budget", .code = 7 },
        .{ .name = "driver_fault", .code = 8 },
        .{ .name = "no_effect", .code = 9 },
    };
    var seen = std.AutoHashMapUnmanaged(u32, void).empty;
    defer seen.deinit(gpa);
    for (table) |row| {
        var buf: [64]u8 = undefined;
        const decl = try std.fmt.bufPrint(&buf, "{s} = {d},", .{ row.name, row.code });
        if (std.mem.indexOf(u8, body, decl) == null) {
            std.debug.print("ErrorCode drift: expected `{s}`\n", .{decl});
            return error.ErrorCodeDrift;
        }
        try testing.expect((try seen.fetchPut(gpa, row.code, {})) == null); // distinct
    }
    // The enum has no members beyond the frozen table.
    var members: usize = 0;
    var it = std.mem.tokenizeScalar(u8, body, ',');
    while (it.next()) |tok| {
        if (std.mem.trim(u8, tok, " \t\r\n").len > 0) members += 1;
    }
    try testing.expectEqual(table.len, members);
}

test "§7.2 errorFor maps every engine error away from the decode_failed bucket" {
    const gpa = testing.allocator;
    const src = try abiSource(gpa);
    defer gpa.free(src);

    // Natively verifiable half: the engine's error set is exactly these three.
    const set = @typeInfo(engine.EngineError).error_set.error_names.?;
    try testing.expectEqual(@as(usize, 3), set.len);
    var have_oom = false;
    var have_budget = false;
    var have_failed = false;
    for (set) |name| {
        if (std.mem.eql(u8, name, "OutOfMemory")) have_oom = true;
        if (std.mem.eql(u8, name, "EffectBudgetExceeded")) have_budget = true;
        if (std.mem.eql(u8, name, "EngineFailed")) have_failed = true;
    }
    try testing.expect(have_oom and have_budget and have_failed);

    // Source-pinned half: `errorFor` is private, so its arms are checked
    // textually. Together with the closed error set above this proves no
    // engine error falls through to `else => .decode_failed`.
    try testing.expect(std.mem.indexOf(u8, src, "error.OutOfMemory => .out_of_memory") != null);
    try testing.expect(std.mem.indexOf(u8, src, "error.EffectBudgetExceeded => .effect_budget") != null);
    try testing.expect(std.mem.indexOf(u8, src, "error.EngineFailed => .engine_failed") != null);
    try testing.expect(std.mem.indexOf(u8, src, "else => .decode_failed") != null);
}

// ---------------------------------------------------------------------------
// B. Re-derived behavior — engine + host_codec fixtures
// ---------------------------------------------------------------------------

fn flatQset(gpa: std.mem.Allocator, threshold: u32, member_bytes: []const u8) !qset.QuorumSetOwned {
    const vals = try gpa.alloc(qset.NodeId, member_bytes.len);
    errdefer gpa.free(vals);
    for (member_bytes, 0..) |b, i| vals[i] = @splat(b);
    var qs = qset.QuorumSetOwned{
        .threshold = threshold,
        .validators = vals,
        .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
    };
    try qset.validateAndNormalize(gpa, &qs);
    return qs;
}

/// A real validator: node_id IS the public key of secret_seed, so the engine
/// actually signs, self-processes and emits (a mismatched pair would make the
/// effect stream degenerate to bare input_status and the comparisons vacuous).
fn baseConfig(gpa: std.mem.Allocator) !engine.Config {
    const seed: [32]u8 = @splat(0x77);
    const pk = try crypto.publicKeyFromSeed(seed);

    const vals = try gpa.alloc(qset.NodeId, 3);
    errdefer gpa.free(vals);
    vals[0] = pk;
    vals[1] = @splat(0x02);
    vals[2] = @splat(0x03);
    var qs = qset.QuorumSetOwned{
        .threshold = 2,
        .validators = vals,
        .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
    };
    errdefer qs.deinit(gpa);
    try qset.validateAndNormalize(gpa, &qs);

    return .{
        .network_id = crypto.networkIdFromPassphrase("abi-contract v1"),
        .node_id = pk,
        .secret_seed = seed,
        .quorum_set = qs,
        .strict_canonical = true,
        .limits = .{ .max_value_bytes = 2048, .max_live_slots = 8 },
    };
}

/// Drain an engine the way the ABI does — popEffect (borrow) → encodeEffect →
/// pop_commit — collecting the frames the host would have seen.
fn drainFrames(gpa: std.mem.Allocator, eng: *engine.Engine, out: *std.ArrayList([]u8)) !void {
    while (eng.popEffect()) |eff| {
        try out.append(gpa, try host_codec.encodeEffect(gpa, eff));
        eng.commitEffect();
    }
}

fn freeFrames(gpa: std.mem.Allocator, frames: *std.ArrayList([]u8)) void {
    for (frames.items) |f| gpa.free(f);
    frames.deinit(gpa);
}

test "§7.1/§7.2 slcp_engine_new: EngineConfig frame round-trip yields byte-identical engine behavior" {
    const gpa = testing.allocator;

    // Engine A: constructed directly. Engine B: constructed the way
    // slcp_engine_new does — from a decoded EngineConfig frame.
    var cfg_a = try baseConfig(gpa);
    const frame = try host_codec.encodeEngineConfig(gpa, &cfg_a);
    defer gpa.free(frame);

    var eng_a = try engine.Engine.init(gpa, cfg_a, driver_mod.Driver.default());
    defer eng_a.deinit();

    var cfg_b = try host_codec.decodeEngineConfig(gpa, frame);
    errdefer cfg_b.quorum_set.deinit(gpa);
    // Re-encoding the decoded config is byte-identical: the frame is a fixed
    // point, so the host can persist it and re-create the same engine.
    const frame_b = try host_codec.encodeEngineConfig(gpa, &cfg_b);
    defer gpa.free(frame_b);
    try testing.expectEqualSlices(u8, frame, frame_b);

    var eng_b = try engine.Engine.init(gpa, cfg_b, driver_mod.Driver.default());
    defer eng_b.deinit();

    // Identical input sequence, pushed as encoded Input frames on both sides
    // (decode → push → freeInput, exactly slcp_engine_push_input's body).
    const inputs = [_]engine.Input{
        .{ .nominate = .{ .slot = 1, .value = "value-alpha", .prev_value = "genesis" } },
        .{ .nominate = .{ .slot = 1, .value = "value-beta", .prev_value = "genesis" } },
        .{ .timer_fired = .{ .slot = 1, .timer = .nomination } },
        .{ .envelope_received = .{ .bytes = "not-an-envelope" } },
        .{ .purge_slots = .{ .max_slot = 1 } },
    };

    var total_frames: usize = 0;
    for (inputs) |in| {
        const in_frame = try host_codec.encodeInput(gpa, in);
        defer gpa.free(in_frame);

        var frames_a: std.ArrayList([]u8) = .empty;
        defer freeFrames(gpa, &frames_a);
        var frames_b: std.ArrayList([]u8) = .empty;
        defer freeFrames(gpa, &frames_b);

        inline for (.{ .{ &eng_a, &frames_a }, .{ &eng_b, &frames_b } }) |pair| {
            var decoded = try host_codec.decodeInput(gpa, in_frame);
            defer host_codec.freeInput(gpa, &decoded);
            try pair[0].pushInput(decoded);
            try drainFrames(gpa, pair[0], pair[1]);
        }

        try testing.expectEqual(frames_a.items.len, frames_b.items.len);
        try testing.expect(frames_a.items.len > 0); // at least the input_status
        total_frames += frames_a.items.len;
        for (frames_a.items, frames_b.items) |fa, fb| try testing.expectEqualSlices(u8, fa, fb);
    }
    // The comparison is not vacuous: a real validator emits signed envelopes,
    // timers and phase events, not just one input_status per input.
    try testing.expect(total_frames > inputs.len * 2);
    try testing.expectEqual(eng_a.stats().failed, eng_b.stats().failed);
}

test "§7.2 two-phase pop: pop without commit re-yields the same effect; commit advances; empty is none, not an error" {
    const gpa = testing.allocator;
    var cfg = try baseConfig(gpa);
    errdefer cfg.quorum_set.deinit(gpa);
    var eng = try engine.Engine.init(gpa, cfg, driver_mod.Driver.default());
    defer eng.deinit();

    try eng.pushInput(.{ .nominate = .{ .slot = 1, .value = "v", .prev_value = "" } });
    const queued = eng.effects.len();
    try testing.expect(queued > 1);

    // Borrow twice with no commit in between: same effect, same frame bytes.
    const first = eng.popEffect().?;
    const f1 = try host_codec.encodeEffect(gpa, first);
    defer gpa.free(f1);
    const again = eng.popEffect().?;
    try testing.expectEqual(first, again); // identical borrow (same *const Effect)
    const f2 = try host_codec.encodeEffect(gpa, again);
    defer gpa.free(f2);
    try testing.expectEqualSlices(u8, f1, f2);
    try testing.expectEqual(queued, eng.effects.len()); // pop alone never advances

    // Commit advances by exactly one.
    eng.commitEffect();
    try testing.expectEqual(queued - 1, eng.effects.len());
    const second = eng.popEffect().?;
    try testing.expect(second != first); // the borrow moved to the next slot

    // Drain: the last effect of an input is always input_status (§5.1).
    var frames: std.ArrayList([]u8) = .empty;
    defer freeFrames(gpa, &frames);
    try drainFrames(gpa, &eng, &frames);
    var last = try host_codec.decodeEffect(gpa, frames.items[frames.items.len - 1]);
    defer last.deinitPayload(gpa);
    try testing.expect(last == .input_status);

    // Empty queue: "none", never an error. Commit on empty is a no-op.
    try testing.expect(eng.popEffect() == null);
    eng.commitEffect();
    try testing.expect(eng.popEffect() == null);
    try testing.expectEqual(@as(usize, 0), eng.effects.len());
    try testing.expectEqual(@as(usize, 0), eng.effects.bytes());
    try testing.expectEqual(false, eng.stats().failed); // an empty pop is not a failure
}

test "§7.2 effect budget: the queue is bounded and breach surfaces EffectBudgetExceeded" {
    const gpa = testing.allocator;
    var q = engine.EffectQueue.init(gpa);
    defer q.deinit();

    var pushed: usize = 0;
    while (pushed < engine.EffectQueue.max_effects) : (pushed += 1) {
        try q.push(.{ .input_status = .{ .code = .applied } });
    }
    try testing.expectEqual(engine.EffectQueue.max_effects, q.len());

    // One past the budget: typed error, and the queue does NOT grow.
    try testing.expectError(
        error.EffectBudgetExceeded,
        q.push(.{ .input_status = .{ .code = .applied } }),
    );
    try testing.expectEqual(engine.EffectQueue.max_effects, q.len());

    // The byte budget is the other half of the same clause. Fill it exactly,
    // then breach it: the queue takes ownership of the rejected payload and
    // frees it (std.testing.allocator is the leak witness).
    var q2 = engine.EffectQueue.init(gpa);
    defer q2.deinit();
    const chunk = 1024 * 1024;
    var filled: usize = 0;
    while (filled < engine.EffectQueue.max_bytes) : (filled += chunk) {
        const payload = try gpa.alloc(u8, chunk);
        @memset(payload, 0xaa);
        try q2.push(.{ .broadcast_envelope = .{ .slot = 1, .bytes = payload } });
    }
    try testing.expectEqual(engine.EffectQueue.max_bytes, q2.bytes());

    const over = try gpa.alloc(u8, 1);
    over[0] = 0xff;
    try testing.expectError(
        error.EffectBudgetExceeded,
        q2.push(.{ .broadcast_envelope = .{ .slot = 2, .bytes = over } }),
    );
    try testing.expectEqual(engine.EffectQueue.max_bytes, q2.bytes()); // no growth
}

test "§7.2 freeInput releases every owned slice on all six Input arms" {
    const gpa = testing.allocator;
    // std.testing.allocator is the leak witness: any arm freeInput forgets
    // fails this test.
    const arms = [_]engine.Input{
        .{ .envelope_received = .{ .bytes = "envelope-bytes" } },
        .{ .timer_fired = .{ .slot = 3, .timer = .ballot } },
        .{ .nominate = .{ .slot = 4, .value = "val", .prev_value = "prev" } },
        .{ .qset_received = .{ .bytes = "qset-bytes" } },
        .{ .restore_own_envelope = .{ .bytes = "own-bytes" } },
        .{ .purge_slots = .{ .max_slot = 99 } },
    };
    try testing.expectEqual(@typeInfo(engine.Input).@"union".field_names.len, arms.len);

    for (arms) |in| {
        const frame = try host_codec.encodeInput(gpa, in);
        defer gpa.free(frame);
        var decoded = try host_codec.decodeInput(gpa, frame);
        host_codec.freeInput(gpa, &decoded);
    }
    // Empty payloads too (present zero-length Data still allocates).
    {
        const frame = try host_codec.encodeInput(gpa, .{ .nominate = .{ .slot = 1, .value = "", .prev_value = "" } });
        defer gpa.free(frame);
        var decoded = try host_codec.decodeInput(gpa, frame);
        host_codec.freeInput(gpa, &decoded);
    }
}

// ---------------------------------------------------------------------------
// Lint (§12) — encodeLint frame round-trip + vectors/lint.json cross-check
// ---------------------------------------------------------------------------

/// MIRROR of `slcp_host_abi.encodeLint` (unreachable natively — see module
/// docs). Kept byte-for-byte structurally identical; the wasm differential
/// harness is what pins the real export's bytes against this shape.
///
/// BUG FOUND (reported, fixed here only): the real `encodeLint` does
///     const framed = try mb.toBytes();
///     return alloc.dupe(u8, framed);
/// but `MessageBuilder.toBytes` returns an ALLOCATOR-OWNED slice ("the caller
/// must free the returned slice"), and `mb.deinit()` does not reclaim it — so
/// every `slcp_lint_qset` call leaks one frame in the wasm heap. The
/// `defer alloc.free(framed)` below is the missing line.
fn encodeLintMirror(gpa: std.mem.Allocator, findings: []const qset.LintFinding) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var root = try gen_host.LintDiagnostics.Builder.init(&mb);
    if (findings.len > 0) {
        const list = try root.initFindings(@intCast(findings.len));
        for (findings, 0..) |f, i| {
            var b = try list.get(@intCast(i));
            try b.setLevel(@backingInt(f.level));
            try b.setCode(@backingInt(f.code));
            try b.setMembers(f.members);
            try b.setThreshold(f.threshold);
        }
    }
    const framed = try mb.toBytes();
    defer gpa.free(framed); // the line slcp_host_abi.encodeLint is missing
    return gpa.dupe(u8, framed);
}

fn decodeLint(gpa: std.mem.Allocator, frame: []const u8) ![]qset.LintFinding {
    var msg = try Message.init(gpa, frame, .{});
    defer msg.deinit();
    const r = try gen_host.LintDiagnostics.Reader.init(&msg);
    const list = try r.getFindings();
    const out = try gpa.alloc(qset.LintFinding, list.len());
    errdefer gpa.free(out);
    for (out, 0..) |*slot, i| {
        const f = try list.get(@intCast(i));
        slot.* = .{
            .level = std.enums.fromInt(qset.LintLevel, try f.getLevel()) orelse return error.InvalidEnumValue,
            .code = std.enums.fromInt(qset.LintCode, try f.getCode()) orelse return error.InvalidEnumValue,
            .members = try f.getMembers(),
            .threshold = try f.getThreshold(),
        };
    }
    return out;
}

fn expectLintRoundTrip(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned) ![]qset.LintFinding {
    const findings = try qset.lint(gpa, qs);
    defer gpa.free(findings);
    const frame = try encodeLintMirror(gpa, findings);
    defer gpa.free(frame);
    const decoded = try decodeLint(gpa, frame);
    errdefer gpa.free(decoded);
    try testing.expectEqual(findings.len, decoded.len);
    for (findings, decoded) |a, b| {
        try testing.expectEqual(a.level, b.level);
        try testing.expectEqual(a.code, b.code);
        try testing.expectEqual(a.members, b.members);
        try testing.expectEqual(a.threshold, b.threshold);
    }
    return decoded;
}

test "§7.2/§12 slcp_lint_qset: LintDiagnostics frame round-trips the four lint shapes" {
    const gpa = testing.allocator;

    const Shape = struct { threshold: u32, members: []const u8, want: usize };
    const shapes = [_]Shape{
        .{ .threshold = 2, .members = &.{ 1, 2, 3 }, .want = 0 }, // clean 2-of-3
        .{ .threshold = 1, .members = &.{ 1, 2, 3 }, .want = 2 }, // sub-majority 1-of-3
        .{ .threshold = 3, .members = &.{ 1, 2, 3 }, .want = 1 }, // all-critical 3-of-3
        .{ .threshold = 3, .members = &.{ 1, 2, 3, 4, 5 }, .want = 1 }, // below-two-thirds 3-of-5
    };
    for (shapes) |sh| {
        var qs = try flatQset(gpa, sh.threshold, sh.members);
        defer qs.deinit(gpa);
        const decoded = try expectLintRoundTrip(gpa, &qs);
        defer gpa.free(decoded);
        try testing.expectEqual(sh.want, decoded.len);
        for (decoded) |f| {
            try testing.expectEqual(@as(u32, @intCast(sh.members.len)), f.members);
            try testing.expectEqual(sh.threshold, f.threshold);
        }
    }
}

test "§7.2/§12 lint frame and vectors/lint.json agree" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = std.testing.io;
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, "vectors/lint.json", arena, .unlimited) catch
        return error.SkipZigTest;
    const root = try std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{});
    const cases = root.object.get("cases").?.array;
    try testing.expectEqual(@as(usize, 4), cases.items.len);

    for (cases.items) |case| {
        const input = case.object.get("input").?.object;
        const validators = input.get("validators").?.array;
        const threshold: u32 = @intCast(input.get("threshold").?.integer);

        const vals = try gpa.alloc(qset.NodeId, validators.items.len);
        for (validators.items, 0..) |v, i| {
            const hex = v.string;
            try testing.expectEqual(@as(usize, 64), hex.len);
            _ = try std.fmt.hexToBytes(&vals[i], hex);
        }
        var qs = qset.QuorumSetOwned{
            .threshold = threshold,
            .validators = vals,
            .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
        };
        defer qs.deinit(gpa);
        try qset.validateAndNormalize(gpa, &qs);

        // The findings that came back through the ABI frame — not the raw
        // qset.lint slice — are what gets compared to the vector.
        const decoded = try expectLintRoundTrip(gpa, &qs);
        defer gpa.free(decoded);

        const want = case.object.get("findings").?.array;
        try testing.expectEqual(want.items.len, decoded.len);
        for (want.items, decoded) |w, got| {
            const wo = w.object;
            const want_level = std.meta.stringToEnum(qset.LintLevel, wo.get("level").?.string).?;
            const want_code = std.meta.stringToEnum(qset.LintCode, wo.get("code").?.string).?;
            try testing.expectEqual(want_level, got.level);
            try testing.expectEqual(want_code, got.code);
            try testing.expectEqual(@as(u32, @intCast(wo.get("members").?.integer)), got.members);
            try testing.expectEqual(@as(u32, @intCast(wo.get("threshold").?.integer)), got.threshold);
        }
    }
}

// ---------------------------------------------------------------------------
// qset hash (§4.3 / §7.2) — the ABI normalizes before hashing
// ---------------------------------------------------------------------------

/// Build a framed `QuorumSet` message with validators in the given (possibly
/// unsorted) order — the wire shape `slcp_qset_hash` receives.
fn framedQset(gpa: std.mem.Allocator, threshold: u32, member_bytes: []const u8) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var b = try gen_slcp.QuorumSet.Builder.init(&mb);
    try b.setThreshold(threshold);
    const vl = try b.initValidators(@intCast(member_bytes.len));
    for (member_bytes, 0..) |m, i| {
        const id: qset.NodeId = @splat(m);
        try vl.set(@intCast(i), &id);
    }
    const framed = try mb.toBytes();
    defer gpa.free(framed);
    return gpa.dupe(u8, framed);
}

/// MIRROR of the ABI's private `decodeNormalizedQset`: decode → fromReader →
/// validateAndNormalize. Both `slcp_qset_hash` and `slcp_lint_qset` funnel
/// through this, which is why an unsorted input can never hash differently.
fn decodeNormalizedQsetMirror(gpa: std.mem.Allocator, bytes: []const u8) !qset.QuorumSetOwned {
    var msg = try Message.init(gpa, bytes, .{});
    defer msg.deinit();
    const reader = try gen_slcp.QuorumSet.Reader.init(&msg);
    var owned = try qset.fromReader(gpa, reader);
    errdefer owned.deinit(gpa);
    try qset.validateAndNormalize(gpa, &owned);
    return owned;
}

fn hashFramed(gpa: std.mem.Allocator, frame: []const u8) ![32]u8 {
    var owned = try decodeNormalizedQsetMirror(gpa, frame);
    defer owned.deinit(gpa);
    return qset.hashNormalized(gpa, &owned);
}

test "§7.2 slcp_qset_hash normalizes before hashing: unsorted input hashes as its normalized form" {
    const gpa = testing.allocator;

    const unsorted = try framedQset(gpa, 2, &.{ 3, 1, 2 });
    defer gpa.free(unsorted);
    const sorted = try framedQset(gpa, 2, &.{ 1, 2, 3 });
    defer gpa.free(sorted);
    // The two frames really are different bytes — otherwise the test is vacuous.
    try testing.expect(!std.mem.eql(u8, unsorted, sorted));

    const h_unsorted = try hashFramed(gpa, unsorted);
    const h_sorted = try hashFramed(gpa, sorted);
    try testing.expectEqualSlices(u8, &h_sorted, &h_unsorted);

    // Oracle: qset.hashNormalized over the directly-built normalized set.
    var oracle_qs = try flatQset(gpa, 2, &.{ 1, 2, 3 });
    defer oracle_qs.deinit(gpa);
    const oracle = try qset.hashNormalized(gpa, &oracle_qs);
    try testing.expectEqualSlices(u8, &oracle, &h_unsorted);

    // Reordering inner sets is normalized away too (inner sets sort by their
    // own qsetHash), so a nested frame is order-independent as well.
    const nested_a = try framedNested(gpa, &.{ 1, 2 }, &.{ 3, 4 });
    defer gpa.free(nested_a);
    const nested_b = try framedNested(gpa, &.{ 3, 4 }, &.{ 1, 2 });
    defer gpa.free(nested_b);
    try testing.expect(!std.mem.eql(u8, nested_a, nested_b));
    const hn_a = try hashFramed(gpa, nested_a);
    const hn_b = try hashFramed(gpa, nested_b);
    try testing.expectEqualSlices(u8, &hn_a, &hn_b);
}

/// A 2-of-2 over two inner 1-of-2 sets, in the given inner-set order.
fn framedNested(gpa: std.mem.Allocator, first: []const u8, second: []const u8) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var b = try gen_slcp.QuorumSet.Builder.init(&mb);
    try b.setThreshold(2);
    const il = try b.initInnerSets(2);
    for ([_][]const u8{ first, second }, 0..) |members, idx| {
        var ib = try il.get(@intCast(idx));
        try ib.setThreshold(1);
        const vl = try ib.initValidators(@intCast(members.len));
        for (members, 0..) |m, i| {
            const id: qset.NodeId = @splat(m);
            try vl.set(@intCast(i), &id);
        }
    }
    const framed = try mb.toBytes();
    defer gpa.free(framed);
    return gpa.dupe(u8, framed);
}

test "§7.2 slcp_qset_hash rejects an invalid qset (invalid_qset, never a hash)" {
    const gpa = testing.allocator;
    // threshold 4 over 3 members is not satisfiable — validateAndNormalize
    // rejects, which the ABI reports as ErrorCode.invalid_qset.
    {
        const frame = try framedQset(gpa, 4, &.{ 1, 2, 3 });
        defer gpa.free(frame);
        try testing.expectError(error.ThresholdOutOfRange, hashFramed(gpa, frame));
    }
    // A duplicate node anywhere in the tree is rejected (§4.1), not deduped.
    {
        const frame = try framedQset(gpa, 2, &.{ 2, 3, 1, 3 });
        defer gpa.free(frame);
        try testing.expectError(error.DuplicateNode, hashFramed(gpa, frame));
    }
    // Garbage bytes are rejected at the frame layer, never hashed.
    {
        const bad = [_]u8{ 1, 2, 3, 4 };
        try testing.expect(if (hashFramed(gpa, &bad)) |_| false else |_| true);
    }
}

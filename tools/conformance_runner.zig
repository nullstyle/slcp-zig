//! SLCPRUN1: additive native conformance control, separate from host.capnp v1.
//! A failed push has its own outcome; queued effects remain diagnostic and
//! must never be applied after that failure. No schemas or ABI1 exports change.
const std = @import("std");
const core = @import("slcp-core");
const engine = core.engine;
const codec = core.host_codec;

const format = "SLCPRUN1";
const max_fixture_bytes = 32 * 1024 * 1024;
const max_effect_hex_bytes = 64 * 1024 * 1024;

const Overrides = struct {
    max_value_bytes: ?u32 = null,
    max_nomination_values: ?u32 = null,
    max_pending_envelopes: ?u32 = null,
    max_pending_bytes: ?u32 = null,
    max_live_slots: ?u32 = null,
    max_cached_qsets: ?u32 = null,
    timeout_cap_ms: ?u32 = null,
    max_stored_statement_bytes: ?u32 = null,

    fn apply(self: Overrides, limits: *core.limits.Limits) void {
        inline for (@typeInfo(core.limits.Limits).@"struct".field_names) |name| {
            if (@field(self, name)) |value| @field(limits, name) = value;
        }
    }

    fn check(self: Overrides, limits: core.limits.Limits) !void {
        inline for (@typeInfo(core.limits.Limits).@"struct".field_names) |name| {
            if (@field(self, name)) |value| {
                if (@field(limits, name) != value) return error.LimitsMismatch;
            }
        }
    }
};

const Step = struct {
    input: []const u8,
    push_error: ?[]const u8,
    failed: bool,
    /// Exact normative frames, including any partial frames from a failed push.
    effects: []const []const u8,
};
const Case = struct {
    name: []const u8,
    config: []const u8,
    limits: Overrides = .{},
    expect_limits: Overrides = .{},
    driver: enum { default, combine_fault } = .default,
    init_error: ?[]const u8 = null,
    steps: []const Step,
};
const Fixture = struct { format: []const u8, provenance: ?[]const u8 = null, cases: []const Case };

const Outcome = struct {
    push_error: ?[]const u8,
    failed: bool,
    disposition: enum { apply, discard },
    effects: []const []const u8,
    observable_effects: []const []const u8,
};

fn unhex(gpa: std.mem.Allocator, value: []const u8) ![]u8 {
    if (value.len % 2 != 0) return error.InvalidHex;
    const bytes = try gpa.alloc(u8, value.len / 2);
    errdefer gpa.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, value);
    return bytes;
}

fn hex(gpa: std.mem.Allocator, value: []const u8) ![]const u8 {
    const result = try gpa.alloc(u8, value.len * 2);
    const digits = "0123456789abcdef";
    for (value, 0..) |byte, i| {
        result[i * 2] = digits[byte >> 4];
        result[i * 2 + 1] = digits[byte & 15];
    }
    return result;
}

/// Encode before committing. An encoding failure leaves the head borrowed and
/// uncommitted; the enclosing runner closes the instance and fails its process.
fn drain(eng: *engine.Engine, encoding_allocator: std.mem.Allocator, result_allocator: std.mem.Allocator, push_error: ?[]const u8) !Outcome {
    var frames: std.ArrayList([]const u8) = .empty;
    defer frames.deinit(result_allocator);
    errdefer for (frames.items) |frame| result_allocator.free(frame);
    var observable: std.ArrayList([]const u8) = .empty;
    defer observable.deinit(result_allocator);
    errdefer for (observable.items) |frame| result_allocator.free(frame);
    var total: usize = 0;
    while (eng.popEffect()) |effect| {
        const bytes = try codec.encodeEffect(encoding_allocator, effect);
        defer encoding_allocator.free(bytes);
        total = std.math.add(usize, total, bytes.len * 2) catch return error.ReceiptTooLarge;
        if (total > max_effect_hex_bytes) return error.ReceiptTooLarge;
        const encoded = try hex(result_allocator, bytes);
        errdefer result_allocator.free(encoded);
        if (effect.* == .phase_event)
            try observable.append(result_allocator, encoded)
        else
            try frames.append(result_allocator, encoded);
        eng.commitEffect();
    }
    const owned_frames = try frames.toOwnedSlice(result_allocator);
    errdefer {
        for (owned_frames) |frame| result_allocator.free(frame);
        result_allocator.free(owned_frames);
    }
    return .{
        .push_error = push_error,
        .failed = eng.stats().failed,
        .disposition = if (push_error != null or eng.stats().failed) .discard else .apply,
        .effects = owned_frames,
        .observable_effects = try observable.toOwnedSlice(result_allocator),
    };
}

fn failCombine(_: *anyopaque, _: u64, _: []const []const u8, _: std.mem.Allocator, _: *std.ArrayList(u8)) core.driver.DriverError!void {
    return error.DriverFault;
}

fn equalOptional(a: ?[]const u8, b: ?[]const u8) bool {
    if (a) |value| return if (b) |other| std.mem.eql(u8, value, other) else false;
    return b == null;
}

fn checkStep(expected: Step, actual: Outcome) !void {
    if (!equalOptional(expected.push_error, actual.push_error)) return error.PushOutcomeMismatch;
    if (expected.failed != actual.failed) return error.StickyStateMismatch;
    if (expected.effects.len != actual.effects.len) return error.EffectCountMismatch;
    for (expected.effects, actual.effects) |want, got| {
        if (!std.mem.eql(u8, want, got)) return error.EffectBytesMismatch;
    }
}

fn runFixture(gpa: std.mem.Allocator, bytes: []const u8, out: *std.Io.Writer) !void {
    const parsed = try std.json.parseFromSlice(Fixture, gpa, bytes, .{});
    defer parsed.deinit();
    const fixture = parsed.value;
    if (!std.mem.eql(u8, fixture.format, format)) return error.UnsupportedRunnerFormat;
    if (fixture.cases.len == 0 or fixture.cases.len > 64) return error.InvalidCaseCount;
    var declared_inputs: usize = 0;
    for (fixture.cases, 0..) |case, index| {
        if (case.name.len == 0) return error.EmptyCaseName;
        for (fixture.cases[0..index]) |earlier| {
            if (std.mem.eql(u8, case.name, earlier.name)) return error.DuplicateCaseName;
        }
        if (case.steps.len > 4096) return error.TooManyInputs;
        if (case.init_error != null and case.steps.len != 0) return error.InitializationFailureHasInputs;
        if (case.init_error == null and case.steps.len == 0) return error.EmptyCase;
        declared_inputs += case.steps.len;
    }
    if (declared_inputs == 0) return error.NoInputs;
    var input_count: usize = 0;
    for (fixture.cases) |case| {
        // Receipt payloads and decoded input copies are bounded per case and
        // released before the next case; Engine retains only its own copies.
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const scratch = arena.allocator();
        const config_bytes = try unhex(scratch, case.config);
        var cfg = try codec.decodeEngineConfig(gpa, config_bytes);
        var config_owned = true;
        defer if (config_owned) cfg.quorum_set.deinit(gpa);
        case.limits.apply(&cfg.limits);
        try case.expect_limits.check(cfg.limits);
        var drv = core.driver.Driver.default();
        if (case.driver == .combine_fault) drv.combine_candidates = failCombine;
        var eng = engine.Engine.init(gpa, cfg, drv) catch |err| {
            if (!equalOptional(case.init_error, @errorName(err))) return err;
            try std.json.Stringify.value(.{ .format = format, .case = case.name, .init_error = @errorName(err) }, .{}, out);
            try out.writeByte('\n');
            continue;
        };
        config_owned = false;
        defer eng.deinit();
        if (case.init_error != null) return error.ExpectedInitializationFailure;
        var representable = true;
        inline for (@typeInfo(core.limits.Limits).@"struct".field_names) |name| {
            if (@field(cfg.limits, name) == 0) representable = false;
        }
        var v1_config: ?[]const u8 = null;
        if (representable) {
            const encoded = try codec.encodeEngineConfig(scratch, &cfg);
            v1_config = try hex(scratch, encoded);
        }
        try std.json.Stringify.value(.{ .format = format, .case = case.name, .driver = case.driver, .limits = cfg.limits, .v1_config = v1_config }, .{}, out);
        try out.writeByte('\n');
        for (case.steps, 0..) |step, index| {
            var step_arena: std.heap.ArenaAllocator = .init(gpa);
            defer step_arena.deinit();
            const step_scratch = step_arena.allocator();
            const input_bytes = try unhex(step_scratch, step.input);
            var input = try codec.decodeInput(step_scratch, input_bytes);
            defer codec.deinitInput(step_scratch, &input);
            var push_error: ?[]const u8 = null;
            eng.pushInput(input) catch |err| {
                push_error = @errorName(err);
            };
            const outcome = try drain(&eng, gpa, step_scratch, push_error);
            try std.json.Stringify.value(.{ .format = format, .case = case.name, .index = index, .outcome = outcome }, .{}, out);
            try out.writeByte('\n');
            checkStep(step, outcome) catch |err| {
                std.debug.print("{s}: input {d}: {s}\n", .{ case.name, index, @errorName(err) });
                return err;
            };
            input_count += 1;
        }
    }
    try std.json.Stringify.value(.{ .format = format, .result = "PASS", .cases = fixture.cases.len, .inputs = input_count }, .{}, out);
    try out.writeByte('\n');
}

pub fn main(init: std.process.Init) !void {
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const path = args.next() orelse return error.ExpectedFixturePath;
    if (args.next() != null) return error.UnexpectedArgument;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(max_fixture_bytes));
    defer init.gpa.free(bytes);
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    // A failure exits nonzero even when earlier diagnostic receipts were
    // written. Only the final PASS record qualifies this complete fixture.
    runFixture(init.gpa, bytes, &out.interface) catch |err| {
        try out.interface.flush();
        return err;
    };
    try out.interface.flush();
}

test "runner control preserves absent/default, explicit zero and nonzero through JSON" {
    const gpa = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(Overrides, gpa,
        \\{"max_cached_qsets":0,"max_live_slots":7,"max_pending_bytes":null}
    , .{});
    defer parsed.deinit();
    var limits: core.limits.Limits = .{};
    parsed.value.apply(&limits);
    try std.testing.expectEqual(@as(u32, 0), limits.max_cached_qsets);
    try std.testing.expectEqual(@as(u32, 7), limits.max_live_slots);
    try std.testing.expectEqual((core.limits.Limits{}).max_pending_bytes, limits.max_pending_bytes);
    const encoded = try std.json.Stringify.valueAlloc(gpa, parsed.value, .{});
    defer gpa.free(encoded);
    const round_trip = try std.json.parseFromSlice(Overrides, gpa, encoded, .{});
    defer round_trip.deinit();
    try std.testing.expectEqual(parsed.value, round_trip.value);
}

test "runner serialization failure leaves queued head uncommitted before instance destruction" {
    const gpa = std.testing.allocator;
    var cfg = engine.Config{
        .network_id = @splat(0x11),
        .node_id = @splat(0x22),
        .secret_seed = null,
        .quorum_set = .{
            .threshold = 1,
            .validators = try gpa.dupe([32]u8, &.{@splat(0x22)}),
            .inner_sets = try gpa.alloc(core.qset.QuorumSetOwned, 0),
        },
    };
    var eng = engine.Engine.init(gpa, cfg, core.driver.Driver.default()) catch |err| {
        cfg.quorum_set.deinit(gpa);
        return err;
    };
    defer eng.deinit();
    try eng.pushInput(.{ .purge_slots = .{ .max_slot = 1 } });
    const count = eng.effects.len();
    const head = eng.popEffect().?;
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, drain(&eng, failing.allocator(), gpa, null));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(count, eng.effects.len());
    try std.testing.expect(eng.popEffect().? == head);
}

test "runner requires supported format and nonempty fixtures" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.UnsupportedRunnerFormat, runFixture(std.testing.allocator, "{\"format\":\"future\",\"cases\":[]}", &out.writer));
    try std.testing.expectError(error.InvalidCaseCount, runFixture(std.testing.allocator, "{\"format\":\"SLCPRUN1\",\"cases\":[]}", &out.writer));
    try std.testing.expectError(error.EmptyCase, runFixture(std.testing.allocator,
        \\{"format":"SLCPRUN1","cases":[{"name":"empty","config":"","steps":[]}]}
    , &out.writer));
    try std.testing.expectError(error.NoInputs, runFixture(std.testing.allocator,
        \\{"format":"SLCPRUN1","cases":[{"name":"init-only","config":"","init_error":"BadValueBytes","steps":[]}]}
    , &out.writer));
    try std.testing.expectError(error.InitializationFailureHasInputs, runFixture(std.testing.allocator,
        \\{"format":"SLCPRUN1","cases":[{"name":"ignored-input","config":"","init_error":"BadValueBytes","steps":[{"input":"","push_error":null,"failed":false,"effects":[]}]}]}
    , &out.writer));
}

test "runner refuses a changed expected frame and emits no completion marker" {
    const gpa = std.testing.allocator;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "vectors/runner/SLCPRUN1.json", gpa, .limited(max_fixture_bytes));
    defer gpa.free(bytes);
    const changed = try gpa.dupe(u8, bytes);
    defer gpa.free(changed);
    // The first armTimer's delay is frozen by SLCPTRC1, not derived from the
    // runner implementation. Changing its expected bytes must fail replay.
    const offset = std.mem.indexOf(u8, changed, "00000000e8030000") orelse return error.MissingFrozenTimer;
    changed[offset + 9] = '9';
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try std.testing.expectError(error.EffectBytesMismatch, runFixture(gpa, changed, &out.writer));
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"result\":\"PASS\"") == null);
}

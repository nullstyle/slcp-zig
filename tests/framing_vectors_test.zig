//! Vendored framing conformance replay (design §9.1).
//!
//! `vectors/framing/framing_fixtures.json` is capnp-zig's PUBLISHED fixture
//! file for `rpc.wire.framing.Framer`, copied verbatim (provenance and the
//! upstream commit live in `vectors/framing/PROVENANCE.md`). We vendor it
//! because that Framer sits on our consensus wire path: `src/node/overlay.zig`
//! reassembles every segment frame the flood overlay receives with it, so a
//! drift in its framing behavior changes what our nodes accept off the wire.
//!
//! This runner is deliberately NOT a copy of upstream's. Upstream replays the
//! fixtures against a DEFAULT Framer; we replay them against the Framer AS
//! SLCP CONFIGURES IT — `overlay.framer_options`, imported from the overlay
//! module rather than restated here, so a change to our 1 MiB frame cap breaks
//! this suite loudly instead of leaving it asserting someone else's setup.
//!
//! Three layers of assertion:
//!   1. the fixtures' recorded `constants` block vs. the LIVE constants of our
//!      pinned capnp-zig (v0.14.0) — a limit change upstream makes this
//!      vendored copy stale rather than silently passing;
//!   2. every fixture case replayed through slcp's own Framer options;
//!   3. slcp-specific cases the upstream fixtures cannot express: our
//!      buffered-bytes ceiling is a different number from theirs, and the
//!      overlay's push/pop loop is what turns it into a frame-size cap.
//!
//! Skips with error.SkipZigTest when the fixture file is absent, matching this
//! repo's convention for artifact-dependent tests.

const std = @import("std");
const slcp = @import("slcp");

const overlay = slcp.overlay;
/// The very same Framer the overlay compiled against: `slcp.core` is the
/// full-capnp-bound slcp-core instance, so this is module-identical to the
/// type inside `Overlay.runConnection`.
const Framer = slcp.core.capnpc.rpc.wire.framing.Framer;
const json = std.json;

const fixtures_path = "vectors/framing/framing_fixtures.json";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Parse the vendored fixtures onto `arena`, or null when the file is absent
/// (caller turns null into error.SkipZigTest).
fn loadFixtures(arena: std.mem.Allocator) !?json.Value {
    const io = std.testing.io;
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, fixtures_path, arena, .unlimited) catch return null;
    return try json.parseFromSliceLeaky(json.Value, arena, bytes, .{});
}

fn field(v: json.Value, name: []const u8) json.Value {
    return v.object.get(name).?;
}

fn optString(v: json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn hexAlloc(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    try std.testing.expectEqual(@as(usize, 0), s.len % 2);
    const out = try gpa.alloc(u8, s.len / 2);
    errdefer gpa.free(out);
    const written = try std.fmt.hexToBytes(out, s);
    try std.testing.expectEqual(out.len, written.len);
    return out;
}

/// What the overlay's reader loop observes for one byte stream: the frames
/// that popped, and the first error (if any) with the call that raised it.
const Replay = struct {
    frames: std.ArrayList([]u8) = .empty,
    err: ?anyerror = null,
    err_on: []const u8 = "",

    fn deinit(self: *Replay, gpa: std.mem.Allocator) void {
        for (self.frames.items) |f| gpa.free(f);
        self.frames.deinit(gpa);
    }
};

/// Push each chunk, popping frames after every push until the framer reports
/// "no complete frame yet" — the fixtures' documented protocol, and exactly
/// the shape of `Overlay.nextRawFrame`. Stops at the first error.
fn replayBytes(gpa: std.mem.Allocator, options: Framer.Options, chunks: []const []const u8) !Replay {
    var out: Replay = .{};
    errdefer out.deinit(gpa);

    var framer = Framer.initWithOptions(gpa, options);
    defer framer.deinit();

    for (chunks) |chunk| {
        framer.push(chunk) catch |err| {
            out.err = err;
            out.err_on = "push";
            return out;
        };
        while (true) {
            const maybe_frame = framer.popFrame() catch |err| {
                out.err = err;
                out.err_on = "pop";
                return out;
            };
            const frame = maybe_frame orelse break;
            out.frames.append(gpa, frame) catch |err| {
                gpa.free(frame);
                return err;
            };
        }
    }
    return out;
}

/// `replayBytes` over a fixture case's hex `chunks` array.
fn replayHexChunks(gpa: std.mem.Allocator, options: Framer.Options, chunks: []const json.Value) !Replay {
    var decoded: std.ArrayList([]const u8) = .empty;
    defer {
        for (decoded.items) |c| gpa.free(c);
        decoded.deinit(gpa);
    }
    for (chunks) |c| {
        const bytes = try hexAlloc(gpa, c.string);
        decoded.append(gpa, bytes) catch |err| {
            gpa.free(bytes);
            return err;
        };
    }
    return replayBytes(gpa, options, decoded.items);
}

/// Compare one replay against a fixture's `expect` object.
fn expectMatches(gpa: std.mem.Allocator, name: []const u8, expect: json.Value, got: *const Replay) !void {
    errdefer std.debug.print("framing fixture failed: {s}\n", .{name});

    const want_error = optString(field(expect, "error"));
    const want_error_on = optString(field(expect, "error_on"));

    if (want_error) |want| {
        const got_err = got.err orelse {
            std.debug.print("fixture {s}: expected error {s}, got none\n", .{ name, want });
            return error.TestExpectedError;
        };
        try std.testing.expectEqualStrings(want, @errorName(got_err));
        if (want_error_on) |where| try std.testing.expectEqualStrings(where, got.err_on);
    } else if (got.err) |got_err| {
        std.debug.print("fixture {s}: unexpected {s} error {s}\n", .{ name, got.err_on, @errorName(got_err) });
        return error.TestUnexpectedResult;
    }

    const want_frames = field(expect, "frames").array.items;
    try std.testing.expectEqual(want_frames.len, got.frames.items.len);
    for (want_frames, got.frames.items) |want_value, got_frame| {
        const want_bytes = try hexAlloc(gpa, want_value.string);
        defer gpa.free(want_bytes);
        try std.testing.expectEqualSlices(u8, want_bytes, got_frame);
    }
}

// ---------------------------------------------------------------------------
// 1. Recorded limits vs. our live constants
// ---------------------------------------------------------------------------

test "framing vectors: recorded limits match our pinned capnp-zig" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = (try loadFixtures(arena)) orelse return error.SkipZigTest;

    try std.testing.expectEqual(@as(i64, 1), field(root, "version").integer);

    // The fixtures publish the limits they were generated against (upstream
    // main). If OUR pinned Framer disagrees, this vendored copy is stale and
    // every verdict below is describing a different implementation.
    const constants = field(root, "constants");
    try std.testing.expectEqual(
        @as(i64, @intCast(Framer.max_frame_words)),
        field(constants, "max_frame_words").integer,
    );
    try std.testing.expectEqual(
        @as(i64, @intCast(Framer.max_segment_count)),
        field(constants, "max_segment_count").integer,
    );
    try std.testing.expectEqual(
        @as(i64, @intCast(Framer.max_header_bytes)),
        field(constants, "max_header_bytes").integer,
    );
    try std.testing.expectEqual(
        @as(i64, @intCast(Framer.default_max_buffered_bytes)),
        field(constants, "default_max_buffered_bytes").integer,
    );

    // slcp does NOT run the default ceiling: §9.1 tightens it to one max-size
    // frame plus one read chunk. Pin the relationship both ways so neither our
    // constants nor upstream's default can move unnoticed.
    try std.testing.expectEqual(
        overlay.max_frame_bytes + overlay.default_read_buffer_size,
        overlay.framer_options.max_buffered_bytes,
    );
    try std.testing.expect(overlay.framer_options.max_buffered_bytes < Framer.default_max_buffered_bytes);
    // A frame at our cap must still be representable under the Framer's own
    // word limit, or our cap would be decorative.
    try std.testing.expect(overlay.max_frame_bytes <= Framer.max_frame_words * 8);
}

// ---------------------------------------------------------------------------
// 2. Every fixture case, through slcp's Framer options
// ---------------------------------------------------------------------------

test "framing vectors: fixtures replay through slcp's overlay Framer" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = (try loadFixtures(arena)) orelse return error.SkipZigTest;

    const cases = field(root, "cases").array.items;
    try std.testing.expect(cases.len > 0);

    var replayed_with_our_options: usize = 0;
    for (cases) |case| {
        const name = field(case, "name").string;
        const chunks = field(case, "chunks").array.items;
        const expect = field(case, "expect");

        if (case.object.get("options")) |opts| {
            // This case pins the buffered-bytes ceiling itself, with a cap
            // that is not ours. Honor the override for the recorded verdict
            // (that is upstream's conformance claim about the mechanism)...
            const capped: Framer.Options = .{
                .max_buffered_bytes = @intCast(field(opts, "max_buffered_bytes").integer),
            };
            try std.testing.expect(capped.max_buffered_bytes < overlay.framer_options.max_buffered_bytes);

            var got = try replayHexChunks(gpa, capped, chunks);
            defer got.deinit(gpa);
            try expectMatches(gpa, name, expect, &got);

            // ...then re-run the SAME bytes under slcp's real cap, where they
            // are comfortably under the ceiling and must not raise.
            var ours = try replayHexChunks(gpa, overlay.framer_options, chunks);
            defer ours.deinit(gpa);
            if (ours.err) |err| {
                std.debug.print(
                    "fixture {s}: unexpected {s} error {s} under slcp's cap ({d} bytes)\n",
                    .{ name, ours.err_on, @errorName(err), overlay.framer_options.max_buffered_bytes },
                );
                return error.TestUnexpectedResult;
            }
            continue;
        }

        // Everything else is cap-independent at these sizes: the recorded
        // verdict must hold for the Framer exactly as the overlay builds it.
        var got = try replayHexChunks(gpa, overlay.framer_options, chunks);
        defer got.deinit(gpa);
        try expectMatches(gpa, name, expect, &got);
        replayed_with_our_options += 1;
    }

    // Guard against a future fixture file that is all overrides (which would
    // leave slcp's own configuration untested by the loop above).
    try std.testing.expect(replayed_with_our_options >= 8);
}

// ---------------------------------------------------------------------------
// 3. slcp-specific: our ceiling, and the loop that turns it into a frame cap
// ---------------------------------------------------------------------------

test "framing vectors: slcp's buffered-bytes ceiling is the enforced one" {
    const gpa = std.testing.allocator;
    const cap = overlay.framer_options.max_buffered_bytes;

    const at_cap = try gpa.alloc(u8, cap);
    defer gpa.free(at_cap);
    @memset(at_cap, 0xab);
    // A 1-segment header declaring twice the ceiling, so nothing ever pops and
    // the buffer is measuring exactly what we mean to measure.
    std.mem.writeInt(u32, at_cap[0..4], 0, .little); // segment_count - 1
    std.mem.writeInt(u32, at_cap[4..8], @intCast((2 * cap) / 8), .little);

    // Exactly at the ceiling: accepted, no frame yet, no error.
    {
        var got = try replayBytes(gpa, overlay.framer_options, &.{at_cap});
        defer got.deinit(gpa);
        if (got.err) |err| {
            std.debug.print("push of exactly {d} bytes raised {s}\n", .{ cap, @errorName(err) });
            return error.TestUnexpectedResult;
        }
        try std.testing.expectEqual(@as(usize, 0), got.frames.items.len);
    }

    // One byte past it: FrameTooLarge, at PUSH time, before any framing.
    {
        var got = try replayBytes(gpa, overlay.framer_options, &.{ at_cap, "\x00" });
        defer got.deinit(gpa);
        try std.testing.expectEqualStrings("FrameTooLarge", @errorName(got.err orelse return error.TestExpectedError));
        try std.testing.expectEqualStrings("push", got.err_on);
    }
}

test "framing vectors: an oversized frame trips our cap in the overlay's read loop" {
    const gpa = std.testing.allocator;

    // A single-segment frame declaring 2 MiB of body — twice §9.1's
    // max_frame_bytes, but far below the Framer's own max_frame_words. It is
    // rejected only because slcp lowered the buffered-bytes ceiling, and only
    // because the overlay pops after every push (so a legal frame never
    // accumulates past one frame plus one read chunk).
    const body_bytes: usize = 2 * overlay.max_frame_bytes;
    var header: [8]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], 0, .little); // segment_count - 1
    std.mem.writeInt(u32, header[4..8], @intCast(body_bytes / 8), .little);

    const chunk = try gpa.alloc(u8, overlay.default_read_buffer_size);
    defer gpa.free(chunk);
    @memset(chunk, 0xab);
    @memcpy(chunk[0..8], &header);

    // Feed it the way the reader thread does: read-buffer-sized chunks.
    var chunks: std.ArrayList([]const u8) = .empty;
    defer chunks.deinit(gpa);
    var fed: usize = 0;
    while (fed < header.len + body_bytes) : (fed += chunk.len) {
        try chunks.append(gpa, chunk);
    }

    var got = try replayBytes(gpa, overlay.framer_options, chunks.items);
    defer got.deinit(gpa);

    try std.testing.expectEqual(@as(usize, 0), got.frames.items.len);
    try std.testing.expectEqualStrings("FrameTooLarge", @errorName(got.err orelse return error.TestExpectedError));
    try std.testing.expectEqualStrings("push", got.err_on);
}

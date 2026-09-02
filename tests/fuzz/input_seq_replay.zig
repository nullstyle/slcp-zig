//! zig build fuzz-replay -- [file.bin ...]
//!
//! Replays saved input-sequence fuzz inputs — the bytes `zig build fuzz
//! --fuzz` writes to `.zig-cache/f/crash` when the target fails — through
//! tests/fuzz/input_seq_fuzz.zig's OWN `run` path (Smith{ .in = bytes },
//! eos-gated length, §13.1 invariants after every input) and prints one
//! line per derived input, every own statement the engine persisted, and
//! the decoded pair the own-monotonicity invariant rejected. With no
//! arguments it replays the three S9 crash inputs embedded from
//! tests/fuzz/crash/. Exit code 0 either way: this is a diagnostic, the
//! pinning test lives in input_seq_fuzz.zig.

const std = @import("std");
const seq = @import("input_seq_fuzz");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var out_buf: [16 * 1024]u8 = undefined;
    var fw = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &fw.interface;
    defer w.flush() catch {};

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next(); // argv[0]
    var n: usize = 0;
    while (args.next()) |path| {
        n += 1;
        const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 24));
        defer gpa.free(bytes);
        try replayOne(gpa, w, path, bytes);
    }
    if (n == 0) {
        for (seq.crash_inputs) |ci| try replayOne(gpa, w, ci.name, ci.bytes);
    }
}

fn replayOne(gpa: std.mem.Allocator, w: *std.Io.Writer, name: []const u8, bytes: []const u8) !void {
    const tag = seq.hashTag(bytes);
    try w.print("=== {s} ({d} bytes, sha256 {s}…)\n", .{ name, bytes.len, &tag });
    var trace: seq.Trace = .{ .w = w };
    seq.replayBytes(gpa, bytes, &trace) catch |err| {
        try w.print("--- {s}: {t} after {d} inputs\n", .{ name, err, trace.steps });
        if (trace.finding) |f| {
            const class: []const u8 = if (f.same_committed_value) |eq|
                (if (eq) "(a) two EXTERNALIZE, same committed value — isNewerOwned's .externalize arm (HANDOFF §6 class)" else "(b) two EXTERNALIZE, DIFFERENT committed values — FORK")
            else
                "(c) non-EXTERNALIZE pair not newer — stale-vs-self emission";
            try w.print("    class: {s}\n    restore_own_envelope applied between the pair: {}\n", .{ class, f.restore_between });
        }
        try w.flush();
        return;
    };
    try w.print("--- {s}: NOT reproduced ({d} inputs, no invariant violation; {d} input bytes left{s})\n", .{
        name,
        trace.steps,
        trace.bytes_left,
        if (trace.bytes_left == 0) " — stream exhausted: the saved input is a truncated prefix" else "",
    });
    try w.flush();
}

//! example-smoke — the §0 program run for real (plan S4; design §13.6 twin).
//!
//! Builds `examples/counter` THREE times as a consumer package — a nested
//! `zig build -Doptimize=ReleaseSafe` per scratch copy with this repo as a
//! path dependency — then runs the three `counter` processes over loopback
//! (ports 47311..47313), kills node0 with SIGKILL once it has printed
//! `count = 8` and restarts it from the same data_dir (the §0 restart story:
//! the restarted program's FIRST proposal is the stale `{ .next = 1 }`), and
//! waits until every process has printed `--slots` slots. Every printed
//! `slot N: count = C` line is checked for `C == N` and for cross-node
//! agreement.
//!
//! Each scratch copy is the published example with EXACTLY five lines
//! rewritten — the three `const pk_* = slcp.nodeId("…");` lines, the
//! `.listen_port = 7311,` line and the `.peers = &.{ … },` line — the same
//! edit the README asks a hobbyist to make per machine. Each pattern must
//! match exactly once (a drifted example is a red smoke, not a silently
//! vacuous one).
//!
//! Evidence line on success (stdout): `[example-smoke] nodes=3 slots=N count=C`.
//!
//! argv: `--zig <path>` (required; the build step passes its own zig)
//! `[--slots N=20] [--deadline-s S=180] [--build-only] [--keep]
//! [--counter-src <dir>=examples/counter]`. Run from the repo root (the build
//! step pins cwd). Scratch lives under `.zig-cache/example-smoke/node{0,1,2}`
//! and is removed afterwards unless `--keep`.
//!
//! Environment: the nested builds inherit this process's environment.
//! `ZIG_LOCAL_PKG_DIR` is pointed at `<repo>/zig-pkg` when unset, so the
//! nested builds reuse the packages the root build already fetched instead
//! of fetching capnp-zig's dependency tree three more times; the local cache
//! is shared via `--cache-dir <repo>/.zig-cache`.

const std = @import("std");
const slcp = @import("slcp");

pub const n_nodes: usize = 3;
pub const base_port: u16 = 47311;
/// node0 is SIGKILLed once its printed count reaches this (or `--slots`,
/// whichever is smaller).
pub const restart_at_count: u64 = 8;
const default_slots: u64 = 20;
const default_deadline_s: u64 = 180;
const default_counter_src = "examples/counter";
const scratch_root = ".zig-cache/example-smoke";
const tail_lines: usize = 20;
const line_buf_bytes: usize = 64 * 1024;
const tick_ms: u64 = 100;

// ---------------------------------------------------------------------------
// The five frozen deployment lines (examples/counter/src/main.zig)
// ---------------------------------------------------------------------------

/// The three public-key lines, byte-exact.
pub const pk_lines = [n_nodes][]const u8{
    "const pk_a = slcp.nodeId(\"0101010101010101010101010101010101010101010101010101010101010101\");",
    "const pk_b = slcp.nodeId(\"0202020202020202020202020202020202020202020202020202020202020202\");",
    "const pk_c = slcp.nodeId(\"0303030303030303030303030303030303030303030303030303030303030303\");",
};
pub const pk_names = [n_nodes][]const u8{ "pk_a", "pk_b", "pk_c" };
/// The listen-port line (leading indentation included: a FULL line).
pub const port_line = "        .listen_port = 7311,";
/// The peers line (the OTHER two machines), full line.
pub const peers_line = "        .peers = &.{ \"b.example.com:7311\", \"c.example.com:7311\" },";
/// In build.zig.zon: the path dependency to rewrite to the absolute repo root.
const zon_path_needle = ".path = \"../..\"";

pub const RewriteError = error{ PatternMissing, PatternAmbiguous } || std.mem.Allocator.Error;

/// Replace the ONE full line of `src` equal to `needle` with `replacement`
/// (line terminators preserved). Zero matches is `PatternMissing`, two or
/// more is `PatternAmbiguous` — the non-vacuity guard of the whole smoke.
pub fn replaceLineOnce(gpa: std.mem.Allocator, src: []const u8, needle: []const u8, replacement: []const u8) RewriteError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var hits: usize = 0;
    var it = std.mem.splitScalar(u8, src, '\n');
    var first = true;
    while (it.next()) |line| {
        if (!first) try out.append(gpa, '\n');
        first = false;
        if (std.mem.eql(u8, line, needle)) {
            hits += 1;
            try out.appendSlice(gpa, replacement);
        } else {
            try out.appendSlice(gpa, line);
        }
    }
    if (hits == 0) return error.PatternMissing;
    if (hits > 1) return error.PatternAmbiguous;
    return out.toOwnedSlice(gpa);
}

/// The loopback port of node `i`.
pub fn portOf(i: usize) u16 {
    return base_port + @as(u16, @intCast(i));
}

/// `src` (the published main.zig) with the five deployment lines rewritten
/// for node `index`: its own key file's public key per `pks`, port
/// `47311+index`, and the two OTHER loopback nodes as peers.
pub fn rewriteMain(gpa: std.mem.Allocator, src: []const u8, pks: *const [n_nodes][64]u8, index: usize) ![]u8 {
    var cur = try gpa.dupe(u8, src);
    errdefer gpa.free(cur);
    for (0..n_nodes) |k| {
        const repl = try std.fmt.allocPrint(gpa, "const {s} = slcp.nodeId(\"{s}\");", .{ pk_names[k], &pks[k] });
        defer gpa.free(repl);
        const next = try replaceLineOnce(gpa, cur, pk_lines[k], repl);
        gpa.free(cur);
        cur = next;
    }
    {
        const repl = try std.fmt.allocPrint(gpa, "        .listen_port = {d},", .{portOf(index)});
        defer gpa.free(repl);
        const next = try replaceLineOnce(gpa, cur, port_line, repl);
        gpa.free(cur);
        cur = next;
    }
    {
        var others: [n_nodes - 1]u16 = undefined;
        var n: usize = 0;
        for (0..n_nodes) |k| {
            if (k == index) continue;
            others[n] = portOf(k);
            n += 1;
        }
        const repl = try std.fmt.allocPrint(gpa, "        .peers = &.{{ \"127.0.0.1:{d}\", \"127.0.0.1:{d}\" }},", .{ others[0], others[1] });
        defer gpa.free(repl);
        const next = try replaceLineOnce(gpa, cur, peers_line, repl);
        gpa.free(cur);
        cur = next;
    }
    return cur;
}

/// Where the repo root sits relative to a scratch dir: the nested build root
/// is `<repo>/.zig-cache/example-smoke/node{i}`, and `zig build` refuses an
/// absolute `.path` ("expected path relative to build root"), so this is a
/// fixed relative path, not the absolute root the plan sketched.
pub const zon_path_from_scratch = "../../..";

/// `build.zig.zon` with `.path = "../.."` (examples/counter's own location)
/// pointed at `root` — `zon_path_from_scratch` for the scratch copies. A zon
/// without that needle (a URL-pinned consumer copy handed in via
/// `--counter-src`) is returned unchanged.
pub fn rewriteZon(gpa: std.mem.Allocator, src: []const u8, root: []const u8) ![]u8 {
    const at = std.mem.indexOf(u8, src, zon_path_needle) orelse return gpa.dupe(u8, src);
    if (std.mem.indexOfPos(u8, src, at + zon_path_needle.len, zon_path_needle) != null) return error.PatternAmbiguous;
    return std.fmt.allocPrint(gpa, "{s}.path = \"{s}\"{s}", .{ src[0..at], root, src[at + zon_path_needle.len ..] });
}

/// The success evidence line (`just preflight` greps its literal prefix).
pub fn evidenceLine(buf: []u8, nodes: usize, slots: u64, count: u64) ![]const u8 {
    return std.fmt.bufPrint(buf, "[example-smoke] nodes={d} slots={d} count={d}", .{ nodes, slots, count });
}

// ---------------------------------------------------------------------------
// Child processes
// ---------------------------------------------------------------------------

/// A parsed `slot N: count = C` line, or null for any other stderr line.
pub fn parseSlotLine(line: []const u8) ?struct { slot: u64, count: u64 } {
    const prefix = "slot ";
    const mid = ": count = ";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    const rest = line[prefix.len..];
    const colon = std.mem.indexOf(u8, rest, mid) orelse return null;
    const slot = std.fmt.parseInt(u64, rest[0..colon], 10) catch return null;
    const count = std.fmt.parseInt(u64, std.mem.trimEnd(u8, rest[colon + mid.len ..], "\r"), 10) catch return null;
    return .{ .slot = slot, .count = count };
}

/// One counter process: its scratch dir, the child, and a reader thread over
/// the child's stderr (std.debug.print and std.log both write there).
/// Heap-allocated and never moved: `File.Reader` embeds an interface reached
/// by pointer, and the reader thread holds `*NodeProc`.
const NodeProc = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    index: usize,
    dir: []const u8,
    exe: []const u8,
    child: ?std.process.Child = null,
    thread: ?std.Thread = null,
    rdr_buf: []u8,
    rdr: std.Io.File.Reader = undefined,

    mu: std.Io.Mutex = .init,
    // ---- guarded by mu ----
    /// Highest count printed by the CURRENT process (reset on restart).
    max_count: u64 = 0,
    parsed_lines: u64 = 0,
    /// slot → count, across restarts (agreement is checked against this).
    counts: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    eof: bool = false,
    expect_eof: bool = false,
    /// The first line that broke `count == slot` or contradicted an earlier
    /// print of the same slot by this node.
    bad: ?[]u8 = null,
    tail: [tail_lines]?[]u8 = @splat(null),
    tail_next: usize = 0,

    fn create(gpa: std.mem.Allocator, io: std.Io, index: usize, dir: []const u8) !*NodeProc {
        const self = try gpa.create(NodeProc);
        errdefer gpa.destroy(self);
        const rdr_buf = try gpa.alloc(u8, line_buf_bytes);
        errdefer gpa.free(rdr_buf);
        const exe = try std.fmt.allocPrint(gpa, "{s}/zig-out/bin/counter", .{dir});
        errdefer gpa.free(exe);
        self.* = .{ .gpa = gpa, .io = io, .index = index, .dir = try gpa.dupe(u8, dir), .exe = exe, .rdr_buf = rdr_buf };
        return self;
    }

    fn destroy(self: *NodeProc) void {
        self.stop();
        const gpa = self.gpa;
        for (&self.tail) |*t| if (t.*) |s| gpa.free(s);
        if (self.bad) |b| gpa.free(b);
        self.counts.deinit(gpa);
        gpa.free(self.exe);
        gpa.free(self.dir);
        gpa.free(self.rdr_buf);
        gpa.destroy(self);
    }

    /// Spawn the counter in its scratch dir (cwd: `slcp.key` and `slcp-data`
    /// are relative in the published program) with stderr piped to a fresh
    /// reader thread.
    fn spawn(self: *NodeProc) !void {
        std.debug.assert(self.child == null and self.thread == null);
        self.mu.lockUncancelable(self.io);
        self.eof = false;
        self.expect_eof = false;
        self.max_count = 0;
        self.mu.unlock(self.io);
        self.child = try std.process.spawn(self.io, .{
            .argv = &.{self.exe},
            .cwd = .{ .path = self.dir },
            .stdin = .ignore,
            .stdout = .inherit,
            .stderr = .pipe,
        });
        self.rdr = self.child.?.stderr.?.readerStreaming(self.io, self.rdr_buf);
        self.thread = std.Thread.spawn(.{}, readerLoop, .{self}) catch |err| {
            self.child.?.kill(self.io);
            self.child = null;
            return err;
        };
    }

    /// SIGKILL (not the SIGTERM of `Child.kill`), join the reader (its EOF
    /// arrives when the child dies), then reap. Idempotent.
    fn stop(self: *NodeProc) void {
        if (self.child) |*child| {
            if (child.id) |pid| std.posix.kill(pid, .KILL) catch {};
            if (self.thread) |t| t.join();
            self.thread = null;
            _ = child.wait(self.io) catch {};
            self.child = null;
        }
        if (self.thread) |t| t.join();
        self.thread = null;
    }

    fn readerLoop(self: *NodeProc) void {
        while (true) {
            const with_nl = self.rdr.interface.takeDelimiterInclusive('\n') catch break;
            self.noteLine(with_nl[0 .. with_nl.len - 1]);
        }
        self.mu.lockUncancelable(self.io);
        self.eof = true;
        self.mu.unlock(self.io);
    }

    fn noteLine(self: *NodeProc, line: []const u8) void {
        const parsed = parseSlotLine(line);
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const copy = self.gpa.dupe(u8, line) catch return;
        if (self.tail[self.tail_next]) |old| self.gpa.free(old);
        self.tail[self.tail_next] = copy;
        self.tail_next = (self.tail_next + 1) % tail_lines;
        const p = parsed orelse return;
        self.parsed_lines += 1;
        var ok = p.count == p.slot;
        if (self.counts.get(p.slot)) |prev| {
            if (prev != p.count) ok = false;
        } else {
            self.counts.put(self.gpa, p.slot, p.count) catch {};
        }
        if (!ok and self.bad == null) self.bad = self.gpa.dupe(u8, line) catch null;
        if (p.count > self.max_count) self.max_count = p.count;
    }

    /// Print the last `tail_lines` stderr lines (oldest first).
    fn dumpTail(self: *NodeProc) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        std.debug.print("[example-smoke] --- node{d} last {d} stderr lines ---\n", .{ self.index, tail_lines });
        for (0..tail_lines) |k| {
            const idx = (self.tail_next + k) % tail_lines;
            if (self.tail[idx]) |s| std.debug.print("  {s}\n", .{s});
        }
    }
};

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

const Args = struct {
    zig: ?[]const u8 = null,
    slots: u64 = default_slots,
    deadline_s: u64 = default_deadline_s,
    build_only: bool = false,
    keep: bool = false,
    counter_src: []const u8 = default_counter_src,
};

fn parseArgs(init: std.process.Init) !Args {
    var a: Args = .{};
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--zig")) {
            a.zig = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--slots")) {
            a.slots = try std.fmt.parseInt(u64, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--deadline-s")) {
            a.deadline_s = try std.fmt.parseInt(u64, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--build-only")) {
            a.build_only = true;
        } else if (std.mem.eql(u8, arg, "--keep")) {
            a.keep = true;
        } else if (std.mem.eql(u8, arg, "--counter-src")) {
            a.counter_src = it.next() orelse return error.MissingValue;
        } else {
            std.debug.print("[example-smoke] unknown argument: {s}\n", .{arg});
            return error.BadArgument;
        }
    }
    if (a.zig == null) {
        std.debug.print("[example-smoke] --zig <path> is required (the build step passes its own)\n", .{});
        return error.BadArgument;
    }
    if (a.slots == 0) return error.BadArgument;
    return a;
}

pub fn main(init: std.process.Init) !void {
    const args = try parseArgs(init);
    run(init, args) catch |err| {
        std.debug.print("[example-smoke] FAILED: {t}\n", .{err});
        std.process.exit(1);
    };
}

fn readSrc(gpa: std.mem.Allocator, io: std.Io, dir: []const u8, rel: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, rel });
    defer gpa.free(path);
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| {
        std.debug.print("[example-smoke] cannot read {s}: {t}\n", .{ path, err });
        return err;
    };
}

fn writeFile(io: std.Io, dir: std.Io.Dir, rel: []const u8, data: []const u8) !void {
    try dir.writeFile(io, .{ .sub_path = rel, .data = data });
}

fn run(init: std.process.Init, args: Args) !void {
    const gpa = init.gpa;
    const io = init.io;
    const cwd = std.Io.Dir.cwd();

    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try std.process.currentPath(io, &root_buf)];

    // ---- (1) the published example, read once ----
    const main_src = try readSrc(gpa, io, args.counter_src, "src/main.zig");
    defer gpa.free(main_src);
    const build_src = try readSrc(gpa, io, args.counter_src, "build.zig");
    defer gpa.free(build_src);
    const zon_src = try readSrc(gpa, io, args.counter_src, "build.zig.zon");
    defer gpa.free(zon_src);
    const zon_out = try rewriteZon(gpa, zon_src, zon_path_from_scratch);
    defer gpa.free(zon_out);

    // ---- scratch dirs + (2) keys ----
    cwd.deleteTree(io, scratch_root) catch {};
    var dirs: [n_nodes][]u8 = undefined;
    var dirs_made: usize = 0;
    defer for (dirs[0..dirs_made]) |d| gpa.free(d);
    var pks: [n_nodes][64]u8 = undefined;
    for (0..n_nodes) |i| {
        dirs[i] = try std.fmt.allocPrint(gpa, "{s}/{s}/node{d}", .{ root, scratch_root, i });
        dirs_made += 1;
        var d = cwd.createDirPathOpen(io, dirs[i], .{}) catch |err| {
            std.debug.print("[example-smoke] cannot create scratch dir {s}: {t}\n", .{ dirs[i], err });
            return err;
        };
        defer d.close(io);
        try d.createDirPath(io, "src");
        const key_path = try std.fmt.allocPrint(gpa, "{s}/slcp.key", .{dirs[i]});
        defer gpa.free(key_path);
        const kp = slcp.keys.createNew(io, key_path) catch |err| {
            std.debug.print("[example-smoke] cannot mint {s}: {t}\n", .{ key_path, err });
            return err;
        };
        pks[i] = std.fmt.bytesToHex(kp.public_key, .lower);
    }

    // ---- (3) the five-line rewrite per node ----
    for (0..n_nodes) |i| {
        var d = try cwd.openDir(io, dirs[i], .{});
        defer d.close(io);
        const main_out = rewriteMain(gpa, main_src, &pks, i) catch |err| {
            std.debug.print("[example-smoke] {s}/src/main.zig: the five deployment lines did not match exactly once: {t}\n", .{ args.counter_src, err });
            return err;
        };
        defer gpa.free(main_out);
        writeFile(io, d, "src/main.zig", main_out) catch |err| {
            std.debug.print("[example-smoke] cannot write {s}/src/main.zig: {t}\n", .{ dirs[i], err });
            return err;
        };
        try writeFile(io, d, "build.zig", build_src);
        try writeFile(io, d, "build.zig.zon", zon_out);
    }

    // ---- (4) nested consumer builds (sequential; shared local cache) ----
    var env = try init.environ_map.clone(gpa);
    defer env.deinit();
    if (env.get("ZIG_LOCAL_PKG_DIR") == null) {
        const pkg_dir = try std.fmt.allocPrint(gpa, "{s}/zig-pkg", .{root});
        defer gpa.free(pkg_dir);
        try env.put("ZIG_LOCAL_PKG_DIR", pkg_dir);
    }
    const cache_dir = try std.fmt.allocPrint(gpa, "{s}/.zig-cache", .{root});
    defer gpa.free(cache_dir);
    for (0..n_nodes) |i| {
        std.debug.print("[example-smoke] building node{d} (zig build -Doptimize=ReleaseSafe in {s})\n", .{ i, dirs[i] });
        const res = try std.process.run(gpa, io, .{
            .argv = &.{ args.zig.?, "build", "-Doptimize=ReleaseSafe", "--cache-dir", cache_dir },
            .cwd = .{ .path = dirs[i] },
            .environ_map = &env,
        });
        defer gpa.free(res.stdout);
        defer gpa.free(res.stderr);
        if (!res.term.success()) {
            std.debug.print("[example-smoke] nested build of node{d} failed ({any}):\n{s}\n", .{ i, res.term, res.stderr });
            return error.NestedBuildFailed;
        }
    }
    if (args.build_only) {
        std.debug.print("[example-smoke] build-only: {d} consumer builds OK\n", .{n_nodes});
        if (!args.keep) cwd.deleteTree(io, scratch_root) catch {};
        return;
    }

    // ---- (5) run the three counters ----
    var procs: [n_nodes]*NodeProc = undefined;
    var procs_made: usize = 0;
    defer for (procs[0..procs_made]) |p| p.destroy();
    for (0..n_nodes) |i| {
        procs[i] = try NodeProc.create(gpa, io, i, dirs[i]);
        procs_made += 1;
    }
    for (procs) |p| p.spawn() catch |err| {
        std.debug.print("[example-smoke] cannot spawn {s}: {t}\n", .{ p.exe, err });
        return err;
    };

    const restart_at = @min(restart_at_count, args.slots);
    var restarted = false;
    var agreed: std.AutoHashMapUnmanaged(u64, u64) = .empty;
    defer agreed.deinit(gpa);
    const max_ticks = args.deadline_s * 1000 / tick_ms;
    var ticks: u64 = 0;
    var last_report_tick: u64 = 0;
    while (true) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(tick_ms)), .awake);
        ticks += 1;

        var all_done = true;
        var min_count: u64 = std.math.maxInt(u64);
        var failure: ?anyerror = null;
        for (procs) |p| {
            p.mu.lockUncancelable(io);
            defer p.mu.unlock(io);
            if (p.bad) |line| {
                std.debug.print("[example-smoke] node{d} printed a slot/count mismatch: {s}\n", .{ p.index, line });
                failure = error.CountMismatch;
            }
            if (p.eof and !p.expect_eof) {
                std.debug.print("[example-smoke] node{d} exited before reaching {d} slots\n", .{ p.index, args.slots });
                failure = error.ChildExitedEarly;
            }
            var it = p.counts.iterator();
            while (it.next()) |e| {
                if (agreed.get(e.key_ptr.*)) |prev| {
                    if (prev != e.value_ptr.*) {
                        std.debug.print("[example-smoke] disagreement on slot {d}: node{d} says {d}, an earlier node said {d}\n", .{ e.key_ptr.*, p.index, e.value_ptr.*, prev });
                        failure = error.Disagreement;
                    }
                } else {
                    try agreed.put(gpa, e.key_ptr.*, e.value_ptr.*);
                }
            }
            if (p.max_count < args.slots) all_done = false;
            min_count = @min(min_count, p.max_count);
        }
        if (failure) |err| {
            for (procs) |p| p.dumpTail();
            return err;
        }

        if (!restarted) {
            const p0 = procs[0];
            p0.mu.lockUncancelable(io);
            const c0 = p0.max_count;
            p0.mu.unlock(io);
            if (c0 >= restart_at) {
                std.debug.print("[example-smoke] node0 reached count {d}: SIGKILL + restart from the same data_dir\n", .{c0});
                p0.mu.lockUncancelable(io);
                p0.expect_eof = true;
                p0.mu.unlock(io);
                p0.stop();
                try p0.spawn(); // resets max_count: node0 must print `slots` again itself
                restarted = true;
                all_done = false;
            }
        }

        if (all_done and restarted) {
            var buf: [96]u8 = undefined;
            const line = try evidenceLine(&buf, n_nodes, args.slots, min_count);
            var out_buf: [256]u8 = undefined;
            var out = std.Io.File.stdout().writerStreaming(io, &out_buf);
            try out.interface.print("{s}\n", .{line});
            try out.interface.flush();
            std.debug.print("[example-smoke] OK after {d} ms\n", .{ticks * tick_ms});
            break;
        }

        if (ticks - last_report_tick >= 10_000 / tick_ms) {
            last_report_tick = ticks;
            var counts: [n_nodes]u64 = undefined;
            for (procs, 0..) |p, i| {
                p.mu.lockUncancelable(io);
                counts[i] = p.max_count;
                p.mu.unlock(io);
            }
            std.debug.print("[example-smoke] t={d}s counts={any} restarted={}\n", .{ ticks * tick_ms / 1000, counts, restarted });
        }
        if (ticks >= max_ticks) {
            std.debug.print("[example-smoke] deadline of {d} s expired\n", .{args.deadline_s});
            for (procs) |p| p.dumpTail();
            return error.Deadline;
        }
    }

    for (procs) |p| p.stop();
    if (!args.keep) cwd.deleteTree(io, scratch_root) catch {};
}

// ---------------------------------------------------------------------------
// Tests (run from the repo root: `zig build example-smoke-tests`, part of `test`)
// ---------------------------------------------------------------------------

const testing = std.testing;

// Non-vacuity: this reads the REAL examples/counter/src/main.zig. Changing
// any of the five deployment lines there (a different port, a re-flowed
// `.peers` line, a fourth key) makes `rewriteMain` return PatternMissing —
// red — and the two explicit PatternMissing/PatternAmbiguous arms pin that
// the "exactly once" rule is enforced, not just hoped for.
test "rewriter: each of the five deployment lines matches the real main.zig exactly once; missing / doubled patterns are errors" {
    const gpa = testing.allocator;
    const io = testing.io;
    const src = try std.Io.Dir.cwd().readFileAlloc(io, "examples/counter/src/main.zig", gpa, .limited(1 << 20));
    defer gpa.free(src);

    var pks: [n_nodes][64]u8 = undefined;
    for (&pks, 0..) |*pk, i| pk.* = @splat('a' + @as(u8, @intCast(i)));
    const out = try rewriteMain(gpa, src, &pks, 1);
    defer gpa.free(out);

    // Every frozen line is gone from the output, exactly once in the input.
    for (pk_lines) |l| {
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, src, l));
        try testing.expectEqual(@as(usize, 0), std.mem.count(u8, out, l));
    }
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, src, port_line));
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, out, port_line));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, src, peers_line));
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, out, peers_line));
    // …and the replacements are in: node1 listens on 47312 and dials 0 and 2.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n        .listen_port = 47312,\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\n        .peers = &.{ \"127.0.0.1:47311\", \"127.0.0.1:47313\" },\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "\nconst pk_b = slcp.nodeId(\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\");\n"));
    // Only those five lines changed: same line count, five differing lines.
    var a_it = std.mem.splitScalar(u8, src, '\n');
    var b_it = std.mem.splitScalar(u8, out, '\n');
    var differing: usize = 0;
    while (a_it.next()) |la| {
        const lb = b_it.next() orelse return error.LineCountChanged;
        if (!std.mem.eql(u8, la, lb)) differing += 1;
    }
    try testing.expect(b_it.next() == null);
    try testing.expectEqual(@as(usize, 5), differing);

    // The exactly-once rule.
    try testing.expectError(error.PatternMissing, replaceLineOnce(gpa, src, "        .listen_port = 7312,", "x"));
    const doubled = try std.fmt.allocPrint(gpa, "{s}\n{s}\n", .{ port_line, port_line });
    defer gpa.free(doubled);
    try testing.expectError(error.PatternAmbiguous, replaceLineOnce(gpa, doubled, port_line, "x"));
}

// Non-vacuity: the zon rewrite must re-point the path dep (exactly once) to
// where the repo sits relative to a scratch dir, and leave a URL-pinned zon
// alone.
test "rewriter: build.zig.zon path dep → scratch-relative root once; a zon without it is untouched" {
    const gpa = testing.allocator;
    const io = testing.io;
    const src = try std.Io.Dir.cwd().readFileAlloc(io, "examples/counter/build.zig.zon", gpa, .limited(1 << 16));
    defer gpa.free(src);
    const out = try rewriteZon(gpa, src, zon_path_from_scratch);
    defer gpa.free(out);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, src, ".path = \"../..\""));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, ".slcp = .{ .path = \"../../..\" },"));
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, out, ".path = \"../..\" "));
    const pinned = ".{ .dependencies = .{ .slcp = .{ .url = \"https://x/v0.1.0.tar.gz\", .hash = \"h\" } } }";
    const same = try rewriteZon(gpa, pinned, "/abs/repo");
    defer gpa.free(same);
    try testing.expectEqualStrings(pinned, same);
}

// Non-vacuity: the evidence literal is what `just preflight` greps; a typo in
// the formatter (or the parser's `slot N: count = C` shape drifting from the
// program's print) goes red here before it goes red in preflight.
test "evidence line and slot-line parser" {
    var buf: [96]u8 = undefined;
    try testing.expectEqualStrings("[example-smoke] nodes=3 slots=20 count=20", try evidenceLine(&buf, 3, 20, 20));
    const p = parseSlotLine("slot 7: count = 7").?;
    try testing.expectEqual(@as(u64, 7), p.slot);
    try testing.expectEqual(@as(u64, 7), p.count);
    try testing.expect(parseSlotLine("info(slcp_node): peer 1 up (1 live connection(s); 2 peer(s) configured)") == null);
    try testing.expect(parseSlotLine("slot x: count = 7") == null);
}

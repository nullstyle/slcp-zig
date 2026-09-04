//! registry-smoke — examples/registry run for real
//! (docs/examples-roadmap.md "E1 — Registry" acceptance gates).
//!
//! Builds `examples/registry` ONCE as a consumer package — a nested
//! `zig build -Doptimize=ReleaseSafe` of a scratch copy with this repo as a
//! path dependency — then runs three `registry node` processes over loopback
//! (listen 47411..47413, RPC 47421..47423) and drives them through the real
//! `registry` CLI exactly as a user would: alice claims a name, bob's
//! conflicting claim is accepted at submit and loses at apply on every node,
//! set / transfer / release apply everywhere, `head` hashes agree across
//! nodes at the same slot, node2 is SIGKILLed and restarted from its
//! snapshot + journal and catches up to the same hash, and a transaction
//! submitted to the restarted node lands everywhere. It is then killed for
//! at least 201 slots, restored from a quorum-certified history checkpoint inside
//! the 16-slot answering window, and shown to be a necessary voter for the
//! exact next transaction-bearing slot. Before the first crash the
//! nodes form the deliberate line node2→node1→node0. One transaction is
//! submitted only to nomination-disabled node2; `head pending=1` proves it
//! crossed one and two overlay hops while both survivors remain at slot S,
//! then their `slot S+1: txs=1` lines prove it survived node2's SIGKILL and
//! landed in exactly the next slot. The first restart gets a second recovery
//! peer because consensus envelopes are not relayed across that line. For the
//! history restart that peer is dead: node2 has only node1, which was proved
//! unable to advance alone. Every wait is a bounded state poll rather than a
//! fixed sleep.
//!
//! The scratch copy is the published example with ONE line rewritten — the
//! `.path = "../.."` dependency in build.zig.zon, re-pointed at the repo from
//! `.zig-cache/registry-smoke/build/` — and that needle must match exactly
//! once (a drifted example is a red smoke, not a silently vacuous one).
//!
//! Evidence line on success (stdout):
//! `[registry-smoke] nodes=3 txs=8 slots=N head=<hex16>`.
//!
//! argv: `--zig <path>` (required; the build step passes its own zig)
//! `[--deadline-s S=300] [--build-only] [--keep]
//! [--registry-src <dir>=examples/registry]`. Run from the repo root (the
//! build step pins cwd). Scratch lives under `.zig-cache/registry-smoke/`
//! (`build/`, `node{0,1,2}/`, the key files, `quorum.json`) and is removed
//! afterwards unless `--keep`; a failed run always leaves it for inspection.
//!
//! Environment: the nested build inherits this process's environment.
//! `ZIG_LOCAL_PKG_DIR` is pointed at `<repo>/zig-pkg` when unset, so the
//! nested build reuses the packages the root build already fetched instead
//! of fetching capnp-zig's dependency tree again. The nested build gets a
//! scratch-local Zig cache: sharing one local cache among different build
//! roots can replay another example's cached build graph (for example,
//! installing `counter` here instead of `registry`).

const std = @import("std");
const slcp = @import("slcp");

pub const n_nodes: usize = 3;
pub const listen_base: u16 = 47411;
pub const rpc_base: u16 = 47421;
/// The registry network passphrase every node and client is given.
pub const network = "registry-smoke";
/// Transactions the script submits (the `txs=` field of the evidence line).
pub const n_txs: u64 = 8;
const default_deadline_s: u64 = 300;
const default_registry_src = "examples/registry";
const scratch_root = ".zig-cache/registry-smoke";
const tail_lines: usize = 20;
const line_buf_bytes: usize = 64 * 1024;
/// Poll cadence and bounds (ms). Every wait is bounded on its own; the whole
/// run (from the first spawn) is bounded by `--deadline-s`.
const poll_ms: u64 = 200;
const poll_bound_ms: u64 = 90_000;
const history_bound_ms: u64 = 180_000;
const ready_bound_ms: u64 = 60_000;
/// One CLI invocation (a TCP round trip on loopback) may not hang the smoke.
const cli_timeout_ms: u64 = 10_000;
/// The head-agreement sweep keeps sampling at least this long.
const agreement_min_ms: u64 = 3_000;
const report_every_ms: u64 = 10_000;
const all_mask: u8 = (1 << n_nodes) - 1;
/// Busy slots stay open long enough for the smoke to observe propagated
/// pending state before nomination. Idle heartbeats are deliberately fast so
/// a 201-slot history outage does not turn this into an excessive sleep.
/// The combination also pins the production cadence rule: an idle heartbeat
/// must NOT bypass `min-slot-ms` once a transaction is pending.
const survivor_min_slot_ms = "5000";
const survivor_heartbeat_ms = "500";
/// Pending must remain at S past an entire idle-heartbeat deadline. The old
/// `(pending && busy_min) || heartbeat` bug advances during this interval.
const pending_cadence_guard_ms: u64 = 1000;
/// The history-rejoining node must co-vote with the sole survivor through the
/// short retained tail, but a one-second heartbeat leaves a deterministic
/// window in which the harness can observe H and submit tx8 for exactly H+1.
const rejoin_heartbeat_ms = "1000";
const disabled_cadence_ms = "18446744073709551615";
const checkpoint_every = "8";
const absent_slots: u64 = 201;
const answering_window: u64 = 16;
const stable_head_ms: u64 = 1000;

pub fn listenPort(i: usize) u16 {
    return listen_base + @as(u16, @intCast(i));
}

pub fn rpcPort(i: usize) u16 {
    return rpc_base + @as(u16, @intCast(i));
}

fn bit(i: usize) u8 {
    return @as(u8, 1) << @intCast(i);
}

// ---------------------------------------------------------------------------
// The RPC / CLI reply grammar (roadmap §3.10, §3.11) — one line each
// ---------------------------------------------------------------------------

fn isLowerHex(s: []const u8) bool {
    for (s) |c| switch (c) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

fn hex64(s: []const u8) ?[64]u8 {
    if (s.len != 64 or !isLowerHex(s)) return null;
    return s[0..64].*;
}

fn trimLine(line: []const u8) []const u8 {
    return std.mem.trimEnd(u8, line, "\r\n");
}

const Kv = struct { key: []const u8, val: []const u8 };

/// A `key=value` token, or null for a token without `=`.
fn kv(tok: []const u8) ?Kv {
    const eq = std.mem.indexOfScalar(u8, tok, '=') orelse return null;
    return .{ .key = tok[0..eq], .val = tok[eq + 1 ..] };
}

pub const Head = struct {
    slot: u64,
    hash: [64]u8,
    accounts: u64,
    names: u64,
    pending: u64,
    network: [64]u8,
};

/// `head slot=<n> hash=<hex64> accounts=<n> names=<n> pending=<n> network=<hex64>`,
/// or null for anything else. Every field is required and strictly typed
/// (lower-case hex of exactly 64 chars); unknown extra fields are ignored.
pub fn parseHead(raw: []const u8) ?Head {
    var it = std.mem.tokenizeScalar(u8, trimLine(raw), ' ');
    if (!std.mem.eql(u8, it.next() orelse return null, "head")) return null;
    var slot: ?u64 = null;
    var hash: ?[64]u8 = null;
    var accounts: ?u64 = null;
    var names: ?u64 = null;
    var pending: ?u64 = null;
    var net: ?[64]u8 = null;
    while (it.next()) |tok| {
        const f = kv(tok) orelse return null;
        if (std.mem.eql(u8, f.key, "slot")) {
            slot = std.fmt.parseInt(u64, f.val, 10) catch return null;
        } else if (std.mem.eql(u8, f.key, "hash")) {
            hash = hex64(f.val) orelse return null;
        } else if (std.mem.eql(u8, f.key, "accounts")) {
            accounts = std.fmt.parseInt(u64, f.val, 10) catch return null;
        } else if (std.mem.eql(u8, f.key, "names")) {
            names = std.fmt.parseInt(u64, f.val, 10) catch return null;
        } else if (std.mem.eql(u8, f.key, "pending")) {
            pending = std.fmt.parseInt(u64, f.val, 10) catch return null;
        } else if (std.mem.eql(u8, f.key, "network")) {
            net = hex64(f.val) orelse return null;
        }
    }
    return .{
        .slot = slot orelse return null,
        .hash = hash orelse return null,
        .accounts = accounts orelse return null,
        .names = names orelse return null,
        .pending = pending orelse return null,
        .network = net orelse return null,
    };
}

pub const Entry = struct {
    name: []const u8,
    owner: [64]u8,
    /// Lower-case hex of the raw value bytes (empty right after a claim).
    value: []const u8,
};

pub const GetReply = union(enum) { none, entry: Entry };

/// `entry name=<name> owner=<hex64> value=<hex>` | `none`, or null for
/// anything else. The slices point into `raw`.
pub fn parseGet(raw: []const u8) ?GetReply {
    const line = trimLine(raw);
    if (std.mem.eql(u8, line, "none")) return .none;
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    if (!std.mem.eql(u8, it.next() orelse return null, "entry")) return null;
    var name: ?[]const u8 = null;
    var owner: ?[64]u8 = null;
    var value: ?[]const u8 = null;
    while (it.next()) |tok| {
        const f = kv(tok) orelse return null;
        if (std.mem.eql(u8, f.key, "name")) {
            if (f.val.len == 0) return null;
            name = f.val;
        } else if (std.mem.eql(u8, f.key, "owner")) {
            owner = hex64(f.val) orelse return null;
        } else if (std.mem.eql(u8, f.key, "value")) {
            if (f.val.len % 2 != 0 or !isLowerHex(f.val)) return null;
            value = f.val;
        }
    }
    return .{ .entry = .{
        .name = name orelse return null,
        .owner = owner orelse return null,
        .value = value orelse return null,
    } };
}

pub const SubmitReply = union(enum) { ok: [64]u8, err: []const u8 };

/// `ok txid=<hex64>` | `err <code> <text>`, or null for anything else. The
/// error arm carries the code (`bad_seq`, `duplicate`, …).
pub fn parseSubmit(raw: []const u8) ?SubmitReply {
    var it = std.mem.tokenizeScalar(u8, trimLine(raw), ' ');
    const verb = it.next() orelse return null;
    if (std.mem.eql(u8, verb, "ok")) {
        const f = kv(it.next() orelse return null) orelse return null;
        if (!std.mem.eql(u8, f.key, "txid")) return null;
        return .{ .ok = hex64(f.val) orelse return null };
    }
    if (std.mem.eql(u8, verb, "err")) {
        return .{ .err = it.next() orelse return null };
    }
    return null;
}

pub const AccountReply = struct { key: [64]u8, seq: u64 };

/// `account key=<hex64> seq=<n>` (seq=0 when unknown), or null.
pub fn parseAccount(raw: []const u8) ?AccountReply {
    var it = std.mem.tokenizeScalar(u8, trimLine(raw), ' ');
    if (!std.mem.eql(u8, it.next() orelse return null, "account")) return null;
    var key: ?[64]u8 = null;
    var seq: ?u64 = null;
    while (it.next()) |tok| {
        const f = kv(tok) orelse return null;
        if (std.mem.eql(u8, f.key, "key")) {
            key = hex64(f.val) orelse return null;
        } else if (std.mem.eql(u8, f.key, "seq")) {
            seq = std.fmt.parseInt(u64, f.val, 10) catch return null;
        }
    }
    return .{ .key = key orelse return null, .seq = seq orelse return null };
}

pub const SlotLine = struct { slot: u64, txs: u64, head16: ?[16]u8 };

/// A node's stderr `slot N: txs=K ok=J head=<hex16>` line (the `head=` field
/// is taken when present and well-formed), or null for any other line.
pub fn parseSlotLine(raw: []const u8) ?SlotLine {
    const line = trimLine(raw);
    const prefix = "slot ";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    const rest = line[prefix.len..];
    const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    const slot = std.fmt.parseInt(u64, rest[0..colon], 10) catch return null;
    var txs: ?u64 = null;
    var head16: ?[16]u8 = null;
    var it = std.mem.tokenizeScalar(u8, rest[colon + 1 ..], ' ');
    while (it.next()) |tok| {
        const f = kv(tok) orelse continue;
        if (std.mem.eql(u8, f.key, "txs")) {
            txs = std.fmt.parseInt(u64, f.val, 10) catch return null;
        } else if (std.mem.eql(u8, f.key, "head") and f.val.len == 16 and isLowerHex(f.val)) {
            head16 = f.val[0..16].*;
        }
    }
    return .{ .slot = slot, .txs = txs orelse return null, .head16 = head16 };
}

pub const CheckpointKind = enum { signed, certified };
pub const CheckpointLine = struct { slot: u64, kind: CheckpointKind };

/// The machine-readable prefix of the registry's checkpoint progress log:
/// `history checkpoint slot N signed|certified ...`. The suffix is diagnostic
/// and may grow; the first five tokens are the smoke contract.
pub fn parseCheckpointLine(raw: []const u8) ?CheckpointLine {
    var it = std.mem.tokenizeScalar(u8, trimLine(raw), ' ');
    if (!std.mem.eql(u8, it.next() orelse return null, "history")) return null;
    if (!std.mem.eql(u8, it.next() orelse return null, "checkpoint")) return null;
    if (!std.mem.eql(u8, it.next() orelse return null, "slot")) return null;
    const slot = std.fmt.parseInt(u64, it.next() orelse return null, 10) catch return null;
    const status = it.next() orelse return null;
    const kind: CheckpointKind = if (std.mem.eql(u8, status, "signed"))
        .signed
    else if (std.mem.eql(u8, status, "certified"))
        .certified
    else
        return null;
    return .{ .slot = slot, .kind = kind };
}

/// Extract the exact checkpoint slot from the normal node startup line. A
/// local `snapshot` boot must not satisfy this witness.
pub fn parseHistoryBootSlot(raw: []const u8) ?u64 {
    const marker = "starting from history checkpoint at slot ";
    const line = trimLine(raw);
    const at = std.mem.indexOf(u8, line, marker) orelse return null;
    const number = line[at + marker.len ..];
    if (number.len == 0) return null;
    return std.fmt.parseInt(u64, number, 10) catch null;
}

/// The two arithmetic acceptance boundaries of the E2b witness. Written as a
/// pure predicate so off-by-one weakening goes red in unit tests.
pub fn historyWitnessOk(absent_at: u64, stable_head: u64, checkpoint: u64) bool {
    if (stable_head < absent_at or checkpoint > stable_head) return false;
    return stable_head - absent_at >= absent_slots and stable_head - checkpoint < answering_window;
}

// ---------------------------------------------------------------------------
// The consumer copy
// ---------------------------------------------------------------------------

/// In build.zig.zon: the path dependency (examples/registry's own location).
const zon_path_needle = ".path = \"../..\"";

/// Where the repo root sits relative to the scratch build dir
/// `<repo>/.zig-cache/registry-smoke/build`: `zig build` refuses an
/// absolute `.path` ("expected path relative to build root").
pub const zon_path_from_scratch = "../../..";

pub const RewriteError = error{PatternAmbiguous} || std.mem.Allocator.Error;

/// `build.zig.zon` with `.path = "../.."` pointed at `root`. The needle must
/// occur at most once (twice is `PatternAmbiguous`); a zon without it (a
/// URL-pinned consumer copy handed in via `--registry-src`) is returned
/// unchanged.
pub fn rewriteZon(gpa: std.mem.Allocator, src: []const u8, root: []const u8) RewriteError![]u8 {
    const at = std.mem.indexOf(u8, src, zon_path_needle) orelse return gpa.dupe(u8, src);
    if (std.mem.indexOfPos(u8, src, at + zon_path_needle.len, zon_path_needle) != null) return error.PatternAmbiguous;
    return std.fmt.allocPrint(gpa, "{s}.path = \"{s}\"{s}", .{ src[0..at], root, src[at + zon_path_needle.len ..] });
}

/// The success evidence line (`just preflight` greps its literal prefix).
pub fn evidenceLine(buf: []u8, nodes: usize, txs: u64, slots: u64, head16: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "[registry-smoke] nodes={d} txs={d} slots={d} head={s}", .{ nodes, txs, slots, head16 });
}

// ---------------------------------------------------------------------------
// Node processes
// ---------------------------------------------------------------------------

const checkpoint_signed_bit: u8 = 1 << 0;
const checkpoint_certified_bit: u8 = 1 << 1;

/// One `registry node` process: its scratch dir (cwd: `--data-dir data` is
/// relative), its argv (identical across restarts), the child, and a reader
/// thread over the child's stderr (the `slot N:` lines and the library's
/// logs). Heap-allocated and never moved: `File.Reader` embeds an interface
/// reached by pointer, and the reader thread holds `*NodeProc`.
const NodeProc = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    index: usize,
    dir: []const u8,
    argv: [][]const u8,
    child: ?std.process.Child = null,
    thread: ?std.Thread = null,
    rdr_buf: []u8,
    rdr: std.Io.File.Reader = undefined,

    mu: std.Io.Mutex = .init,
    // ---- guarded by mu ----
    /// Highest slot printed by the CURRENT process (reset on restart).
    max_slot: u64 = 0,
    /// slot → the printed `head=` prefix, across restarts (cross-node
    /// agreement is checked against this on the main thread).
    slot_heads: std.AutoHashMapUnmanaged(u64, [16]u8) = .empty,
    /// slot → the number of transactions printed for that externalization.
    /// Kept across restarts so the crash-survival proof can name the exact
    /// successor slot and show that it carried precisely the flooded tx.
    slot_txs: std.AutoHashMapUnmanaged(u64, u64) = .empty,
    /// checkpoint slot → observed progress bits. `certified` also implies
    /// this validator has emitted its own signed attestation.
    history_checkpoints: std.AutoHashMapUnmanaged(u64, u8) = .empty,
    /// Set only by the explicit `starting from history checkpoint` boot log.
    history_boot_slot: ?u64 = null,
    eof: bool = false,
    expect_eof: bool = false,
    /// The first line that contradicted an earlier print of the same slot by
    /// this node (head or transaction count).
    bad: ?[]u8 = null,
    tail: [tail_lines]?[]u8 = @splat(null),
    tail_next: usize = 0,

    fn create(gpa: std.mem.Allocator, io: std.Io, index: usize, dir: []const u8, argv: []const []const u8) !*NodeProc {
        const self = try gpa.create(NodeProc);
        errdefer gpa.destroy(self);
        const rdr_buf = try gpa.alloc(u8, line_buf_bytes);
        errdefer gpa.free(rdr_buf);
        const dir_copy = try gpa.dupe(u8, dir);
        errdefer gpa.free(dir_copy);
        const owned = try gpa.alloc([]const u8, argv.len);
        var made: usize = 0;
        errdefer {
            for (owned[0..made]) |s| gpa.free(s);
            gpa.free(owned);
        }
        for (argv, 0..) |a, k| {
            owned[k] = try gpa.dupe(u8, a);
            made += 1;
        }
        self.* = .{ .gpa = gpa, .io = io, .index = index, .dir = dir_copy, .argv = owned, .rdr_buf = rdr_buf };
        return self;
    }

    fn destroy(self: *NodeProc) void {
        self.stop();
        const gpa = self.gpa;
        for (&self.tail) |*t| if (t.*) |s| gpa.free(s);
        if (self.bad) |b| gpa.free(b);
        self.slot_heads.deinit(gpa);
        self.slot_txs.deinit(gpa);
        self.history_checkpoints.deinit(gpa);
        for (self.argv) |s| gpa.free(s);
        gpa.free(self.argv);
        gpa.free(self.dir);
        gpa.free(self.rdr_buf);
        gpa.destroy(self);
    }

    /// Spawn the node in its scratch dir with stderr piped to a fresh reader
    /// thread. The same argv every time: a restart is the identical command.
    fn spawn(self: *NodeProc) !void {
        std.debug.assert(self.child == null and self.thread == null);
        self.mu.lockUncancelable(self.io);
        self.eof = false;
        self.expect_eof = false;
        self.max_slot = 0;
        self.history_boot_slot = null;
        self.mu.unlock(self.io);
        self.child = try std.process.spawn(self.io, .{
            .argv = self.argv,
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

    /// Add one configured dial before a restart. The flooding proof keeps a
    /// strict line; catch-up subsequently needs statements from two quorum
    /// members because consensus envelopes are not transitively relayed.
    fn appendPeer(self: *NodeProc, spec: []const u8) !void {
        std.debug.assert(self.child == null and self.thread == null);
        const grown = try self.gpa.alloc([]const u8, self.argv.len + 2);
        errdefer self.gpa.free(grown);
        const flag = try self.gpa.dupe(u8, "--peer");
        errdefer self.gpa.free(flag);
        const peer = try self.gpa.dupe(u8, spec);
        errdefer self.gpa.free(peer);
        @memcpy(grown[0..self.argv.len], self.argv);
        grown[self.argv.len] = flag;
        grown[self.argv.len + 1] = peer;
        self.gpa.free(self.argv);
        self.argv = grown;
    }

    /// Replace one `--flag value` pair in the owned argv, or append it when
    /// absent. Restarts deliberately change cadence and select a minimum
    /// checkpoint without rebuilding the rest of the process command.
    fn setFlagValue(self: *NodeProc, flag: []const u8, value: []const u8) !void {
        std.debug.assert(self.child == null and self.thread == null);
        for (self.argv, 0..) |arg, i| {
            if (!std.mem.eql(u8, arg, flag)) continue;
            if (i + 1 >= self.argv.len) return error.MalformedArgv;
            const replacement = try self.gpa.dupe(u8, value);
            self.gpa.free(self.argv[i + 1]);
            self.argv[i + 1] = replacement;
            return;
        }
        const grown = try self.gpa.alloc([]const u8, self.argv.len + 2);
        errdefer self.gpa.free(grown);
        const owned_flag = try self.gpa.dupe(u8, flag);
        errdefer self.gpa.free(owned_flag);
        const owned_value = try self.gpa.dupe(u8, value);
        errdefer self.gpa.free(owned_value);
        @memcpy(grown[0..self.argv.len], self.argv);
        grown[self.argv.len] = owned_flag;
        grown[self.argv.len + 1] = owned_value;
        self.gpa.free(self.argv);
        self.argv = grown;
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
        const checkpoint = parseCheckpointLine(line);
        const history_boot = parseHistoryBootSlot(line);
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const copy = self.gpa.dupe(u8, line) catch return;
        if (self.tail[self.tail_next]) |old| self.gpa.free(old);
        self.tail[self.tail_next] = copy;
        self.tail_next = (self.tail_next + 1) % tail_lines;
        if (checkpoint) |event| {
            const gop = self.history_checkpoints.getOrPut(self.gpa, event.slot) catch return;
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* |= switch (event.kind) {
                .signed => checkpoint_signed_bit,
                .certified => checkpoint_signed_bit | checkpoint_certified_bit,
            };
        }
        if (history_boot) |slot| {
            if (self.history_boot_slot) |old| {
                if (old != slot and self.bad == null) self.bad = self.gpa.dupe(u8, line) catch null;
            } else {
                self.history_boot_slot = slot;
            }
        }
        const p = parsed orelse return;
        if (p.slot > self.max_slot) self.max_slot = p.slot;
        if (self.slot_txs.get(p.slot)) |prev| {
            if (prev != p.txs and self.bad == null) self.bad = self.gpa.dupe(u8, line) catch null;
        } else {
            self.slot_txs.put(self.gpa, p.slot, p.txs) catch {};
        }
        const h = p.head16 orelse return;
        if (self.slot_heads.get(p.slot)) |prev| {
            if (!std.mem.eql(u8, &prev, &h) and self.bad == null) self.bad = self.gpa.dupe(u8, line) catch null;
        } else {
            self.slot_heads.put(self.gpa, p.slot, h) catch {};
        }
    }

    fn maxSlot(self: *NodeProc) u64 {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.max_slot;
    }

    /// Print the last `tail_lines` stderr lines (oldest first).
    fn dumpTail(self: *NodeProc) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        std.debug.print("[registry-smoke] --- node{d} last {d} stderr lines ---\n", .{ self.index, tail_lines });
        for (0..tail_lines) |k| {
            const idx = (self.tail_next + k) % tail_lines;
            if (self.tail[idx]) |s| std.debug.print("  {s}\n", .{s});
        }
    }
};

// ---------------------------------------------------------------------------
// The cluster: three nodes, two clients, the CLI as the only probe
// ---------------------------------------------------------------------------

const Client = enum(usize) { alice, bob };
const client_names = [_][]const u8{ "alice", "bob" };
const n_clients = client_names.len;

/// A `head` answer folded into the slot → hash table: the bit mask says which
/// nodes reported it.
const HeadSeen = struct { hash: [64]u8, mask: u8 };
const LogHeadSeen = struct { head16: [16]u8, mask: u8 };

/// What a `get` poll waits for.
const GetWant = union(enum) {
    none,
    owner: [64]u8,
    value: []const u8,

    fn matches(self: GetWant, reply: ?GetReply) bool {
        const r = reply orelse return false;
        return switch (self) {
            .none => r == .none,
            .owner => |o| r == .entry and std.mem.eql(u8, &r.entry.owner, &o),
            .value => |v| r == .entry and std.mem.eql(u8, r.entry.value, v),
        };
    }
};

/// The first stdout line of one CLI run (owned), plus its whole stderr.
const CliReply = struct {
    exit0: bool,
    timed_out: bool,
    line: []u8,
    stderr: []u8,

    fn deinit(self: CliReply, gpa: std.mem.Allocator) void {
        gpa.free(self.line);
        gpa.free(self.stderr);
    }
};

fn firstLine(s: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, s, '\n') orelse s.len;
    return std.mem.trimEnd(u8, s[0..end], "\r");
}

fn clip(s: []const u8, n: usize) []const u8 {
    return if (s.len <= n) s else s[0..n];
}

fn elapsedMs(io: std.Io, since: std.Io.Timestamp) u64 {
    const d = since.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds();
    return if (d < 0) 0 else @intCast(d);
}

/// One bounded wait. `tick` sleeps a poll interval after checking the
/// processes, the whole-run deadline and this wait's own bound.
const Poll = struct {
    started: std.Io.Timestamp,
    bound_ms: u64,
    what: []const u8,

    fn init(io: std.Io, bound_ms: u64, what: []const u8) Poll {
        return .{ .started = std.Io.Timestamp.now(io, .awake), .bound_ms = bound_ms, .what = what };
    }

    fn elapsed(self: *const Poll, io: std.Io) u64 {
        return elapsedMs(io, self.started);
    }

    fn tick(self: *Poll, c: *Cluster) !void {
        return self.tickEvery(c, poll_ms);
    }

    fn tickEvery(self: *Poll, c: *Cluster, interval_ms: u64) !void {
        try c.checkProcs();
        try c.checkDeadline();
        if (self.elapsed(c.io) >= self.bound_ms) {
            std.debug.print("[registry-smoke] gave up after {d} ms waiting for: {s}\n", .{ self.bound_ms, self.what });
            c.dumpLastReplies();
            return error.PollBound;
        }
        c.maybeReport();
        try std.Io.sleep(c.io, std.Io.Duration.fromMilliseconds(@intCast(interval_ms)), .awake);
    }
};

const Cluster = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// Absolute scratch dir (the CLI's cwd).
    scratch: []const u8,
    /// The consumer-built `registry` binary (absolute).
    exe: []const u8,
    key_paths: [n_clients][]const u8,
    client_pk: [n_clients][64]u8,
    rpc: [n_nodes][]const u8,
    procs: [n_nodes]*NodeProc,
    started: std.Io.Timestamp,
    deadline_ms: u64,
    last_report: std.Io.Timestamp,
    /// Every `head` answer ever received: slot → hash + reporting nodes. A
    /// second hash for a slot is a fork.
    rpc_heads: std.AutoHashMapUnmanaged(u64, HeadSeen) = .empty,
    /// Every `slot N: … head=` stderr line, merged across nodes.
    log_heads: std.AutoHashMapUnmanaged(u64, LogHeadSeen) = .empty,
    /// The last CLI reply per node, for the bound-expiry diagnostic.
    last_reply: [n_nodes]?[]u8 = @splat(null),
    txs: u64 = 0,
    /// Distinct txids seen from `ok txid=…` replies (what `txs` counts).
    txids: std.ArrayList([64]u8) = .empty,

    fn deinit(self: *Cluster) void {
        self.txids.deinit(self.gpa);
        self.rpc_heads.deinit(self.gpa);
        self.log_heads.deinit(self.gpa);
        for (&self.last_reply) |*r| if (r.*) |s| self.gpa.free(s);
    }

    fn pk(self: *const Cluster, c: Client) [64]u8 {
        return self.client_pk[@backingInt(c)];
    }

    fn checkDeadline(self: *Cluster) !void {
        if (elapsedMs(self.io, self.started) >= self.deadline_ms) {
            std.debug.print("[registry-smoke] deadline of {d} s expired\n", .{self.deadline_ms / 1000});
            return error.Deadline;
        }
    }

    fn maybeReport(self: *Cluster) void {
        if (elapsedMs(self.io, self.last_report) < report_every_ms) return;
        self.last_report = std.Io.Timestamp.now(self.io, .awake);
        var slots: [n_nodes]u64 = undefined;
        for (self.procs, 0..) |p, i| slots[i] = p.maxSlot();
        std.debug.print("[registry-smoke] t={d}s txs={d} node slots={any}\n", .{ elapsedMs(self.io, self.started) / 1000, self.txs, slots });
    }

    /// A node that died unasked, contradicted itself, or printed a head for a
    /// slot another node printed differently is a failure.
    fn checkProcs(self: *Cluster) !void {
        for (self.procs) |p| {
            p.mu.lockUncancelable(self.io);
            defer p.mu.unlock(self.io);
            if (p.bad) |line| {
                std.debug.print("[registry-smoke] node{d} contradicted its own earlier evidence for a slot: {s}\n", .{ p.index, line });
                return error.NodeSelfContradiction;
            }
            if (p.eof and !p.expect_eof) {
                std.debug.print("[registry-smoke] node{d} exited unexpectedly\n", .{p.index});
                return error.ChildExitedEarly;
            }
            var it = p.slot_heads.iterator();
            while (it.next()) |e| {
                const gop = try self.log_heads.getOrPut(self.gpa, e.key_ptr.*);
                if (gop.found_existing) {
                    if (!std.mem.eql(u8, &gop.value_ptr.head16, e.value_ptr)) {
                        std.debug.print("[registry-smoke] fork in the logs at slot {d}: node{d} printed head={s}, an earlier node printed head={s}\n", .{ e.key_ptr.*, p.index, e.value_ptr, &gop.value_ptr.head16 });
                        return error.LogHeadDisagreement;
                    }
                    gop.value_ptr.mask |= bit(p.index);
                } else {
                    gop.value_ptr.* = .{ .head16 = e.value_ptr.*, .mask = bit(p.index) };
                }
            }
        }
    }

    fn dumpLastReplies(self: *Cluster) void {
        for (self.last_reply, 0..) |r, i| {
            if (r) |s| std.debug.print("[registry-smoke]   last reply via node{d}: {s}\n", .{ i, s });
        }
    }

    fn noteReply(self: *Cluster, node: usize, argv: []const []const u8, r: CliReply) void {
        const gpa = self.gpa;
        const cmd = std.mem.join(gpa, " ", argv[1..]) catch return;
        defer gpa.free(cmd);
        const s = std.fmt.allocPrint(gpa, "`{s}` exit0={} timed_out={} stdout=\"{s}\" stderr=\"{s}\"", .{
            clip(cmd, 160), r.exit0, r.timed_out, clip(r.line, 200), clip(firstLine(r.stderr), 200),
        }) catch return;
        if (self.last_reply[node]) |old| gpa.free(old);
        self.last_reply[node] = s;
    }

    /// Run the CLI once against node `node`'s RPC (argv[0] is the binary).
    /// A timeout is a reply with `timed_out`, not an error.
    fn cli(self: *Cluster, node: usize, argv: []const []const u8) !CliReply {
        const gpa = self.gpa;
        const res = std.process.run(gpa, self.io, .{
            .argv = argv,
            .cwd = .{ .path = self.scratch },
            .stdout_limit = .limited(1 << 16),
            .stderr_limit = .limited(1 << 16),
            .timeout = .{ .duration = .{ .raw = .fromMilliseconds(@intCast(cli_timeout_ms)), .clock = .awake } },
        }) catch |err| switch (err) {
            error.Timeout => {
                const line = try gpa.dupe(u8, "");
                errdefer gpa.free(line);
                const stderr = try gpa.dupe(u8, "");
                const r: CliReply = .{ .exit0 = false, .timed_out = true, .line = line, .stderr = stderr };
                self.noteReply(node, argv, r);
                return r;
            },
            else => return err,
        };
        defer gpa.free(res.stdout);
        errdefer gpa.free(res.stderr);
        const r: CliReply = .{
            .exit0 = res.term.success(),
            .timed_out = false,
            .line = try gpa.dupe(u8, firstLine(res.stdout)),
            .stderr = res.stderr,
        };
        self.noteReply(node, argv, r);
        return r;
    }

    /// One `head` RPC against node `i`, folded into `rpc_heads` (a second hash
    /// for a slot is a fork → error). Null when the CLI failed (RPC not up).
    fn queryHead(self: *Cluster, i: usize) !?Head {
        const r = try self.cli(i, &.{ self.exe, "head", "--rpc", self.rpc[i] });
        defer r.deinit(self.gpa);
        if (!r.exit0) return null;
        const h = parseHead(r.line) orelse {
            std.debug.print("[registry-smoke] unparseable head reply from node{d}: \"{s}\"\n", .{ i, r.line });
            return error.BadHeadReply;
        };
        const gop = try self.rpc_heads.getOrPut(self.gpa, h.slot);
        if (gop.found_existing) {
            if (!std.mem.eql(u8, &gop.value_ptr.hash, &h.hash)) {
                std.debug.print("[registry-smoke] fork at slot {d}: node{d} says hash={s}, an earlier node said {s}\n", .{ h.slot, i, &h.hash, &gop.value_ptr.hash });
                return error.HeadDisagreement;
            }
            gop.value_ptr.mask |= bit(i);
        } else {
            gop.value_ptr.* = .{ .hash = h.hash, .mask = bit(i) };
        }
        return h;
    }

    /// `head` against node `i`, retried until it answers.
    fn headRetry(self: *Cluster, i: usize, what: []const u8) !Head {
        var poll = Poll.init(self.io, poll_bound_ms, what);
        while (true) {
            if (try self.queryHead(i)) |h| return h;
            try poll.tick(self);
        }
    }

    /// Every node answers `head` (the RPC is up; consensus need not be).
    fn waitReady(self: *Cluster) !void {
        var poll = Poll.init(self.io, ready_bound_ms, "every node's RPC to answer `head`");
        var ready: [n_nodes]bool = @splat(false);
        while (true) {
            var all = true;
            for (0..n_nodes) |i| {
                if (ready[i]) continue;
                if (try self.queryHead(i)) |h| {
                    ready[i] = true;
                    std.debug.print("[registry-smoke] node{d} rpc up ({s}): slot={d} network={s}\n", .{ i, self.rpc[i], h.slot, h.network[0..16] });
                } else all = false;
            }
            if (all) return;
            try poll.tick(self);
        }
    }

    /// `registry submit --key <client> --rpc <node> <op…>` must print `ok`.
    /// Returns the txid; `txs` counts DISTINCT txids (the same transaction
    /// queued on two nodes — a deterministic signature — is one transaction).
    fn submit(self: *Cluster, client: Client, via: usize, op: []const []const u8) ![64]u8 {
        const gpa = self.gpa;
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.appendSlice(gpa, &.{ self.exe, "submit", "--key", self.key_paths[@backingInt(client)], "--rpc", self.rpc[via] });
        try argv.appendSlice(gpa, op);
        const op_text = try std.mem.join(gpa, " ", op);
        defer gpa.free(op_text);
        const r = try self.cli(via, argv.items);
        defer r.deinit(gpa);
        const parsed = if (r.exit0) parseSubmit(r.line) else null;
        if (parsed == null or parsed.? != .ok) {
            std.debug.print("[registry-smoke] submit refused: {s} `{s}` via node{d}: exit0={} timed_out={} stdout=\"{s}\" stderr=\"{s}\"\n", .{
                client_names[@backingInt(client)], op_text, via, r.exit0, r.timed_out, r.line, clip(r.stderr, 400),
            });
            return error.SubmitRefused;
        }
        const txid = parsed.?.ok;
        var seen = false;
        for (self.txids.items) |t| {
            if (std.mem.eql(u8, &t, &txid)) seen = true;
        }
        if (!seen) {
            try self.txids.append(gpa, txid);
            self.txs += 1;
        }
        std.debug.print("[registry-smoke] tx{d}: {s} `{s}` via node{d}: ok txid={s}{s}\n", .{ self.txs, client_names[@backingInt(client)], op_text, via, txid[0..16], if (seen) " (already queued elsewhere)" else "" });
        return txid;
    }

    fn getOn(self: *Cluster, i: usize, name: []const u8) !?GetReply {
        const r = try self.cli(i, &.{ self.exe, "get", "--rpc", self.rpc[i], name });
        defer r.deinit(self.gpa);
        if (!r.exit0) return null;
        // `parseGet` slices into the reply; re-materialize the owned parts.
        const reply = parseGet(r.line) orelse {
            std.debug.print("[registry-smoke] unparseable get reply from node{d}: \"{s}\"\n", .{ i, r.line });
            return error.BadGetReply;
        };
        return switch (reply) {
            .none => .none,
            .entry => |e| .{ .entry = .{
                .name = try self.gpa.dupe(u8, e.name),
                .owner = e.owner,
                .value = try self.gpa.dupe(u8, e.value),
            } },
        };
    }

    fn freeGet(self: *Cluster, reply: ?GetReply) void {
        const r = reply orelse return;
        switch (r) {
            .none => {},
            .entry => |e| {
                self.gpa.free(e.name);
                self.gpa.free(e.value);
            },
        }
    }

    /// Poll `get <name>` on `nodes` until every one of them matches `want`.
    fn waitGet(self: *Cluster, name: []const u8, want: GetWant, nodes: []const usize, what: []const u8) !void {
        var poll = Poll.init(self.io, poll_bound_ms, what);
        while (true) {
            var all_met = true;
            for (nodes) |i| {
                const reply = try self.getOn(i, name);
                defer self.freeGet(reply);
                if (!want.matches(reply)) all_met = false;
            }
            if (all_met) {
                std.debug.print("[registry-smoke] ok after {d} ms: {s}\n", .{ poll.elapsed(self.io), what });
                return;
            }
            try poll.tick(self);
        }
    }

    /// One-shot: every node's `get <name>` matches `want` right now.
    fn expectGetNow(self: *Cluster, name: []const u8, want: GetWant, nodes: []const usize, what: []const u8) !void {
        for (nodes) |i| {
            const reply = try self.getOn(i, name);
            defer self.freeGet(reply);
            if (!want.matches(reply)) {
                std.debug.print("[registry-smoke] wrong state on node{d}: {s}\n", .{ i, what });
                self.dumpLastReplies();
                return error.WrongState;
            }
        }
        std.debug.print("[registry-smoke] ok: {s}\n", .{what});
    }

    /// Poll `account <hex>` on `nodes` until every one reports exactly
    /// `want_seq`; a higher seq is an immediate failure (a double apply).
    fn waitAccountSeq(self: *Cluster, key_hex: [64]u8, want_seq: u64, nodes: []const usize, what: []const u8) !void {
        var poll = Poll.init(self.io, poll_bound_ms, what);
        while (true) {
            var all_met = true;
            for (nodes) |i| {
                const r = try self.cli(i, &.{ self.exe, "account", "--rpc", self.rpc[i], &key_hex });
                defer r.deinit(self.gpa);
                if (!r.exit0) {
                    all_met = false;
                    continue;
                }
                const a = parseAccount(r.line) orelse {
                    std.debug.print("[registry-smoke] unparseable account reply from node{d}: \"{s}\"\n", .{ i, r.line });
                    return error.BadAccountReply;
                };
                if (a.seq > want_seq) {
                    std.debug.print("[registry-smoke] node{d} reports seq={d} for {s}…, expected at most {d}\n", .{ i, a.seq, key_hex[0..16], want_seq });
                    return error.SequenceRanAhead;
                }
                if (a.seq != want_seq) all_met = false;
            }
            if (all_met) {
                std.debug.print("[registry-smoke] ok after {d} ms: {s}\n", .{ poll.elapsed(self.io), what });
                return;
            }
            try poll.tick(self);
        }
    }

    /// Poll `head` on node `i` until its slot is at least `min_slot`.
    fn waitHeadSlotAtLeast(self: *Cluster, i: usize, min_slot: u64, what: []const u8) !Head {
        var poll = Poll.init(self.io, poll_bound_ms, what);
        while (true) {
            if (try self.queryHead(i)) |h| {
                if (h.slot >= min_slot) {
                    std.debug.print("[registry-smoke] ok after {d} ms: {s} (node{d} at slot {d})\n", .{ poll.elapsed(self.io), what, i, h.slot });
                    return h;
                }
            }
            try poll.tick(self);
        }
    }

    /// Sample `head` from all three for at least `agreement_min_ms` and until
    /// some slot > 0 was reported by all three within this sweep. Equal
    /// hashes for equal slots are enforced by `queryHead` on every sample.
    fn headAgreement(self: *Cluster) !u64 {
        var poll = Poll.init(self.io, poll_bound_ms, "a slot reported by all three nodes with one hash");
        var fresh: std.AutoHashMapUnmanaged(u64, u8) = .empty;
        defer fresh.deinit(self.gpa);
        var samples: u64 = 0;
        while (true) {
            for (0..n_nodes) |i| {
                if (try self.queryHead(i)) |h| {
                    samples += 1;
                    const gop = try fresh.getOrPut(self.gpa, h.slot);
                    if (!gop.found_existing) gop.value_ptr.* = 0;
                    gop.value_ptr.* |= bit(i);
                }
            }
            var full: ?u64 = null;
            var it = fresh.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.* == all_mask and e.key_ptr.* > 0) full = @max(full orelse 0, e.key_ptr.*);
            }
            if (poll.elapsed(self.io) >= agreement_min_ms) {
                if (full) |slot| {
                    const seen = self.rpc_heads.get(slot).?;
                    std.debug.print("[registry-smoke] head agreement: slot {d} hash={s}… reported by all three ({d} samples, {d} distinct slots)\n", .{ slot, seen.hash[0..16], samples, fresh.count() });
                    return slot;
                }
            }
            try poll.tick(self);
        }
    }

    /// Wait until every named node reports the same head at or beyond
    /// `min_slot`, with exactly `want_pending` transactions queued. This is
    /// used to start the flooding proof immediately after a fresh idle close,
    /// leaving almost a full cadence interval in which to observe the queues.
    fn waitCommonHead(
        self: *Cluster,
        nodes: []const usize,
        min_slot: u64,
        want_pending: u64,
        what: []const u8,
    ) !Head {
        var poll = Poll.init(self.io, poll_bound_ms, what);
        while (true) {
            var common: ?Head = null;
            var all_met = true;
            for (nodes) |i| {
                const maybe = try self.queryHead(i);
                const h = maybe orelse {
                    all_met = false;
                    continue;
                };
                if (h.slot < min_slot or h.pending != want_pending) all_met = false;
                if (common) |first| {
                    if (h.slot != first.slot or !std.mem.eql(u8, &h.hash, &first.hash)) all_met = false;
                } else {
                    common = h;
                }
            }
            if (all_met) {
                const h = common orelse return error.NoNodes;
                std.debug.print("[registry-smoke] ok after {d} ms: {s} (slot {d}, pending={d}, head={s}…)\n", .{
                    poll.elapsed(self.io), what, h.slot, h.pending, h.hash[0..16],
                });
                return h;
            }
            try poll.tick(self);
        }
    }

    /// Prove application-message propagation before consensus can hide it:
    /// every node must expose the expected pending count while still exactly
    /// at `slot`, continuously past the idle-heartbeat deadline. Advancing
    /// past the observation slot is a hard failure, not a reason to weaken the
    /// assertion and accept eventual application. This is the red witness for
    /// an idle heartbeat incorrectly bypassing the busy minimum.
    fn waitPendingAtExactSlot(
        self: *Cluster,
        nodes: []const usize,
        slot: u64,
        want_pending: u64,
        what: []const u8,
    ) !void {
        var poll = Poll.init(self.io, poll_bound_ms, what);
        var all_since: ?std.Io.Timestamp = null;
        while (true) {
            var all_met = true;
            for (nodes) |i| {
                const maybe = try self.queryHead(i);
                const h = maybe orelse {
                    all_met = false;
                    continue;
                };
                if (h.slot > slot) {
                    std.debug.print("[registry-smoke] node{d} advanced to slot {d} before pending={d} was proved at slot {d}\n", .{
                        i, h.slot, want_pending, slot,
                    });
                    return error.GossipObservationMissed;
                }
                if (h.slot != slot or h.pending != want_pending) all_met = false;
            }
            if (all_met) {
                if (all_since == null) all_since = std.Io.Timestamp.now(self.io, .awake);
                if (elapsedMs(self.io, all_since.?) >= pending_cadence_guard_ms) {
                    std.debug.print("[registry-smoke] ok after {d} ms: {s}; remained pending at S for >= {d} ms (> idle heartbeat)\n", .{
                        poll.elapsed(self.io), what, pending_cadence_guard_ms,
                    });
                    return;
                }
            } else {
                all_since = null;
            }
            try poll.tick(self);
        }
    }

    /// Wait for the stderr evidence for one exact externalization. If a node
    /// prints the target slot with another transaction count, or advances
    /// without retaining its line, fail immediately.
    fn waitSlotTxs(
        self: *Cluster,
        nodes: []const usize,
        slot: u64,
        want_txs: u64,
        what: []const u8,
    ) !void {
        var poll = Poll.init(self.io, poll_bound_ms, what);
        while (true) {
            try self.checkProcs();
            var all_met = true;
            for (nodes) |i| {
                const p = self.procs[i];
                p.mu.lockUncancelable(self.io);
                const got = p.slot_txs.get(slot);
                const max_slot = p.max_slot;
                p.mu.unlock(self.io);
                if (got) |n| {
                    if (n != want_txs) {
                        std.debug.print("[registry-smoke] node{d} externalized slot {d} with txs={d}, expected {d}\n", .{
                            i, slot, n, want_txs,
                        });
                        return error.WrongSlotTxCount;
                    }
                } else {
                    if (max_slot >= slot) {
                        std.debug.print("[registry-smoke] node{d} reached slot {d} without retained tx-count evidence for slot {d}\n", .{
                            i, max_slot, slot,
                        });
                        return error.MissingSlotEvidence;
                    }
                    all_met = false;
                }
            }
            if (all_met) {
                std.debug.print("[registry-smoke] ok after {d} ms: {s}\n", .{ poll.elapsed(self.io), what });
                return;
            }
            try poll.tick(self);
        }
    }

    fn nodesMask(nodes: []const usize) u8 {
        var mask: u8 = 0;
        for (nodes) |i| mask |= bit(i);
        return mask;
    }

    /// Highest durable slot whose application log was printed by every named
    /// node, optionally with one exact transaction count. The registry writes
    /// its snapshot before this line, so this is stronger than a fleeting RPC
    /// sample and remains usable with sub-second idle slots.
    fn commonLoggedSlotNow(self: *Cluster, nodes: []const usize, min_slot: u64, want_txs: ?u64) ?u64 {
        const want_mask = nodesMask(nodes);
        var best: ?u64 = null;
        var it = self.log_heads.iterator();
        while (it.next()) |e| {
            const slot = e.key_ptr.*;
            if (slot < min_slot or e.value_ptr.mask & want_mask != want_mask) continue;
            if (want_txs) |want| {
                var counts_match = true;
                for (nodes) |i| {
                    const p = self.procs[i];
                    p.mu.lockUncancelable(self.io);
                    const got = p.slot_txs.get(slot);
                    p.mu.unlock(self.io);
                    if (got == null or got.? != want) counts_match = false;
                }
                if (!counts_match) continue;
            }
            if (best == null or slot > best.?) best = slot;
        }
        return best;
    }

    fn waitCommonLoggedSlot(
        self: *Cluster,
        nodes: []const usize,
        min_slot: u64,
        want_txs: ?u64,
        what: []const u8,
    ) !u64 {
        var poll = Poll.init(self.io, poll_bound_ms, what);
        while (true) {
            try self.checkProcs();
            if (self.commonLoggedSlotNow(nodes, min_slot, want_txs)) |slot| {
                const seen = self.log_heads.get(slot).?;
                std.debug.print("[registry-smoke] ok after {d} ms: {s} (durable slot {d}, head={s}…)\n", .{
                    poll.elapsed(self.io), what, slot, &seen.head16,
                });
                return slot;
            }
            try poll.tick(self);
        }
    }

    /// Catch the first fresh common application line before the node loops'
    /// 100 ms `waitApplied` tick returns and lets them nominate an idle value.
    /// Once the transaction is admitted, the 5 s busy minimum takes over.
    fn waitFreshCommonLoggedSlot(
        self: *Cluster,
        nodes: []const usize,
        min_slot: u64,
        what: []const u8,
    ) !u64 {
        var poll = Poll.init(self.io, poll_bound_ms, what);
        while (true) {
            try self.checkProcs();
            if (self.commonLoggedSlotNow(nodes, min_slot, 0)) |slot| {
                const seen = self.log_heads.get(slot).?;
                std.debug.print("[registry-smoke] ok after {d} ms: {s} (fresh durable slot {d}, head={s}…)\n", .{
                    poll.elapsed(self.io), what, slot, &seen.head16,
                });
                return slot;
            }
            try poll.tickEvery(self, 1);
        }
    }

    const CertifiedWitness = struct { checkpoint: u64, live_head: u64 };

    fn certifiedCheckpointNow(self: *Cluster, nodes: *const [2]usize, max_slot: u64) ?u64 {
        const mask = nodesMask(nodes);
        const a = self.procs[nodes[0]];
        const b = self.procs[nodes[1]];
        var best: ?u64 = null;
        a.mu.lockUncancelable(self.io);
        b.mu.lockUncancelable(self.io);
        defer b.mu.unlock(self.io);
        defer a.mu.unlock(self.io);
        var it = a.history_checkpoints.iterator();
        while (it.next()) |e| {
            const slot = e.key_ptr.*;
            const a_status = e.value_ptr.*;
            const b_status = b.history_checkpoints.get(slot) orelse continue;
            if (a_status & checkpoint_signed_bit == 0 or b_status & checkpoint_signed_bit == 0) continue;
            if ((a_status | b_status) & checkpoint_certified_bit == 0) continue;
            if (slot > max_slot) continue;
            const logged = self.log_heads.get(slot) orelse continue;
            if (logged.mask & mask != mask) continue;
            if (best == null or slot > best.?) best = slot;
        }
        return best;
    }

    /// Wait for two distinct survivor processes to report their attestation
    /// for C, at least one to report C certified, and both to have durably
    /// applied C with the same head. The returned live head is within the
    /// protocol's 16-slot answering window of C.
    fn waitCertifiedCheckpoint(self: *Cluster, nodes: *const [2]usize, min_live_slot: u64) !CertifiedWitness {
        var poll = Poll.init(self.io, history_bound_ms, "a recent two-signer certified history checkpoint after at least 201 missed slots");
        while (true) {
            try self.checkProcs();
            const live_head = self.commonLoggedSlotNow(nodes, min_live_slot, 0);
            if (live_head) |h| {
                if (self.certifiedCheckpointNow(nodes, h)) |c| {
                    if (h - c >= answering_window) {
                        try poll.tick(self);
                        continue;
                    }
                    std.debug.print("[registry-smoke] ok after {d} ms: checkpoint C={d} signed by node{d}+node{d}, certified, live H={d}, lag={d}\n", .{
                        poll.elapsed(self.io), c, nodes[0], nodes[1], h, h - c,
                    });
                    return .{ .checkpoint = c, .live_head = h };
                }
            }
            try poll.tick(self);
        }
    }

    /// After the second validator dies, allow already-buffered work to drain,
    /// then require one exact slot/hash to remain unchanged for `stable_ms`.
    fn waitHeadStable(self: *Cluster, i: usize, min_slot: u64, stable_ms: u64) !Head {
        var poll = Poll.init(self.io, poll_bound_ms, "the sole survivor's head to remain unchanged for one second");
        var candidate: ?Head = null;
        var since = std.Io.Timestamp.now(self.io, .awake);
        while (true) {
            const h = (try self.queryHead(i)) orelse {
                candidate = null;
                try poll.tick(self);
                continue;
            };
            if (h.slot < min_slot) {
                try poll.tick(self);
                continue;
            }
            if (candidate == null or candidate.?.slot != h.slot or !std.mem.eql(u8, &candidate.?.hash, &h.hash)) {
                candidate = h;
                since = std.Io.Timestamp.now(self.io, .awake);
            } else if (elapsedMs(self.io, since) >= stable_ms) {
                std.debug.print("[registry-smoke] ok after {d} ms: node{d} stalled without quorum at H={d} head={s}… for >= {d} ms\n", .{
                    poll.elapsed(self.io), i, h.slot, h.hash[0..16], stable_ms,
                });
                return h;
            }
            try poll.tick(self);
        }
    }

    fn waitHistoryBoot(self: *Cluster, i: usize, min_slot: u64, stable_head: u64) !u64 {
        var poll = Poll.init(self.io, ready_bound_ms, "node2's explicit history-checkpoint boot log");
        while (true) {
            const p = self.procs[i];
            p.mu.lockUncancelable(self.io);
            const got = p.history_boot_slot;
            p.mu.unlock(self.io);
            if (got) |slot| {
                // A second certificate can become complete after the harness
                // sampled C but before node0's kill reaches it. loadLatest
                // correctly chooses that newer artifact, so accept B >= C
                // while retaining the same stable-H/window proof.
                if (slot < min_slot or slot > stable_head or stable_head - slot >= answering_window) {
                    std.debug.print("[registry-smoke] node{d} booted from history checkpoint B={d}; expected C={d} <= B <= H={d} and H-B < {d}\n", .{
                        i, slot, min_slot, stable_head, answering_window,
                    });
                    return error.WrongHistoryCheckpoint;
                }
                std.debug.print("[registry-smoke] ok after {d} ms: node{d} booted from history checkpoint B={d} (requested minimum C={d}, stable H={d})\n", .{
                    poll.elapsed(self.io), i, slot, min_slot, stable_head,
                });
                return slot;
            }
            try poll.tick(self);
        }
    }

    /// The checkpoint-restored process must visibly pass through the exact
    /// stable frontier, not merely appear at some later matching state.
    fn waitHeadExact(self: *Cluster, i: usize, want: Head) !Head {
        var poll = Poll.init(self.io, poll_bound_ms, "node2 to catch the sole survivor's exact stable H/hash");
        while (true) {
            if (try self.queryHead(i)) |h| {
                if (h.slot > want.slot) {
                    std.debug.print("[registry-smoke] node{d} skipped the observable catch-up frontier H={d} and reached {d}\n", .{ i, want.slot, h.slot });
                    return error.CatchUpOvershot;
                }
                if (h.slot == want.slot) {
                    if (!std.mem.eql(u8, &h.hash, &want.hash)) return error.HeadDisagreement;
                    std.debug.print("[registry-smoke] ok after {d} ms: node{d} caught exact H={d} head={s}…\n", .{
                        poll.elapsed(self.io), i, h.slot, h.hash[0..16],
                    });
                    return h;
                }
            }
            try poll.tick(self);
        }
    }

    /// The restarted node `i` reaches `min_slot` and its head at some slot
    /// equals another node's head at that slot.
    fn waitCatchUp(self: *Cluster, i: usize, min_slot: u64) !void {
        var poll = Poll.init(self.io, poll_bound_ms, "the restarted node2 to catch up to the others' head");
        while (true) {
            if (try self.queryHead(i)) |h| {
                if (h.slot >= min_slot) {
                    var seen_other = (self.rpc_heads.get(h.slot).?.mask & ~bit(i)) != 0;
                    if (!seen_other) {
                        for (0..n_nodes) |j| {
                            if (j == i) continue;
                            if (try self.queryHead(j)) |hj| {
                                if (hj.slot == h.slot) seen_other = true;
                            }
                        }
                    }
                    if (seen_other) {
                        std.debug.print("[registry-smoke] ok after {d} ms: node{d} caught up: slot {d} hash={s}… matches the others\n", .{ poll.elapsed(self.io), i, h.slot, h.hash[0..16] });
                        return;
                    }
                }
            }
            try poll.tick(self);
        }
    }

    /// The highest slot any `head` answered, with its hash.
    fn highestHead(self: *const Cluster) ?struct { slot: u64, hash: [64]u8 } {
        var best: ?u64 = null;
        var it = self.rpc_heads.iterator();
        while (it.next()) |e| {
            if (best == null or e.key_ptr.* > best.?) best = e.key_ptr.*;
        }
        const slot = best orelse return null;
        return .{ .slot = slot, .hash = self.rpc_heads.get(slot).?.hash };
    }

    // ---- the §2.1 acceptance script ----

    fn script(self: *Cluster) !void {
        const all = [_]usize{ 0, 1, 2 };
        const bob_hex: []const u8 = &self.client_pk[@backingInt(Client.bob)];

        try self.waitReady();

        // tx1: alice claims "alice" via node0.
        _ = try self.submit(.alice, 0, &.{ "claim", "alice" });
        try self.waitGet("alice", .{ .owner = self.pk(.alice) }, &all, "get alice → owner=alice on every node");

        // tx2: bob's conflicting claim via node1 is accepted at submit (it
        // only queues), then loses at apply: the failed op still consumes
        // bob's sequence number (§3.7), so seq=1 everywhere proves it landed.
        const at_submit = try self.headRetry(1, "node1 to answer `head` before the conflicting claim");
        _ = try self.submit(.bob, 1, &.{ "claim", "alice" });
        _ = try self.waitHeadSlotAtLeast(1, at_submit.slot + 1, "node1 to close a slot after the conflicting claim");
        try self.waitAccountSeq(self.pk(.bob), 1, &all, "bob's losing claim consumed seq 1 on every node");
        try self.expectGetNow("alice", .{ .owner = self.pk(.alice) }, &all, "alice still owns alice after bob's conflicting claim");

        // tx3: alice sets a value via node2.
        _ = try self.submit(.alice, 2, &.{ "set", "alice", "hello" });
        try self.waitGet("alice", .{ .value = "68656c6c6f" }, &all, "get alice → value=68656c6c6f on every node");

        // tx4: bob claims his own name via node1.
        _ = try self.submit(.bob, 1, &.{ "claim", "bob" });
        try self.waitGet("bob", .{ .owner = self.pk(.bob) }, &all, "get bob → owner=bob on every node");

        // tx5: alice transfers "alice" to bob via node0.
        _ = try self.submit(.alice, 0, &.{ "transfer", "alice", bob_hex });
        try self.waitGet("alice", .{ .owner = self.pk(.bob) }, &all, "get alice → owner=bob on every node");

        // (6) Retain the broad head-agreement sweep, then catch the next
        // common durable idle close through the process logs at 1 ms cadence.
        // CLI sampling is intentionally not used for this edge: with a fast
        // idle heartbeat, sequential `head` processes can consume the whole
        // pre-nomination interval before tx6 is even submitted.
        _ = try self.headAgreement();
        var before_barrier: u64 = 0;
        for (self.procs) |p| before_barrier = @max(before_barrier, p.maxSlot());
        const settled = try self.waitFreshCommonLoggedSlot(
            &all,
            before_barrier + 1,
            "the first fresh common pending-free slot for the flooding barrier",
        );

        // tx6 enters ONLY nomination-disabled node2. In the line topology,
        // node1 is one overlay hop from the source and node0 is two. Seeing
        // pending=1 on both while their ledger heads remain exactly S proves
        // application-message flooding itself, before consensus can make the
        // transaction visible indirectly.
        _ = try self.submit(.bob, 2, &.{ "set", "bob", "x" });
        try self.waitPendingAtExactSlot(
            &.{ 1, 0 },
            settled,
            1,
            "tx6 pending on node1 (one hop) and node0 (two hops), both still at S",
        );

        // (7) Kill the sole submission node before any nomination. The two
        // survivors are the quorum; their own per-slot lines must show the
        // flooded transaction in exactly S+1, not merely some later slot.
        std.debug.print("[registry-smoke] SIGKILL source node2 at proof slot S={d}\n", .{settled});
        {
            const p2 = self.procs[2];
            p2.mu.lockUncancelable(self.io);
            p2.expect_eof = true;
            p2.mu.unlock(self.io);
            p2.stop();
        }
        try self.waitSlotTxs(
            &.{ 0, 1 },
            settled + 1,
            1,
            "node0 and node1 externalized exactly S+1 with txs=1 after the source died",
        );
        try self.waitGet("bob", .{ .value = "78" }, &.{ 0, 1 }, "get bob → value=78 on node0 and node1 (node2 down)");
        const at_restart = try self.headRetry(0, "node0 to answer `head` before node2 restarts");
        // The application-flooding proof above requires the line, but a
        // recovering SCP participant needs statements from both members of
        // its 2-of-3 quorum: node1 does not relay node0's consensus envelopes.
        // Widen only the restarted process with a direct recovery dial.
        var recovery_peer_buf: [24]u8 = undefined;
        const recovery_peer = try std.fmt.bufPrint(&recovery_peer_buf, "127.0.0.1:{d}", .{listenPort(0)});
        try self.procs[2].appendPeer(recovery_peer);
        std.debug.print("[registry-smoke] restarting node2 from its data dir with node0 recovery peer (node0 at slot {d})\n", .{at_restart.slot});
        self.procs[2].spawn() catch |err| {
            std.debug.print("[registry-smoke] cannot respawn node2: {t}\n", .{err});
            return err;
        };
        try self.waitCatchUp(2, at_restart.slot);

        // (8) A second single-source transaction through the restarted,
        // nomination-disabled end of the line. It can land only by flooding
        // to a survivor that can nominate it (tx7, the end of the E2a slice).
        _ = try self.submit(.bob, 2, &.{ "release", "bob" });
        try self.waitGet("bob", .none, &all, "get bob → none on every node (released via the restarted node2)");

        // (9) Move one durable, empty slot beyond tx7, then kill node2 again.
        // Record the stopped process's actual final slot (rather than a
        // pre-kill sample) and require both survivors' persisted/logged chain
        // to contain that exact slot. This is absence origin S.
        var after_tx7: u64 = 0;
        for (self.procs) |p| after_tx7 = @max(after_tx7, p.maxSlot());
        _ = try self.waitCommonLoggedSlot(&all, after_tx7 + 1, 0, "a common durable empty head after tx7");
        {
            const p2 = self.procs[2];
            p2.mu.lockUncancelable(self.io);
            p2.expect_eof = true;
            p2.mu.unlock(self.io);
            p2.stop();
        }
        const absent_at = self.procs[2].maxSlot();
        try self.waitSlotTxs(&all, absent_at, 0, "all three durably recorded absence origin S before node2 misses at least 201 slots");
        std.debug.print("[registry-smoke] history outage begins at durable S={d}; node2 stopped\n", .{absent_at});

        // node0+node1 are still a 2-of-3 quorum. Their 500 ms idle heartbeat
        // drives at least 201 transaction-free slots while the shared history
        // archive receives an attestation every 8 slots. A usable C must be
        // signed by both, certified by the local qset, and no more than 15
        // slots behind the live common head.
        const survivors = [_]usize{ 0, 1 };
        const certified = try self.waitCertifiedCheckpoint(&survivors, absent_at + absent_slots);

        // Remove node0 as well. node1 may finish already-buffered work, so the
        // stable H is measured after the kill; five or more independent head
        // samples over one second prove it cannot advance by itself.
        {
            const p0 = self.procs[0];
            p0.mu.lockUncancelable(self.io);
            p0.expect_eof = true;
            p0.mu.unlock(self.io);
            p0.stop();
        }
        const stable = try self.waitHeadStable(1, certified.live_head, stable_head_ms);
        // node0's reader is joined, so freeze the newest certificate both
        // survivors actually logged before selecting the import floor. This
        // closes the C→C+8 race between the earlier sample and SIGKILL.
        try self.checkProcs();
        const checkpoint_floor = self.certifiedCheckpointNow(&survivors, stable.slot) orelse return error.MissingCertifiedCheckpoint;
        if (!historyWitnessOk(absent_at, stable.slot, checkpoint_floor)) {
            std.debug.print("[registry-smoke] invalid E2b witness: S={d} C={d} stable H={d}; need H-S >= {d} and H-C < {d}\n", .{
                absent_at, checkpoint_floor, stable.slot, absent_slots, answering_window,
            });
            return error.HistoryWitnessOutOfRange;
        }
        {
            const p1 = self.procs[1];
            p1.mu.lockUncancelable(self.io);
            const advanced = p1.slot_txs.contains(stable.slot + 1);
            p1.mu.unlock(self.io);
            if (advanced) return error.SoleSurvivorAdvanced;
        }

        // (10) Restart node2 from the certified archive, not its 201-slot-old
        // local snapshot. The extra node0 dial from its first restart remains
        // configured but node0 is dead, leaving node1 as its only live peer.
        // A finite heartbeat lets node2 co-vote through C+1..H; the one-second
        // interval then leaves time to observe exact H before tx8 is queued.
        var checkpoint_buf: [20]u8 = undefined;
        const checkpoint_s = try std.fmt.bufPrint(&checkpoint_buf, "{d}", .{checkpoint_floor});
        try self.procs[2].setFlagValue("--min-slot-ms", survivor_min_slot_ms);
        try self.procs[2].setFlagValue("--heartbeat-ms", rejoin_heartbeat_ms);
        try self.procs[2].setFlagValue("--history-min-slot", checkpoint_s);
        std.debug.print("[registry-smoke] restarting node2 with --history-min-slot C={d}; node0 peer is configured but dead, node1 is the sole live peer\n", .{checkpoint_floor});
        self.procs[2].spawn() catch |err| {
            std.debug.print("[registry-smoke] cannot respawn node2 from history: {t}\n", .{err});
            return err;
        };
        const boot_checkpoint = try self.waitHistoryBoot(2, checkpoint_floor, stable.slot);
        if (!historyWitnessOk(absent_at, stable.slot, boot_checkpoint)) return error.HistoryWitnessOutOfRange;
        _ = try self.waitHeadExact(2, stable);

        // tx8 changes state and must land in exactly H+1 on both live nodes.
        // node1 was proved stalled at H, so this externalization proves the
        // checkpoint-restored node has rejoined as a necessary voter.
        _ = try self.submit(.bob, 2, &.{ "set", "alice", "history" });
        const rejoined_slot = stable.slot + 1;
        try self.waitSlotTxs(&.{ 1, 2 }, rejoined_slot, 1, "node1+node2 externalized tx8 in exactly H+1 after checkpoint catch-up");
        try self.waitGet("alice", .{ .value = "686973746f7279" }, &.{ 1, 2 }, "tx8 state agrees on node1+node2 at the rejoined frontier");

        // (11) Finally restart node0. Depending on whether H+1 was itself an
        // 8-slot boundary it may select local persistence or the newer shared
        // certificate; either path must converge with the two-node chain.
        // (The exact tx8 line is already pinned on its necessary voters.)
        std.debug.print("[registry-smoke] restarting node0 after node1+node2 rejoined at slot {d}\n", .{rejoined_slot});
        self.procs[0].spawn() catch |err| {
            std.debug.print("[registry-smoke] cannot respawn node0: {t}\n", .{err});
            return err;
        };
        try self.waitCatchUp(0, rejoined_slot);
        try self.waitGet("alice", .{ .value = "686973746f7279" }, &all, "tx8 state agrees on all three nodes after node0 restarts");

        // A last sweep so the evidence names the newest slot every node agrees on.
        _ = try self.headAgreement();
        for (all) |i| _ = try self.headRetry(i, "a final `head` from every node");
        try self.checkProcs();
        if (self.txs != n_txs) {
            std.debug.print("[registry-smoke] submitted {d} distinct transactions, expected exactly {d}\n", .{ self.txs, n_txs });
            return error.TxCountDrift;
        }
        const top = self.highestHead() orelse return error.NoHeadSeen;
        var buf: [128]u8 = undefined;
        const line = try evidenceLine(&buf, n_nodes, self.txs, top.slot, top.hash[0..16]);
        var out_buf: [256]u8 = undefined;
        var out = std.Io.File.stdout().writerStreaming(self.io, &out_buf);
        try out.interface.print("{s}\n", .{line});
        try out.interface.flush();
        std.debug.print("[registry-smoke] OK after {d} ms\n", .{elapsedMs(self.io, self.started)});
    }
};

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

const Args = struct {
    zig: ?[]const u8 = null,
    deadline_s: u64 = default_deadline_s,
    build_only: bool = false,
    keep: bool = false,
    registry_src: []const u8 = default_registry_src,
};

fn parseArgs(init: std.process.Init) !Args {
    var a: Args = .{};
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--zig")) {
            a.zig = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--deadline-s")) {
            a.deadline_s = try std.fmt.parseInt(u64, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--build-only")) {
            a.build_only = true;
        } else if (std.mem.eql(u8, arg, "--keep")) {
            a.keep = true;
        } else if (std.mem.eql(u8, arg, "--registry-src")) {
            a.registry_src = it.next() orelse return error.MissingValue;
        } else {
            std.debug.print("[registry-smoke] unknown argument: {s}\n", .{arg});
            return error.BadArgument;
        }
    }
    if (a.zig == null) {
        std.debug.print("[registry-smoke] --zig <path> is required (the build step passes its own)\n", .{});
        return error.BadArgument;
    }
    if (a.deadline_s == 0) return error.BadArgument;
    return a;
}

pub fn main(init: std.process.Init) !void {
    const args = try parseArgs(init);
    run(init, args) catch |err| {
        std.debug.print("[registry-smoke] FAILED: {t}\n", .{err});
        std.process.exit(1);
    };
}

fn readSrc(gpa: std.mem.Allocator, io: std.Io, dir: []const u8, rel: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, rel });
    defer gpa.free(path);
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| {
        std.debug.print("[registry-smoke] cannot read {s}: {t}\n", .{ path, err });
        return err;
    };
}

fn writeFile(io: std.Io, dir: std.Io.Dir, rel: []const u8, data: []const u8) !void {
    try dir.writeFile(io, .{ .sub_path = rel, .data = data });
}

/// Copy every `<registry_src>/src/*.zig` into `dest/src/`; returns the count.
fn copyZigSources(gpa: std.mem.Allocator, io: std.Io, registry_src: []const u8, dest: std.Io.Dir) !usize {
    const src_dir_path = try std.fmt.allocPrint(gpa, "{s}/src", .{registry_src});
    defer gpa.free(src_dir_path);
    var src_dir = std.Io.Dir.cwd().openDir(io, src_dir_path, .{ .iterate = true }) catch |err| {
        std.debug.print("[registry-smoke] cannot open {s}: {t}\n", .{ src_dir_path, err });
        return err;
    };
    defer src_dir.close(io);
    var copied: usize = 0;
    var it = src_dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".zig")) continue;
        const data = try src_dir.readFileAlloc(io, entry.name, gpa, .limited(1 << 20));
        defer gpa.free(data);
        const rel = try std.fmt.allocPrint(gpa, "src/{s}", .{entry.name});
        defer gpa.free(rel);
        try writeFile(io, dest, rel, data);
        copied += 1;
    }
    if (copied == 0) {
        std.debug.print("[registry-smoke] no .zig sources under {s}\n", .{src_dir_path});
        return error.NoSources;
    }
    return copied;
}

fn run(init: std.process.Init, args: Args) !void {
    const gpa = init.gpa;
    const io = init.io;
    const cwd = std.Io.Dir.cwd();

    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try std.process.currentPath(io, &root_buf)];

    // ---- (1) scratch + the consumer copy ----
    cwd.deleteTree(io, scratch_root) catch {};
    const scratch = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ root, scratch_root });
    defer gpa.free(scratch);
    const build_dir = try std.fmt.allocPrint(gpa, "{s}/build", .{scratch});
    defer gpa.free(build_dir);
    {
        var d = cwd.createDirPathOpen(io, build_dir, .{}) catch |err| {
            std.debug.print("[registry-smoke] cannot create scratch dir {s}: {t}\n", .{ build_dir, err });
            return err;
        };
        defer d.close(io);
        try d.createDirPath(io, "src");
        const build_src = try readSrc(gpa, io, args.registry_src, "build.zig");
        defer gpa.free(build_src);
        try writeFile(io, d, "build.zig", build_src);
        const zon_src = try readSrc(gpa, io, args.registry_src, "build.zig.zon");
        defer gpa.free(zon_src);
        const zon_out = rewriteZon(gpa, zon_src, zon_path_from_scratch) catch |err| {
            std.debug.print("[registry-smoke] {s}/build.zig.zon: the path dependency did not match exactly once: {t}\n", .{ args.registry_src, err });
            return err;
        };
        defer gpa.free(zon_out);
        try writeFile(io, d, "build.zig.zon", zon_out);
        const n = try copyZigSources(gpa, io, args.registry_src, d);
        std.debug.print("[registry-smoke] scratch copy of {s} in {s} ({d} sources)\n", .{ args.registry_src, build_dir, n });
    }

    // ---- (2) ONE nested consumer build (isolated local cache) ----
    var env = try init.environ_map.clone(gpa);
    defer env.deinit();
    if (env.get("ZIG_LOCAL_PKG_DIR") == null) {
        const pkg_dir = try std.fmt.allocPrint(gpa, "{s}/zig-pkg", .{root});
        defer gpa.free(pkg_dir);
        try env.put("ZIG_LOCAL_PKG_DIR", pkg_dir);
    }
    const cache_dir = try std.fmt.allocPrint(gpa, "{s}/.zig-cache", .{build_dir});
    defer gpa.free(cache_dir);
    std.debug.print("[registry-smoke] building (zig build -Doptimize=ReleaseSafe in {s})\n", .{build_dir});
    {
        const res = try std.process.run(gpa, io, .{
            .argv = &.{ args.zig.?, "build", "-Doptimize=ReleaseSafe", "--cache-dir", cache_dir },
            .cwd = .{ .path = build_dir },
            .environ_map = &env,
        });
        defer gpa.free(res.stdout);
        defer gpa.free(res.stderr);
        if (!res.term.success()) {
            std.debug.print("[registry-smoke] nested build failed ({f}):\n{s}\n", .{ res.term, res.stderr });
            return error.NestedBuildFailed;
        }
    }
    const exe = try std.fmt.allocPrint(gpa, "{s}/zig-out/bin/registry", .{build_dir});
    defer gpa.free(exe);
    cwd.access(io, exe, .{}) catch |err| {
        std.debug.print("[registry-smoke] the consumer build installed no {s}: {t}\n", .{ exe, err });
        return error.NoRegistryBinary;
    };
    if (args.build_only) {
        std.debug.print("[registry-smoke] build-only: consumer build OK\n", .{});
        if (!args.keep) cwd.deleteTree(io, scratch_root) catch {};
        return;
    }

    // ---- (3) keys + the 2-of-3 quorum ----
    var node_ids: [n_nodes]slcp.NodeId = undefined;
    var node_key_paths: [n_nodes][]u8 = undefined;
    var node_keys_made: usize = 0;
    defer for (node_key_paths[0..node_keys_made]) |p| gpa.free(p);
    for (0..n_nodes) |i| {
        node_key_paths[i] = try std.fmt.allocPrint(gpa, "{s}/node{d}.key", .{ scratch, i });
        node_keys_made += 1;
        const kp = slcp.keys.createNew(io, node_key_paths[i]) catch |err| {
            std.debug.print("[registry-smoke] cannot mint {s}: {t}\n", .{ node_key_paths[i], err });
            return err;
        };
        node_ids[i] = kp.public_key;
    }
    var client_pk: [n_clients][64]u8 = undefined;
    var client_key_paths: [n_clients][]u8 = undefined;
    var client_keys_made: usize = 0;
    defer for (client_key_paths[0..client_keys_made]) |p| gpa.free(p);
    for (client_names, 0..) |name, c| {
        client_key_paths[c] = try std.fmt.allocPrint(gpa, "{s}/{s}.key", .{ scratch, name });
        client_keys_made += 1;
        const kp = slcp.keys.createNew(io, client_key_paths[c]) catch |err| {
            std.debug.print("[registry-smoke] cannot mint {s}: {t}\n", .{ client_key_paths[c], err });
            return err;
        };
        client_pk[c] = std.fmt.bytesToHex(kp.public_key, .lower);
    }
    const quorum_path = try std.fmt.allocPrint(gpa, "{s}/quorum.json", .{scratch});
    defer gpa.free(quorum_path);
    {
        var owned = try slcp.Quorum.twoThirdsOf(&node_ids).toOwned(gpa);
        defer owned.deinit(gpa);
        var sink = std.Io.Writer.Allocating.init(gpa);
        defer sink.deinit();
        try slcp.Quorum.writeJson(&sink.writer, &owned);
        try sink.writer.writeByte('\n');
        try cwd.writeFile(io, .{ .sub_path = quorum_path, .data = sink.written() });
    }
    std.debug.print("[registry-smoke] quorum 2-of-3 over node0..2 in {s}; alice={s}… bob={s}…\n", .{ quorum_path, client_pk[0][0..16], client_pk[1][0..16] });

    // ---- (4) the three nodes ----
    var procs: [n_nodes]*NodeProc = undefined;
    var procs_made: usize = 0;
    defer for (procs[0..procs_made]) |p| p.destroy();
    var rpc: [n_nodes][]u8 = undefined;
    var rpc_made: usize = 0;
    defer for (rpc[0..rpc_made]) |r| gpa.free(r);
    const history_dir = try std.fmt.allocPrint(gpa, "{s}/history", .{scratch});
    defer gpa.free(history_dir);
    try cwd.createDirPath(io, history_dir);
    for (0..n_nodes) |i| {
        const dir = try std.fmt.allocPrint(gpa, "{s}/node{d}", .{ scratch, i });
        defer gpa.free(dir);
        try cwd.createDirPath(io, dir);
        rpc[i] = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{rpcPort(i)});
        rpc_made += 1;
        var listen_buf: [8]u8 = undefined;
        var rpc_buf: [8]u8 = undefined;
        const listen_s = try std.fmt.bufPrint(&listen_buf, "{d}", .{listenPort(i)});
        const rpc_s = try std.fmt.bufPrint(&rpc_buf, "{d}", .{rpcPort(i)});
        const min_slot = if (i == 2) disabled_cadence_ms else survivor_min_slot_ms;
        const heartbeat = if (i == 2) disabled_cadence_ms else survivor_heartbeat_ms;
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.appendSlice(gpa, &.{
            exe,                  "node",
            "--network",          network,
            "--key",              node_key_paths[i],
            "--data-dir",         "data",
            "--quorum",           quorum_path,
            "--listen",           listen_s,
            "--rpc",              rpc_s,
            "--min-slot-ms",      min_slot,
            "--heartbeat-ms",     heartbeat,
            "--history-dir",      history_dir,
            "--checkpoint-every", checkpoint_every,
        });
        // A deliberate line, with arrows denoting the only configured dial:
        // node2 --peer node1; node1 --peer node0; node0 has no peer argument.
        // Overlay connections are duplex, but node2 and node0 have no direct
        // path, so the pending proof below necessarily includes a relay.
        var peer_buf: [24]u8 = undefined;
        if (i > 0) {
            const peer = try std.fmt.bufPrint(&peer_buf, "127.0.0.1:{d}", .{listenPort(i - 1)});
            try argv.appendSlice(gpa, &.{ "--peer", peer });
        }
        procs[i] = try NodeProc.create(gpa, io, i, dir, argv.items);
        procs_made += 1;
    }
    for (procs) |p| p.spawn() catch |err| {
        std.debug.print("[registry-smoke] cannot spawn node{d} ({s}): {t}\n", .{ p.index, p.argv[0], err });
        return err;
    };
    std.debug.print("[registry-smoke] 3 nodes spawned in line node2→node1→node0: listen {d}..{d}, rpc {d}..{d}; busy min {s} ms, idle heartbeat {s} ms, checkpoint every {s}; node2 nomination disabled\n", .{
        listenPort(0), listenPort(n_nodes - 1), rpcPort(0), rpcPort(n_nodes - 1), survivor_min_slot_ms, survivor_heartbeat_ms, checkpoint_every,
    });

    // ---- (5)–(9) the acceptance script ----
    const now = std.Io.Timestamp.now(io, .awake);
    var cluster: Cluster = .{
        .gpa = gpa,
        .io = io,
        .scratch = scratch,
        .exe = exe,
        .key_paths = .{ client_key_paths[0], client_key_paths[1] },
        .client_pk = client_pk,
        .rpc = .{ rpc[0], rpc[1], rpc[2] },
        .procs = procs,
        .started = now,
        .deadline_ms = args.deadline_s * 1000,
        .last_report = now,
    };
    defer cluster.deinit();
    cluster.script() catch |err| {
        for (procs) |p| p.dumpTail();
        return err;
    };

    for (procs) |p| p.stop();
    if (!args.keep) cwd.deleteTree(io, scratch_root) catch {};
}

// ---------------------------------------------------------------------------
// Tests (run from the repo root: `zig build registry-smoke-tests`, part of `test`)
// ---------------------------------------------------------------------------

const testing = std.testing;
const hex_a: [64]u8 = @splat('a');
const hex_b: [64]u8 = @splat('b');
const hex_upper: [64]u8 = @splat('A');

// Non-vacuity: every poll, the head-agreement sweep and the evidence line
// read through this parser. Dropping a field, shortening the hash or
// upper-casing it makes `parseHead` return null (the poll then never
// completes), and the other verbs' replies must not pass as a head.
test "parseHead: the §3.10 head line field by field; malformed lines are null" {
    const line = "head slot=12 hash=" ++ hex_a ++ " accounts=2 names=1 pending=0 network=" ++ hex_b ++ "\n";
    const h = parseHead(line).?;
    try testing.expectEqual(@as(u64, 12), h.slot);
    try testing.expectEqualStrings(&hex_a, &h.hash);
    try testing.expectEqual(@as(u64, 2), h.accounts);
    try testing.expectEqual(@as(u64, 1), h.names);
    try testing.expectEqual(@as(u64, 0), h.pending);
    try testing.expectEqualStrings(&hex_b, &h.network);
    // An extra field is tolerated; a missing, short, or upper-case one is not.
    try testing.expect(parseHead("head slot=1 hash=" ++ hex_a ++ " accounts=0 names=0 pending=0 network=" ++ hex_b ++ " peers=2") != null);
    try testing.expect(parseHead("head slot=1 hash=" ++ hex_a ++ " accounts=0 names=0 pending=0") == null);
    try testing.expect(parseHead("head slot=1 hash=abc accounts=0 names=0 pending=0 network=" ++ hex_b) == null);
    try testing.expect(parseHead("head slot=1 hash=" ++ hex_upper ++ " accounts=0 names=0 pending=0 network=" ++ hex_b) == null);
    try testing.expect(parseHead("head slot=x hash=" ++ hex_a ++ " accounts=0 names=0 pending=0 network=" ++ hex_b) == null);
    try testing.expect(parseHead("entry name=alice owner=" ++ hex_a ++ " value=") == null);
    try testing.expect(parseHead("") == null);
}

// Non-vacuity: `get` is what every ownership / value / release wait polls.
// `none`, an empty value (right after a claim) and a hex value are the
// three shapes; a non-hex or odd-length value, a missing field or another
// verb is null; `GetWant.matches` is what decides a poll is done.
test "parseGet: entry / none, empty and hex values; GetWant.matches" {
    const e = parseGet("entry name=alice owner=" ++ hex_a ++ " value=68656c6c6f\n").?;
    try testing.expect(e == .entry);
    try testing.expectEqualStrings("alice", e.entry.name);
    try testing.expectEqualStrings(&hex_a, &e.entry.owner);
    try testing.expectEqualStrings("68656c6c6f", e.entry.value);
    const fresh = parseGet("entry name=bob owner=" ++ hex_b ++ " value=").?;
    try testing.expectEqualStrings("", fresh.entry.value);
    try testing.expect(parseGet("none").? == .none);
    try testing.expect(parseGet("none\r\n").? == .none);
    try testing.expect(parseGet("entry name=alice owner=" ++ hex_a ++ " value=abc") == null);
    try testing.expect(parseGet("entry name=alice owner=" ++ hex_a ++ " value=AB") == null);
    try testing.expect(parseGet("entry name=alice owner=" ++ hex_a) == null);
    try testing.expect(parseGet("entry name= owner=" ++ hex_a ++ " value=") == null);
    try testing.expect(parseGet("head slot=1") == null);
    try testing.expect(parseGet("") == null);

    const want_owner: GetWant = .{ .owner = hex_a };
    try testing.expect(want_owner.matches(e));
    try testing.expect(!want_owner.matches(fresh));
    try testing.expect(!want_owner.matches(.none));
    try testing.expect(!want_owner.matches(null));
    const want_value: GetWant = .{ .value = "68656c6c6f" };
    try testing.expect(want_value.matches(e));
    try testing.expect(!want_value.matches(fresh));
    const want_none: GetWant = .none;
    try testing.expect(want_none.matches(.none));
    try testing.expect(!want_none.matches(e));
}

// Non-vacuity: `submit` is the one CLI whose refusal is a hard failure; the
// `ok txid=` shape must carry a full hex64 id and the `err <code>` shape
// must expose the code, so a refusal is diagnosable from the log.
test "parseSubmit: ok txid=<hex64> and err <code> <text>; anything else is null" {
    const ok = parseSubmit("ok txid=" ++ hex_a ++ "\n").?;
    try testing.expect(ok == .ok);
    try testing.expectEqualStrings(&hex_a, &ok.ok);
    const refused = parseSubmit("err bad_seq expected 2 got 1").?;
    try testing.expect(refused == .err);
    try testing.expectEqualStrings("bad_seq", refused.err);
    try testing.expect(parseSubmit("ok txid=abc") == null);
    try testing.expect(parseSubmit("ok") == null);
    try testing.expect(parseSubmit("err") == null);
    try testing.expect(parseSubmit("accepted") == null);
}

// Non-vacuity: the conflicting-claim step waits on `account … seq=1`; a
// parser that misread `seq` would either never finish or pass vacuously.
test "parseAccount: account key=<hex64> seq=<n>" {
    const a = parseAccount("account key=" ++ hex_a ++ " seq=7").?;
    try testing.expectEqualStrings(&hex_a, &a.key);
    try testing.expectEqual(@as(u64, 7), a.seq);
    try testing.expect(parseAccount("account key=" ++ hex_a) == null);
    try testing.expect(parseAccount("account key=zz seq=1") == null);
    try testing.expect(parseAccount("head slot=1") == null);
}

// Non-vacuity: the per-node stderr parser feeds the progress report and the
// cross-node fork check on the logs; the library's own `slot` mentions
// (`info(slcp_node): …`) must not be mistaken for the program's line.
test "parseSlotLine: the node's `slot N: txs=K ok=J head=<hex16>` line" {
    const p = parseSlotLine("slot 12: txs=2 ok=2 head=0123456789abcdef").?;
    try testing.expectEqual(@as(u64, 12), p.slot);
    try testing.expectEqual(@as(u64, 2), p.txs);
    try testing.expectEqualStrings("0123456789abcdef", &p.head16.?);
    const no_head = parseSlotLine("slot 3: txs=0 ok=0").?;
    try testing.expectEqual(@as(u64, 3), no_head.slot);
    try testing.expectEqual(@as(u64, 0), no_head.txs);
    try testing.expect(no_head.head16 == null);
    try testing.expect(parseSlotLine("slot 3: ok=0 head=0123456789abcdef") == null);
    try testing.expect(parseSlotLine("slot 3: txs=x ok=0 head=0123456789abcdef") == null);
    try testing.expect(parseSlotLine("info(slcp_node): slot 3 externalized") == null);
    try testing.expect(parseSlotLine("slot x: txs=0 ok=0") == null);
    try testing.expect(parseSlotLine("") == null);
}

// Non-vacuity: a locally published signature is not itself a certificate.
// The at-least-201-slot witness waits specifically for `.certified`, while retaining
// the per-process `.signed` observations that prove two distinct signers.
test "parseCheckpointLine: signed and certified are distinct exact statuses" {
    const signed = parseCheckpointLine("history checkpoint slot 208 signed signer=abc").?;
    try testing.expectEqual(@as(u64, 208), signed.slot);
    try testing.expectEqual(CheckpointKind.signed, signed.kind);
    const certified = parseCheckpointLine("history checkpoint slot 216 certified signers=2").?;
    try testing.expectEqual(@as(u64, 216), certified.slot);
    try testing.expectEqual(CheckpointKind.certified, certified.kind);
    try testing.expect(parseCheckpointLine("history checkpoint slot 216 published") == null);
    try testing.expect(parseCheckpointLine("history checkpoint slot x certified") == null);
    try testing.expect(parseCheckpointLine("checkpoint slot 216 certified") == null);
    try testing.expect(parseCheckpointLine("slot 216: txs=0 ok=0") == null);
}

test "parseHistoryBootSlot: only an explicit history-checkpoint boot satisfies it" {
    const line = "registry: node abc listening on port 1; 1 peer(s); data in data; starting from history checkpoint at slot 208";
    try testing.expectEqual(@as(?u64, 208), parseHistoryBootSlot(line));
    try testing.expect(parseHistoryBootSlot("registry: node abc; starting from the snapshot at slot 208") == null);
    try testing.expect(parseHistoryBootSlot("registry: node abc; starting from history checkpoint at slot nope") == null);
    try testing.expect(parseHistoryBootSlot("history checkpoint slot 208 certified") == null);
}

test "history witness boundaries: more than 200 absent slots and checkpoint inside 16-slot window" {
    try testing.expect(historyWitnessOk(10, 211, 196)); // exact 201; exact lag 15
    try testing.expect(!historyWitnessOk(10, 210, 195)); // exact 200 is insufficient
    try testing.expect(!historyWitnessOk(10, 211, 195)); // lag 16 is outside
    try testing.expect(!historyWitnessOk(10, 211, 212)); // checkpoint from the future
    try testing.expect(!historyWitnessOk(10, 9, 9));
}

test "NodeProc retains per-slot tx counts and rejects contradictory evidence" {
    const gpa = testing.allocator;
    var empty_buf: [0]u8 = .{};
    var p: NodeProc = .{
        .gpa = gpa,
        .io = testing.io,
        .index = 0,
        .dir = "",
        .argv = &.{},
        .rdr_buf = &empty_buf,
    };
    defer {
        for (&p.tail) |*line| if (line.*) |s| gpa.free(s);
        if (p.bad) |s| gpa.free(s);
        p.slot_heads.deinit(gpa);
        p.slot_txs.deinit(gpa);
        p.history_checkpoints.deinit(gpa);
    }

    p.noteLine("slot 7: txs=1 ok=1 head=0123456789abcdef");
    try testing.expectEqual(@as(?u64, 1), p.slot_txs.get(7));
    try testing.expect(p.bad == null);
    p.noteLine("slot 7: txs=1 ok=1 head=0123456789abcdef");
    try testing.expect(p.bad == null);
    p.noteLine("slot 7: txs=2 ok=1 head=0123456789abcdef");
    try testing.expect(p.bad != null);
}

test "NodeProc retains history attestations, certification, and boot source" {
    const gpa = testing.allocator;
    var empty_buf: [0]u8 = .{};
    var p: NodeProc = .{
        .gpa = gpa,
        .io = testing.io,
        .index = 2,
        .dir = "",
        .argv = &.{},
        .rdr_buf = &empty_buf,
    };
    defer {
        for (&p.tail) |*line| if (line.*) |s| gpa.free(s);
        if (p.bad) |s| gpa.free(s);
        p.slot_heads.deinit(gpa);
        p.slot_txs.deinit(gpa);
        p.history_checkpoints.deinit(gpa);
    }

    p.noteLine("history checkpoint slot 208 signed signer=aaa");
    try testing.expectEqual(checkpoint_signed_bit, p.history_checkpoints.get(208).?);
    p.noteLine("history checkpoint slot 208 certified signers=2");
    try testing.expectEqual(checkpoint_signed_bit | checkpoint_certified_bit, p.history_checkpoints.get(208).?);
    p.noteLine("registry: node abc; starting from history checkpoint at slot 208");
    try testing.expectEqual(@as(?u64, 208), p.history_boot_slot);
}

test "NodeProc restart argv replaces cadence and appends history minimum" {
    const gpa = testing.allocator;
    const p = try NodeProc.create(gpa, testing.io, 2, "", &.{ "registry", "node", "--heartbeat-ms", disabled_cadence_ms });
    defer p.destroy();
    try p.setFlagValue("--heartbeat-ms", rejoin_heartbeat_ms);
    try testing.expectEqualStrings(rejoin_heartbeat_ms, p.argv[3]);
    try p.setFlagValue("--history-min-slot", "208");
    try testing.expectEqualStrings("--history-min-slot", p.argv[4]);
    try testing.expectEqualStrings("208", p.argv[5]);
}

// Non-vacuity: the evidence literal is what `just preflight` greps; a typo
// in the formatter goes red here before it goes red in preflight.
test "evidence line" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("[registry-smoke] nodes=3 txs=8 slots=217 head=0123456789abcdef", try evidenceLine(&buf, 3, 8, 217, "0123456789abcdef"));
}

// Non-vacuity: the zon rewrite must re-point the path dep (exactly once) to
// where the repo sits relative to the scratch build dir, refuse a doubled
// needle, and leave a URL-pinned zon alone. The REAL
// examples/registry/build.zig.zon must carry the needle exactly once; the
// example is written in parallel with this tool, so an absent manifest
// skips (an absent example is already red at `registry-intree`).
test "rewriter: build.zig.zon path dep → scratch-relative root once; doubled is ambiguous; pinned is untouched" {
    const gpa = testing.allocator;
    const io = testing.io;
    const literal = ".{ .dependencies = .{ .slcp = .{ .path = \"../..\" } } }";
    const out = try rewriteZon(gpa, literal, zon_path_from_scratch);
    defer gpa.free(out);
    try testing.expectEqualStrings(".{ .dependencies = .{ .slcp = .{ .path = \"../../..\" } } }", out);
    const doubled = literal ++ "\n" ++ literal;
    try testing.expectError(error.PatternAmbiguous, rewriteZon(gpa, doubled, zon_path_from_scratch));
    const pinned = ".{ .dependencies = .{ .slcp = .{ .url = \"https://x/v0.1.0.tar.gz\", .hash = \"h\" } } }";
    const same = try rewriteZon(gpa, pinned, "/abs/repo");
    defer gpa.free(same);
    try testing.expectEqualStrings(pinned, same);

    const real = std.Io.Dir.cwd().readFileAlloc(io, "examples/registry/build.zig.zon", gpa, .limited(1 << 16)) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer gpa.free(real);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, real, zon_path_needle));
    const real_out = try rewriteZon(gpa, real, zon_path_from_scratch);
    defer gpa.free(real_out);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, real_out, ".slcp = .{ .path = \"../../..\" },"));
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, real_out, zon_path_needle ++ " "));
}

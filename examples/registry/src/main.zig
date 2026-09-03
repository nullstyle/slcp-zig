//! main.zig — the `registry` process (docs/examples-roadmap.md E1:
//! persistence/restart, nomination cadence, and CLI). `registry node …` runs one validator: the typed node from
//! app.zig, the RPC server from rpc.zig, the snapshot file, and the cadence
//! loop that turns the pending queue into proposals. `submit`, `get`,
//! `account` and `head` are the client verbs: they talk to a node's RPC.

const std = @import("std");
const slcp = @import("slcp");
const registry = @import("registry.zig");
const app = @import("app.zig");
const rpc = @import("rpc.zig");

const default_rpc = "127.0.0.1:7412";

const usage =
    \\registry — a replicated name registry on slcp (examples/registry)
    \\
    \\  registry node --network <passphrase> --key <file> --data-dir <dir> --quorum <json>
    \\                --listen <port> --rpc <port> [--peer host:port]...
    \\                [--min-slot-ms 1000] [--heartbeat-ms 3000]
    \\  registry submit --key <file> [--rpc ip:port] claim <name>
    \\  registry submit --key <file> [--rpc ip:port] set <name> <value>
    \\  registry submit --key <file> [--rpc ip:port] transfer <name> <hex64>
    \\  registry submit --key <file> [--rpc ip:port] release <name>
    \\  registry get [--rpc ip:port] <name>
    \\  registry account [--rpc ip:port] <hex64>
    \\  registry head [--rpc ip:port]
    \\
    \\--rpc defaults to 127.0.0.1:7412. Key files are slcp seeds (`slcp key new file.key`).
    \\Names are [a-z0-9-], 1..32 bytes; values up to 64 bytes.
    \\Exit codes: 0 ok · 1 refused or failed · 2 usage · 3 the node fell behind a gap it cannot recover.
    \\
;

pub fn main(init: std.process.Init) !void {
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next(); // argv[0]
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(init.gpa);
    while (it.next()) |arg| try args.append(init.gpa, arg);

    var out_buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &out_buf);
    const code = run(init, args.items, &out.interface) catch |err| blk: {
        std.debug.print("registry: {t}\n", .{err});
        break :blk @as(u8, 1);
    };
    out.interface.flush() catch {};
    std.process.exit(code);
}

fn run(init: std.process.Init, args: []const []const u8, out: *std.Io.Writer) !u8 {
    if (args.len == 0) return usageError("missing verb");
    const verb = args[0];
    if (eql(verb, "--help") or eql(verb, "-h") or eql(verb, "help")) {
        try out.writeAll(usage);
        return 0;
    }
    if (eql(verb, "node")) return runNode(init, args[1..]);
    if (eql(verb, "submit")) return runSubmit(init, args[1..], out);
    if (eql(verb, "get") or eql(verb, "account") or eql(verb, "head")) return runQuery(init, verb, args[1..], out);
    return usageError("unknown verb");
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn usageError(msg: []const u8) u8 {
    std.debug.print("registry: {s}\n\n{s}", .{ msg, usage });
    return 2;
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

const Flags = struct {
    network: ?[]const u8 = null,
    key: ?[]const u8 = null,
    data_dir: ?[]const u8 = null,
    quorum: ?[]const u8 = null,
    listen: ?u16 = null,
    /// `--rpc` is a port for `node`, an `ip:port` spec for the client verbs.
    rpc_port: ?u16 = null,
    rpc: []const u8 = default_rpc,
    min_slot_ms: u64 = registry.min_slot_ms,
    heartbeat_ms: u64 = registry.heartbeat_ms,
    peers: std.ArrayList([]const u8) = .empty,
    positional: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *Flags, gpa: std.mem.Allocator) void {
        self.peers.deinit(gpa);
        self.positional.deinit(gpa);
    }
};

const FlagError = error{ UnknownFlag, MissingValue, BadPort, BadMillis } || std.mem.Allocator.Error;

fn parseFlags(gpa: std.mem.Allocator, args: []const []const u8, node_mode: bool) FlagError!Flags {
    var f: Flags = .{};
    errdefer f.deinit(gpa);
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (!std.mem.startsWith(u8, arg, "--")) {
            try f.positional.append(gpa, arg);
            continue;
        }
        const name = arg[2..];
        if (i + 1 >= args.len) return error.MissingValue;
        i += 1;
        const value = args[i];
        if (eql(name, "network")) {
            f.network = value;
        } else if (eql(name, "key")) {
            f.key = value;
        } else if (eql(name, "data-dir")) {
            f.data_dir = value;
        } else if (eql(name, "quorum")) {
            f.quorum = value;
        } else if (eql(name, "listen")) {
            f.listen = std.fmt.parseInt(u16, value, 10) catch return error.BadPort;
            if (f.listen.? == 0) return error.BadPort;
        } else if (eql(name, "rpc")) {
            if (node_mode) {
                f.rpc_port = std.fmt.parseInt(u16, value, 10) catch return error.BadPort;
                if (f.rpc_port.? == 0) return error.BadPort;
            } else {
                f.rpc = value;
            }
        } else if (eql(name, "peer")) {
            try f.peers.append(gpa, value);
        } else if (eql(name, "min-slot-ms")) {
            f.min_slot_ms = std.fmt.parseInt(u64, value, 10) catch return error.BadMillis;
        } else if (eql(name, "heartbeat-ms")) {
            f.heartbeat_ms = std.fmt.parseInt(u64, value, 10) catch return error.BadMillis;
            if (f.heartbeat_ms == 0) return error.BadMillis;
        } else {
            return error.UnknownFlag;
        }
    }
    return f;
}

fn flagsOrUsage(gpa: std.mem.Allocator, args: []const []const u8, node_mode: bool) ?Flags {
    return parseFlags(gpa, args, node_mode) catch |err| {
        _ = usageError(switch (err) {
            error.UnknownFlag => "unknown flag",
            error.MissingValue => "a flag is missing its value",
            error.BadPort => "a port must be a number in 1..65535",
            error.BadMillis => "--min-slot-ms / --heartbeat-ms take milliseconds (heartbeat > 0)",
            error.OutOfMemory => "out of memory",
        });
        return null;
    };
}

// ---------------------------------------------------------------------------
// registry node
// ---------------------------------------------------------------------------

/// How long without an applied slot before the node loop says so.
const stall_warn_ms: u64 = 60_000;

fn nowMs(io: std.Io) u64 {
    const ns = std.Io.Clock.now(.awake, io).nanoseconds;
    return @intCast(@divTrunc(ns, std.time.ns_per_ms));
}

fn readSnapshotFile(io: std.Io, dir: std.Io.Dir, gpa: std.mem.Allocator) !?registry.State {
    const bytes = dir.readFileAlloc(io, "snapshot", gpa, .limited(registry.snapshot_max_bytes + 1)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer gpa.free(bytes);
    return registry.readSnapshot(bytes) orelse error.SnapshotCorrupt;
}

/// `snapshot.tmp` → write → fsync → rename over `snapshot` (roadmap §3.8).
fn writeSnapshotFile(io: std.Io, dir: std.Io.Dir, state: *const registry.State) !void {
    var buf: [registry.snapshot_max_bytes]u8 = undefined;
    const bytes = registry.writeSnapshot(state, &buf);
    var f = try dir.createFile(io, "snapshot.tmp", .{});
    var open = true;
    defer if (open) f.close(io);
    try f.writeStreamingAll(io, bytes);
    try f.sync(io);
    f.close(io);
    open = false;
    try dir.rename("snapshot.tmp", dir, "snapshot", io);
}

fn runNode(init: std.process.Init, args: []const []const u8) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var f = flagsOrUsage(gpa, args, true) orelse return 2;
    defer f.deinit(gpa);
    const network = f.network orelse return usageError("--network is required");
    const key_path = f.key orelse return usageError("--key is required");
    const data_dir = f.data_dir orelse return usageError("--data-dir is required");
    const quorum_path = f.quorum orelse return usageError("--quorum is required");
    const listen = f.listen orelse return usageError("--listen is required");
    const rpc_port = f.rpc_port orelse return usageError("--rpc is required");
    if (f.positional.items.len != 0) return usageError("unexpected argument");

    // The quorum spec: a JSON file (docs/quorum-recipes.md), linted at create.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const qbytes = std.Io.Dir.cwd().readFileAlloc(io, quorum_path, gpa, .limited(1 << 20)) catch |err| {
        std.debug.print("registry node: cannot read --quorum {s}: {t}\n", .{ quorum_path, err });
        return 1;
    };
    defer gpa.free(qbytes);
    const quorum = slcp.Quorum.fromJson(arena.allocator(), qbytes) catch |err| {
        std.debug.print("registry node: --quorum {s} is not a quorum spec ({t}); see docs/quorum-recipes.md\n", .{ quorum_path, err });
        return 1;
    };

    // Identity: the same seed file the node loads (minted 0600 when absent).
    const kp = slcp.keys.loadOrCreate(io, key_path) catch |err| {
        std.debug.print("registry node: cannot load or create --key {s}: {t}\n", .{ key_path, err });
        return 1;
    };

    // Boot state: the snapshot, or genesis for a fresh data dir (§3.8).
    const nid = registry.networkId(network);
    const dir = std.Io.Dir.cwd().createDirPathOpen(io, data_dir, .{}) catch |err| {
        std.debug.print("registry node: cannot create --data-dir {s}: {t}\n", .{ data_dir, err });
        return 1;
    };
    defer dir.close(io);
    var restored = false;
    if (readSnapshotFile(io, dir, gpa) catch |err| {
        std.debug.print("registry node: {s}/snapshot: {t} — a corrupt snapshot cannot be repaired in E1; keep this node stopped\n", .{ data_dir, err });
        return 1;
    }) |snap| {
        if (!std.mem.eql(u8, &snap.network_id, &nid)) {
            std.debug.print("registry node: {s}/snapshot belongs to another --network; use a fresh --data-dir\n", .{data_dir});
            return 1;
        }
        app.boot = .{ .state = snap, .slot = snap.head.slot };
        restored = true;
    } else {
        // No snapshot: genesis. A data dir with a journal is judged after
        // create (below) — an uncompacted journal replays onto genesis
        // correctly; a compacted one cannot.
        app.boot = .{ .state = .{ .network_id = nid }, .slot = 0 };
    }
    const slcp_dir = try std.fmt.allocPrint(gpa, "{s}/slcp", .{data_dir});
    defer gpa.free(slcp_dir);

    var diag: slcp.node.Diagnostic = .{};
    const node = app.Node.create(gpa, io, .{
        .network = network,
        .key_file = key_path,
        .listen_port = listen,
        .peers = f.peers.items,
        .quorum = quorum,
        .data_dir = slcp_dir,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    }) catch |err| {
        std.debug.print("registry node: cannot start ({t}): {s}\n", .{ err, diag.message() });
        return 1;
    };
    defer node.deinit();
    if (!restored) {
        if (node.raw().journal_tail) |tail| {
            if (tail.first > 1) {
                // The journal was compacted and there is no snapshot: the
                // slots below the tail are gone, genesis + the tail is a
                // wrong state. (A node stopped before its first applied
                // slot has no journal, or one that starts at 1, and is fine.)
                std.debug.print("registry node: {s}/snapshot is missing but {s}/slcp holds a compacted journal (slots {d}..{d}); the state cannot be rebuilt in E1 (roadmap §2.1) — use a fresh --data-dir\n", .{ data_dir, data_dir, tail.first, tail.last });
                return 1;
            }
        }
    }

    var shared = rpc.Shared{ .io = io, .state = app.boot.state };
    const server = rpc.Server.start(gpa, io, &shared, rpc_port) catch |err| {
        std.debug.print("registry node: cannot bind the rpc port 127.0.0.1:{d}: {t}\n", .{ rpc_port, err });
        return 1;
    };
    defer server.stop();

    std.debug.print("registry: node {s} listening on port {d}; {d} peer(s); data in {s}; starting from {s} at slot {d}\n", .{
        &registry.hex32(kp.public_key), node.raw().boundPort(), f.peers.items.len, data_dir, if (restored) "the snapshot" else "genesis", app.boot.slot,
    });
    std.debug.print("registry: limits: {d} txs per set, {d} accounts, {d} names, {d} pending; busy slots every >= {d} ms, idle heartbeat every {d} ms\n", .{
        registry.max_txs, registry.max_accounts, registry.max_names, registry.max_pending, f.min_slot_ms, f.heartbeat_ms,
    });
    std.debug.print("registry: rpc listening on 127.0.0.1:{d}\n", .{server.port});

    // The cadence loop (§3.9): after every applied slot, refresh the shared
    // copy, prune the queue, persist, and propose once for the next slot —
    // right away when transactions are pending, else at the heartbeat.
    var last_close = nowMs(io);
    var proposed = false;
    // A node that fell more than ~80 slots behind (the library's 64-slot
    // hold window plus its 16-slot answering window) is not told so: the
    // statements it needs are dropped silently. Say something every minute.
    var next_stall_warn = nowMs(io) + stall_warn_ms;
    while (true) {
        const item = node.waitApplied(.{ .timeout_ms = 100 }) catch |err| switch (err) {
            error.NodeHalted => {
                if (node.haltError()) |e| {
                    std.debug.print("registry node: the node halted: {t}; see the log above\n", .{e});
                } else {
                    std.debug.print("registry node: the node halted; see the log above\n", .{});
                }
                return 1;
            },
        };
        if (item) |a| {
            if (a.slot != a.state.head.slot) {
                // Delivered a slot past a gap the library could not answer
                // (roadmap §2.1 gap 2): `apply` skipped the set (it does
                // not fit this state) and the header stayed put. Stop at
                // once — `exit`, not a return through `deinit`, so the
                // engine thread applies nothing more meanwhile.
                std.debug.print("registry node: applied slot {d} but the state's header is at slot {d}: this node missed slots the peers have already compacted and cannot rebuild them in E1 (no history catch-up until E2). Exiting with code 3; it can only rejoin a network that starts over.\n", .{ a.slot, a.state.head.slot });
                std.process.exit(3);
            }
            shared.lock();
            shared.state = a.state;
            shared.prune();
            shared.unlock();
            writeSnapshotFile(io, dir, &a.state) catch |err| {
                std.debug.print("registry node: cannot write {s}/snapshot: {t}; stopping (a node that cannot persist must stop)\n", .{ data_dir, err });
                return 1;
            };
            var ok: usize = 0;
            for (a.state.lastResults()) |r| {
                if (r == .ok) ok += 1;
            }
            const head_hex = registry.hex32(a.state.head.hash);
            std.debug.print("slot {d}: txs={d} ok={d} head={s}\n", .{ a.slot, a.state.last_count, ok, head_hex[0..16] });
            last_close = nowMs(io);
            next_stall_warn = last_close + stall_warn_ms;
            proposed = false;
        }
        if (nowMs(io) >= next_stall_warn) {
            std.debug.print("registry node: no slot applied for {d} s — either the network has no quorum (the library says `consensus needs a quorum; waiting` every 60 s) or this node fell more than ~80 slots behind and cannot rejoin in E1 (roadmap §2.1); restart it from a fresh --data-dir only when the whole network starts over\n", .{(nowMs(io) -| last_close) / 1000});
            next_stall_warn = nowMs(io) + stall_warn_ms;
        }
        if (!proposed) {
            const since = nowMs(io) -| last_close;
            var set: ?registry.TxSet = null;
            shared.lock();
            if ((shared.n_pending > 0 and since >= f.min_slot_ms) or since >= f.heartbeat_ms) {
                set = registry.proposal(&shared.state, shared.pendingSlice());
            }
            shared.unlock();
            if (set) |s| {
                node.propose(s) catch |err| {
                    std.debug.print("registry node: propose failed: {t}\n", .{err});
                };
                proposed = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// registry submit
// ---------------------------------------------------------------------------

/// The message and exit code for a client verb whose RPC request failed:
/// a malformed `--rpc` is a usage error (2), an unreachable node is 1.
fn rpcFailure(verb: []const u8, spec: []const u8, err: anyerror) u8 {
    if (err == error.BadRpcSpec) {
        std.debug.print("registry {s}: --rpc must be ip:port — an IPv4 or IPv6 literal with a port, not a hostname (got {s})\n", .{ verb, spec });
        return 2;
    }
    std.debug.print("registry {s}: cannot reach the node at {s}: {t}\n", .{ verb, spec, err });
    return 1;
}

fn runSubmit(init: std.process.Init, args: []const []const u8, out: *std.Io.Writer) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var f = flagsOrUsage(gpa, args, false) orelse return 2;
    defer f.deinit(gpa);
    const key_path = f.key orelse return usageError("--key is required");
    const pos = f.positional.items;
    if (pos.len < 2) return usageError("submit needs an operation and a name");
    const op: registry.Op = if (eql(pos[0], "claim")) .claim else if (eql(pos[0], "set")) .set else if (eql(pos[0], "transfer")) .transfer else if (eql(pos[0], "release")) .release else return usageError("operation must be claim | set | transfer | release");
    const name = pos[1];
    var value: []const u8 = "";
    var to: registry.Key = registry.zero_key;
    switch (op) {
        .set => {
            if (pos.len != 3) return usageError("set <name> <value>");
            value = pos[2];
        },
        .transfer => {
            if (pos.len != 3) return usageError("transfer <name> <hex64>");
            to = registry.parseKey(pos[2]) orelse return usageError("the transfer target must be a 64-hex public key");
        },
        .claim, .release => if (pos.len != 2) return usageError("claim/release take only a name"),
    }

    const kp = slcp.keys.load(io, key_path) catch |err| {
        std.debug.print("registry submit: cannot load --key {s}: {t}\n", .{ key_path, err });
        return 1;
    };

    // The node tells us the network id and the next seq for this key.
    var buf: [rpc.max_line]u8 = undefined;
    const head = rpc.request(io, f.rpc, "head", &buf) catch |err| return rpcFailure("submit", f.rpc, err);
    const nid = registry.parseKey(rpc.field(head, "network") orelse "") orelse {
        std.debug.print("registry submit: unexpected head reply: {s}\n", .{head});
        return 1;
    };
    var line_buf: [rpc.max_line]u8 = undefined;
    const acct_req = try std.fmt.bufPrint(&line_buf, "account {s}", .{&registry.hex32(kp.public_key)});
    const acct = rpc.request(io, f.rpc, acct_req, &buf) catch |err| return rpcFailure("submit", f.rpc, err);
    const next = std.fmt.parseInt(u64, rpc.field(acct, "next") orelse "", 10) catch {
        std.debug.print("registry submit: unexpected account reply: {s}\n", .{acct});
        return 1;
    };

    var tx = registry.Tx.init(kp.public_key, next, op, name, value, to) orelse
        return usageError("bad name or value (names are [a-z0-9-], 1..32 bytes; values up to 64 bytes)");
    tx.sign(kp.seed, nid) catch |err| {
        std.debug.print("registry submit: cannot sign: {t}\n", .{err});
        return 1;
    };
    var enc: [registry.tx_bytes]u8 = undefined;
    tx.encode(&enc);
    const hex = std.fmt.bytesToHex(enc, .lower);
    const req = try std.fmt.bufPrint(&line_buf, "submit {s}", .{&hex});
    const resp = rpc.request(io, f.rpc, req, &buf) catch |err| return rpcFailure("submit", f.rpc, err);
    try out.print("{s}\n", .{resp});
    return if (std.mem.startsWith(u8, resp, "ok")) 0 else 1;
}

// ---------------------------------------------------------------------------
// registry get | account | head
// ---------------------------------------------------------------------------

fn runQuery(init: std.process.Init, verb: []const u8, args: []const []const u8, out: *std.Io.Writer) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var f = flagsOrUsage(gpa, args, false) orelse return 2;
    defer f.deinit(gpa);
    const pos = f.positional.items;
    var line_buf: [rpc.max_line]u8 = undefined;
    const req = if (eql(verb, "head")) blk: {
        if (pos.len != 0) return usageError("head takes no argument");
        break :blk "head";
    } else blk: {
        if (pos.len != 1) return usageError(if (eql(verb, "get")) "get <name>" else "account <hex64>");
        break :blk try std.fmt.bufPrint(&line_buf, "{s} {s}", .{ verb, pos[0] });
    };
    var buf: [rpc.max_line]u8 = undefined;
    const resp = rpc.request(io, f.rpc, req, &buf) catch |err| return rpcFailure(verb, f.rpc, err);
    try out.print("{s}\n", .{resp});
    return if (std.mem.startsWith(u8, resp, "err")) 1 else 0;
}

test {
    _ = app;
}

//! rpc.zig — the registry's client port (docs/examples-roadmap.md E1,
//! "localhost RPC"): a line protocol on 127.0.0.1, one request line in, one response
//! line out. The server half runs inside `registry node`; the client half
//! is what the CLI verbs use.
//!
//! The server never touches the consensus node: it reads the latest applied
//! `State` copy and the pending queue in `Shared`, under one mutex. The main
//! thread refreshes the copy after every applied slot and drains the queue
//! into proposals (main.zig).

const std = @import("std");
const registry = @import("registry.zig");
const net = std.Io.net;
const Tx = registry.Tx;

/// Longest request or response line, newline included.
pub const max_line: usize = 2048;

// ---------------------------------------------------------------------------
// Shared state between the main thread and the RPC threads
// ---------------------------------------------------------------------------

pub const SubmitOutcome = union(enum) {
    ok,
    bad_seq: u64, // the seq the node expects from this source
    duplicate,
    queue_full,
};

pub const Shared = struct {
    io: std.Io,
    mu: std.Io.Mutex = .init,
    /// The latest applied state (a value copy; main.zig refreshes it).
    state: registry.State,
    pending: [registry.max_pending]Tx = undefined,
    n_pending: usize = 0,

    pub fn lock(self: *Shared) void {
        self.mu.lockUncancelable(self.io);
    }
    pub fn unlock(self: *Shared) void {
        self.mu.unlock(self.io);
    }

    pub fn pendingSlice(self: *Shared) []Tx {
        return self.pending[0..self.n_pending];
    }

    /// Under `mu`: how many pending transactions `source` has queued.
    pub fn pendingFrom(self: *const Shared, source: registry.Key) usize {
        var n: usize = 0;
        for (self.pending[0..self.n_pending]) |*tx| {
            if (std.mem.eql(u8, &tx.source, &source)) n += 1;
        }
        return n;
    }

    /// Under `mu`: the seq a new transaction from `source` must carry
    /// (applied seq, plus what is already queued, plus one).
    pub fn nextSeq(self: *const Shared, source: registry.Key) u64 {
        return self.state.accountSeq(source) + self.pendingFrom(source) + 1;
    }

    /// Under `mu`: the §3.10 submit rules. The signature and canonical
    /// form were checked by the caller.
    pub fn submit(self: *Shared, tx: *const Tx) SubmitOutcome {
        for (self.pending[0..self.n_pending]) |*p| {
            if (std.mem.eql(u8, &p.source, &tx.source) and p.seq == tx.seq) return .duplicate;
        }
        const expected = self.nextSeq(tx.source);
        if (tx.seq != expected) return .{ .bad_seq = expected };
        if (self.n_pending == registry.max_pending) return .queue_full;
        self.pending[self.n_pending] = tx.*;
        self.n_pending += 1;
        return .ok;
    }

    /// Under `mu`, after `state` was refreshed: drop every pending
    /// transaction at or below its account's applied seq (applied, or
    /// superseded by another node's transaction with that seq).
    pub fn prune(self: *Shared) void {
        var i: usize = 0;
        while (i < self.n_pending) {
            const tx = &self.pending[i];
            if (tx.seq <= self.state.accountSeq(tx.source)) {
                self.pending[i] = self.pending[self.n_pending - 1];
                self.n_pending -= 1;
            } else {
                i += 1;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Request handling (pure over Shared; no sockets)
// ---------------------------------------------------------------------------

fn hexOf(bytes: []const u8, out: []u8) []const u8 {
    const table = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[2 * i] = table[b >> 4];
        out[2 * i + 1] = table[b & 15];
    }
    return out[0 .. 2 * bytes.len];
}

/// Answer one request line into `out` (roadmap §3.10). Never fails: every
/// problem is an `err <code> <text>` line.
pub fn handle(shared: *Shared, line: []const u8, out: []u8) []const u8 {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    const verb = it.next() orelse return fmt(out, "err bad_request empty line", .{});
    if (std.mem.eql(u8, verb, "head")) {
        shared.lock();
        defer shared.unlock();
        const s = &shared.state;
        return fmt(out, "head slot={d} hash={s} accounts={d} names={d} pending={d} network={s}", .{
            s.head.slot, &registry.hex32(s.head.hash), s.n_accounts, s.n_names, shared.n_pending, &registry.hex32(s.network_id),
        });
    }
    if (std.mem.eql(u8, verb, "get")) {
        const name = it.next() orelse return fmt(out, "err bad_request get <name>", .{});
        if (!registry.nameOk(name)) return fmt(out, "err bad_request name must be [a-z0-9-], 1..32 bytes", .{});
        shared.lock();
        defer shared.unlock();
        const e = shared.state.findName(name) orelse return fmt(out, "none", .{});
        var vhex: [2 * registry.value_max]u8 = undefined;
        return fmt(out, "entry name={s} owner={s} value={s}", .{ e.nameSlice(), &registry.hex32(e.owner), hexOf(e.valueSlice(), &vhex) });
    }
    if (std.mem.eql(u8, verb, "account")) {
        const hex = it.next() orelse return fmt(out, "err bad_request account <hex64>", .{});
        const key = registry.parseKey(hex) orelse return fmt(out, "err bad_request account key must be 64 hex chars", .{});
        shared.lock();
        defer shared.unlock();
        return fmt(out, "account key={s} seq={d} next={d}", .{ &registry.hex32(key), shared.state.accountSeq(key), shared.nextSeq(key) });
    }
    if (std.mem.eql(u8, verb, "submit")) {
        const hex = it.next() orelse return fmt(out, "err bad_request submit <hex of {d} bytes>", .{registry.tx_bytes});
        if (hex.len != 2 * registry.tx_bytes) return fmt(out, "err bad_tx expected {d} hex chars, got {d}", .{ 2 * registry.tx_bytes, hex.len });
        var raw: [registry.tx_bytes]u8 = undefined;
        _ = std.fmt.hexToBytes(&raw, hex) catch return fmt(out, "err bad_tx not hex", .{});
        const tx = Tx.decode(&raw) orelse return fmt(out, "err bad_tx not a canonical transaction", .{});
        shared.lock();
        defer shared.unlock();
        if (!tx.verify(shared.state.network_id)) return fmt(out, "err bad_sig signature does not verify for this network", .{});
        return switch (shared.submit(&tx)) {
            .ok => fmt(out, "ok txid={s}", .{&registry.hex32(tx.digest(shared.state.network_id))}),
            .bad_seq => |want| fmt(out, "err bad_seq expected={d} got={d}", .{ want, tx.seq }),
            .duplicate => fmt(out, "err duplicate a transaction with this source and seq is already queued", .{}),
            .queue_full => fmt(out, "err queue_full {d} transactions are queued; try again after the next slot", .{registry.max_pending}),
        };
    }
    return fmt(out, "err bad_request unknown verb (head | get | account | submit)", .{});
}

fn fmt(out: []u8, comptime f: []const u8, args: anytype) []const u8 {
    return std.fmt.bufPrint(out, f, args) catch "err internal response too long";
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

fn writeAll(io: std.Io, sock: net.Socket.Handle, bytes: []const u8) !void {
    // net_write splats `data[data.len-1]`; it requires a non-empty `data`, so
    // pass a single empty pattern with splat 0 — header carries all the bytes.
    const empty_pattern: []const u8 = &.{};
    const data: [1][]const u8 = .{empty_pattern};
    var offset: usize = 0;
    while (offset < bytes.len) {
        const res = try io.operate(.{ .net_write = .{
            .socket_handle = sock,
            .header = bytes[offset..],
            .data = &data,
            .splat = 0,
        } });
        const n = try res.net_write;
        if (n == 0) return error.WriteZero;
        offset += n;
    }
}

fn portOf(addr: net.IpAddress) u16 {
    return switch (addr) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Concurrent connections the server serves; the 65th is closed at accept.
pub const max_conns: usize = 64;
/// A connection that sends nothing for this long is dropped.
pub const idle_timeout_ms: u64 = 30_000;

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    shared: *Shared,
    server: net.Server,
    port: u16,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    mu: std.Io.Mutex = .init,
    drained: std.Io.Condition = .init,
    /// Live connections (under `mu`); `stop` shuts their sockets down and
    /// waits for the list to empty before freeing anything.
    conns: std.ArrayList(*Conn) = .empty,

    /// Bind 127.0.0.1:`port` (0 = ephemeral; see `port`) and start accepting.
    /// A port somebody already answers on is refused (`AddressInUse`): on
    /// macOS `reuse_address` also sets SO_REUSEPORT, so a second listener
    /// would otherwise silently share the port with the first.
    pub fn start(gpa: std.mem.Allocator, io: std.Io, shared: *Shared, port: u16) !*Server {
        if (port != 0) {
            var probe = try net.IpAddress.parse("127.0.0.1", port);
            if (net.IpAddress.connect(&probe, io, .{ .mode = .stream })) |s| {
                s.close(io);
                return error.AddressInUse;
            } else |_| {}
        }
        const self = try gpa.create(Server);
        errdefer gpa.destroy(self);
        var addr = try net.IpAddress.parse("127.0.0.1", port);
        const srv = try net.IpAddress.listen(&addr, io, .{ .mode = .stream, .reuse_address = true });
        self.* = .{ .gpa = gpa, .io = io, .shared = shared, .server = srv, .port = portOf(srv.socket.address) };
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
        return self;
    }

    /// Stop accepting (a loopback self-connect wakes the accept thread on
    /// every OS), join it, shut down every live connection's socket so its
    /// thread returns from `read`, wait for all of them to leave, then close
    /// and free.
    pub fn stop(self: *Server) void {
        const io = self.io;
        self.stopping.store(true, .release);
        if (net.IpAddress.parse("127.0.0.1", self.port)) |*addr| {
            if (net.IpAddress.connect(addr, io, .{ .mode = .stream })) |s| s.close(io) else |_| {}
        } else |_| {}
        if (self.thread) |t| t.join();
        self.mu.lockUncancelable(io);
        for (self.conns.items) |c| c.stream.shutdown(io, .both) catch {};
        while (self.conns.items.len > 0) self.drained.waitUncancelable(io, &self.mu);
        self.mu.unlock(io);
        self.server.deinit(io);
        const gpa = self.gpa;
        self.conns.deinit(gpa);
        gpa.destroy(self);
    }

    /// Under `mu`: admit `conn` unless the cap is reached.
    fn register(self: *Server, conn: *Conn) bool {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (self.conns.items.len >= max_conns) return false;
        self.conns.append(self.gpa, conn) catch return false;
        return true;
    }

    fn unregister(self: *Server, conn: *Conn) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        for (self.conns.items, 0..) |c, i| {
            if (c == conn) {
                _ = self.conns.swapRemove(i);
                break;
            }
        }
        if (self.conns.items.len == 0) self.drained.broadcast(self.io);
    }

    fn acceptLoop(self: *Server) void {
        while (!self.stopping.load(.acquire)) {
            const stream = self.server.accept(self.io) catch {
                std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(50), .awake) catch {};
                continue;
            };
            if (self.stopping.load(.acquire)) {
                stream.close(self.io);
                break;
            }
            const conn = self.gpa.create(Conn) catch {
                stream.close(self.io);
                continue;
            };
            conn.* = .{ .server = self, .stream = stream };
            if (!self.register(conn)) {
                stream.close(self.io);
                self.gpa.destroy(conn);
                continue;
            }
            const t = std.Thread.spawn(.{}, Conn.run, .{conn}) catch {
                self.unregister(conn);
                stream.close(self.io);
                self.gpa.destroy(conn);
                continue;
            };
            t.detach();
        }
    }
};

const Conn = struct {
    server: *Server,
    stream: net.Stream,

    fn run(self: *Conn) void {
        // Locals: after `unregister` the Server may already be freed by `stop`.
        const srv = self.server;
        const io = srv.io;
        const gpa = srv.gpa;
        defer {
            srv.unregister(self); // first: `stop` only touches registered sockets
            self.stream.close(io);
            gpa.destroy(self);
        }
        var buf: [max_line]u8 = undefined;
        var len: usize = 0;
        while (true) {
            if (std.mem.indexOfScalar(u8, buf[0..len], '\n')) |nl| {
                const line = std.mem.trimEnd(u8, buf[0..nl], "\r");
                var out: [max_line]u8 = undefined;
                const resp = handle(srv.shared, line, out[0 .. max_line - 1]);
                writeAll(io, self.stream.socket.handle, resp) catch return;
                writeAll(io, self.stream.socket.handle, "\n") catch return;
                const rest = len - (nl + 1);
                std.mem.copyForwards(u8, buf[0..rest], buf[nl + 1 .. len]);
                len = rest;
                continue;
            }
            if (len == buf.len) return; // a line longer than max_line: hang up
            // A read bounded by the idle timeout (the deadline is on the Io
            // operation, not the socket — the overlay's pattern).
            var bufs: [1][]u8 = .{buf[len..]};
            const res = io.operateTimeout(.{ .net_read = .{
                .socket_handle = self.stream.socket.handle,
                .data = &bufs,
            } }, .{ .duration = .{ .raw = std.Io.Duration.fromMilliseconds(idle_timeout_ms), .clock = .awake } }) catch return;
            const n = res.net_read catch return;
            if (n == 0) return;
            len += n;
        }
    }
};

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Send `line` to `spec` ("ip:port", an IPv4/IPv6 literal) and return the
/// response line (without its newline), stored in `out`.
pub fn request(io: std.Io, spec: []const u8, line: []const u8, out: []u8) ![]const u8 {
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.BadRpcSpec;
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.BadRpcSpec;
    const host = std.mem.trim(u8, spec[0..colon], "[]");
    var addr = net.IpAddress.parse(host, port) catch return error.BadRpcSpec;
    const stream = try net.IpAddress.connect(&addr, io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream.socket.handle, line);
    try writeAll(io, stream.socket.handle, "\n");
    var len: usize = 0;
    while (len < out.len) {
        var bufs: [1][]u8 = .{out[len..]};
        const n = try stream.read(io, &bufs);
        if (n == 0) break;
        len += n;
        if (std.mem.indexOfScalar(u8, out[0..len], '\n')) |nl| return std.mem.trimEnd(u8, out[0..nl], "\r");
    }
    if (len == 0) return error.NoResponse;
    return std.mem.trimEnd(u8, out[0..len], "\r\n");
}

/// `key=value` lookup in a response line (the first token that starts with
/// `key=`); null when absent.
pub fn field(line: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    while (it.next()) |tok| {
        if (tok.len > key.len and std.mem.startsWith(u8, tok, key) and tok[key.len] == '=') return tok[key.len + 1 ..];
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testShared() Shared {
    return .{ .io = testing.io, .state = .{ .network_id = registry.networkId("rpc test") } };
}

fn signedTx(seed_byte: u8, seq: u64, name: []const u8, nid: [32]u8) Tx {
    const seed: [32]u8 = @splat(seed_byte);
    const pk = registry.publicKeyOf(seed) catch unreachable;
    var tx = Tx.init(pk, seq, .claim, name, "", registry.zero_key).?;
    tx.sign(seed, nid) catch unreachable;
    return tx;
}

// Non-vacuity: each SubmitOutcome variant is produced once; `prune` must
// drop exactly the applied/superseded entries.
test "shared: submit rules (seq, duplicate, queue) and prune after apply" {
    var sh = testShared();
    const nid = sh.state.network_id;
    const t1 = signedTx(0x21, 1, "a", nid);
    const t2 = signedTx(0x21, 2, "b", nid);
    const t3 = signedTx(0x21, 3, "c", nid);
    try testing.expectEqual(SubmitOutcome.ok, sh.submit(&t1));
    try testing.expectEqual(SubmitOutcome.duplicate, sh.submit(&t1));
    try testing.expectEqual(SubmitOutcome{ .bad_seq = 2 }, sh.submit(&t3));
    try testing.expectEqual(SubmitOutcome.ok, sh.submit(&t2));
    try testing.expectEqual(@as(u64, 3), sh.nextSeq(t1.source));
    try testing.expectEqual(@as(usize, 2), sh.n_pending);

    // Slot 1 applied t1 only (say another node's set): t1 pruned, t2 stays.
    var set: registry.TxSet = .{ .count = 1 };
    set.txs[0] = t1;
    registry.apply(&sh.state, &set);
    sh.prune();
    try testing.expectEqual(@as(usize, 1), sh.n_pending);
    try testing.expectEqual(@as(u64, 2), sh.pending[0].seq);
    try testing.expectEqual(@as(u64, 3), sh.nextSeq(t1.source));

    // Queue full.
    var full = testShared();
    for (0..registry.max_pending) |i| {
        var k: registry.Key = @splat(0);
        std.mem.writeInt(u64, k[24..32], @intCast(i + 1), .big);
        var tx = Tx.init(k, 1, .claim, "x", "", registry.zero_key).?; // unsigned: submit() does not verify
        tx.sig = @splat(0);
        try testing.expectEqual(SubmitOutcome.ok, full.submit(&tx));
    }
    try testing.expectEqual(SubmitOutcome.queue_full, full.submit(&t1));
}

// Non-vacuity: every verb and every `err` code in `handle` has a line here;
// the `field` helper must find the first `key=` token only.
test "handle: head/get/account/submit lines and every error code" {
    var sh = testShared();
    const nid = sh.state.network_id;
    var out: [max_line]u8 = undefined;
    var r = handle(&sh, "head", &out);
    try testing.expectEqualStrings("0", field(r, "slot").?);
    try testing.expectEqualStrings(&registry.hex32(nid), field(r, "network").?);
    try testing.expectEqualStrings("0", field(r, "pending").?);

    r = handle(&sh, "get alice", &out);
    try testing.expectEqualStrings("none", r);
    r = handle(&sh, "get Alice", &out);
    try testing.expect(std.mem.startsWith(u8, r, "err bad_request"));

    const t1 = signedTx(0x31, 1, "alice", nid);
    var enc: [registry.tx_bytes]u8 = undefined;
    t1.encode(&enc);
    var hex_buf: [2 * registry.tx_bytes]u8 = undefined;
    const hex = hexOf(&enc, &hex_buf);
    var line_buf: [max_line]u8 = undefined;
    const submit_line = try std.fmt.bufPrint(&line_buf, "submit {s}", .{hex});
    r = handle(&sh, submit_line, &out);
    try testing.expectEqualStrings(&registry.hex32(t1.digest(nid)), field(r, "txid").?);
    try testing.expect(std.mem.startsWith(u8, r, "ok "));
    r = handle(&sh, submit_line, &out);
    try testing.expect(std.mem.startsWith(u8, r, "err duplicate"));
    var pk_hex_buf: [64]u8 = undefined;
    const acct_line = try std.fmt.bufPrint(&line_buf, "account {s}", .{hexOf(&t1.source, &pk_hex_buf)});
    r = handle(&sh, acct_line, &out);
    try testing.expectEqualStrings("0", field(r, "seq").?);
    try testing.expectEqualStrings("2", field(r, "next").?);

    // bad_seq, bad_sig, bad_tx, bad_request.
    const t5 = signedTx(0x31, 5, "bob", nid);
    t5.encode(&enc);
    const l5 = try std.fmt.bufPrint(&line_buf, "submit {s}", .{hexOf(&enc, &hex_buf)});
    r = handle(&sh, l5, &out);
    try testing.expect(std.mem.startsWith(u8, r, "err bad_seq expected=2"));
    var wrong = signedTx(0x31, 2, "bob", registry.networkId("other"));
    wrong.encode(&enc);
    const lw = try std.fmt.bufPrint(&line_buf, "submit {s}", .{hexOf(&enc, &hex_buf)});
    r = handle(&sh, lw, &out);
    try testing.expect(std.mem.startsWith(u8, r, "err bad_sig"));
    wrong = t1;
    wrong.name[0] = 'A'; // non-canonical bytes → not a transaction at all
    wrong.encode(&enc);
    const lb = try std.fmt.bufPrint(&line_buf, "submit {s}", .{hexOf(&enc, &hex_buf)});
    r = handle(&sh, lb, &out);
    try testing.expect(std.mem.startsWith(u8, r, "err bad_tx"));
    r = handle(&sh, "submit abc", &out);
    try testing.expect(std.mem.startsWith(u8, r, "err bad_tx"));
    r = handle(&sh, "frobnicate", &out);
    try testing.expect(std.mem.startsWith(u8, r, "err bad_request"));
    r = handle(&sh, "", &out);
    try testing.expect(std.mem.startsWith(u8, r, "err bad_request"));

    // After the claim applies, `get` shows the entry with a hex value.
    var set: registry.TxSet = .{ .count = 1 };
    set.txs[0] = t1;
    registry.apply(&sh.state, &set);
    var v = signedTx(0x31, 2, "alice", nid);
    v = Tx.init(v.source, 2, .set, "alice", "hi", registry.zero_key).?;
    v.sign(@splat(0x31), nid) catch unreachable;
    var set2: registry.TxSet = .{ .count = 1 };
    set2.txs[0] = v;
    registry.apply(&sh.state, &set2);
    r = handle(&sh, "get alice", &out);
    try testing.expectEqualStrings("alice", field(r, "name").?);
    try testing.expectEqualStrings("6869", field(r, "value").?);
    try testing.expectEqualStrings(&registry.hex32(t1.source), field(r, "owner").?);
    try testing.expect(field(r, "nothing") == null);
}

// Non-vacuity: a real socket round-trip through Server + request; dropping
// the newline handling in Conn.run leaves the client waiting (NoResponse
// after EOF is what `request` returns when the server hangs up).
test "server + client: one request line, one response line over loopback; stop joins" {
    const gpa = testing.allocator;
    const io = testing.io;
    var sh = testShared();
    const srv = try Server.start(gpa, io, &sh, 0);
    defer srv.stop();
    var spec_buf: [32]u8 = undefined;
    const spec = try std.fmt.bufPrint(&spec_buf, "127.0.0.1:{d}", .{srv.port});
    var out: [max_line]u8 = undefined;
    const r = try request(io, spec, "head", &out);
    try testing.expectEqualStrings("0", field(r, "slot").?);
    const r2 = try request(io, spec, "get nobody", &out);
    try testing.expectEqualStrings("none", r2);
    try testing.expectError(error.BadRpcSpec, request(io, "nonsense", "head", &out));
    try testing.expectError(error.BadRpcSpec, request(io, "localhost:1", "head", &out));
}

// Non-vacuity: without the connect probe in `Server.start`, macOS (where
// `reuse_address` also sets SO_REUSEPORT) lets the second listener share
// the port and this test's second `start` succeeds.
test "server: a port somebody already answers on is refused" {
    const gpa = testing.allocator;
    const io = testing.io;
    var sh = testShared();
    const first = try Server.start(gpa, io, &sh, 0);
    defer first.stop();
    if (Server.start(gpa, io, &sh, first.port)) |second| {
        second.stop();
        return error.SecondListenerAccepted;
    } else |err| {
        try testing.expectEqual(error.AddressInUse, err);
    }
}

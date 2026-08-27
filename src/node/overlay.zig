//! TCP flood-gossip overlay (design §9). Symmetric: every node listens AND
//! dials. Deliberately NOT capnp RPC — it reuses only capnp-zig's frozen
//! segment framer and otherwise drives sockets straight on `std.Io.net`:
//!
//!   * capnpc.rpc.wire.framing.Framer   — segment-frame reassembly
//!   * std.Io.net.{Server,Stream}       — listen/accept/connect + blocking I/O
//!
//! (capnp-zig's `tcp.stream.Transport` was the natural fit for the per-conn
//! writer thread, but its write path calls `io.vtable.netWrite`, a VTable
//! entry that no longer exists on the pinned Zig — so this module owns a small
//! equivalent: a blocking reader plus an async, queue-backed writer thread.)
//!
//! Trust model (§9.1): ONLY envelope signatures are authenticated. Hello
//! fields are unauthenticated hints. A wrong `networkIdPrefix` ⇒ disconnect.
//!
//! Threading (§9.3): one accept thread; one reader thread per connection; one
//! writer thread per connection (draining that connection's send queue). The
//! engine thread calls broadcast/send/broadcastExcept during effect drain;
//! reader threads call the `on_recv` callback. The peer table is mutex-guarded;
//! sends go through each connection's thread-safe write queue.
//!
//! Callback contract: `on_recv(ctx, peer_id, frame)` is invoked on a reader
//! thread with a BORROWED frame — valid only for the call; copy anything you
//! keep. `on_peer_up(ctx, peer_id)` fires once per peer after a valid Hello
//! exchange (the Node uses it to push catch-up: own latest envelopes +
//! getSlotState(0)). Neither callback may block on the engine.
//!
//! ==== IMPLEMENTATION NOTES (M5) ==========================================
//! All private state lives on `Overlay` and is wired up in `start`, so the
//! frozen `init` stays pointer-free and the Node can hold us by value.
//!
//!   * One accept thread (`acceptLoop`) blocks in `Server.accept`. Each
//!     accepted stream becomes a heap `Conn` and a reader thread (`connThread`).
//!   * One dialer thread per configured peer (`dialerLoop`) owns exactly one
//!     outbound connection at a time and reconnects with exponential backoff
//!     (1s→60s) plus deterministic per-peer jitter (Wyhash over the attempt
//!     counter — no wall clock, no RNG).
//!   * Every connection, inbound or outbound, runs `runConnection`: register
//!     the `Conn`, send OUR Hello first, read the peer's first frame and
//!     require a matching Hello, then start the writer, assign a stable
//!     peer_id, fire `on_peer_up`, and enter the read loop delivering frames
//!     to `on_recv`.
//!
//! Shutdown (`stop`, idempotent): flip `stopping`, wake the dialers' backoff
//! condvar, `shutdown`+close the listener (which — per `Server.accept`'s
//! documented contract — unblocks a parked accept), join the accept thread
//! (after which no new inbound conns appear), `shutdown` every live socket
//! (so every reader's blocking `read` returns EOF and every writer wakes),
//! then join every reader and dialer thread. Each reader frees its own `Conn`
//! on the way out, so after the joins the peer table is empty; `deinit` frees
//! the table.
//!
//! Sends hold the peer-table mutex across `enqueue` (which only touches the
//! connection's own queue lock, never blocking I/O), while a reader's teardown
//! removes its `Conn` from the table under the same mutex before tearing the
//! socket down — so a send never races a free. Readers enter the table only
//! AFTER starting the writer, so `enqueue` is always the async path and no two
//! threads ever sync-write the same fd.
//! ========================================================================

const std = @import("std");
const builtin = @import("builtin");
const core = @import("slcp-core");
const capnpc = @import("capnpc-zig");
const wire = @import("wire.zig");

const log = std.log.scoped(.slcp_overlay);

const net = std.Io.net;
const framing = capnpc.rpc.wire.framing;

pub const default_read_buffer_size: usize = 256 * 1024;
pub const inbound_rate_soft_cap_bytes_per_s: usize = 256 * 1024;
pub const max_outstanding_requests: usize = 64;

/// Consecutive per-peer budget breaches before we disconnect the peer. Kept
/// well clear of anything healthy loopback traffic produces.
const max_budget_strikes: u32 = 32;
/// Upper bound on the backoff-window exponent (1s<<6 = 64s, capped to 60s).
const max_backoff_shift: u6 = 6;

pub const RecvFn = *const fn (ctx: ?*anyopaque, peer_id: usize, frame: *const wire.OverlayFrame) void;
pub const PeerEventFn = *const fn (ctx: ?*anyopaque, peer_id: usize) void;

// -----------------------------------------------------------------------
// Test-only link filter (design §13.6 e2e partition/heal). When set, the
// send path drops any frame whose (local nodeId, peer nodeId) pair the
// filter rejects — simulating a network partition WITHOUT touching the wire
// or the public surface. Null in production. Set/read atomically because it
// crosses the test thread and the engine/reader threads.
// -----------------------------------------------------------------------
pub const TestLinkFilter = *const fn (local: [32]u8, peer: [32]u8) bool;
var g_test_link_filter: ?TestLinkFilter = null;

pub fn setTestLinkFilter(f: ?TestLinkFilter) void {
    @atomicStore(?TestLinkFilter, &g_test_link_filter, f, .seq_cst);
}

fn linkAllowed(local: [32]u8, peer: [32]u8) bool {
    const f = @atomicLoad(?TestLinkFilter, &g_test_link_filter, .seq_cst) orelse return true;
    return f(local, peer);
}

pub const Config = struct {
    listen_port: u16,
    /// "host:port" strings to dial.
    peers: []const []const u8,
    network_id_prefix: [8]u8,
    node_id: [32]u8,
};

pub const Callbacks = struct {
    ctx: ?*anyopaque = null,
    on_recv: RecvFn,
    on_peer_up: PeerEventFn,
    on_peer_down: ?PeerEventFn = null,
};

/// One live connection: the socket, a blocking reader (the owning reader
/// thread) and an async, queue-backed writer thread. Heap-allocated so its
/// address (captured by the writer thread) stays stable. Budget fields are
/// touched only by this connection's own reader thread.
const Conn = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    stream: net.Stream,
    read_buf: []u8,

    /// Stable id assigned once the Hello exchange completes; 0 until then.
    id: usize = 0,
    hello_done: bool = false,
    outbound: bool = false,
    /// The peer's advertised (unauthenticated) nodeId from its Hello. Used
    /// only by the test link filter to simulate network partitions.
    peer_node_id: [32]u8 = @splat(0),

    // Async write queue drained by the writer thread.
    wq_mu: std.Io.Mutex = .init,
    wq_cond: std.Io.Condition = .init,
    wq: std.ArrayListUnmanaged([]u8) = .empty,
    wq_closed: bool = false,
    writer_started: bool = false,
    writer_thread: ?std.Thread = null,

    // Per-peer inbound budget window (reader-thread-local; no lock).
    win_start_ns: i96 = 0,
    win_bytes: usize = 0,
    win_reqs: usize = 0,
    strikes: u32 = 0,

    fn read(self: *Conn) net.Stream.Reader.Error!usize {
        var bufs: [1][]u8 = .{self.read_buf};
        return self.stream.read(self.io, &bufs);
    }

    /// Copy `bytes` onto the write queue (async) or, before the writer thread
    /// exists (handshake), write them synchronously on the caller's thread.
    fn enqueue(self: *Conn, bytes: []const u8) !void {
        if (!self.writer_started) {
            return writeAll(self.io, self.stream.socket.handle, bytes);
        }
        self.wq_mu.lockUncancelable(self.io);
        defer self.wq_mu.unlock(self.io);
        if (self.wq_closed) return error.WriteClosed;
        const copy = try self.gpa.dupe(u8, bytes);
        errdefer self.gpa.free(copy);
        try self.wq.append(self.gpa, copy);
        self.wq_cond.signal(self.io);
    }

    fn startWriter(self: *Conn) !void {
        self.writer_thread = try std.Thread.spawn(.{}, writerLoop, .{self});
        self.writer_started = true;
    }

    fn writerLoop(self: *Conn) void {
        const io = self.io;
        const gpa = self.gpa;
        const handle = self.stream.socket.handle;
        while (true) {
            self.wq_mu.lockUncancelable(io);
            while (self.wq.items.len == 0 and !self.wq_closed) {
                self.wq_cond.waitUncancelable(io, &self.wq_mu);
            }
            if (self.wq.items.len == 0) {
                self.wq_mu.unlock(io);
                break; // closed and drained
            }
            var batch = self.wq;
            self.wq = .empty;
            self.wq_mu.unlock(io);

            var failed = false;
            for (batch.items) |item| {
                if (!failed) writeAll(io, handle, item) catch {
                    failed = true;
                };
                gpa.free(item);
            }
            batch.deinit(gpa);
            if (failed) {
                self.shutdown();
                break;
            }
        }
    }

    /// Unblock the reader (socket EOF) and wake the writer to exit. Thread-safe
    /// and idempotent.
    fn shutdown(self: *Conn) void {
        self.stream.shutdown(self.io, .both) catch {};
        self.closeQueue();
    }

    fn closeQueue(self: *Conn) void {
        self.wq_mu.lockUncancelable(self.io);
        defer self.wq_mu.unlock(self.io);
        self.wq_closed = true;
        self.wq_cond.broadcast(self.io);
    }

    /// Join the writer, then release the socket and all buffers. Caller must
    /// have already removed us from the peer table.
    fn deinit(self: *Conn) void {
        self.closeQueue();
        if (self.writer_thread) |t| {
            t.join();
            self.writer_thread = null;
        }
        for (self.wq.items) |item| self.gpa.free(item);
        self.wq.deinit(self.gpa);
        self.stream.close(self.io);
        self.gpa.free(self.read_buf);
    }
};

pub const Overlay = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    cfg: Config,
    cb: Callbacks,
    _placeholder: usize = 0,

    // ---- private state, all default-initialized; wired up in `start` -------
    started: bool = false,
    deinited: bool = false,
    stopping: std.atomic.Value(bool) = .init(false),
    bound_port: u16 = 0,
    next_peer_id: usize = 1,

    server: ?net.Server = null,
    accept_thread: ?std.Thread = null,
    /// Reader threads spawned by the accept thread (one per inbound conn).
    conn_threads: std.ArrayListUnmanaged(std.Thread) = .empty,
    /// One dialer thread per configured peer (fixed for our lifetime).
    dialer_threads: std.ArrayListUnmanaged(std.Thread) = .empty,

    /// Guards `conns`, per-conn id/hello_done, and `next_peer_id`.
    conns_mu: std.Io.Mutex = .init,
    /// Every live connection (handshaking + established), for send/broadcast
    /// iteration and for shutdown fan-out.
    conns: std.ArrayListUnmanaged(*Conn) = .empty,

    /// Backoff/shutdown wakeup for dialer threads.
    wait_mu: std.Io.Mutex = .init,
    wait_cond: std.Io.Condition = .init,

    /// Initialize (no sockets yet). The Node holds the Overlay by stable
    /// pointer; init must not capture `&self` internally — do that in start.
    pub fn init(gpa: std.mem.Allocator, io: std.Io, cfg: Config, cb: Callbacks) !Overlay {
        return .{ .gpa = gpa, .io = io, .cfg = cfg, .cb = cb };
    }

    /// Bind the listener, spawn the accept thread, and start dialing peers.
    pub fn start(self: *Overlay) !void {
        if (self.started) return;

        const bind_addr: net.IpAddress = .{ .ip4 = .unspecified(self.cfg.listen_port) };
        self.server = try net.IpAddress.listen(&bind_addr, self.io, .{
            .mode = .stream,
            .reuse_address = true,
        });
        errdefer {
            self.closeListener();
        }
        self.bound_port = portOf(self.server.?.socket.address);

        try self.dialer_threads.ensureTotalCapacity(self.gpa, self.cfg.peers.len);

        self.accept_thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
        // From here, any failure must join everything already spawned.
        errdefer {
            self.stopping.store(true, .release);
            self.joinAll();
        }

        for (self.cfg.peers, 0..) |_, i| {
            const t = try std.Thread.spawn(.{}, dialerLoop, .{ self, i });
            self.dialer_threads.appendAssumeCapacity(t);
        }

        self.started = true;
    }

    /// The actually-bound listen port (equals cfg.listen_port unless 0 was
    /// given for an ephemeral port).
    pub fn boundPort(self: *Overlay) u16 {
        return self.bound_port;
    }

    /// Encode `frame` and enqueue it to every connected, Hello-complete peer.
    pub fn broadcast(self: *Overlay, frame: wire.OverlayFrame) void {
        self.emit(frame, .all);
    }

    /// Send `frame` to one peer (no-op if that peer is gone).
    pub fn send(self: *Overlay, peer_id: usize, frame: wire.OverlayFrame) void {
        self.emit(frame, .{ .one = peer_id });
    }

    /// Broadcast to all peers except `except_peer_id` (the relay path).
    pub fn broadcastExcept(self: *Overlay, except_peer_id: usize, frame: wire.OverlayFrame) void {
        self.emit(frame, .{ .except = except_peer_id });
    }

    /// Number of Hello-complete peers.
    pub fn peerCount(self: *Overlay) usize {
        self.conns_mu.lockUncancelable(self.io);
        defer self.conns_mu.unlock(self.io);
        var n: usize = 0;
        for (self.conns.items) |conn| {
            if (conn.hello_done) n += 1;
        }
        return n;
    }

    /// Stop accepting/dialing, close peers, join all threads. Idempotent.
    pub fn stop(self: *Overlay) void {
        if (self.stopping.swap(true, .acq_rel)) return;
        self.joinAll();
    }

    pub fn deinit(self: *Overlay) void {
        if (self.deinited) return;
        self.deinited = true;
        // stop() has joined every thread, so every Conn has already removed
        // itself and freed its own socket/buffers; only the backing lists are
        // left.
        self.conns.deinit(self.gpa);
        self.conn_threads.deinit(self.gpa);
        self.dialer_threads.deinit(self.gpa);
        self.server = null;
    }

    // -----------------------------------------------------------------------
    // Send path (engine thread + reader threads via callbacks)
    // -----------------------------------------------------------------------

    const Target = union(enum) {
        all,
        one: usize,
        except: usize,
    };

    fn emit(self: *Overlay, frame: wire.OverlayFrame, target: Target) void {
        const bytes = wire.encode(self.gpa, frame) catch |err| {
            log.warn("overlay: dropping frame, encode failed: {t}", .{err});
            return;
        };
        defer self.gpa.free(bytes);

        self.conns_mu.lockUncancelable(self.io);
        defer self.conns_mu.unlock(self.io);
        for (self.conns.items) |conn| {
            if (!conn.hello_done) continue;
            switch (target) {
                .all => {},
                .one => |id| if (conn.id != id) continue,
                .except => |id| if (conn.id == id) continue,
            }
            // Test-only partition simulation; a no-op in production.
            if (!linkAllowed(self.cfg.node_id, conn.peer_node_id)) continue;
            // enqueue copies `bytes` and only touches the conn's queue lock; it
            // never blocks on I/O, so holding conns_mu is fine.
            conn.enqueue(bytes) catch |err| {
                log.debug("overlay: enqueue to peer {d} failed: {t}", .{ conn.id, err });
            };
        }
    }

    // -----------------------------------------------------------------------
    // Accept + dial
    // -----------------------------------------------------------------------

    fn acceptLoop(self: *Overlay) void {
        while (!self.stopping.load(.acquire)) {
            const stream = self.server.?.accept(self.io) catch {
                if (self.stopping.load(.acquire)) break;
                // Transient accept error; pause briefly to avoid a busy spin.
                self.waitInterruptible(10 * std.time.ns_per_ms);
                continue;
            };
            if (self.stopping.load(.acquire)) {
                stream.close(self.io);
                break;
            }
            setTcpNoDelay(stream.socket.handle);
            self.startInboundConn(stream);
        }
    }

    fn startInboundConn(self: *Overlay, stream: net.Stream) void {
        const conn = self.makeConn(stream, false) orelse return;
        self.conns_mu.lockUncancelable(self.io);
        defer self.conns_mu.unlock(self.io);
        // Reserve the join slot before spawning so we can never lose a handle.
        self.conn_threads.ensureUnusedCapacity(self.gpa, 1) catch {
            conn.deinit();
            self.gpa.destroy(conn);
            return;
        };
        const t = std.Thread.spawn(.{}, connThread, .{ self, conn }) catch {
            conn.deinit();
            self.gpa.destroy(conn);
            return;
        };
        self.conn_threads.appendAssumeCapacity(t);
    }

    fn dialerLoop(self: *Overlay, peer_index: usize) void {
        const spec = self.cfg.peers[peer_index];
        var attempt: u32 = 0;
        while (!self.stopping.load(.acquire)) {
            const conn = self.dialOne(spec) orelse {
                self.waitInterruptible(backoffNs(peer_index, attempt));
                if (attempt < 30) attempt += 1;
                continue;
            };
            attempt = 0; // TCP connect succeeded — reset backoff growth.
            self.runConnection(conn);
            if (self.stopping.load(.acquire)) break;
            // Reconnect after a base (attempt 0 ≈ 1s) delay + jitter.
            self.waitInterruptible(backoffNs(peer_index, 0));
        }
    }

    fn dialOne(self: *Overlay, spec: []const u8) ?*Conn {
        const hp = parseHostPort(spec) catch {
            log.warn("overlay: bad peer spec '{s}'", .{spec});
            return null;
        };
        var addr = net.IpAddress.parse(hp.host, hp.port) catch {
            log.warn("overlay: cannot parse peer address '{s}'", .{spec});
            return null;
        };
        const stream = net.IpAddress.connect(&addr, self.io, .{ .mode = .stream }) catch {
            return null;
        };
        setTcpNoDelay(stream.socket.handle);
        return self.makeConn(stream, true);
    }

    /// Wrap `stream` in a heap Conn. Closes `stream` and returns null on
    /// failure. On success the Conn owns the socket.
    fn makeConn(self: *Overlay, stream: net.Stream, outbound: bool) ?*Conn {
        const buf = self.gpa.alloc(u8, default_read_buffer_size) catch {
            stream.close(self.io);
            return null;
        };
        const conn = self.gpa.create(Conn) catch {
            self.gpa.free(buf);
            stream.close(self.io);
            return null;
        };
        conn.* = .{
            .io = self.io,
            .gpa = self.gpa,
            .stream = stream,
            .read_buf = buf,
            .outbound = outbound,
        };
        return conn;
    }

    // -----------------------------------------------------------------------
    // Per-connection lifecycle (reader thread)
    // -----------------------------------------------------------------------

    fn connThread(self: *Overlay, conn: *Conn) void {
        self.runConnection(conn);
    }

    fn runConnection(self: *Overlay, conn: *Conn) void {
        const gpa = self.gpa;

        // Register in the peer table, or bail immediately if we are stopping
        // (this closes the race with a concurrent shutdown fan-out that ran
        // before we got here).
        self.conns_mu.lockUncancelable(self.io);
        if (self.stopping.load(.acquire)) {
            self.conns_mu.unlock(self.io);
            conn.deinit();
            gpa.destroy(conn);
            return;
        }
        self.conns.append(gpa, conn) catch {
            self.conns_mu.unlock(self.io);
            conn.deinit();
            gpa.destroy(conn);
            return;
        };
        self.conns_mu.unlock(self.io);

        var framer = framing.Framer.init(gpa);

        if (self.handshake(conn, &framer)) {
            // Start the writer BEFORE the peer is visible to senders, so every
            // enqueue takes the async path (no two threads sync-write).
            conn.startWriter() catch |err| {
                log.warn("overlay: startWriter failed: {t}", .{err});
            };
            self.conns_mu.lockUncancelable(self.io);
            conn.id = self.next_peer_id;
            self.next_peer_id += 1;
            conn.hello_done = true;
            self.conns_mu.unlock(self.io);

            self.cb.on_peer_up(self.cb.ctx, conn.id);
            self.readLoop(conn, &framer);
            if (self.cb.on_peer_down) |down| down(self.cb.ctx, conn.id);
        }

        framer.deinit();
        // Remove from the table (under the lock) BEFORE tearing the socket
        // down, so no in-flight send can reference a freed connection.
        self.removeConn(conn);
        conn.deinit();
        gpa.destroy(conn);
    }

    /// Send our Hello, then read + validate the peer's Hello. Returns true iff
    /// the peer is an accepted flood peer.
    fn handshake(self: *Overlay, conn: *Conn, framer: *framing.Framer) bool {
        self.sendHello(conn) catch return false;

        const raw = self.nextRawFrame(conn, framer) orelse return false;
        defer self.gpa.free(raw);
        var frame = wire.decode(self.gpa, raw) catch return false;
        defer frame.deinit(self.gpa);
        switch (frame) {
            .hello => |h| {
                if (h.protocol_version != wire.protocol_version) {
                    log.warn("overlay: rejecting peer, protocol_version {d}", .{h.protocol_version});
                    return false;
                }
                if (!std.mem.eql(u8, &h.network_id_prefix, &self.cfg.network_id_prefix)) {
                    log.warn("overlay: rejecting peer, network_id_prefix mismatch", .{});
                    return false;
                }
                conn.peer_node_id = h.node_id; // advisory; used by the test link filter
                return true;
            },
            else => {
                log.warn("overlay: rejecting peer, first frame was not a Hello", .{});
                return false;
            },
        }
    }

    fn sendHello(self: *Overlay, conn: *Conn) !void {
        const frame: wire.OverlayFrame = .{ .hello = .{
            .protocol_version = wire.protocol_version,
            .network_id_prefix = self.cfg.network_id_prefix,
            .node_id = self.cfg.node_id,
            .current_slot = 0,
            .listen_port = self.bound_port,
        } };
        const bytes = try wire.encode(self.gpa, frame);
        defer self.gpa.free(bytes);
        // Writer not started yet ⇒ this is a synchronous blocking write, which
        // is exactly what we want: our Hello leaves first, on one thread.
        try conn.enqueue(bytes);
    }

    fn readLoop(self: *Overlay, conn: *Conn, framer: *framing.Framer) void {
        const gpa = self.gpa;
        while (true) {
            const raw = self.nextRawFrame(conn, framer) orelse return;
            defer gpa.free(raw);
            var frame = wire.decode(gpa, raw) catch |err| {
                // Valid framing, malformed contents: drop the frame, keep peer.
                log.debug("overlay: dropping malformed frame from peer {d}: {t}", .{ conn.id, err });
                continue;
            };
            defer frame.deinit(gpa);
            if (isRequestFrame(frame) and !self.chargeRequest(conn)) continue;
            self.cb.on_recv(self.cb.ctx, conn.id, &frame);
        }
    }

    /// Pull the next complete wire frame (caller frees), or null on EOF, read
    /// error, framing error, or a byte-budget disconnect.
    fn nextRawFrame(self: *Overlay, conn: *Conn, framer: *framing.Framer) ?[]u8 {
        while (true) {
            const popped = framer.popFrame() catch {
                framer.reset();
                return null;
            };
            if (popped) |f| return f;

            const n = conn.read() catch return null;
            if (n == 0) return null; // EOF or socket shut down.
            if (!self.chargeBytes(conn, n)) return null;
            framer.push(conn.read_buf[0..n]) catch {
                framer.reset();
                return null;
            };
        }
    }

    // -----------------------------------------------------------------------
    // Per-peer inbound budgets (§9.1). Reader-thread-local, no lock.
    // -----------------------------------------------------------------------

    fn rollWindow(self: *Overlay, conn: *Conn) void {
        const now = self.monoNs();
        if (now - conn.win_start_ns >= std.time.ns_per_s) {
            conn.win_start_ns = now;
            conn.win_bytes = 0;
            conn.win_reqs = 0;
        }
    }

    /// Charge `n` inbound bytes; returns false to disconnect on repeated breach.
    fn chargeBytes(self: *Overlay, conn: *Conn, n: usize) bool {
        self.rollWindow(conn);
        conn.win_bytes += n;
        if (conn.win_bytes > inbound_rate_soft_cap_bytes_per_s) {
            conn.strikes += 1;
            log.warn("overlay: peer {d} byte-rate breach ({d} B in window), strike {d}", .{ conn.id, conn.win_bytes, conn.strikes });
            if (conn.strikes >= max_budget_strikes) {
                log.warn("overlay: peer {d} exceeded budget strikes; disconnecting", .{conn.id});
                return false;
            }
        }
        return true;
    }

    /// Charge one inbound request; returns false to drop (drop-and-log) it.
    fn chargeRequest(self: *Overlay, conn: *Conn) bool {
        self.rollWindow(conn);
        conn.win_reqs += 1;
        if (conn.win_reqs > max_outstanding_requests) {
            conn.strikes += 1;
            log.warn("overlay: peer {d} request-rate breach ({d} in window); dropping request", .{ conn.id, conn.win_reqs });
            return false;
        }
        return true;
    }

    fn monoNs(self: *Overlay) i96 {
        return std.Io.Clock.now(.awake, self.io).nanoseconds;
    }

    // -----------------------------------------------------------------------
    // Table + shutdown helpers
    // -----------------------------------------------------------------------

    fn removeConn(self: *Overlay, conn: *Conn) void {
        self.conns_mu.lockUncancelable(self.io);
        defer self.conns_mu.unlock(self.io);
        for (self.conns.items, 0..) |c, i| {
            if (c == conn) {
                _ = self.conns.swapRemove(i);
                return;
            }
        }
    }

    fn shutdownAllConns(self: *Overlay) void {
        self.conns_mu.lockUncancelable(self.io);
        defer self.conns_mu.unlock(self.io);
        for (self.conns.items) |conn| conn.shutdown();
    }

    /// Shut down (to wake a parked accept — see `Server.accept`) then close the
    /// listening socket. Idempotent.
    fn closeListener(self: *Overlay) void {
        if (self.server) |*s| {
            self.io.vtable.netShutdown(self.io.userdata, s.socket.handle, .both) catch {};
            s.socket.close(self.io);
            self.server = null;
        }
    }

    fn joinAll(self: *Overlay) void {
        // Wake any dialer parked in backoff.
        self.wakeWaiters();
        // Unblock the accept thread, then join it: after this, no NEW inbound
        // connection threads can be spawned.
        self.closeListener();
        if (self.accept_thread) |t| {
            t.join();
            self.accept_thread = null;
        }
        // Unblock every reader's blocking read, then join the reader threads.
        self.shutdownAllConns();
        for (self.conn_threads.items) |t| t.join();
        self.conn_threads.clearAndFree(self.gpa);
        for (self.dialer_threads.items) |t| t.join();
        self.dialer_threads.clearAndFree(self.gpa);
    }

    fn wakeWaiters(self: *Overlay) void {
        self.wait_mu.lockUncancelable(self.io);
        defer self.wait_mu.unlock(self.io);
        self.wait_cond.broadcast(self.io);
    }

    /// Sleep up to `ns`, returning early if we start stopping.
    fn waitInterruptible(self: *Overlay, ns: u64) void {
        self.wait_mu.lockUncancelable(self.io);
        defer self.wait_mu.unlock(self.io);
        if (self.stopping.load(.acquire)) return;
        self.wait_cond.waitTimeout(self.io, &self.wait_mu, .{ .duration = .{
            .raw = std.Io.Duration.fromNanoseconds(@intCast(ns)),
            .clock = .awake,
        } }) catch {};
    }
};

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Blocking write of every byte in `bytes` to `handle`, retrying partial
/// writes. Uses the `net_write` operation directly (header-only, no splat).
fn writeAll(io: std.Io, handle: net.Socket.Handle, bytes: []const u8) !void {
    // net_write splats `data[data.len-1]`; it requires a non-empty `data`, so
    // pass a single empty pattern with splat 0 — header carries all the bytes.
    const empty_pattern: []const u8 = &.{};
    const data: [1][]const u8 = .{empty_pattern};
    var offset: usize = 0;
    while (offset < bytes.len) {
        const res = try io.operate(.{ .net_write = .{
            .socket_handle = handle,
            .header = bytes[offset..],
            .data = &data,
            .splat = 0,
        } });
        const n = try res.net_write;
        if (n == 0) return error.WriteZero;
        offset += n;
    }
}

/// Best-effort TCP_NODELAY; loopback control frames are latency-sensitive.
/// Failures are ignored (the socket may already be torn down by the peer).
fn setTcpNoDelay(handle: net.Socket.Handle) void {
    if (comptime builtin.target.os.tag == .windows) return;
    const one = std.mem.toBytes(@as(c_int, 1));
    _ = std.posix.system.setsockopt(
        handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        &one,
        @intCast(one.len),
    );
}

fn portOf(addr: net.IpAddress) u16 {
    return switch (addr) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
}

fn isRequestFrame(frame: wire.OverlayFrame) bool {
    return switch (frame) {
        .get_qset, .get_slot_state => true,
        else => false,
    };
}

const HostPort = struct { host: []const u8, port: u16 };

fn parseHostPort(spec: []const u8) !HostPort {
    const idx = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.BadPeerSpec;
    if (idx == 0 or idx + 1 >= spec.len) return error.BadPeerSpec;
    return .{
        .host = spec[0..idx],
        .port = try std.fmt.parseInt(u16, spec[idx + 1 ..], 10),
    };
}

/// Exponential backoff 1s→60s plus deterministic per-peer jitter (Wyhash over
/// the attempt counter — no wall clock, no RNG, so tests stay reproducible).
fn backoffNs(peer_index: usize, attempt: u32) u64 {
    const shift: u6 = @intCast(@min(attempt, @as(u32, max_backoff_shift)));
    const base_s: u64 = @min(@as(u64, 1) << shift, 60);
    const base_ns = base_s * std.time.ns_per_s;

    var h = std.hash.Wyhash.init(@as(u64, peer_index));
    h.update(std.mem.asBytes(&attempt));
    const jitter_ns = (h.final() % 1000) * std.time.ns_per_ms;
    return base_ns + jitter_ns;
}

// ---------------------------------------------------------------------------
// Tests (loopback, std.testing.allocator, generous timing slack)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "backoff grows and stays bounded, jitter is deterministic" {
    // Base doubles 1,2,4,... and caps at 60s; jitter < 1s and reproducible.
    const s = std.time.ns_per_s;
    try testing.expect(backoffNs(0, 0) >= 1 * s and backoffNs(0, 0) < 2 * s);
    try testing.expect(backoffNs(0, 1) >= 2 * s and backoffNs(0, 1) < 3 * s);
    try testing.expect(backoffNs(0, 2) >= 4 * s and backoffNs(0, 2) < 5 * s);
    try testing.expect(backoffNs(0, 100) >= 60 * s and backoffNs(0, 100) < 61 * s);
    try testing.expectEqual(backoffNs(3, 5), backoffNs(3, 5));
    // Different peers generally differ in jitter.
    try testing.expect(backoffNs(1, 0) != backoffNs(2, 0));
}

test "parseHostPort" {
    const hp = try parseHostPort("127.0.0.1:9001");
    try testing.expectEqualStrings("127.0.0.1", hp.host);
    try testing.expectEqual(@as(u16, 9001), hp.port);
    try testing.expectError(error.BadPeerSpec, parseHostPort("noport"));
}

/// Records callback deliveries for one overlay; thread-safe.
const Recorder = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    /// The overlay these callbacks belong to (so on_recv can reply).
    ov: ?*Overlay = null,
    mu: std.Io.Mutex = .init,
    peer_up: usize = 0,
    up_ids: std.ArrayListUnmanaged(usize) = .empty,
    pings: std.ArrayListUnmanaged(u64) = .empty,
    pongs: std.ArrayListUnmanaged(u64) = .empty,
    envelopes: std.ArrayListUnmanaged([]u8) = .empty,
    /// If set, reply to every received ping with a matching pong.
    reply_pong: bool = false,

    fn onRecv(ctx: ?*anyopaque, peer_id: usize, frame: *const wire.OverlayFrame) void {
        const self: *Recorder = @ptrCast(@alignCast(ctx.?));
        self.mu.lockUncancelable(self.io);
        switch (frame.*) {
            .ping => |n| {
                self.pings.append(self.gpa, n) catch {};
                self.mu.unlock(self.io);
                if (self.reply_pong) {
                    if (self.ov) |ov| ov.send(peer_id, .{ .pong = n });
                }
                return;
            },
            .pong => |n| self.pongs.append(self.gpa, n) catch {},
            .envelope => |b| {
                const c = self.gpa.dupe(u8, b) catch {
                    self.mu.unlock(self.io);
                    return;
                };
                self.envelopes.append(self.gpa, c) catch self.gpa.free(c);
            },
            else => {},
        }
        self.mu.unlock(self.io);
    }

    fn onPeerUp(ctx: ?*anyopaque, peer_id: usize) void {
        const self: *Recorder = @ptrCast(@alignCast(ctx.?));
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        self.peer_up += 1;
        self.up_ids.append(self.gpa, peer_id) catch {};
    }

    fn peerUpCount(self: *Recorder) usize {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.peer_up;
    }

    fn firstUpId(self: *Recorder) usize {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.up_ids.items[0];
    }

    fn pongCount(self: *Recorder, want: u64) usize {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        var c: usize = 0;
        for (self.pongs.items) |v| {
            if (v == want) c += 1;
        }
        return c;
    }

    fn envelopeCount(self: *Recorder, want: []const u8) usize {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        var c: usize = 0;
        for (self.envelopes.items) |e| {
            if (std.mem.eql(u8, e, want)) c += 1;
        }
        return c;
    }

    fn callbacks(self: *Recorder) Callbacks {
        return .{ .ctx = self, .on_recv = onRecv, .on_peer_up = onPeerUp };
    }

    fn deinit(self: *Recorder) void {
        for (self.envelopes.items) |e| self.gpa.free(e);
        self.envelopes.deinit(self.gpa);
        self.up_ids.deinit(self.gpa);
        self.pings.deinit(self.gpa);
        self.pongs.deinit(self.gpa);
    }
};

fn sleepMs(io: std.Io, ms: u64) void {
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(ms)), .awake) catch {};
}

/// Poll `ov.peerCount()` until it reaches `want`, or fail after a bounded wait.
fn waitPeerCount(io: std.Io, ov: *Overlay, want: usize) !void {
    var i: usize = 0;
    while (i < 300) : (i += 1) { // up to ~3s
        if (ov.peerCount() >= want) return;
        sleepMs(io, 10);
    }
    return error.PeerCountTimeout;
}

fn buildEnvelope(gpa: std.mem.Allocator, statement: []const u8, sig: []const u8) ![]u8 {
    var mb = core.capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var eb = try core.gen.slcp.Envelope.Builder.init(&mb);
    try eb.setStatementBytes(statement);
    try eb.setSignature(sig);
    return @constCast(try mb.toBytes());
}

const test_prefix: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

fn testConfig(port: u16, peers: []const []const u8, prefix: [8]u8, id_byte: u8) Config {
    return .{
        .listen_port = port,
        .peers = peers,
        .network_id_prefix = prefix,
        .node_id = @as([32]u8, @splat(id_byte)),
    };
}

test "two overlays connect and exchange ping/pong" {
    const io = testing.io;
    const gpa = testing.allocator;

    var b_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer b_rec.deinit();
    var a_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer a_rec.deinit();

    // B listens on an ephemeral port and echoes pings.
    b_rec.reply_pong = true;
    var ov_b = try Overlay.init(gpa, io, testConfig(0, &.{}, test_prefix, 0xBB), b_rec.callbacks());
    b_rec.ov = &ov_b;
    try ov_b.start();
    defer ov_b.deinit();
    defer ov_b.stop();

    // A dials B.
    var buf: [64]u8 = undefined;
    const b_spec = try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{ov_b.boundPort()});
    var ov_a = try Overlay.init(gpa, io, testConfig(0, &.{b_spec}, test_prefix, 0xAA), a_rec.callbacks());
    a_rec.ov = &ov_a;
    try ov_a.start();
    defer ov_a.deinit();
    defer ov_a.stop();

    try waitPeerCount(io, &ov_a, 1);
    try waitPeerCount(io, &ov_b, 1);
    try testing.expectEqual(@as(usize, 1), a_rec.peerUpCount());
    try testing.expectEqual(@as(usize, 1), b_rec.peerUpCount());

    // A pings B; B replies pong; A records it.
    ov_a.broadcast(.{ .ping = 0xABCDEF });
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        if (a_rec.pongCount(0xABCDEF) >= 1) break;
        sleepMs(io, 10);
    }
    try testing.expect(a_rec.pongCount(0xABCDEF) >= 1);
}

test "broadcast delivers an envelope byte-identical" {
    const io = testing.io;
    const gpa = testing.allocator;

    const env = try buildEnvelope(gpa, "a statement to sign over", &@as([64]u8, @splat(0x5A)));
    defer gpa.free(env);

    var b_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer b_rec.deinit();
    var a_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer a_rec.deinit();

    var ov_b = try Overlay.init(gpa, io, testConfig(0, &.{}, test_prefix, 0xBB), b_rec.callbacks());
    b_rec.ov = &ov_b;
    try ov_b.start();
    defer ov_b.deinit();
    defer ov_b.stop();

    var buf: [64]u8 = undefined;
    const b_spec = try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{ov_b.boundPort()});
    var ov_a = try Overlay.init(gpa, io, testConfig(0, &.{b_spec}, test_prefix, 0xAA), a_rec.callbacks());
    a_rec.ov = &ov_a;
    try ov_a.start();
    defer ov_a.deinit();
    defer ov_a.stop();

    try waitPeerCount(io, &ov_a, 1);
    try waitPeerCount(io, &ov_b, 1);

    ov_a.broadcast(.{ .envelope = env });
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        if (b_rec.envelopeCount(env) >= 1) break;
        sleepMs(io, 10);
    }
    try testing.expectEqual(@as(usize, 1), b_rec.envelopeCount(env));
}

test "wrong network_id_prefix closes the connection, no peer_up" {
    const io = testing.io;
    const gpa = testing.allocator;

    var b_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer b_rec.deinit();
    var a_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer a_rec.deinit();

    const prefix_b: [8]u8 = .{ 1, 1, 1, 1, 1, 1, 1, 1 };
    const prefix_a: [8]u8 = .{ 9, 9, 9, 9, 9, 9, 9, 9 };

    var ov_b = try Overlay.init(gpa, io, testConfig(0, &.{}, prefix_b, 0xBB), b_rec.callbacks());
    b_rec.ov = &ov_b;
    try ov_b.start();
    defer ov_b.deinit();
    defer ov_b.stop();

    var buf: [64]u8 = undefined;
    const b_spec = try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{ov_b.boundPort()});
    var ov_a = try Overlay.init(gpa, io, testConfig(0, &.{b_spec}, prefix_a, 0xAA), a_rec.callbacks());
    a_rec.ov = &ov_a;
    try ov_a.start();
    defer ov_a.deinit();
    defer ov_a.stop();

    // Give the handshake (and at least one reconnect attempt) time to fail.
    sleepMs(io, 400);
    try testing.expectEqual(@as(usize, 0), ov_a.peerCount());
    try testing.expectEqual(@as(usize, 0), ov_b.peerCount());
    try testing.expectEqual(@as(usize, 0), a_rec.peerUpCount());
    try testing.expectEqual(@as(usize, 0), b_rec.peerUpCount());
}

test "broadcastExcept skips the named peer but reaches others" {
    const io = testing.io;
    const gpa = testing.allocator;

    const env_all = try buildEnvelope(gpa, "reaches-b-normally", &@as([64]u8, @splat(0x11)));
    defer gpa.free(env_all);
    const env_skip = try buildEnvelope(gpa, "excluded-from-b", &@as([64]u8, @splat(0x22)));
    defer gpa.free(env_skip);
    const env_other = try buildEnvelope(gpa, "excludes-a-phantom", &@as([64]u8, @splat(0x33)));
    defer gpa.free(env_other);

    var b_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer b_rec.deinit();
    var a_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer a_rec.deinit();

    var ov_b = try Overlay.init(gpa, io, testConfig(0, &.{}, test_prefix, 0xBB), b_rec.callbacks());
    b_rec.ov = &ov_b;
    try ov_b.start();
    defer ov_b.deinit();
    defer ov_b.stop();

    var buf: [64]u8 = undefined;
    const b_spec = try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{ov_b.boundPort()});
    var ov_a = try Overlay.init(gpa, io, testConfig(0, &.{b_spec}, test_prefix, 0xAA), a_rec.callbacks());
    a_rec.ov = &ov_a;
    try ov_a.start();
    defer ov_a.deinit();
    defer ov_a.stop();

    try waitPeerCount(io, &ov_a, 1);
    try waitPeerCount(io, &ov_b, 1);
    const b_id = a_rec.firstUpId(); // A's stable id for its single peer B.

    // A plain broadcast reaches B (proves the channel is live and drained).
    ov_a.broadcast(.{ .envelope = env_all });
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        if (b_rec.envelopeCount(env_all) >= 1) break;
        sleepMs(io, 10);
    }
    try testing.expectEqual(@as(usize, 1), b_rec.envelopeCount(env_all));

    // broadcastExcept(non-B) still reaches B (filter is by id, not a no-op)…
    ov_a.broadcastExcept(b_id + 999, .{ .envelope = env_other });
    i = 0;
    while (i < 300) : (i += 1) {
        if (b_rec.envelopeCount(env_other) >= 1) break;
        sleepMs(io, 10);
    }
    try testing.expectEqual(@as(usize, 1), b_rec.envelopeCount(env_other));

    // …but broadcastExcept(B) must never reach B.
    ov_a.broadcastExcept(b_id, .{ .envelope = env_skip });
    sleepMs(io, 200);
    try testing.expectEqual(@as(usize, 0), b_rec.envelopeCount(env_skip));
}

test "stop joins cleanly with a live connection" {
    const io = testing.io;
    const gpa = testing.allocator;

    var b_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer b_rec.deinit();
    var a_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer a_rec.deinit();

    var ov_b = try Overlay.init(gpa, io, testConfig(0, &.{}, test_prefix, 0xBB), b_rec.callbacks());
    b_rec.ov = &ov_b;
    try ov_b.start();

    var buf: [64]u8 = undefined;
    const b_spec = try std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{ov_b.boundPort()});
    var ov_a = try Overlay.init(gpa, io, testConfig(0, &.{b_spec}, test_prefix, 0xAA), a_rec.callbacks());
    a_rec.ov = &ov_a;
    try ov_a.start();

    try waitPeerCount(io, &ov_a, 1);
    try waitPeerCount(io, &ov_b, 1);

    // Tear down while the connection is live; the joins must complete.
    ov_a.stop();
    ov_a.stop(); // idempotent
    ov_b.stop();
    ov_a.deinit();
    ov_a.deinit(); // idempotent
    ov_b.deinit();
}

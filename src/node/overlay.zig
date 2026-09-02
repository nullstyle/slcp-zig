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
//!     Inbound conns are capped at `max_inbound_conns` (over-cap accepts are
//!     closed immediately), and finished reader threads are reaped on each
//!     accept iteration, so thread/handle growth is bounded by LIVE conns.
//!   * One dialer thread per configured peer (`dialerLoop`) owns exactly one
//!     outbound connection at a time and reconnects with exponential backoff
//!     (1s→60s) plus deterministic per-peer jitter (Wyhash over the attempt
//!     counter — no wall clock, no RNG).
//!   * Every connection, inbound or outbound, runs `runConnection`: register
//!     the `Conn`, send OUR Hello first, read the peer's first frame and
//!     require a matching Hello, then start the writer, assign a stable
//!     peer_id, fire `on_peer_up`, and enter the read loop delivering frames
//!     to `on_recv`. A conn whose writer thread fails to start is torn down,
//!     never published (a writer-less conn would sync-write under conns_mu).
//!
//! Resource bounds (§9.1 hardening):
//!   * Frames are capped at `max_frame_bytes` (1 MiB): the framer's buffered
//!     bytes are limited to one max-size frame plus one read chunk, and since
//!     frames are popped after every push, exceeding that means an oversized
//!     frame — framing error, disconnect.
//!   * Each conn's write queue is bounded (`max_write_queue_items` /
//!     `max_write_queue_bytes`). A Hello-complete peer that stops draining
//!     overflows it; the overflow fails the enqueue and force-disconnects the
//!     conn (socket shutdown → its reader unblocks → normal teardown).
//!   * The handshake has a receive deadline (`handshake_timeout_s`): a peer
//!     that connects but never sends its Hello cannot wedge a reader thread
//!     forever. The deadline belongs to the Io OPERATION, not to the socket:
//!     `std.Io.operateTimeout(.{ .net_read = ... }, deadline)` is std's own
//!     mechanism for this — it bounds (and abandons) the read itself and
//!     yields `error.Timeout`, which drives the ordinary teardown. The
//!     deadline is made absolute once per handshake, so a peer dribbling
//!     bytes cannot renew the window on every read. Once the Hello exchange
//!     completes the conn reads untimed again through `Conn.read`.
//!
//! Shutdown (`stop`, idempotent): flip `stopping`, wake the dialers' backoff
//! condvar, wake the accept thread WITHOUT invalidating the listener fd
//! (netShutdown per `Server.accept`'s documented cancellation contract, plus
//! a loopback self-connect for OSes where shutting down a listening socket is
//! a no-op — e.g. macOS), JOIN the accept thread, and only then close the
//! listener and clear the field (so the accept thread can never see a null
//! server or a closed/recycled fd). Then `shutdown` every live socket (so
//! every reader's blocking `read` returns EOF and every writer wakes), and
//! join every reader and dialer thread. Each reader frees its own `Conn` on
//! the way out, so after the joins the peer table is empty; `deinit` frees
//! the table.
//!
//! Sends hold the peer-table mutex across `enqueue` (which only touches the
//! connection's own queue lock and — on overflow — a non-blocking socket
//! shutdown, never blocking I/O), while a reader's teardown removes its
//! `Conn` from the table under the same mutex before tearing the socket down
//! — so a send never races a free. Readers enter the table only AFTER
//! starting the writer, so `enqueue` is always the async path and no two
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

/// §9.1: largest wire frame we accept (1 MiB). Enforced through the framer's
/// buffered-bytes cap — see the implementation notes above.
pub const max_frame_bytes: usize = 1 << 20;
/// Per-conn write queue bounds. Overflow means the peer stopped draining:
/// the enqueue fails and the conn is force-disconnected.
pub const max_write_queue_items: usize = 1024;
pub const max_write_queue_bytes: usize = 16 * 1024 * 1024;
/// Maximum concurrently-live inbound connections; over-cap accepts are
/// closed immediately, before any per-conn resources are allocated.
pub const max_inbound_conns: usize = 128;

/// How EVERY consensus-network Framer in this process is constructed: one
/// max-size frame plus one read chunk of headroom. This is the single
/// definition — `runConnection` builds its framer from it, and the vendored
/// framing conformance replay (tests/framing_vectors_test.zig) imports it, so
/// a change to the cap is a change to what that suite asserts.
pub const framer_options: framing.Framer.Options = .{
    .max_buffered_bytes = max_frame_bytes + default_read_buffer_size,
};

/// Runtime inbound cap. Production always runs the `max_inbound_conns`
/// default; file-private so a test can lower it to something small without
/// opening 128 real sockets.
var inbound_conn_cap: usize = max_inbound_conns;

/// Handshake receive deadline (10s), as an `std.Io.Timeout`: a peer that
/// connects but never sends its Hello is disconnected after this long. The
/// deadline rides on the Io read operation (`operateTimeout`), never on the
/// socket — see the implementation notes above.
const handshake_timeout_s: std.Io.Timeout = .{ .duration = .{
    .raw = std.Io.Duration.fromSeconds(10),
    .clock = .awake,
} };

/// Runtime handshake deadline. Production always runs the
/// `handshake_timeout_s` default; file-private so a test can drop it to a
/// few hundred milliseconds instead of stalling the suite for ten seconds.
var handshake_deadline: std.Io.Timeout = handshake_timeout_s;

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

    // Async write queue drained by the writer thread. Bounded by
    // `max_write_queue_items` / `max_write_queue_bytes` (`wq_bytes` tracks
    // the queued payload bytes; zeroed when the writer takes the batch).
    wq_mu: std.Io.Mutex = .init,
    wq_cond: std.Io.Condition = .init,
    wq: std.ArrayListUnmanaged([]u8) = .empty,
    wq_bytes: usize = 0,
    wq_closed: bool = false,
    writer_started: bool = false,
    writer_thread: ?std.Thread = null,

    // Per-peer inbound budget window (reader-thread-local; no lock).
    win_start_ns: i96 = 0,
    win_bytes: usize = 0,
    win_reqs: usize = 0,
    strikes: u32 = 0,

    /// Blocking read into `read_buf`; 0 on EOF. The established-connection
    /// path — no deadline, straight through the Io vtable.
    fn read(self: *Conn) !usize {
        var bufs: [1][]u8 = .{self.read_buf};
        return self.stream.read(self.io, &bufs);
    }

    /// Blocking read into `read_buf` under a DEADLINE, returning
    /// `error.Timeout` if it expires first. Used for the handshake phase
    /// only.
    ///
    /// The deadline is attached to the Io OPERATION rather than to the
    /// socket: `operateTimeout` bounds the `net_read` itself, so the read
    /// path never has to interpret a timed-out `recv`. (Arming SO_RCVTIMEO
    /// instead would make a plain timeout arrive as EAGAIN, which
    /// `Io.Threaded` classifies as a programmer bug — a debug-build panic.)
    fn readTimeout(self: *Conn, timeout: std.Io.Timeout) !usize {
        var bufs: [1][]u8 = .{self.read_buf};
        const result = try self.io.operateTimeout(.{ .net_read = .{
            .socket_handle = self.stream.socket.handle,
            .data = &bufs,
        } }, timeout);
        return result.net_read;
    }

    /// Copy `bytes` onto the write queue (async) or, before the writer thread
    /// exists (handshake), write them synchronously on the caller's thread.
    /// The queue is bounded: on overflow the peer is treated as dead — the
    /// queue closes, the socket is shut down (so the conn's reader unblocks
    /// and the normal teardown path runs), and the enqueue fails. Never
    /// blocks on I/O once the writer is started.
    fn enqueue(self: *Conn, bytes: []const u8) !void {
        if (!self.writer_started) {
            return writeAll(self.io, self.stream.socket.handle, bytes);
        }
        {
            self.wq_mu.lockUncancelable(self.io);
            defer self.wq_mu.unlock(self.io);
            if (self.wq_closed) return error.WriteClosed;
            if (self.wq.items.len < max_write_queue_items and
                self.wq_bytes + bytes.len <= max_write_queue_bytes)
            {
                const copy = try self.gpa.dupe(u8, bytes);
                self.wq.append(self.gpa, copy) catch |err| {
                    self.gpa.free(copy);
                    return err;
                };
                self.wq_bytes += copy.len;
                self.wq_cond.signal(self.io);
                return;
            }
            log.warn("overlay: peer {d} write queue overflow ({d} items, {d} B); disconnecting", .{
                self.id, self.wq.items.len, self.wq_bytes,
            });
            self.wq_closed = true;
            self.wq_cond.broadcast(self.io);
        }
        // Shut the socket down outside wq_mu (shutdown() would re-lock it).
        self.stream.shutdown(self.io, .both) catch {};
        return error.WriteQueueFull;
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
            self.wq_bytes = 0;
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

/// Join-handle record for one inbound reader thread. Heap-allocated so the
/// thread can flip `done` (its very last action) after its `Conn` is already
/// destroyed; freed by whoever joins the thread — the accept loop's reaper,
/// or `joinAll` at stop.
const InboundSlot = struct {
    thread: std.Thread = undefined,
    done: std.atomic.Value(bool) = .init(false),
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
    /// One record per inbound reader thread (spawned by the accept thread).
    /// Finished threads are reaped on each accept iteration, so this grows
    /// with LIVE inbound conns (≤ the inbound cap), not historical ones.
    inbound_slots: std.ArrayListUnmanaged(*InboundSlot) = .empty,
    /// One dialer thread per configured peer (fixed for our lifetime).
    dialer_threads: std.ArrayListUnmanaged(std.Thread) = .empty,

    /// Guards `conns`, `inbound_slots`, per-conn id/hello_done, and
    /// `next_peer_id`.
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

        // Thread-spawn failures are reported as ONE named error so the Node
        // can tell "cannot start a thread" (`CreateError.ThreadSpawnFailed`)
        // apart from "cannot bind the port" (the ListenError members above).
        self.accept_thread = std.Thread.spawn(.{}, acceptLoop, .{self}) catch
            return error.ThreadSpawnFailed;
        // From here, any failure must join everything already spawned.
        errdefer {
            self.stopping.store(true, .release);
            self.joinAll();
        }

        for (self.cfg.peers, 0..) |_, i| {
            const t = std.Thread.spawn(.{}, dialerLoop, .{ self, i }) catch
                return error.ThreadSpawnFailed;
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
        self.inbound_slots.deinit(self.gpa);
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
            const detail: usize = switch (frame) {
                .envelope => |b| b.len,
                .qset => |b| b.len,
                .slot_state => |ss| ss.envelopes.len,
                else => 0,
            };
            log.warn("overlay: dropping {s} frame (detail={d}), encode failed: {t}", .{ @tagName(frame), detail, err });
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
            // enqueue copies `bytes` and only touches the conn's queue lock
            // (plus, on queue overflow, a non-blocking socket shutdown); it
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
            // Reap finished reader threads, then enforce the inbound cap
            // BEFORE allocating anything for this conn.
            self.reapInboundThreads();
            if (self.inboundConnCount() >= inbound_conn_cap) {
                log.warn("overlay: inbound conn cap ({d}) reached; closing new conn", .{inbound_conn_cap});
                stream.close(self.io);
                continue;
            }
            setTcpNoDelay(stream.socket.handle);
            self.startInboundConn(stream);
        }
    }

    fn inboundConnCount(self: *Overlay) usize {
        self.conns_mu.lockUncancelable(self.io);
        defer self.conns_mu.unlock(self.io);
        return self.inbound_slots.items.len;
    }

    /// Join and free inbound-thread records whose reader has finished (its
    /// `done` flag is its last action, so these joins cannot block). Runs on
    /// the accept thread between accepts, a bounded batch per call; `joinAll`
    /// handles whatever is left at stop.
    fn reapInboundThreads(self: *Overlay) void {
        var done_buf: [16]*InboundSlot = undefined;
        var done_n: usize = 0;
        {
            self.conns_mu.lockUncancelable(self.io);
            defer self.conns_mu.unlock(self.io);
            var i: usize = 0;
            while (i < self.inbound_slots.items.len and done_n < done_buf.len) {
                const slot = self.inbound_slots.items[i];
                if (slot.done.load(.acquire)) {
                    done_buf[done_n] = slot;
                    done_n += 1;
                    _ = self.inbound_slots.swapRemove(i);
                    continue; // a new item moved into index i
                }
                i += 1;
            }
        }
        for (done_buf[0..done_n]) |slot| {
            slot.thread.join();
            self.gpa.destroy(slot);
        }
    }

    fn startInboundConn(self: *Overlay, stream: net.Stream) void {
        const conn = self.makeConn(stream, false) orelse return;
        const slot = self.gpa.create(InboundSlot) catch {
            conn.deinit();
            self.gpa.destroy(conn);
            return;
        };
        slot.* = .{};
        self.conns_mu.lockUncancelable(self.io);
        defer self.conns_mu.unlock(self.io);
        // Reserve the join slot before spawning so we can never lose a handle.
        self.inbound_slots.ensureUnusedCapacity(self.gpa, 1) catch {
            self.gpa.destroy(slot);
            conn.deinit();
            self.gpa.destroy(conn);
            return;
        };
        slot.thread = std.Thread.spawn(.{}, connThread, .{ self, conn, slot }) catch {
            self.gpa.destroy(slot);
            conn.deinit();
            self.gpa.destroy(conn);
            return;
        };
        self.inbound_slots.appendAssumeCapacity(slot);
    }

    fn dialerLoop(self: *Overlay, peer_index: usize) void {
        const spec = self.cfg.peers[peer_index];
        var attempt: u32 = 0;
        // Consecutive dial failures since the last success; drives the
        // rate-limited "unreachable" warning (attempt saturates at 30 for the
        // backoff table, so it cannot serve as the warn counter).
        var failures: u64 = 0;
        while (!self.stopping.load(.acquire)) {
            const conn = self.dialOne(spec, failures) orelse {
                failures +|= 1;
                self.waitInterruptible(backoffNs(peer_index, attempt));
                if (attempt < 30) attempt += 1;
                continue;
            };
            attempt = 0; // TCP connect succeeded — reset backoff growth.
            failures = 0;
            self.runConnection(conn);
            if (self.stopping.load(.acquire)) break;
            // Reconnect after a base (attempt 0 ≈ 1s) delay + jitter.
            self.waitInterruptible(backoffNs(peer_index, 0));
        }
    }

    /// One dial attempt. An IP literal connects directly; anything else is a
    /// hostname resolved through `std.Io.net.HostName.connect` (the Io's
    /// resolver: /etc/hosts + DNS under Threaded), so `a.example.com:7311`
    /// and `localhost:7311` both work (§9 peer specs). `failures` is the
    /// consecutive-failure count: the unreachable warning fires on the first
    /// failure and every 8th thereafter, not on every 1..60 s retry.
    fn dialOne(self: *Overlay, spec: []const u8, failures: u64) ?*Conn {
        const hp = parseHostPort(spec) catch {
            log.warn("overlay: bad peer spec '{s}'", .{spec});
            return null;
        };
        const stream = blk: {
            if (net.IpAddress.parse(hp.host, hp.port)) |parsed| {
                var addr = parsed;
                break :blk net.IpAddress.connect(&addr, self.io, .{ .mode = .stream }) catch |err| {
                    warnUnreachable(spec, failures, err);
                    return null;
                };
            } else |_| {
                const hn = net.HostName.init(hp.host) catch {
                    log.warn("overlay: cannot parse peer address '{s}'", .{spec});
                    return null;
                };
                break :blk hn.connect(self.io, hp.port, .{ .mode = .stream }) catch |err| {
                    warnUnreachable(spec, failures, err);
                    return null;
                };
            }
        };
        setTcpNoDelay(stream.socket.handle);
        return self.makeConn(stream, true);
    }

    fn warnUnreachable(spec: []const u8, failures: u64, err: anyerror) void {
        if (failures == 0 or failures % 8 == 0) {
            log.warn("overlay: peer '{s}' unreachable ({t}); retrying with backoff (1s..60s)", .{ spec, err });
        }
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

    fn connThread(self: *Overlay, conn: *Conn, slot: *InboundSlot) void {
        self.runConnection(conn);
        // Last action: publish that this thread is joinable (see reaper).
        slot.done.store(true, .release);
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

        // §9.1 frame cap: frames are popped after every push, so the framer
        // never legitimately buffers more than one incomplete frame plus one
        // read chunk. A push past this cap ⇒ oversized frame ⇒ framing
        // error ⇒ disconnect.
        var framer = framing.Framer.initWithOptions(gpa, framer_options);

        // Handshake deadline: a peer that never sends its Hello must not
        // park this thread forever in a blocking read. Resolved to an
        // ABSOLUTE deadline here so it bounds the whole Hello exchange
        // rather than restarting on every read.
        const deadline = handshake_deadline.toDeadline(self.io);

        var established = false;
        if (self.handshake(conn, &framer, deadline)) {
            // Start the writer BEFORE the peer is visible to senders, so every
            // enqueue takes the async path (no two threads sync-write). If the
            // writer cannot start, the conn must NOT be published: a published
            // writer-less conn would sync-write (blocking) under conns_mu.
            if (conn.startWriter()) {
                established = true;
            } else |err| {
                log.warn("overlay: startWriter failed; dropping peer: {t}", .{err});
            }
        }

        if (established) {
            // Past the Hello: the read loop below runs untimed again.
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

    /// Send our Hello, then read + validate the peer's Hello under
    /// `deadline`. Returns true iff the peer is an accepted flood peer; a
    /// silent peer trips the deadline and returns false, which runs the same
    /// teardown as any other rejected conn.
    fn handshake(self: *Overlay, conn: *Conn, framer: *framing.Framer, deadline: std.Io.Timeout) bool {
        self.sendHello(conn) catch return false;

        const raw = self.nextRawFrame(conn, framer, deadline) orelse return false;
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
            // Established: no deadline — an idle peer is a legal peer.
            const raw = self.nextRawFrame(conn, framer, .none) orelse return;
            defer gpa.free(raw);
            var frame = wire.decode(gpa, raw) catch |err| {
                // Valid framing, malformed contents: drop the frame, keep peer.
                log.debug("overlay: dropping malformed frame from peer {d}: {t}", .{ conn.id, err });
                continue;
            };
            defer frame.deinit(gpa);
            if (isRequestFrame(frame)) switch (self.chargeRequest(conn)) {
                .accept => {},
                .drop => continue,
                .disconnect => return,
            };
            self.cb.on_recv(self.cb.ctx, conn.id, &frame);
        }
    }

    /// Pull the next complete wire frame (caller frees), or null on EOF, read
    /// error, framing error, an expired `deadline`, or a byte-budget
    /// disconnect. Pass `.none` for the untimed (established) path.
    fn nextRawFrame(self: *Overlay, conn: *Conn, framer: *framing.Framer, deadline: std.Io.Timeout) ?[]u8 {
        while (true) {
            const popped = framer.popFrame() catch {
                framer.reset();
                return null;
            };
            if (popped) |f| return f;

            const n = blk: {
                if (deadline == .none) break :blk conn.read() catch return null;
                break :blk conn.readTimeout(deadline) catch |err| {
                    if (err == error.Timeout) {
                        log.warn("overlay: handshake deadline expired before Hello; disconnecting", .{});
                    }
                    return null;
                };
            };
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

    const RequestVerdict = enum { accept, drop, disconnect };

    /// Charge one inbound request. Over budget is a strike and the request
    /// is dropped (drop-and-log); the strike that reaches
    /// `max_budget_strikes` disconnects the peer — the same ladder as
    /// `chargeBytes`, which is what protocol.md §12 / threat-model.md §3
    /// promise ("32 breaches ⇒ disconnect").
    fn chargeRequest(self: *Overlay, conn: *Conn) RequestVerdict {
        self.rollWindow(conn);
        conn.win_reqs += 1;
        if (conn.win_reqs > max_outstanding_requests) {
            conn.strikes += 1;
            if (conn.strikes >= max_budget_strikes) {
                log.warn("overlay: peer {d} request-rate breach ({d} in window), strike {d}; exceeded budget strikes, disconnecting", .{ conn.id, conn.win_reqs, conn.strikes });
                return .disconnect;
            }
            log.warn("overlay: peer {d} request-rate breach ({d} in window), strike {d}; dropping request", .{ conn.id, conn.win_reqs, conn.strikes });
            return .drop;
        }
        return .accept;
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

    /// Close the listening socket and clear the field. Idempotent. Must only
    /// run while no accept thread is live (before it is spawned, or after it
    /// is joined) — the accept thread reads `self.server` unsynchronized.
    fn closeListener(self: *Overlay) void {
        if (self.server) |*s| {
            s.socket.close(self.io);
            self.server = null;
        }
    }

    /// Wake a possibly-parked accept WITHOUT invalidating the listener fd.
    /// `netShutdown` fulfills `Server.accept`'s documented cancellation
    /// contract where the OS honors it (Linux); on macOS shutting down a
    /// listening socket is a no-op (ENOTCONN, accept stays parked), so ALSO
    /// nudge the listener with a loopback self-connect — the accept thread
    /// wakes holding either an error or the nudge conn, observes `stopping`,
    /// and exits. The fd stays open (and `self.server` stays set) until
    /// after the join, so the accept thread can never unwrap a nulled field
    /// or accept on a closed/recycled fd.
    fn wakeAcceptThread(self: *Overlay) void {
        const srv = self.server orelse return;
        self.io.vtable.netShutdown(self.io.userdata, srv.socket.handle, .both) catch {};
        var addr = net.IpAddress.parse("127.0.0.1", self.bound_port) catch return;
        const stream = net.IpAddress.connect(&addr, self.io, .{ .mode = .stream }) catch return;
        stream.close(self.io);
    }

    fn joinAll(self: *Overlay) void {
        // Wake any dialer parked in backoff.
        self.wakeWaiters();
        // Wake and join the accept thread while the listener fd is still
        // valid; only then close the listener. After the join, no NEW
        // inbound connection threads can be spawned.
        if (self.accept_thread) |t| {
            self.wakeAcceptThread();
            t.join();
            self.accept_thread = null;
        }
        self.closeListener();
        // Unblock every reader's blocking read, then join the reader threads
        // (done or not — a finished one joins immediately).
        self.shutdownAllConns();
        for (self.inbound_slots.items) |slot| {
            slot.thread.join();
            self.gpa.destroy(slot);
        }
        self.inbound_slots.clearAndFree(self.gpa);
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

pub const HostPort = struct { host: []const u8, port: u16 };

/// Split a peer spec into its raw host and port TEXT (no validation of
/// either). A spec starting with '[' is the bracketed-v6 form: the host is
/// what the brackets enclose and the port must follow as `]:<port>` — the
/// brackets are looked at BEFORE any ':' so that `[::1]` (no port) reports
/// `MissingPort`, not a garbled port `1]`. Anything else splits on its LAST
/// ':' so an unbracketed `::1` never swallows the port.
fn splitPeerSpec(spec: []const u8) PeerSpecError!struct { host: []const u8, port_text: []const u8 } {
    if (spec.len > 0 and spec[0] == '[') {
        const close = std.mem.indexOfScalar(u8, spec, ']') orelse return error.BadHost;
        const rest = spec[close + 1 ..];
        if (rest.len == 0 or (rest.len == 1 and rest[0] == ':')) return error.MissingPort;
        if (rest[0] != ':') return error.BadHost;
        return .{ .host = spec[1..close], .port_text = rest[1..] };
    }
    const idx = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.MissingPort;
    if (idx + 1 >= spec.len) return error.MissingPort;
    return .{ .host = spec[0..idx], .port_text = spec[idx + 1 ..] };
}

/// Split a peer spec into host and port. The bracketed form `[::1]:7311`
/// yields host `::1`. Port 0 is rejected (nothing listens on port 0). The
/// host is NOT validated here — see `validatePeerSpec`.
pub fn parseHostPort(spec: []const u8) error{BadPeerSpec}!HostPort {
    const parts = splitPeerSpec(spec) catch return error.BadPeerSpec;
    if (parts.host.len == 0) return error.BadPeerSpec;
    const port = std.fmt.parseInt(u16, parts.port_text, 10) catch return error.BadPeerSpec;
    if (port == 0) return error.BadPeerSpec;
    return .{ .host = parts.host, .port = port };
}

pub const PeerSpecError = error{ MissingPort, EmptyHost, BadPort, BadHost };

/// Is `spec` something `dialOne` can act on? `host:port` where host is an
/// IPv4/IPv6 literal (`[v6]:port` accepted) or an RFC 1123 hostname, and
/// port is 1..65535. `Node.create` maps a failure to `BadPeerSpec` naming
/// the index, the spec and which part is wrong.
pub fn validatePeerSpec(spec: []const u8) PeerSpecError!void {
    const parts = try splitPeerSpec(spec);
    if (parts.host.len == 0) return error.EmptyHost;
    const port = std.fmt.parseInt(u16, parts.port_text, 10) catch return error.BadPort;
    if (port == 0) return error.BadPort;
    if (net.IpAddress.parse(parts.host, port)) |_| return else |_| {}
    net.HostName.validate(parts.host) catch return error.BadHost;
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

/// Poll `ov.peerCount()` until it reaches `want`, or fail after a bounded
/// wait. Returns as soon as the count is reached; the bound is generous
/// (~8s) so a cold-start hiccup (first-run firewall stalls, loaded CI) does
/// not flake the suite.
fn waitPeerCount(io: std.Io, ov: *Overlay, want: usize) !void {
    var i: usize = 0;
    while (i < 800) : (i += 1) {
        if (ov.peerCount() >= want) return;
        sleepMs(io, 10);
    }
    return error.PeerCountTimeout;
}

/// One read from a raw test socket under its own bounded deadline, so a
/// broken overlay teardown FAILS the test instead of hanging it. Uses the
/// same `operateTimeout` mechanism the overlay's handshake read does.
fn readBounded(io: std.Io, handle: net.Socket.Handle, buf: []u8, ms: i64) !usize {
    var bufs: [1][]u8 = .{buf};
    const result = try io.operateTimeout(.{ .net_read = .{
        .socket_handle = handle,
        .data = &bufs,
    } }, .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(ms),
        .clock = .awake,
    } });
    return result.net_read;
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

test "inbound conn cap: over-cap accepts are closed, under-cap conns still work" {
    const io = testing.io;
    const gpa = testing.allocator;

    // Lower the file-private runtime cap so the test needs 3 sockets, not
    // 129. The pub const stays the production default.
    const saved_cap = inbound_conn_cap;
    inbound_conn_cap = 2;
    defer inbound_conn_cap = saved_cap;

    var b_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer b_rec.deinit();
    var ov_b = try Overlay.init(gpa, io, testConfig(0, &.{}, test_prefix, 0xBB), b_rec.callbacks());
    b_rec.ov = &ov_b;
    try ov_b.start();
    defer ov_b.deinit();
    defer ov_b.stop();

    var addr = try net.IpAddress.parse("127.0.0.1", ov_b.boundPort());

    // Three raw conns, connected in order. The accept queue is FIFO and
    // startInboundConn registers each reader slot synchronously on the
    // accept thread, so B accepts c1 and c2 and must close c3 at the cap.
    const c1 = try net.IpAddress.connect(&addr, io, .{ .mode = .stream });
    defer c1.close(io);
    const c2 = try net.IpAddress.connect(&addr, io, .{ .mode = .stream });
    defer c2.close(io);
    const c3 = try net.IpAddress.connect(&addr, io, .{ .mode = .stream });
    defer c3.close(io);

    // c3 must see EOF without ever receiving B's Hello (an accepted conn
    // would have been sent one immediately).
    var rb: [64]u8 = undefined;
    var rbufs: [1][]u8 = .{&rb};
    const n = c3.read(io, &rbufs) catch 0;
    try testing.expectEqual(@as(usize, 0), n);

    // c1 and c2 were kept: complete their Hello exchanges and become peers.
    inline for (.{ c1, c2 }, .{ 0x01, 0x02 }) |c, id_byte| {
        const hello = try wire.encode(gpa, .{ .hello = .{
            .protocol_version = wire.protocol_version,
            .network_id_prefix = test_prefix,
            .node_id = @as([32]u8, @splat(id_byte)),
            .current_slot = 0,
            .listen_port = 0,
        } });
        defer gpa.free(hello);
        try writeAll(io, c.socket.handle, hello);
    }
    try waitPeerCount(io, &ov_b, 2);
    try testing.expectEqual(@as(usize, 2), b_rec.peerUpCount());
    try testing.expectEqual(@as(usize, 2), ov_b.peerCount());
}

test "handshake deadline: a silent peer is disconnected, never published" {
    const io = testing.io;
    const gpa = testing.allocator;

    // Drop the file-private runtime deadline so this costs milliseconds, not
    // ten seconds. The `handshake_timeout_s` const stays the production
    // default. (Zig runs tests sequentially, as the inbound-cap test above
    // already relies on.)
    const saved_deadline = handshake_deadline;
    handshake_deadline = .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(200),
        .clock = .awake,
    } };
    defer handshake_deadline = saved_deadline;

    var b_rec: Recorder = .{ .io = io, .gpa = gpa };
    defer b_rec.deinit();
    var ov_b = try Overlay.init(gpa, io, testConfig(0, &.{}, test_prefix, 0xBB), b_rec.callbacks());
    b_rec.ov = &ov_b;
    try ov_b.start();
    defer ov_b.deinit();
    defer ov_b.stop();

    var addr = try net.IpAddress.parse("127.0.0.1", ov_b.boundPort());
    const c = try net.IpAddress.connect(&addr, io, .{ .mode = .stream });
    defer c.close(io);

    // We send NOTHING. B sends its own Hello immediately, then blocks on the
    // deadline read; when it expires B must tear the conn down, so our socket
    // sees EOF (or a reset) after at most a couple of reads.
    var rb: [1024]u8 = undefined;
    var closed = false;
    var i: usize = 0;
    while (i < 8 and !closed) : (i += 1) {
        const n = readBounded(io, c.socket.handle, &rb, 4000) catch |err| {
            // Timeout here means B never dropped us — the bug this guards.
            if (err == error.Timeout) return error.HandshakeDeadlineDidNotFire;
            closed = true; // a reset is a close too
            continue;
        };
        if (n == 0) closed = true;
    }
    try testing.expect(closed);

    // The conn was never published: no peer, no on_peer_up.
    try testing.expectEqual(@as(usize, 0), ov_b.peerCount());
    try testing.expectEqual(@as(usize, 0), b_rec.peerUpCount());
}

test "write queue caps: overflow fails the enqueue and shuts the conn down" {
    const io = testing.io;
    const gpa = testing.allocator;

    // A loopback pair per scenario; the Conn owns the client end.
    const bind_addr: net.IpAddress = .{ .ip4 = .unspecified(0) };
    var server = try net.IpAddress.listen(&bind_addr, io, .{
        .mode = .stream,
        .reuse_address = true,
    });
    defer server.deinit(io);
    var addr = try net.IpAddress.parse("127.0.0.1", portOf(server.socket.address));

    // --- item-count cap ----------------------------------------------------
    {
        const client = try net.IpAddress.connect(&addr, io, .{ .mode = .stream });
        const srv_side = try server.accept(io);
        defer srv_side.close(io);

        const conn = try gpa.create(Conn);
        conn.* = .{
            .io = io,
            .gpa = gpa,
            .stream = client,
            .read_buf = try gpa.alloc(u8, 64),
        };
        defer {
            conn.deinit();
            gpa.destroy(conn);
        }
        // Pretend the writer thread exists but never drains: enqueue takes
        // the queued (async) path and the queue only ever grows.
        conn.writer_started = true;

        var i: usize = 0;
        while (i < max_write_queue_items) : (i += 1) try conn.enqueue("x");
        try testing.expectError(error.WriteQueueFull, conn.enqueue("x"));
        // The overflow closed the queue…
        try testing.expectError(error.WriteClosed, conn.enqueue("x"));
        // …and shut the socket down: the peer side sees EOF.
        var rb: [8]u8 = undefined;
        var rbufs: [1][]u8 = .{&rb};
        const n = srv_side.read(io, &rbufs) catch 0;
        try testing.expectEqual(@as(usize, 0), n);
    }

    // --- byte cap ----------------------------------------------------------
    {
        const client = try net.IpAddress.connect(&addr, io, .{ .mode = .stream });
        const srv_side = try server.accept(io);
        defer srv_side.close(io);

        const conn = try gpa.create(Conn);
        conn.* = .{
            .io = io,
            .gpa = gpa,
            .stream = client,
            .read_buf = try gpa.alloc(u8, 64),
        };
        defer {
            conn.deinit();
            gpa.destroy(conn);
        }
        conn.writer_started = true;

        const chunk = try gpa.alloc(u8, max_write_queue_bytes / 8);
        defer gpa.free(chunk);
        @memset(chunk, 0xAB);
        var i: usize = 0;
        while (i < 8) : (i += 1) try conn.enqueue(chunk); // exactly the byte cap
        try testing.expectError(error.WriteQueueFull, conn.enqueue("y"));
        try testing.expectError(error.WriteClosed, conn.enqueue("y"));
    }
}

// Non-vacuity: dropping the bracket strip makes `[::1]` the host (red);
// removing the `port == 0` rejection makes `a.example.com:0` validate;
// replacing `HostName.validate` with "accept anything" lets `bad_host!`
// through; skipping `IpAddress.parse` first rejects `[::1]:7311` as a bad
// hostname.
test "validatePeerSpec / parseHostPort: literals, bracket-v6, hostnames, and each rejection" {
    try validatePeerSpec("127.0.0.1:7311");
    try validatePeerSpec("[::1]:7311");
    try validatePeerSpec("a.example.com:7311");
    try validatePeerSpec("localhost:7311");
    try validatePeerSpec("localhost:65535");
    try testing.expectError(error.MissingPort, validatePeerSpec("nohost"));
    try testing.expectError(error.MissingPort, validatePeerSpec("host:"));
    // S8 finding "BadPeerSpec gives the wrong reason for a bracketed IPv6
    // literal without a port": splitting on the LAST ':' before looking at
    // the brackets turned `[::1]` into host `[:` + port `1]` (BadPort).
    try testing.expectError(error.MissingPort, validatePeerSpec("[::1]"));
    try testing.expectError(error.MissingPort, validatePeerSpec("[2001:db8::2]"));
    try testing.expectError(error.MissingPort, validatePeerSpec("[::1]:"));
    try testing.expectError(error.BadHost, validatePeerSpec("[::1:7311"));
    try testing.expectError(error.BadHost, validatePeerSpec("[::1]x:7311"));
    try testing.expectError(error.BadPort, validatePeerSpec("[::1]:0"));
    try testing.expectError(error.EmptyHost, validatePeerSpec(":7311"));
    try testing.expectError(error.EmptyHost, validatePeerSpec("[]:7311"));
    try testing.expectError(error.BadPort, validatePeerSpec("a.example.com:0"));
    try testing.expectError(error.BadPort, validatePeerSpec("a.example.com:70000"));
    try testing.expectError(error.BadPort, validatePeerSpec("a.example.com:seven"));
    try testing.expectError(error.BadHost, validatePeerSpec("bad_host!:7311"));
    try testing.expectError(error.BadHost, validatePeerSpec("-leading.example.com:7311"));

    const v6 = try parseHostPort("[::1]:7311");
    try testing.expectEqualStrings("::1", v6.host);
    try testing.expectEqual(@as(u16, 7311), v6.port);
    const host = try parseHostPort("a.example.com:7311");
    try testing.expectEqualStrings("a.example.com", host.host);
    try testing.expectError(error.BadPeerSpec, parseHostPort("a.example.com:0"));
    try testing.expectError(error.BadPeerSpec, parseHostPort("[]:7311"));
    try testing.expectError(error.BadPeerSpec, parseHostPort("[::1]"));
    try testing.expectError(error.BadPeerSpec, parseHostPort("[::1:7311"));
    const v6_full = try parseHostPort("[2001:db8::2]:7311");
    try testing.expectEqualStrings("2001:db8::2", v6_full.host);
}

// Non-vacuity: this is the M6 hostname path. Reverting `dialOne` to the
// IP-literal-only branch makes `localhost:<port>` unparseable and the peer
// never comes up (PeerCountTimeout). The first assertion pins that
// `IpAddress.parse` really rejects "localhost", so the old branch cannot
// pass this test by accident.
test "dialer resolves a hostname peer spec" {
    const io = testing.io;
    const gpa = testing.allocator;
    try testing.expect(std.meta.isError(net.IpAddress.parse("localhost", 1)));

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
    const b_spec = try std.fmt.bufPrint(&buf, "localhost:{d}", .{ov_b.boundPort()});
    var ov_a = try Overlay.init(gpa, io, testConfig(0, &.{b_spec}, test_prefix, 0xAA), a_rec.callbacks());
    a_rec.ov = &ov_a;
    try ov_a.start();
    defer ov_a.deinit();
    defer ov_a.stop();

    // on_peer_up within the (generous, ~8 s) poll bound; the plan asks for 5 s.
    try waitPeerCount(io, &ov_a, 1);
    try waitPeerCount(io, &ov_b, 1);
    try testing.expectEqual(@as(usize, 1), a_rec.peerUpCount());
    try testing.expectEqual(@as(usize, 1), b_rec.peerUpCount());
}

// Non-vacuity: the S8 pin for "request-rate strikes are counted but never
// enforced". Reverting `chargeRequest` to a per-frame drop (no
// `max_budget_strikes` comparison) or making `readLoop` `continue` on a
// disconnect verdict leaves the flooder connected: `peerCount()` stays 1
// and the trailing ping is still answered with a pong.
test "request budget: a getQset flood is disconnected at max_budget_strikes, not merely dropped" {
    const io = testing.io;
    const gpa = testing.allocator;

    var b_rec: Recorder = .{ .io = io, .gpa = gpa };
    b_rec.reply_pong = true;
    defer b_rec.deinit();
    var ov_b = try Overlay.init(gpa, io, testConfig(0, &.{}, test_prefix, 0xBB), b_rec.callbacks());
    b_rec.ov = &ov_b;
    try ov_b.start();
    defer ov_b.deinit();
    defer ov_b.stop();

    var addr = try net.IpAddress.parse("127.0.0.1", ov_b.boundPort());
    const c = try net.IpAddress.connect(&addr, io, .{ .mode = .stream });
    defer c.close(io);

    // Complete a valid Hello so the conn is published and request-charged.
    const hello = try wire.encode(gpa, .{ .hello = .{
        .protocol_version = wire.protocol_version,
        .network_id_prefix = test_prefix,
        .node_id = @as([32]u8, @splat(0x01)),
        .current_slot = 0,
        .listen_port = 0,
    } });
    defer gpa.free(hello);
    try writeAll(io, c.socket.handle, hello);
    try waitPeerCount(io, &ov_b, 1);

    // One burst of tiny getQset frames: ~12 KiB, far under the 256 KiB/s
    // byte cap, so the ONLY budget breached is the request budget. Two full
    // windows plus the strikes are sent so a window roll mid-burst cannot
    // leave the count short. Writes may fail once B has hung up — that is
    // the point.
    const req = try wire.encode(gpa, .{ .get_qset = @as([32]u8, @splat(0xAB)) });
    defer gpa.free(req);
    const n_frames = 2 * max_outstanding_requests + max_budget_strikes + 8;
    var i: usize = 0;
    while (i < n_frames) : (i += 1) writeAll(io, c.socket.handle, req) catch break;

    // The flooder must be torn down.
    var tries: usize = 0;
    while (tries < 500 and ov_b.peerCount() != 0) : (tries += 1) sleepMs(io, 10);
    try testing.expectEqual(@as(usize, 0), ov_b.peerCount());

    // And the wire is dead: a ping gets EOF/error, never a pong.
    const ping = try wire.encode(gpa, .{ .ping = 0xFEED });
    defer gpa.free(ping);
    writeAll(io, c.socket.handle, ping) catch {};
    var framer = framing.Framer.initWithOptions(gpa, framer_options);
    defer framer.deinit();
    var got_pong = false;
    tries = 0;
    while (tries < 20 and !got_pong) : (tries += 1) {
        var rb: [4096]u8 = undefined;
        const n = readBounded(io, c.socket.handle, &rb, 500) catch break;
        if (n == 0) break;
        framer.push(rb[0..n]) catch break;
        while (framer.popFrame() catch null) |raw| {
            defer gpa.free(raw);
            var fr = wire.decode(gpa, raw) catch continue;
            defer fr.deinit(gpa);
            if (fr == .pong and fr.pong == 0xFEED) got_pong = true;
        }
    }
    try testing.expect(!got_pong);
}

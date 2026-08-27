//! TCP flood-gossip overlay (design §9). Symmetric: every node listens AND
//! dials. Deliberately NOT capnp RPC — it reuses only capnp-zig's frozen
//! transport surfaces:
//!
//!   * capnpc.rpc.wire.framing.Framer   — segment-frame reassembly
//!   * capnpc.rpc.transport.tcp         — Listener + Transport (sockets, the
//!                                        proven per-connection writer thread)
//!
//! Trust model (§9.1): ONLY envelope signatures are authenticated. Hello
//! fields are unauthenticated hints. A wrong `networkIdPrefix` ⇒ disconnect.
//!
//! Threading (§9.3): one accept thread; one reader thread per peer; the
//! writer thread lives inside each capnp-zig Transport. The engine thread
//! calls broadcast/send/broadcastExcept during effect drain; reader threads
//! call the `on_recv` callback. The peer table is mutex-guarded; sends go
//! through the thread-safe Transport write queue.
//!
//! Callback contract: `on_recv(ctx, peer_id, frame)` is invoked on a reader
//! thread with a BORROWED frame — valid only for the call; copy anything you
//! keep. `on_peer_up(ctx, peer_id)` fires once per peer after a valid Hello
//! exchange (the Node uses it to push catch-up: own latest envelopes +
//! getSlotState(0)). Neither callback may block on the engine.
//!
//! ==== IMPLEMENTATION BRIEF (M5 agent) ====================================
//! Public interface below is FROZEN — implement bodies + tests, do not change
//! signatures/field names. Study capnp-zig's TCP transport before writing:
//!   zig-pkg/capnpc_zig-0.14.0-*/src/rpc/transport/tcp/{runtime,stream_transport,client}.zig
//!   zig-pkg/capnpc_zig-0.14.0-*/src/rpc/wire/framing.zig
//! Key entry points (confirmed for this pin):
//!   - Listener.init(gpa, io, net.IpAddress, Connection.Options) / .accept()
//!     OR bind a socket and use net.Server.accept(io); acceptFd() gives a raw
//!     SocketFd. Use SocketFd → Transport.init(gpa, io, socket, read_buf_sz).
//!   - Outbound: rpc.transport.tcp.client.ClientSession is RPC-level (too
//!     much). Instead dial with std.Io.net.IpAddress.parse(host, port) +
//!     .connect(io, .{ .mode = .stream }), setTcpNoDelay, wrap the fd in a
//!     Transport. (See client.zig:connect for the exact call shape.)
//!   - Per peer: a Framer (framing.Framer.init(gpa)); loop: Transport.read()
//!     → framer.push(bytes) → while (framer.popFrame()) |f| decode+dispatch.
//!     On framing error: framer.reset(), drop the peer.
//!   - Send: wire.encode(gpa, frame) → Transport.enqueueWrite(bytes) → free
//!     bytes. startWriter() once after Hello so enqueue is async.
//!
//! Handshake: immediately on a new connection (inbound or outbound) send our
//! Hello (protocol_version=1, our network_id_prefix, our node_id,
//! current_slot=0 advisory, our listen_port). Read the peer's first frame; it
//! MUST be a Hello with protocol_version==1 and a matching network_id_prefix,
//! else close. Only then assign a peer_id, fire on_peer_up, and enter the
//! read loop delivering subsequent frames to on_recv.
//!
//! Dialing & reconnect: dial every configured peer; on failure or drop,
//! reconnect with exponential backoff 1s→60s + jitter. Inbound peers are not
//! reciprocally dialed (they dialed us); duplicate A↔B connections are
//! tolerated — flood dedup is the engine's freshness, not the overlay's.
//! Derive jitter deterministically from a per-peer counter (no Math.random).
//!
//! Per-peer budgets (§9.1, basic is fine for M5): track an inbound byte-rate
//! window (soft cap ~256 KiB/s) and outstanding-request count (≤64); on
//! breach drop-and-log, on repeat disconnect. The e2e does not stress these;
//! implement conservatively and don't false-positive under healthy load.
//!
//!   * stop(): stop accepting, close all peer transports (unblocks reader
//!     reads → threads exit), signal dialers to quit, join all threads.
//!     deinit frees the table. Both idempotent and leak-free (ReleaseSafe +
//!     debug allocator gates run in CI).
//!   * Tests (loopback, ephemeral/fixed 127.0.0.1 ports): two overlays
//!     connect and exchange a ping/pong; wrong network_id_prefix → no
//!     on_peer_up, connection closed; an envelope frame broadcast by A
//!     arrives at B's on_recv byte-identical; broadcastExcept skips the
//!     named peer; stop() joins cleanly with a live connection.
//! ========================================================================

const std = @import("std");
const core = @import("slcp-core");
const capnpc = @import("capnpc-zig");
const wire = @import("wire.zig");

pub const default_read_buffer_size: usize = 256 * 1024;
pub const inbound_rate_soft_cap_bytes_per_s: usize = 256 * 1024;
pub const max_outstanding_requests: usize = 64;

pub const RecvFn = *const fn (ctx: ?*anyopaque, peer_id: usize, frame: *const wire.OverlayFrame) void;
pub const PeerEventFn = *const fn (ctx: ?*anyopaque, peer_id: usize) void;

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

pub const Overlay = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    cfg: Config,
    cb: Callbacks,
    _placeholder: usize = 0,

    /// Initialize (no sockets yet). The Node holds the Overlay by stable
    /// pointer; init must not capture `&self` internally — do that in start.
    pub fn init(gpa: std.mem.Allocator, io: std.Io, cfg: Config, cb: Callbacks) !Overlay {
        return .{ .gpa = gpa, .io = io, .cfg = cfg, .cb = cb };
    }

    /// Bind the listener, spawn the accept thread, and start dialing peers.
    pub fn start(self: *Overlay) !void {
        _ = self;
        @panic("stub: overlay.start — M5 agent");
    }

    /// The actually-bound listen port (equals cfg.listen_port unless 0 was
    /// given for an ephemeral port).
    pub fn boundPort(self: *Overlay) u16 {
        _ = self;
        @panic("stub: overlay.boundPort — M5 agent");
    }

    /// Encode `frame` and enqueue it to every connected, Hello-complete peer.
    pub fn broadcast(self: *Overlay, frame: wire.OverlayFrame) void {
        _ = self;
        _ = frame;
        @panic("stub: overlay.broadcast — M5 agent");
    }

    /// Send `frame` to one peer (no-op if that peer is gone).
    pub fn send(self: *Overlay, peer_id: usize, frame: wire.OverlayFrame) void {
        _ = self;
        _ = peer_id;
        _ = frame;
        @panic("stub: overlay.send — M5 agent");
    }

    /// Broadcast to all peers except `except_peer_id` (the relay path).
    pub fn broadcastExcept(self: *Overlay, except_peer_id: usize, frame: wire.OverlayFrame) void {
        _ = self;
        _ = except_peer_id;
        _ = frame;
        @panic("stub: overlay.broadcastExcept — M5 agent");
    }

    /// Number of Hello-complete peers.
    pub fn peerCount(self: *Overlay) usize {
        _ = self;
        @panic("stub: overlay.peerCount — M5 agent");
    }

    /// Stop accepting/dialing, close peers, join all threads. Idempotent.
    pub fn stop(self: *Overlay) void {
        _ = self;
        @panic("stub: overlay.stop — M5 agent");
    }

    pub fn deinit(self: *Overlay) void {
        _ = self;
        @panic("stub: overlay.deinit — M5 agent");
    }
};

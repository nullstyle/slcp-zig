//! registry.zig — the pure state machine of `examples/registry`
//! (docs/examples-roadmap.md "E1 — Registry").
//!
//! Standard library only: no slcp import, no I/O, no clock, no allocator.
//! Everything here is deterministic and bounded so it can run inside
//! `validate` / `apply` / `combine` on the engine thread. `app.zig` adapts it
//! to `slcp.AppNode`; `main.zig` and `rpc.zig` are the process around it.
//!
//! The shape is stellar-core's without money: principals hold Ed25519 keys
//! and sign transactions carrying a per-account sequence number; a slot's
//! value is a close time plus a transaction set; applying it advances a
//! ledger header hash chain over a bounded, sorted, plain-data state.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

// ---------------------------------------------------------------------------
// Constants (roadmap §3.1)
// ---------------------------------------------------------------------------

/// Transactions per set. 1 + 32 × 235 = 7521 bytes ≤ `max_value_bytes`.
pub const max_txs: usize = 32;
/// Bounded plain-data state (roadmap §2.1 gap 1): accounts and names.
pub const max_accounts: usize = 64;
pub const max_names: usize = 128;
/// Names are `[a-z0-9-]`, 1..32 bytes; values are any bytes, 0..64.
pub const name_max: usize = 32;
pub const value_max: usize = 64;
/// The fixed transaction encoding; the first 171 bytes are what is signed.
pub const tx_bytes: usize = 235;
pub const unsigned_tx_bytes: usize = 171;
/// Largest encoded transaction set: the count byte plus a full set.
pub const max_set_bytes: usize = 1 + max_txs * tx_bytes;
/// A consensus value has a disjoint domain tag, its close time, and a set.
pub const value_magic = "REGISTRY-VALUE-V1\n";
pub const max_ledger_value_bytes: usize = value_magic.len + 8 + max_set_bytes;
/// The node option: raised from the library's 4096 default to fit a full
/// ledger value (7547 bytes at the transaction cap).
pub const max_value_bytes: u32 = 8192;
/// The node's submit queue.
pub const max_pending: usize = 256;
/// Cadence defaults (`--min-slot-ms`, `--heartbeat-ms`): close no faster
/// than `min_slot_ms` when transactions are pending; when idle, close every
/// `heartbeat_ms`. E2a floods admitted transactions before nomination, so a
/// transaction can land in the first eligible slot after network admission;
/// the library's 16-slot answering window is 16 heartbeats of idle time.
pub const min_slot_ms: u64 = 1000;
pub const heartbeat_ms: u64 = 3000;

/// Whether the process should nominate after `elapsed_ms` since its last
/// applied slot. Pending work observes the busy-slot minimum; the heartbeat
/// is strictly the idle path and must never bypass that minimum.
pub fn nominationDue(has_pending: bool, elapsed_ms: u64, busy_min_ms: u64, idle_heartbeat_ms: u64) bool {
    return if (has_pending)
        elapsed_ms >= busy_min_ms
    else
        elapsed_ms >= idle_heartbeat_ms;
}

pub const max_close_time_step: u64 = 60;

/// Whether `close_time` can be reached at `slot` from the configured genesis
/// anchor using one deterministic 1..60-second step per ledger. Slot zero is
/// therefore exact equality with `genesis_close_time`; if even the lower
/// endpoint is not representable, no continuation exists.
pub fn closeTimeAtSlotOk(genesis_close_time: u64, slot: u64, close_time: u64) bool {
    const lower = std.math.add(u64, genesis_close_time, slot) catch return false;
    const upper = genesis_close_time +| (slot *| max_close_time_step);
    return close_time >= lower and close_time <= upper;
}

pub const tag_net = "REGISTRY-NET-V2";
pub const tag_tx = "REGISTRY-TX-V1";
pub const tag_hdr = "REGISTRY-HDR-V2";
pub const snap_magic = "REGISTRY-SNAP-V3\n";

comptime {
    std.debug.assert(max_ledger_value_bytes == 7547);
    std.debug.assert(max_ledger_value_bytes <= max_value_bytes);
    std.debug.assert(max_txs <= 255 and max_accounts <= 255 and max_names <= 255);
}

pub const Key = [32]u8;
pub const zero_key: Key = @splat(0);

/// The canonical network descriptor: tag ‖ genesis close time ‖ passphrase.
/// `out` must have room for the descriptor. The explicit genesis time makes
/// two otherwise identical deployments distinct transaction-signing domains.
pub fn networkDescriptor(genesis_close_time: u64, passphrase: []const u8, out: []u8) []u8 {
    const len = tag_net.len + 8 + passphrase.len;
    std.debug.assert(out.len >= len);
    @memcpy(out[0..tag_net.len], tag_net);
    std.mem.writeInt(u64, out[tag_net.len..][0..8], genesis_close_time, .big);
    @memcpy(out[tag_net.len + 8 ..][0..passphrase.len], passphrase);
    return out[0..len];
}

/// The registry's own network id: SHA-256 of `networkDescriptor`. Not the
/// library's networkId (different tag) — a transaction signed for one
/// descriptor is invalid on every other network.
pub fn networkId(passphrase: []const u8, genesis_close_time: u64) [32]u8 {
    var h = Sha256.init(.{});
    h.update(tag_net);
    var time_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &time_be, genesis_close_time, .big);
    h.update(&time_be);
    h.update(passphrase);
    return h.finalResult();
}

fn isZero(bytes: []const u8) bool {
    for (bytes) |b| if (b != 0) return false;
    return true;
}

/// `[a-z0-9-]`, 1..32 bytes.
pub fn nameOk(name: []const u8) bool {
    if (name.len == 0 or name.len > name_max) return false;
    for (name) |c| switch (c) {
        'a'...'z', '0'...'9', '-' => {},
        else => return false,
    };
    return true;
}

// ---------------------------------------------------------------------------
// Transactions (roadmap §3.2)
// ---------------------------------------------------------------------------

pub const Op = enum(u8) { claim = 1, set = 2, transfer = 3, release = 4 };

pub const Tx = struct {
    source: Key,
    seq: u64,
    op: Op,
    name_len: u8,
    name: [name_max]u8,
    value_len: u8,
    value: [value_max]u8,
    to: Key,
    sig: [64]u8,

    pub fn nameSlice(self: *const Tx) []const u8 {
        return self.name[0..self.name_len];
    }
    pub fn valueSlice(self: *const Tx) []const u8 {
        return self.value[0..self.value_len];
    }

    /// The largest legal seq: `seq + 1` must never overflow (review A:
    /// a signed transaction at 2^64−1 from any in-graph peer would have
    /// panicked `validate` on every node that heard it).
    pub const max_seq: u64 = std.math.maxInt(u64) - 1;

    /// An unsigned, canonical transaction; null when the name, value or
    /// per-op rules are violated (the same rules `decode` enforces).
    pub fn init(source: Key, seq: u64, op: Op, name: []const u8, value: []const u8, to: Key) ?Tx {
        if (seq == 0 or seq > max_seq or !nameOk(name) or value.len > value_max) return null;
        var tx: Tx = .{
            .source = source,
            .seq = seq,
            .op = op,
            .name_len = @intCast(name.len),
            .name = @splat(0),
            .value_len = @intCast(value.len),
            .value = @splat(0),
            .to = to,
            .sig = @splat(0),
        };
        @memcpy(tx.name[0..name.len], name);
        @memcpy(tx.value[0..value.len], value);
        if (!tx.opRulesOk()) return null;
        return tx;
    }

    /// Per-op canonical rules: claim/release carry no value and no `to`;
    /// set carries no `to`; transfer carries no value and a non-zero `to`.
    fn opRulesOk(self: *const Tx) bool {
        const to_zero = isZero(&self.to);
        return switch (self.op) {
            .claim, .release => self.value_len == 0 and to_zero,
            .set => to_zero,
            .transfer => self.value_len == 0 and !to_zero,
        };
    }

    pub fn encode(self: *const Tx, out: *[tx_bytes]u8) void {
        @memcpy(out[0..32], &self.source);
        std.mem.writeInt(u64, out[32..40], self.seq, .big);
        out[40] = @backingInt(self.op);
        out[41] = self.name_len;
        @memcpy(out[42..74], &self.name);
        out[74] = self.value_len;
        @memcpy(out[75..139], &self.value);
        @memcpy(out[139..171], &self.to);
        @memcpy(out[171..235], &self.sig);
    }

    /// Strict decode of exactly `tx_bytes`: one canonical spelling per
    /// transaction (zero padding, valid name bytes, the per-op rules,
    /// 1 ≤ seq ≤ `max_seq`).
    pub fn decode(bytes: []const u8) ?Tx {
        if (bytes.len != tx_bytes) return null;
        const op = std.enums.fromInt(Op, bytes[40]) orelse return null;
        const name_len = bytes[41];
        const value_len = bytes[74];
        if (name_len == 0 or name_len > name_max or value_len > value_max) return null;
        var tx: Tx = .{
            .source = bytes[0..32].*,
            .seq = std.mem.readInt(u64, bytes[32..40], .big),
            .op = op,
            .name_len = name_len,
            .name = bytes[42..74].*,
            .value_len = value_len,
            .value = bytes[75..139].*,
            .to = bytes[139..171].*,
            .sig = bytes[171..235].*,
        };
        if (tx.seq == 0 or tx.seq > max_seq) return null;
        if (!nameOk(tx.name[0..name_len]) or !isZero(tx.name[name_len..])) return null;
        if (!isZero(tx.value[value_len..])) return null;
        if (!tx.opRulesOk()) return null;
        return tx;
    }

    /// The transaction id and signing digest: SHA-256(tag ‖ network_id ‖ the
    /// 171 unsigned bytes). Never the raw preimage.
    pub fn digest(self: *const Tx, network_id: [32]u8) [32]u8 {
        var enc: [tx_bytes]u8 = undefined;
        self.encode(&enc);
        var h = Sha256.init(.{});
        h.update(tag_tx);
        h.update(&network_id);
        h.update(enc[0..unsigned_tx_bytes]);
        return h.finalResult();
    }

    pub fn sign(self: *Tx, seed: [32]u8, network_id: [32]u8) !void {
        const kp = try Ed25519.KeyPair.generateDeterministic(seed);
        const d = self.digest(network_id);
        const s = try kp.sign(&d, null);
        self.sig = s.toBytes();
    }

    pub fn verify(self: *const Tx, network_id: [32]u8) bool {
        const pk = Ed25519.PublicKey.fromBytes(self.source) catch return false;
        const s = Ed25519.Signature.fromBytes(self.sig);
        const d = self.digest(network_id);
        s.verify(&d, pk) catch return false;
        return true;
    }

    /// The set order: source bytes, then seq.
    pub fn order(a: *const Tx, b: *const Tx) std.math.Order {
        const o = std.mem.order(u8, &a.source, &b.source);
        if (o != .eq) return o;
        return std.math.order(a.seq, b.seq);
    }

    fn lessThan(_: void, a: Tx, b: Tx) bool {
        return order(&a, &b) == .lt;
    }

    /// Byte order of the full encodings (the dedup tie-break in `combine`).
    fn encodedOrder(a: *const Tx, b: *const Tx) std.math.Order {
        var ea: [tx_bytes]u8 = undefined;
        var eb: [tx_bytes]u8 = undefined;
        a.encode(&ea);
        b.encode(&eb);
        return std.mem.order(u8, &ea, &eb);
    }
};

// ---------------------------------------------------------------------------
// Transaction sets — the Command (roadmap §3.3)
// ---------------------------------------------------------------------------

pub const TxSet = struct {
    count: u8 = 0,
    /// Only `txs[0..count]` are meaningful; the rest is never read.
    txs: [max_txs]Tx = undefined,

    pub const empty: TxSet = .{ .count = 0 };

    pub fn slice(self: *const TxSet) []const Tx {
        return self.txs[0..self.count];
    }

    /// `count` then `count` transactions. `buf.len >= max_set_bytes`.
    pub fn encode(self: *const TxSet, buf: []u8) []u8 {
        std.debug.assert(buf.len >= max_set_bytes);
        buf[0] = self.count;
        var off: usize = 1;
        for (self.slice()) |*tx| {
            tx.encode(buf[off..][0..tx_bytes]);
            off += tx_bytes;
        }
        return buf[0..off];
    }

    /// Strict: exact length, `count <= max_txs`, every transaction canonical,
    /// strictly ascending by (source, seq).
    pub fn decode(bytes: []const u8) ?TxSet {
        if (bytes.len == 0) return null;
        const count = bytes[0];
        if (count > max_txs) return null;
        if (bytes.len != 1 + @as(usize, count) * tx_bytes) return null;
        var set: TxSet = .{ .count = count };
        var off: usize = 1;
        for (0..count) |i| {
            set.txs[i] = Tx.decode(bytes[off..][0..tx_bytes]) orelse return null;
            if (i > 0 and Tx.order(&set.txs[i - 1], &set.txs[i]) != .lt) return null;
            off += tx_bytes;
        }
        return set;
    }

    /// SHA-256 of the encoding (the header's `txset_hash`).
    pub fn hash(self: *const TxSet) [32]u8 {
        var buf: [max_set_bytes]u8 = undefined;
        return sha256(self.encode(&buf));
    }
};

/// The application value externalized by consensus. Its domain-tagged
/// encoding is intentionally disjoint from both a bare transaction set and a
/// transaction, so pre-E2c bytes cannot acquire a new meaning after upgrade.
pub const LedgerValue = struct {
    close_time: u64,
    txs: TxSet,

    pub fn encode(self: *const LedgerValue, buf: []u8) []u8 {
        std.debug.assert(buf.len >= max_ledger_value_bytes);
        @memcpy(buf[0..value_magic.len], value_magic);
        std.mem.writeInt(u64, buf[value_magic.len..][0..8], self.close_time, .big);
        const encoded_txs = self.txs.encode(buf[value_magic.len + 8 ..]);
        return buf[0 .. value_magic.len + 8 + encoded_txs.len];
    }

    pub fn decode(bytes: []const u8) ?LedgerValue {
        if (bytes.len < value_magic.len + 8 + 1) return null;
        if (!std.mem.eql(u8, bytes[0..value_magic.len], value_magic)) return null;
        return .{
            .close_time = std.mem.readInt(u64, bytes[value_magic.len..][0..8], .big),
            .txs = TxSet.decode(bytes[value_magic.len + 8 ..]) orelse return null,
        };
    }

    pub fn hash(self: *const LedgerValue) [32]u8 {
        var buf: [max_ledger_value_bytes]u8 = undefined;
        return sha256(self.encode(&buf));
    }
};

fn sha256(bytes: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(bytes);
    return h.finalResult();
}

// ---------------------------------------------------------------------------
// State (roadmap §3.4)
// ---------------------------------------------------------------------------

pub const Result = enum(u8) { ok = 0, name_taken = 1, not_owner = 2, no_such_name = 3, registry_full = 4 };

pub const Header = struct {
    slot: u64 = 0,
    close_time: u64 = 0,
    hash: [32]u8 = @splat(0),
    prev_hash: [32]u8 = @splat(0),
    txset_hash: [32]u8 = @splat(0),
    state_root: [32]u8 = @splat(0),
};

pub const Account = struct { key: Key = zero_key, seq: u64 = 0 };

pub const Entry = struct {
    name_len: u8 = 0,
    name: [name_max]u8 = @splat(0),
    owner: Key = zero_key,
    value_len: u8 = 0,
    value: [value_max]u8 = @splat(0),

    pub fn nameSlice(self: *const Entry) []const u8 {
        return self.name[0..self.name_len];
    }
    pub fn valueSlice(self: *const Entry) []const u8 {
        return self.value[0..self.value_len];
    }
};

/// The canonical state bytes: `n_accounts ‖ accounts ‖ n_names ‖ names`.
pub const state_bytes_max: usize = 1 + max_accounts * 40 + 1 + max_names * 130;

pub const State = struct {
    /// Set at genesis from the passphrase plus genesis close time; identical
    /// on every node.
    network_id: [32]u8 = @splat(0),
    head: Header = .{},
    n_accounts: u8 = 0,
    /// Sorted by key.
    accounts: [max_accounts]Account = @splat(Account{}),
    n_names: u8 = 0,
    /// Sorted by (padded) name.
    names: [max_names]Entry = @splat(Entry{}),
    /// The results of the last applied set, in set order.
    last_count: u8 = 0,
    last_results: [max_txs]Result = @splat(.ok),
    /// The exact consensus value that advanced `head` to its current slot.
    /// This is checkpoint context, not part of the replicated state root.
    last_value: ?LedgerValue = null,

    /// Construct the one canonical slot-zero ledger head for a network.
    /// Genesis is a real header: it commits to the empty state and its
    /// configured close time, but to no transaction set or previous header.
    pub fn genesis(network_id: [32]u8, genesis_close_time: u64) State {
        var state: State = .{ .network_id = network_id };
        state.head.close_time = genesis_close_time;
        state.head.state_root = state.stateRoot();
        state.head.hash = headerHash(network_id, &state.head);
        return state;
    }

    pub fn accountsSlice(self: *const State) []const Account {
        return self.accounts[0..self.n_accounts];
    }
    pub fn namesSlice(self: *const State) []const Entry {
        return self.names[0..self.n_names];
    }
    pub fn lastResults(self: *const State) []const Result {
        return self.last_results[0..self.last_count];
    }

    /// Binary search over the sorted accounts: the index, or the insertion
    /// point wrapped as `.missing`.
    fn locateAccount(self: *const State, key: Key) union(enum) { found: usize, missing: usize } {
        var lo: usize = 0;
        var hi: usize = self.n_accounts;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, &self.accounts[mid].key, &key)) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return .{ .found = mid },
            }
        }
        return .{ .missing = lo };
    }

    fn locateName(self: *const State, padded: *const [name_max]u8) union(enum) { found: usize, missing: usize } {
        var lo: usize = 0;
        var hi: usize = self.n_names;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, &self.names[mid].name, padded)) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return .{ .found = mid },
            }
        }
        return .{ .missing = lo };
    }

    pub fn findAccount(self: *const State, key: Key) ?*const Account {
        return switch (self.locateAccount(key)) {
            .found => |i| &self.accounts[i],
            .missing => null,
        };
    }

    /// 0 for an unknown account.
    pub fn accountSeq(self: *const State, key: Key) u64 {
        return if (self.findAccount(key)) |a| a.seq else 0;
    }

    pub fn findName(self: *const State, name: []const u8) ?*const Entry {
        if (!nameOk(name)) return null;
        var padded: [name_max]u8 = @splat(0);
        @memcpy(padded[0..name.len], name);
        return switch (self.locateName(&padded)) {
            .found => |i| &self.names[i],
            .missing => null,
        };
    }

    /// The account for `key`, created (seq 0) at its sorted position when
    /// absent. Asserts room: `validate` refused sets that need more.
    fn accountFor(self: *State, key: Key) *Account {
        switch (self.locateAccount(key)) {
            .found => |i| return &self.accounts[i],
            .missing => |at| {
                std.debug.assert(self.n_accounts < max_accounts);
                var i: usize = self.n_accounts;
                while (i > at) : (i -= 1) self.accounts[i] = self.accounts[i - 1];
                self.accounts[at] = .{ .key = key, .seq = 0 };
                self.n_accounts += 1;
                return &self.accounts[at];
            },
        }
    }

    fn insertName(self: *State, at: usize, e: Entry) void {
        std.debug.assert(self.n_names < max_names);
        var i: usize = self.n_names;
        while (i > at) : (i -= 1) self.names[i] = self.names[i - 1];
        self.names[at] = e;
        self.n_names += 1;
    }

    fn removeName(self: *State, at: usize) void {
        var i: usize = at;
        while (i + 1 < self.n_names) : (i += 1) self.names[i] = self.names[i + 1];
        self.n_names -= 1;
        self.names[self.n_names] = .{};
    }

    /// The canonical state bytes (what `state_root` hashes and what the
    /// snapshot stores). `buf.len >= state_bytes_max`.
    pub fn serialize(self: *const State, buf: []u8) []u8 {
        std.debug.assert(buf.len >= state_bytes_max);
        var off: usize = 0;
        buf[off] = self.n_accounts;
        off += 1;
        for (self.accountsSlice()) |a| {
            @memcpy(buf[off..][0..32], &a.key);
            std.mem.writeInt(u64, buf[off + 32 ..][0..8], a.seq, .big);
            off += 40;
        }
        buf[off] = self.n_names;
        off += 1;
        for (self.namesSlice()) |e| {
            buf[off] = e.name_len;
            @memcpy(buf[off + 1 ..][0..32], &e.name);
            @memcpy(buf[off + 33 ..][0..32], &e.owner);
            buf[off + 65] = e.value_len;
            @memcpy(buf[off + 66 ..][0..64], &e.value);
            off += 130;
        }
        return buf[0..off];
    }

    /// Strict inverse of `serialize`: exact length, sorted and unique keys
    /// and names, canonical padding. Header, network id and results are the
    /// caller's (see the snapshot functions).
    pub fn deserialize(bytes: []const u8) ?State {
        var s: State = .{};
        if (bytes.len < 1) return null;
        const na = bytes[0];
        if (na > max_accounts) return null;
        var off: usize = 1;
        if (bytes.len < off + @as(usize, na) * 40 + 1) return null;
        for (0..na) |i| {
            s.accounts[i] = .{ .key = bytes[off..][0..32].*, .seq = std.mem.readInt(u64, bytes[off + 32 ..][0..8], .big) };
            if (i > 0 and std.mem.order(u8, &s.accounts[i - 1].key, &s.accounts[i].key) != .lt) return null;
            off += 40;
        }
        s.n_accounts = na;
        const nn = bytes[off];
        off += 1;
        if (nn > max_names) return null;
        if (bytes.len != off + @as(usize, nn) * 130) return null;
        for (0..nn) |i| {
            var e: Entry = .{
                .name_len = bytes[off],
                .name = bytes[off + 1 ..][0..32].*,
                .owner = bytes[off + 33 ..][0..32].*,
                .value_len = bytes[off + 65],
                .value = bytes[off + 66 ..][0..64].*,
            };
            if (e.name_len == 0 or e.name_len > name_max or e.value_len > value_max) return null;
            if (!nameOk(e.name[0..e.name_len]) or !isZero(e.name[e.name_len..])) return null;
            if (!isZero(e.value[e.value_len..])) return null;
            if (i > 0 and std.mem.order(u8, &s.names[i - 1].name, &e.name) != .lt) return null;
            s.names[i] = e;
            e = undefined;
            off += 130;
        }
        s.n_names = nn;
        return s;
    }

    /// SHA-256 of `serialize`: excludes the header, the network id, the last
    /// results, and the last consensus ledger value.
    pub fn stateRoot(self: *const State) [32]u8 {
        var buf: [state_bytes_max]u8 = undefined;
        return sha256(self.serialize(&buf));
    }
};

// ---------------------------------------------------------------------------
// validate / combine / apply (roadmap §3.5–§3.7)
// ---------------------------------------------------------------------------

pub const Verdict = enum { invalid, maybe_valid, valid };

/// Judge a value for contextual slot `slot`. Close time must lie in the
/// slot-derived interval `[T + d, T + 60d]`, where `(H,T)` is the local head
/// and `d = slot - H`. A value for the immediate successor must be completely
/// valid now; a value for a later slot is necessarily `.maybe_valid` even when
/// its transaction set is otherwise valid, because the intervening state is
/// not known locally.
pub fn validate(state: *const State, value: *const LedgerValue, slot: u64) Verdict {
    const head = state.head;
    if (slot <= head.slot) return .invalid;
    const d = slot - head.slot;
    const lower = std.math.add(u64, head.close_time, d) catch return .invalid;
    const upper = head.close_time +| (d *| max_close_time_step);
    if (value.close_time < lower or value.close_time > upper) return .invalid;

    return switch (judge(state, &value.txs, true)) {
        .invalid => .invalid,
        .valid => if (d == 1) .valid else .maybe_valid,
        .maybe_valid => if (d == 1) .invalid else .maybe_valid,
    };
}

/// The structural half of `validate` — order, per-source contiguity from
/// the expected seq, account capacity — without the signatures. True iff
/// `apply` can run the set on `state` without tripping an assertion.
pub fn appliesCleanly(state: *const State, set: *const TxSet) bool {
    return judge(state, set, false) == .valid;
}

fn judge(state: *const State, set: *const TxSet, check_sigs: bool) Verdict {
    const txs = set.slice();
    var verdict: Verdict = .valid;
    var new_accounts: usize = 0;
    var i: usize = 0;
    while (i < txs.len) {
        const src = txs[i].source;
        const known = state.findAccount(src);
        var expected: u64 = if (known) |a| a.seq +| 1 else 1;
        if (known == null) {
            new_accounts += 1;
            if (@as(usize, state.n_accounts) + new_accounts > max_accounts) return .invalid;
        }
        var first = true;
        while (i < txs.len and std.mem.eql(u8, &txs[i].source, &src)) : (i += 1) {
            const tx = &txs[i];
            if (i > 0 and Tx.order(&txs[i - 1], tx) != .lt) return .invalid;
            if (check_sigs and !tx.verify(state.network_id)) return .invalid;
            if (tx.seq < expected) return .invalid; // replay
            if (tx.seq > expected) {
                if (!first) return .invalid; // a gap inside one source's run
                verdict = .maybe_valid; // ahead: this node may be behind
                expected = tx.seq;
            }
            expected +|= 1;
            first = false;
        }
    }
    return verdict;
}

/// The bounded merge pool `combine` fills before selecting.
pub const pool_cap: usize = 256;

/// Insert `tx` into the sorted, (source, seq)-unique `pool[0..n.*]`. A
/// duplicate keeps the smaller full encoding. A full pool drops the largest
/// element (the pool keeps the smallest `pool_cap` in set order), so the
/// result depends only on the multiset of inputs.
fn poolInsert(pool: []Tx, n: *usize, tx: *const Tx) void {
    var lo: usize = 0;
    var hi: usize = n.*;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (Tx.order(&pool[mid], tx)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => {
                if (Tx.encodedOrder(tx, &pool[mid]) == .lt) pool[mid] = tx.*;
                return;
            },
        }
    }
    if (n.* == pool.len) {
        if (lo == pool.len) return; // larger than everything kept
        n.* -= 1; // drop the largest
    }
    var i: usize = n.*;
    while (i > lo) : (i -= 1) pool[i] = pool[i - 1];
    pool[lo] = tx.*;
    n.* += 1;
}

/// From a sorted, (source, seq)-unique pool, the set that applies cleanly
/// on `state`: per source the contiguous run from `expected` (replays
/// dropped, a run that starts ahead dropped whole), signatures verified,
/// the account table's capacity respected, at most `max_txs`. The result
/// validates `.valid` on `state` by construction.
pub fn select(state: *const State, pool: []const Tx) TxSet {
    var out: TxSet = .{ .count = 0 };
    var new_accounts: usize = 0;
    var i: usize = 0;
    while (i < pool.len and out.count < max_txs) {
        const src = pool[i].source;
        const known = state.findAccount(src);
        const expected0: u64 = if (known) |a| a.seq +| 1 else 1;
        var expected = expected0;
        var taken: usize = 0;
        const room = known != null or @as(usize, state.n_accounts) + new_accounts < max_accounts;
        while (i < pool.len and std.mem.eql(u8, &pool[i].source, &src)) : (i += 1) {
            const tx = &pool[i];
            if (!room or out.count >= max_txs) continue;
            if (tx.seq < expected) continue; // replay
            if (tx.seq != expected) {
                // Ahead (or the run broke): nothing more from this source.
                expected = 0;
                continue;
            }
            if (!tx.verify(state.network_id)) {
                expected = 0;
                continue;
            }
            out.txs[out.count] = tx.*;
            out.count += 1;
            taken += 1;
            expected +|= 1;
        }
        if (known == null and taken > 0) new_accounts += 1;
    }
    return out;
}

/// The nomination composite uses the minimum proposed close time and the
/// union of every candidate's transactions, deduplicated and selected against
/// `state`. Candidate order therefore cannot influence either field.
/// `cmds` is non-empty because the consensus engine combines candidates only
/// after nomination has produced at least one.
pub fn combine(state: *const State, cmds: []const LedgerValue) LedgerValue {
    std.debug.assert(cmds.len > 0);
    var close_time = cmds[0].close_time;
    var pool: [pool_cap]Tx = undefined;
    var n: usize = 0;
    for (cmds) |*value| {
        close_time = @min(close_time, value.close_time);
        for (value.txs.slice()) |*tx| poolInsert(&pool, &n, tx);
    }
    return .{ .close_time = close_time, .txs = select(state, pool[0..n]) };
}

/// The node's own proposal: a read-only pending queue, sorted and deduplicated
/// through the bounded local pool, selected against `state`, with wall time
/// clamped into the immediate successor's deterministic legal interval.
/// No successor exists once close time has reached `u64` maximum.
pub fn proposal(state: *const State, pending: []const Tx, wall_s: u64) ?LedgerValue {
    if (state.head.close_time == std.math.maxInt(u64)) return null;
    var pool: [pool_cap]Tx = undefined;
    var n: usize = 0;
    for (pending) |*tx| poolInsert(&pool, &n, tx);
    const lower = state.head.close_time + 1;
    const upper = state.head.close_time +| max_close_time_step;
    return .{
        .close_time = std.math.clamp(wall_s, lower, upper),
        .txs = select(state, pool[0..n]),
    };
}

/// Apply an immediate-successor value that `validate` judged `.valid`
/// (roadmap §3.7): every
/// transaction consumes its sequence number, even when its operation
/// fails; then the header advances one slot.
///
/// Total and defensive: a value whose close time is not in `(T, T + 60]`,
/// whose transactions do not apply cleanly, or whose successor slot would
/// overflow is skipped and the state stays put.
pub fn apply(state: *State, value: *const LedgerValue) void {
    if (state.head.slot == std.math.maxInt(u64) or
        state.head.close_time == std.math.maxInt(u64) or
        value.close_time <= state.head.close_time or
        value.close_time > state.head.close_time +| max_close_time_step or
        !appliesCleanly(state, &value.txs)) return;

    const txs = value.txs.slice();
    for (txs, 0..) |*tx, i| {
        const acct = state.accountFor(tx.source);
        std.debug.assert(tx.seq == acct.seq + 1);
        acct.seq = tx.seq;
        state.last_results[i] = execute(state, tx);
    }
    state.last_count = @intCast(txs.len);
    for (state.last_results[txs.len..]) |*r| r.* = .ok;
    state.last_value = value.*;

    const h = &state.head;
    h.slot += 1;
    h.close_time = value.close_time;
    h.prev_hash = h.hash;
    h.txset_hash = value.txs.hash();
    h.state_root = state.stateRoot();
    h.hash = headerHash(state.network_id, h);
}

fn execute(state: *State, tx: *const Tx) Result {
    switch (state.locateName(&tx.name)) {
        .found => |i| {
            const e = &state.names[i];
            switch (tx.op) {
                .claim => return .name_taken,
                .set => {
                    if (!std.mem.eql(u8, &e.owner, &tx.source)) return .not_owner;
                    e.value_len = tx.value_len;
                    e.value = tx.value;
                    return .ok;
                },
                .transfer => {
                    if (!std.mem.eql(u8, &e.owner, &tx.source)) return .not_owner;
                    e.owner = tx.to;
                    return .ok;
                },
                .release => {
                    if (!std.mem.eql(u8, &e.owner, &tx.source)) return .not_owner;
                    state.removeName(i);
                    return .ok;
                },
            }
        },
        .missing => |at| {
            switch (tx.op) {
                .claim => {
                    if (state.n_names >= max_names) return .registry_full;
                    state.insertName(at, .{ .name_len = tx.name_len, .name = tx.name, .owner = tx.source });
                    return .ok;
                },
                .set, .transfer, .release => return .no_such_name,
            }
        },
    }
}

/// SHA-256(tag ‖ network_id ‖ slot ‖ close_time ‖ prev_hash ‖
/// txset_hash ‖ state_root).
pub fn headerHash(network_id: [32]u8, h: *const Header) [32]u8 {
    var hh = Sha256.init(.{});
    hh.update(tag_hdr);
    hh.update(&network_id);
    var slot_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &slot_be, h.slot, .big);
    hh.update(&slot_be);
    var close_time_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &close_time_be, h.close_time, .big);
    hh.update(&close_time_be);
    hh.update(&h.prev_hash);
    hh.update(&h.txset_hash);
    hh.update(&h.state_root);
    return hh.finalResult();
}

// ---------------------------------------------------------------------------
// Snapshot (roadmap §3.8)
// ---------------------------------------------------------------------------

/// V3: magic ‖ network_id ‖ slot ‖ close_time ‖ hash ‖ prev_hash ‖
/// txset_hash ‖ state_root ‖ last-value length ‖ last-value bytes ‖
/// state bytes ‖ SHA-256 of everything before it. A zero last-value length
/// is reserved for the canonical, real genesis header.
pub const snapshot_max_bytes: usize = snap_magic.len + 32 + 8 + 8 + 4 * 32 + 2 + max_ledger_value_bytes + state_bytes_max + 32;
const snapshot_fixed_prefix: usize = snap_magic.len + 32 + 8 + 8 + 4 * 32;

/// `buf.len >= snapshot_max_bytes`.
pub fn writeSnapshot(state: *const State, buf: []u8) []u8 {
    std.debug.assert(buf.len >= snapshot_max_bytes);
    var off: usize = 0;
    @memcpy(buf[off..][0..snap_magic.len], snap_magic);
    off += snap_magic.len;
    @memcpy(buf[off..][0..32], &state.network_id);
    off += 32;
    std.mem.writeInt(u64, buf[off..][0..8], state.head.slot, .big);
    off += 8;
    std.mem.writeInt(u64, buf[off..][0..8], state.head.close_time, .big);
    off += 8;
    inline for (.{ &state.head.hash, &state.head.prev_hash, &state.head.txset_hash, &state.head.state_root }) |f| {
        @memcpy(buf[off..][0..32], f);
        off += 32;
    }
    if (state.last_value) |*value| {
        std.debug.assert(state.head.slot > 0);
        std.debug.assert(value.close_time == state.head.close_time);
        std.debug.assert(std.mem.eql(u8, &state.head.txset_hash, &value.txs.hash()));
        var value_buf: [max_ledger_value_bytes]u8 = undefined;
        const encoded = value.encode(&value_buf);
        std.mem.writeInt(u16, buf[off..][0..2], @intCast(encoded.len), .big);
        off += 2;
        @memcpy(buf[off..][0..encoded.len], encoded);
        off += encoded.len;
    } else {
        std.debug.assert(state.head.slot == 0);
        std.mem.writeInt(u16, buf[off..][0..2], 0, .big);
        off += 2;
    }
    const body = state.serialize(buf[off..]);
    off += body.len;
    const sum = sha256(buf[0..off]);
    @memcpy(buf[off..][0..32], &sum);
    off += 32;
    return buf[0..off];
}

/// Strict V3 only: checksum, canonical state bytes, and the header's
/// `state_root` must equal the root of the state read back. Every non-genesis
/// snapshot carries the exact canonical last consensus value and binds both
/// its close time and transaction-set hash to the head. Genesis must be the
/// exact real header constructed by `State.genesis`. Results are zeroed (they
/// are not persisted).
pub fn readSnapshot(bytes: []const u8) ?State {
    if (bytes.len < snapshot_fixed_prefix + 2 + 32) return null;
    if (!std.mem.eql(u8, bytes[0..snap_magic.len], snap_magic)) return null;
    const body_end = bytes.len - 32;
    const sum = sha256(bytes[0..body_end]);
    if (!std.mem.eql(u8, &sum, bytes[body_end..])) return null;
    var off: usize = snap_magic.len;
    const network_id = bytes[off..][0..32].*;
    off += 32;
    var head: Header = .{};
    head.slot = std.mem.readInt(u64, bytes[off..][0..8], .big);
    off += 8;
    head.close_time = std.mem.readInt(u64, bytes[off..][0..8], .big);
    off += 8;
    head.hash = bytes[off..][0..32].*;
    head.prev_hash = bytes[off + 32 ..][0..32].*;
    head.txset_hash = bytes[off + 64 ..][0..32].*;
    head.state_root = bytes[off + 96 ..][0..32].*;
    off = snapshot_fixed_prefix;

    if (body_end < off + 2 + 2) return null;
    const value_len: usize = std.mem.readInt(u16, bytes[off..][0..2], .big);
    off += 2;
    if (value_len > max_ledger_value_bytes or body_end < off + value_len + 2) return null;
    var last_value: ?LedgerValue = null;
    if (head.slot == 0) {
        if (value_len != 0) return null;
    } else {
        if (value_len == 0) return null;
        const value = LedgerValue.decode(bytes[off..][0..value_len]) orelse return null;
        if (value.close_time != head.close_time or
            !std.mem.eql(u8, &head.txset_hash, &value.txs.hash())) return null;
        last_value = value;
    }
    off += value_len;

    var state = State.deserialize(bytes[off..body_end]) orelse return null;
    state.network_id = network_id;
    state.head = head;
    state.last_value = last_value;
    if (state.head.slot == 0) {
        if (state.n_accounts != 0 or state.n_names != 0) return null;
        const canonical = State.genesis(network_id, state.head.close_time);
        if (!std.meta.eql(state.head, canonical.head)) return null;
    } else {
        if (!std.mem.eql(u8, &state.head.state_root, &state.stateRoot())) return null;
        if (!std.mem.eql(u8, &state.head.hash, &headerHash(state.network_id, &state.head))) return null;
    }
    return state;
}

// ---------------------------------------------------------------------------
// Hex helpers shared by the CLI, the RPC and the tests
// ---------------------------------------------------------------------------

pub fn hex32(bytes: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(bytes, .lower);
}

/// The public key of a 32-byte seed (the library's key-file format).
pub fn publicKeyOf(seed: [32]u8) !Key {
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    return kp.public_key.toBytes();
}

pub fn parseKey(hex: []const u8) ?Key {
    if (hex.len != 64) return null;
    var out: Key = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch return null;
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const TestNet = struct {
    const genesis_close_time: u64 = 1_700_000_000;

    id: [32]u8,
    seeds: [3][32]u8,
    keys: [3]Key,

    fn init() TestNet {
        var t: TestNet = .{ .id = networkId("registry test net", genesis_close_time), .seeds = undefined, .keys = undefined };
        for (0..3) |i| {
            t.seeds[i] = @splat(@intCast(i + 11));
            const kp = Ed25519.KeyPair.generateDeterministic(t.seeds[i]) catch unreachable;
            t.keys[i] = kp.public_key.toBytes();
        }
        return t;
    }

    fn tx(self: *const TestNet, who: usize, seq: u64, op: Op, name: []const u8, value: []const u8, to: Key) Tx {
        var t = Tx.init(self.keys[who], seq, op, name, value, to).?;
        t.sign(self.seeds[who], self.id) catch unreachable;
        return t;
    }

    fn set(txs: []const Tx) TxSet {
        var s: TxSet = .{ .count = @intCast(txs.len) };
        for (txs, 0..) |t, i| s.txs[i] = t;
        return s;
    }

    fn genesis(self: *const TestNet) State {
        return State.genesis(self.id, genesis_close_time);
    }

    fn nextValue(state: *const State, set_value: TxSet) LedgerValue {
        return .{ .close_time = state.head.close_time + 1, .txs = set_value };
    }

    fn validateNext(state: *const State, set_value: *const TxSet) Verdict {
        const value = nextValue(state, set_value.*);
        return validate(state, &value, state.head.slot + 1);
    }

    fn applyNext(state: *State, set_value: *const TxSet) void {
        const value = nextValue(state, set_value.*);
        apply(state, &value);
    }
};

// Non-vacuity: dropping `tag_net` from networkId, or `network_id` from the
// digest, makes the cross-network signature verify.
test "network id: passphrases differ; a signature does not carry across networks" {
    const t = TestNet.init();
    try testing.expect(!std.mem.eql(u8, &networkId("a", TestNet.genesis_close_time), &networkId("b", TestNet.genesis_close_time)));
    try testing.expect(!std.mem.eql(u8, &networkId("a", TestNet.genesis_close_time), &networkId("a", TestNet.genesis_close_time + 1)));
    const tx = t.tx(0, 1, .claim, "alice", "", zero_key);
    try testing.expect(tx.verify(t.id));
    try testing.expect(!tx.verify(networkId("some other net", TestNet.genesis_close_time)));
    var tampered = tx;
    tampered.seq = 2;
    try testing.expect(!tampered.verify(t.id));
}

// Non-vacuity: each `return null` in Tx.decode has a case below.
test "tx: encode/decode round-trips; every non-canonical spelling is refused" {
    const t = TestNet.init();
    const tx = t.tx(1, 7, .set, "bob-1", "hello", zero_key);
    var enc: [tx_bytes]u8 = undefined;
    tx.encode(&enc);
    const back = Tx.decode(&enc).?;
    try testing.expectEqual(tx.seq, back.seq);
    try testing.expectEqualStrings("bob-1", back.nameSlice());
    try testing.expectEqualStrings("hello", back.valueSlice());
    try testing.expect(back.verify(t.id));

    try testing.expect(Tx.decode(enc[0 .. tx_bytes - 1]) == null); // length
    var bad = enc;
    bad[40] = 9; // op tag
    try testing.expect(Tx.decode(&bad) == null);
    bad = enc;
    @memset(bad[32..40], 0); // seq 0
    try testing.expect(Tx.decode(&bad) == null);
    bad = enc;
    bad[41] = 0; // name_len 0
    try testing.expect(Tx.decode(&bad) == null);
    bad = enc;
    bad[42 + 5] = 'x'; // name padding
    try testing.expect(Tx.decode(&bad) == null);
    bad = enc;
    bad[42] = 'B'; // name chars
    try testing.expect(Tx.decode(&bad) == null);
    bad = enc;
    bad[75 + 5] = 1; // value padding
    try testing.expect(Tx.decode(&bad) == null);
    bad = enc;
    bad[74] = 65; // value_len
    try testing.expect(Tx.decode(&bad) == null);
    bad = enc;
    bad[139] = 1; // `to` on a set
    try testing.expect(Tx.decode(&bad) == null);
    // claim with a value; transfer with a zero `to`; release with a value.
    try testing.expect(Tx.init(t.keys[0], 1, .claim, "a", "v", zero_key) == null);
    try testing.expect(Tx.init(t.keys[0], 1, .transfer, "a", "", zero_key) == null);
    try testing.expect(Tx.init(t.keys[0], 1, .release, "a", "v", zero_key) == null);
    try testing.expect(Tx.init(t.keys[0], 1, .transfer, "a", "", t.keys[1]) != null);
    try testing.expect(Tx.init(t.keys[0], 1, .claim, "Not-Ok", "", zero_key) == null);
    const long_name: [name_max + 1]u8 = @splat('x');
    try testing.expect(Tx.init(t.keys[0], 1, .claim, &long_name, "", zero_key) == null);
    try testing.expect(Tx.init(t.keys[0], 0, .claim, "a", "", zero_key) == null);
}

// Non-vacuity: removing the order check in TxSet.decode accepts the
// swapped set; removing the count check accepts 33.
test "tx set: empty set is one byte; round-trip; unsorted, duplicate, oversize and trailing bytes refused" {
    const t = TestNet.init();
    var buf: [max_set_bytes]u8 = undefined;
    const e = TxSet.empty.encode(&buf);
    try testing.expectEqual(@as(usize, 1), e.len);
    try testing.expectEqual(@as(u8, 0), e[0]);
    try testing.expectEqual(@as(u8, 0), TxSet.decode(e).?.count);

    const a1 = t.tx(0, 1, .claim, "alice", "", zero_key);
    const a2 = t.tx(0, 2, .set, "alice", "v", zero_key);
    const b1 = t.tx(1, 1, .claim, "bob", "", zero_key);
    // Sorted by source bytes then seq — whichever key is smaller comes first.
    const first_is_0 = std.mem.order(u8, &t.keys[0], &t.keys[1]) == .lt;
    const sorted = if (first_is_0) TestNet.set(&.{ a1, a2, b1 }) else TestNet.set(&.{ b1, a1, a2 });
    const enc = sorted.encode(&buf);
    try testing.expectEqual(1 + 3 * tx_bytes, enc.len);
    const back = TxSet.decode(enc).?;
    try testing.expectEqual(@as(u8, 3), back.count);
    try testing.expectEqual(Verdict.valid, TestNet.validateNext(&t.genesis(), &back));

    const swapped = if (first_is_0) TestNet.set(&.{ a2, a1, b1 }) else TestNet.set(&.{ b1, a2, a1 });
    var buf2: [max_set_bytes]u8 = undefined;
    try testing.expect(TxSet.decode(swapped.encode(&buf2)) == null);
    const dup = TestNet.set(&.{ a1, a1 });
    try testing.expect(TxSet.decode(dup.encode(&buf2)) == null);
    var trailing: [max_set_bytes + 1]u8 = undefined;
    @memcpy(trailing[0..enc.len], enc);
    try testing.expect(TxSet.decode(trailing[0 .. enc.len + 1]) == null);
    var big: [1 + (max_txs + 1) * tx_bytes]u8 = undefined;
    big[0] = max_txs + 1;
    try testing.expect(TxSet.decode(&big) == null);
}

// Non-vacuity (review A): with a plain `+ 1` in `judge`, a run at the top
// of the seq range overflows and panics; without the `max_seq` bound a
// signed transaction at 2^64−1 decodes and reaches `validate`.
test "seq range: 2^64−1 is not a transaction; a run at the top of the range does not overflow validate" {
    const t = TestNet.init();
    try testing.expect(Tx.init(t.keys[0], std.math.maxInt(u64), .claim, "a", "", zero_key) == null);
    try testing.expect(Tx.init(t.keys[0], Tx.max_seq, .claim, "a", "", zero_key) != null);
    var top = t.tx(0, Tx.max_seq, .claim, "top", "", zero_key);
    var enc: [tx_bytes]u8 = undefined;
    top.encode(&enc);
    std.mem.writeInt(u64, enc[32..40], std.math.maxInt(u64), .big); // forge the seq past the bound
    try testing.expect(Tx.decode(&enc) == null);
    // An account one below the top: the next seq is `max_seq`, valid; the
    // saturating arithmetic keeps `expected` in range.
    var s = t.genesis();
    _ = s.accountFor(t.keys[0]);
    s.accounts[s.locateAccount(t.keys[0]).found].seq = Tx.max_seq - 1;
    try testing.expectEqual(Verdict.valid, TestNet.validateNext(&s, &TestNet.set(&.{top})));
    top = t.tx(0, Tx.max_seq - 1, .claim, "top", "", zero_key);
    try testing.expectEqual(Verdict.invalid, TestNet.validateNext(&s, &TestNet.set(&.{top}))); // replay
    TestNet.applyNext(&s, &TestNet.set(&.{t.tx(0, Tx.max_seq, .claim, "top", "", zero_key)}));
    try testing.expectEqual(Tx.max_seq, s.accountSeq(t.keys[0]));
    // Nothing more can ever come from this account (validate says replay
    // or ahead, never valid), and `select` drops it: no overflow anywhere.
    try testing.expectEqual(@as(u8, 0), select(&s, &.{t.tx(0, Tx.max_seq, .set, "top", "v", zero_key)}).count);
}

// Non-vacuity (review A): without the `appliesCleanly` guard, applying a
// set that is valid on a LATER state trips `apply`'s seq assertion — the
// engine thread abort the library's gap-jump used to cause.
test "apply is total: a set from a later state is skipped and the header stays put" {
    const t = TestNet.init();
    var s = t.genesis();
    TestNet.applyNext(&s, &TestNet.set(&.{t.tx(0, 1, .claim, "alice", "", zero_key)}));
    TestNet.applyNext(&s, &TestNet.set(&.{t.tx(0, 2, .set, "alice", "v", zero_key)}));
    const later = TestNet.set(&.{t.tx(0, 3, .set, "alice", "w", zero_key)}); // valid on s (slot 2)
    try testing.expectEqual(Verdict.valid, TestNet.validateNext(&s, &later));
    var stale = t.genesis(); // a node that missed slots 1–2
    try testing.expectEqual(Verdict.invalid, TestNet.validateNext(&stale, &later));
    try testing.expect(!appliesCleanly(&stale, &later));
    TestNet.applyNext(&stale, &later);
    try testing.expectEqual(@as(u64, 0), stale.head.slot);
    try testing.expectEqual(@as(u8, 0), stale.n_accounts);
    try testing.expectEqual(@as(u8, 0), stale.last_count);
    // The right state applies it as usual.
    TestNet.applyNext(&s, &later);
    try testing.expectEqual(@as(u64, 3), s.head.slot);
    try testing.expectEqualStrings("w", s.findName("alice").?.valueSlice());
}

// Non-vacuity: each verdict rule in `validate` is hit once; turning the
// "ahead" branch into `.invalid` fails the maybe case (roadmap §2.1 gap 5).
test "validate: contiguous runs are valid; replay/gap/bad signature invalid; a run starting ahead is maybe_valid; account capacity" {
    const t = TestNet.init();
    var s = t.genesis();
    const a1 = t.tx(0, 1, .claim, "alice", "", zero_key);
    const a2 = t.tx(0, 2, .set, "alice", "v", zero_key);
    const a3 = t.tx(0, 3, .set, "alice", "w", zero_key);
    try testing.expectEqual(Verdict.valid, TestNet.validateNext(&s, &TestNet.set(&.{ a1, a2 })));
    try testing.expectEqual(Verdict.invalid, TestNet.validateNext(&s, &TestNet.set(&.{ a1, a3 }))); // gap inside the run
    try testing.expectEqual(Verdict.invalid, TestNet.validateNext(&s, &TestNet.set(&.{ a2, a3 }))); // immediate successor cannot defer a seq gap
    TestNet.applyNext(&s, &TestNet.set(&.{a1}));
    try testing.expectEqual(Verdict.invalid, TestNet.validateNext(&s, &TestNet.set(&.{a1}))); // replay
    try testing.expectEqual(Verdict.valid, TestNet.validateNext(&s, &TestNet.set(&.{ a2, a3 })));
    var forged = a2;
    forged.value[0] = 'x'; // signed bytes changed; signature stale
    try testing.expectEqual(Verdict.invalid, TestNet.validateNext(&s, &TestNet.set(&.{forged})));

    // Fill the account table: the 65th new source is invalid, a known one fine.
    var full = t.genesis();
    for (0..max_accounts) |i| {
        var k: Key = @splat(0);
        std.mem.writeInt(u64, k[24..32], @intCast(i + 1000), .big);
        _ = full.accountFor(k);
    }
    try testing.expectEqual(@as(u8, max_accounts), full.n_accounts);
    try testing.expectEqual(Verdict.invalid, TestNet.validateNext(&full, &TestNet.set(&.{a1})));
    // A table with room for exactly one more: one new source fine, two not.
    var almost = t.genesis();
    for (0..max_accounts - 1) |i| {
        var k: Key = @splat(0);
        std.mem.writeInt(u64, k[24..32], @intCast(i + 1000), .big);
        _ = almost.accountFor(k);
    }
    const b1 = t.tx(1, 1, .claim, "bob", "", zero_key);
    try testing.expectEqual(Verdict.valid, TestNet.validateNext(&almost, &TestNet.set(&.{a1})));
    const first_is_0 = std.mem.order(u8, &t.keys[0], &t.keys[1]) == .lt;
    const two = if (first_is_0) TestNet.set(&.{ a1, b1 }) else TestNet.set(&.{ b1, a1 });
    try testing.expectEqual(Verdict.invalid, TestNet.validateNext(&almost, &two));
    try testing.expectEqual(@as(u8, 1), select(&almost, two.slice()).count); // combine keeps the first that fits
}

// Non-vacuity: every Result variant is produced; the "seq consumed on
// failure" line is what keeps validate and apply in agreement.
test "apply: operations, results, sequence numbers consumed on failure, header chain" {
    const t = TestNet.init();
    var s = t.genesis();
    const genesis_hash = s.head.hash;

    const claim_a = t.tx(0, 1, .claim, "alice", "", zero_key);
    const claim_b_alice = t.tx(1, 1, .claim, "alice", "", zero_key); // conflict
    const set_b = t.tx(1, 2, .set, "alice", "hi", zero_key); // not the owner
    const first_is_0 = std.mem.order(u8, &t.keys[0], &t.keys[1]) == .lt;
    const set1 = if (first_is_0) TestNet.set(&.{ claim_a, claim_b_alice, set_b }) else TestNet.set(&.{ claim_b_alice, set_b, claim_a });
    try testing.expectEqual(Verdict.valid, TestNet.validateNext(&s, &set1));
    TestNet.applyNext(&s, &set1);
    try testing.expectEqual(@as(u64, 1), s.head.slot);
    try testing.expectEqualSlices(u8, &genesis_hash, &s.head.prev_hash);
    try testing.expectEqual(@as(u64, 1), s.accountSeq(t.keys[0]));
    try testing.expectEqual(@as(u64, 2), s.accountSeq(t.keys[1])); // consumed despite failures
    const winner = if (first_is_0) t.keys[0] else t.keys[1];
    try testing.expectEqualSlices(u8, &winner, &s.findName("alice").?.owner);
    var ok: usize = 0;
    var taken: usize = 0;
    var not_owner: usize = 0;
    for (s.lastResults()) |r| switch (r) {
        .ok => ok += 1,
        .name_taken => taken += 1,
        .not_owner => not_owner += 1,
        else => return error.UnexpectedResult,
    };
    // Set order is source-byte order: when key 0 sorts first, its claim
    // wins and key 1's claim/set fail (name_taken, not_owner); when key 1
    // sorts first, key 1's claim and set both succeed and key 0's claim
    // is name_taken.
    try testing.expectEqual(@as(usize, 1), taken);
    if (first_is_0) {
        try testing.expectEqual(@as(usize, 1), ok);
        try testing.expectEqual(@as(usize, 1), not_owner);
    } else {
        try testing.expectEqual(@as(usize, 2), ok);
        try testing.expectEqual(@as(usize, 0), not_owner);
    }

    const hash1 = s.head.hash;
    // Owner sets, transfers, then the new owner releases; an empty slot too.
    const owner_seed: usize = if (first_is_0) 0 else 1;
    const other: usize = 1 - owner_seed;
    const owner_seq = s.accountSeq(t.keys[owner_seed]) + 1;
    const s2 = TestNet.set(&.{t.tx(owner_seed, owner_seq, .set, "alice", "v1", zero_key)});
    TestNet.applyNext(&s, &s2);
    try testing.expectEqualStrings("v1", s.findName("alice").?.valueSlice());
    const s3 = TestNet.set(&.{t.tx(owner_seed, owner_seq + 1, .transfer, "alice", "", t.keys[other])});
    TestNet.applyNext(&s, &s3);
    try testing.expectEqualSlices(u8, &t.keys[other], &s.findName("alice").?.owner);
    TestNet.applyNext(&s, &TxSet.empty);
    const root_before_empty = s.head.state_root;
    try testing.expectEqualSlices(u8, &root_before_empty, &s.stateRoot()); // empty slot: root unchanged
    const other_seq = s.accountSeq(t.keys[other]) + 1;
    const s5 = TestNet.set(&.{ t.tx(other, other_seq, .release, "alice", "", zero_key), t.tx(other, other_seq + 1, .set, "alice", "x", zero_key) });
    TestNet.applyNext(&s, &s5);
    try testing.expect(s.findName("alice") == null);
    try testing.expectEqual(Result.ok, s.lastResults()[0]);
    try testing.expectEqual(Result.no_such_name, s.lastResults()[1]);
    try testing.expectEqual(@as(u64, 5), s.head.slot);
    try testing.expect(!std.mem.eql(u8, &hash1, &s.head.hash));

    // registry_full: claim names until the table is full.
    var full = t.genesis();
    var seq: u64 = 1;
    for (0..max_names) |i| {
        var name_buf: [8]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "n{d}", .{i}) catch unreachable;
        TestNet.applyNext(&full, &TestNet.set(&.{t.tx(2, seq, .claim, name, "", zero_key)}));
        try testing.expectEqual(Result.ok, full.lastResults()[0]);
        seq += 1;
    }
    TestNet.applyNext(&full, &TestNet.set(&.{t.tx(2, seq, .claim, "one-more", "", zero_key)}));
    try testing.expectEqual(Result.registry_full, full.lastResults()[0]);
    try testing.expectEqual(@as(u8, max_names), full.n_names);
}

test "apply: records the exact last consensus value, including an empty set" {
    const t = TestNet.init();
    var s = t.genesis();
    const set1 = TestNet.set(&.{t.tx(0, 1, .claim, "alice", "", zero_key)});

    TestNet.applyNext(&s, &set1);
    var expected_buf: [max_ledger_value_bytes]u8 = undefined;
    var actual_buf: [max_ledger_value_bytes]u8 = undefined;
    const expected = TestNet.nextValue(&t.genesis(), set1);
    try testing.expectEqualSlices(u8, expected.encode(&expected_buf), s.last_value.?.encode(&actual_buf));

    TestNet.applyNext(&s, &TxSet.empty);
    try testing.expectEqual(@as(u8, 0), s.last_value.?.txs.count);
    try testing.expectEqual(TestNet.genesis_close_time + 2, s.last_value.?.close_time);

    var without_context = s;
    without_context.last_value = null;
    var with_buf: [state_bytes_max]u8 = undefined;
    var without_buf: [state_bytes_max]u8 = undefined;
    try testing.expectEqualSlices(u8, s.serialize(&with_buf), without_context.serialize(&without_buf));
    try testing.expectEqualSlices(u8, &s.stateRoot(), &without_context.stateRoot());
}

// Non-vacuity: two states fed the same sets must serialize identically and
// carry the same head; a different set in the middle must not.
test "determinism: identical histories give identical roots and header hashes" {
    const t = TestNet.init();
    var x = t.genesis();
    var y = t.genesis();
    const s1 = TestNet.set(&.{t.tx(0, 1, .claim, "alice", "", zero_key)});
    const s2 = TestNet.set(&.{t.tx(0, 2, .set, "alice", "v", zero_key)});
    TestNet.applyNext(&x, &s1);
    TestNet.applyNext(&x, &s2);
    TestNet.applyNext(&y, &s1);
    TestNet.applyNext(&y, &s2);
    var bx: [state_bytes_max]u8 = undefined;
    var by: [state_bytes_max]u8 = undefined;
    try testing.expectEqualSlices(u8, x.serialize(&bx), y.serialize(&by));
    try testing.expectEqualSlices(u8, &x.head.hash, &y.head.hash);
    var z = t.genesis();
    TestNet.applyNext(&z, &s1);
    TestNet.applyNext(&z, &TxSet.empty);
    try testing.expect(!std.mem.eql(u8, &z.head.hash, &y.head.hash));
    try testing.expectEqualSlices(u8, &y.head.prev_hash, &z.head.prev_hash); // same slot-1 header
}

// Non-vacuity: removing the dedup tie-break, the contiguity filter or the
// truncation makes one of the expectations fail; the composite must
// self-validate `.valid` (§8.1).
test "combine: union, dedup by (source, seq) keeps the smaller encoding, contiguity per source, cap at max_txs, self-validates" {
    const t = TestNet.init();
    var s = t.genesis();
    const a1 = t.tx(0, 1, .claim, "alice", "", zero_key);
    const a1_alt = t.tx(0, 1, .claim, "alice-alt", "", zero_key); // same (source, seq), other tx
    const a2 = t.tx(0, 2, .set, "alice", "v", zero_key);
    const a4 = t.tx(0, 4, .set, "alice", "w", zero_key); // gap: never selected
    const b3 = t.tx(1, 3, .claim, "bob", "", zero_key); // bob starts ahead: dropped
    const c1 = t.tx(2, 1, .claim, "carol", "", zero_key);

    const next_time = s.head.close_time + 1;
    const cands = [_]LedgerValue{
        .{ .close_time = next_time, .txs = TestNet.set(&.{ a1, a4 }) },
        .{ .close_time = next_time, .txs = TestNet.set(&.{ a1_alt, a2 }) },
        .{ .close_time = next_time, .txs = TestNet.set(&.{b3}) },
        .{ .close_time = next_time, .txs = TestNet.set(&.{c1}) },
    };
    // Candidate order must not matter.
    const merged = combine(&s, &cands);
    const cands_rev = [_]LedgerValue{ cands[3], cands[2], cands[1], cands[0] };
    const merged_rev = combine(&s, &cands_rev);
    var b1: [max_ledger_value_bytes]u8 = undefined;
    var b2: [max_ledger_value_bytes]u8 = undefined;
    try testing.expectEqualSlices(u8, merged.encode(&b1), merged_rev.encode(&b2));
    try testing.expectEqual(@as(u8, 3), merged.txs.count); // a1 or a1_alt, a2, c1
    try testing.expectEqual(Verdict.valid, validate(&s, &merged, s.head.slot + 1));
    var saw_alt = false;
    var saw_a1 = false;
    for (merged.txs.slice()) |*tx| {
        if (std.mem.eql(u8, tx.nameSlice(), "alice-alt")) saw_alt = true;
        if (std.mem.eql(u8, tx.nameSlice(), "alice") and tx.seq == 1) saw_a1 = true;
        try testing.expect(tx.seq != 4 and !std.mem.eql(u8, tx.nameSlice(), "bob"));
    }
    try testing.expect(saw_alt != saw_a1);
    var e1: [tx_bytes]u8 = undefined;
    var e2: [tx_bytes]u8 = undefined;
    a1.encode(&e1);
    a1_alt.encode(&e2);
    try testing.expectEqual(std.mem.order(u8, &e1, &e2) == .lt, saw_a1);

    // Cap: 40 contiguous txs from one source select to 32, still contiguous.
    var many: [40]Tx = undefined;
    for (0..40) |i| many[i] = t.tx(2, @intCast(i + 1), .claim, "carol", "", zero_key);
    const capped = combine(&s, &.{
        LedgerValue{ .close_time = next_time, .txs = TestNet.set(many[0..32]) },
        LedgerValue{ .close_time = next_time, .txs = TestNet.set(many[32..40]) },
    });
    try testing.expectEqual(@as(u8, max_txs), capped.txs.count);
    try testing.expectEqual(Verdict.valid, validate(&s, &capped, s.head.slot + 1));
    apply(&s, &capped);
    try testing.expectEqual(@as(u64, 32), s.accountSeq(t.keys[2]));
    // Now the rest is selectable from the same candidates; the first 32 are replays.
    const rest = combine(&s, &.{
        LedgerValue{ .close_time = s.head.close_time + 1, .txs = TestNet.set(many[0..32]) },
        LedgerValue{ .close_time = s.head.close_time + 1, .txs = TestNet.set(many[32..40]) },
    });
    try testing.expectEqual(@as(u8, 8), rest.txs.count);
    try testing.expectEqual(@as(u64, 33), rest.txs.txs[0].seq);
}

// Non-vacuity: `proposal` must sort and deduplicate a pending queue the RPC
// filled in arrival order.
test "proposal: pending queue in arrival order becomes a sorted, contiguous set" {
    const t = TestNet.init();
    const s = t.genesis();
    var pending = [_]Tx{
        t.tx(0, 2, .set, "alice", "v", zero_key),
        t.tx(1, 1, .claim, "bob", "", zero_key),
        t.tx(0, 1, .claim, "alice", "", zero_key),
        t.tx(0, 1, .claim, "alice", "", zero_key), // duplicate
    };
    const p = proposal(&s, &pending, s.head.close_time + 1).?;
    try testing.expectEqual(@as(u8, 3), p.txs.count);
    try testing.expectEqual(Verdict.valid, validate(&s, &p, s.head.slot + 1));
    var buf: [max_ledger_value_bytes]u8 = undefined;
    try testing.expect(LedgerValue.decode(p.encode(&buf)) != null);
}

// The heartbeat is an idle liveness mechanism, not a second busy cadence.
// If the pending branch were ORed with the heartbeat branch, the third case
// would nominate 4.9 seconds before the configured busy minimum.
test "nomination cadence: pending work observes the busy minimum while only idle work uses the heartbeat" {
    try testing.expect(!nominationDue(true, 99, 100, 10));
    try testing.expect(nominationDue(true, 100, 100, 10));
    try testing.expect(!nominationDue(true, 100, 5_000, 100));
    try testing.expect(!nominationDue(false, 99, 5_000, 100));
    try testing.expect(nominationDue(false, 100, 5_000, 100));
}

// Non-vacuity: flipping any byte of the snapshot (checksum, an entry, the
// recorded root) makes readSnapshot return null.
test "snapshot V3: round-trip; checksum, tampering and a wrong root are refused; results are not persisted" {
    const t = TestNet.init();
    var s = t.genesis();
    TestNet.applyNext(&s, &TestNet.set(&.{t.tx(0, 1, .claim, "alice", "", zero_key)}));
    TestNet.applyNext(&s, &TestNet.set(&.{ t.tx(0, 2, .set, "alice", "v", zero_key), t.tx(0, 3, .claim, "alice", "", zero_key) }));
    try testing.expectEqual(@as(u8, 2), s.last_count);
    var buf: [snapshot_max_bytes]u8 = undefined;
    const snap = writeSnapshot(&s, &buf);
    try testing.expectEqualStrings(snap_magic, snap[0..snap_magic.len]);
    const back = readSnapshot(snap).?;
    try testing.expectEqual(s.head.slot, back.head.slot);
    try testing.expectEqualSlices(u8, &s.head.hash, &back.head.hash);
    try testing.expectEqualSlices(u8, &s.network_id, &back.network_id);
    try testing.expectEqualStrings("v", back.findName("alice").?.valueSlice());
    try testing.expectEqual(@as(u64, 3), back.accountSeq(t.keys[0]));
    try testing.expectEqual(@as(u8, 0), back.last_count);
    var expected_value_buf: [max_ledger_value_bytes]u8 = undefined;
    var actual_value_buf: [max_ledger_value_bytes]u8 = undefined;
    try testing.expectEqualSlices(u8, s.last_value.?.encode(&expected_value_buf), back.last_value.?.encode(&actual_value_buf));
    var bx: [state_bytes_max]u8 = undefined;
    var by: [state_bytes_max]u8 = undefined;
    try testing.expectEqualSlices(u8, s.serialize(&bx), back.serialize(&by));

    var bad = buf;
    bad[snap.len - 1] ^= 1; // checksum
    try testing.expect(readSnapshot(bad[0..snap.len]) == null);
    try testing.expect(readSnapshot(snap[0 .. snap.len - 1]) == null); // short
    // Tamper with an entry AND fix the checksum: the recorded root disagrees.
    var tampered = buf;
    const last_value_len: usize = std.mem.readInt(u16, snap[snapshot_fixed_prefix..][0..2], .big);
    const state_offset = snapshot_fixed_prefix + 2 + last_value_len;
    tampered[state_offset + 1 + 40 + 1 + 66] ^= 1; // first name's first value byte
    const fixed = sha256(tampered[0 .. snap.len - 32]);
    @memcpy(tampered[snap.len - 32 ..][0..32], &fixed);
    try testing.expect(readSnapshot(tampered[0..snap.len]) == null);
    // A lone valid state body with an unrelated header hash is refused too.
    var wrong_head = buf;
    wrong_head[snap_magic.len + 32 + 8 + 8] ^= 1; // head.hash byte
    const fixed2 = sha256(wrong_head[0 .. snap.len - 32]);
    @memcpy(wrong_head[snap.len - 32 ..][0..32], &fixed2);
    try testing.expect(readSnapshot(wrong_head[0..snap.len]) == null);
}

test "snapshot V3: replacing the canonical last value is refused even with a repaired checksum" {
    const t = TestNet.init();
    var s = t.genesis();
    const original = TestNet.set(&.{t.tx(0, 1, .claim, "alice", "", zero_key)});
    TestNet.applyNext(&s, &original);

    var snapshot_buf: [snapshot_max_bytes]u8 = undefined;
    const snapshot = writeSnapshot(&s, &snapshot_buf);
    const value_len: usize = std.mem.readInt(u16, snapshot[snapshot_fixed_prefix..][0..2], .big);
    try testing.expectEqual(@as(usize, value_magic.len + 8 + 1 + tx_bytes), value_len);

    const replacement: LedgerValue = .{
        .close_time = s.head.close_time,
        .txs = TestNet.set(&.{t.tx(0, 1, .claim, "mallory", "", zero_key)}),
    };
    var replacement_buf: [max_ledger_value_bytes]u8 = undefined;
    const replacement_bytes = replacement.encode(&replacement_buf);
    try testing.expectEqual(value_len, replacement_bytes.len);

    var tampered = snapshot_buf;
    @memcpy(tampered[snapshot_fixed_prefix + 2 ..][0..value_len], replacement_bytes);
    const repaired = sha256(tampered[0 .. snapshot.len - 32]);
    @memcpy(tampered[snapshot.len - 32 ..][0..32], &repaired);
    try testing.expect(readSnapshot(tampered[0..snapshot.len]) == null);
}

test "snapshot V3: legacy magic is rejected rather than reinterpreted" {
    const t = TestNet.init();
    var s = t.genesis();
    TestNet.applyNext(&s, &TestNet.set(&.{t.tx(0, 1, .claim, "alice", "", zero_key)}));

    var buf: [snapshot_max_bytes]u8 = undefined;
    const snapshot = writeSnapshot(&s, &buf);
    var legacy = buf;
    @memcpy(legacy[0..snap_magic.len], "REGISTRY-SNAP-V2\n");
    const checksum = sha256(legacy[0 .. snapshot.len - 32]);
    @memcpy(legacy[snapshot.len - 32 ..][0..32], &checksum);
    try testing.expect(readSnapshot(legacy[0..snapshot.len]) == null);
}

test "snapshot V3: canonical real genesis round-trips and forged genesis is refused" {
    const network_id = networkId("snapshot genesis", TestNet.genesis_close_time);
    const genesis = State.genesis(network_id, TestNet.genesis_close_time);
    var buf: [snapshot_max_bytes]u8 = undefined;
    const encoded = writeSnapshot(&genesis, &buf);
    const restored = readSnapshot(encoded).?;
    try testing.expectEqual(@as(u64, 0), restored.head.slot);
    try testing.expectEqualSlices(u8, &network_id, &restored.network_id);
    try testing.expect(!isZero(&restored.head.hash));
    try testing.expectEqual(TestNet.genesis_close_time, restored.head.close_time);
    try testing.expectEqual(@as(u8, 0), restored.n_accounts);
    try testing.expectEqual(@as(u8, 0), restored.n_names);
    try testing.expect(restored.last_value == null);

    var forged = buf;
    const prev_hash_offset = snap_magic.len + 32 + 8 + 8 + 32;
    forged[prev_hash_offset] ^= 1;
    const checksum = sha256(forged[0 .. encoded.len - 32]);
    @memcpy(forged[encoded.len - 32 ..][0..32], &checksum);
    try testing.expect(readSnapshot(forged[0..encoded.len]) == null);
}

// Non-vacuity: the golden bytes pin the header format (tag, field order,
// big-endian slot) and the genesis state root. Change the format on
// purpose only, and change these with it.
test "E2c golden: canonical genesis and the header after one empty ledger" {
    const network_id = networkId("testnet", TestNet.genesis_close_time);
    var s = State.genesis(network_id, TestNet.genesis_close_time);
    const root = std.fmt.bytesToHex(s.head.state_root, .lower);
    // state root of `00 00` (no accounts, no names)
    try testing.expectEqualStrings("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", &root);
    try testing.expect(isZero(&s.head.txset_hash));
    try testing.expectEqualStrings(
        "0ac47307b63113dc84b47d582540229b11198aa5a6175340942f3809479e9474",
        &std.fmt.bytesToHex(s.head.hash, .lower),
    );

    apply(&s, &.{ .close_time = TestNet.genesis_close_time + 1, .txs = .empty });
    const txset = std.fmt.bytesToHex(s.head.txset_hash, .lower);
    const head = std.fmt.bytesToHex(s.head.hash, .lower);
    // txset hash of the single byte `00`
    try testing.expectEqualStrings("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", &txset);
    try testing.expectEqualStrings("15dbc342c6c0942315b5c55422aea3ab62539b699d3cd7f214b97bf0311131c7", &head);
}

test "hex helpers" {
    const k: Key = @splat(0xab);
    const h = hex32(k);
    for (0..32) |i| try testing.expectEqualStrings("ab", h[2 * i ..][0..2]);
    try testing.expectEqualSlices(u8, &k, &parseKey(&h).?);
    try testing.expect(parseKey("zz") == null);
    const not_hex: [64]u8 = @splat('g');
    try testing.expect(parseKey(&not_hex) == null);
}

test "E2c golden: network descriptor and ledger value use disjoint canonical domains" {
    const genesis_close_time: u64 = 1_700_000_000;
    var descriptor_buf: [128]u8 = undefined;
    const descriptor = networkDescriptor(genesis_close_time, "testnet", &descriptor_buf);
    try testing.expectEqual(@as(usize, 30), descriptor.len);
    try testing.expectEqualStrings(
        "52454749535452592d4e45542d5632000000006553f100746573746e6574",
        &std.fmt.bytesToHex(descriptor[0..30].*, .lower),
    );
    const nid = networkId("testnet", genesis_close_time);
    try testing.expectEqualStrings(
        "f43d2c05072db41167a6b75274d123e37df41109114d7ef8793d99b3c96b0bd9",
        &std.fmt.bytesToHex(nid, .lower),
    );

    const value: LedgerValue = .{ .close_time = genesis_close_time + 1, .txs = .empty };
    var value_buf: [max_ledger_value_bytes]u8 = undefined;
    const encoded = value.encode(&value_buf);
    try testing.expectEqual(@as(usize, 27), encoded.len);
    try testing.expectEqualStrings(
        "52454749535452592d56414c55452d56310a000000006553f10100",
        &std.fmt.bytesToHex(encoded[0..27].*, .lower),
    );
    try testing.expectEqualStrings(
        "2910206993ce0098f0ce4d10ea9e3c2138212301d42ee4978d1782d042dfdbe0",
        &std.fmt.bytesToHex(value.hash(), .lower),
    );
    try testing.expect(LedgerValue.decode(encoded) != null);
    try testing.expect(LedgerValue.decode(value.txs.encode(value_buf[0..max_set_bytes])) == null);
    try testing.expect(TxSet.decode(encoded) == null);
}

test "E2c contextual validation enforces the exact slot-derived close-time interval" {
    const t = TestNet.init();
    var state = t.genesis();
    state.head.slot = 10;
    state.head.close_time = 1000;

    const clean = TestNet.set(&.{});
    try testing.expectEqual(Verdict.invalid, validate(&state, &.{ .close_time = 1001, .txs = clean }, 10));
    try testing.expectEqual(Verdict.invalid, validate(&state, &.{ .close_time = 1000, .txs = clean }, 11));
    try testing.expectEqual(Verdict.valid, validate(&state, &.{ .close_time = 1001, .txs = clean }, 11));
    try testing.expectEqual(Verdict.valid, validate(&state, &.{ .close_time = 1060, .txs = clean }, 11));
    try testing.expectEqual(Verdict.invalid, validate(&state, &.{ .close_time = 1061, .txs = clean }, 11));
    try testing.expectEqual(Verdict.invalid, validate(&state, &.{ .close_time = 1002, .txs = clean }, 13));
    try testing.expectEqual(Verdict.maybe_valid, validate(&state, &.{ .close_time = 1003, .txs = clean }, 13));
    try testing.expectEqual(Verdict.maybe_valid, validate(&state, &.{ .close_time = 1180, .txs = clean }, 13));
    try testing.expectEqual(Verdict.invalid, validate(&state, &.{ .close_time = 1181, .txs = clean }, 13));

    const ahead = TestNet.set(&.{t.tx(0, 2, .claim, "ahead", "", zero_key)});
    try testing.expectEqual(Verdict.invalid, validate(&state, &.{ .close_time = 1001, .txs = ahead }, 11));
    try testing.expectEqual(Verdict.maybe_valid, validate(&state, &.{ .close_time = 1003, .txs = ahead }, 13));
    var forged = ahead;
    forged.txs[0].name[0] = 'x';
    try testing.expectEqual(Verdict.invalid, validate(&state, &.{ .close_time = 1003, .txs = forged }, 13));

    var near_end = state;
    near_end.head.close_time = std.math.maxInt(u64) - 5;
    try testing.expectEqual(Verdict.invalid, validate(&near_end, &.{ .close_time = std.math.maxInt(u64) - 5, .txs = clean }, 11));
    try testing.expectEqual(Verdict.valid, validate(&near_end, &.{ .close_time = std.math.maxInt(u64) - 4, .txs = clean }, 11));
    try testing.expectEqual(Verdict.valid, validate(&near_end, &.{ .close_time = std.math.maxInt(u64), .txs = clean }, 11));

    var at_end = state;
    at_end.head.close_time = std.math.maxInt(u64);
    try testing.expectEqual(Verdict.invalid, validate(&at_end, &.{ .close_time = std.math.maxInt(u64), .txs = clean }, 11));
}

test "E2c restored heads remain inside the representable genesis-anchored interval" {
    const genesis: u64 = 1_000;
    try testing.expect(closeTimeAtSlotOk(genesis, 0, 1_000));
    try testing.expect(!closeTimeAtSlotOk(genesis, 0, 1_001));
    try testing.expect(closeTimeAtSlotOk(genesis, 2, 1_002));
    try testing.expect(closeTimeAtSlotOk(genesis, 2, 1_120));
    try testing.expect(!closeTimeAtSlotOk(genesis, 2, 1_001));
    try testing.expect(!closeTimeAtSlotOk(genesis, 2, 1_121));

    const near_max = std.math.maxInt(u64) - 1;
    try testing.expect(closeTimeAtSlotOk(near_max, 1, std.math.maxInt(u64)));
    try testing.expect(!closeTimeAtSlotOk(near_max, 2, std.math.maxInt(u64)));
}

test "E2c proposal clamps wall time and combination chooses the minimum candidate time" {
    const t = TestNet.init();
    const state = t.genesis();
    const pending = [_]Tx{
        t.tx(0, 2, .set, "alice", "v", zero_key),
        t.tx(0, 1, .claim, "alice", "", zero_key),
    };
    const original_pending = pending;
    const low = proposal(&state, &pending, 1_699_999_900).?;
    const inside = proposal(&state, &.{}, 1_700_000_025).?;
    const high = proposal(&state, &.{}, 1_700_009_999).?;
    try testing.expectEqual(@as(u64, 1_700_000_001), low.close_time);
    try testing.expectEqual(@as(u64, 1_700_000_025), inside.close_time);
    try testing.expectEqual(@as(u64, 1_700_000_060), high.close_time);
    try testing.expect(std.meta.eql(original_pending, pending));

    const combined = combine(&state, &.{
        LedgerValue{ .close_time = 5, .txs = .empty },
        LedgerValue{ .close_time = 2, .txs = .empty },
        LedgerValue{ .close_time = 4, .txs = .empty },
    });
    try testing.expectEqual(@as(u64, 2), combined.close_time);
    const permuted = combine(&state, &.{
        LedgerValue{ .close_time = 4, .txs = .empty },
        LedgerValue{ .close_time = 5, .txs = .empty },
        LedgerValue{ .close_time = 2, .txs = .empty },
    });
    try testing.expectEqualSlices(u8, &combined.hash(), &permuted.hash());

    var at_end = state;
    at_end.head.close_time = std.math.maxInt(u64);
    try testing.expect(proposal(&at_end, &.{}, 0) == null);

    var near_end = state;
    near_end.head.close_time = std.math.maxInt(u64) - 5;
    try testing.expectEqual(std.math.maxInt(u64), proposal(&near_end, &.{}, std.math.maxInt(u64)).?.close_time);
}

test "E2c apply is a no-op unless value is an exact clean close-time successor" {
    const t = TestNet.init();
    const genesis = t.genesis();
    const clean = TxSet.empty;

    var stale_time = genesis;
    apply(&stale_time, &.{ .close_time = genesis.head.close_time, .txs = clean });
    try testing.expect(std.meta.eql(genesis, stale_time));

    var far_time = genesis;
    apply(&far_time, &.{ .close_time = genesis.head.close_time + max_close_time_step + 1, .txs = clean });
    try testing.expect(std.meta.eql(genesis, far_time));

    var seq_gap = genesis;
    apply(&seq_gap, &.{
        .close_time = genesis.head.close_time + 1,
        .txs = TestNet.set(&.{t.tx(0, 2, .claim, "ahead", "", zero_key)}),
    });
    try testing.expect(std.meta.eql(genesis, seq_gap));

    var exhausted_slot = genesis;
    exhausted_slot.head.slot = std.math.maxInt(u64);
    const before_hash = exhausted_slot.head.hash;
    apply(&exhausted_slot, &.{ .close_time = genesis.head.close_time + 1, .txs = clean });
    try testing.expectEqual(std.math.maxInt(u64), exhausted_slot.head.slot);
    try testing.expectEqualSlices(u8, &before_hash, &exhausted_slot.head.hash);
    try testing.expect(exhausted_slot.last_value == null);

    var applied = genesis;
    apply(&applied, &.{ .close_time = genesis.head.close_time + max_close_time_step, .txs = clean });
    try testing.expectEqual(@as(u64, 1), applied.head.slot);
    try testing.expectEqual(genesis.head.close_time + max_close_time_step, applied.head.close_time);
    try testing.expectEqual(applied.head.close_time, applied.last_value.?.close_time);
}

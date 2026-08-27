//! Crash-safe persistence (design §10). Byte-identical file formats in both
//! languages (shared fixtures test cross-language identity later).
//!
//!   slcp-data/
//!     own.log            append-only: (u64 slot, u32 len, envelope bytes,
//!                        u32 crc32); fsync'd. The write-ahead record.
//!     externalized.log   append-only: (u64 slot, u32 len, value, u32 crc32);
//!                        fsync'd. App journal AND crash-fallback slot bound.
//!     qsets/<hex64>.bin  verified foreign qset cache (best-effort, no fsync).
//!
//! Record framing (both logs): little-endian u64 slot, little-endian u32
//! payload length, `len` payload bytes, little-endian u32 crc32 (IEEE, over
//! slot ++ len ++ payload). A torn tail (short read / bad crc at the end) is
//! recoverable: everything up to the first bad record is a valid prefix.
//!
//! ==== IMPLEMENTATION BRIEF (M5 agent) ====================================
//! Public interface below is FROZEN — implement bodies + tests, do not change
//! signatures/field names/record layout. File I/O uses this Zig version's
//! `std.Io` API (see tools/gen_vectors.zig and tests/*/*.zig for the shape:
//! `std.Io.Dir.cwd().createFile(io, path, .{})`, `readFileAlloc`, `access`,
//! `makePath`). Discover the fsync call on the file handle (data-sync).
//!
//!   * open: makePath(data_dir), makePath(data_dir/qsets). Open/create both
//!     logs for append. Keep the Dir + open file handles.
//!   * appendOwn / appendExternalized: encode one record, write, fsync. These
//!     are on the write-ahead path — fsync MUST complete before return (§10:
//!     persist strictly precedes broadcast; the Node relies on that).
//!   * putQset: write qsets/<hex of hash>.bin (best-effort; swallow errors,
//!     log). getQset: read it back if present (caller frees), else null.
//!   * recover(): read both logs.
//!       - own.log: parse records front-to-back. On the FIRST bad/short
//!         record, stop and set `own_log_corrupt = (that record is not simply
//!         EOF)` — i.e. a crc mismatch or truncated-mid-record tail means the
//!         whole own.log is untrusted (§10 corrupt-log fallback). A clean EOF
//!         on a record boundary is NOT corrupt. Dedup the valid records to
//!         the LAST record per (slot, protocol-kind) — protocol-kind is the
//!         pledge union tag of the statement inside the envelope (nominate /
//!         prepare / confirm / externalize), parsed via core.gen.slcp. Return
//!         them in ascending (slot, then kind) order — deterministic.
//!       - externalized.log: parse records; `externalized_hwm` = the highest
//!         slot in any valid record (null if none). A torn tail still yields
//!         the valid prefix's high-water mark.
//!   * deinitRecovery frees everything recover() allocated.
//!   * Tests (use std.testing.tmpDir): round-trip append→recover; last-wins
//!     dedup across two prepares for one slot; a hand-corrupted own.log tail
//!     byte sets own_log_corrupt AND still yields externalized_hwm from the
//!     intact externalized.log; qset put/get round-trip; crc rejects a
//!     flipped payload byte. To build valid envelope bytes for tests, use
//!     core.emit or hand-build via core.gen.slcp (see src/engine/emit.zig).
//! ========================================================================

const std = @import("std");
const core = @import("slcp-core");

const Crc32 = std.hash.Crc32;

pub const Error = error{ BadRecord, IoFailed } || std.mem.Allocator.Error;

const own_log_name = "own.log";
const ext_log_name = "externalized.log";
const qsets_dir_name = "qsets";
/// "qsets/" ++ 64 hex chars ++ ".bin".
const qset_path_len = qsets_dir_name.len + 1 + 64 + 4;

/// Record framing overhead: u64 slot + u32 len (header) + u32 crc (trailer).
const rec_header_len = 8 + 4;
const rec_crc_len = 4;

/// Two dedup buckets per slot: a nomination, and the ballot family
/// (prepare / confirm / externalize) — §10. `nom` sorts before `ballot`.
const Kind = enum(u2) { nom = 0, ballot = 1 };

/// One recovered own-statement: a standalone framed Envelope.
pub const OwnRecord = struct {
    slot: u64,
    /// Framed Envelope message bytes (owned by the Recovery).
    envelope: []u8,
};

pub const Recovery = struct {
    /// Latest own envelope per (slot, protocol), ascending. Replay these as
    /// `restore_own_envelope` inputs BEFORE any other input (§10).
    own_latest: []OwnRecord,
    /// Highest externalized slot on disk, or null if none.
    externalized_hwm: ?u64,
    /// own.log failed integrity → the Node must fall back to watcher mode
    /// for slots ≤ max(peer_high, externalized_hwm + 1) (§10).
    own_log_corrupt: bool,
};

pub const Store = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// Handle to the data directory; qset files and log reads resolve against it.
    dir: std.Io.Dir,
    /// Append handles for the two write-ahead logs (write-only, kept open).
    own_file: std.Io.File,
    ext_file: std.Io.File,
    /// Owned copy of the data-dir path (diagnostics only).
    data_dir: []u8,

    /// Open (creating if needed) the data dir and both logs.
    pub fn open(gpa: std.mem.Allocator, io: std.Io, data_dir: []const u8) !Store {
        const dir = std.Io.Dir.cwd().createDirPathOpen(io, data_dir, .{}) catch
            return Error.IoFailed;
        errdefer dir.close(io);

        dir.createDirPath(io, qsets_dir_name) catch return Error.IoFailed;

        // truncate=false: preserve an existing log across a restart (recovery).
        const own_file = dir.createFile(io, own_log_name, .{ .truncate = false }) catch
            return Error.IoFailed;
        errdefer own_file.close(io);
        const ext_file = dir.createFile(io, ext_log_name, .{ .truncate = false }) catch
            return Error.IoFailed;
        errdefer ext_file.close(io);

        const dd = try gpa.dupe(u8, data_dir);

        return .{
            .gpa = gpa,
            .io = io,
            .dir = dir,
            .own_file = own_file,
            .ext_file = ext_file,
            .data_dir = dd,
        };
    }

    pub fn deinit(self: *Store) void {
        self.own_file.close(self.io);
        self.ext_file.close(self.io);
        self.dir.close(self.io);
        self.gpa.free(self.data_dir);
        self.* = undefined;
    }

    /// Append + fsync one own-envelope record (write-ahead; §10).
    pub fn appendOwn(self: *Store, slot: u64, framed_envelope: []const u8) !void {
        return self.appendRecord(self.own_file, slot, framed_envelope);
    }

    /// Append + fsync one externalized-value record.
    pub fn appendExternalized(self: *Store, slot: u64, value: []const u8) !void {
        return self.appendRecord(self.ext_file, slot, value);
    }

    /// Encode one framed record, append it at end-of-file, flush, and data-sync
    /// before returning. fsync completing before return is the write-ahead
    /// durability guarantee the Node relies on (§10: persist precedes broadcast).
    fn appendRecord(self: *Store, file: std.Io.File, slot: u64, payload: []const u8) Error!void {
        const total = rec_header_len + payload.len + rec_crc_len;
        const rec = try self.gpa.alloc(u8, total);
        defer self.gpa.free(rec);

        std.mem.writeInt(u64, rec[0..8], slot, .little);
        std.mem.writeInt(u32, rec[8..12], @intCast(payload.len), .little);
        @memcpy(rec[rec_header_len..][0..payload.len], payload);
        const crc = Crc32.hash(rec[0 .. rec_header_len + payload.len]);
        std.mem.writeInt(u32, rec[rec_header_len + payload.len ..][0..4], crc, .little);

        // Positional append: write at the current end, so a kept-open handle
        // never depends on a global seek position.
        const end = file.length(self.io) catch return Error.IoFailed;
        var buf: [4096]u8 = undefined;
        var w = file.writer(self.io, &buf);
        w.pos = end;
        w.interface.writeAll(rec) catch return Error.IoFailed;
        w.interface.flush() catch return Error.IoFailed;
        file.sync(self.io) catch return Error.IoFailed;
    }

    /// Best-effort write of a verified foreign qset (no fsync).
    pub fn putQset(self: *Store, hash: [32]u8, framed_qset: []const u8) void {
        var path_buf: [qset_path_len]u8 = undefined;
        const path = qsetPath(hash, &path_buf);
        var file = self.dir.createFile(self.io, path, .{}) catch |err| {
            std.log.warn("store: putQset create failed: {s}", .{@errorName(err)});
            return;
        };
        defer file.close(self.io);
        file.writeStreamingAll(self.io, framed_qset) catch |err|
            std.log.warn("store: putQset write failed: {s}", .{@errorName(err)});
    }

    /// Read a cached qset by hash (caller frees), or null.
    pub fn getQset(self: *Store, gpa: std.mem.Allocator, hash: [32]u8) !?[]u8 {
        var path_buf: [qset_path_len]u8 = undefined;
        const path = qsetPath(hash, &path_buf);
        return self.dir.readFileAlloc(self.io, path, gpa, .unlimited) catch |err| switch (err) {
            error.FileNotFound => null,
            error.OutOfMemory => Error.OutOfMemory,
            else => Error.IoFailed,
        };
    }

    /// Read both logs and compute the restart plan (§10).
    pub fn recover(self: *Store, gpa: std.mem.Allocator) !Recovery {
        const own_data = self.dir.readFileAlloc(self.io, own_log_name, gpa, .unlimited) catch |err| switch (err) {
            error.OutOfMemory => return Error.OutOfMemory,
            else => return Error.IoFailed,
        };
        defer gpa.free(own_data);

        const own_latest, const own_corrupt = try recoverOwn(gpa, own_data);
        errdefer {
            for (own_latest) |r| gpa.free(r.envelope);
            gpa.free(own_latest);
        }

        const ext_data = self.dir.readFileAlloc(self.io, ext_log_name, gpa, .unlimited) catch |err| switch (err) {
            error.OutOfMemory => return Error.OutOfMemory,
            else => return Error.IoFailed,
        };
        defer gpa.free(ext_data);

        var ext_iter = RecordIter{ .data = ext_data };
        var hwm: ?u64 = null;
        while (ext_iter.next()) |item| {
            if (hwm == null or item.slot > hwm.?) hwm = item.slot;
        }

        return .{
            .own_latest = own_latest,
            .externalized_hwm = hwm,
            .own_log_corrupt = own_corrupt,
        };
    }

    /// Parse own.log's valid prefix, dedup to the last record per (slot, kind),
    /// and return them ascending by (slot, then kind). The bool is
    /// `own_log_corrupt`: true when parsing stopped on a bad/short record rather
    /// than a clean record-boundary EOF.
    fn recoverOwn(gpa: std.mem.Allocator, data: []const u8) Error!struct { []OwnRecord, bool } {
        const Entry = struct { slot: u64, kind: Kind, payload: []const u8 };
        const Key = struct { slot: u64, kind: Kind };

        var entries: std.ArrayList(Entry) = .empty;
        defer entries.deinit(gpa);
        var index = std.AutoHashMap(Key, usize).init(gpa);
        defer index.deinit();

        var iter = RecordIter{ .data = data };
        while (iter.next()) |item| {
            const kind = classifyKind(gpa, item.payload) catch |err| switch (err) {
                error.OutOfMemory => return Error.OutOfMemory,
                // A crc-valid record we can't parse to a pledge is not something
                // we ever write; skip it defensively rather than crash recovery.
                else => continue,
            };
            const key = Key{ .slot = item.slot, .kind = kind };
            const entry = Entry{ .slot = item.slot, .kind = kind, .payload = item.payload };
            if (index.get(key)) |idx| {
                entries.items[idx] = entry; // last record wins
            } else {
                try entries.append(gpa, entry);
                try index.put(key, entries.items.len - 1);
            }
        }

        std.mem.sort(Entry, entries.items, {}, struct {
            fn lessThan(_: void, a: Entry, b: Entry) bool {
                if (a.slot != b.slot) return a.slot < b.slot;
                return @intFromEnum(a.kind) < @intFromEnum(b.kind);
            }
        }.lessThan);

        const own_latest = try gpa.alloc(OwnRecord, entries.items.len);
        var built: usize = 0;
        errdefer {
            for (own_latest[0..built]) |r| gpa.free(r.envelope);
            gpa.free(own_latest);
        }
        for (entries.items) |e| {
            own_latest[built] = .{ .slot = e.slot, .envelope = try gpa.dupe(u8, e.payload) };
            built += 1;
        }

        return .{ own_latest, !iter.clean };
    }

    pub fn deinitRecovery(gpa: std.mem.Allocator, rec: *Recovery) void {
        for (rec.own_latest) |r| gpa.free(r.envelope);
        gpa.free(rec.own_latest);
        rec.* = undefined;
    }
};

/// Front-to-back reader over a log's framed records. `clean` starts true and is
/// cleared the moment a truncated-mid-record tail or a crc mismatch stops the
/// walk; a run of the iterator to `null` at an exact record boundary leaves it
/// true (clean EOF).
const RecordIter = struct {
    data: []const u8,
    pos: usize = 0,
    clean: bool = true,

    const Item = struct { slot: u64, payload: []const u8 };

    fn next(self: *RecordIter) ?Item {
        const data = self.data;
        const i = self.pos;
        if (i >= data.len) return null; // clean boundary EOF
        if (data.len - i < rec_header_len) {
            self.clean = false; // truncated header
            return null;
        }
        const slot = std.mem.readInt(u64, data[i..][0..8], .little);
        const len = std.mem.readInt(u32, data[i + 8 ..][0..4], .little);
        if (len > data.len) {
            self.clean = false;
            return null;
        }
        const payload_start = i + rec_header_len;
        const crc_start = payload_start + len;
        const rec_end = crc_start + rec_crc_len;
        if (rec_end > data.len) {
            self.clean = false; // truncated payload / crc
            return null;
        }
        const stored_crc = std.mem.readInt(u32, data[crc_start..][0..4], .little);
        const calc_crc = Crc32.hash(data[i..crc_start]); // slot ++ len ++ payload
        if (calc_crc != stored_crc) {
            self.clean = false; // corrupt record
            return null;
        }
        self.pos = rec_end;
        return .{ .slot = slot, .payload = data[payload_start..crc_start] };
    }
};

/// The protocol-kind dedup bucket of a framed own envelope: `.nom` for a
/// nomination, `.ballot` for prepare/confirm/externalize (§10). Borrows nothing
/// past the call.
fn classifyKind(gpa: std.mem.Allocator, framed_envelope: []const u8) !Kind {
    var env_msg = try core.capnpc.message.Message.init(gpa, framed_envelope, .{});
    defer env_msg.deinit();
    const env = try core.gen.slcp.Envelope.Reader.init(&env_msg);
    const stmt_bytes = try env.getStatementBytes();

    var stmt_msg = try core.canonical.decodeFlat(gpa, stmt_bytes, .{});
    defer stmt_msg.deinit();
    const stmt = try core.gen.slcp.Statement.Reader.init(&stmt_msg);

    return switch (try stmt.getPledges().which()) {
        .nominate => .nom,
        .prepare, .confirm, .externalize => .ballot,
        .unset => Error.BadRecord,
    };
}

/// Render "qsets/<hex64>.bin" for `hash` into `buf`, returning the full path.
fn qsetPath(hash: [32]u8, buf: *[qset_path_len]u8) []const u8 {
    const hex = "0123456789abcdef";
    @memcpy(buf[0..qsets_dir_name.len], qsets_dir_name);
    buf[qsets_dir_name.len] = '/';
    const off = qsets_dir_name.len + 1;
    for (hash, 0..) |b, i| {
        buf[off + i * 2] = hex[b >> 4];
        buf[off + i * 2 + 1] = hex[b & 0x0f];
    }
    @memcpy(buf[off + 64 ..][0..4], ".bin");
    return buf[0..qset_path_len];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const TestPledge = enum { nominate, prepare };

/// Build valid framed Envelope bytes (mirrors src/engine/emit.zig's build →
/// canonicalize → frame path). `marker` distinguishes otherwise-identical
/// statements so last-wins dedup is observable. Caller frees.
fn buildTestEnvelope(gpa: std.mem.Allocator, slot: u64, pledge: TestPledge, marker: u8) ![]const u8 {
    var mb = core.capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try core.gen.slcp.Statement.Builder.init(&mb);
    const node_id: [32]u8 = @splat(0xab);
    try st.setNodeId(&node_id);
    try st.setSlotIndex(slot);
    var pledges = st.getPledges();
    const value = [_]u8{marker};
    switch (pledge) {
        .nominate => {
            var nom = try pledges.initNominate();
            const qsh: [32]u8 = @splat(0x11);
            try nom.setQuorumSetHash(&qsh);
            const votes = try nom.initVotes(1);
            try votes.set(0, &value);
        },
        .prepare => {
            var prep = try pledges.initPrepare();
            const qsh: [32]u8 = @splat(0x22);
            try prep.setQuorumSetHash(&qsh);
            var ballot = try prep.initBallot();
            try ballot.setCounter(1);
            try ballot.setValue(&value);
            try prep.setNC(0);
            try prep.setNH(0);
        },
    }
    const statement_bytes = try core.canonical.canonicalFlatFromBuilder(gpa, &mb);
    defer gpa.free(statement_bytes);

    var emb = core.capnpc.message.MessageBuilder.init(gpa);
    defer emb.deinit();
    var env = try core.gen.slcp.Envelope.Builder.init(&emb);
    try env.setStatementBytes(statement_bytes);
    const sig: [64]u8 = @splat(0x33);
    try env.setSignature(&sig);
    return emb.toBytes();
}

/// Data-dir path inside a testing tmpDir (cwd-relative, cleaned by the tmpDir).
fn tmpDataDir(tmp: *std.testing.TmpDir, buf: []u8) ![]const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}/data", .{tmp.sub_path});
}

test "store: append then recover round-trips across reopen" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const env = try buildTestEnvelope(gpa, 5, .nominate, 0x01);
    defer gpa.free(env);

    {
        var store = try Store.open(gpa, io, data_dir);
        defer store.deinit();
        try store.appendOwn(5, env);
        try store.appendExternalized(3, "value-a");
        try store.appendExternalized(7, "value-b");
    }

    // Reopen (simulated restart) and recover.
    var store = try Store.open(gpa, io, data_dir);
    defer store.deinit();
    var rec = try store.recover(gpa);
    defer Store.deinitRecovery(gpa, &rec);

    try testing.expect(!rec.own_log_corrupt);
    try testing.expectEqual(@as(usize, 1), rec.own_latest.len);
    try testing.expectEqual(@as(u64, 5), rec.own_latest[0].slot);
    try testing.expectEqualSlices(u8, env, rec.own_latest[0].envelope);
    try testing.expectEqual(@as(?u64, 7), rec.externalized_hwm);
}

test "store: last-wins dedup for two prepares in one slot (ballot bucket)" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const prep_a = try buildTestEnvelope(gpa, 4, .prepare, 0xa1);
    defer gpa.free(prep_a);
    const prep_b = try buildTestEnvelope(gpa, 4, .prepare, 0xb2);
    defer gpa.free(prep_b);
    try testing.expect(!std.mem.eql(u8, prep_a, prep_b)); // distinct on-disk bytes

    var store = try Store.open(gpa, io, data_dir);
    defer store.deinit();
    try store.appendOwn(4, prep_a);
    try store.appendOwn(4, prep_b);

    var rec = try store.recover(gpa);
    defer Store.deinitRecovery(gpa, &rec);

    try testing.expect(!rec.own_log_corrupt);
    try testing.expectEqual(@as(usize, 1), rec.own_latest.len);
    try testing.expectEqual(@as(u64, 4), rec.own_latest[0].slot);
    try testing.expectEqualSlices(u8, prep_b, rec.own_latest[0].envelope); // last wins
}

test "store: nominate + prepare in one slot yield two ordered records" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const nom = try buildTestEnvelope(gpa, 9, .nominate, 0x01);
    defer gpa.free(nom);
    const prep = try buildTestEnvelope(gpa, 9, .prepare, 0x02);
    defer gpa.free(prep);

    var store = try Store.open(gpa, io, data_dir);
    defer store.deinit();
    // Append prepare first to prove ordering is by (slot, kind), not arrival.
    try store.appendOwn(9, prep);
    try store.appendOwn(9, nom);

    var rec = try store.recover(gpa);
    defer Store.deinitRecovery(gpa, &rec);

    try testing.expect(!rec.own_log_corrupt);
    try testing.expectEqual(@as(usize, 2), rec.own_latest.len);
    // nom (kind 0) sorts before ballot (kind 1)
    try testing.expectEqual(@as(u64, 9), rec.own_latest[0].slot);
    try testing.expectEqualSlices(u8, nom, rec.own_latest[0].envelope);
    try testing.expectEqual(@as(u64, 9), rec.own_latest[1].slot);
    try testing.expectEqualSlices(u8, prep, rec.own_latest[1].envelope);
}

test "store: corrupted own.log tail sets own_log_corrupt but keeps externalized hwm" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const env_a = try buildTestEnvelope(gpa, 1, .nominate, 0x01);
    defer gpa.free(env_a);
    const env_b = try buildTestEnvelope(gpa, 2, .prepare, 0x02);
    defer gpa.free(env_b);

    {
        var store = try Store.open(gpa, io, data_dir);
        defer store.deinit();
        try store.appendOwn(1, env_a);
        try store.appendOwn(2, env_b);
        try store.appendExternalized(10, "ext-a");
        try store.appendExternalized(42, "ext-b");
    }

    // Flip the final byte of own.log (part of the last record's crc trailer).
    // NOTE: own_path gets its own buffer — reusing path_buf would clobber data_dir.
    var op_buf: [128]u8 = undefined;
    const own_path = try std.fmt.bufPrint(&op_buf, "data/{s}", .{own_log_name});
    const bytes = try tmp.dir.readFileAlloc(io, own_path, gpa, .unlimited);
    defer gpa.free(bytes);
    bytes[bytes.len - 1] ^= 0xff;
    var f = try tmp.dir.createFile(io, own_path, .{});
    try f.writeStreamingAll(io, bytes);
    f.close(io);

    var store = try Store.open(gpa, io, data_dir);
    defer store.deinit();
    var rec = try store.recover(gpa);
    defer Store.deinitRecovery(gpa, &rec);

    try testing.expect(rec.own_log_corrupt);
    // The intact prefix (record 1) still recovers.
    try testing.expectEqual(@as(usize, 1), rec.own_latest.len);
    try testing.expectEqual(@as(u64, 1), rec.own_latest[0].slot);
    try testing.expectEqualSlices(u8, env_a, rec.own_latest[0].envelope);
    // externalized.log is untouched → its hwm survives.
    try testing.expectEqual(@as(?u64, 42), rec.externalized_hwm);
}

test "store: truncated mid-record own.log tail is a recoverable prefix" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const env_a = try buildTestEnvelope(gpa, 1, .nominate, 0x01);
    defer gpa.free(env_a);
    const env_b = try buildTestEnvelope(gpa, 2, .prepare, 0x02);
    defer gpa.free(env_b);

    {
        var store = try Store.open(gpa, io, data_dir);
        defer store.deinit();
        try store.appendOwn(1, env_a);
        try store.appendOwn(2, env_b);
    }

    // Cut the file a few bytes into record 2's header (record 1 is
    // rec_header_len + env_a.len + rec_crc_len bytes).
    const rec1_end = rec_header_len + env_a.len + rec_crc_len;
    var op_buf: [128]u8 = undefined;
    const own_path = try std.fmt.bufPrint(&op_buf, "data/{s}", .{own_log_name});
    const bytes = try tmp.dir.readFileAlloc(io, own_path, gpa, .unlimited);
    defer gpa.free(bytes);
    const truncated = bytes[0 .. rec1_end + 5];
    var f = try tmp.dir.createFile(io, own_path, .{});
    try f.writeStreamingAll(io, truncated);
    f.close(io);

    var store = try Store.open(gpa, io, data_dir);
    defer store.deinit();
    var rec = try store.recover(gpa);
    defer Store.deinitRecovery(gpa, &rec);

    try testing.expect(rec.own_log_corrupt); // torn tail → untrusted (§10)
    try testing.expectEqual(@as(usize, 1), rec.own_latest.len);
    try testing.expectEqual(@as(u64, 1), rec.own_latest[0].slot);
    try testing.expectEqualSlices(u8, env_a, rec.own_latest[0].envelope);
}

test "store: crc rejects a flipped payload byte" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const env = try buildTestEnvelope(gpa, 1, .nominate, 0x01);
    defer gpa.free(env);

    {
        var store = try Store.open(gpa, io, data_dir);
        defer store.deinit();
        try store.appendOwn(1, env);
    }

    // Flip a byte in the payload region (past the 12-byte header, before crc).
    var op_buf: [128]u8 = undefined;
    const own_path = try std.fmt.bufPrint(&op_buf, "data/{s}", .{own_log_name});
    const bytes = try tmp.dir.readFileAlloc(io, own_path, gpa, .unlimited);
    defer gpa.free(bytes);
    bytes[rec_header_len] ^= 0xff;
    var f = try tmp.dir.createFile(io, own_path, .{});
    try f.writeStreamingAll(io, bytes);
    f.close(io);

    var store = try Store.open(gpa, io, data_dir);
    defer store.deinit();
    var rec = try store.recover(gpa);
    defer Store.deinitRecovery(gpa, &rec);

    // The single record fails crc → nothing recovered, log flagged corrupt.
    try testing.expect(rec.own_log_corrupt);
    try testing.expectEqual(@as(usize, 0), rec.own_latest.len);
}

test "store: qset put/get round-trips and absent returns null" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    var store = try Store.open(gpa, io, data_dir);
    defer store.deinit();

    const hash: [32]u8 = @splat(0x5c);
    const payload = "framed-qset-bytes";
    store.putQset(hash, payload);

    const got = try store.getQset(gpa, hash);
    try testing.expect(got != null);
    defer gpa.free(got.?);
    try testing.expectEqualSlices(u8, payload, got.?);

    const absent: [32]u8 = @splat(0xff);
    try testing.expectEqual(@as(?[]u8, null), try store.getQset(gpa, absent));
}

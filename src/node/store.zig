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
//! slot ++ len ++ payload). Recovery distinguishes two failure shapes:
//!
//!   * TORN TAIL — the file physically ends mid-record (short header, or the
//!     declared payload+crc extends past EOF). This is the routine power-loss
//!     artifact: §10's persist-precedes-broadcast means a torn final record
//!     was never broadcast, so the valid prefix is fully trustworthy. Not
//!     corruption. `recover()` truncates the log back to the prefix.
//!   * TRUE CORRUPTION — a structurally complete record (full header +
//!     payload + crc present) whose crc mismatches. The log is untrusted;
//!     for own.log the §10 corrupt-log fallback applies. The log is still
//!     truncated to the prefix before the bad record so later appends do not
//!     land behind unreachable garbage.
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
//!       - own.log: parse records front-to-back. On the FIRST bad record,
//!         stop and classify it: a torn tail (file ends mid-record) is safe
//!         and only sets `torn_tail_repaired`; a structurally complete record
//!         with a crc mismatch sets `own_log_corrupt` (§10 corrupt-log
//!         fallback). Either way the log file is truncated back to its valid
//!         prefix. A clean EOF on a record boundary sets neither. Dedup the
//!         valid records to the LAST record per (slot, protocol-kind) —
//!         protocol-kind is the pledge union tag of the statement inside the
//!         envelope (nominate / prepare / confirm / externalize), parsed via
//!         core.gen.slcp. Return them in ascending (slot, then kind) order —
//!         deterministic.
//!       - externalized.log: parse records; `externalized_hwm` = the highest
//!         slot in any valid record (null if none). A bad tail still yields
//!         the valid prefix's high-water mark, and the file is likewise
//!         truncated to that prefix (a torn tail sets `torn_tail_repaired`).
//!   * compact(keep_from_slot): atomically rewrite both logs keeping only
//!     records with slot >= keep_from_slot (§10's 16-slot answering window).
//!     Temp file + fsync + rename-over — crash-safe at every point.
//!   * deinitRecovery frees everything recover() allocated.
//!   * Tests (use std.testing.tmpDir): round-trip append→recover; last-wins
//!     dedup across two prepares for one slot; a hand-corrupted own.log tail
//!     byte sets own_log_corrupt AND still yields externalized_hwm from the
//!     intact externalized.log; qset put/get round-trip; crc rejects a
//!     flipped payload byte. To build valid envelope bytes for tests, use
//!     core.emit or hand-build via core.gen.slcp (see src/engine/emit.zig).
//! ========================================================================

const std = @import("std");
const builtin = @import("builtin");
const core = @import("slcp-core");

const Crc32 = std.hash.Crc32;

pub const Error = error{ BadRecord, IoFailed } || std.mem.Allocator.Error;

const own_log_name = "own.log";
const ext_log_name = "externalized.log";
/// Scratch names compact() writes before the atomic rename-over. A leftover
/// (from a crash mid-compact) is harmless: the real names always hold a
/// complete log, and the next compact truncates the scratch file.
const own_tmp_name = "own.log.compact";
const ext_tmp_name = "externalized.log.compact";
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

/// One recovered externalized value from the journal.
pub const ExtRecord = struct {
    slot: u64,
    /// Owned by the Recovery.
    value: []u8,
};

pub const Recovery = struct {
    /// Latest own envelope per (slot, protocol), ascending. Replay these as
    /// `restore_own_envelope` inputs BEFORE any other input (§10).
    own_latest: []OwnRecord,
    /// Highest externalized slot on disk, or null if none.
    externalized_hwm: ?u64,
    /// The valid journal records, deduped last-wins per slot, ascending by
    /// slot (bounded by compaction). §10: externalized.log is the
    /// app-visible journal — the Node replays this tail into the app stream
    /// after a restart (the app dedups by slot), so a crash between journal
    /// append and app consumption never silently loses a value.
    ext_tail: []ExtRecord,
    /// A structurally complete own.log record failed its crc — the log is
    /// untrusted; the §10 fallback applies.
    own_log_corrupt: bool,
    /// recover() found a torn final append (file ends mid-record) in either
    /// log and TRUNCATED that log back to its valid prefix. Informational.
    torn_tail_repaired: bool,
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
        // read=true: compact() re-reads each log through its open handle.
        const own_file = dir.createFile(io, own_log_name, .{ .truncate = false, .read = true }) catch
            return Error.IoFailed;
        errdefer own_file.close(io);
        const ext_file = dir.createFile(io, ext_log_name, .{ .truncate = false, .read = true }) catch
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
        try fullSync(self.io, file);
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

    /// Read both logs and compute the restart plan (§10). Whenever a log's
    /// parse stops before EOF — torn tail or true corruption — the file is
    /// truncated back to its valid prefix through the open handle, so
    /// subsequent appends land on a clean record boundary.
    pub fn recover(self: *Store, gpa: std.mem.Allocator) !Recovery {
        var torn_tail_repaired = false;

        const own_data = self.dir.readFileAlloc(self.io, own_log_name, gpa, .unlimited) catch |err| switch (err) {
            error.OutOfMemory => return Error.OutOfMemory,
            else => return Error.IoFailed,
        };
        defer gpa.free(own_data);

        const own_scan = try recoverOwn(gpa, own_data);
        errdefer {
            for (own_scan.records) |r| gpa.free(r.envelope);
            gpa.free(own_scan.records);
        }
        if (own_scan.tail != .clean) {
            try truncateTo(self.io, self.own_file, own_scan.valid_len);
            if (own_scan.tail == .torn) torn_tail_repaired = true;
        }

        const ext_data = self.dir.readFileAlloc(self.io, ext_log_name, gpa, .unlimited) catch |err| switch (err) {
            error.OutOfMemory => return Error.OutOfMemory,
            else => return Error.IoFailed,
        };
        defer gpa.free(ext_data);

        var ext_iter = RecordIter{ .data = ext_data };
        var hwm: ?u64 = null;
        // Journal tail: last-wins per slot (restart replay can append the
        // same slot twice; agreement makes the values identical anyway).
        var tail_map: std.AutoArrayHashMapUnmanaged(u64, []u8) = .empty;
        errdefer {
            for (tail_map.values()) |v| gpa.free(v);
            tail_map.deinit(gpa);
        }
        while (ext_iter.next()) |item| {
            if (hwm == null or item.slot > hwm.?) hwm = item.slot;
            const copy = try gpa.dupe(u8, item.payload);
            const gop = try tail_map.getOrPut(gpa, item.slot);
            if (gop.found_existing) gpa.free(gop.value_ptr.*);
            gop.value_ptr.* = copy;
        }
        if (ext_iter.tail != .clean) {
            try truncateTo(self.io, self.ext_file, ext_iter.pos);
            if (ext_iter.tail == .torn) torn_tail_repaired = true;
        }

        // Flatten ascending by slot.
        const ext_tail = try gpa.alloc(ExtRecord, tail_map.count());
        for (tail_map.keys(), tail_map.values(), 0..) |k, v, i| ext_tail[i] = .{ .slot = k, .value = v };
        std.mem.sort(ExtRecord, ext_tail, {}, struct {
            fn lt(_: void, a: ExtRecord, b: ExtRecord) bool {
                return a.slot < b.slot;
            }
        }.lt);
        tail_map.deinit(gpa); // values now owned by ext_tail

        return .{
            .own_latest = own_scan.records,
            .externalized_hwm = hwm,
            .ext_tail = ext_tail,
            .own_log_corrupt = own_scan.tail == .corrupt,
            .torn_tail_repaired = torn_tail_repaired,
        };
    }

    /// recoverOwn's result: the deduped valid records, how the parse of the
    /// log ended, and the byte length of the valid prefix (where a repair
    /// truncation must cut).
    const OwnScan = struct {
        records: []OwnRecord,
        tail: RecordIter.Tail,
        valid_len: usize,
    };

    /// Parse own.log's valid prefix, dedup to the last record per (slot, kind),
    /// and return them ascending by (slot, then kind), together with the tail
    /// classification (clean / torn / corrupt) and the valid-prefix length.
    fn recoverOwn(gpa: std.mem.Allocator, data: []const u8) Error!OwnScan {
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
                return @backingInt(a.kind) < @backingInt(b.kind);
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

        return .{ .records = own_latest, .tail = iter.tail, .valid_len = iter.pos };
    }

    pub fn deinitRecovery(gpa: std.mem.Allocator, rec: *Recovery) void {
        for (rec.own_latest) |r| gpa.free(r.envelope);
        gpa.free(rec.own_latest);
        for (rec.ext_tail) |r| gpa.free(r.value);
        gpa.free(rec.ext_tail);
        rec.* = undefined;
    }

    /// Atomically rewrite both logs keeping only records with slot >= keep_from_slot.
    /// (own.log keeps consensus state for the answering window; externalized.log
    /// keeps the recent journal — its high-water mark is preserved because the
    /// max-slot record always survives.) Called occasionally by the Node.
    pub fn compact(self: *Store, keep_from_slot: u64) Error!void {
        try self.compactLog(&self.own_file, own_log_name, own_tmp_name, keep_from_slot);
        try self.compactLog(&self.ext_file, ext_log_name, ext_tmp_name, keep_from_slot);
    }

    /// Rewrite one log, dropping records with slot < keep_from_slot. Surviving
    /// record bytes are copied verbatim IN ORDER (so own.log's last-wins replay
    /// semantics are preserved). Crash-safe: the new content goes to a temp
    /// file which is fsync'd and then atomically renamed over the real name —
    /// at any interruption point the real name holds either the old or the new
    /// complete log. On success `file` is swapped to a handle on the new file.
    fn compactLog(
        self: *Store,
        file: *std.Io.File,
        log_name: []const u8,
        tmp_name: []const u8,
        keep_from_slot: u64,
    ) Error!void {
        const io = self.io;
        const gpa = self.gpa;

        // Read + parse the current log through the open handle.
        const file_len_u64 = file.length(io) catch return Error.IoFailed;
        const file_len = std.math.cast(usize, file_len_u64) orelse return Error.IoFailed;
        const data = try gpa.alloc(u8, file_len);
        defer gpa.free(data);
        const n_read = file.readPositionalAll(io, data, 0) catch return Error.IoFailed;
        if (n_read != file_len) return Error.IoFailed;

        var kept: std.ArrayList(u8) = .empty;
        defer kept.deinit(gpa);
        var iter = RecordIter{ .data = data };
        while (true) {
            const rec_start = iter.pos;
            const item = iter.next() orelse break;
            if (item.slot >= keep_from_slot)
                try kept.appendSlice(gpa, data[rec_start..iter.pos]);
        }

        // Write + durably sync the survivors under the temp name.
        var tmp = self.dir.createFile(io, tmp_name, .{ .read = true }) catch
            return Error.IoFailed;
        var tmp_is_temp = true;
        errdefer if (tmp_is_temp) {
            tmp.close(io);
            self.dir.deleteFile(io, tmp_name) catch {};
        };
        tmp.writeStreamingAll(io, kept.items) catch return Error.IoFailed;
        try fullSync(io, tmp);

        // Atomic swap under the real name. The open `tmp` handle follows the
        // inode across the rename, so it IS the new log handle.
        self.dir.rename(tmp_name, self.dir, log_name, io) catch return Error.IoFailed;
        tmp_is_temp = false;
        file.close(io);
        file.* = tmp;

        // Durability barrier for the rename itself (on darwin F_FULLFSYNC
        // flushes the journal and the drive cache; a lost-but-atomic rename on
        // other targets still leaves the old complete log, which is safe).
        try fullSync(io, tmp);
    }
};

/// fsync `file`, upgraded to a real media flush on macOS. Plain fsync there
/// only reaches the drive cache; F_FULLFSYNC asks the drive to flush to
/// stable media — required for the §10 persist-precedes-broadcast guarantee.
/// If the filesystem rejects F_FULLFSYNC (e.g. SMB), the completed fsync is
/// the strongest barrier available, so — like SQLite — fall back to it.
fn fullSync(io: std.Io, file: std.Io.File) Error!void {
    file.sync(io) catch return Error.IoFailed;
    if (comptime builtin.os.tag == .macos) {
        _ = std.c.fcntl(file.handle, std.c.F.FULLFSYNC);
    }
}

/// Cut `file` back to `new_len` bytes (a log's valid prefix) and sync, so the
/// next append lands on a clean record boundary.
fn truncateTo(io: std.Io, file: std.Io.File, new_len: usize) Error!void {
    file.setLength(io, new_len) catch return Error.IoFailed;
    try fullSync(io, file);
}

/// Front-to-back reader over a log's framed records. `pos` only advances past
/// records that fully verify, so after the walk it is the byte length of the
/// log's valid prefix. `tail` records how the walk ended:
///
///   * .clean   — `null` was returned at an exact record boundary (EOF).
///   * .torn    — the file physically ends mid-record: fewer than the 12
///                header bytes remain, or the declared payload+crc extends
///                past EOF. The routine power-loss artifact; the prefix is
///                trustworthy (§10: persist precedes broadcast).
///   * .corrupt — a structurally complete record (full header + payload + crc
///                all present) failed its crc. The log is untrusted.
const RecordIter = struct {
    data: []const u8,
    pos: usize = 0,
    tail: Tail = .clean,

    const Tail = enum { clean, torn, corrupt };

    const Item = struct { slot: u64, payload: []const u8 };

    fn next(self: *RecordIter) ?Item {
        const data = self.data;
        const i = self.pos;
        if (i >= data.len) return null; // clean boundary EOF
        if (data.len - i < rec_header_len) {
            self.tail = .torn; // file ends mid-header
            return null;
        }
        const slot = std.mem.readInt(u64, data[i..][0..8], .little);
        const len = std.mem.readInt(u32, data[i + 8 ..][0..4], .little);
        const payload_start = i + rec_header_len;
        // Widen: payload_start + len + crc must not overflow usize on 32-bit.
        const rec_end_wide = @as(u64, payload_start) + len + rec_crc_len;
        if (rec_end_wide > data.len) {
            self.tail = .torn; // declared payload+crc extends past EOF
            return null;
        }
        const rec_end: usize = @intCast(rec_end_wide);
        const crc_start = payload_start + len;
        const stored_crc = std.mem.readInt(u32, data[crc_start..][0..4], .little);
        const calc_crc = Crc32.hash(data[i..crc_start]); // slot ++ len ++ payload
        if (calc_crc != stored_crc) {
            self.tail = .corrupt; // complete record, bad crc
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
    try testing.expect(!rec.torn_tail_repaired);
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
    try testing.expect(!rec.torn_tail_repaired);
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
    try testing.expect(!rec.torn_tail_repaired);
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

    // The final record is structurally COMPLETE with a bad crc → true
    // corruption, not a torn tail.
    try testing.expect(rec.own_log_corrupt);
    try testing.expect(!rec.torn_tail_repaired);
    // The intact prefix (record 1) still recovers.
    try testing.expectEqual(@as(usize, 1), rec.own_latest.len);
    try testing.expectEqual(@as(u64, 1), rec.own_latest[0].slot);
    try testing.expectEqualSlices(u8, env_a, rec.own_latest[0].envelope);
    // externalized.log is untouched → its hwm survives.
    try testing.expectEqual(@as(?u64, 42), rec.externalized_hwm);
}

test "store: torn own.log tail is repaired, not corruption" {
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
    const env_c = try buildTestEnvelope(gpa, 3, .prepare, 0x03);
    defer gpa.free(env_c);

    {
        var store = try Store.open(gpa, io, data_dir);
        defer store.deinit();
        try store.appendOwn(1, env_a);
        try store.appendOwn(2, env_b);
    }

    // Cut the file a few bytes into record 2's header (record 1 is
    // rec_header_len + env_a.len + rec_crc_len bytes) — the power-loss shape.
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
    {
        var rec = try store.recover(gpa);
        defer Store.deinitRecovery(gpa, &rec);
        // A torn final append is the routine crash artifact — NOT corruption.
        try testing.expect(!rec.own_log_corrupt);
        try testing.expect(rec.torn_tail_repaired);
        try testing.expectEqual(@as(usize, 1), rec.own_latest.len);
        try testing.expectEqual(@as(u64, 1), rec.own_latest[0].slot);
        try testing.expectEqualSlices(u8, env_a, rec.own_latest[0].envelope);
    }

    // recover() physically truncated the log back to its valid prefix.
    const after = try tmp.dir.readFileAlloc(io, own_path, gpa, .unlimited);
    defer gpa.free(after);
    try testing.expectEqual(@as(usize, rec1_end), after.len);

    // A second recover is clean (nothing left to repair) with the same records.
    {
        var rec = try store.recover(gpa);
        defer Store.deinitRecovery(gpa, &rec);
        try testing.expect(!rec.own_log_corrupt);
        try testing.expect(!rec.torn_tail_repaired);
        try testing.expectEqual(@as(usize, 1), rec.own_latest.len);
        try testing.expectEqualSlices(u8, env_a, rec.own_latest[0].envelope);
    }

    // Fresh appends land on the repaired boundary; recover sees prefix + new.
    try store.appendOwn(3, env_c);
    {
        var rec = try store.recover(gpa);
        defer Store.deinitRecovery(gpa, &rec);
        try testing.expect(!rec.own_log_corrupt);
        try testing.expect(!rec.torn_tail_repaired);
        try testing.expectEqual(@as(usize, 2), rec.own_latest.len);
        try testing.expectEqual(@as(u64, 1), rec.own_latest[0].slot);
        try testing.expectEqualSlices(u8, env_a, rec.own_latest[0].envelope);
        try testing.expectEqual(@as(u64, 3), rec.own_latest[1].slot);
        try testing.expectEqualSlices(u8, env_c, rec.own_latest[1].envelope);
    }

    // And the repair + append survive a full reopen.
    store.deinit();
    store = try Store.open(gpa, io, data_dir);
    var rec = try store.recover(gpa);
    defer Store.deinitRecovery(gpa, &rec);
    try testing.expect(!rec.own_log_corrupt);
    try testing.expect(!rec.torn_tail_repaired);
    try testing.expectEqual(@as(usize, 2), rec.own_latest.len);
    try testing.expectEqualSlices(u8, env_a, rec.own_latest[0].envelope);
    try testing.expectEqualSlices(u8, env_c, rec.own_latest[1].envelope);
}

test "store: mid-file crc corruption truncates to the prefix before the bad record" {
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
    const env_c = try buildTestEnvelope(gpa, 3, .prepare, 0x03);
    defer gpa.free(env_c);

    {
        var store = try Store.open(gpa, io, data_dir);
        defer store.deinit();
        try store.appendOwn(1, env_a);
        try store.appendOwn(2, env_b);
        try store.appendOwn(3, env_c);
    }

    // Flip one payload byte of record 2 — a COMPLETE record surrounded by
    // valid neighbors — i.e. true silent corruption, not a torn tail.
    const rec1_end = rec_header_len + env_a.len + rec_crc_len;
    var op_buf: [128]u8 = undefined;
    const own_path = try std.fmt.bufPrint(&op_buf, "data/{s}", .{own_log_name});
    const bytes = try tmp.dir.readFileAlloc(io, own_path, gpa, .unlimited);
    defer gpa.free(bytes);
    bytes[rec1_end + rec_header_len] ^= 0xff;
    var f = try tmp.dir.createFile(io, own_path, .{});
    try f.writeStreamingAll(io, bytes);
    f.close(io);

    var store = try Store.open(gpa, io, data_dir);
    defer store.deinit();
    {
        var rec = try store.recover(gpa);
        defer Store.deinitRecovery(gpa, &rec);
        try testing.expect(rec.own_log_corrupt);
        try testing.expect(!rec.torn_tail_repaired);
        // Only the prefix before the bad record survives (record 3 is
        // unreachable behind it).
        try testing.expectEqual(@as(usize, 1), rec.own_latest.len);
        try testing.expectEqual(@as(u64, 1), rec.own_latest[0].slot);
        try testing.expectEqualSlices(u8, env_a, rec.own_latest[0].envelope);
    }

    // The file was cut back to the prefix before the corrupt record.
    const after = try tmp.dir.readFileAlloc(io, own_path, gpa, .unlimited);
    defer gpa.free(after);
    try testing.expectEqual(@as(usize, rec1_end), after.len);
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

    // The single record is complete but fails crc → nothing recovered, log
    // flagged corrupt (this is not a torn tail), file cut back to empty.
    try testing.expect(rec.own_log_corrupt);
    try testing.expect(!rec.torn_tail_repaired);
    try testing.expectEqual(@as(usize, 0), rec.own_latest.len);
    const after = try tmp.dir.readFileAlloc(io, own_path, gpa, .unlimited);
    defer gpa.free(after);
    try testing.expectEqual(@as(usize, 0), after.len);
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

test "store: torn externalized.log tail is repaired and keeps prefix hwm" {
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
        try store.appendExternalized(10, "ext-a");
        try store.appendExternalized(42, "ext-b");
    }

    // Cut externalized.log mid-way into record 2 ("ext-a" record 1 is
    // rec_header_len + 5 + rec_crc_len bytes). own.log stays intact.
    const rec1_end = rec_header_len + "ext-a".len + rec_crc_len;
    var ep_buf: [128]u8 = undefined;
    const ext_path = try std.fmt.bufPrint(&ep_buf, "data/{s}", .{ext_log_name});
    const bytes = try tmp.dir.readFileAlloc(io, ext_path, gpa, .unlimited);
    defer gpa.free(bytes);
    var f = try tmp.dir.createFile(io, ext_path, .{});
    try f.writeStreamingAll(io, bytes[0 .. rec1_end + 3]);
    f.close(io);

    var store = try Store.open(gpa, io, data_dir);
    defer store.deinit();
    {
        var rec = try store.recover(gpa);
        defer Store.deinitRecovery(gpa, &rec);
        try testing.expect(!rec.own_log_corrupt); // own.log untouched
        try testing.expect(rec.torn_tail_repaired); // ext tail was torn
        try testing.expectEqual(@as(usize, 1), rec.own_latest.len);
        try testing.expectEqual(@as(?u64, 10), rec.externalized_hwm); // prefix hwm
    }

    // Physically truncated back to the valid prefix.
    const after = try tmp.dir.readFileAlloc(io, ext_path, gpa, .unlimited);
    defer gpa.free(after);
    try testing.expectEqual(@as(usize, rec1_end), after.len);

    // Appends land on the repaired boundary and advance the hwm again.
    try store.appendExternalized(43, "ext-c");
    var rec = try store.recover(gpa);
    defer Store.deinitRecovery(gpa, &rec);
    try testing.expect(!rec.own_log_corrupt);
    try testing.expect(!rec.torn_tail_repaired);
    try testing.expectEqual(@as(?u64, 43), rec.externalized_hwm);
}

test "store: compact keeps only slots >= keep_from_slot and stays appendable" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    var envs: [41]?[]const u8 = @splat(null);
    defer for (envs) |e| {
        if (e) |bytes| gpa.free(bytes);
    };

    var store = try Store.open(gpa, io, data_dir);
    defer store.deinit();

    // Records for slots 1..40 in both logs, plus a qset that must survive.
    const qset_hash: [32]u8 = @splat(0x5c);
    store.putQset(qset_hash, "framed-qset-bytes");
    var slot: u64 = 1;
    while (slot <= 40) : (slot += 1) {
        const env = try buildTestEnvelope(gpa, slot, .prepare, @intCast(slot));
        envs[slot] = env;
        try store.appendOwn(slot, env);
        var vbuf: [8]u8 = undefined;
        const value = try std.fmt.bufPrint(&vbuf, "v{d}", .{slot});
        try store.appendExternalized(slot, value);
    }

    var op_buf: [128]u8 = undefined;
    const own_path = try std.fmt.bufPrint(&op_buf, "data/{s}", .{own_log_name});
    const before = try tmp.dir.readFileAlloc(io, own_path, gpa, .unlimited);
    defer gpa.free(before);

    try store.compact(25);

    // The rewritten log physically shrank.
    const after = try tmp.dir.readFileAlloc(io, own_path, gpa, .unlimited);
    defer gpa.free(after);
    try testing.expect(after.len < before.len);

    {
        var rec = try store.recover(gpa);
        defer Store.deinitRecovery(gpa, &rec);
        try testing.expect(!rec.own_log_corrupt);
        try testing.expect(!rec.torn_tail_repaired);
        // Only slots 25..40 remain, ascending, bytes intact.
        try testing.expectEqual(@as(usize, 16), rec.own_latest.len);
        for (rec.own_latest, 0..) |r, i| {
            try testing.expectEqual(@as(u64, 25 + i), r.slot);
            try testing.expectEqualSlices(u8, envs[r.slot].?, r.envelope);
        }
        // hwm preserved: the max-slot externalized record always survives.
        try testing.expectEqual(@as(?u64, 40), rec.externalized_hwm);
    }

    // qsets/ dir untouched by compaction.
    const qset = try store.getQset(gpa, qset_hash);
    try testing.expect(qset != null);
    defer gpa.free(qset.?);
    try testing.expectEqualSlices(u8, "framed-qset-bytes", qset.?);

    // Appends still work on the swapped handles, and survive a reopen.
    const env41 = try buildTestEnvelope(gpa, 41, .prepare, 41);
    defer gpa.free(env41);
    try store.appendOwn(41, env41);
    try store.appendExternalized(41, "v41");

    store.deinit();
    store = try Store.open(gpa, io, data_dir);
    var rec = try store.recover(gpa);
    defer Store.deinitRecovery(gpa, &rec);
    try testing.expect(!rec.own_log_corrupt);
    try testing.expect(!rec.torn_tail_repaired);
    try testing.expectEqual(@as(usize, 17), rec.own_latest.len);
    try testing.expectEqual(@as(u64, 25), rec.own_latest[0].slot);
    try testing.expectEqual(@as(u64, 41), rec.own_latest[16].slot);
    try testing.expectEqualSlices(u8, env41, rec.own_latest[16].envelope);
    try testing.expectEqual(@as(?u64, 41), rec.externalized_hwm);
}

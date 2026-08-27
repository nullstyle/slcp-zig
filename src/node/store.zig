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

pub const Error = error{ BadRecord, IoFailed } || std.mem.Allocator.Error;

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
    // Fields are the agent's to define. Named `impl`-free so node.zig only
    // touches the methods below.
    gpa: std.mem.Allocator,
    io: std.Io,
    // ... agent adds Dir + file handles + data_dir copy ...
    _placeholder: usize = 0,

    /// Open (creating if needed) the data dir and both logs.
    pub fn open(gpa: std.mem.Allocator, io: std.Io, data_dir: []const u8) !Store {
        _ = gpa;
        _ = io;
        _ = data_dir;
        @panic("stub: store.open — M5 agent");
    }

    pub fn deinit(self: *Store) void {
        _ = self;
        @panic("stub: store.deinit — M5 agent");
    }

    /// Append + fsync one own-envelope record (write-ahead; §10).
    pub fn appendOwn(self: *Store, slot: u64, framed_envelope: []const u8) !void {
        _ = self;
        _ = slot;
        _ = framed_envelope;
        @panic("stub: store.appendOwn — M5 agent");
    }

    /// Append + fsync one externalized-value record.
    pub fn appendExternalized(self: *Store, slot: u64, value: []const u8) !void {
        _ = self;
        _ = slot;
        _ = value;
        @panic("stub: store.appendExternalized — M5 agent");
    }

    /// Best-effort write of a verified foreign qset (no fsync).
    pub fn putQset(self: *Store, hash: [32]u8, framed_qset: []const u8) void {
        _ = self;
        _ = hash;
        _ = framed_qset;
        @panic("stub: store.putQset — M5 agent");
    }

    /// Read a cached qset by hash (caller frees), or null.
    pub fn getQset(self: *Store, gpa: std.mem.Allocator, hash: [32]u8) !?[]u8 {
        _ = self;
        _ = gpa;
        _ = hash;
        @panic("stub: store.getQset — M5 agent");
    }

    /// Read both logs and compute the restart plan (§10).
    pub fn recover(self: *Store, gpa: std.mem.Allocator) !Recovery {
        _ = self;
        _ = gpa;
        @panic("stub: store.recover — M5 agent");
    }

    pub fn deinitRecovery(gpa: std.mem.Allocator, rec: *Recovery) void {
        _ = gpa;
        _ = rec;
        @panic("stub: store.deinitRecovery — M5 agent");
    }
};

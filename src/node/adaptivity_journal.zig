//! Durable ordered records for managed consensus hosts. Experimental.
//!
//! One journal binds a signing identity to a genesis domain and retains quorum
//! changes, own envelopes, application acknowledgments and successor installs
//! in their original order. Append returns only after a durability barrier.
//! Reopening never creates missing state. Complete corrupt records fail closed;
//! only an incomplete final append is repaired. This protects crash recovery,
//! not rollback by an administrator who can replace the entire data directory.
//!
//! The caller serializes access and interprets payloads through its Session.
//! Capacity exhaustion requires archival/rotation by an application protocol;
//! this module never deletes signing or migration history to make space.

const std = @import("std");
const builtin = @import("builtin");
const Hash = std.crypto.hash.sha2.Sha256;
const magic = "SLCPAJ1\x00";
const header_len = 76;
const record_header_len = 52;
const digest_len = 32;
const file_name = "adaptivity.log";

pub const Kind = enum(u8) {
    initial = 1,
    quorum_change = 2,
    own_envelope = 3,
    applied = 4,
    successor_install = 5,
    retirement = 6,
};

pub const Limits = struct {
    max_record_bytes: u32 = 16 * 1024 * 1024,
    max_journal_bytes: u64 = 64 * 1024 * 1024,
};

pub const Identity = struct {
    node_id: [32]u8,
    root_network_id: [32]u8,
};

pub const Record = struct {
    kind: Kind,
    sequence: u64,
    /// Borrows Recovery.bytes until Recovery.deinit.
    payload: []const u8,
};

pub const Recovery = struct {
    gpa: std.mem.Allocator,
    bytes: []u8,
    records: []Record,
    torn_tail_repaired: bool,

    pub fn deinit(self: *Recovery) void {
        self.gpa.free(self.records);
        self.gpa.free(self.bytes);
        self.* = undefined;
    }
};

pub const Journal = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    lock: std.Io.File,
    file: std.Io.File,
    identity: Identity,
    limits: Limits,
    recovered: bool = false,
    failed: bool = false,
    end: u64 = header_len,
    sequence: u64 = 0,
    digest: [32]u8,

    /// Explicit new history. Fails if adaptivity.log already exists. `path`
    /// must be an existing, durably provisioned directory; no missing parent
    /// or journal is silently re-created during restart.
    pub fn create(gpa: std.mem.Allocator, io: std.Io, path: []const u8, identity: Identity, limits: Limits) !Journal {
        return openImpl(gpa, io, path, identity, limits, true);
    }

    /// Existing history only. Call recover successfully before appending.
    pub fn open(gpa: std.mem.Allocator, io: std.Io, path: []const u8, identity: Identity, limits: Limits) !Journal {
        return openImpl(gpa, io, path, identity, limits, false);
    }

    fn openImpl(gpa: std.mem.Allocator, io: std.Io, path: []const u8, identity: Identity, limits: Limits, create_new: bool) !Journal {
        if (limits.max_record_bytes == 0 or limits.max_journal_bytes < header_len) return error.InvalidLimits;
        // Linux's path-only directory descriptors cannot be fsynced. Keep
        // a readable directory descriptor for the creation durability barrier.
        const dir = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        errdefer dir.close(io);
        const lock = try dir.createFile(io, "adaptivity.lock", .{ .truncate = false });
        errdefer lock.close(io);
        // Unsupported locking is an error: silently sharing a signing journal
        // between processes would invalidate the safety contract.
        if (!try lock.tryLock(io, .exclusive)) return error.Busy;
        const file = if (create_new)
            try dir.createFile(io, file_name, .{ .exclusive = true, .read = true })
        else
            try dir.openFile(io, file_name, .{ .mode = .read_write });
        errdefer file.close(io);
        var header: [header_len]u8 = undefined;
        @memcpy(header[0..8], magic);
        @memcpy(header[8..40], &identity.node_id);
        @memcpy(header[40..72], &identity.root_network_id);
        std.mem.writeInt(u32, header[72..76], std.hash.Crc32.hash(header[0..72]), .big);
        if (create_new) {
            try file.writeStreamingAll(io, &header);
            try syncFile(io, file);
            // Persist the filename as well as its contents before signing.
            try syncFile(io, .{ .handle = dir.handle, .flags = .{ .nonblocking = false } });
        }
        var digest: [32]u8 = undefined;
        Hash.hash(&header, &digest, .{});
        return .{ .gpa = gpa, .io = io, .dir = dir, .lock = lock, .file = file, .identity = identity, .limits = limits, .recovered = create_new, .digest = digest };
    }

    pub fn deinit(self: *Journal) void {
        self.file.close(self.io);
        self.lock.close(self.io);
        self.dir.close(self.io);
        self.* = undefined;
    }

    /// Call once after open, before restoring inputs into a Session. All
    /// records remain ordered; this does not apply Node's last-record dedup.
    pub fn recover(self: *Journal) !Recovery {
        if (self.failed) return error.JournalFailed;
        if (self.recovered) return error.AlreadyRecovered;
        errdefer self.failed = true;
        const len = try self.file.length(self.io);
        if (len > self.limits.max_journal_bytes) return error.JournalFull;
        const size = std.math.cast(usize, len) orelse return error.JournalFull;
        const bytes = try self.gpa.alloc(u8, size);
        errdefer self.gpa.free(bytes);
        if (try self.file.readPositionalAll(self.io, bytes, 0) != size) return error.ShortRead;
        if (size < header_len) return error.CorruptJournal;
        if (!std.mem.eql(u8, bytes[0..8], magic) or
            std.mem.readInt(u32, bytes[72..76], .big) != std.hash.Crc32.hash(bytes[0..72])) return error.CorruptJournal;
        if (!std.mem.eql(u8, bytes[8..40], &self.identity.node_id) or
            !std.mem.eql(u8, bytes[40..72], &self.identity.root_network_id)) return error.WrongIdentity;
        Hash.hash(bytes[0..header_len], &self.digest, .{});
        var records: std.ArrayList(Record) = .empty;
        defer records.deinit(self.gpa);
        var offset: usize = header_len;
        var sequence: u64 = 0;
        while (offset < size) {
            if (size - offset < record_header_len) break;
            const header = bytes[offset..][0..record_header_len];
            // Check length metadata BEFORE deciding that a tail is torn: a
            // flipped length in a complete record must never erase history.
            if (std.mem.readInt(u32, header[48..52], .big) != std.hash.Crc32.hash(header[0..48])) return error.CorruptJournal;
            if (!std.mem.eql(u8, header[5..8], &.{ 0, 0, 0 })) return error.CorruptJournal;
            const kind: Kind = switch (header[4]) {
                1...6 => @fromBackingInt(@intCast(header[4])),
                else => return error.CorruptJournal,
            };
            if (std.mem.readInt(u64, header[8..16], .big) != sequence or
                !std.mem.eql(u8, header[16..48], &self.digest)) return error.CorruptJournal;
            const payload_len = std.mem.readInt(u32, header[0..4], .big);
            if (payload_len > self.limits.max_record_bytes) return error.RecordTooLarge;
            const total: u64 = @as(u64, record_header_len) + payload_len + digest_len;
            if (total > size - offset) break;
            const payload_start = offset + record_header_len;
            const digest_start = payload_start + payload_len;
            var digest: [32]u8 = undefined;
            Hash.hash(bytes[offset..digest_start], &digest, .{});
            if (!std.mem.eql(u8, &digest, bytes[digest_start..][0..digest_len])) return error.CorruptJournal;
            try records.append(self.gpa, .{ .kind = kind, .sequence = sequence, .payload = bytes[payload_start..digest_start] });
            sequence = std.math.add(u64, sequence, 1) catch return error.CorruptJournal;
            self.digest = digest;
            offset = digest_start + digest_len;
        }
        const torn = offset != size;
        // Allocate the return value before modifying disk. Failure leaves the
        // existing journal recoverable by a fresh instance.
        const owned_records = try records.toOwnedSlice(self.gpa);
        errdefer self.gpa.free(owned_records);
        if (torn) {
            try self.file.setLength(self.io, offset);
            try syncFile(self.io, self.file);
        }
        self.end = offset;
        self.sequence = sequence;
        self.recovered = true;
        return .{ .gpa = self.gpa, .bytes = bytes, .records = owned_records, .torn_tail_repaired = torn };
    }

    /// A write or sync error makes this instance unusable. Restart and recover
    /// before deciding whether an uncertain append reached stable storage.
    pub fn append(self: *Journal, kind: Kind, payload: []const u8) !void {
        if (self.failed) return error.JournalFailed;
        if (!self.recovered) return error.RecoveryRequired;
        if (payload.len > self.limits.max_record_bytes) return error.RecordTooLarge;
        const total = std.math.add(usize, payload.len, record_header_len + digest_len) catch return error.RecordTooLarge;
        if (total > self.limits.max_journal_bytes - self.end) return error.JournalFull;
        const next_sequence = std.math.add(u64, self.sequence, 1) catch return error.JournalFull;
        const record = try self.gpa.alloc(u8, total);
        defer self.gpa.free(record);
        std.mem.writeInt(u32, record[0..4], @intCast(payload.len), .big);
        record[4] = @backingInt(kind);
        @memset(record[5..8], 0);
        std.mem.writeInt(u64, record[8..16], self.sequence, .big);
        @memcpy(record[16..48], &self.digest);
        std.mem.writeInt(u32, record[48..52], std.hash.Crc32.hash(record[0..48]), .big);
        @memcpy(record[record_header_len..][0..payload.len], payload);
        var digest: [32]u8 = undefined;
        Hash.hash(record[0 .. total - digest_len], &digest, .{});
        @memcpy(record[total - digest_len ..], &digest);
        errdefer self.failed = true;
        // Detect unsupported out-of-band edits before overwriting a journal.
        if (try self.file.length(self.io) != self.end) return error.ConcurrentModification;
        var buffer: [4096]u8 = undefined;
        var writer = self.file.writer(self.io, &buffer);
        writer.pos = self.end;
        try writer.interface.writeAll(record);
        try writer.interface.flush();
        try syncFile(self.io, self.file);
        self.end += total;
        self.sequence = next_sequence;
        self.digest = digest;
    }
};

fn syncFile(io: std.Io, file: std.Io.File) !void {
    try file.sync(io);
    if (comptime builtin.os.tag == .macos) {
        // Match the native store's best-effort media-flush upgrade. Filesystems
        // without FULLFSYNC support retain the successful fsync barrier above.
        _ = std.c.fcntl(file.handle, std.c.F.FULLFSYNC);
    }
}

const testing = std.testing;
const test_identity: Identity = .{ .node_id = @splat(3), .root_network_id = @splat(8) };

fn testPath(tmp: *testing.TmpDir, buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, ".zig-cache/tmp/{s}", .{tmp.sub_path});
}

test "adaptivity journal preserves ordered history and requires explicit recovery" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [256]u8 = undefined;
    const path = try testPath(&tmp, &buffer);
    {
        var journal = try Journal.create(testing.allocator, testing.io, path, test_identity, .{});
        defer journal.deinit();
        try journal.append(.initial, "genesis");
        try journal.append(.quorum_change, "revision");
        try journal.append(.own_envelope, "terminal envelope before externalized");
        try journal.append(.successor_install, "certificate and checkpoint");
        try testing.expectError(error.Busy, Journal.open(testing.allocator, testing.io, path, test_identity, .{}));
    }
    var journal = try Journal.open(testing.allocator, testing.io, path, test_identity, .{});
    defer journal.deinit();
    try testing.expectError(error.RecoveryRequired, journal.append(.applied, "too soon"));
    var recovery = try journal.recover();
    defer recovery.deinit();
    try testing.expect(!recovery.torn_tail_repaired);
    try testing.expectEqual(@as(usize, 4), recovery.records.len);
    try testing.expectEqual(Kind.own_envelope, recovery.records[2].kind);
    try testing.expectEqualStrings("terminal envelope before externalized", recovery.records[2].payload);
    try testing.expectEqual(@as(u64, 3), recovery.records[3].sequence);
    try journal.append(.applied, "next state");
}

test "adaptivity journal repairs every interrupted final append and accepts a new suffix" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [256]u8 = undefined;
    const path = try testPath(&tmp, &buffer);
    var first_end: u64 = 0;
    {
        var journal = try Journal.create(testing.allocator, testing.io, path, test_identity, .{});
        defer journal.deinit();
        try journal.append(.initial, "root");
        first_end = journal.end;
        try journal.append(.own_envelope, "terminal");
    }
    const original = try tmp.dir.readFileAlloc(testing.io, file_name, testing.allocator, .unlimited);
    defer testing.allocator.free(original);
    var cut: usize = @intCast(first_end);
    while (cut < original.len) : (cut += 1) {
        const file = try tmp.dir.createFile(testing.io, file_name, .{});
        try file.writeStreamingAll(testing.io, original[0..cut]);
        file.close(testing.io);
        var journal = try Journal.open(testing.allocator, testing.io, path, test_identity, .{});
        defer journal.deinit();
        var recovery = try journal.recover();
        defer recovery.deinit();
        try testing.expectEqual(@as(usize, 1), recovery.records.len);
        try testing.expectEqual(cut != first_end, recovery.torn_tail_repaired);
        try journal.append(.own_envelope, "new final record");
    }
}

test "adaptivity journal fails closed on complete corruption including length metadata" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [256]u8 = undefined;
    const path = try testPath(&tmp, &buffer);
    {
        var journal = try Journal.create(testing.allocator, testing.io, path, test_identity, .{});
        defer journal.deinit();
        try journal.append(.own_envelope, "signed terminal statement");
    }
    const original = try tmp.dir.readFileAlloc(testing.io, file_name, testing.allocator, .unlimited);
    defer testing.allocator.free(original);
    const positions = [_]usize{ 0, 72, header_len, header_len + 4, header_len + 8, header_len + 16, header_len + 48, header_len + record_header_len, original.len - 1 };
    for (positions) |position| {
        original[position] ^= 1;
        const file = try tmp.dir.createFile(testing.io, file_name, .{});
        try file.writeStreamingAll(testing.io, original);
        file.close(testing.io);
        original[position] ^= 1;
        var journal = try Journal.open(testing.allocator, testing.io, path, test_identity, .{});
        defer journal.deinit();
        try testing.expectError(error.CorruptJournal, journal.recover());
        try testing.expectError(error.JournalFailed, journal.append(.initial, "unsafe reset"));
        try testing.expectEqual(@as(u64, original.len), try journal.file.length(testing.io));
    }
}

test "adaptivity journal rejects foreign identity and bounded capacity without mutation" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [256]u8 = undefined;
    const path = try testPath(&tmp, &buffer);
    const limits: Limits = .{ .max_record_bytes = 4, .max_journal_bytes = header_len + record_header_len + digest_len + 4 };
    {
        var journal = try Journal.create(testing.allocator, testing.io, path, test_identity, limits);
        defer journal.deinit();
        try testing.expectError(error.RecordTooLarge, journal.append(.initial, "large"));
        try journal.append(.initial, "root");
        try testing.expectError(error.JournalFull, journal.append(.applied, "next"));
        try testing.expect(!journal.failed);
    }
    var foreign = test_identity;
    foreign.root_network_id[0] ^= 1;
    var journal = try Journal.open(testing.allocator, testing.io, path, foreign, .{});
    defer journal.deinit();
    try testing.expectError(error.WrongIdentity, journal.recover());
}

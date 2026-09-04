//! Bounded, best-effort on-disk answering cache for verified quorum sets.
//!
//! The local quorum set is pinned in memory. Remote entries are merely an
//! answering cache: filesystem failures degrade to misses and counters rather
//! than making consensus fail.

const std = @import("std");
const core = @import("slcp-core");

pub const Limits = struct {
    max_entries: usize,
    max_bytes: usize,
    max_entry_bytes: usize = core.limits.frozen_max_frame_bytes,
};

pub const Stats = struct {
    entries: usize,
    bytes: usize,
    evictions: u64,
    read_failures: u64,
    write_failures: u64,
    degraded: bool,
};

pub const Local = struct {
    hash: [32]u8,
    framed: []const u8,
};

pub const QsetDiskCache = struct {
    const Hash = [32]u8;
    const filename_len = 64 + ".bin".len;
    const temp_filename_len = filename_len + ".tmp.".len + 16;

    const Entry = struct {
        hash: Hash,
        bytes: usize,
    };

    const Candidate = struct {
        hash: Hash,
        bytes: usize,
        mtime_ns: i96,
    };

    gpa: std.mem.Allocator,
    io: std.Io,
    limits: Limits,
    local_hash: Hash,
    local_framed: []u8,
    qsets_dir: ?std.Io.Dir = null,
    remotes: std.ArrayList(Entry) = .empty,
    writes_disabled: bool = false,
    mu: std.Io.Mutex = .init,
    current: Stats,

    pub fn open(
        gpa: std.mem.Allocator,
        io: std.Io,
        data_dir: []const u8,
        local: Local,
    ) std.mem.Allocator.Error!QsetDiskCache {
        return openWithLimits(gpa, io, data_dir, .{
            .max_entries = 1024,
            .max_bytes = 64 * 1024 * 1024,
        }, local);
    }

    fn openWithLimits(
        gpa: std.mem.Allocator,
        io: std.Io,
        data_dir: []const u8,
        limits: Limits,
        local: Local,
    ) std.mem.Allocator.Error!QsetDiskCache {
        std.debug.assert(limits.max_entries >= 1);
        std.debug.assert(local.framed.len <= limits.max_entry_bytes);
        std.debug.assert(local.framed.len <= limits.max_bytes);

        const local_copy = try gpa.dupe(u8, local.framed);
        var self: QsetDiskCache = .{
            .gpa = gpa,
            .io = io,
            .limits = limits,
            .local_hash = local.hash,
            .local_framed = local_copy,
            .current = .{
                .entries = 1,
                .bytes = local_copy.len,
                .evictions = 0,
                .read_failures = 0,
                .write_failures = 0,
                .degraded = true,
            },
        };
        errdefer self.deinit();

        const data = std.Io.Dir.cwd().createDirPathOpen(io, data_dir, .{}) catch {
            self.latchWriteFailure();
            self.writes_disabled = true;
            return self;
        };
        defer data.close(io);
        self.qsets_dir = data.createDirPathOpen(io, "qsets", .{
            .open_options = .{ .iterate = true, .follow_symlinks = false },
        }) catch {
            self.latchWriteFailure();
            self.writes_disabled = true;
            return self;
        };
        self.current.degraded = false;

        self.reconcile();

        if (!self.writes_disabled) {
            if (self.writeAtomic(local.hash, local.framed)) |_| {} else |_| {
                self.latchWriteFailure();
                self.writes_disabled = true;
            }
        }
        return self;
    }

    pub fn rememberRequested(self: *QsetDiskCache, hash: [32]u8, framed: []const u8) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);

        if (std.mem.eql(u8, &hash, &self.local_hash)) return;
        if (framed.len > self.limits.max_entry_bytes or
            self.limits.max_entries <= 1 or
            framed.len > self.limits.max_bytes - self.local_framed.len)
        {
            return;
        }
        if (self.findRemote(hash) != null) return;
        if (self.qsets_dir == null or self.writes_disabled) {
            self.latchWriteFailure();
            return;
        }
        self.remotes.ensureUnusedCapacity(self.gpa, 1) catch {
            self.latchWriteFailure();
            return;
        };
        while (self.current.entries >= self.limits.max_entries or
            framed.len > self.limits.max_bytes - self.current.bytes)
        {
            if (!self.evictOldest()) return;
        }
        self.writeAtomic(hash, framed) catch {
            self.latchWriteFailure();
            self.writes_disabled = true;
            return;
        };
        self.remotes.appendAssumeCapacity(.{ .hash = hash, .bytes = framed.len });
        self.current.entries += 1;
        self.current.bytes += framed.len;
    }

    pub fn copy(self: *QsetDiskCache, out_allocator: std.mem.Allocator, hash: [32]u8) ?[]u8 {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (std.mem.eql(u8, &hash, &self.local_hash)) {
            return out_allocator.dupe(u8, self.local_framed) catch {
                self.current.read_failures +|= 1;
                self.current.degraded = true;
                return null;
            };
        }
        const index = self.findRemote(hash) orelse return null;
        const entry = self.remotes.items[index];
        const dir = self.qsets_dir orelse return null;
        var name_buf: [filename_len]u8 = undefined;
        const name = finalName(hash, &name_buf);
        var file = dir.openFile(self.io, name, .{
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        }) catch {
            self.current.read_failures +|= 1;
            self.current.degraded = true;
            self.invalidateRemote(index, hash);
            return null;
        };
        var file_open = true;
        defer if (file_open) file.close(self.io);
        const stat = file.stat(self.io) catch {
            file.close(self.io);
            file_open = false;
            self.current.read_failures +|= 1;
            self.current.degraded = true;
            self.invalidateRemote(index, hash);
            return null;
        };
        const size = std.math.cast(usize, stat.size) orelse {
            file.close(self.io);
            file_open = false;
            self.current.read_failures +|= 1;
            self.current.degraded = true;
            self.invalidateRemote(index, hash);
            return null;
        };
        if (stat.kind != .file or size != entry.bytes or size > self.limits.max_entry_bytes) {
            file.close(self.io);
            file_open = false;
            self.current.read_failures +|= 1;
            self.current.degraded = true;
            self.invalidateRemote(index, hash);
            return null;
        }
        const bytes = out_allocator.alloc(u8, size) catch {
            self.current.read_failures +|= 1;
            self.current.degraded = true;
            return null;
        };
        const read = file.readPositionalAll(self.io, bytes, 0) catch {
            out_allocator.free(bytes);
            file.close(self.io);
            file_open = false;
            self.current.read_failures +|= 1;
            self.current.degraded = true;
            self.invalidateRemote(index, hash);
            return null;
        };
        if (read != bytes.len) {
            out_allocator.free(bytes);
            file.close(self.io);
            file_open = false;
            self.current.read_failures +|= 1;
            self.current.degraded = true;
            self.invalidateRemote(index, hash);
            return null;
        }
        const matches = cachedFrameMatchesHash(self.gpa, bytes, hash) catch |err| {
            out_allocator.free(bytes);
            if (err == error.OutOfMemory) {
                self.current.read_failures +|= 1;
                self.current.degraded = true;
                return null;
            }
            file.close(self.io);
            file_open = false;
            self.current.read_failures +|= 1;
            self.current.degraded = true;
            self.invalidateRemote(index, hash);
            return null;
        };
        if (!matches) {
            out_allocator.free(bytes);
            file.close(self.io);
            file_open = false;
            self.current.read_failures +|= 1;
            self.current.degraded = true;
            self.invalidateRemote(index, hash);
            return null;
        }
        return bytes;
    }

    pub fn snapshot(self: *QsetDiskCache) Stats {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.current;
    }

    pub fn deinit(self: *QsetDiskCache) void {
        if (self.qsets_dir) |dir| dir.close(self.io);
        self.remotes.deinit(self.gpa);
        self.gpa.free(self.local_framed);
        self.* = undefined;
    }

    fn findRemote(self: *const QsetDiskCache, hash: Hash) ?usize {
        for (self.remotes.items, 0..) |entry, i| {
            if (std.mem.eql(u8, &entry.hash, &hash)) return i;
        }
        return null;
    }

    fn reconcile(self: *QsetDiskCache) void {
        const dir = self.qsets_dir orelse return;
        const remote_slots = self.limits.max_entries - 1;
        const remote_bytes = self.limits.max_bytes - self.local_framed.len;
        var keep: std.ArrayList(Candidate) = .empty;
        defer keep.deinit(self.gpa);
        var selection_failed = false;
        var kept_bytes: usize = 0;

        var iterator = dir.iterate();
        scan: while (true) {
            const next = iterator.next(self.io) catch {
                self.latchWriteFailure();
                self.writes_disabled = true;
                selection_failed = true;
                break :scan;
            };
            const entry = next orelse break;
            const hash = parseFinalName(entry.name) orelse continue;
            if (std.mem.eql(u8, &hash, &self.local_hash)) continue;
            const stat = dir.statFile(self.io, entry.name, .{ .follow_symlinks = false }) catch {
                self.current.read_failures +|= 1;
                self.current.degraded = true;
                continue;
            };
            const size = std.math.cast(usize, stat.size) orelse continue;
            if (stat.kind != .file or size > self.limits.max_entry_bytes or size > remote_bytes) continue;
            const candidate: Candidate = .{
                .hash = hash,
                .bytes = size,
                .mtime_ns = stat.mtime.nanoseconds,
            };
            if (keep.items.len < remote_slots) {
                keep.append(self.gpa, candidate) catch {
                    self.latchWriteFailure();
                    self.writes_disabled = true;
                    selection_failed = true;
                    break :scan;
                };
                kept_bytes += candidate.bytes;
                candidateHeapSiftUp(keep.items, keep.items.len - 1);
            } else if (remote_slots > 0) {
                if (candidateLess({}, keep.items[0], candidate)) {
                    kept_bytes -= keep.items[0].bytes;
                    kept_bytes += candidate.bytes;
                    keep.items[0] = candidate;
                    candidateHeapSiftDown(keep.items, 0);
                }
            }
        }

        if (selection_failed) {
            keep.clearRetainingCapacity();
            kept_bytes = 0;
        }
        while (kept_bytes > remote_bytes) {
            const removed = candidateHeapPopOldest(&keep);
            kept_bytes -= removed.bytes;
        }

        // Membership checks during cleanup must stay logarithmic even when
        // upgrading an old, unbounded qsets/ directory. Reuse the bounded
        // candidate buffer as a hash-sorted index, then restore FIFO order.
        std.mem.sort(Candidate, keep.items, {}, candidateHashLess);

        self.remotes.ensureTotalCapacityPrecise(self.gpa, keep.items.len) catch {
            self.latchWriteFailure();
            self.writes_disabled = true;
            keep.clearRetainingCapacity();
            kept_bytes = 0;
        };

        if (!self.cleanupOwned(keep.items)) self.writes_disabled = true;
        std.mem.sort(Candidate, keep.items, {}, candidateLess);
        for (keep.items) |candidate| {
            self.remotes.appendAssumeCapacity(.{ .hash = candidate.hash, .bytes = candidate.bytes });
        }
        self.current.entries += keep.items.len;
        self.current.bytes += kept_bytes;
    }

    fn cleanupOwned(self: *QsetDiskCache, keep: []const Candidate) bool {
        const dir = self.qsets_dir orelse return false;
        var clean = true;
        while (true) {
            var deleted_any = false;
            var iterator = dir.iterate();
            while (iterator.next(self.io) catch {
                self.latchWriteFailure();
                return false;
            }) |entry| {
                const final_hash = parseFinalName(entry.name);
                const stale_temp = isStaleTempName(entry.name);
                if (final_hash == null and !stale_temp) continue;
                if (entry.kind == .directory) continue;
                if (final_hash) |hash| {
                    if (std.mem.eql(u8, &hash, &self.local_hash) or candidateContains(keep, hash)) continue;
                }
                dir.deleteFile(self.io, entry.name) catch {
                    self.latchWriteFailure();
                    clean = false;
                    continue;
                };
                if (final_hash != null) self.current.evictions +|= 1;
                deleted_any = true;
            }
            if (!deleted_any) break;
        }
        return clean;
    }

    fn latchWriteFailure(self: *QsetDiskCache) void {
        self.current.write_failures +|= 1;
        self.current.degraded = true;
    }

    fn forgetRemote(self: *QsetDiskCache, index: usize) void {
        const removed = self.remotes.orderedRemove(index);
        self.current.entries -= 1;
        self.current.bytes -= removed.bytes;
    }

    fn invalidateRemote(self: *QsetDiskCache, index: usize, hash: Hash) void {
        self.forgetRemote(index);
        self.current.evictions +|= 1;
        const dir = self.qsets_dir orelse return;
        var name_buf: [filename_len]u8 = undefined;
        const name = finalName(hash, &name_buf);
        const state = self.canonicalNameState(name) catch {
            self.latchWriteFailure();
            self.writes_disabled = true;
            return;
        };
        if (state == .alias) {
            self.latchWriteFailure();
            self.writes_disabled = true;
            return;
        }
        if (state == .absent) return;
        dir.deleteFile(self.io, name) catch |err| switch (err) {
            error.FileNotFound, error.IsDir => {},
            else => {
                self.latchWriteFailure();
                self.writes_disabled = true;
            },
        };
    }

    fn evictOldest(self: *QsetDiskCache) bool {
        if (self.remotes.items.len == 0) return false;
        const oldest = self.remotes.items[0];
        const dir = self.qsets_dir orelse return false;
        var name_buf: [filename_len]u8 = undefined;
        const name = finalName(oldest.hash, &name_buf);
        if (self.canonicalNameState(name) catch {
            self.latchWriteFailure();
            self.writes_disabled = true;
            return false;
        } != .exact) {
            self.latchWriteFailure();
            self.writes_disabled = true;
            return false;
        }
        dir.deleteFile(self.io, name) catch {
            self.latchWriteFailure();
            self.writes_disabled = true;
            return false;
        };
        self.forgetRemote(0);
        self.current.evictions +|= 1;
        return true;
    }

    fn writeAtomic(self: *QsetDiskCache, hash: Hash, framed: []const u8) !void {
        const dir = self.qsets_dir orelse return error.CacheUnavailable;
        var final_buf: [filename_len]u8 = undefined;
        const final = finalName(hash, &final_buf);
        if (try self.canonicalNameState(final) == .alias) return error.CaseAliasConflict;

        var nonce_bytes: [8]u8 = undefined;
        self.io.random(&nonce_bytes);
        var temp_buf: [temp_filename_len]u8 = undefined;
        @memcpy(temp_buf[0..filename_len], final);
        @memcpy(temp_buf[filename_len..][0..".tmp.".len], ".tmp.");
        writeHex(&nonce_bytes, temp_buf[filename_len + ".tmp.".len ..]);
        const temp = temp_buf[0..];

        var file = try dir.createFile(self.io, temp, .{
            .exclusive = true,
            .resolve_beneath = true,
        });
        var file_open = true;
        var temp_exists = true;
        defer if (temp_exists) dir.deleteFile(self.io, temp) catch {};
        defer if (file_open) file.close(self.io);

        try file.writeStreamingAll(self.io, framed);
        file.close(self.io);
        file_open = false;
        try dir.rename(temp, dir, final, self.io);
        temp_exists = false;
    }

    const CanonicalNameState = enum { absent, exact, alias };

    /// On a case-insensitive filesystem, opening or renaming the canonical
    /// lowercase path can target an operator-owned mixed-case lookalike. Scan
    /// the directory's actual spellings before every path-based mutation.
    fn canonicalNameState(self: *QsetDiskCache, canonical: []const u8) !CanonicalNameState {
        const dir = self.qsets_dir orelse return .absent;
        var saw_alias = false;
        var iterator = dir.iterate();
        while (try iterator.next(self.io)) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.name, canonical)) continue;
            if (std.mem.eql(u8, entry.name, canonical)) return .exact;
            saw_alias = true;
        }
        return if (saw_alias) .alias else .absent;
    }
};

fn candidateLess(_: void, a: QsetDiskCache.Candidate, b: QsetDiskCache.Candidate) bool {
    if (a.mtime_ns != b.mtime_ns) return a.mtime_ns < b.mtime_ns;
    return std.mem.order(u8, &a.hash, &b.hash) == .lt;
}

fn candidateHashLess(_: void, a: QsetDiskCache.Candidate, b: QsetDiskCache.Candidate) bool {
    return std.mem.order(u8, &a.hash, &b.hash) == .lt;
}

fn candidateHeapSiftUp(items: []QsetDiskCache.Candidate, start: usize) void {
    var child = start;
    while (child > 0) {
        const parent = (child - 1) / 2;
        if (!candidateLess({}, items[child], items[parent])) break;
        std.mem.swap(QsetDiskCache.Candidate, &items[child], &items[parent]);
        child = parent;
    }
}

fn candidateHeapSiftDown(items: []QsetDiskCache.Candidate, start: usize) void {
    var parent = start;
    while (true) {
        const left = parent * 2 + 1;
        if (left >= items.len) return;
        const right = left + 1;
        const oldest_child = if (right < items.len and candidateLess({}, items[right], items[left])) right else left;
        if (!candidateLess({}, items[oldest_child], items[parent])) return;
        std.mem.swap(QsetDiskCache.Candidate, &items[parent], &items[oldest_child]);
        parent = oldest_child;
    }
}

fn candidateHeapPopOldest(candidates: *std.ArrayList(QsetDiskCache.Candidate)) QsetDiskCache.Candidate {
    std.debug.assert(candidates.items.len > 0);
    const oldest = candidates.items[0];
    const last = candidates.items[candidates.items.len - 1];
    candidates.items.len -= 1;
    if (candidates.items.len > 0) {
        candidates.items[0] = last;
        candidateHeapSiftDown(candidates.items, 0);
    }
    return oldest;
}

fn candidateContains(candidates: []const QsetDiskCache.Candidate, hash: [32]u8) bool {
    var lo: usize = 0;
    var hi = candidates.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, &candidates[mid].hash, &hash)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return true,
        }
    }
    return false;
}

fn finalName(hash: [32]u8, buf: *[QsetDiskCache.filename_len]u8) []const u8 {
    writeHex(&hash, buf[0..64]);
    @memcpy(buf[64..], ".bin");
    return buf;
}

fn parseFinalName(name: []const u8) ?[32]u8 {
    if (name.len != QsetDiskCache.filename_len or !std.mem.eql(u8, name[64..], ".bin")) return null;
    var hash: [32]u8 = undefined;
    for (&hash, 0..) |*byte, i| {
        const high = lowerHexNibble(name[i * 2]) orelse return null;
        const low = lowerHexNibble(name[i * 2 + 1]) orelse return null;
        byte.* = (high << 4) | low;
    }
    return hash;
}

fn isStaleTempName(name: []const u8) bool {
    if (name.len != QsetDiskCache.temp_filename_len) return false;
    if (parseFinalName(name[0..QsetDiskCache.filename_len]) == null) return false;
    const marker_start = QsetDiskCache.filename_len;
    if (!std.mem.eql(u8, name[marker_start .. marker_start + ".tmp.".len], ".tmp.")) return false;
    for (name[marker_start + ".tmp.".len ..]) |c| {
        if (lowerHexNibble(c) == null) return false;
    }
    return true;
}

fn lowerHexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        else => null,
    };
}

fn writeHex(bytes: []const u8, out: []u8) void {
    std.debug.assert(out.len == bytes.len * 2);
    const hex = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        out[i * 2] = hex[byte >> 4];
        out[i * 2 + 1] = hex[byte & 0x0f];
    }
}

fn cachedFrameMatchesHash(gpa: std.mem.Allocator, framed: []const u8, expected: [32]u8) !bool {
    if (framed.len > core.limits.frozen_max_frame_bytes) return false;
    var msg = try core.capnpc.message.Message.init(gpa, framed, .{
        .nesting_limit = 32,
        .traversal_limit_words = core.limits.frozen_max_frame_bytes / 8,
    });
    defer msg.deinit();
    const reader = try core.gen.slcp.QuorumSet.Reader.init(&msg);
    var qs = try core.qset.fromReader(gpa, reader);
    defer qs.deinit(gpa);
    try core.qset.validateAndNormalize(gpa, &qs);
    const actual = try core.qset.hashNormalized(gpa, &qs);
    return std.mem.eql(u8, &actual, &expected);
}

const testing = std.testing;

const TestFrame = struct {
    hash: [32]u8,
    bytes: []u8,

    fn deinit(self: *TestFrame, gpa: std.mem.Allocator) void {
        gpa.free(self.bytes);
        self.* = undefined;
    }
};

fn testFrame(gpa: std.mem.Allocator, marker: u8) !TestFrame {
    const validator: [32]u8 = @splat(marker);
    const validators = try gpa.dupe(core.qset.NodeId, &.{validator});
    const inner_sets = gpa.alloc(core.qset.QuorumSetOwned, 0) catch |err| {
        gpa.free(validators);
        return err;
    };
    var qs: core.qset.QuorumSetOwned = .{
        .threshold = 1,
        .validators = validators,
        .inner_sets = inner_sets,
    };
    defer qs.deinit(gpa);
    try core.qset.validateAndNormalize(gpa, &qs);
    const hash = try core.qset.hashNormalized(gpa, &qs);

    var builder = core.capnpc.message.MessageBuilder.init(gpa);
    defer builder.deinit();
    var root = try core.gen.slcp.QuorumSet.Builder.init(&builder);
    try root.setThreshold(1);
    var out_validators = try root.initValidators(1);
    try out_validators.set(0, &validator);
    return .{ .hash = hash, .bytes = @constCast(try builder.toBytes()) };
}

fn tmpDataDir(tmp: *std.testing.TmpDir, buf: []u8) ![]const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}/data", .{tmp.sub_path});
}

test "qset disk cache: local quorum set is pinned and accounted" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const local_hash: [32]u8 = @splat(0x11);
    const local_framed = "local-framed-quorum-set";
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 64,
        .max_entry_bytes = 32,
    }, .{ .hash = local_hash, .framed = local_framed });
    defer cache.deinit();

    const got = cache.copy(gpa, local_hash) orelse return error.TestUnexpectedResult;
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, local_framed, got);

    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 1), stats.entries);
    try testing.expectEqual(@as(usize, local_framed.len), stats.bytes);
    try testing.expectEqual(@as(u64, 0), stats.evictions);
    try testing.expectEqual(@as(u64, 0), stats.read_failures);
}

test "qset disk cache: local copy allocation failure is observable but preserves the pin" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const local_hash: [32]u8 = @splat(0x12);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 64,
        .max_entry_bytes = 32,
    }, .{ .hash = local_hash, .framed = "local" });
    defer cache.deinit();

    var failing = testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    try testing.expectEqual(@as(?[]u8, null), cache.copy(failing.allocator(), local_hash));
    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 1), stats.entries);
    try testing.expectEqual(@as(u64, 1), stats.read_failures);
    try testing.expect(stats.degraded);

    const local = cache.copy(gpa, local_hash) orelse return error.TestUnexpectedResult;
    defer gpa.free(local);
    try testing.expectEqualSlices(u8, "local", local);
}

test "qset disk cache: requested quorum set round-trips within both budgets" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const local_hash: [32]u8 = @splat(0x11);
    const local_framed = "local-qset";
    var remote = try testFrame(gpa, 0x22);
    defer remote.deinit(gpa);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 512,
        .max_entry_bytes = 256,
    }, .{ .hash = local_hash, .framed = local_framed });
    defer cache.deinit();

    cache.rememberRequested(remote.hash, remote.bytes);
    const got = cache.copy(gpa, remote.hash) orelse return error.TestUnexpectedResult;
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, remote.bytes, got);

    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 2), stats.entries);
    try testing.expectEqual(@as(usize, local_framed.len + remote.bytes.len), stats.bytes);
    try testing.expectEqual(@as(u64, 0), stats.evictions);
    try testing.expect(!stats.degraded);
}

test "qset disk cache: entry pressure evicts remote FIFO without refreshing on hit" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const local_hash: [32]u8 = @splat(0x10);
    var first = try testFrame(gpa, 0x21);
    defer first.deinit(gpa);
    var second = try testFrame(gpa, 0x22);
    defer second.deinit(gpa);
    var third = try testFrame(gpa, 0x23);
    defer third.deinit(gpa);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 1024,
        .max_entry_bytes = 256,
    }, .{ .hash = local_hash, .framed = "local" });
    defer cache.deinit();

    cache.rememberRequested(first.hash, first.bytes);
    cache.rememberRequested(second.hash, second.bytes);
    const first_hit = cache.copy(gpa, first.hash) orelse return error.TestUnexpectedResult;
    gpa.free(first_hit); // A hit must not refresh FIFO position.
    cache.rememberRequested(first.hash, first.bytes); // Nor may a duplicate.
    cache.rememberRequested(third.hash, third.bytes);

    if (cache.copy(gpa, first.hash)) |unexpected| {
        gpa.free(unexpected);
        return error.TestExpectedEqual;
    }
    const expected_hashes = [_][32]u8{ second.hash, third.hash, local_hash };
    const expected_frames = [_][]const u8{ second.bytes, third.bytes, "local" };
    for (expected_hashes, expected_frames) |expected_hash, expected_frame| {
        const got = cache.copy(gpa, expected_hash) orelse return error.TestUnexpectedResult;
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, expected_frame, got);
    }
    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 3), stats.entries);
    try testing.expectEqual(@as(usize, "local".len + second.bytes.len + third.bytes.len), stats.bytes);
    try testing.expectEqual(@as(u64, 1), stats.evictions);
}

test "qset disk cache: byte pressure evicts FIFO and rejects an impossible entry without I/O failure" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const local_hash: [32]u8 = @splat(0x10);
    var first = try testFrame(gpa, 0x31);
    defer first.deinit(gpa);
    var second = try testFrame(gpa, 0x32);
    defer second.deinit(gpa);
    var third = try testFrame(gpa, 0x33);
    defer third.deinit(gpa);
    const oversized_hash: [32]u8 = @splat(0x34);
    const remote_budget = second.bytes.len + third.bytes.len;
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 6,
        .max_bytes = "local".len + remote_budget,
        .max_entry_bytes = second.bytes.len,
    }, .{ .hash = local_hash, .framed = "local" });
    defer cache.deinit();

    cache.rememberRequested(first.hash, first.bytes);
    cache.rememberRequested(second.hash, second.bytes);
    cache.rememberRequested(third.hash, third.bytes);
    const oversized = try gpa.alloc(u8, second.bytes.len + 1);
    defer gpa.free(oversized);
    @memset(oversized, 0);
    cache.rememberRequested(oversized_hash, oversized);

    if (cache.copy(gpa, first.hash)) |unexpected| {
        gpa.free(unexpected);
        return error.TestExpectedEqual;
    }
    try testing.expectEqual(@as(?[]u8, null), cache.copy(gpa, oversized_hash));
    const expected_hashes = [_][32]u8{ local_hash, second.hash, third.hash };
    const expected_frames = [_][]const u8{ "local", second.bytes, third.bytes };
    for (expected_hashes, expected_frames) |expected_hash, expected_frame| {
        const got = cache.copy(gpa, expected_hash) orelse return error.TestUnexpectedResult;
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, expected_frame, got);
    }
    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 3), stats.entries);
    try testing.expectEqual(@as(usize, "local".len + remote_budget), stats.bytes);
    try testing.expectEqual(@as(u64, 1), stats.evictions);
    try testing.expectEqual(@as(u64, 0), stats.write_failures);
}

test "qset disk cache: bounded remote entries are restored across reopen" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &path_buf);

    const local_hash: [32]u8 = @splat(0x40);
    var first = try testFrame(gpa, 0x41);
    defer first.deinit(gpa);
    var second = try testFrame(gpa, 0x42);
    defer second.deinit(gpa);
    var third = try testFrame(gpa, 0x43);
    defer third.deinit(gpa);
    const limits: Limits = .{
        .max_entries = 3,
        .max_bytes = 1024,
        .max_entry_bytes = 256,
    };

    {
        var cache = try QsetDiskCache.openWithLimits(
            gpa,
            io,
            data_dir,
            limits,
            .{ .hash = local_hash, .framed = "local" },
        );
        defer cache.deinit();
        cache.rememberRequested(first.hash, first.bytes);
        cache.rememberRequested(second.hash, second.bytes);
        cache.rememberRequested(third.hash, third.bytes);
    }

    var reopened = try QsetDiskCache.openWithLimits(
        gpa,
        io,
        data_dir,
        limits,
        .{ .hash = local_hash, .framed = "local" },
    );
    defer reopened.deinit();

    if (reopened.copy(gpa, first.hash)) |unexpected| {
        gpa.free(unexpected);
        return error.TestExpectedEqual;
    }
    const expected_hashes = [_][32]u8{ local_hash, second.hash, third.hash };
    const expected_frames = [_][]const u8{ "local", second.bytes, third.bytes };
    for (expected_hashes, expected_frames) |expected_hash, expected_frame| {
        const got = reopened.copy(gpa, expected_hash) orelse return error.TestUnexpectedResult;
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, expected_frame, got);
    }
    const stats = reopened.snapshot();
    try testing.expectEqual(@as(usize, 3), stats.entries);
    try testing.expectEqual(@as(usize, "local".len + second.bytes.len + third.bytes.len), stats.bytes);
}

test "qset disk cache: startup prunes owned overflow and stale temps but preserves unrelated names" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "data/qsets");

    const local_hash: [32]u8 = @splat(0x50);
    const remote_hashes = [_][32]u8{
        @splat(0x51),
        @splat(0x52),
        @splat(0x53),
        @splat(0x54),
        @splat(0x55),
    };
    var name_buf: [QsetDiskCache.filename_len]u8 = undefined;
    var path_buf: [128]u8 = undefined;

    try writeTestFile(&tmp, io, try std.fmt.bufPrint(&path_buf, "data/qsets/{s}", .{finalName(local_hash, &name_buf)}), "stale-local");
    for (remote_hashes, 0..) |hash, i| {
        const payloads = [_][]const u8{ "aaaaa", "bbbbb", "ccccc", "ddddd", "eeeee" };
        const path = try std.fmt.bufPrint(&path_buf, "data/qsets/{s}", .{finalName(hash, &name_buf)});
        try writeTestFile(&tmp, io, path, payloads[i]);
    }

    const temp_final = finalName(remote_hashes[0], &name_buf);
    const stale_temp = try std.fmt.bufPrint(&path_buf, "data/qsets/{s}.tmp.0123456789abcdef", .{temp_final});
    try writeTestFile(&tmp, io, stale_temp, "partial");
    try writeTestFile(&tmp, io, "data/qsets/notes.txt", "operator note");
    try writeTestFile(&tmp, io, "data/qsets/5151515151515151515151515151515151515151515151515151515151515151.bin.bak", "backup");
    try writeTestFile(&tmp, io, "data/qsets/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.bin", "uppercase");
    try tmp.dir.createDirPath(io, "data/qsets/7777777777777777777777777777777777777777777777777777777777777777.bin");

    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 15,
        .max_entry_bytes = 8,
    }, .{ .hash = local_hash, .framed = "local" });
    defer cache.deinit();

    const stats = cache.snapshot();
    try testing.expect(stats.entries <= 3);
    try testing.expect(stats.bytes <= 15);
    try testing.expect(!stats.degraded);

    var qsets = try tmp.dir.openDir(io, "data/qsets", .{ .iterate = true });
    defer qsets.close(io);
    var iterator = qsets.iterate();
    var managed_finals: usize = 0;
    while (try iterator.next(io)) |entry| {
        if (parseFinalName(entry.name) != null and entry.kind == .file) managed_finals += 1;
    }
    try testing.expectEqual(stats.entries, managed_finals);
    try testing.expect(managed_finals <= 3);

    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, stale_temp, .{}));
    _ = try tmp.dir.statFile(io, "data/qsets/notes.txt", .{});
    _ = try tmp.dir.statFile(io, "data/qsets/5151515151515151515151515151515151515151515151515151515151515151.bin.bak", .{});
    _ = try tmp.dir.statFile(io, "data/qsets/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.bin", .{});
    const operator_dir = try tmp.dir.statFile(io, "data/qsets/7777777777777777777777777777777777777777777777777777777777777777.bin", .{ .follow_symlinks = false });
    try testing.expectEqual(std.Io.File.Kind.directory, operator_dir.kind);

    const local_path = try std.fmt.bufPrint(&path_buf, "data/qsets/{s}", .{finalName(local_hash, &name_buf)});
    const local_disk = try tmp.dir.readFileAlloc(io, local_path, gpa, .limited(9));
    defer gpa.free(local_disk);
    try testing.expectEqualSlices(u8, "local", local_disk);
}

test "qset disk cache: startup memory is bounded by the configured entry cap" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "data/qsets");

    var name_buf: [QsetDiskCache.filename_len]u8 = undefined;
    var path_buf: [128]u8 = undefined;
    for (0..256) |i| {
        var hash: [32]u8 = @splat(@as(u8, @intCast(i)));
        hash[0] = @intCast(i / 256);
        const path = try std.fmt.bufPrint(&path_buf, "data/qsets/{s}", .{finalName(hash, &name_buf)});
        try writeTestFile(&tmp, io, path, "remote");
    }

    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);
    var storage: [1024]u8 = undefined;
    var bounded = std.heap.FixedBufferAllocator.init(&storage);
    var cache = try QsetDiskCache.openWithLimits(bounded.allocator(), io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 32,
        .max_entry_bytes = 16,
    }, .{ .hash = @splat(0xff), .framed = "local" });
    defer cache.deinit();

    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 3), stats.entries);
    try testing.expect(stats.bytes <= 32);
    try testing.expect(!stats.degraded);
    try testing.expect(bounded.end_index <= storage.len);
}

test "qset disk cache: corrupt and wrong-hash restart entries become bounded misses" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "data/qsets");

    var valid_for_another_hash = try testFrame(gpa, 0xd1);
    defer valid_for_another_hash.deinit(gpa);
    const wrong_hash: [32]u8 = @splat(0xd2);
    const malformed_hash: [32]u8 = @splat(0xd3);
    try testing.expect(!std.mem.eql(u8, &wrong_hash, &valid_for_another_hash.hash));

    var name_buf: [QsetDiskCache.filename_len]u8 = undefined;
    var path_buf: [128]u8 = undefined;
    const wrong_path = try std.fmt.bufPrint(&path_buf, "data/qsets/{s}", .{finalName(wrong_hash, &name_buf)});
    try writeTestFile(&tmp, io, wrong_path, valid_for_another_hash.bytes);
    const malformed_path = try std.fmt.bufPrint(&path_buf, "data/qsets/{s}", .{finalName(malformed_hash, &name_buf)});
    try writeTestFile(&tmp, io, malformed_path, "malformed");

    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 4,
        .max_bytes = 1024,
        .max_entry_bytes = 256,
    }, .{ .hash = @splat(0xd0), .framed = "local" });
    defer cache.deinit();
    try testing.expectEqual(@as(usize, 3), cache.snapshot().entries);

    try testing.expectEqual(@as(?[]u8, null), cache.copy(gpa, wrong_hash));
    try testing.expectEqual(@as(?[]u8, null), cache.copy(gpa, malformed_hash));
    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 1), stats.entries);
    try testing.expectEqual(@as(u64, 2), stats.read_failures);
    try testing.expectEqual(@as(u64, 2), stats.evictions);
    try testing.expect(stats.degraded);
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, wrong_path, .{}));
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, malformed_path, .{}));
}

test "qset disk cache: mixed-case path alias is preserved and disables writes" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "data/qsets");

    const local_hash: [32]u8 = @splat(0xab);
    var canonical_buf: [QsetDiskCache.filename_len]u8 = undefined;
    const canonical = finalName(local_hash, &canonical_buf);
    var alias_buf: [QsetDiskCache.filename_len]u8 = undefined;
    _ = std.ascii.upperString(&alias_buf, canonical);
    var alias_path_buf: [128]u8 = undefined;
    const alias_path = try std.fmt.bufPrint(&alias_path_buf, "data/qsets/{s}", .{&alias_buf});
    try writeTestFile(&tmp, io, alias_path, "operator-owned");

    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 64,
        .max_entry_bytes = 32,
    }, .{ .hash = local_hash, .framed = "local" });
    defer cache.deinit();

    const after_open = cache.snapshot();
    try testing.expectEqual(@as(usize, 1), after_open.entries);
    try testing.expectEqual(@as(u64, 1), after_open.write_failures);
    try testing.expect(after_open.degraded);
    cache.rememberRequested(@splat(0xac), "not-written");
    try testing.expectEqual(@as(u64, 2), cache.snapshot().write_failures);

    const alias_bytes = try tmp.dir.readFileAlloc(io, alias_path, gpa, .limited(32));
    defer gpa.free(alias_bytes);
    try testing.expectEqualSlices(u8, "operator-owned", alias_bytes);
    const local = cache.copy(gpa, local_hash) orelse return error.TestUnexpectedResult;
    defer gpa.free(local);
    try testing.expectEqualSlices(u8, "local", local);
}

test "qset disk cache: a qsets root symlink degrades to memory-only" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "data");
    try tmp.dir.createDirPath(io, "outside");
    try writeTestFile(&tmp, io, "outside/sentinel", "untouched");
    try tmp.dir.symLink(io, "../outside", "data/qsets", .{ .is_directory = true });

    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);
    const local_hash: [32]u8 = @splat(0xe0);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 64,
        .max_entry_bytes = 32,
    }, .{ .hash = local_hash, .framed = "local" });
    defer cache.deinit();

    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 1), stats.entries);
    try testing.expectEqual(@as(u64, 1), stats.write_failures);
    try testing.expect(stats.degraded);
    const sentinel = try tmp.dir.readFileAlloc(io, "outside/sentinel", gpa, .limited(16));
    defer gpa.free(sentinel);
    try testing.expectEqualSlices(u8, "untouched", sentinel);
    const local = cache.copy(gpa, local_hash) orelse return error.TestUnexpectedResult;
    defer gpa.free(local);
    try testing.expectEqualSlices(u8, "local", local);
}

test "qset disk cache: startup removes exact cache symlinks without touching their targets" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "data/qsets");
    try writeTestFile(&tmp, io, "outside-final", "final-target");
    try writeTestFile(&tmp, io, "outside-temp", "temp-target");

    const remote_hash: [32]u8 = @splat(0xe1);
    var name_buf: [QsetDiskCache.filename_len]u8 = undefined;
    const final = finalName(remote_hash, &name_buf);
    var final_path_buf: [128]u8 = undefined;
    const final_path = try std.fmt.bufPrint(&final_path_buf, "data/qsets/{s}", .{final});
    try tmp.dir.symLink(io, "../../outside-final", final_path, .{});

    var temp_path_buf: [128]u8 = undefined;
    const temp_path = try std.fmt.bufPrint(&temp_path_buf, "data/qsets/{s}.tmp.0123456789abcdef", .{final});
    try tmp.dir.symLink(io, "../../outside-temp", temp_path, .{});

    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);
    const local_hash: [32]u8 = @splat(0xe2);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 64,
        .max_entry_bytes = 32,
    }, .{ .hash = local_hash, .framed = "local" });
    defer cache.deinit();

    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 1), stats.entries);
    try testing.expectEqual(@as(u64, 1), stats.evictions);
    try testing.expectEqual(@as(u64, 0), stats.write_failures);
    try testing.expect(!stats.degraded);
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, final_path, .{ .follow_symlinks = false }));
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, temp_path, .{ .follow_symlinks = false }));

    const final_target = try tmp.dir.readFileAlloc(io, "outside-final", gpa, .limited(32));
    defer gpa.free(final_target);
    try testing.expectEqualSlices(u8, "final-target", final_target);
    const temp_target = try tmp.dir.readFileAlloc(io, "outside-temp", gpa, .limited(32));
    defer gpa.free(temp_target);
    try testing.expectEqualSlices(u8, "temp-target", temp_target);
}

test "qset disk cache: every startup allocation failure unwinds or degrades without leaks" {
    const io = testing.io;
    var swept: usize = 0;
    var fail_index: usize = 0;
    while (fail_index < 16) : (fail_index += 1) {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        try tmp.dir.createDirPath(io, "data/qsets");

        const remote_hash: [32]u8 = @splat(0xa1);
        var name_buf: [QsetDiskCache.filename_len]u8 = undefined;
        var file_path_buf: [128]u8 = undefined;
        const file_path = try std.fmt.bufPrint(&file_path_buf, "data/qsets/{s}", .{finalName(remote_hash, &name_buf)});
        try writeTestFile(&tmp, io, file_path, "remote");

        var data_path_buf: [128]u8 = undefined;
        const data_dir = try tmpDataDir(&tmp, &data_path_buf);
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        const opened = QsetDiskCache.openWithLimits(failing.allocator(), io, data_dir, .{
            .max_entries = 3,
            .max_bytes = 32,
            .max_entry_bytes = 16,
        }, .{ .hash = @splat(0xa0), .framed = "local" });

        if (opened) |value| {
            var cache = value;
            if (failing.has_induced_failure) {
                swept += 1;
                try testing.expect(cache.snapshot().degraded);
            }
            cache.deinit();
        } else |err| {
            swept += 1;
            try testing.expect(failing.has_induced_failure);
            try testing.expectEqual(error.OutOfMemory, err);
        }
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (!failing.has_induced_failure) break;
    }
    try testing.expect(swept >= 3);
    try testing.expect(fail_index < 16);
}

test "qset disk cache: runtime allocation failures preserve the pinned local entry" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);

    const local_hash: [32]u8 = @splat(0xb0);
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var cache = try QsetDiskCache.openWithLimits(failing.allocator(), io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 32,
        .max_entry_bytes = 16,
    }, .{ .hash = local_hash, .framed = "local" });

    failing.fail_index = failing.alloc_index;
    cache.rememberRequested(@splat(0xb1), "remote");
    try testing.expect(failing.has_induced_failure);
    const after_write = cache.snapshot();
    try testing.expectEqual(@as(usize, 1), after_write.entries);
    try testing.expectEqual(@as(usize, "local".len), after_write.bytes);
    try testing.expectEqual(@as(u64, 1), after_write.write_failures);
    try testing.expect(after_write.degraded);

    const local = cache.copy(testing.allocator, local_hash) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(local);
    try testing.expectEqualSlices(u8, "local", local);
    cache.deinit();
    try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "qset disk cache: copy allocation failure leaves remote accounting intact" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);

    var remote_frame = try testFrame(gpa, 0xc1);
    defer remote_frame.deinit(gpa);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 512,
        .max_entry_bytes = 256,
    }, .{ .hash = @splat(0xc0), .framed = "local" });
    defer cache.deinit();
    cache.rememberRequested(remote_frame.hash, remote_frame.bytes);

    var failing = testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    try testing.expectEqual(@as(?[]u8, null), cache.copy(failing.allocator(), remote_frame.hash));
    try testing.expect(failing.has_induced_failure);
    try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);

    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 2), stats.entries);
    try testing.expectEqual(@as(usize, "local".len + remote_frame.bytes.len), stats.bytes);
    try testing.expectEqual(@as(u64, 1), stats.read_failures);
    try testing.expect(stats.degraded);

    const remote = cache.copy(gpa, remote_frame.hash) orelse return error.TestUnexpectedResult;
    defer gpa.free(remote);
    try testing.expectEqualSlices(u8, remote_frame.bytes, remote);
}

test "qset disk cache: oversized final is a bounded miss and is removed from accounting" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);

    const local_hash: [32]u8 = @splat(0x60);
    const remote_hash: [32]u8 = @splat(0x61);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 32,
        .max_entry_bytes = 8,
    }, .{ .hash = local_hash, .framed = "local" });
    defer cache.deinit();
    cache.rememberRequested(remote_hash, "remote");

    var name_buf: [QsetDiskCache.filename_len]u8 = undefined;
    var path_buf: [128]u8 = undefined;
    const remote_path = try std.fmt.bufPrint(&path_buf, "data/qsets/{s}", .{finalName(remote_hash, &name_buf)});
    try writeTestFile(&tmp, io, remote_path, "123456789");

    var no_storage: [0]u8 = .{};
    var fba = std.heap.FixedBufferAllocator.init(&no_storage);
    try testing.expectEqual(@as(?[]u8, null), cache.copy(fba.allocator(), remote_hash));

    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 1), stats.entries);
    try testing.expectEqual(@as(usize, "local".len), stats.bytes);
    try testing.expectEqual(@as(u64, 1), stats.read_failures);
    try testing.expect(stats.degraded);
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, remote_path, .{}));

    const local = cache.copy(gpa, local_hash) orelse return error.TestUnexpectedResult;
    defer gpa.free(local);
    try testing.expectEqualSlices(u8, "local", local);
}

test "qset disk cache: failed atomic rename leaves no partial final or temp debris" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);

    const local_hash: [32]u8 = @splat(0x70);
    const remote_hash: [32]u8 = @splat(0x71);
    const later_hash: [32]u8 = @splat(0x72);
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 3,
        .max_bytes = 32,
        .max_entry_bytes = 16,
    }, .{ .hash = local_hash, .framed = "local" });
    defer cache.deinit();

    var name_buf: [QsetDiskCache.filename_len]u8 = undefined;
    var path_buf: [128]u8 = undefined;
    const remote_path = try std.fmt.bufPrint(&path_buf, "data/qsets/{s}", .{finalName(remote_hash, &name_buf)});
    try tmp.dir.createDirPath(io, remote_path); // Rename-over-directory must fail.
    cache.rememberRequested(remote_hash, "complete-remote");

    try testing.expectEqual(@as(?[]u8, null), cache.copy(gpa, remote_hash));
    const stats = cache.snapshot();
    try testing.expectEqual(@as(usize, 1), stats.entries);
    try testing.expectEqual(@as(u64, 1), stats.write_failures);
    try testing.expect(stats.degraded);
    cache.rememberRequested(later_hash, "later");
    try testing.expectEqual(@as(u64, 2), cache.snapshot().write_failures);
    const final_stat = try tmp.dir.statFile(io, remote_path, .{ .follow_symlinks = false });
    try testing.expectEqual(std.Io.File.Kind.directory, final_stat.kind);

    var qsets = try tmp.dir.openDir(io, "data/qsets", .{ .iterate = true });
    defer qsets.close(io);
    var iterator = qsets.iterate();
    while (try iterator.next(io)) |entry| try testing.expect(!isStaleTempName(entry.name));

    const later_path = try std.fmt.bufPrint(&path_buf, "data/qsets/{s}", .{finalName(later_hash, &name_buf)});
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, later_path, .{}));

    const local = cache.copy(gpa, local_hash) orelse return error.TestUnexpectedResult;
    defer gpa.free(local);
    try testing.expectEqualSlices(u8, "local", local);
}

test "qset disk cache: concurrent remember and copy expose only complete bounded entries" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var data_path_buf: [128]u8 = undefined;
    const data_dir = try tmpDataDir(&tmp, &data_path_buf);

    const local_hash: [32]u8 = @splat(0x80);
    var frames: [8]TestFrame = undefined;
    var built: usize = 0;
    defer for (frames[0..built]) |*frame| frame.deinit(gpa);
    for (&frames, 0..) |*frame, i| {
        frame.* = try testFrame(gpa, @intCast(i + 1));
        built += 1;
    }
    var cache = try QsetDiskCache.openWithLimits(gpa, io, data_dir, .{
        .max_entries = 4,
        .max_bytes = 1024,
        .max_entry_bytes = 256,
    }, .{ .hash = local_hash, .framed = "local" });
    defer cache.deinit();

    const Worker = struct {
        fn run(c: *QsetDiskCache, available: []const TestFrame, worker: usize, failed: *std.atomic.Value(bool)) void {
            for (0..200) |iteration| {
                const frame = available[(iteration + worker) % available.len];
                if ((iteration + worker) % 2 == 0) {
                    c.rememberRequested(frame.hash, frame.bytes);
                } else if (c.copy(std.heap.page_allocator, frame.hash)) |got| {
                    if (!std.mem.eql(u8, frame.bytes, got)) failed.store(true, .release);
                    std.heap.page_allocator.free(got);
                }
            }
        }
    };

    var failed = std.atomic.Value(bool).init(false);
    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*thread, worker| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &cache, &frames, worker, &failed });
    }
    for (threads) |thread| thread.join();
    try testing.expect(!failed.load(.acquire));

    const stats = cache.snapshot();
    try testing.expect(stats.entries <= 4);
    try testing.expect(stats.bytes <= 1024);
    try testing.expectEqual(@as(u64, 0), stats.read_failures);
    try testing.expectEqual(@as(u64, 0), stats.write_failures);

    var qsets = try tmp.dir.openDir(io, "data/qsets", .{ .iterate = true });
    defer qsets.close(io);
    var iterator = qsets.iterate();
    var managed_finals: usize = 0;
    while (try iterator.next(io)) |entry| {
        try testing.expect(!isStaleTempName(entry.name));
        if (parseFinalName(entry.name) != null and entry.kind == .file) managed_finals += 1;
    }
    try testing.expectEqual(stats.entries, managed_finals);

    const local = cache.copy(gpa, local_hash) orelse return error.TestUnexpectedResult;
    defer gpa.free(local);
    try testing.expectEqualSlices(u8, "local", local);
}

fn writeTestFile(tmp: *std.testing.TmpDir, io: std.Io, path: []const u8, bytes: []const u8) !void {
    var file = try tmp.dir.createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

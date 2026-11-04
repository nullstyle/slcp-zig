//! Private native durability syscall boundary. Test faults replace only the
//! selected syscall result; callers still perform real file I/O and recovery.
const std = @import("std");
const builtin = @import("builtin");

pub const Testing = if (builtin.is_test) struct {
    pub const Operation = enum { file_sync, media_flush, directory_sync };
    pub const Fault = struct {
        operation: Operation,
        handle: ?std.Io.File.Handle = null,
        after: usize = 0,
    };
    pub threadlocal var fault: ?Fault = null;
    pub threadlocal var injected: usize = 0;

    fn fails(operation: Operation, handle: std.Io.File.Handle) bool {
        const f = if (fault) |*value| value else return false;
        if (f.operation != operation or (f.handle != null and f.handle.? != handle)) return false;
        if (f.after != 0) {
            f.after -= 1;
            return false;
        }
        injected += 1;
        return true;
    }
} else struct {};

pub fn syncFile(io: std.Io, file: std.Io.File) !void {
    if (comptime builtin.is_test) {
        if (Testing.fails(.file_sync, file.handle)) return error.FileSyncFailed;
    }
    try file.sync(io);
    try flushMedia(file);
}

/// Flush a preceding file or directory sync out of the device cache on
/// macOS. Directory-entry publication must invoke this AFTER directory sync.
pub fn flushMedia(file: std.Io.File) !void {
    if (comptime builtin.os.tag == .macos) {
        if (mediaFlush(file) < 0) return error.FullSyncFailed;
    }
}

/// Sync namespace metadata through a readable directory descriptor. Unlike
/// file sync this does not request FULLFSYNC on the directory itself.
pub fn syncDirectory(io: std.Io, dir: std.Io.Dir) !void {
    if (comptime builtin.is_test) {
        if (Testing.fails(.directory_sync, dir.handle)) return error.DirectorySyncFailed;
    }
    try (std.Io.File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

/// Persist every containing directory entry when a convenience API may have
/// recursively created the path. The caller follows this with flushMedia on
/// a file on the same supported local filesystem.
pub fn syncParentDirectories(io: std.Io, path: []const u8) !void {
    var current = std.fs.path.dirname(path) orelse ".";
    while (true) {
        const dir = try std.Io.Dir.cwd().openDir(io, current, .{ .iterate = true });
        defer dir.close(io);
        try syncDirectory(io, dir);
        const parent = std.fs.path.dirname(current) orelse {
            if (!std.fs.path.isAbsolute(current) and !std.mem.eql(u8, current, ".")) {
                current = ".";
                continue;
            }
            break;
        };
        if (std.mem.eql(u8, parent, current)) break;
        current = parent;
    }
}

fn mediaFlush(file: std.Io.File) c_int {
    if (comptime builtin.is_test) {
        if (Testing.fails(.media_flush, file.handle)) return -1;
    }
    return std.c.fcntl(file.handle, std.c.F.FULLFSYNC);
}

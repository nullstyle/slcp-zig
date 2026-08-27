//! Ed25519 key file (design §11 keys UX).
//!
//! `loadOrCreate(path)` reads a 32-byte secret seed from `path`, or generates
//! a fresh one (from OS entropy via `io`) and writes it with 0600 permissions
//! the first time. The public key (nodeId) is derived from the seed.
//!
//! Creation is atomic AND durable: the seed is written to an unnamed/temp
//! file (0600 from birth), fsync'd (plus F_FULLFSYNC on macOS, where fsync
//! alone does not flush the drive cache), and only then linked into place
//! under the final name. A crash, ENOSPC, or power loss mid-ceremony leaves
//! either no key file at all (next boot mints a fresh identity — fine, the
//! old one never existed durably) or the complete 32-byte file. It can never
//! leave a partial file that bricks startup, and it can never expose a name
//! whose seed bytes are not yet on disk (which could otherwise mint a NEW
//! identity on the next boot — identity-level equivocation).
//!
//! Watcher nodes call `ephemeral(io)` instead: a random nodeId that never
//! signs (the engine needs one for its maps; §11).
//!
//! ==== IMPLEMENTATION BRIEF (M5 agent) ====================================
//! Public interface below is FROZEN — implement the bodies + tests, do not
//! change signatures or field names.
//!
//!   * File format: exactly 32 raw bytes (the seed). Not hex — raw. A file of
//!     any other length is `error.BadKeyFile`.
//!   * loadOrCreate: if the file exists, read+validate length, derive pubkey
//!     via `core.crypto.publicKeyFromSeed`. If absent, generate 32 random
//!     bytes from `io` (std.Io random / CSPRNG — fail closed on no entropy),
//!     write atomically with mode 0600, then derive. Create parent dirs? No —
//!     the seed lives at a caller-given path; assume its dir exists (Node
//!     creates data_dir; the key file is separate and its dir is the cwd or a
//!     caller path). Missing parent dir → surface the fs error.
//!   * ephemeral: 32 random bytes → pubkey; seed is retained (KeyPair.seed)
//!     but the Node never passes it as secret_seed in watcher mode.
//!   * Tests: create-then-load round-trip (same pubkey); reject wrong-length
//!     file; two ephemeral() calls differ; created file has 0600 perms.
//!   * Use a tmp dir (std.testing.tmpDir) for file tests.
//! ========================================================================

const std = @import("std");
const builtin = @import("builtin");
const core = @import("slcp-core");

pub const Error = error{ BadKeyFile, EntropyUnavailable } || std.mem.Allocator.Error;

pub const KeyPair = struct {
    seed: [32]u8,
    public_key: [32]u8,
};

/// Load the seed at `path`, or create a fresh 0600 key file there.
pub fn loadOrCreate(io: std.Io, path: []const u8) !KeyPair {
    const cwd = std.Io.Dir.cwd();
    var seed: [32]u8 = undefined;

    if (cwd.openFile(io, path, .{})) |opened| {
        // Existing key file: it must be exactly 32 raw seed bytes. The buffer
        // is one byte longer than the seed so an over-length file reads 33 and
        // fails the `!= 32` check alongside a short one.
        var file = opened;
        defer file.close(io);
        var buf: [33]u8 = undefined;
        const n = try file.readPositionalAll(io, &buf, 0);
        if (n != 32) return error.BadKeyFile;
        seed = buf[0..32].*;
    } else |err| switch (err) {
        // First run: mint fresh OS entropy and commit it atomically + durably
        // with owner-only perms set at creation, so the seed never exists on
        // disk world-readable and the final name never refers to a partial or
        // volatile file. Ceremony: temp file (0600) → write → fsync (and
        // F_FULLFSYNC on macOS) → link into place. `link` fails with
        // PathAlreadyExists rather than replacing, so a concurrently created
        // key is never clobbered. A missing parent dir surfaces here as the
        // underlying fs error.
        error.FileNotFound => {
            try io.randomSecure(&seed);
            var af = try cwd.createFileAtomic(io, path, .{
                .permissions = std.Io.File.Permissions.fromMode(0o600),
            });
            // Cleans up the temp file on any failure below; a no-op on the
            // handles that `link` already consumed on success.
            defer af.deinit(io);
            try af.file.writeStreamingAll(io, &seed);
            // Make the seed bytes durable BEFORE the name appears: a power
            // loss after link-but-before-flush would otherwise leave a named
            // key file whose content evaporates, so the next boot silently
            // mints a different identity.
            try af.file.sync(io);
            if (comptime builtin.os.tag == .macos) {
                // fsync(2) on macOS does not flush the drive's own cache;
                // F_FULLFSYNC asks for a true flush to media. Filesystems
                // that lack it (e.g. SMB) fail the fcntl — the plain fsync
                // above is then the best available, so this is deliberately
                // non-fatal (the same fallback SQLite uses).
                _ = std.c.fcntl(af.file.handle, std.posix.F.FULLFSYNC);
            }
            try af.link(io);
        },
        else => return err,
    }

    return .{ .seed = seed, .public_key = try core.crypto.publicKeyFromSeed(seed) };
}

/// A random, non-signing identity for watcher mode.
pub fn ephemeral(io: std.Io) !KeyPair {
    var seed: [32]u8 = undefined;
    try io.randomSecure(&seed);
    return .{ .seed = seed, .public_key = try core.crypto.publicKeyFromSeed(seed) };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// The absolute path of `name` inside `tmp`, written into `buf`. Keeps the file
/// tests off the tmpDir internal layout: `loadOrCreate` resolves paths against
/// `Dir.cwd()`, and an absolute path is cwd-independent.
fn tmpPath(io: std.Io, tmp: *std.testing.TmpDir, buf: []u8, name: []const u8) ![]const u8 {
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buf);
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ dir_buf[0..dir_len], name });
}

test "loadOrCreate: create then load round-trips to the same key" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(io, &tmp, &path_buf, "node.seed");

    const created = try loadOrCreate(io, path); // first call generates
    const loaded = try loadOrCreate(io, path); // second call reads it back

    try testing.expectEqualSlices(u8, &created.seed, &loaded.seed);
    try testing.expectEqualSlices(u8, &created.public_key, &loaded.public_key);
    // The public key really is the Ed25519 pubkey of the stored seed.
    const derived = try core.crypto.publicKeyFromSeed(created.seed);
    try testing.expectEqualSlices(u8, &derived, &created.public_key);
}

// A wrong-length key file is ALWAYS BadKeyFile — never silently overwritten
// with a fresh key. With atomic creation such a file cannot be a torn write
// from us; it is operator damage (truncation, edit, wrong file), and minting
// a new identity over it would be silent equivocation at the identity level.
// Recovery is a deliberate, manual `rm` of the key file by the operator.
test "loadOrCreate: a key file that is not exactly 32 bytes is rejected" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // 31 bytes: one short of the seed length.
    {
        const short: [31]u8 = @splat(0xab);
        var f = try tmp.dir.createFile(io, "short.seed", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, &short);
    }
    var short_buf: [std.fs.max_path_bytes]u8 = undefined;
    const short_path = try tmpPath(io, &tmp, &short_buf, "short.seed");
    try testing.expectError(error.BadKeyFile, loadOrCreate(io, short_path));

    // 33 bytes: one past the seed length.
    {
        const long: [33]u8 = @splat(0xcd);
        var f = try tmp.dir.createFile(io, "long.seed", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, &long);
    }
    var long_buf: [std.fs.max_path_bytes]u8 = undefined;
    const long_path = try tmpPath(io, &tmp, &long_buf, "long.seed");
    try testing.expectError(error.BadKeyFile, loadOrCreate(io, long_path));
}

test "ephemeral: two calls produce distinct random identities" {
    const io = testing.io;
    const a = try ephemeral(io);
    const b = try ephemeral(io);
    try testing.expect(!std.mem.eql(u8, &a.seed, &b.seed));
    try testing.expect(!std.mem.eql(u8, &a.public_key, &b.public_key));
    // Even a non-signing identity carries a valid derived public key.
    const derived = try core.crypto.publicKeyFromSeed(a.seed);
    try testing.expectEqualSlices(u8, &derived, &a.public_key);
}

test "loadOrCreate: a freshly created key file is complete (32 bytes) and mode 0600" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(io, &tmp, &path_buf, "perms.seed");
    _ = try loadOrCreate(io, path);

    const st = try tmp.dir.statFile(io, "perms.seed", .{});
    // Atomic creation: once the name exists it is the complete seed, never a
    // partial write (link happens only after write + fsync succeed).
    try testing.expectEqual(@as(u64, 32), st.size);
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);

    // And no temp-file debris is left behind: the key file is the only entry.
    var it = tmp.dir.iterate();
    var entries: usize = 0;
    while (try it.next(io)) |entry| {
        entries += 1;
        try testing.expectEqualStrings("perms.seed", entry.name);
    }
    try testing.expectEqual(@as(usize, 1), entries);
}

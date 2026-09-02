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

pub const Error = error{ BadKeyFile, EntropyUnavailable, KeyFileExists } || std.mem.Allocator.Error;

// Explicit error sets (M6 S6 API freeze). These are signature-only
// annotations: each is the union of what the body's callees declare, so the
// behaviour is unchanged — but the snapshot gate now pins a NAMED contract a
// consumer can `switch` on, instead of an inferred set that silently follows
// std's file-system error vocabulary.
/// `error.IdentityElement` from deriving the public key of a seed.
pub const DeriveError = error{IdentityElement};
/// Reading an existing key file: open + positional read + derive, plus
/// `BadKeyFile` for a wrong-length file.
pub const LoadError = error{BadKeyFile} ||
    std.Io.File.OpenError ||
    std.Io.File.ReadPositionalError ||
    DeriveError;
/// The first-run mint ceremony: entropy, atomic 0600 create, write, fsync,
/// link into place.
pub const MintError = std.Io.RandomSecureError ||
    std.Io.Dir.CreateFileAtomicError ||
    std.Io.File.Writer.Error ||
    std.Io.File.SyncError ||
    std.Io.File.Atomic.LinkError;
/// `loadOrCreate`: a load, or (on `FileNotFound`) a mint.
pub const LoadOrCreateError = LoadError || MintError;
/// `createNew`: the existence probe (open), a mint, `KeyFileExists`, derive.
pub const CreateNewError = error{KeyFileExists} ||
    std.Io.File.OpenError ||
    MintError ||
    DeriveError;

pub const KeyPair = struct {
    seed: [32]u8,
    public_key: [32]u8,
};

/// Load the seed at `path`, or create a fresh 0600 key file there.
pub fn loadOrCreate(io: std.Io, path: []const u8) LoadOrCreateError!KeyPair {
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
        error.FileNotFound => try mint(io, cwd, path, &seed),
        else => return err,
    }

    return .{ .seed = seed, .public_key = try core.crypto.publicKeyFromSeed(seed) };
}

/// Load the seed at `path`; NEVER mints. An absent file is
/// `error.FileNotFound` (and no file appears); a wrong-length file is
/// `error.BadKeyFile`. The `Node.create` path uses this so a typo in
/// `.key_file` cannot silently mint a second identity.
pub fn load(io: std.Io, path: []const u8) LoadError!KeyPair {
    const cwd = std.Io.Dir.cwd();
    var file = try cwd.openFile(io, path, .{});
    defer file.close(io);
    var buf: [33]u8 = undefined;
    const n = try file.readPositionalAll(io, &buf, 0);
    if (n != 32) return error.BadKeyFile;
    const seed = buf[0..32].*;
    return .{ .seed = seed, .public_key = try core.crypto.publicKeyFromSeed(seed) };
}

/// The permission bits (`mode & 0o777`) of the file at `path` — the load-time
/// companion of the 0600 mint contract. `mint` writes owner-only; this is
/// how a caller finds out whether a `cp`/`scp`/umask-022 restore loosened it.
/// Zero on targets without POSIX modes (a `stat` failure surfaces as is).
pub fn modeOf(io: std.Io, path: []const u8) std.Io.Dir.StatFileError!u32 {
    if (comptime std.posix.mode_t == u0 or builtin.os.tag == .windows) return 0;
    const st = try std.Io.Dir.cwd().statFile(io, path, .{});
    return st.permissions.toMode() & 0o777;
}

/// `true` when `mode` grants group or other ANY access (`mode & 0o077`):
/// a seed such a file holds is readable by every account in the group or on
/// the machine. Owner-only modes (0600, 0400, 0700) are fine.
pub fn modeTooOpen(mode: u32) bool {
    return mode & 0o077 != 0;
}

/// Mint a fresh key file at `path` (0600, atomic + durable — the same
/// ceremony as `loadOrCreate`'s first run). `error.KeyFileExists` if any
/// file already sits there — a key file is never overwritten.
pub fn createNew(io: std.Io, path: []const u8) CreateNewError!KeyPair {
    const cwd = std.Io.Dir.cwd();
    if (cwd.openFile(io, path, .{})) |opened| {
        var file = opened;
        file.close(io);
        return error.KeyFileExists;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    var seed: [32]u8 = undefined;
    mint(io, cwd, path, &seed) catch |err| switch (err) {
        // Lost a race with a concurrent creator: `link` refuses to replace.
        error.PathAlreadyExists => return error.KeyFileExists,
        else => return err,
    };
    return .{ .seed = seed, .public_key = try core.crypto.publicKeyFromSeed(seed) };
}

/// First-run ceremony: fresh OS entropy committed atomically + durably with
/// owner-only perms set at creation, so the seed never exists on disk
/// world-readable and the final name never refers to a partial or volatile
/// file. Temp file (0600) → write → fsync (and F_FULLFSYNC on macOS) → link
/// into place. `link` fails with PathAlreadyExists rather than replacing, so
/// a concurrently created key is never clobbered. A missing parent dir
/// surfaces here as the underlying fs error (FileNotFound).
fn mint(io: std.Io, cwd: std.Io.Dir, path: []const u8, seed: *[32]u8) MintError!void {
    try io.randomSecure(seed);
    var af = try cwd.createFileAtomic(io, path, .{
        .permissions = std.Io.File.Permissions.fromMode(0o600),
    });
    // Cleans up the temp file on any failure below; a no-op on the
    // handles that `link` already consumed on success.
    defer af.deinit(io);
    try af.file.writeStreamingAll(io, seed);
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

// Non-vacuity: dropping the pre-check AND the PathAlreadyExists mapping in
// `createNew` lets the second call mint over the first (the bytes-unchanged
// assertion goes red); making `load` fall through to `mint` on FileNotFound
// makes the "no file appears" assertion red.
test "createNew twice is KeyFileExists (bytes unchanged); load on an absent path is FileNotFound and mints nothing" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(io, &tmp, &path_buf, "new.seed");

    // load never mints.
    try testing.expectError(error.FileNotFound, load(io, path));
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "new.seed", .{}));

    const first = try createNew(io, path);
    try testing.expectError(error.KeyFileExists, createNew(io, path));
    const st = try tmp.dir.statFile(io, "new.seed", .{});
    try testing.expectEqual(@as(u64, 32), st.size);
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);

    // The bytes are the first mint's, and load agrees with loadOrCreate.
    const loaded = try load(io, path);
    try testing.expectEqualSlices(u8, &first.seed, &loaded.seed);
    try testing.expectEqualSlices(u8, &first.public_key, &loaded.public_key);
    const via_loc = try loadOrCreate(io, path);
    try testing.expectEqualSlices(u8, &first.seed, &via_loc.seed);

    // No temp-file debris.
    var it = tmp.dir.iterate();
    var entries: usize = 0;
    while (try it.next(io)) |entry| {
        entries += 1;
        try testing.expectEqualStrings("new.seed", entry.name);
    }
    try testing.expectEqual(@as(usize, 1), entries);
}

// Pins the S8 finding "A world-readable key file (mode 0644) is accepted
// silently despite the documented 0600 contract": the load side can now SEE
// the mode, and group/other bits (0o077) are exactly what `Node.create`
// refuses with `KeyFileTooPermissive` (S8b) and `slcp key show` warns about. Red before the fix: neither `modeOf` nor `modeTooOpen`
// existed — nothing on the load path looked at the mode at all. Ablations:
// masking with 0o007 instead of 0o077 lets the 0640 case through (red);
// returning the raw mode without `& 0o777` breaks the equality on file
// systems that set the type bits (red).
test "modeOf/modeTooOpen: a minted key file is owner-only; 0640, 0644 and 0666 are too open" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(io, &tmp, &path_buf, "mode.seed");
    _ = try createNew(io, path);

    // The mint contract: owner-only.
    try testing.expectEqual(@as(u32, 0o600), try modeOf(io, path));
    try testing.expect(!modeTooOpen(try modeOf(io, path)));

    // Anything a `cp`/`scp`/umask-022 restore leaves behind is too open.
    for ([_]u32{ 0o640, 0o644, 0o666 }) |mode| {
        try tmp.dir.setFilePermissions(io, "mode.seed", std.Io.File.Permissions.fromMode(@intCast(mode)), .{});
        try testing.expectEqual(mode, try modeOf(io, path));
        try testing.expect(modeTooOpen(mode));
        // The keys layer itself still loads it: the refusal is Node.create's
        // policy (and `key show` must still be able to print the public key
        // of a loose file while telling the operator to tighten it).
        _ = try load(io, path);
    }

    // Owner-only variants stay quiet (0400 is a legitimate read-only seed).
    try testing.expect(!modeTooOpen(0o400));
    try testing.expect(!modeTooOpen(0o700));
    // An absent file is the stat error, not a false "fine".
    var absent_buf: [std.fs.max_path_bytes]u8 = undefined;
    const absent = try tmpPath(io, &tmp, &absent_buf, "absent.seed");
    try testing.expectError(error.FileNotFound, modeOf(io, absent));
}

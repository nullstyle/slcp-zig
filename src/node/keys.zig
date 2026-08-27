//! Ed25519 key file (design §11 keys UX).
//!
//! `loadOrCreate(path)` reads a 32-byte secret seed from `path`, or generates
//! a fresh one (from OS entropy via `io`) and writes it with 0600 permissions
//! the first time. The public key (nodeId) is derived from the seed.
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
const core = @import("slcp-core");

pub const Error = error{ BadKeyFile, EntropyUnavailable } || std.mem.Allocator.Error;

pub const KeyPair = struct {
    seed: [32]u8,
    public_key: [32]u8,
};

/// Load the seed at `path`, or create a fresh 0600 key file there.
pub fn loadOrCreate(io: std.Io, path: []const u8) !KeyPair {
    _ = io;
    _ = path;
    @panic("stub: keys.loadOrCreate — M5 agent");
}

/// A random, non-signing identity for watcher mode.
pub fn ephemeral(io: std.Io) !KeyPair {
    _ = io;
    @panic("stub: keys.ephemeral — M5 agent");
}

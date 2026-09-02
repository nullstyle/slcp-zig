//! `Node.create` misconfiguration matrix (plan S2 tests 1–12). A golden
//! config (secret_seed identity, twoThirdsOf including self, no peers, a
//! tmpDir data_dir, ephemeral listen port) creates cleanly; every other test
//! mutates ONE field and asserts both the `CreateError` member AND that the
//! `Diagnostic` message names the offending value.

const std = @import("std");
const builtin = @import("builtin");
const core = @import("slcp-core");
const node = @import("node.zig");
const store = @import("store.zig");
const keys = @import("keys.zig");

const Node = node.Node;
const Quorum = core.quorum.Quorum;
const NodeId = core.qset.NodeId;
const qset = core.qset;
const crypto = core.crypto;
const testing = std.testing;

fn isRoot() bool {
    return switch (builtin.os.tag) {
        .linux => std.os.linux.geteuid() == 0,
        .macos => std.c.geteuid() == 0,
        else => false,
    };
}

fn hexOf(id: NodeId) [64]u8 {
    return std.fmt.bytesToHex(id, .lower);
}

fn expectContains(hay: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, hay, needle) == null) {
        std.debug.print("\nmessage: {s}\nmissing needle: {s}\n", .{ hay, needle });
        return error.NeedleMissing;
    }
}

const Golden = struct {
    tmp: testing.TmpDir,
    dir_buf: [std.fs.max_path_bytes]u8 = undefined,
    dir_len: usize = 0,
    seeds: [3][32]u8 = undefined,
    ids: [3]NodeId = undefined,
    diag: node.Diagnostic = .{},

    fn init() !Golden {
        var g: Golden = .{ .tmp = testing.tmpDir(.{ .iterate = true }) };
        for (&g.seeds, &g.ids, 0..) |*seed, *id, i| {
            seed.* = @splat(@intCast(0x11 * (i + 1)));
            id.* = try crypto.publicKeyFromSeed(seed.*);
        }
        g.dir_len = try g.tmp.dir.realPath(testing.io, &g.dir_buf);
        return g;
    }

    fn deinit(self: *Golden) void {
        self.tmp.cleanup();
    }

    fn dataDir(self: *Golden) []const u8 {
        return self.dir_buf[0..self.dir_len];
    }

    /// `<tmp>/<name>` into `buf`.
    fn sub(self: *Golden, buf: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ self.dataDir(), name });
    }

    fn options(self: *Golden) node.Options {
        return .{
            .network = "my-counter-app v1",
            .secret_seed = self.seeds[0],
            .quorum = Quorum.twoThirdsOf(&self.ids),
            .listen_port = 0,
            .data_dir = self.dataDir(),
            .diagnostic = &self.diag,
        };
    }

    /// `create` must fail with exactly `want`, and the diagnostic must name
    /// `needle`. An unexpected success is torn down and reported.
    fn expectFail(self: *Golden, opts: node.Options, want: anyerror, needle: []const u8) !void {
        self.diag.len = 0;
        if (Node.create(testing.allocator, testing.io, opts)) |n| {
            n.deinit();
            std.debug.print("\nexpected {t}, but create succeeded\n", .{want});
            return error.UnexpectedSuccess;
        } else |err| {
            if (@as(anyerror, err) != want) {
                std.debug.print("\nexpected {t}, got {t}: {s}\n", .{ want, err, self.diag.message() });
                return error.WrongCreateError;
            }
            try expectContains(self.diag.message(), needle);
        }
    }
};

// Non-vacuity: any regression that makes the golden config refuse (a
// check that fires on a clean config, a leaked allocation in create/deinit,
// a listener that never binds) turns this red — it is the baseline every
// single-field mutation below is measured against.
test "golden config creates, binds an ephemeral port, and deinits without leaks" {
    var g = try Golden.init();
    defer g.deinit();
    const n = try Node.create(testing.allocator, testing.io, g.options());
    defer n.deinit();
    try testing.expect(n.boundPort() != 0);
    try testing.expect(!n.watcher);
    try testing.expectEqualStrings("", g.diag.message());
}

// Non-vacuity: removing the passphrase check lets `network = ""` hash to a
// valid (empty-passphrase) networkId and start; dropping the example text
// from the message fails the needle.
test "network = \"\" is NetworkPassphraseEmpty and the message shows an example passphrase" {
    var g = try Golden.init();
    defer g.deinit();
    var o = g.options();
    o.network = "";
    try g.expectFail(o, error.NetworkPassphraseEmpty, "my-counter-app v1");
}

// Non-vacuity: each arm is one `if` in create's identity block; deleting
// any of them either starts the node (ConflictingIdentity, WatcherHasIdentity,
// IdentityMismatch) or returns a different member (NoIdentity).
test "identity: none, key_file + seed, watcher + seed, node_id not matching the seed" {
    var g = try Golden.init();
    defer g.deinit();

    var none = g.options();
    none.secret_seed = null;
    try g.expectFail(none, error.NoIdentity, ".key_file");

    var both = g.options();
    both.key_file = "/nonexistent/dir/slcp.key";
    try g.expectFail(both, error.ConflictingIdentity, "/nonexistent/dir/slcp.key");

    var watcher = g.options();
    watcher.watcher = true;
    try g.expectFail(watcher, error.WatcherHasIdentity, ".secret_seed");

    var mismatch = g.options();
    mismatch.node_id = g.ids[1];
    try g.expectFail(mismatch, error.IdentityMismatch, &hexOf(g.ids[1]));
    try expectContains(g.diag.message(), &hexOf(g.ids[0]));

    // node_id alone cannot sign.
    var id_only = g.options();
    id_only.secret_seed = null;
    id_only.node_id = g.ids[0];
    try g.expectFail(id_only, error.NoIdentity, &hexOf(g.ids[0]));
}

// Non-vacuity: routing BadKeyFile to KeyFileIoFailed, or FileNotFound-of-
// parent to KeyFileIoFailed, changes the member; dropping the stat makes the
// "31 bytes" needle red; the happy path pins that a fresh key file is minted
// and its public key becomes the node id.
test "key_file: 31-byte file, missing parent dir, read-only dir, and first-run mint" {
    const io = testing.io;
    var g = try Golden.init();
    defer g.deinit();

    {
        const short: [31]u8 = @splat(0xab);
        try g.tmp.dir.writeFile(io, .{ .sub_path = "short.key", .data = &short });
    }
    var b1: [std.fs.max_path_bytes]u8 = undefined;
    const short_path = try g.sub(&b1, "short.key");
    var bad = g.options();
    bad.secret_seed = null;
    bad.key_file = short_path;
    try g.expectFail(bad, error.KeyFileBad, "31 bytes");
    try expectContains(g.diag.message(), short_path);

    var b2: [std.fs.max_path_bytes]u8 = undefined;
    const nodir_path = try g.sub(&b2, "nodir/slcp.key");
    var nodir = g.options();
    nodir.secret_seed = null;
    nodir.key_file = nodir_path;
    try g.expectFail(nodir, error.KeyFileDirMissing, "nodir/slcp.key");

    if (!isRoot()) {
        try g.tmp.dir.createDirPath(io, "ro");
        var ro = try g.tmp.dir.openDir(io, "ro", .{});
        defer ro.close(io);
        try g.tmp.dir.setFilePermissions(io, "ro", std.Io.File.Permissions.fromMode(0o500), .{});
        defer g.tmp.dir.setFilePermissions(io, "ro", std.Io.File.Permissions.fromMode(0o700), .{}) catch {};
        var b3: [std.fs.max_path_bytes]u8 = undefined;
        const ro_path = try g.sub(&b3, "ro/slcp.key");
        var denied = g.options();
        denied.secret_seed = null;
        denied.key_file = ro_path;
        try g.expectFail(denied, error.KeyFileAccessDenied, "ro/slcp.key");
    }

    var b4: [std.fs.max_path_bytes]u8 = undefined;
    const fresh_path = try g.sub(&b4, "fresh.key");
    var fresh = g.options();
    fresh.secret_seed = null;
    fresh.key_file = fresh_path;
    // The minted key is not in the golden quorum: include_self adds it, so
    // 3-of-3 becomes 3-of-4 (2-of-3 would become a sub-majority 2-of-4 and
    // be refused as UnsafeQuorum — the lint is doing its job).
    fresh.quorum = Quorum.of(3, &g.ids);
    const n = try Node.create(testing.allocator, io, fresh);
    defer n.deinit();
    const kp = try keys.load(io, fresh_path);
    try testing.expectEqualSlices(u8, &kp.public_key, &n.node_id);
    const st = try g.tmp.dir.statFile(io, "fresh.key", .{});
    try testing.expectEqual(@as(u64, 32), st.size);
}

// Non-vacuity: dropping the `> 65536` bound accepts 65537; dropping the
// journal comparison starts a node whose first nomination targets an
// already-externalized slot (StartSlotBehindJournal never fires); the
// start_slot = 6 case proves the comparison is `<=`, not `<`.
test "limits: max_value_bytes 0 / 65537, start_slot 0, start_slot behind the journal" {
    const io = testing.io;
    var g = try Golden.init();
    defer g.deinit();

    var zero = g.options();
    zero.max_value_bytes = 0;
    try g.expectFail(zero, error.MaxValueBytesOutOfRange, ".max_value_bytes 0 ");
    var big = g.options();
    big.max_value_bytes = 65537;
    try g.expectFail(big, error.MaxValueBytesOutOfRange, "65537");

    var slot0 = g.options();
    slot0.start_slot = 0;
    try g.expectFail(slot0, error.StartSlotZero, ".start_slot is 0");

    // A data_dir whose externalized.log has high-water mark 5.
    {
        var st = try store.Store.open(testing.allocator, io, g.dataDir());
        try st.appendExternalized(5, "v5");
        st.deinit();
    }
    var behind = g.options();
    behind.start_slot = 3;
    try g.expectFail(behind, error.StartSlotBehindJournal, "high-water mark 5");
    try expectContains(g.diag.message(), "resumes at 6");
    var at = g.options();
    at.start_slot = 5;
    try g.expectFail(at, error.StartSlotBehindJournal, "high-water mark 5");

    var past = g.options();
    past.start_slot = 6;
    const n = try Node.create(testing.allocator, io, past);
    n.deinit();
}

// Non-vacuity: each bad spec exercises one `validatePeerSpec` arm — wiring
// create to a permissive parser starts the node instead; removing the
// duplicate scan or the loopback+port test drops those members.
test "peers: bad specs name index and spec, duplicates, and the node's own address" {
    var g = try Golden.init();
    defer g.deinit();

    const bad_specs = [_][]const u8{ "nohost", ":7311", "a.example.com:0", "a.example.com:70000", "bad_host!:7311" };
    for (bad_specs) |spec| {
        var o = g.options();
        o.peers = &.{spec};
        try g.expectFail(o, error.BadPeerSpec, spec);
        try expectContains(g.diag.message(), ".peers[0] = \"");
    }
    // The index is the offending entry's, not always 0.
    {
        var o = g.options();
        o.peers = &.{ "a.example.com:7311", "nohost" };
        try g.expectFail(o, error.BadPeerSpec, ".peers[1] = \"nohost\"");
    }

    var dup = g.options();
    dup.peers = &.{ "x:1", "x:1" };
    try g.expectFail(dup, error.DuplicatePeer, ".peers[1] = \"x:1\" repeats .peers[0]");

    const self_specs = [_][]const u8{ "127.0.0.1:7311", "localhost:7311", "[::1]:7311", "127.0.0.9:7311" };
    for (self_specs) |spec| {
        var o = g.options();
        o.listen_port = 7311;
        o.peers = &.{spec};
        try g.expectFail(o, error.PeerIsSelf, spec);
    }
}

// Non-vacuity: each arm maps to one structural check (or its
// validateAndNormalize fallback); the UnsafeQuorum arm pins the lint gate
// and `allow_unsafe_quorum` pins that the gate — not the lint — is what
// `allow_unsafe_quorum` bypasses.
test "quorum: empty, threshold out of range, duplicate, 5-deep, 256 validators, unsafe (and allow_unsafe_quorum)" {
    var g = try Golden.init();
    defer g.deinit();

    var empty = g.options();
    empty.quorum = Quorum.of(2, &.{});
    try g.expectFail(empty, error.QuorumEmpty, "threshold 2 of 0");

    var over = g.options();
    over.quorum = Quorum.of(4, &g.ids);
    try g.expectFail(over, error.QuorumThresholdOutOfRange, "threshold 4 is outside [1, 3]");

    const dup_ids = [_]NodeId{ g.ids[0], g.ids[1], g.ids[1] };
    var dup = g.options();
    dup.quorum = Quorum.of(2, &dup_ids);
    try g.expectFail(dup, error.QuorumDuplicateNode, &hexOf(g.ids[1]));

    // 5 levels: each inner level has ONE inner set (never flattened — only
    // {1, [single validator], no inner} is lifted), the leaf has two
    // validators.
    const leaf = Quorum.of(1, g.ids[1..3]);
    const l4_arr = [_]Quorum{leaf};
    const l4 = Quorum.ofSets(1, &l4_arr);
    const l3_arr = [_]Quorum{l4};
    const l3 = Quorum.ofSets(1, &l3_arr);
    const l2_arr = [_]Quorum{l3};
    const l2 = Quorum.ofSets(1, &l2_arr);
    const l1_arr = [_]Quorum{l2};
    var deep = g.options();
    deep.quorum = Quorum.ofSets(1, &l1_arr);
    try g.expectFail(deep, error.QuorumTooDeep, "5 levels deep");

    var many: [256]NodeId = undefined;
    for (&many, 0..) |*id, i| {
        id.* = @splat(0xEE);
        id[0] = @intCast(i);
    }
    many[0] = g.ids[0]; // self included, so the count stays 256
    var too_many = g.options();
    too_many.quorum = Quorum.twoThirdsOf(&many);
    try g.expectFail(too_many, error.QuorumTooManyValidators, "256 validators");

    var unsafe = g.options();
    unsafe.quorum = Quorum.of(1, &g.ids);
    try g.expectFail(unsafe, error.UnsafeQuorum, "1-of-3");
    try expectContains(g.diag.message(), "at least 2");
    try expectContains(g.diag.message(), "allow_unsafe_quorum");

    unsafe.allow_unsafe_quorum = true;
    const n = try Node.create(testing.allocator, testing.io, unsafe);
    n.deinit();
}

fn expectedHash(spec: Quorum) ![32]u8 {
    const gpa = testing.allocator;
    var owned = try spec.toOwned(gpa);
    defer owned.deinit(gpa);
    try qset.validateAndNormalize(gpa, &owned);
    return qset.hashNormalized(gpa, &owned);
}

// Non-vacuity: dropping the self-append makes the first hash equal the
// 2-of-{b,c} hash (red on `h1 != h2`); ignoring `include_self = false`
// makes the second case red; adding self for watchers makes the third red.
test "self-inclusion is observable via local_qset_hash; include_self = false and watchers never add" {
    const io = testing.io;
    var g = try Golden.init();
    defer g.deinit();
    const others = g.ids[1..3];
    const with_self = [_]NodeId{ g.ids[0], g.ids[1], g.ids[2] };
    const h_with_self = try expectedHash(Quorum.of(2, &with_self));
    const h_others = try expectedHash(Quorum.of(2, others));
    try testing.expect(!std.mem.eql(u8, &h_with_self, &h_others));

    var b1: [std.fs.max_path_bytes]u8 = undefined;
    var b2: [std.fs.max_path_bytes]u8 = undefined;
    var b3: [std.fs.max_path_bytes]u8 = undefined;

    var added = g.options();
    added.quorum = Quorum.twoThirdsOf(others);
    added.data_dir = try g.sub(&b1, "h1");
    {
        const n = try Node.create(testing.allocator, io, added);
        defer n.deinit();
        try testing.expectEqualSlices(u8, &h_with_self, &n.local_qset_hash);
    }

    var opted_out = added;
    opted_out.include_self = false;
    opted_out.data_dir = try g.sub(&b2, "h2");
    {
        const n = try Node.create(testing.allocator, io, opted_out);
        defer n.deinit();
        try testing.expectEqualSlices(u8, &h_others, &n.local_qset_hash);
    }

    var watcher = added;
    watcher.watcher = true;
    watcher.secret_seed = null;
    watcher.data_dir = try g.sub(&b3, "h3");
    {
        const n = try Node.create(testing.allocator, io, watcher);
        defer n.deinit();
        try testing.expect(n.watcher);
        try testing.expectEqualSlices(u8, &h_others, &n.local_qset_hash);
    }
}

// Non-vacuity: skipping the marker comparison makes the other-network and
// other-node cases start (red); comparing the node line for watchers makes
// the watcher case red; writing no marker makes every comparison vacuous —
// the success case after two refusals proves the marker is not a blanket
// refusal.
test "data_dir: empty, regular file, read-only parent, other network, other node, same identity" {
    const io = testing.io;
    var g = try Golden.init();
    defer g.deinit();

    var empty = g.options();
    empty.data_dir = "";
    try g.expectFail(empty, error.DataDirEmpty, ".data_dir is empty");

    try g.tmp.dir.writeFile(io, .{ .sub_path = "afile", .data = "not a dir" });
    var b1: [std.fs.max_path_bytes]u8 = undefined;
    var file = g.options();
    file.data_dir = try g.sub(&b1, "afile");
    try g.expectFail(file, error.DataDirNotADirectory, "afile");

    if (!isRoot()) {
        try g.tmp.dir.createDirPath(io, "locked");
        var locked = try g.tmp.dir.openDir(io, "locked", .{});
        defer locked.close(io);
        try g.tmp.dir.setFilePermissions(io, "locked", std.Io.File.Permissions.fromMode(0o500), .{});
        defer g.tmp.dir.setFilePermissions(io, "locked", std.Io.File.Permissions.fromMode(0o700), .{}) catch {};
        var b2: [std.fs.max_path_bytes]u8 = undefined;
        var denied = g.options();
        denied.data_dir = try g.sub(&b2, "locked/sub");
        try g.expectFail(denied, error.DataDirAccessDenied, "locked/sub");
    }

    var b3: [std.fs.max_path_bytes]u8 = undefined;
    const shared = try g.sub(&b3, "shared");
    var first = g.options();
    first.data_dir = shared;
    {
        const n = try Node.create(testing.allocator, io, first);
        n.deinit();
    }
    // The marker exists with the documented format.
    {
        var sub = try g.tmp.dir.openDir(io, "shared", .{});
        defer sub.close(io);
        const marker = try sub.readFileAlloc(io, "identity", testing.allocator, .limited(512));
        defer testing.allocator.free(marker);
        const net_id = crypto.networkIdFromPassphrase("my-counter-app v1");
        var want_buf: [128]u8 = undefined;
        const want = try std.fmt.bufPrint(&want_buf, "slcp-identity-v1\n{s}\n{s}\n", .{ &std.fmt.bytesToHex(net_id[0..8].*, .lower), &hexOf(g.ids[0]) });
        try testing.expectEqualStrings(want, marker);
    }

    var other_net = first;
    other_net.network = "some other app v1";
    try g.expectFail(other_net, error.DataDirOtherNetwork, shared);

    var other_node = first;
    other_node.secret_seed = g.seeds[1];
    try g.expectFail(other_node, error.DataDirOtherNode, &hexOf(g.ids[1]));
    try expectContains(g.diag.message(), &hexOf(g.ids[0]));

    // Same network + same key: the marker is a binding, not a blanket refusal.
    {
        const n = try Node.create(testing.allocator, io, first);
        n.deinit();
    }
    // A watcher on the same dir passes the node comparison (its id is ephemeral).
    var watcher = first;
    watcher.watcher = true;
    watcher.secret_seed = null;
    {
        const n = try Node.create(testing.allocator, io, watcher);
        n.deinit();
    }
}

// Non-vacuity (S8 review, D12): the identity marker only refuses a DIFFERENT
// key, so the same key + same data_dir used to start twice — two live
// signers over one own.log (the equivocation threat-model §7 claims the
// marker prevents). The store now holds an exclusive lock on the data_dir
// for the node's lifetime; dropping it turns this red ("expected
// DataDirBusy, but create succeeded"). The retry after deinit proves the
// lock dies with the node (the restart path), and the OTHER data_dir proves
// the lock is per-directory, not per-key.
test "data_dir: a live node holds its data_dir; the same key + same dir again is DataDirBusy" {
    const io = testing.io;
    var g = try Golden.init();
    defer g.deinit();

    var b1: [std.fs.max_path_bytes]u8 = undefined;
    var first = g.options();
    first.data_dir = try g.sub(&b1, "held");
    var live: ?*Node = try Node.create(testing.allocator, io, first);
    defer if (live) |n| n.deinit();
    try testing.expect(!live.?.watcher);

    // Same identity, same dir, while the first is live: refused, and the
    // message names the directory and says what to do.
    try g.expectFail(first, error.DataDirBusy, "held");
    try expectContains(g.diag.message(), "another live slcp node");
    // A watcher on the held dir is refused too: it would read the same logs.
    var watcher = first;
    watcher.watcher = true;
    watcher.secret_seed = null;
    try g.expectFail(watcher, error.DataDirBusy, "held");

    // The same key in ANOTHER data_dir is not what the lock guards (that is
    // the operator's key hygiene, examples/counter/README.md).
    var b2: [std.fs.max_path_bytes]u8 = undefined;
    var elsewhere = first;
    elsewhere.data_dir = try g.sub(&b2, "elsewhere");
    {
        const n = try Node.create(testing.allocator, io, elsewhere);
        n.deinit();
    }

    // The lock is released with the node: a restart over the dir succeeds.
    live.?.deinit();
    live = null;
    const again = try Node.create(testing.allocator, io, first);
    again.deinit();
}

// Non-vacuity: mapping AddressInUse to ListenFailed (or letting the overlay
// swallow the bind error) changes the member; mapping AccessDenied without
// the < 1024 test turns the privileged case into ListenFailed.
test "listen: an occupied port is ListenPortInUse; port 1 is ListenPortPrivileged" {
    const io = testing.io;
    const net = std.Io.net;
    var g = try Golden.init();
    defer g.deinit();

    const bind: net.IpAddress = .{ .ip4 = .unspecified(0) };
    var server = try net.IpAddress.listen(&bind, io, .{ .mode = .stream, .reuse_address = false });
    defer server.deinit(io);
    const port: u16 = switch (server.socket.address) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
    try testing.expect(port != 0);

    var b1: [std.fs.max_path_bytes]u8 = undefined;
    var busy = g.options();
    busy.listen_port = port;
    busy.data_dir = try g.sub(&b1, "busy");
    g.diag.len = 0;
    if (Node.create(testing.allocator, io, busy)) |n| {
        n.deinit();
        std.debug.print("\nnode bound port {d} while a test listener held it (SO_REUSEPORT sandbox?); skipping\n", .{port});
        return error.SkipZigTest;
    } else |err| {
        try testing.expectEqual(error.ListenPortInUse, err);
        var port_buf: [8]u8 = undefined;
        try expectContains(g.diag.message(), try std.fmt.bufPrint(&port_buf, "{d}", .{port}));
    }

    if (!isRoot()) {
        var b2: [std.fs.max_path_bytes]u8 = undefined;
        var priv = g.options();
        priv.listen_port = 1;
        priv.data_dir = try g.sub(&b2, "priv");
        g.diag.len = 0;
        if (Node.create(testing.allocator, io, priv)) |n| {
            // macOS 10.14+ lets any user bind ports < 1024; Linux and the
            // BSDs still refuse. Nothing to assert here on such a host.
            n.deinit();
            std.debug.print("\nnode bound port 1 as uid != 0 (this OS has no privileged ports); skipping\n", .{});
            return error.SkipZigTest;
        } else |err| {
            try testing.expectEqual(error.ListenPortPrivileged, err);
            try expectContains(g.diag.message(), ".listen_port 1 is a privileged port");
        }
    }
}

// Non-vacuity: removing an arm from `explain`'s switch is a compile error
// (exhaustive); returning "" or a shared string for two members is red here.
test "explain covers every CreateError member with a non-empty, unique message" {
    const names = @typeInfo(node.CreateError).error_set.error_names.?;
    var msgs: [names.len][]const u8 = undefined;
    inline for (names, 0..) |name, i| {
        const e: node.CreateError = @field(node.CreateError, name);
        msgs[i] = node.explain(e);
        try testing.expect(msgs[i].len > 0);
    }
    for (msgs, 0..) |a, i| {
        for (msgs[i + 1 ..]) |b| try testing.expect(!std.mem.eql(u8, a, b));
    }
    try testing.expect(names.len >= 33); // 32 named members + OutOfMemory
    try testing.expectEqualStrings(node.explain(error.NoIdentity), Node.explain(error.NoIdentity));
}

// Non-vacuity: a message longer than the buffer must be cut at a UTF-8
// boundary and end with "…" — dropping the truncation arm makes `set`
// silently keep a zero-length message (red on the endsWith).
test "diagnostic messages longer than the buffer are truncated with an ellipsis" {
    var g = try Golden.init();
    defer g.deinit();
    var long_path: [1500]u8 = @splat('p');
    long_path[0] = '/';
    var o = g.options();
    o.secret_seed = null;
    o.key_file = &long_path;
    g.diag.len = 0;
    try testing.expect(std.meta.isError(Node.create(testing.allocator, testing.io, o)));
    const msg = g.diag.message();
    try testing.expect(msg.len <= 1024);
    try testing.expect(std.mem.endsWith(u8, msg, "…"));
    try testing.expect(std.mem.startsWith(u8, msg, ".key_file \"/ppp"));
}

// Non-vacuity: each guard in `propose` is one line; removing the watcher
// guard queues a value on a watcher (never nominated — red on the member),
// removing the size guards hands the engine values it silently drops.
test "propose: watcher, empty, oversized, and a 1-byte value" {
    const io = testing.io;
    var g = try Golden.init();
    defer g.deinit();

    {
        const n = try Node.create(testing.allocator, io, g.options());
        defer n.deinit();
        try testing.expectError(error.ValueEmpty, n.propose(""));
        const big: [4097]u8 = @splat('x');
        try testing.expectError(error.ValueTooLarge, n.propose(&big));
        try n.propose("x");
        try n.propose(big[0..4096]);
    }

    var b1: [std.fs.max_path_bytes]u8 = undefined;
    var watcher = g.options();
    watcher.watcher = true;
    watcher.secret_seed = null;
    watcher.data_dir = try g.sub(&b1, "watcher");
    const w = try Node.create(testing.allocator, io, watcher);
    defer w.deinit();
    try testing.expectError(error.WatcherCannotPropose, w.propose("x"));
}

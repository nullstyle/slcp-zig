//! The `slcp` CLI (design §12, plan R5): `lint-quorum`, `key new`,
//! `key show`. `run` is the whole program minus process plumbing so the
//! tests drive it in-process with allocating writers; `main.zig` wires
//! argv/stdout/stderr/exit around it.
//!
//! Exit codes: 0 clean (or warnings only); 1 lint errors / key operation
//! failed; 2 usage, unreadable or unparseable input (message on stderr).

const std = @import("std");
const slcp = @import("slcp");
const core = slcp.core;
const qset = core.qset;
const Quorum = slcp.Quorum;
const keys = slcp.keys;
const lint_report = slcp.lint_report;
/// `version` = build.zig.zon's `.version`, injected by build.zig.
const build_options = @import("build_options");

pub const usage =
    \\usage: slcp <command> [args]
    \\
    \\  slcp lint-quorum <quorum.json> [--self <hex64>]
    \\      Validate and lint a quorum spec: {"threshold":T,"validators":[<hex64>...],"innerSets":[...]}.
    \\      Prints the normalized tree, its hash, the minimum blocking-set size, critical nodes and
    \\      every finding. --self adds your own node id to the top level when absent (what
    \\      Node.create does by default). Exit 0 clean/warnings, 1 lint errors, 2 bad input.
    \\  slcp key new <file>
    \\      Mint a new Ed25519 key file (raw 32-byte seed, mode 0600) and print its public key
    \\      (your node id). Never overwrites an existing file.
    \\  slcp key show <file>
    \\      Print the public key (node id) of an existing key file.
    \\  slcp --help
    \\      This text (also `slcp <command> --help`). `--` ends the options: what follows is a path.
    \\  slcp --version
    \\      Print the package version.
    \\
;

/// `--help` / `-h` anywhere before a `--` separator: every verb prints the
/// usage to stdout and exits 0 before it touches the filesystem.
fn wantsHelp(args: []const []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, "--")) return false;
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) return true;
    }
    return false;
}

/// An argument that looks like an option (`-x`, `--x`); never a path unless
/// it follows `--`. A lone `-` is a path.
fn looksLikeOption(a: []const u8) bool {
    return a.len > 1 and a[0] == '-';
}

fn unknownOption(err_out: *std.Io.Writer, verb: []const u8, arg: []const u8) RunError!u8 {
    try err_out.print("slcp{s}{s}: unknown option \"{s}\" (use `--` before a path that starts with `-`)\n\n", .{ if (verb.len == 0) "" else " ", verb, arg });
    try err_out.writeAll(usage);
    return 2;
}

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: *std.Io.Writer, err_out: *std.Io.Writer) u8 {
    return runInner(gpa, io, args, out, err_out) catch |err| switch (err) {
        error.OutOfMemory => {
            err_out.writeAll("slcp: out of memory\n") catch {};
            return 2;
        },
        error.WriteFailed => 2,
    };
}

const RunError = std.mem.Allocator.Error || std.Io.Writer.Error;

fn runInner(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: *std.Io.Writer, err_out: *std.Io.Writer) RunError!u8 {
    if (args.len == 0) {
        try err_out.writeAll(usage);
        return 2;
    }
    const verb = args[0];
    if (std.mem.eql(u8, verb, "--help") or std.mem.eql(u8, verb, "-h") or std.mem.eql(u8, verb, "help")) {
        try out.writeAll(usage);
        return 0;
    }
    if (std.mem.eql(u8, verb, "--version") or std.mem.eql(u8, verb, "-V")) {
        try out.writeAll("slcp " ++ build_options.version ++ "\n");
        return 0;
    }
    if (std.mem.eql(u8, verb, "lint-quorum")) return lintQuorum(gpa, io, args[1..], out, err_out);
    if (std.mem.eql(u8, verb, "key")) return keyCommand(io, args[1..], out, err_out);
    if (looksLikeOption(verb)) return unknownOption(err_out, "", verb);
    try err_out.print("slcp: unknown command \"{s}\"\n\n", .{verb});
    try err_out.writeAll(usage);
    return 2;
}

fn lintQuorum(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, out: *std.Io.Writer, err_out: *std.Io.Writer) RunError!u8 {
    if (wantsHelp(args)) {
        try out.writeAll(usage);
        return 0;
    }
    // A leading `--` makes the next argument a path however it looks.
    const literal = args.len > 0 and std.mem.eql(u8, args[0], "--");
    const rest = if (literal) args[1..] else args;
    if (rest.len == 0) {
        try err_out.writeAll("slcp lint-quorum: missing <quorum.json>\n\n");
        try err_out.writeAll(usage);
        return 2;
    }
    const path = rest[0];
    if (!literal and looksLikeOption(path)) return unknownOption(err_out, "lint-quorum", path);
    var self_id: ?qset.NodeId = null;
    var i: usize = 1;
    while (i < rest.len) : (i += 1) {
        if (std.mem.eql(u8, rest[i], "--self")) {
            if (i + 1 >= rest.len) {
                try err_out.writeAll("slcp lint-quorum: --self needs a <hex64> node id\n");
                return 2;
            }
            i += 1;
            self_id = slcp.parseNodeId(rest[i]) catch {
                try err_out.print("slcp lint-quorum: --self expects 64 hex characters, got \"{s}\"\n", .{rest[i]});
                return 2;
            };
        } else if (looksLikeOption(rest[i])) {
            return unknownOption(err_out, "lint-quorum", rest[i]);
        } else {
            try err_out.print("slcp lint-quorum: unknown argument \"{s}\"\n", .{rest[i]});
            return 2;
        }
    }

    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| switch (err) {
        // An allocation failure is ours, not the file's: it takes `run`'s
        // dedicated `slcp: out of memory` path like every other site.
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try err_out.print("slcp lint-quorum: cannot read {s}: {t}\n", .{ path, err });
            return 2;
        },
    };
    defer gpa.free(bytes);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const spec = Quorum.fromJson(arena_state.allocator(), bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try err_out.print("slcp lint-quorum: {s}: not a quorum spec ({t}); expected {{\"threshold\":T,\"validators\":[<hex64>...],\"innerSets\":[...]}}\n", .{ path, err });
            return 2;
        },
    };

    var owned = try spec.toOwned(gpa);
    defer owned.deinit(gpa);
    if (self_id) |id| {
        if (!spec.containsNode(id)) {
            const grown = try gpa.realloc(owned.validators, owned.validators.len + 1);
            grown[grown.len - 1] = id;
            owned.validators = grown;
            try out.print("note: added self {s} to the top-level quorum\n", .{&std.fmt.bytesToHex(id, .lower)});
        }
    }

    qset.validateAndNormalize(gpa, &owned) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.EmptyQuorumSet => {
            try out.writeAll("ERROR empty_quorum: the spec has no members; list the validators\n");
            return 1;
        },
        error.ThresholdOutOfRange => {
            const bad = lint_report.firstBadThreshold(&owned) orelse lint_report.Level{ .threshold = owned.threshold, .members = 0 };
            try out.print("ERROR threshold_out_of_range: threshold {d} is outside [1, {d}] for a level with {d} members\n", .{ bad.threshold, bad.members, bad.members });
            return 1;
        },
        error.DuplicateNode => {
            const dup = (try lint_report.firstDuplicate(gpa, &owned)) orelse @as(qset.NodeId, @splat(0));
            try out.print("ERROR duplicate_node: {s} appears more than once in the tree\n", .{&std.fmt.bytesToHex(dup, .lower)});
            return 1;
        },
        error.DepthExceeded => {
            try out.print("ERROR too_deep: the tree nests {d} levels but the wire limit is {d}\n", .{ lint_report.depth(&owned), qset.max_depth });
            return 1;
        },
        error.TooManyValidators => {
            try out.print("ERROR too_many_validators: the tree names {d} validators but the wire limit is {d}\n", .{ lint_report.totalValidators(&owned), qset.max_total_validators });
            return 1;
        },
        else => |e| {
            try out.print("ERROR {t}: the quorum spec is invalid\n", .{e});
            return 1;
        },
    };

    const hash = qset.hashNormalized(gpa, &owned) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => |e| {
            try out.print("ERROR {t}: cannot hash the normalized quorum set\n", .{e});
            return 1;
        },
    };
    const findings = try qset.lint(gpa, &owned);
    defer gpa.free(findings);
    try lint_report.write(out, .{ .qs = &owned, .findings = findings, .hash = hash });
    return if (lint_report.hasErrors(findings)) 1 else 0;
}

fn keyCommand(io: std.Io, args: []const []const u8, out: *std.Io.Writer, err_out: *std.Io.Writer) RunError!u8 {
    if (wantsHelp(args)) {
        try out.writeAll(usage);
        return 0;
    }
    const known_verb = args.len >= 1 and (std.mem.eql(u8, args[0], "new") or std.mem.eql(u8, args[0], "show"));
    // `key new -- <file>`: the path is taken verbatim however it looks.
    const literal = args.len >= 2 and std.mem.eql(u8, args[1], "--");
    const rest = if (known_verb) args[@as(usize, if (literal) 2 else 1)..] else args;
    if (!known_verb or rest.len != 1) {
        try err_out.writeAll("slcp key: expected `key new <file>` or `key show <file>`\n\n");
        try err_out.writeAll(usage);
        return 2;
    }
    const path = rest[0];
    if (!literal and looksLikeOption(path)) return unknownOption(err_out, if (std.mem.eql(u8, args[0], "new")) "key new" else "key show", path);
    if (std.mem.eql(u8, args[0], "new")) {
        const kp = keys.createNew(io, path) catch |err| switch (err) {
            error.KeyFileExists => {
                if (keys.load(io, path)) |existing| {
                    try err_out.print("slcp key new: {s} already exists (public key: {s}); move it aside first to mint a new identity\n", .{ path, &std.fmt.bytesToHex(existing.public_key, .lower) });
                } else |_| {
                    try err_out.print("slcp key new: {s} already exists; move it aside first to mint a new identity\n", .{path});
                }
                return 1;
            },
            error.FileNotFound => {
                try err_out.print("slcp key new: cannot create {s}: its directory does not exist\n", .{path});
                return 1;
            },
            else => |e| {
                try err_out.print("slcp key new: cannot create {s}: {t}\n", .{ path, e });
                return 1;
            },
        };
        try out.print("public key: {s}\n", .{&std.fmt.bytesToHex(kp.public_key, .lower)});
        return 0;
    }
    const kp = keys.load(io, path) catch |err| switch (err) {
        error.FileNotFound => {
            try err_out.print("slcp key show: {s} not found; create one with: slcp key new {s}\n", .{ path, path });
            return 1;
        },
        error.BadKeyFile => {
            try err_out.print("slcp key show: {s} is not a slcp key file (expected exactly 32 raw seed bytes)\n", .{path});
            return 1;
        },
        else => |e| {
            try err_out.print("slcp key show: cannot read {s}: {t}\n", .{ path, e });
            return 1;
        },
    };
    try out.print("public key: {s}\n", .{&std.fmt.bytesToHex(kp.public_key, .lower)});
    return 0;
}

// ---------------------------------------------------------------------------
// Tests (in-process `run`; inline JSON + tmpDir only)
// ---------------------------------------------------------------------------

const testing = std.testing;

const Captured = struct {
    out: std.Io.Writer.Allocating,
    err: std.Io.Writer.Allocating,
    code: u8 = 0,

    fn init(gpa: std.mem.Allocator) Captured {
        return .{ .out = .init(gpa), .err = .init(gpa) };
    }
    fn deinit(self: *Captured) void {
        self.out.deinit();
        self.err.deinit();
    }
    fn exec(self: *Captured, gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) void {
        self.out.clearRetainingCapacity();
        self.err.clearRetainingCapacity();
        self.code = run(gpa, io, args, &self.out.writer, &self.err.writer);
    }
    fn stdout(self: *Captured) []const u8 {
        return self.out.written();
    }
    fn stderr(self: *Captured) []const u8 {
        return self.err.written();
    }
};

fn tmpPath(io: std.Io, tmp: *std.testing.TmpDir, buf: []u8, name: []const u8) ![]const u8 {
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buf);
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ dir_buf[0..dir_len], name });
}

const two_of_three_json =
    \\{"threshold":2,"validators":[
    \\ "0101010101010101010101010101010101010101010101010101010101010101",
    \\ "0202020202020202020202020202020202020202020202020202020202020202",
    \\ "0303030303030303030303030303030303030303030303030303030303030303"],
    \\ "innerSets":[]}
;
const one_of_three_json =
    \\{"threshold":1,"validators":[
    \\ "0101010101010101010101010101010101010101010101010101010101010101",
    \\ "0202020202020202020202020202020202020202020202020202020202020202",
    \\ "0303030303030303030303030303030303030303030303030303030303030303"]}
;
/// vectors/qset.json pin for the flat 2-of-3 over 0101…/0202…/0303….
const two_of_three_hash = "6125525525c7e57dc1dbc7f7f23161f7f3b4e6262c0c1f082fa31e75e3372fc9";

// Non-vacuity: returning 0 for lint errors (or dropping the `ERROR` prefix
// from `writeFinding`) makes the 1-of-3 case red; skipping the JSON error
// path's file name makes the malformed case red; forgetting the "note:"
// line or the self append breaks the `--self` cases.
test "cli lint-quorum: clean 2-of-3 (pinned hash), 1-of-3 errors, malformed JSON, --self absent/present" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "two.json", .data = two_of_three_json });
    try tmp.dir.writeFile(io, .{ .sub_path = "one.json", .data = one_of_three_json });
    try tmp.dir.writeFile(io, .{ .sub_path = "bad.json", .data = "{\"threshold\":2,\"validators\":[" });
    var b1: [std.fs.max_path_bytes]u8 = undefined;
    var b2: [std.fs.max_path_bytes]u8 = undefined;
    var b3: [std.fs.max_path_bytes]u8 = undefined;
    const two = try tmpPath(io, &tmp, &b1, "two.json");
    const one = try tmpPath(io, &tmp, &b2, "one.json");
    const bad = try tmpPath(io, &tmp, &b3, "bad.json");

    var c = Captured.init(gpa);
    defer c.deinit();

    c.exec(gpa, io, &.{ "lint-quorum", two });
    try testing.expectEqual(@as(u8, 0), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), two_of_three_hash) != null);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "quorum: 2-of-3") != null);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "critical nodes: none\nresult: OK\n") != null);
    try testing.expectEqualStrings("", c.stderr());

    c.exec(gpa, io, &.{ "lint-quorum", one });
    try testing.expectEqual(@as(u8, 1), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "ERROR sub_majority_threshold") != null);

    c.exec(gpa, io, &.{ "lint-quorum", bad });
    try testing.expectEqual(@as(u8, 2), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stderr(), "bad.json") != null);
    try testing.expectEqualStrings("", c.stdout());

    var b4: [std.fs.max_path_bytes]u8 = undefined;
    const missing = try tmpPath(io, &tmp, &b4, "absent.json");
    c.exec(gpa, io, &.{ "lint-quorum", missing });
    try testing.expectEqual(@as(u8, 2), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stderr(), "absent.json") != null);

    const absent_self = "0909090909090909090909090909090909090909090909090909090909090909";
    // Adding an absent self turns 2-of-3 into a sub-majority 2-of-4: the
    // note is printed AND the lint refuses it (exit 1) — exactly what
    // Node.create would do with include_self (the default).
    c.exec(gpa, io, &.{ "lint-quorum", two, "--self", absent_self });
    try testing.expectEqual(@as(u8, 1), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "note: added self " ++ absent_self) != null);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "quorum: 2-of-4") != null);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "ERROR sub_majority_threshold: 2-of-4") != null);

    const present_self = "0202020202020202020202020202020202020202020202020202020202020202";
    c.exec(gpa, io, &.{ "lint-quorum", two, "--self", present_self });
    try testing.expectEqual(@as(u8, 0), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "note:") == null);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "quorum: 2-of-3") != null);

    c.exec(gpa, io, &.{ "lint-quorum", two, "--self", "zz" });
    try testing.expectEqual(@as(u8, 2), c.code);

    // Structural errors from validateAndNormalize are exit 1 with an ERROR line.
    try tmp.dir.writeFile(io, .{ .sub_path = "over.json", .data = "{\"threshold\":4,\"validators\":[\"" ++ present_self ++ "\"]}" });
    var b5: [std.fs.max_path_bytes]u8 = undefined;
    const over = try tmpPath(io, &tmp, &b5, "over.json");
    c.exec(gpa, io, &.{ "lint-quorum", over });
    try testing.expectEqual(@as(u8, 1), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "ERROR threshold_out_of_range: threshold 4 is outside [1, 1]") != null);
}

// Non-vacuity: letting `key new` overwrite makes the bytes-unchanged check
// red; printing the wrong key (e.g. the seed) breaks the `keys.load`
// equality; dropping the `slcp key new` hint from `key show` is red.
test "cli key new / key show: mint once, refuse to overwrite, show, missing file hint, --help" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var b1: [std.fs.max_path_bytes]u8 = undefined;
    const key_path = try tmpPath(io, &tmp, &b1, "node.key");

    var c = Captured.init(gpa);
    defer c.deinit();

    c.exec(gpa, io, &.{ "key", "new", key_path });
    try testing.expectEqual(@as(u8, 0), c.code);
    try testing.expect(std.mem.startsWith(u8, c.stdout(), "public key: "));
    const loaded = try keys.load(io, key_path);
    const want_hex = std.fmt.bytesToHex(loaded.public_key, .lower);
    try testing.expectEqualStrings("public key: " ++ "", c.stdout()[0..12]);
    try testing.expectEqualStrings(&want_hex, std.mem.trimEnd(u8, c.stdout()[12..], "\n"));
    const st = try tmp.dir.statFile(io, "node.key", .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);

    c.exec(gpa, io, &.{ "key", "new", key_path });
    try testing.expectEqual(@as(u8, 1), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stderr(), "already exists") != null);
    const again = try keys.load(io, key_path);
    try testing.expectEqualSlices(u8, &loaded.seed, &again.seed);

    c.exec(gpa, io, &.{ "key", "show", key_path });
    try testing.expectEqual(@as(u8, 0), c.code);
    try testing.expectEqualStrings(&want_hex, std.mem.trimEnd(u8, c.stdout()[12..], "\n"));

    var b2: [std.fs.max_path_bytes]u8 = undefined;
    const missing = try tmpPath(io, &tmp, &b2, "nope.key");
    c.exec(gpa, io, &.{ "key", "show", missing });
    try testing.expectEqual(@as(u8, 1), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stderr(), "slcp key new") != null);

    c.exec(gpa, io, &.{"--help"});
    try testing.expectEqual(@as(u8, 0), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "slcp lint-quorum") != null);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "slcp key new") != null);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), "slcp key show") != null);

    c.exec(gpa, io, &.{});
    try testing.expectEqual(@as(u8, 2), c.code);
    c.exec(gpa, io, &.{"frobnicate"});
    try testing.expectEqual(@as(u8, 2), c.code);
    c.exec(gpa, io, &.{ "key", "burn", key_path });
    try testing.expectEqual(@as(u8, 2), c.code);
}

// Non-vacuity: a bare `catch` around `readFileAlloc` (blaming the file for
// an OutOfMemory) turns the fail_index=0 point red with
// `cannot read <path>: OutOfMemory`; the sweep stops only once a run
// completes with no induced failure, so every allocation point is covered.
test "cli lint-quorum: an allocation failure anywhere is `slcp: out of memory`, never blamed on the file" {
    const base = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "two.json", .data = two_of_three_json });
    var b1: [std.fs.max_path_bytes]u8 = undefined;
    const two = try tmpPath(io, &tmp, &b1, "two.json");

    // The capture buffers live on the base allocator so only the CLI's own
    // allocations are subject to the induced failure.
    var c = Captured.init(base);
    defer c.deinit();

    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(base, .{ .fail_index = fail_index });
        c.exec(failing.allocator(), io, &.{ "lint-quorum", two });
        if (!failing.has_induced_failure) break;
        try testing.expectEqual(@as(u8, 2), c.code);
        try testing.expectEqualStrings("slcp: out of memory\n", c.stderr());
        try testing.expectEqualStrings("", c.stdout());
    }
    // The sweep really exercised several allocation points and ended on a
    // clean run.
    try testing.expect(fail_index >= 3);
    try testing.expectEqual(@as(u8, 0), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stdout(), two_of_three_hash) != null);
}

// Non-vacuity: treating `--help` as a file name mints a key literally named
// `--help` (exit 0 with a `public key:` line) and makes `lint-quorum --help`
// a FileNotFound (exit 2); dropping the option check lets `--bogus` through
// as a path; `--version` was "unknown command" (exit 2).
test "cli per-verb --help/-h prints usage (exit 0, no file touched); option-looking paths are refused; --version" {
    const gpa = testing.allocator;
    const io = testing.io;
    var c = Captured.init(gpa);
    defer c.deinit();
    // On a red run `key new --help` mints a file literally named `--help`
    // in the cwd; remove it so a failure does not litter the tree.
    defer std.Io.Dir.cwd().deleteFile(io, "--help") catch {};
    defer std.Io.Dir.cwd().deleteFile(io, "-h") catch {};

    const help_forms = [_][]const []const u8{
        &.{ "key", "new", "--help" },
        &.{ "key", "new", "-h" },
        &.{ "key", "show", "--help" },
        &.{ "key", "--help" },
        &.{ "lint-quorum", "--help" },
        &.{ "lint-quorum", "-h" },
        &.{ "lint-quorum", "spec.json", "--help" },
        &.{ "help", "key" },
    };
    for (help_forms) |args| {
        c.exec(gpa, io, args);
        try testing.expectEqual(@as(u8, 0), c.code);
        try testing.expectEqualStrings(usage, c.stdout());
        try testing.expectEqualStrings("", c.stderr());
    }
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, "--help", .{}));
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, "-h", .{}));

    // An option-looking positional is refused before the filesystem is
    // touched (exit 2, names the option, shows the usage).
    const option_paths = [_][]const []const u8{
        &.{ "key", "new", "--bogus" },
        &.{ "key", "show", "-x" },
        &.{ "lint-quorum", "--bogus" },
        &.{ "lint-quorum", "-x.json" },
        &.{"--bogus"},
    };
    for (option_paths) |args| {
        c.exec(gpa, io, args);
        try testing.expectEqual(@as(u8, 2), c.code);
        try testing.expect(std.mem.indexOf(u8, c.stderr(), "unknown option") != null);
        try testing.expect(std.mem.indexOf(u8, c.stderr(), args[args.len - 1]) != null);
        try testing.expect(std.mem.indexOf(u8, c.stderr(), "usage: slcp") != null);
        try testing.expectEqualStrings("", c.stdout());
    }
    // `--` ends option parsing: what follows is a path, however it looks.
    c.exec(gpa, io, &.{ "lint-quorum", "--", "-x.json" });
    try testing.expectEqual(@as(u8, 2), c.code);
    try testing.expect(std.mem.indexOf(u8, c.stderr(), "cannot read -x.json") != null);

    // `--version` / `-V` print the manifest version on stdout.
    for ([_][]const u8{ "--version", "-V" }) |flag| {
        c.exec(gpa, io, &.{flag});
        try testing.expectEqual(@as(u8, 0), c.code);
        try testing.expectEqualStrings("slcp " ++ build_options.version ++ "\n", c.stdout());
        try testing.expect(std.ascii.isDigit(build_options.version[0]));
    }
}

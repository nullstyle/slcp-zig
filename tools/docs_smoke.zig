//! docs-smoke — the documentation gate (plan S5b; design §13.7).
//!
//! Every claim the docs make that a program can check IS checked: quoted
//! sources are byte-equal to the files they quote, quoted CLI output is
//! byte-equal to what the real CLI prints, every `zig build X` / `just X` /
//! `slcp <verb>` named in the docs exists, every enum arm the protocol doc
//! enumerates is spelled the way the source spells it, and the pinned
//! versions match the manifests. `zig build docs-smoke` (part of `test`)
//! runs it from the repo root with the freshly built CLI.
//!
//! argv: `docs-smoke <path-to-slcp-cli>`. Every finding is one line
//! `[FAIL] <file>:<line>: <what> (<why>)`; the final line is ALWAYS
//! `[docs-smoke] checks={d} failures={d}` (R11; `just preflight` greps it);
//! exit is nonzero (`error.DocsSmokeFailed`) on any failure or when fewer
//! than `min_checks` checks ran (a vacuous run is a failure).
//!
//! ## Marker grammar (the one grammar every active doc follows)
//!
//! ```
//! <!-- snippet: <path> -->                 | <!-- output: lint-quorum <path> -->
//! ```[language-tag]                        (opening fence; the tag is optional,
//!                                           [A-Za-z0-9_+-]* directly after ```)
//! <body lines, byte-exact>
//! ```                                      (closing fence: exactly three backticks)
//! <!-- /snippet -->                        (optional; ignored wherever it appears)
//! ```
//!
//! - The marker line must be IMMEDIATELY followed by the opening fence.
//! - The body is every byte between the two fence lines, each line with its
//!   `\n` — so it equals a file that ends in exactly one newline.
//! - `snippet:` compares the body to the named file; `output: lint-quorum P`
//!   compares it to the stdout of `<cli> lint-quorum P`, which must exit 0.
//! - Log excerpts and anti-recipe outputs carry NO marker and are never
//!   compared (the counter README abbreviates a node id in its log excerpt).
//!
//! Tests at the bottom run under `zig build docs-smoke-tests` (part of
//! `test`) from the repo root; they read src/ and the manifests, never
//! zig-out.

const std = @import("std");
const slcp = @import("slcp");

/// The docs whose markers, tokens and needles are checked.
pub const active_docs = [_][]const u8{
    "README.md",
    "docs/protocol.md",
    "docs/threat-model.md",
    "docs/quorum-recipes.md",
    "docs/driver-upgrade.md",
    "docs/determinism.md",
    "docs/stability.md",
    "examples/counter/README.md",
};

pub const recipe_files = [_][]const u8{
    "docs/recipes/three-friends-2of3.json",
    "docs/recipes/five-nodes-4of5.json",
    "docs/recipes/three-orgs-2of3-majority.json",
};

/// Every one of these must be quoted (byte-exact) by at least one marker.
pub const required_snippets = [_][]const u8{
    "examples/counter/src/main.zig",
    "examples/counter/build.zig",
    "examples/bytes_node.zig",
} ++ recipe_files;

/// Paths that must exist regardless of what the docs mention.
pub const required_paths = active_docs ++ required_snippets ++ [_][]const u8{
    "examples/counter/build.zig.zon",
    "build.zig",
    "build.zig.zon",
    "Justfile",
    "mise.toml",
    "src/engine/statement.zig",
    "src/engine/engine.zig",
    "src/engine/qset.zig",
};

/// Build steps / Justfile recipes that must exist even if no doc names them.
pub const required_steps = [_][]const u8{ "test", "docs-smoke", "e2e", "cli", "example-smoke" };

pub const min_output_markers: usize = 3;
pub const min_cli_tokens: usize = 3;
pub const min_insane_arms: usize = 15;
pub const min_input_status_arms: usize = 7;
pub const min_lint_codes: usize = 4;
pub const min_checks: usize = 25;

/// The README notice (lines 1–14 of README.md are frozen; these two lines
/// are what the gate pins) must precede the first body `## ` heading.
pub const notice_heading = "> ## ⚠️ This is a vibe-coded project. Do not use it.";
pub const notice_sentence = "**Do not depend on this code, run it in production, or trust it with anything";

/// docs/protocol.md must carry these literals verbatim (§2 tags, §8 limits).
pub const protocol_needles = [_][]const u8{
    "\"SLCP-STMT-V1\"",
    "\"SLCP-QSET-V1\"",
    "\"SLCP-GI-V1\\x00\\x00\"",
    "\"SLCP-NET-V1\\x00\"",
    "65536",
    "4096",
    "255",
    "60 s",
};
pub const threat_model_needles = [_][]const u8{
    "**No transport authentication in v1.**",
    "WireGuard",
    "quorum intersection",
};
/// Spellings that must appear in NO active doc (stale designs, wrong verbs).
pub const forbidden_needles = [_][]const u8{
    "SO_RCVTIMEO",
    "@nullstyle/slcp",
    "slcp-zig.git#v",
    "slcp keygen",
    "key create",
};

/// The field names of `slcp.NodeOptions`, at comptime: every `.option` row
/// in a docs option table must be one of these, and README's table must
/// list every one of them.
pub const option_fields = std.meta.fieldNames(slcp.NodeOptions);

pub const read_limit: std.Io.Limit = .limited(4 << 20);

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// Counts checks and failures; every failure is one `[FAIL]` line.
pub const Report = struct {
    checks: usize = 0,
    failures: usize = 0,
    out: *std.Io.Writer,

    /// One check; `ok == false` prints `[FAIL] file:line: what (why)`.
    pub fn check(self: *Report, ok: bool, file: []const u8, line: usize, what: []const u8, why: []const u8) void {
        self.checks += 1;
        if (!ok) self.failLine(file, line, what, why);
    }

    pub fn checkFmt(self: *Report, ok: bool, file: []const u8, line: usize, comptime what_fmt: []const u8, what_args: anytype, comptime why_fmt: []const u8, why_args: anytype) void {
        self.checks += 1;
        if (ok) return;
        self.failures += 1;
        self.out.print("[FAIL] {s}:{d}: ", .{ file, line }) catch {};
        self.out.print(what_fmt, what_args) catch {};
        self.out.writeAll(" (") catch {};
        self.out.print(why_fmt, why_args) catch {};
        self.out.writeAll(")\n") catch {};
    }

    fn failLine(self: *Report, file: []const u8, line: usize, what: []const u8, why: []const u8) void {
        self.failures += 1;
        self.out.print("[FAIL] {s}:{d}: {s} ({s})\n", .{ file, line, what, why }) catch {};
    }

    /// The final evidence line (R11).
    pub fn summary(self: *Report) void {
        self.out.print("[docs-smoke] checks={d} failures={d}\n", .{ self.checks, self.failures }) catch {};
    }
};

// ---------------------------------------------------------------------------
// Markers
// ---------------------------------------------------------------------------

pub const BlockKind = enum { snippet, output };

pub const Block = struct {
    kind: BlockKind,
    /// `snippet:` the quoted path; `output:` the text after `output: ` (e.g.
    /// `lint-quorum docs/recipes/x.json`).
    arg: []const u8,
    /// 1-based line of the marker.
    line: usize,
    /// The fence body (every byte between the fence lines), or null when
    /// `problem` is set.
    body: ?[]const u8,
    problem: ?[]const u8,
};

const snippet_open = "<!-- snippet: ";
const output_open = "<!-- output: ";
const marker_close = " -->";

fn markerArg(line: []const u8, comptime open: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, open)) return null;
    if (!std.mem.endsWith(u8, line, marker_close)) return null;
    if (line.len < open.len + marker_close.len) return null;
    return line[open.len .. line.len - marker_close.len];
}

/// An opening fence: ``` followed by an optional language tag and nothing else.
pub fn isOpeningFence(line: []const u8) bool {
    if (!std.mem.startsWith(u8, line, "```")) return false;
    for (line[3..]) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '+')) return false;
    }
    return true;
}

/// Every marked block of `text`, in order. Malformed markers come back with
/// `problem` set (the caller reports them); unmarked fences are skipped.
pub fn extractBlocks(gpa: std.mem.Allocator, text: []const u8) ![]Block {
    var blocks: std.ArrayList(Block) = .empty;
    errdefer blocks.deinit(gpa);
    var pos: usize = 0;
    var line_no: usize = 0;
    while (pos < text.len) {
        const nl = std.mem.indexOfScalarPos(u8, text, pos, '\n') orelse text.len;
        const line = text[pos..nl];
        line_no += 1;
        const next = if (nl < text.len) nl + 1 else text.len;
        const Marker = struct { kind: BlockKind, arg: []const u8 };
        const marker: Marker = blk: {
            if (markerArg(line, snippet_open)) |a| break :blk .{ .kind = .snippet, .arg = a };
            if (markerArg(line, output_open)) |a| break :blk .{ .kind = .output, .arg = a };
            pos = next;
            continue;
        };
        const kind = marker.kind;
        const arg = marker.arg;
        const marker_line = line_no;
        // The very next line must open a fence.
        if (next >= text.len) {
            try blocks.append(gpa, .{ .kind = kind, .arg = arg, .line = marker_line, .body = null, .problem = "marker is not followed by a fence" });
            break;
        }
        const fence_nl = std.mem.indexOfScalarPos(u8, text, next, '\n') orelse text.len;
        const fence_line = text[next..fence_nl];
        line_no += 1;
        if (!isOpeningFence(fence_line)) {
            try blocks.append(gpa, .{ .kind = kind, .arg = arg, .line = marker_line, .body = null, .problem = "marker is not followed by a fence" });
            pos = next;
            line_no -= 1;
            continue;
        }
        const body_start = if (fence_nl < text.len) fence_nl + 1 else text.len;
        // Scan for the closing fence: a line that is exactly ```.
        var p = body_start;
        var found: ?usize = null;
        while (p < text.len) {
            const e = std.mem.indexOfScalarPos(u8, text, p, '\n') orelse text.len;
            line_no += 1;
            if (std.mem.eql(u8, text[p..e], "```")) {
                found = p;
                pos = if (e < text.len) e + 1 else text.len;
                break;
            }
            p = if (e < text.len) e + 1 else text.len;
        }
        if (found) |close_at| {
            try blocks.append(gpa, .{ .kind = kind, .arg = arg, .line = marker_line, .body = text[body_start..close_at], .problem = null });
        } else {
            try blocks.append(gpa, .{ .kind = kind, .arg = arg, .line = marker_line, .body = null, .problem = "fence is not terminated" });
            break;
        }
    }
    return blocks.toOwnedSlice(gpa);
}

/// First differing byte offset of two buffers (or the shorter length).
pub fn firstDifference(a: []const u8, b: []const u8) ?usize {
    const n = @min(a.len, b.len);
    for (0..n) |i| if (a[i] != b[i]) return i;
    if (a.len == b.len) return null;
    return n;
}

// ---------------------------------------------------------------------------
// Token scanners
// ---------------------------------------------------------------------------

pub const TokenKind = enum { zig_build, just };

pub const Token = struct {
    kind: TokenKind,
    name: []const u8,
    line: usize,
};

fn isStepChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_';
}

/// A step/recipe name at `text[at..]`: `[a-z][a-z0-9_-]*` ending at a
/// non-name byte. `-D…` flags, backticks, `#`, EOL → null.
fn stepName(text: []const u8, at: usize) ?[]const u8 {
    if (at >= text.len) return null;
    if (!std.ascii.isLower(text[at])) return null;
    var end = at;
    while (end < text.len and isStepChar(text[end])) end += 1;
    return text[at..end];
}

fn scanPrefix(gpa: std.mem.Allocator, out: *std.ArrayList(Token), text: []const u8, line: usize, comptime prefix: []const u8, kind: TokenKind) !void {
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, text, from, prefix)) |at| {
        from = at + prefix.len;
        // A word boundary before the prefix (`just` must not match `adjust`).
        if (at > 0 and std.ascii.isAlphanumeric(text[at - 1])) continue;
        var p = at + prefix.len;
        while (p < text.len and text[p] == ' ') p += 1;
        if (p == at + prefix.len) continue; // "zig build" at EOL / followed by `
        const name = stepName(text, p) orelse continue;
        try out.append(gpa, .{ .kind = kind, .name = name, .line = line });
    }
}

/// Every `zig build X` (anywhere: prose, backticks, fences) and every
/// `just X` inside a fence or a backtick span (prose `just waits` is English).
pub fn scanStepTokens(gpa: std.mem.Allocator, text: []const u8) ![]Token {
    var out: std.ArrayList(Token) = .empty;
    errdefer out.deinit(gpa);
    var in_fence = false;
    var line_no: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        line_no += 1;
        if (std.mem.startsWith(u8, line, "```")) {
            in_fence = !in_fence;
            continue;
        }
        try scanPrefix(gpa, &out, line, line_no, "zig build", .zig_build);
        if (in_fence) {
            try scanPrefix(gpa, &out, line, line_no, "just", .just);
        } else {
            var spans = std.mem.splitScalar(u8, line, '`');
            var odd = false;
            while (spans.next()) |span| {
                if (odd) try scanPrefix(gpa, &out, span, line_no, "just", .just);
                odd = !odd;
            }
        }
    }
    return out.toOwnedSlice(gpa);
}

/// `b.step("name"` in build.zig outside `//` comments.
pub fn hasBuildStep(build_zig: []const u8, name: []const u8) bool {
    var it = std.mem.splitScalar(u8, build_zig, '\n');
    while (it.next()) |raw| {
        const line = if (std.mem.indexOf(u8, raw, "//")) |c| raw[0..c] else raw;
        var from: usize = 0;
        while (std.mem.indexOfPos(u8, line, from, "b.step(\"")) |at| {
            const start = at + "b.step(\"".len;
            const end = std.mem.indexOfScalarPos(u8, line, start, '"') orelse break;
            if (std.mem.eql(u8, line[start..end], name)) return true;
            from = end;
        }
    }
    return false;
}

/// A Justfile recipe header `name:` / `name ARGS:` at column 0.
pub fn hasJustRecipe(justfile: []const u8, name: []const u8) bool {
    var it = std.mem.splitScalar(u8, justfile, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, name)) continue;
        if (line.len == name.len) continue;
        const c = line[name.len];
        if (c != ':' and c != ' ') continue;
        if (std.mem.indexOfScalar(u8, line, ':') == null) continue;
        return true;
    }
    return false;
}

pub const CliToken = struct {
    /// `slcp <verb>` or `slcp <verb> <verb>` (the longest verb chain).
    needle: []const u8,
    line: usize,
};

fn isVerbChar(c: u8) bool {
    return std.ascii.isLower(c) or c == '-';
}

fn verbAt(text: []const u8, at: usize) ?[]const u8 {
    if (at >= text.len or !isVerbChar(text[at])) return null;
    var end = at;
    while (end < text.len and isVerbChar(text[end])) end += 1;
    if (end < text.len and !(text[end] == ' ' or text[end] == '`')) return null; // `quorum.json`, `<file>`
    return text[at..end];
}

/// Every backtick span that starts with `slcp ` (prose only — fences are
/// shell transcripts with their own paths): the `slcp <verb>[ <verb>]`
/// needle that must appear in `slcp --help`.
pub fn scanCliTokens(gpa: std.mem.Allocator, text: []const u8) ![]CliToken {
    var out: std.ArrayList(CliToken) = .empty;
    errdefer out.deinit(gpa);
    var in_fence = false;
    var line_no: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        line_no += 1;
        if (std.mem.startsWith(u8, line, "```")) {
            in_fence = !in_fence;
            continue;
        }
        if (in_fence) continue;
        var spans = std.mem.splitScalar(u8, line, '`');
        var odd = false;
        while (spans.next()) |span| {
            defer odd = !odd;
            if (!odd or !std.mem.startsWith(u8, span, "slcp ")) continue;
            const v1 = verbAt(span, "slcp ".len) orelse continue;
            var end = "slcp ".len + v1.len;
            if (end < span.len and span[end] == ' ') {
                if (verbAt(span, end + 1)) |v2| end = end + 1 + v2.len;
            }
            try out.append(gpa, .{ .needle = span[0..end], .line = line_no });
        }
    }
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Source parsers
// ---------------------------------------------------------------------------

pub const EnumError = error{EnumNotFound} || std.mem.Allocator.Error;

/// The arms of `pub const <name> = enum[(tag)] {` in `src`, in declaration
/// order: one identifier per line, `///` and `//` lines skipped, until the
/// `};` line. Header absent → `error.EnumNotFound`.
pub fn parseEnumArms(gpa: std.mem.Allocator, src: []const u8, name: []const u8) EnumError![]const []const u8 {
    var arms: std.ArrayList([]const u8) = .empty;
    errdefer arms.deinit(gpa);
    var it = std.mem.splitScalar(u8, src, '\n');
    var header_buf: [128]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "pub const {s} = enum", .{name}) catch return error.EnumNotFound;
    var inside = false;
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (!inside) {
            if (std.mem.startsWith(u8, line, header) and std.mem.endsWith(u8, line, "{")) inside = true;
            continue;
        }
        if (std.mem.eql(u8, line, "};")) return arms.toOwnedSlice(gpa);
        if (line.len == 0 or std.mem.startsWith(u8, line, "//")) continue;
        var end: usize = 0;
        while (end < line.len and (std.ascii.isAlphanumeric(line[end]) or line[end] == '_')) end += 1;
        if (end == 0 or end >= line.len or line[end] != ',') continue; // `pub fn …` etc. are not arms
        try arms.append(gpa, line[0..end]);
    }
    return error.EnumNotFound;
}

/// `.version = "<v>"` of a build.zig.zon, or null.
pub fn parseManifestVersion(zon: []const u8) ?[]const u8 {
    const key = ".version = \"";
    const at = std.mem.indexOf(u8, zon, key) orelse return null;
    const start = at + key.len;
    const end = std.mem.indexOfScalarPos(u8, zon, start, '"') orelse return null;
    if (end == start) return null;
    return zon[start..end];
}

/// `zig = "<v>"` of mise.toml, or null.
pub fn parseMiseZig(toml: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, toml, '\n');
    while (it.next()) |line| {
        const t = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, t, "zig")) continue;
        const eq = std.mem.indexOfScalar(u8, t, '=') orelse continue;
        if (std.mem.trim(u8, t[3..eq], " \t").len != 0) continue;
        const rest = std.mem.trim(u8, t[eq + 1 ..], " \t");
        if (rest.len < 2 or rest[0] != '"') continue;
        const end = std.mem.indexOfScalarPos(u8, rest, 1, '"') orelse continue;
        return rest[1..end];
    }
    return null;
}

pub const PinHit = struct { version: []const u8, line: usize };

/// Every `refs/tags/v<version>.tar.gz` in `text` (the stale-pin scan).
pub fn scanTagPins(gpa: std.mem.Allocator, text: []const u8) ![]PinHit {
    var out: std.ArrayList(PinHit) = .empty;
    errdefer out.deinit(gpa);
    const key = "refs/tags/v";
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, text, from, key)) |at| {
        const start = at + key.len;
        var end = start;
        while (end < text.len and (std.ascii.isAlphanumeric(text[end]) or text[end] == '.' or text[end] == '-')) end += 1;
        from = end;
        var v = text[start..end];
        if (std.mem.endsWith(u8, v, ".tar.gz")) v = v[0 .. v.len - ".tar.gz".len];
        try out.append(gpa, .{ .version = v, .line = lineOf(text, at) });
    }
    return out.toOwnedSlice(gpa);
}

/// Every `0.17.0-dev.<…>` spelling in `text` (the zig-pin scan).
pub fn scanZigPins(gpa: std.mem.Allocator, text: []const u8) ![]PinHit {
    var out: std.ArrayList(PinHit) = .empty;
    errdefer out.deinit(gpa);
    const key = "0.17.0-dev.";
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, text, from, key)) |at| {
        var end = at + key.len;
        while (end < text.len and (std.ascii.isAlphanumeric(text[end]) or text[end] == '.' or text[end] == '-' or text[end] == '+')) end += 1;
        while (end > at + key.len and text[end - 1] == '.') end -= 1; // sentence-final period
        from = end;
        try out.append(gpa, .{ .version = text[at..end], .line = lineOf(text, at) });
    }
    return out.toOwnedSlice(gpa);
}

/// 1-based line number of byte offset `at`.
pub fn lineOf(text: []const u8, at: usize) usize {
    return 1 + std.mem.count(u8, text[0..@min(at, text.len)], "\n");
}

/// Option names from table rows `| `.name` …` (the docs option tables).
pub fn scanOptionRows(gpa: std.mem.Allocator, text: []const u8) ![]PinHit {
    var out: std.ArrayList(PinHit) = .empty;
    errdefer out.deinit(gpa);
    var line_no: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        line_no += 1;
        const prefix = "| `.";
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        const end = std.mem.indexOfScalarPos(u8, line, prefix.len, '`') orelse continue;
        try out.append(gpa, .{ .version = line[prefix.len..end], .line = line_no });
    }
    return out.toOwnedSlice(gpa);
}

pub fn isOptionField(name: []const u8) bool {
    inline for (option_fields) |f| if (std.mem.eql(u8, f, name)) return true;
    return false;
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

const Doc = struct { path: []const u8, text: []const u8 };

fn readFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, read_limit);
}

fn containsBackticked(text: []const u8, name: []const u8) bool {
    var buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&buf, "`{s}`", .{name}) catch return false;
    return std.mem.indexOf(u8, text, needle) != null;
}

const Cli = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,

    /// stdout + exit status of `<cli> <args…>`.
    fn run(self: Cli, args: []const []const u8) !struct { stdout: []u8, stderr: []u8, exit_ok: bool } {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.gpa);
        try argv.append(self.gpa, self.path);
        try argv.appendSlice(self.gpa, args);
        const res = try std.process.run(self.gpa, self.io, .{ .argv = argv.items });
        return .{ .stdout = res.stdout, .stderr = res.stderr, .exit_ok = res.term.success() };
    }
};

/// Every check, over the repo at cwd. `cli` is the built `slcp` executable.
pub fn runGate(gpa: std.mem.Allocator, io: std.Io, cli_path: []const u8, rep: *Report) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cli = Cli{ .gpa = arena, .io = io, .path = cli_path };

    // ---- (1) required paths ----
    for (required_paths) |p| {
        const ok = if (std.Io.Dir.cwd().access(io, p, .{})) |_| true else |_| false;
        rep.checkFmt(ok, p, 0, "required path exists", .{}, "missing", .{});
    }

    // ---- active docs, read once ----
    var docs: [active_docs.len]Doc = undefined;
    for (active_docs, 0..) |p, i| {
        docs[i] = .{ .path = p, .text = readFile(arena, io, p) catch "" };
    }
    const readme = docs[0].text;
    const build_zig = readFile(arena, io, "build.zig") catch "";
    const justfile = readFile(arena, io, "Justfile") catch "";

    // ---- (2) the notice stays on top ----
    {
        const heading_at = std.mem.indexOf(u8, readme, notice_heading);
        const sentence_at = std.mem.indexOf(u8, readme, notice_sentence);
        const first_body = std.mem.indexOf(u8, readme, "\n## ");
        rep.checkFmt(heading_at != null, "README.md", 1, "vibe-coded notice heading present", .{}, "the notice must never be softened or removed", .{});
        rep.checkFmt(sentence_at != null, "README.md", 1, "vibe-coded notice sentence present", .{}, "the notice must never be softened or removed", .{});
        const before = heading_at != null and first_body != null and heading_at.? < first_body.?;
        rep.checkFmt(before, "README.md", if (first_body) |b| lineOf(readme, b + 1) else 1, "notice precedes the first body heading", .{}, "the notice must be the first thing a reader sees", .{});
    }

    // ---- (3) snippet + (4) output markers ----
    var seen_snippets: std.StringHashMapUnmanaged(void) = .empty;
    var output_markers: usize = 0;
    for (docs) |doc| {
        const blocks = try extractBlocks(arena, doc.text);
        for (blocks) |b| {
            if (b.problem) |why| {
                rep.checkFmt(false, doc.path, b.line, "marker `{s}`", .{b.arg}, "{s}", .{why});
                continue;
            }
            switch (b.kind) {
                .snippet => {
                    try seen_snippets.put(arena, b.arg, {});
                    const file = readFile(arena, io, b.arg) catch {
                        rep.checkFmt(false, doc.path, b.line, "snippet {s}", .{b.arg}, "file cannot be read", .{});
                        continue;
                    };
                    if (firstDifference(b.body.?, file)) |off| {
                        rep.checkFmt(false, doc.path, b.line, "snippet {s} is byte-equal to the file", .{b.arg}, "first difference at body offset {d} = {s}:{d}, doc line {d}; body {d} bytes, file {d} bytes", .{ off, b.arg, lineOf(file, off), b.line + 1 + lineOf(b.body.?, off), b.body.?.len, file.len });
                    } else {
                        rep.checkFmt(true, doc.path, b.line, "", .{}, "", .{});
                    }
                },
                .output => {
                    const cmd = "lint-quorum ";
                    if (!std.mem.startsWith(u8, b.arg, cmd)) {
                        rep.checkFmt(false, doc.path, b.line, "output marker `{s}`", .{b.arg}, "only `lint-quorum <path>` is supported", .{});
                        continue;
                    }
                    output_markers += 1;
                    const spec = b.arg[cmd.len..];
                    const res = cli.run(&.{ "lint-quorum", spec }) catch |err| {
                        rep.checkFmt(false, doc.path, b.line, "output of `slcp {s}`", .{b.arg}, "spawning {s} failed: {t}", .{ cli_path, err });
                        continue;
                    };
                    rep.checkFmt(res.exit_ok, doc.path, b.line, "`slcp {s}` exits 0", .{b.arg}, "stderr: {s}", .{std.mem.trim(u8, res.stderr, "\n")});
                    if (firstDifference(b.body.?, res.stdout)) |off| {
                        rep.checkFmt(false, doc.path, b.line, "output of `slcp {s}` is byte-equal to the doc", .{b.arg}, "first difference at offset {d}, doc line {d}; doc {d} bytes, stdout {d} bytes — recapture the block", .{ off, b.line + 1 + lineOf(b.body.?, off), b.body.?.len, res.stdout.len });
                    } else {
                        rep.checkFmt(true, doc.path, b.line, "", .{}, "", .{});
                    }
                },
            }
        }
    }
    for (required_snippets) |p| {
        rep.checkFmt(seen_snippets.contains(p), "README.md", 0, "{s} is quoted by a snippet marker", .{p}, "add `<!-- snippet: {s} -->` before its fence", .{p});
    }
    rep.checkFmt(output_markers >= min_output_markers, "docs/quorum-recipes.md", 0, "at least {d} output markers", .{min_output_markers}, "found {d}", .{output_markers});

    // ---- (5) build steps / recipes ----
    for (docs) |doc| {
        const toks = try scanStepTokens(arena, doc.text);
        for (toks) |t| switch (t.kind) {
            .zig_build => rep.checkFmt(hasBuildStep(build_zig, t.name), doc.path, t.line, "`zig build {s}` exists", .{t.name}, "no b.step(\"{s}\" in build.zig", .{t.name}),
            .just => rep.checkFmt(hasJustRecipe(justfile, t.name), doc.path, t.line, "`just {s}` exists", .{t.name}, "no `{s}:` recipe in Justfile", .{t.name}),
        };
    }
    for (required_steps) |s| {
        rep.checkFmt(hasBuildStep(build_zig, s), "build.zig", 0, "build step `{s}` exists", .{s}, "required by the docs gate", .{});
        rep.checkFmt(hasJustRecipe(justfile, s), "Justfile", 0, "recipe `{s}` exists", .{s}, "required by the docs gate", .{});
    }

    // ---- (6) CLI verbs ----
    {
        const help = cli.run(&.{"--help"}) catch |err| blk: {
            rep.checkFmt(false, "README.md", 0, "`slcp --help` runs", .{}, "spawning {s} failed: {t}", .{ cli_path, err });
            break :blk null;
        };
        var found: usize = 0;
        if (help) |h| {
            rep.checkFmt(h.exit_ok, "README.md", 0, "`slcp --help` exits 0", .{}, "stderr: {s}", .{std.mem.trim(u8, h.stderr, "\n")});
            for (docs) |doc| {
                const toks = try scanCliTokens(arena, doc.text);
                for (toks) |t| {
                    found += 1;
                    const ok = std.mem.indexOf(u8, h.stdout, t.needle) != null or std.mem.indexOf(u8, h.stderr, t.needle) != null;
                    rep.checkFmt(ok, doc.path, t.line, "`{s}` is a CLI verb", .{t.needle}, "not in `slcp --help`", .{});
                }
            }
        }
        rep.checkFmt(found >= min_cli_tokens, "README.md", 0, "at least {d} backticked `slcp <verb>` tokens", .{min_cli_tokens}, "found {d}", .{found});
    }

    // ---- (7) enum arms ----
    const protocol = docs[1].text;
    const recipes = docs[3].text;
    const EnumSpec = struct { file: []const u8, name: []const u8, min: usize, also_recipes: bool };
    const enums = [_]EnumSpec{
        .{ .file = "src/engine/statement.zig", .name = "InsaneReason", .min = min_insane_arms, .also_recipes = false },
        .{ .file = "src/engine/engine.zig", .name = "InputStatus", .min = min_input_status_arms, .also_recipes = false },
        .{ .file = "src/engine/qset.zig", .name = "LintCode", .min = min_lint_codes, .also_recipes = true },
    };
    for (enums) |e| {
        const src = readFile(arena, io, e.file) catch "";
        const arms = parseEnumArms(arena, src, e.name) catch &.{};
        rep.checkFmt(arms.len >= e.min, e.file, 0, "{s} parses to at least {d} arms", .{ e.name, e.min }, "parsed {d}", .{arms.len});
        for (arms) |arm| {
            const ok = containsBackticked(protocol, arm) or (e.also_recipes and containsBackticked(recipes, arm));
            rep.checkFmt(ok, "docs/protocol.md", 0, "{s}.{s} is documented", .{ e.name, arm }, "no `{s}` in docs/protocol.md{s}", .{ arm, if (e.also_recipes) " or docs/quorum-recipes.md" else "" });
        }
    }

    // ---- (8) option names ----
    {
        var readme_rows: std.StringHashMapUnmanaged(void) = .empty;
        for (docs) |doc| {
            const rows = try scanOptionRows(arena, doc.text);
            for (rows) |r| {
                rep.checkFmt(isOptionField(r.version), doc.path, r.line, "`.{s}` is a field of slcp.NodeOptions", .{r.version}, "no such option", .{});
                if (std.mem.eql(u8, doc.path, "README.md")) try readme_rows.put(arena, r.version, {});
            }
        }
        inline for (option_fields) |f| {
            rep.checkFmt(readme_rows.contains(f), "README.md", 0, "option `.{s}` has a row in the README option table", .{f}, "every slcp.NodeOptions field is documented there", .{});
        }
    }

    // ---- (9) fixed needles ----
    for (protocol_needles) |n| rep.checkFmt(std.mem.indexOf(u8, protocol, n) != null, "docs/protocol.md", 0, "contains `{s}`", .{n}, "copied literal missing", .{});
    for (threat_model_needles) |n| rep.checkFmt(std.mem.indexOf(u8, docs[2].text, n) != null, "docs/threat-model.md", 0, "contains `{s}`", .{n}, "required statement missing", .{});
    for (docs) |doc| {
        for (forbidden_needles) |n| {
            const at = std.mem.indexOf(u8, doc.text, n);
            rep.checkFmt(at == null, doc.path, if (at) |a| lineOf(doc.text, a) else 0, "does not contain `{s}`", .{n}, "forbidden spelling", .{});
        }
    }

    // ---- (10) version needles ----
    {
        const zon = readFile(arena, io, "build.zig.zon") catch "";
        const version = parseManifestVersion(zon) orelse "";
        rep.checkFmt(version.len > 0, "build.zig.zon", 0, ".version parses", .{}, "no `.version = \"…\"`", .{});
        const pin = try std.fmt.allocPrint(arena, "refs/tags/v{s}.tar.gz", .{version});
        for ([_][]const u8{ "README.md", "examples/counter/README.md" }) |p| {
            const text = for (docs) |d| (if (std.mem.eql(u8, d.path, p)) break d.text) else "";
            rep.checkFmt(std.mem.indexOf(u8, text, pin) != null, p, 0, "install pin `{s}` present", .{pin}, "the tarball pin must name build.zig.zon's .version", .{});
        }
        for (docs) |doc| {
            const hits = try scanTagPins(arena, doc.text);
            for (hits) |h| rep.checkFmt(std.mem.eql(u8, h.version, version), doc.path, h.line, "tag pin v{s} is current", .{h.version}, "build.zig.zon says {s}", .{version});
        }
    }
    // ---- (11) zig pin ----
    {
        const mise = readFile(arena, io, "mise.toml") catch "";
        const zig_pin = parseMiseZig(mise) orelse "";
        rep.checkFmt(zig_pin.len > 0, "mise.toml", 0, "zig pin parses", .{}, "no `zig = \"…\"`", .{});
        for (docs) |doc| {
            const hits = try scanZigPins(arena, doc.text);
            for (hits) |h| rep.checkFmt(std.mem.eql(u8, h.version, zig_pin), doc.path, h.line, "zig pin `{s}` matches mise.toml", .{h.version}, "mise.toml says {s}", .{zig_pin});
        }
    }
    // ---- (12) path dep ----
    {
        const zon = readFile(arena, io, "examples/counter/build.zig.zon") catch "";
        rep.checkFmt(std.mem.indexOf(u8, zon, ".path = \"../..\"") != null, "examples/counter/build.zig.zon", 0, "depends on the repo by path", .{}, "`.path = \"../..\"` missing", .{});
        rep.checkFmt(std.mem.indexOf(u8, zon, "refs/tags/") == null, "examples/counter/build.zig.zon", 0, "is not tag-pinned", .{}, "the in-tree example must build against the working tree", .{});
    }
}

pub fn main(init: std.process.Init) !void {
    var out_buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &out_buf);
    defer out.interface.flush() catch {};
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next();
    const cli_path = it.next() orelse {
        try out.interface.writeAll("usage: docs-smoke <path-to-slcp-cli>\n");
        try out.interface.flush();
        return error.BadArgument;
    };
    var rep = Report{ .out = &out.interface };
    runGate(init.gpa, init.io, cli_path, &rep) catch |err| {
        rep.checkFmt(false, "docs-smoke", 0, "gate ran to completion", .{}, "{t}", .{err});
    };
    rep.checkFmt(rep.checks >= min_checks, "docs-smoke", 0, "at least {d} checks ran", .{min_checks}, "ran {d} — a vacuous gate", .{rep.checks});
    rep.summary();
    try out.interface.flush();
    if (rep.failures > 0) return error.DocsSmokeFailed;
}

// ---------------------------------------------------------------------------
// Tests (run from the repo root: `zig build docs-smoke-tests`, part of `test`)
// ---------------------------------------------------------------------------

const testing = std.testing;

// Non-vacuity: the body is every byte between the fences INCLUDING the last
// newline; drop the `+ "\n"` in the expectation (or make the extractor trim)
// and the exact case fails, and the appended-byte case pins that a one-byte
// drift is a difference, not a prefix match.
test "markers: fence body extraction is exact; one appended byte differs" {
    const gpa = testing.allocator;
    const doc = "intro\n<!-- snippet: x.zig -->\n```zig\nconst a = 1;\n\nconst b = 2;\n```\n<!-- /snippet -->\nafter\n";
    const blocks = try extractBlocks(gpa, doc);
    defer gpa.free(blocks);
    try testing.expectEqual(@as(usize, 1), blocks.len);
    try testing.expectEqual(BlockKind.snippet, blocks[0].kind);
    try testing.expectEqualStrings("x.zig", blocks[0].arg);
    try testing.expectEqual(@as(usize, 2), blocks[0].line);
    try testing.expect(blocks[0].problem == null);
    const body = blocks[0].body.?;
    try testing.expectEqualStrings("const a = 1;\n\nconst b = 2;\n", body);
    try testing.expect(firstDifference(body, "const a = 1;\n\nconst b = 2;\n") == null);
    try testing.expectEqual(@as(?usize, body.len), firstDifference(body, "const a = 1;\n\nconst b = 2;\n\n"));
    try testing.expectEqual(@as(?usize, 6), firstDifference(body, "const A = 1;\n\nconst b = 2;\n"));
}

// Non-vacuity: a language tag after the fence is accepted (the S5a docs use
// ```json / ```text) but a fence with trailing junk, or prose where the
// fence should be, is "marker is not followed by a fence"; a fence with no
// closing ``` is "fence is not terminated". Remove either arm of the parser
// and the matching expectation fails.
test "markers: language tags accepted; missing fence and unterminated fence are failures" {
    const gpa = testing.allocator;
    try testing.expect(isOpeningFence("```"));
    try testing.expect(isOpeningFence("```json"));
    try testing.expect(isOpeningFence("```c++"));
    try testing.expect(!isOpeningFence("``` json"));
    try testing.expect(!isOpeningFence("```json extra"));
    try testing.expect(!isOpeningFence("`` `"));

    const tagged = "<!-- output: lint-quorum r.json -->\n```text\nresult: OK\n```\n";
    const b1 = try extractBlocks(gpa, tagged);
    defer gpa.free(b1);
    try testing.expectEqual(@as(usize, 1), b1.len);
    try testing.expectEqual(BlockKind.output, b1[0].kind);
    try testing.expectEqualStrings("lint-quorum r.json", b1[0].arg);
    try testing.expectEqualStrings("result: OK\n", b1[0].body.?);

    const no_fence = "<!-- snippet: x.zig -->\nprose instead of a fence\n```\nx\n```\n";
    const b2 = try extractBlocks(gpa, no_fence);
    defer gpa.free(b2);
    try testing.expectEqual(@as(usize, 1), b2.len);
    try testing.expect(b2[0].body == null);
    try testing.expectEqualStrings("marker is not followed by a fence", b2[0].problem.?);

    const unterminated = "<!-- snippet: x.zig -->\n```zig\nconst a = 1;\n";
    const b3 = try extractBlocks(gpa, unterminated);
    defer gpa.free(b3);
    try testing.expectEqual(@as(usize, 1), b3.len);
    try testing.expect(b3[0].body == null);
    try testing.expectEqualStrings("fence is not terminated", b3[0].problem.?);

    const at_eof = "text\n<!-- snippet: x.zig -->\n";
    const b4 = try extractBlocks(gpa, at_eof);
    defer gpa.free(b4);
    try testing.expectEqual(@as(usize, 1), b4.len);
    try testing.expectEqualStrings("marker is not followed by a fence", b4[0].problem.?);
}

// Non-vacuity: reads the REAL src/engine files. Renaming `bad_externalize_nh`
// or deleting arms below 15 in statement.zig, or reordering InputStatus in
// engine.zig, goes red here; the header-less case pins that a missing enum
// is an error, not an empty list (an empty list would pass a `>= 0` gate).
test "enum parser: real statement.zig >= 15 arms incl. bad_externalize_nh; engine.zig InputStatus 7 in order; missing header is EnumNotFound" {
    const gpa = testing.allocator;
    const io = testing.io;
    const statement = try std.Io.Dir.cwd().readFileAlloc(io, "src/engine/statement.zig", gpa, read_limit);
    defer gpa.free(statement);
    const arms = try parseEnumArms(gpa, statement, "InsaneReason");
    defer gpa.free(arms);
    try testing.expect(arms.len >= 15);
    var seen = false;
    for (arms) |a| {
        if (std.mem.eql(u8, a, "bad_externalize_nh")) seen = true;
    }
    try testing.expect(seen);
    try testing.expectEqualStrings("decode_error", arms[0]);

    const engine = try std.Io.Dir.cwd().readFileAlloc(io, "src/engine/engine.zig", gpa, read_limit);
    defer gpa.free(engine);
    const status = try parseEnumArms(gpa, engine, "InputStatus");
    defer gpa.free(status);
    const want = [_][]const u8{ "applied", "stale", "invalid_signature", "insane", "parked_awaiting_qset", "over_limit", "ignored" };
    try testing.expectEqual(want.len, status.len);
    for (want, status) |w, s| try testing.expectEqualStrings(w, s);

    try testing.expectError(error.EnumNotFound, parseEnumArms(gpa, "const x = 1;\n", "InputStatus"));
    try testing.expectError(error.EnumNotFound, parseEnumArms(gpa, engine, "NoSuchEnum"));
}

// Non-vacuity: `zig build X` is found in a bash fence AND in prose; `just X`
// only in a fence or a backtick span (prose "just waits" must NOT count);
// `hasBuildStep` must ignore a `b.step("…"` that lives in a `//` comment
// (drop the comment stripping and the last expectation fails).
test "token scanner: steps in bash fences and prose; hasBuildStep rejects comment-only matches" {
    const gpa = testing.allocator;
    const doc =
        \\Run `zig build test` first, then zig build e2e (slow).
        \\A node that comes up first just waits; use `just cli` to build.
        \\```sh
        \\zig build -Doptimize=ReleaseSafe run
        \\just example-smoke --slots 40
        \\zig build                      # default step
        \\```
        \\Readjust nothing.
        \\
    ;
    const toks = try scanStepTokens(gpa, doc);
    defer gpa.free(toks);
    try testing.expectEqual(@as(usize, 4), toks.len);
    try testing.expectEqualStrings("test", toks[0].name);
    try testing.expectEqual(@as(usize, 1), toks[0].line);
    try testing.expectEqualStrings("e2e", toks[1].name);
    try testing.expectEqualStrings("cli", toks[2].name);
    try testing.expectEqual(TokenKind.just, toks[2].kind);
    try testing.expectEqualStrings("example-smoke", toks[3].name);
    try testing.expectEqual(@as(usize, 5), toks[3].line);

    const build_zig =
        \\    // const old = b.step("old-step", "gone");
        \\    const t = b.step("test", "Run tests"); // b.step("commented", "")
        \\
    ;
    try testing.expect(hasBuildStep(build_zig, "test"));
    try testing.expect(!hasBuildStep(build_zig, "tests"));
    try testing.expect(!hasBuildStep(build_zig, "old-step"));
    try testing.expect(!hasBuildStep(build_zig, "commented"));

    const justfile = "# test: not a recipe\ntest:\n    zig build test\nexample-smoke *ARGS:\n    zig build example-smoke\n";
    try testing.expect(hasJustRecipe(justfile, "test"));
    try testing.expect(hasJustRecipe(justfile, "example-smoke"));
    try testing.expect(!hasJustRecipe(justfile, "tests"));
    try testing.expect(!hasJustRecipe(justfile, "example"));
}

// Non-vacuity: the CLI scanner takes the longest verb chain and stops at a
// non-verb argument; drop the second-verb step and `slcp key new` collapses
// to `slcp key` (which the help text also contains — so the expectation
// pins the full chain).
test "cli token scanner: backticked verbs, longest chain, prose only" {
    const gpa = testing.allocator;
    const doc = "Run `slcp key new slcp.key` then `slcp lint-quorum quorum.json`; `slcp key show <file>` prints it.\n```sh\n./zig-out/bin/slcp key new x\n```\n`slcp --help`\n";
    const toks = try scanCliTokens(gpa, doc);
    defer gpa.free(toks);
    try testing.expectEqual(@as(usize, 4), toks.len);
    try testing.expectEqualStrings("slcp key new", toks[0].needle);
    try testing.expectEqualStrings("slcp lint-quorum", toks[1].needle);
    try testing.expectEqualStrings("slcp key show", toks[2].needle);
    try testing.expectEqualStrings("slcp --help", toks[3].needle);
}

// Non-vacuity: a doc pinning v0.0.9 against a 0.1.0 manifest must be flagged
// — the scanner must strip `.tar.gz` and compare the bare version; and the
// REAL build.zig.zon must yield a version (a parse miss would make the pin
// needle `refs/tags/v.tar.gz`, which no doc contains — red, not vacuous).
test "version scanner: refs/tags/v0.0.9.tar.gz vs 0.1.0 is flagged; real manifest version parses" {
    const gpa = testing.allocator;
    const io = testing.io;
    const hits = try scanTagPins(gpa, "zig fetch --save=slcp https://x/archive/refs/tags/v0.0.9.tar.gz\nand refs/tags/v0.1.0.tar.gz\n");
    defer gpa.free(hits);
    try testing.expectEqual(@as(usize, 2), hits.len);
    try testing.expectEqualStrings("0.0.9", hits[0].version);
    try testing.expectEqual(@as(usize, 1), hits[0].line);
    try testing.expectEqualStrings("0.1.0", hits[1].version);
    try testing.expectEqual(@as(usize, 2), hits[1].line);
    try testing.expect(!std.mem.eql(u8, hits[0].version, "0.1.0"));

    const zon = try std.Io.Dir.cwd().readFileAlloc(io, "build.zig.zon", gpa, read_limit);
    defer gpa.free(zon);
    const v = parseManifestVersion(zon) orelse return error.NoVersion;
    try testing.expect(v.len > 0);
    try testing.expect(std.mem.count(u8, v, ".") == 2);
    try testing.expect(parseManifestVersion(".{ .name = .x }") == null);

    const mise = try std.Io.Dir.cwd().readFileAlloc(io, "mise.toml", gpa, read_limit);
    defer gpa.free(mise);
    const zig_pin = parseMiseZig(mise) orelse return error.NoZigPin;
    try testing.expect(std.mem.startsWith(u8, zig_pin, "0.17.0-dev."));
    const zhits = try scanZigPins(gpa, "mise use -g zig@0.17.0-dev.1786+75044cb04\nfloor 0.17.0-dev.1786.\n");
    defer gpa.free(zhits);
    try testing.expectEqual(@as(usize, 2), zhits.len);
    try testing.expectEqualStrings("0.17.0-dev.1786+75044cb04", zhits[0].version);
    try testing.expectEqualStrings("0.17.0-dev.1786", zhits[1].version);
}

// Non-vacuity: `option_fields` is the comptime field list of the live
// `slcp.NodeOptions`; a row naming a field that does not exist is rejected,
// and the frozen option names (plan §2) are accepted — rename `key_file` in
// node.zig and this goes red before the README does.
test "option rows: table rows parse; names are checked against slcp.NodeOptions" {
    const gpa = testing.allocator;
    const rows = try scanOptionRows(gpa, "| Option | Default |\n|---|---|\n| `.network` | — |\n| `.key_file` | null |\n| `.no_such_option` | ? |\nprose `.peers` is not a row\n");
    defer gpa.free(rows);
    try testing.expectEqual(@as(usize, 3), rows.len);
    try testing.expectEqualStrings("network", rows[0].version);
    try testing.expectEqual(@as(usize, 3), rows[0].line);
    try testing.expect(isOptionField("network"));
    try testing.expect(isOptionField("key_file"));
    try testing.expect(isOptionField("allow_unsafe_quorum"));
    try testing.expect(isOptionField("include_self"));
    try testing.expect(isOptionField("diagnostic"));
    try testing.expect(!isOptionField("no_such_option"));
    try testing.expect(option_fields.len >= 10);
}

// Non-vacuity: the evidence line is what `just preflight` greps and the
// `[FAIL] file:line: what (why)` shape is what a human greps; change either
// format string and this fails.
test "report: failure line shape and the evidence line" {
    const gpa = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    var rep = Report{ .out = &aw.writer };
    rep.check(true, "README.md", 1, "x", "y");
    rep.checkFmt(false, "README.md", 42, "snippet {s} is byte-equal to the file", .{"examples/bytes_node.zig"}, "first difference at body offset {d}", .{7});
    rep.summary();
    try testing.expectEqual(@as(usize, 2), rep.checks);
    try testing.expectEqual(@as(usize, 1), rep.failures);
    try testing.expectEqualStrings("[FAIL] README.md:42: snippet examples/bytes_node.zig is byte-equal to the file (first difference at body offset 7)\n[docs-smoke] checks=2 failures=1\n", aw.written());
}

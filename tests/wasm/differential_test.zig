//! Differential native-vs-wasm harness (design §13.5 "Differential fuzz",
//! §14-M4 accept: "all trace vectors replay byte-identically through the real
//! wasm"). This is the M4 acceptance core: the same inputs go into the NATIVE
//! `engine.Engine` and into `zig-out/bin/slcp_core.wasm` driven through the
//! frozen §7.2 ABI, and every effect frame must come back BYTE-IDENTICAL from
//! both — and, for the recorded trace vectors, byte-identical to the frozen
//! recording as well. Any drift in the codec, the ABI, or the driver-import
//! bridge (§7.3) fails here instead of at a cross-implementation boundary.
//!
//! Running the full gate:
//!
//!     zig build wasm && zig build wasm-diff
//!
//! `zig build wasm-diff` builds `slcp_core.wasm` itself, so it never silently
//! skips. `zig build test` runs the SAME tests through a second run step that
//! does NOT depend on the wasm artifact: on a clean tree (no `zig build wasm`
//! yet) every test here reports `error.SkipZigTest` and the plain test suite
//! still passes. The same skip covers a missing `node` and missing
//! `vectors/traces/*.bin`.
//!
//! The wasm side is driven by `tests/wasm/host.mjs` — a Node/Deno runner that
//! supplies the three `slcp_driver` imports with the DEFAULT driver semantics
//! (§8.4) and speaks newline-delimited JSON with hex payloads (protocol
//! documented in that file's header). It has to be a real WebAssembly
//! embedding rather than the wasmtime CLI because this ABI is not
//! zero-import: `combine_candidates` re-enters `slcp_alloc` mid-transition.
//!
//! What is compared, and on which channel:
//!   - NORMATIVE (trace kind 2): native frame == wasm frame == recorded frame,
//!     byte-exact, in queue order.
//!   - OBSERVABLE (trace kind 3, `phase_event` only): compared in a SEPARATE
//!     pass so the §13.4 normative/observability split stays visible — a
//!     conforming replayer may ignore kind-3 records entirely.
//!   - Queue accounting: `slcp_engine_effect_count` vs the native
//!     `effects.len()`, checked before every drain.
//!   - Push agreement: a native `pushInput` error must coincide with the
//!     ABI's `slcp_engine_push_input` returning 0 (a typed refusal, §7.2).
//!
//! Test list:
//!   1. ABI version / feature-flag negotiation (§7.2, §14-M4 accept).
//!   2. Trace-vector replay: native vs wasm vs recorded.
//!   3. Differential fuzz: `fuzz_iterations` iterations, each a deterministic
//!      consensus warm-up (`seedConsensus`) followed by up to `fuzz_steps`
//!      random valid-typed inputs, byte-identical effect sequences at EVERY
//!      step (§13.5). The generator mirrors the shape space of
//!      tests/fuzz/input_seq_fuzz.zig's `stepOnce` (nominate / timer / forged
//!      envelope / garbage envelope / qset answer / purge / own-frame
//!      restore) and mints peer envelopes with the same `adversary.Forger`.
//!      Its summary line is the run's evidence — inputs, effect frames,
//!      effect shapes, sticky refusals, and the `slcp_driver` import counts.
//!   4. Tooling exports: `slcp_qset_hash` and `slcp_lint_qset` frames agree
//!      with the native `qset.hashNormalized` / lint encoding.
//!
//! Those summary lines go to stderr, so `zig build` echoes the test command
//! next to them ("failed command: ..."). That is build-runner noise for any
//! step that writes to stderr — the step's exit status, and
//! `zig build wasm-diff --summary all`, are what say whether it passed.
//!
//! FIXED DEFECT (found by this harness on its first run) — stored-bytes
//! accounting underflow. `nomination.emitNomination` self-stored the emitted
//! envelope into `slot.latest_nom` while DISCARDING the `storeLatest` byte
//! delta, so `Slot.storedBytes()` counted those bytes but
//! `Engine.stored_statement_bytes` never did; `handlePurge` subtracted the
//! former from the latter and underflowed. It was a genuine NATIVE-vs-WASM
//! divergence: native ReleaseSafe panicked while the ReleaseSmall wasm
//! wrapped the counter silently and kept applying inputs — precisely the
//! class of bug this harness exists to catch, and invisible to every
//! native-only suite. Fixed by giving `engine.Ctx` the counter
//! (`Ctx.addStoredBytes`) so protocol self-stores account, with a saturating
//! subtraction in `handlePurge` as defense in depth. The guard, the tally and
//! the pinning test are gone; the reproducer now runs as an ordinary
//! differential case.

const std = @import("std");
const slcp = @import("slcp-core");
const adversary = @import("adversary");

const engine = slcp.engine;
const driver = slcp.driver;
const host_codec = slcp.host_codec;
const qset = slcp.qset;
const crypto = slcp.crypto;
const canonical = slcp.canonical;
const capnpc = slcp.capnpc;
const gen_host = slcp.gen.host;

const testing = std.testing;
const json = std.json;

const wasm_path = "zig-out/bin/slcp_core.wasm";
const host_script = "tests/wasm/host.mjs";

/// One response line holds a whole drain's worth of hex effect frames; 4 MiB
/// is far above anything these scenarios produce (a HARNESS limit, not an ABI
/// one — `EffectQueue.max_bytes` is 16 MiB).
const response_buf_bytes = 4 * 1024 * 1024;

/// Strings must be copied out of the reader buffer: the next line read
/// overwrites it.
const parse_options: json.ParseOptions = .{ .allocate = .alloc_always };

// ---------------------------------------------------------------------------
// Expectations pinned against the FROZEN ABI (src/wasm/slcp_host_abi.zig).
// They are duplicated here rather than imported because that file is a
// wasm32-freestanding root with `export`/`extern` declarations — it cannot be
// compiled into a native test. Duplication is the point: a change to the
// frozen constants has to be made in two places on purpose.
// ---------------------------------------------------------------------------
const abi_version: u32 = 1;
const abi_min_version: u32 = 1;
const abi_max_version: u32 = 1;
/// bit 0 = driver imports required, bit 1 = external_signer (OFF in v1),
/// bit 2 = lint exports present.
const abi_feature_flags: u64 = 0b101;

// ---------------------------------------------------------------------------
// Host runner handle
// ---------------------------------------------------------------------------

/// A live `node tests/wasm/host.mjs` process. Heap-allocated and never moved:
/// `std.Io.File.Reader` embeds an interface reached by pointer.
const Host = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    child: std.process.Child,
    buf: []u8,
    rdr: std.Io.File.Reader,
    next_id: u64 = 1,

    /// Returns `error.SkipZigTest` when the wasm artifact, the runner script,
    /// or `node` is absent, so a clean-tree `zig build test` stays green.
    fn start(gpa: std.mem.Allocator) !*Host {
        const io = testing.io;
        std.Io.Dir.cwd().access(io, wasm_path, .{ .read = true }) catch return error.SkipZigTest;
        std.Io.Dir.cwd().access(io, host_script, .{ .read = true }) catch return error.SkipZigTest;

        const child = std.process.spawn(io, .{
            .argv = &.{ "node", host_script, wasm_path },
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .inherit, // runner stack traces land in the test log
        }) catch |err| switch (err) {
            error.FileNotFound => return error.SkipZigTest, // no node on PATH
            else => return err,
        };

        const self = try gpa.create(Host);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .child = child,
            .buf = try gpa.alloc(u8, response_buf_bytes),
            .rdr = undefined,
        };
        self.rdr = self.child.stdout.?.readerStreaming(io, self.buf);
        return self;
    }

    fn stop(self: *Host) void {
        if (self.child.stdin) |in| {
            in.writeStreamingAll(self.io, "{\"cmd\":\"quit\"}\n") catch {};
            in.close(self.io);
            self.child.stdin = null;
        }
        _ = self.child.wait(self.io) catch {};
        self.gpa.free(self.buf);
        self.gpa.destroy(self);
    }

    /// Send one request line and parse the single response line into `arena`.
    /// The protocol is strictly request/response — never pipelined.
    fn call(self: *Host, arena: std.mem.Allocator, req: []const u8) !json.Value {
        try self.child.stdin.?.writeStreamingAll(self.io, req);
        try self.child.stdin.?.writeStreamingAll(self.io, "\n");
        // takeDelimiterInclusive, not ...Exclusive: the Exclusive variant
        // tosses only the returned bytes and leaves the '\n' buffered, so
        // every second call would return an empty line.
        const with_nl = self.rdr.interface.takeDelimiterInclusive('\n') catch |err| {
            std.debug.print("host runner died or overflowed the {d}-byte line buffer: {s}\n", .{ response_buf_bytes, @errorName(err) });
            return err;
        };
        const line = with_nl[0 .. with_nl.len - 1];
        return json.parseFromSliceLeaky(json.Value, arena, line, parse_options) catch |err| {
            std.debug.print("host runner sent unparseable line (len={d}): {s}\n", .{ line.len, line });
            return err;
        };
    }

    /// `call` plus the `ok:true` assertion; an `ok:false` prints the ABI's
    /// sticky error (code + static text) before failing.
    fn callOk(self: *Host, arena: std.mem.Allocator, req: []const u8) !json.Value {
        const v = try self.call(arena, req);
        if (!v.object.get("ok").?.bool) {
            std.debug.print("host runner error for {s}: {f}\n", .{ req, json.fmt(v, .{}) });
            return error.HostRunnerFailed;
        }
        return v;
    }

    fn nextId(self: *Host) u64 {
        const id = self.next_id;
        self.next_id += 1;
        return id;
    }
};

// ---------------------------------------------------------------------------
// Request building / hex
// ---------------------------------------------------------------------------

fn hexAppend(list: *std.ArrayList(u8), gpa: std.mem.Allocator, bytes: []const u8) !void {
    const digits = "0123456789abcdef";
    try list.ensureUnusedCapacity(gpa, bytes.len * 2);
    for (bytes) |b| {
        list.appendAssumeCapacity(digits[b >> 4]);
        list.appendAssumeCapacity(digits[b & 0xf]);
    }
}

fn hexToBytes(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

/// `{"id":N,"cmd":"<cmd>"[,"handle":H][,"<field>":"<hex>"]}` — no escaping
/// needed: every value is an integer or lowercase hex.
fn request(
    gpa: std.mem.Allocator,
    id: u64,
    cmd: []const u8,
    handle: ?u64,
    field_name: ?[]const u8,
    payload: ?[]const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.print(gpa, "{{\"id\":{d},\"cmd\":\"{s}\"", .{ id, cmd });
    if (handle) |h| try out.print(gpa, ",\"handle\":{d}", .{h});
    if (field_name) |f| {
        try out.print(gpa, ",\"{s}\":\"", .{f});
        try hexAppend(&out, gpa, payload.?);
        try out.append(gpa, '"');
    }
    try out.append(gpa, '}');
    return out.toOwnedSlice(gpa);
}

fn printHex(bytes: []const u8) void {
    for (bytes) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
}

// ---------------------------------------------------------------------------
// The paired engines
// ---------------------------------------------------------------------------

/// One native engine and one wasm engine built from the SAME EngineConfig
/// frame, driven in lockstep.
const Pair = struct {
    gpa: std.mem.Allocator,
    host: *Host,
    native: engine.Engine,
    handle: u64,
    /// Sticky error (§7.2) taken from the ABI after the most recent refused
    /// push, via `slcp_error_take`. Reported by the fuzz so a wave of
    /// refusals names its own cause instead of vanishing into a counter.
    last_refusal_code: i64 = 0,
    last_refusal_msg: []const u8 = "",
    /// Input union tag that produced it (a static `@tagName` string).
    last_refusal_input: []const u8 = "",

    const PushResult = enum { applied, refused };

    fn init(gpa: std.mem.Allocator, host: *Host, cfg_frame: []const u8) !Pair {
        var cfg = try host_codec.decodeEngineConfig(gpa, cfg_frame);
        var native = engine.Engine.init(gpa, cfg, driver.Driver.default()) catch |err| {
            cfg.quorum_set.deinit(gpa); // init takes ownership on success only
            return err;
        };
        errdefer native.deinit();

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const res = try host.callOk(arena, try request(arena, host.nextId(), "new", null, "config", cfg_frame));
        return .{
            .gpa = gpa,
            .host = host,
            .native = native,
            .handle = @intCast(res.object.get("handle").?.integer),
        };
    }

    fn deinit(self: *Pair) void {
        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        if (request(arena, self.host.nextId(), "free", self.handle, null, null)) |req| {
            _ = self.host.callOk(arena, req) catch {};
        } else |_| {}
        self.native.deinit();
        self.* = undefined;
    }

    /// Push one already-encoded §7.1 Input frame into BOTH engines and assert
    /// they agree on acceptance. The native side decodes the same bytes the
    /// wasm side gets, so nothing but the codec sits between them.
    fn push(self: *Pair, arena: std.mem.Allocator, input_frame: []const u8) !PushResult {
        var decoded = try host_codec.decodeInput(self.gpa, input_frame);
        defer host_codec.deinitInput(self.gpa, &decoded);

        var native_failed = false;
        self.native.pushInput(decoded) catch {
            native_failed = true;
        };

        const res = try self.host.callOk(arena, try request(arena, self.host.nextId(), "push", self.handle, "input", input_frame));
        const wasm_failed = res.object.get("pushed").?.integer == 0;

        if (native_failed != wasm_failed) {
            std.debug.print(
                "PUSH DIVERGENCE: native_failed={} wasm_failed={} wasm_response={f}\n  input frame = ",
                .{ native_failed, wasm_failed, json.fmt(res, .{}) },
            );
            printHex(input_frame);
            return error.PushDivergence;
        }
        if (wasm_failed) {
            // The ABI's sticky error, taken atomically by the runner.
            self.last_refusal_code = res.object.get("errCode").?.integer;
            self.last_refusal_msg = try arena.dupe(u8, res.object.get("errMsg").?.string);
            self.last_refusal_input = @tagName(decoded);
        }
        return if (native_failed) .refused else .applied;
    }

    /// Drain both engines, asserting frame-for-frame byte identity. Returns
    /// the native frames (arena-allocated) so the caller can additionally
    /// compare them against a recorded trace.
    fn drain(self: *Pair, arena: std.mem.Allocator) ![][]const u8 {
        // Queue accounting must agree BEFORE either side is drained.
        {
            const res = try self.host.callOk(arena, try request(arena, self.host.nextId(), "counts", self.handle, null, null));
            const wasm_count: usize = @intCast(res.object.get("count").?.integer);
            const wasm_bytes: usize = @intCast(res.object.get("bytes").?.integer);
            if (wasm_count != self.native.effects.len() or wasm_bytes != self.native.effects.bytes()) {
                std.debug.print(
                    "EFFECT-QUEUE ACCOUNTING DIVERGENCE: native={d} effects/{d} bytes, wasm={d}/{d}\n",
                    .{ self.native.effects.len(), self.native.effects.bytes(), wasm_count, wasm_bytes },
                );
                return error.EffectCountDivergence;
            }
        }

        var native_frames: std.ArrayList([]const u8) = .empty;
        while (self.native.popEffect()) |eff| {
            try native_frames.append(arena, try host_codec.encodeEffect(arena, eff));
            self.native.commitEffect();
        }

        const res = try self.host.callOk(arena, try request(arena, self.host.nextId(), "drain", self.handle, null, null));
        const wasm_items = res.object.get("effects").?.array.items;

        if (wasm_items.len != native_frames.items.len) {
            std.debug.print(
                "EFFECT-SEQUENCE DIVERGENCE: native produced {d} effects, wasm {d}\n",
                .{ native_frames.items.len, wasm_items.len },
            );
            for (native_frames.items, 0..) |f, i| {
                std.debug.print("  native[{d}] = ", .{i});
                printHex(f);
            }
            for (wasm_items, 0..) |f, i| std.debug.print("  wasm  [{d}] = {s}\n", .{ i, f.string });
            return error.EffectSequenceDivergence;
        }

        for (native_frames.items, wasm_items, 0..) |ours, theirs, i| {
            const wasm_bytes = try hexToBytes(arena, theirs.string);
            if (!std.mem.eql(u8, ours, wasm_bytes)) {
                std.debug.print("EFFECT FRAME DIVERGENCE at index {d}\n  native = ", .{i});
                printHex(ours);
                std.debug.print("  wasm   = {s}\n", .{theirs.string});
                return error.EffectFrameDivergence;
            }
        }
        return native_frames.items;
    }
};

// ---------------------------------------------------------------------------
// 1. ABI version / feature negotiation (§7.2)
// ---------------------------------------------------------------------------

test "wasm ABI: version and feature-flag negotiation" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const host = try Host.start(testing.allocator);
    defer host.stop();

    const res = try host.callOk(arena, try request(arena, host.nextId(), "abi", null, null, null));
    try testing.expectEqual(@as(i64, abi_version), res.object.get("version").?.integer);
    try testing.expectEqual(@as(i64, abi_min_version), res.object.get("min").?.integer);
    try testing.expectEqual(@as(i64, abi_max_version), res.object.get("max").?.integer);

    const lo: u64 = @intCast(res.object.get("flagsLo").?.integer);
    const hi: u64 = @intCast(res.object.get("flagsHi").?.integer);
    const flags = lo | (hi << 32);
    try testing.expectEqual(abi_feature_flags, flags);
    try testing.expect(flags & 0b001 != 0); // driver imports required
    try testing.expect(flags & 0b010 == 0); // external_signer OFF in v1
    try testing.expect(flags & 0b100 != 0); // lint exports present

    const ver = try host.callOk(arena, try request(arena, host.nextId(), "version", null, null, null));
    try testing.expect(std.mem.startsWith(u8, ver.object.get("version").?.string, "slcp-core "));
}

// ---------------------------------------------------------------------------
// 2. Trace-vector replay: native vs wasm vs recorded
// ---------------------------------------------------------------------------

const trace_magic = "SLCPTRC1";
const trace_names = [_][]const u8{
    "single-node-1of1",
    "insane-and-stale",
    "qset-park-resume",
    "timer-bump",
};

const TraceRecord = struct { kind: u8, payload: []const u8 };

fn parseTrace(gpa: std.mem.Allocator, bytes: []const u8) ![]TraceRecord {
    if (bytes.len < trace_magic.len or !std.mem.eql(u8, bytes[0..trace_magic.len], trace_magic))
        return error.BadTraceMagic;
    var recs: std.ArrayList(TraceRecord) = .empty;
    var i: usize = trace_magic.len;
    while (i < bytes.len) {
        if (bytes.len - i < 5) return error.TruncatedTraceRecord;
        const kind = bytes[i];
        const len = std.mem.readInt(u32, bytes[i + 1 ..][0..4], .little);
        i += 5;
        if (bytes.len - i < len) return error.TruncatedTraceRecord;
        try recs.append(gpa, .{ .kind = kind, .payload = bytes[i .. i + len] });
        i += len;
    }
    return recs.items;
}

fn readTrace(gpa: std.mem.Allocator, name: []const u8) !?[]u8 {
    const path = try std.fmt.allocPrint(gpa, "vectors/traces/{s}.bin", .{name});
    defer gpa.free(path);
    return std.Io.Dir.cwd().readFileAlloc(testing.io, path, gpa, .unlimited) catch null;
}

/// A recorded observable (kind-3) frame and its replay, compared in a pass of
/// their own.
const ObservablePair = struct { recorded: []const u8, replayed: []const u8 };

test "wasm differential: trace vectors replay byte-identically (native vs wasm vs recorded)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const host = try Host.start(testing.allocator);
    defer host.stop();

    var traces_compared: usize = 0;
    var normative_compared: usize = 0;
    var observable: std.ArrayList(ObservablePair) = .empty;

    for (trace_names) |name| {
        const bytes = (try readTrace(arena, name)) orelse return error.SkipZigTest;
        const recs = try parseTrace(arena, bytes);
        try testing.expect(recs.len >= 2);
        try testing.expectEqual(@as(u8, 0), recs[0].kind); // config first

        var pair = try Pair.init(testing.allocator, host, recs[0].payload);
        defer pair.deinit();

        var idx: usize = 1;
        while (idx < recs.len) {
            try testing.expectEqual(@as(u8, 1), recs[idx].kind);
            const input_frame = recs[idx].payload;
            idx += 1;

            // A recorded trace only holds inputs the engine accepted.
            const outcome = pair.push(arena, input_frame) catch |err| {
                std.debug.print("trace {s}: push diverged at record {d}\n", .{ name, idx - 1 });
                return err;
            };
            try testing.expectEqual(Pair.PushResult.applied, outcome);

            const frames = pair.drain(arena) catch |err| {
                std.debug.print("trace {s}: drain diverged after record {d}\n", .{ name, idx - 1 });
                return err;
            };

            // The recorded effect records for this input, in queue order.
            var f: usize = 0;
            while (idx < recs.len and recs[idx].kind != 1) : (idx += 1) {
                if (f >= frames.len) {
                    std.debug.print("trace {s}: recording has MORE effects than the replay\n", .{name});
                    return error.TraceEffectCountMismatch;
                }
                const rec = recs[idx];
                switch (rec.kind) {
                    2 => {
                        // NORMATIVE: byte-exact, no exceptions.
                        if (!std.mem.eql(u8, rec.payload, frames[f])) {
                            std.debug.print("trace {s}: NORMATIVE frame {d} diverges\n  recorded = ", .{ name, f });
                            printHex(rec.payload);
                            std.debug.print("  replayed = ", .{});
                            printHex(frames[f]);
                            return error.TraceNormativeDivergence;
                        }
                        normative_compared += 1;
                    },
                    3 => try observable.append(arena, .{ .recorded = rec.payload, .replayed = frames[f] }),
                    else => return error.BadTraceRecordKind,
                }
                f += 1;
            }
            if (f != frames.len) {
                std.debug.print("trace {s}: replay produced MORE effects than the recording\n", .{name});
                return error.TraceEffectCountMismatch;
            }
        }
        traces_compared += 1;
    }

    // OBSERVABLE channel (kind 3, phase_event only) — a separate pass, so the
    // §13.4 normative/observability split stays visible: a conforming
    // replayer may drop this assertion entirely.
    for (observable.items, 0..) |p, i| {
        if (!std.mem.eql(u8, p.recorded, p.replayed)) {
            std.debug.print("OBSERVABLE frame {d} diverges\n  recorded = ", .{i});
            printHex(p.recorded);
            std.debug.print("  replayed = ", .{});
            printHex(p.replayed);
            return error.TraceObservableDivergence;
        }
        var eff = try host_codec.decodeEffect(arena, p.replayed);
        defer eff.deinitPayload(arena);
        try testing.expect(eff == .phase_event); // kind 3 really is phase_event
    }

    try testing.expectEqual(trace_names.len, traces_compared);
    try testing.expect(normative_compared > 0);
    try testing.expect(observable.items.len > 0);
    std.debug.print(
        "\n[wasm-diff] traces={d} normative_effects={d} observable_effects={d}\n",
        .{ traces_compared, normative_compared, observable.items.len },
    );
}

// ---------------------------------------------------------------------------
// 3. Differential fuzz (§13.5)
// ---------------------------------------------------------------------------

pub const fuzz_iterations: usize = 300;
pub const fuzz_steps: usize = 12;
pub const fuzz_seed: u64 = 0x5c1c_d1ff_2608_2726;

const sim_passphrase = "slcp-sim v1";
const n_members: u8 = 4;
const max_value_bytes = 40;

fn nodeSeed(i: u8) [32]u8 {
    var s: [32]u8 = @splat(0);
    s[0] = i +% 1;
    return s;
}

/// Everything the fuzz needs that is INDEPENDENT of a single iteration: the
/// shared quorum set (as an EngineConfig frame and as an answerable framed
/// QuorumSet) and one `Forger` per PEER validator of that set, so their
/// envelopes pass the §5.4 relevance filter instead of being dropped.
///
/// Three peers (not one) on purpose: with a 3-of-4 threshold a single forged
/// key can never complete a quorum, so nomination would never reach federated
/// accept and `combine_candidates` — the re-entrant §7.3 import, and the only
/// one whose argument the runner has to capnp-decode — would go untested.
const FuzzWorld = struct {
    cfg_frame: []u8,
    shared_framed: []u8,
    shared_hash: [32]u8,
    forgers: [n_members - 1]adversary.Forger,

    fn init(gpa: std.mem.Allocator) !FuzzWorld {
        var pks: [n_members][32]u8 = undefined;
        for (0..n_members) |i| pks[i] = try crypto.publicKeyFromSeed(nodeSeed(@intCast(i)));

        var shared = qset.QuorumSetOwned{
            .threshold = (2 * @as(u32, n_members) + 2) / 3,
            .validators = try gpa.dupe([32]u8, pks[0..]),
            .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
        };
        defer shared.deinit(gpa);
        try qset.validateAndNormalize(gpa, &shared);

        const shared_flat = try qset.canonicalBytes(gpa, &shared);
        defer gpa.free(shared_flat);
        const shared_hash = crypto.qsetHash(shared_flat);
        const shared_framed = try canonical.frameFlat(gpa, shared_flat);
        errdefer gpa.free(shared_framed);

        const net = crypto.networkIdFromPassphrase(sim_passphrase);
        var cfg = engine.Config{
            .network_id = net,
            .node_id = pks[0],
            .secret_seed = nodeSeed(0),
            .quorum_set = try qset.clone(gpa, &shared),
        };
        defer cfg.quorum_set.deinit(gpa);
        const cfg_frame = try host_codec.encodeEngineConfig(gpa, &cfg);
        errdefer gpa.free(cfg_frame);

        var forgers: [n_members - 1]adversary.Forger = undefined;
        for (0..n_members - 1) |i| forgers[i] = try adversary.Forger.init(gpa, nodeSeed(@intCast(i + 1)), net);

        return .{
            .cfg_frame = cfg_frame,
            .shared_framed = shared_framed,
            .shared_hash = shared_hash,
            .forgers = forgers,
        };
    }

    fn deinit(self: *FuzzWorld, gpa: std.mem.Allocator) void {
        gpa.free(self.cfg_frame);
        gpa.free(self.shared_framed);
        self.* = undefined;
    }
};

fn pickBallot(rand: std.Random, value: []const u8) adversary.BV {
    return .{ .counter = rand.uintAtMost(u32, 6), .value = value };
}

/// A small SHARED value pool. Purely random values never coincide across
/// peers, so federated accept — and with it the nomination→ballot transition
/// that calls `combine_candidates` — would be unreachable. Drawing mostly
/// from a four-value pool over a three-slot range makes agreement likely
/// while random draws still cover the arbitrary-bytes space.
const value_pool = [_][]const u8{ "value-A", "value-B", "value-C", "value-D" };

/// Derive ONE arbitrary valid-typed Input frame (§7.1) — the same shape space
/// as tests/fuzz/input_seq_fuzz.zig's `stepOnce`. `last_own` is the newest own
/// envelope frame the pair emitted (for the restore path), or null. Returns
/// null when this draw has nothing to push (e.g. restore with no own frame
/// yet). The frame is allocated on `arena`.
fn randomInputFrame(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    world: *FuzzWorld,
    rand: std.Random,
    last_own: ?[]const u8,
) !?[]u8 {
    const slot = rand.intRangeAtMost(u64, 1, 3);
    var vbuf: [max_value_bytes]u8 = undefined;
    const value: []const u8 = if (rand.uintLessThan(u8, 4) != 0)
        value_pool[rand.uintLessThan(usize, value_pool.len)]
    else blk: {
        const vlen = rand.uintAtMost(usize, max_value_bytes);
        rand.bytes(vbuf[0..vlen]);
        break :blk vbuf[0..vlen];
    };

    switch (rand.uintAtMost(u8, 6)) {
        0 => return try host_codec.encodeInput(arena, .{
            .nominate = .{ .slot = slot, .value = value, .prev_value = &.{} },
        }),
        1 => return try host_codec.encodeInput(arena, .{ .timer_fired = .{
            .slot = slot,
            .timer = if (rand.boolean()) engine.TimerId.ballot else engine.TimerId.nomination,
        } }),
        2 => {
            // A real key-holder envelope with random content. Mostly the
            // shared hash (statements resolve); occasionally a random one, so
            // the park path (request_qset) is exercised too.
            var hash: [32]u8 = world.shared_hash;
            if (rand.uintLessThan(u8, 8) == 0) rand.bytes(&hash);
            const raw: adversary.RawStatement = switch (rand.uintAtMost(u8, 3)) {
                0 => .{ .nominate = .{ .qset_hash = hash, .votes = &.{value}, .accepted = &.{} } },
                1 => .{ .prepare = .{ .qset_hash = hash, .ballot = pickBallot(rand, value) } },
                2 => .{ .confirm = .{
                    .qset_hash = hash,
                    .ballot = pickBallot(rand, value),
                    .n_prepared = rand.uintAtMost(u32, 6),
                    .n_commit = rand.uintAtMost(u32, 6),
                    .n_h = rand.uintAtMost(u32, 6),
                } },
                else => .{ .externalize = .{
                    .commit = pickBallot(rand, value),
                    .n_h = rand.uintAtMost(u32, 6),
                    .commit_qset_hash = hash,
                } },
            };
            // Forger allocates from the gpa it was constructed with.
            const peer = &world.forgers[rand.uintLessThan(usize, world.forgers.len)];
            const env = peer.sign(slot, raw) catch return null;
            defer gpa.free(env);
            return try host_codec.encodeInput(arena, .{ .envelope_received = .{ .bytes = env } });
        },
        3 => return try host_codec.encodeInput(arena, .{ .qset_received = .{ .bytes = world.shared_framed } }),
        4 => return try host_codec.encodeInput(arena, .{
            .purge_slots = .{ .max_slot = rand.uintAtMost(u64, 8) },
        }),
        5 => {
            // A MID-STREAM own-envelope replay. §10 makes this a startup-only
            // input in practice, and the engine answers it with a sticky
            // failure (both sides agree — see `sticky_refusals` on the
            // summary line), which retires the pair. Drawn at 1-in-4 of this
            // slot so the path stays covered without truncating most
            // iterations before they reach the ballot protocol.
            if (rand.uintLessThan(u8, 4) != 0) return null;
            const frame = last_own orelse return null;
            return try host_codec.encodeInput(arena, .{ .restore_own_envelope = .{ .bytes = frame } });
        },
        else => {
            // A typed envelope carrying arbitrary garbage bytes.
            var gbuf: [64]u8 = undefined;
            const glen = rand.uintAtMost(usize, 64);
            rand.bytes(gbuf[0..glen]);
            return try host_codec.encodeInput(arena, .{ .envelope_received = .{ .bytes = gbuf[0..glen] } });
        },
    }
}

/// Deterministic warm-up pushed at the head of every iteration: answer the
/// qset, nominate locally, then let all three peers nominate the SAME value
/// at the same slot. That completes the 3-of-4 threshold, so federated accept
/// fires and nomination hands off to the ballot protocol — which is the only
/// way `combine_candidates` (the re-entrant §7.3 import whose ValueList frame
/// the runner decodes by hand) is ever reached. Purely random draws never
/// agree often enough to get there, so without this the fuzz would compare
/// nothing but nomination-phase effects.
///
/// This is seeding, not shortcutting: every warm-up input goes through the
/// same `Pair.push`/`Pair.drain` differential as the random ones.
fn seedConsensus(
    arena: std.mem.Allocator,
    world: *FuzzWorld,
    rand: std.Random,
    pair: *Pair,
    tally: *Tally,
) !void {
    const slot = rand.intRangeAtMost(u64, 1, 3);
    const value = value_pool[rand.uintLessThan(usize, value_pool.len)];

    var seq: std.ArrayList([]const u8) = .empty;
    try seq.append(arena, try host_codec.encodeInput(arena, .{
        .qset_received = .{ .bytes = world.shared_framed },
    }));
    try seq.append(arena, try host_codec.encodeInput(arena, .{
        .nominate = .{ .slot = slot, .value = value, .prev_value = &.{} },
    }));
    for (&world.forgers) |*peer| {
        const env = try peer.sign(slot, .{ .nominate = .{
            .qset_hash = world.shared_hash,
            .votes = &.{value},
            .accepted = &.{value},
        } });
        defer pair.gpa.free(env);
        try seq.append(arena, try host_codec.encodeInput(arena, .{
            .envelope_received = .{ .bytes = env },
        }));
    }

    for (seq.items) |frame| {
        tally.inputs += 1;
        if (try pair.push(arena, frame) == .refused) {
            tally.noteRefusal(pair);
            return;
        }
        try tally.record(arena, try pair.drain(arena));
    }
}

/// Cumulative shape of everything the fuzz drove — reported at the end and
/// used as the non-vacuity gate (a differential that compared nothing must
/// not pass).
const Tally = struct {
    inputs: usize = 0,
    effects: usize = 0,
    refusals: usize = 0,
    /// Iterations retired early by the known stored-bytes accounting defect.
    own_envelopes: usize = 0,
    broadcasts: usize = 0,
    externalized: usize = 0,
    /// Newest own envelope frame, for the `restore_own_envelope` draw.
    last_own: ?[]const u8 = null,
    /// The ABI sticky error behind the most recent refusal (§7.2), copied out
    /// of the per-iteration arena so it survives to the summary line.
    refusal_code: i64 = 0,
    refusal_input: []const u8 = "",
    refusal_msg_buf: [64]u8 = @splat(0),
    refusal_msg_len: usize = 0,

    fn noteRefusal(self: *Tally, pair: *const Pair) void {
        self.refusals += 1;
        self.refusal_code = pair.last_refusal_code;
        self.refusal_input = pair.last_refusal_input; // static tag name
        const n = @min(self.refusal_msg_buf.len, pair.last_refusal_msg.len);
        @memcpy(self.refusal_msg_buf[0..n], pair.last_refusal_msg[0..n]);
        self.refusal_msg_len = n;
    }

    fn refusalMsg(self: *const Tally) []const u8 {
        return self.refusal_msg_buf[0..self.refusal_msg_len];
    }

    fn record(self: *Tally, arena: std.mem.Allocator, frames: [][]const u8) !void {
        self.effects += frames.len;
        for (frames) |f| {
            var eff = try host_codec.decodeEffect(arena, f);
            defer eff.deinitPayload(arena);
            switch (eff) {
                .persist_own_envelope => |sb| {
                    self.own_envelopes += 1;
                    self.last_own = try arena.dupe(u8, sb.bytes);
                },
                .broadcast_envelope => self.broadcasts += 1,
                .externalized => self.externalized += 1,
                else => {},
            }
        }
    }
};

test "wasm differential fuzz: random input sequences produce byte-identical effects" {
    const gpa = testing.allocator;

    const host = try Host.start(gpa);
    defer host.stop();

    var world = try FuzzWorld.init(gpa);
    defer world.deinit(gpa);

    var prng = std.Random.DefaultPrng.init(fuzz_seed);
    const rand = prng.random();

    var tally: Tally = .{};

    var iter: usize = 0;
    while (iter < fuzz_iterations) : (iter += 1) {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var pair = try Pair.init(gpa, host, world.cfg_frame);
        defer pair.deinit();

        tally.last_own = null; // arena-scoped: never outlives this iteration
        seedConsensus(arena, &world, rand, &pair, &tally) catch |err| {
            std.debug.print("fuzz iter {d}: warm-up diverged\n", .{iter});
            return err;
        };

        var step: usize = 0;
        while (step < fuzz_steps) : (step += 1) {
            const frame = (try randomInputFrame(gpa, arena, &world, rand, tally.last_own)) orelse continue;
            tally.inputs += 1;

            const outcome = pair.push(arena, frame) catch |err| switch (err) {
                else => {
                    std.debug.print("fuzz iter {d} step {d}: push diverged\n", .{ iter, step });
                    return err;
                },
            };
            const frames = pair.drain(arena) catch |err| {
                std.debug.print("fuzz iter {d} step {d}: drain diverged\n", .{ iter, step });
                return err;
            };
            try tally.record(arena, frames);

            if (outcome == .refused) {
                tally.noteRefusal(&pair);
                break; // both engines sticky-failed identically; retire the pair
            }
        }
    }

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const stats = try host.callOk(arena, try request(arena, host.nextId(), "stats", null, null, null));
    const validates = stats.object.get("validate").?.integer;
    const combines = stats.object.get("combine").?.integer;

    // Printed BEFORE the gates so a non-vacuity failure names its own numbers.
    std.debug.print(
        "\n[wasm-diff] fuzz iters={d} inputs={d} effects={d} own_envelopes={d} broadcasts={d}" ++
            " externalized={d} sticky_refusals={d} (last: on {s}, code={d} \"{s}\")" ++
            " driver(validate={d},combine={d},extract={d})\n",
        .{
            fuzz_iterations,
            tally.inputs,
            tally.effects,
            tally.own_envelopes,
            tally.broadcasts,
            tally.externalized,
            tally.refusals,
            tally.refusal_input,
            tally.refusal_code,
            tally.refusalMsg(),
            validates,
            combines,
            stats.object.get("extract").?.integer,
        },
    );

    // Non-vacuity: a differential that compared nothing must not pass. The
    // run has to have driven real inputs, produced real effects, emitted own
    // statements (so the ballot protocol was reached), and crossed the §7.3
    // driver-import bridge — including `combine_candidates`, the re-entrant
    // one, whose ValueList argument the runner decodes by hand.
    try testing.expect(tally.inputs > fuzz_iterations * 4);
    try testing.expect(tally.effects > fuzz_iterations * 4);
    try testing.expect(tally.own_envelopes > 0);
    try testing.expect(tally.broadcasts > 0);
    try testing.expect(validates > 0);
    try testing.expect(combines > 0);
}

// ---------------------------------------------------------------------------
// 4. Tooling exports: qset hash + lint frames (§7.2, §12)
// ---------------------------------------------------------------------------

test "wasm differential: qset hash and lint diagnostics match native" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const host = try Host.start(gpa);
    defer host.stop();

    var pks: [4][32]u8 = undefined;
    for (0..4) |i| pks[i] = try crypto.publicKeyFromSeed(nodeSeed(@intCast(i)));

    // A healthy 3-of-4, a 1-of-1 (lint has something to say), and a 2-of-3.
    const thresholds = [_]u32{ 3, 1, 2 };
    const counts = [_]usize{ 4, 1, 3 };

    for (thresholds, counts) |threshold, count| {
        var qs = qset.QuorumSetOwned{
            .threshold = threshold,
            .validators = try arena.dupe([32]u8, pks[0..count]),
            .inner_sets = try arena.alloc(qset.QuorumSetOwned, 0),
        };
        try qset.validateAndNormalize(arena, &qs);

        const flat = try qset.canonicalBytes(arena, &qs);
        const framed = try canonical.frameFlat(arena, flat);

        const expect_hash = try qset.hashNormalized(arena, &qs);
        const hres = try host.callOk(arena, try request(arena, host.nextId(), "qsetHash", null, "qset", framed));
        const got_hash = try hexToBytes(arena, hres.object.get("hash").?.string);
        try testing.expectEqualSlices(u8, &expect_hash, got_hash);

        const findings = try qset.lint(arena, &qs);
        const expect_frame = try encodeLintNative(arena, findings);
        const lres = try host.callOk(arena, try request(arena, host.nextId(), "lint", null, "qset", framed));
        const got_frame = try hexToBytes(arena, lres.object.get("frame").?.string);
        if (!std.mem.eql(u8, expect_frame, got_frame)) {
            std.debug.print("LINT FRAME DIVERGENCE (threshold {d} of {d})\n  native = ", .{ threshold, count });
            printHex(expect_frame);
            std.debug.print("  wasm   = ", .{});
            printHex(got_frame);
            return error.LintFrameDivergence;
        }
    }
}

/// Mirror of `slcp_host_abi.encodeLint`. That module is a
/// wasm32-freestanding root and cannot be imported natively, so this is the
/// independent re-derivation the differential compares against.
fn encodeLintNative(gpa: std.mem.Allocator, findings: []const qset.LintFinding) ![]u8 {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var root = try gen_host.LintDiagnostics.Builder.init(&mb);
    if (findings.len > 0) {
        const list = try root.initFindings(@intCast(findings.len));
        for (findings, 0..) |f, i| {
            var b = try list.get(@intCast(i));
            try b.setLevel(@backingInt(f.level));
            try b.setCode(@backingInt(f.code));
            try b.setMembers(f.members);
            try b.setThreshold(f.threshold);
        }
    }
    return gpa.dupe(u8, try mb.toBytes());
}

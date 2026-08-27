//! The WASM host ABI (design §7): `slcp_core.wasm`'s entire export surface.
//!
//! Clones the capnp host ABI's proven discipline — all-u32 scalars, a sticky
//! per-instance error cleared before each mutating call, two-phase borrowed
//! pop, copy-everything memory, version + feature-flag negotiation — with one
//! deliberate difference: **boundary payloads are capnp-encoded `host.capnp`
//! messages** (§7.1), so the export surface stays small and the same encoded
//! frames double as conformance-vector artifacts (the M2 trace format).
//!
//! Memory contract:
//!   - Every buffer the host hands IN is copied before the call returns; the
//!     host may free it immediately after.
//!   - Every buffer handed OUT via `out_ptr_ptr`/`out_len_ptr` is either
//!     BORROWED (pop_effect: valid until `slcp_engine_pop_commit`) or OWNED by
//!     the host (lint/error/version: release with `slcp_buf_free`). Each
//!     export's doc comment says which.
//!   - `slcp_alloc(0)` returns a valid nonzero pointer (capnp ABI convention).
//!
//! Threading: single-threaded by construction (wasm32-freestanding, one
//! instance per node). The session invariant — push ONE input, then drain ALL
//! effects before the next input — is enforced host-side (§7.2).

const std = @import("std");
const slcp = @import("slcp-core");

const engine = slcp.engine;
const host_codec = slcp.host_codec;
const qset = slcp.qset;
const crypto = slcp.crypto;
const capnpc = slcp.capnpc;
const gen_host = slcp.gen.host;
const driver_mod = slcp.driver;

// ---------------------------------------------------------------------------
// Version + feature negotiation (§7.2)
// ---------------------------------------------------------------------------

pub const abi_version: u32 = 1;
pub const abi_min_version: u32 = 1;
pub const abi_max_version: u32 = 1;

/// bit 0 = driver imports required (§7.3 — this ABI is NOT zero-import)
/// bit 1 = external_signer (reserved, OFF in v1 — §6)
/// bit 2 = lint exports present (§12)
pub const feature_flags: u64 = 0b101;

pub const version_string = "slcp-core " ++ @import("builtin").zig_version_string;

// ---------------------------------------------------------------------------
// Allocator
// ---------------------------------------------------------------------------

/// wasm32-freestanding has no libc; the page allocator is the whole heap.
/// Every allocation crossing the boundary is length-tracked by the host (the
/// ABI is explicit-length everywhere), so a bump/page allocator is enough.
const wasm_allocator = std.heap.wasm_allocator;

fn gpa() std.mem.Allocator {
    return wasm_allocator;
}

// ---------------------------------------------------------------------------
// Sticky error state (§7.2: cleared before each mutating call)
// ---------------------------------------------------------------------------

pub const ErrorCode = enum(u32) {
    none = 0,
    out_of_memory = 1,
    bad_handle = 2,
    decode_failed = 3,
    engine_failed = 4,
    invalid_config = 5,
    invalid_qset = 6,
    effect_budget = 7,
    driver_fault = 8,
    no_effect = 9,
};

var last_error_code: u32 = 0;
var last_error_msg: []const u8 = "";

fn setError(code: ErrorCode, msg: []const u8) void {
    last_error_code = @intFromEnum(code);
    last_error_msg = msg; // static strings only — never freed
}

fn clearError() void {
    last_error_code = 0;
    last_error_msg = "";
}

fn errorFor(err: anyerror) ErrorCode {
    return switch (err) {
        error.OutOfMemory => .out_of_memory,
        error.EffectBudgetExceeded => .effect_budget,
        error.EngineFailed => .engine_failed,
        else => .decode_failed,
    };
}

// ---------------------------------------------------------------------------
// Handle map (multi-instance, §7.2)
// ---------------------------------------------------------------------------

const Instance = struct {
    eng: engine.Engine,
    /// Frame for the effect currently borrowed by the host (freed at commit).
    borrowed: ?[]u8 = null,
};

var instances: std.AutoHashMapUnmanaged(u32, *Instance) = .empty;
var next_handle: u32 = 1;

fn lookup(handle: u32) ?*Instance {
    return instances.get(handle);
}

// ---------------------------------------------------------------------------
// Memory exports
// ---------------------------------------------------------------------------

/// Allocate `len` bytes. `len == 0` returns a valid nonzero pointer (capnp
/// ABI convention). Returns 0 on OOM.
export fn slcp_alloc(len: u32) u32 {
    const n = if (len == 0) 1 else len;
    const buf = gpa().alloc(u8, n) catch {
        setError(.out_of_memory, "slcp_alloc");
        return 0;
    };
    return @intCast(@intFromPtr(buf.ptr));
}

export fn slcp_free(ptr: u32, len: u32) void {
    if (ptr == 0) return;
    const n = if (len == 0) 1 else len;
    const p: [*]u8 = @ptrFromInt(ptr);
    gpa().free(p[0..n]);
}

/// Release a buffer the ABI handed out as OWNED (lint diagnostics, error
/// text, version string). Same as slcp_free; named for host-side clarity.
export fn slcp_buf_free(ptr: u32, len: u32) void {
    slcp_free(ptr, len);
}

// ---------------------------------------------------------------------------
// Version / feature exports
// ---------------------------------------------------------------------------

export fn slcp_abi_version() u32 {
    return abi_version;
}
export fn slcp_abi_min_version() u32 {
    return abi_min_version;
}
export fn slcp_abi_max_version() u32 {
    return abi_max_version;
}
export fn slcp_feature_flags_lo() u32 {
    return @truncate(feature_flags);
}
export fn slcp_feature_flags_hi() u32 {
    return @truncate(feature_flags >> 32);
}

/// Writes an OWNED copy of the version string (host frees with slcp_buf_free).
export fn slcp_version_string(out_ptr_ptr: u32, out_len_ptr: u32) void {
    const copy = gpa().dupe(u8, version_string) catch {
        writeOut(out_ptr_ptr, out_len_ptr, 0, 0);
        return;
    };
    writeOut(out_ptr_ptr, out_len_ptr, @intCast(@intFromPtr(copy.ptr)), @intCast(copy.len));
}

// ---------------------------------------------------------------------------
// Error exports
// ---------------------------------------------------------------------------

export fn slcp_last_error_code() u32 {
    return last_error_code;
}
export fn slcp_last_error_ptr() u32 {
    return @intCast(@intFromPtr(last_error_msg.ptr));
}
export fn slcp_last_error_len() u32 {
    return @intCast(last_error_msg.len);
}
export fn slcp_clear_error() void {
    clearError();
}

/// Take the error atomically: writes [code, ptr, len] into out3 and clears.
/// The text is STATIC (never freed by the host).
export fn slcp_error_take(out3: u32) void {
    const out: [*]u32 = @ptrFromInt(out3);
    out[0] = last_error_code;
    out[1] = @intCast(@intFromPtr(last_error_msg.ptr));
    out[2] = @intCast(last_error_msg.len);
    clearError();
}

fn writeOut(out_ptr_ptr: u32, out_len_ptr: u32, ptr: u32, len: u32) void {
    const pp: *u32 = @ptrFromInt(out_ptr_ptr);
    const lp: *u32 = @ptrFromInt(out_len_ptr);
    pp.* = ptr;
    lp.* = len;
}

fn hostSlice(ptr: u32, len: u32) []const u8 {
    if (len == 0) return &.{};
    const p: [*]const u8 = @ptrFromInt(ptr);
    return p[0..len];
}

// ---------------------------------------------------------------------------
// Engine lifecycle
// ---------------------------------------------------------------------------

/// Decode an `EngineConfig` frame (§7.1) and construct an engine. Returns a
/// nonzero handle, or 0 with the sticky error set.
export fn slcp_engine_new(config_ptr: u32, config_len: u32) u32 {
    clearError();
    const bytes = hostSlice(config_ptr, config_len);

    var cfg = host_codec.decodeEngineConfig(gpa(), bytes) catch |err| {
        setError(errorFor(err), "slcp_engine_new: config decode");
        return 0;
    };
    // Engine.init takes ownership of cfg.quorum_set on success only.
    var eng = engine.Engine.init(gpa(), cfg, driverFromImports()) catch |err| {
        cfg.quorum_set.deinit(gpa());
        setError(errorFor(err), "slcp_engine_new: init");
        return 0;
    };
    errdefer eng.deinit();

    const inst = gpa().create(Instance) catch {
        eng.deinit();
        setError(.out_of_memory, "slcp_engine_new: instance");
        return 0;
    };
    inst.* = .{ .eng = eng };

    const handle = next_handle;
    instances.put(gpa(), handle, inst) catch {
        inst.eng.deinit();
        gpa().destroy(inst);
        setError(.out_of_memory, "slcp_engine_new: handle map");
        return 0;
    };
    next_handle += 1;
    return handle;
}

export fn slcp_engine_free(handle: u32) void {
    if (instances.fetchRemove(handle)) |kv| {
        const inst = kv.value;
        if (inst.borrowed) |b| gpa().free(b);
        inst.eng.deinit();
        gpa().destroy(inst);
    }
}

/// Push exactly ONE `Input` frame (§7.1). Returns 1 on success, 0 with the
/// sticky error set. After a 0 the handle stays valid but the engine may be
/// sticky-failed (check slcp_last_error_code).
export fn slcp_engine_push_input(handle: u32, ptr: u32, len: u32) u32 {
    clearError();
    const inst = lookup(handle) orelse {
        setError(.bad_handle, "slcp_engine_push_input");
        return 0;
    };
    var input = host_codec.decodeInput(gpa(), hostSlice(ptr, len)) catch |err| {
        setError(errorFor(err), "slcp_engine_push_input: decode");
        return 0;
    };
    defer host_codec.freeInput(gpa(), &input);

    inst.eng.pushInput(input) catch |err| {
        setError(errorFor(err), "slcp_engine_push_input: engine");
        return 0;
    };
    return 1;
}

/// Two-phase borrowed pop (§5.1/§7.2): writes a BORROWED `Effect` frame
/// (valid until `slcp_engine_pop_commit`). Returns 1 when an effect was
/// produced, 0 when the queue is empty (not an error) or on failure (error
/// code set).
export fn slcp_engine_pop_effect(handle: u32, out_ptr_ptr: u32, out_len_ptr: u32) u32 {
    clearError();
    writeOut(out_ptr_ptr, out_len_ptr, 0, 0);
    const inst = lookup(handle) orelse {
        setError(.bad_handle, "slcp_engine_pop_effect");
        return 0;
    };
    // A previously borrowed frame is released here if the host skipped commit.
    if (inst.borrowed) |b| {
        gpa().free(b);
        inst.borrowed = null;
    }
    const eff = inst.eng.popEffect() orelse return 0;
    const frame = host_codec.encodeEffect(gpa(), eff) catch |err| {
        setError(errorFor(err), "slcp_engine_pop_effect: encode");
        return 0;
    };
    inst.borrowed = frame;
    writeOut(out_ptr_ptr, out_len_ptr, @intCast(@intFromPtr(frame.ptr)), @intCast(frame.len));
    return 1;
}

/// Commit the borrowed effect: frees the frame and advances the queue.
export fn slcp_engine_pop_commit(handle: u32) void {
    const inst = lookup(handle) orelse return;
    if (inst.borrowed) |b| {
        gpa().free(b);
        inst.borrowed = null;
    }
    inst.eng.commitEffect();
}

export fn slcp_engine_effect_count(handle: u32) u32 {
    const inst = lookup(handle) orelse return 0;
    return @intCast(inst.eng.effects.len());
}

export fn slcp_engine_effect_bytes(handle: u32) u32 {
    const inst = lookup(handle) orelse return 0;
    return @intCast(inst.eng.effects.bytes());
}

// ---------------------------------------------------------------------------
// Tooling helpers (§7.2, §12)
// ---------------------------------------------------------------------------

/// qsetHash of a framed `QuorumSet` (§4.3): validates + normalizes first, so
/// the hash is always of the NORMALIZED set. Writes 32 bytes to out32_ptr.
export fn slcp_qset_hash(ptr: u32, len: u32, out32_ptr: u32) u32 {
    clearError();
    var owned = decodeNormalizedQset(hostSlice(ptr, len)) catch |err| {
        setError(if (err == error.OutOfMemory) .out_of_memory else .invalid_qset, "slcp_qset_hash");
        return 0;
    };
    defer owned.deinit(gpa());
    const h = qset.hashNormalized(gpa(), &owned) catch {
        setError(.out_of_memory, "slcp_qset_hash");
        return 0;
    };
    const out: [*]u8 = @ptrFromInt(out32_ptr);
    @memcpy(out[0..32], &h);
    return 1;
}

/// Lint a framed `QuorumSet` (§12): writes an OWNED `LintDiagnostics` frame
/// (host frees with slcp_buf_free). Returns 1 on success. A qset that fails
/// validation is itself an error (invalid_qset), not a lint finding.
export fn slcp_lint_qset(ptr: u32, len: u32, out_ptr_ptr: u32, out_len_ptr: u32) u32 {
    clearError();
    writeOut(out_ptr_ptr, out_len_ptr, 0, 0);
    var owned = decodeNormalizedQset(hostSlice(ptr, len)) catch |err| {
        setError(if (err == error.OutOfMemory) .out_of_memory else .invalid_qset, "slcp_lint_qset");
        return 0;
    };
    defer owned.deinit(gpa());

    const findings = qset.lint(gpa(), &owned) catch {
        setError(.out_of_memory, "slcp_lint_qset");
        return 0;
    };
    defer gpa().free(findings);

    const frame = encodeLint(gpa(), findings) catch {
        setError(.out_of_memory, "slcp_lint_qset: encode");
        return 0;
    };
    writeOut(out_ptr_ptr, out_len_ptr, @intCast(@intFromPtr(frame.ptr)), @intCast(frame.len));
    return 1;
}

fn decodeNormalizedQset(bytes: []const u8) !qset.QuorumSetOwned {
    var msg = try capnpc.message.Message.init(gpa(), bytes, .{});
    defer msg.deinit();
    const reader = try slcp.gen.slcp.QuorumSet.Reader.init(&msg);
    var owned = try qset.fromReader(gpa(), reader);
    errdefer owned.deinit(gpa());
    try qset.validateAndNormalize(gpa(), &owned);
    return owned;
}

/// Encode lint findings as a `LintDiagnostics` frame — byte-identical across
/// hosts, which is what makes the lint.json vectors cross-implementation.
pub fn encodeLint(alloc: std.mem.Allocator, findings: []const qset.LintFinding) ![]u8 {
    var mb = capnpc.message.MessageBuilder.init(alloc);
    defer mb.deinit();
    var root = try gen_host.LintDiagnostics.Builder.init(&mb);
    if (findings.len > 0) {
        const list = try root.initFindings(@intCast(findings.len));
        for (findings, 0..) |f, i| {
            var b = try list.get(@intCast(i));
            try b.setLevel(@intFromEnum(f.level));
            try b.setCode(@intFromEnum(f.code));
            try b.setMembers(f.members);
            try b.setThreshold(f.threshold);
        }
    }
    const framed = try mb.toBytes();
    return alloc.dupe(u8, framed);
}

// ---------------------------------------------------------------------------
// Driver imports (§7.3) — the one structural departure from capnp's ABI
// ---------------------------------------------------------------------------

/// Host-supplied, module "slcp_driver". SCP calls the driver INSIDE envelope
/// processing, so these are synchronous imports; the state machine cannot
/// suspend mid-transition. u64 slots cross as (lo, hi) u32 pairs to preserve
/// the all-u32 discipline.
const imports = struct {
    /// 0 invalid | 1 maybeValid | 2 valid | 3 DRIVER FAULT
    extern "slcp_driver" fn validate_value(slot_lo: u32, slot_hi: u32, ptr: u32, len: u32, is_nomination: u32) u32;
    /// `list` is a ValueList frame; host writes the result via slcp_alloc and
    /// stores (ptr, len) in the out params. Nonzero return = driver fault.
    extern "slcp_driver" fn combine_candidates(slot_lo: u32, slot_hi: u32, list_ptr: u32, list_len: u32, out_ptr_ptr: u32, out_len_ptr: u32) u32;
    /// 0 none | 1 some | other = driver fault
    extern "slcp_driver" fn extract_valid_value(slot_lo: u32, slot_hi: u32, ptr: u32, len: u32, out_ptr_ptr: u32, out_len_ptr: u32) u32;
};

fn splitSlot(slot: u64) struct { lo: u32, hi: u32 } {
    return .{ .lo = @truncate(slot), .hi = @truncate(slot >> 32) };
}

fn importValidate(ctx: *anyopaque, slot: u64, value: []const u8, is_nomination: bool) driver_mod.Validity {
    _ = ctx;
    const s = splitSlot(slot);
    const code = imports.validate_value(
        s.lo,
        s.hi,
        @intCast(@intFromPtr(value.ptr)),
        @intCast(value.len),
        @intFromBool(is_nomination),
    );
    // Out-of-range codes are driver faults (§7.3); the engine treats
    // `.invalid` as the safe floor and the host's sticky error records it.
    return switch (code) {
        0 => .invalid,
        1 => .maybe_valid,
        2 => .valid,
        else => blk: {
            setError(.driver_fault, "driver.validate_value");
            break :blk .invalid;
        },
    };
}

fn importCombine(ctx: *anyopaque, slot: u64, candidates: []const []const u8, alloc: std.mem.Allocator, out: *std.ArrayList(u8)) driver_mod.DriverError!void {
    _ = ctx;
    const s = splitSlot(slot);
    // Candidates cross as a ValueList frame (§7.1), sorted ascending by the
    // caller (determinism aid).
    const list = encodeValueList(alloc, candidates) catch return error.OutOfMemory;
    defer alloc.free(list);

    var out_ptr: u32 = 0;
    var out_len: u32 = 0;
    const rc = imports.combine_candidates(
        s.lo,
        s.hi,
        @intCast(@intFromPtr(list.ptr)),
        @intCast(list.len),
        @intCast(@intFromPtr(&out_ptr)),
        @intCast(@intFromPtr(&out_len)),
    );
    if (rc != 0) {
        setError(.driver_fault, "driver.combine_candidates");
        return error.DriverFault;
    }
    if (out_ptr == 0 or out_len == 0) {
        setError(.driver_fault, "driver.combine_candidates: empty result");
        return error.DriverFault;
    }
    // The host allocated via slcp_alloc; we copy and free it (§7.3 ownership).
    const result = hostSlice(out_ptr, out_len);
    try out.appendSlice(alloc, result);
    slcp_free(out_ptr, out_len);
}

fn importExtract(ctx: *anyopaque, slot: u64, value: []const u8, alloc: std.mem.Allocator, out: *std.ArrayList(u8)) driver_mod.DriverError!bool {
    _ = ctx;
    const s = splitSlot(slot);
    var out_ptr: u32 = 0;
    var out_len: u32 = 0;
    const rc = imports.extract_valid_value(
        s.lo,
        s.hi,
        @intCast(@intFromPtr(value.ptr)),
        @intCast(value.len),
        @intCast(@intFromPtr(&out_ptr)),
        @intCast(@intFromPtr(&out_len)),
    );
    switch (rc) {
        0 => return false, // none — the engine drops the value (stellar-core default)
        1 => {
            if (out_ptr == 0 or out_len == 0) {
                setError(.driver_fault, "driver.extract_valid_value: empty result");
                return error.DriverFault;
            }
            try out.appendSlice(alloc, hostSlice(out_ptr, out_len));
            slcp_free(out_ptr, out_len);
            return true;
        },
        else => {
            setError(.driver_fault, "driver.extract_valid_value");
            return error.DriverFault;
        },
    }
}

fn encodeValueList(alloc: std.mem.Allocator, values: []const []const u8) ![]u8 {
    var mb = capnpc.message.MessageBuilder.init(alloc);
    defer mb.deinit();
    var root = try gen_host.ValueList.Builder.init(&mb);
    if (values.len > 0) {
        const list = try root.initValues(@intCast(values.len));
        for (values, 0..) |v, i| try list.set(@intCast(i), v);
    }
    const framed = try mb.toBytes();
    return alloc.dupe(u8, framed);
}

var driver_ctx: u8 = 0;

fn driverFromImports() driver_mod.Driver {
    return .{
        .ctx = @ptrCast(&driver_ctx),
        .validate_value = importValidate,
        .combine_candidates = importCombine,
        .extract_valid_value = importExtract,
    };
}

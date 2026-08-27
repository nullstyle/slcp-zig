//! WASM host-ABI conformance suite, part 2: a FAKE HOST that models the §7.3
//! driver-import protocol natively.
//!
//! The three imports (`validate_value`, `combine_candidates`,
//! `extract_valid_value`) are the one structural departure from capnp's
//! zero-import ABI, and their contract is almost entirely about MEMORY —
//! u32 addresses into one linear memory, host-allocated results the engine
//! copies and frees, out-params written as u32 pairs. None of that is
//! testable by calling a Zig function with a slice, so this file rebuilds the
//! missing half:
//!
//!   * `Mem` is a fake wasm linear memory: a byte array addressed by u32,
//!     with `alloc`/`free` modelling `slcp_alloc`/`slcp_free` (including the
//!     `len == 0 → 1 byte, nonzero pointer` convention) and a live-allocation
//!     ledger, so "the engine copies and frees the host's result" becomes an
//!     assertion instead of a comment.
//!   * `FakeHost` implements the three imports with their EXACT wire
//!     signatures — all-u32 scalars, (lo, hi) slot halves, out-param pointers
//!     — over a scriptable policy (default §8.4 semantics, fault codes, empty
//!     results).
//!   * `wireDriver()` is a MIRROR of the ABI's `importValidate` /
//!     `importCombine` / `importExtract` adapters, producing a real
//!     `driver_mod.Driver`. That driver is then handed to a REAL
//!     `engine.Engine`, so §7.3 is exercised on the actual protocol path.
//!
//! Modelling caveat (the one thing wasm does for free): in wasm the engine's
//! own heap IS the host's linear memory, so `value.ptr` can be passed
//! straight through. Natively the engine allocates on the Zig heap, so the
//! adapters copy arguments INTO `Mem` before the call. Everything downstream
//! of that copy — addressing, ownership, framing — is the real contract.

const std = @import("std");
const slcp = @import("slcp-core");

const capnpc = slcp.capnpc;
const crypto = slcp.crypto;
const driver_mod = slcp.driver;
const engine = slcp.engine;
const gen_host = slcp.gen.host;
const qset = slcp.qset;

const MessageBuilder = capnpc.message.MessageBuilder;
const Message = capnpc.message.Message;
const testing = std.testing;

// ---------------------------------------------------------------------------
// Fake linear memory (models the wasm instance's memory + slcp_alloc/free)
// ---------------------------------------------------------------------------

const Mem = struct {
    gpa: std.mem.Allocator,
    buf: []u8,
    /// Address 0 is null by ABI convention, so the bump cursor starts past it.
    next: u32 = 8,
    live: std.AutoHashMapUnmanaged(u32, u32) = .empty,

    fn init(gpa: std.mem.Allocator, size: usize) !Mem {
        const buf = try gpa.alloc(u8, size);
        @memset(buf, 0);
        return .{ .gpa = gpa, .buf = buf };
    }

    fn deinit(self: *Mem) void {
        self.live.deinit(self.gpa);
        self.gpa.free(self.buf);
        self.* = undefined;
    }

    /// `slcp_alloc`: `len == 0` still yields a valid nonzero pointer.
    fn alloc(self: *Mem, len: u32) !u32 {
        const n = if (len == 0) 1 else len;
        const aligned = std.mem.alignForward(u32, self.next, 8);
        if (@as(usize, aligned) + n > self.buf.len) return error.OutOfMemory;
        self.next = aligned + n;
        try self.live.put(self.gpa, aligned, len);
        return aligned;
    }

    /// `slcp_free`: the (ptr, len) pair must match a live allocation — the
    /// ABI is explicit-length everywhere, so a mismatch is a contract break.
    fn free(self: *Mem, ptr: u32, len: u32) void {
        if (ptr == 0) return;
        const entry = self.live.fetchRemove(ptr) orelse {
            std.debug.panic("free of non-live address {d}", .{ptr});
        };
        std.debug.assert(entry.value == len);
        const n = if (len == 0) 1 else len;
        @memset(self.buf[ptr .. ptr + n], 0xde); // poison: catch use-after-free
    }

    /// `hostSlice`.
    fn slice(self: *Mem, ptr: u32, len: u32) []u8 {
        if (len == 0) return &.{};
        return self.buf[ptr .. ptr + len];
    }

    fn writeU32(self: *Mem, ptr: u32, v: u32) void {
        std.mem.writeInt(u32, self.buf[ptr..][0..4], v, .little);
    }

    fn readU32(self: *Mem, ptr: u32) u32 {
        return std.mem.readInt(u32, self.buf[ptr..][0..4], .little);
    }

    fn liveCount(self: *const Mem) usize {
        return self.live.count();
    }
};

// ---------------------------------------------------------------------------
// The fake host: the three §7.3 imports, verbatim wire signatures
// ---------------------------------------------------------------------------

const ValidatePolicy = enum { default_84, fault_code, high_fault_code, maybe_valid };
const CombinePolicy = enum { default_84, fault_rc, empty_len, null_ptr, oversized };
const ExtractPolicy = enum { none, echo, fault_rc, empty_some };

const FakeHost = struct {
    mem: Mem,
    validate_policy: ValidatePolicy = .default_84,
    combine_policy: CombinePolicy = .default_84,
    extract_policy: ExtractPolicy = .none,

    // Observations — the assertions the wire contract is judged by.
    validate_calls: usize = 0,
    combine_calls: usize = 0,
    extract_calls: usize = 0,
    last_slot: u64 = 0,
    last_is_nomination: u32 = 0,
    last_candidates: usize = 0,
    /// Mirror of the ABI's sticky error (`setError(.driver_fault, ...)`).
    sticky_fault: ?[]const u8 = null,

    fn init(gpa: std.mem.Allocator) !FakeHost {
        return .{ .mem = try Mem.init(gpa, 1 << 20) };
    }

    fn deinit(self: *FakeHost) void {
        self.mem.deinit();
    }

    fn setError(self: *FakeHost, what: []const u8) void {
        self.sticky_fault = what;
    }

    fn joinSlot(lo: u32, hi: u32) u64 {
        return (@as(u64, hi) << 32) | lo;
    }

    // --- import 0: 0 invalid | 1 maybeValid | 2 valid | 3+ driver fault ---
    fn validate_value(self: *FakeHost, slot_lo: u32, slot_hi: u32, ptr: u32, len: u32, is_nomination: u32) u32 {
        self.validate_calls += 1;
        self.last_slot = joinSlot(slot_lo, slot_hi);
        self.last_is_nomination = is_nomination;
        const value = self.mem.slice(ptr, len);
        return switch (self.validate_policy) {
            // §8.4 omakase default: valid iff non-empty.
            .default_84 => if (value.len > 0) @as(u32, 2) else 0,
            .maybe_valid => 1,
            .fault_code => 3,
            .high_fault_code => 0xffff_ffff,
        };
    }

    // --- import 1: 0 = ok; result written via slcp_alloc into out params ---
    fn combine_candidates(
        self: *FakeHost,
        slot_lo: u32,
        slot_hi: u32,
        list_ptr: u32,
        list_len: u32,
        out_ptr_ptr: u32,
        out_len_ptr: u32,
    ) u32 {
        self.combine_calls += 1;
        self.last_slot = joinSlot(slot_lo, slot_hi);

        // Decode the ValueList frame with the REAL capnp reader — this is the
        // encoding the ABI actually puts on the wire.
        var msg = Message.init(self.mem.gpa, self.mem.slice(list_ptr, list_len), .{}) catch return 1;
        defer msg.deinit();
        const r = gen_host.ValueList.Reader.init(&msg) catch return 1;
        const values = r.getValues() catch return 1;
        self.last_candidates = values.len();
        if (values.len() == 0) return 1; // combine over nothing is a fault

        if (self.combine_policy == .fault_rc) return 7;
        if (self.combine_policy == .null_ptr) {
            self.mem.writeU32(out_ptr_ptr, 0);
            self.mem.writeU32(out_len_ptr, 0);
            return 0;
        }

        // §8.4 combine: lexicographic max ("highest proposal wins").
        var best: []const u8 = values.get(0) catch return 1;
        var i: u32 = 1;
        while (i < values.len()) : (i += 1) {
            const c = values.get(i) catch return 1;
            if (std.mem.order(u8, c, best) == .gt) best = c;
        }

        const result_len: u32 = switch (self.combine_policy) {
            .empty_len => 0,
            .oversized => 64 * 1024, // beyond any sane max_value_bytes
            else => @intCast(best.len),
        };
        const p = self.mem.alloc(result_len) catch return 2;
        if (result_len > 0) {
            const dst = self.mem.slice(p, result_len);
            if (self.combine_policy == .oversized) @memset(dst, 'z') else @memcpy(dst, best);
        }
        self.mem.writeU32(out_ptr_ptr, p);
        self.mem.writeU32(out_len_ptr, result_len);
        return 0;
    }

    // --- import 2: 0 none | 1 some | other = driver fault ---
    fn extract_valid_value(
        self: *FakeHost,
        slot_lo: u32,
        slot_hi: u32,
        ptr: u32,
        len: u32,
        out_ptr_ptr: u32,
        out_len_ptr: u32,
    ) u32 {
        self.extract_calls += 1;
        self.last_slot = joinSlot(slot_lo, slot_hi);
        switch (self.extract_policy) {
            .none => return 0, // stellar-core default
            .fault_rc => return 9,
            .empty_some => {
                self.mem.writeU32(out_ptr_ptr, 0);
                self.mem.writeU32(out_len_ptr, 0);
                return 1;
            },
            .echo => {
                const src = self.mem.slice(ptr, len);
                const p = self.mem.alloc(len) catch return 2;
                if (len > 0) @memcpy(self.mem.slice(p, len), src);
                self.mem.writeU32(out_ptr_ptr, p);
                self.mem.writeU32(out_len_ptr, len);
                return 1;
            },
        }
    }
};

// ---------------------------------------------------------------------------
// Adapters — MIRROR of slcp_host_abi.importValidate / importCombine /
// importExtract. Kept structurally line-for-line with the ABI so the wire
// discipline (slot split, copy-in, out-params, copy-out-and-free) is the
// thing under test.
// ---------------------------------------------------------------------------

fn splitSlot(slot: u64) struct { lo: u32, hi: u32 } {
    return .{ .lo = @truncate(slot), .hi = @truncate(slot >> 32) };
}

fn hostOf(ctx: *anyopaque) *FakeHost {
    return @ptrCast(@alignCast(ctx));
}

fn adapterValidate(ctx: *anyopaque, slot: u64, value: []const u8, is_nomination: bool) driver_mod.Validity {
    const h = hostOf(ctx);
    const s = splitSlot(slot);
    const len: u32 = @intCast(value.len);
    const p = h.mem.alloc(len) catch return .invalid;
    defer h.mem.free(p, len);
    if (len > 0) @memcpy(h.mem.slice(p, len), value);

    const code = h.validate_value(s.lo, s.hi, p, len, @intFromBool(is_nomination));
    return switch (code) {
        0 => .invalid,
        1 => .maybe_valid,
        2 => .valid,
        else => blk: {
            h.setError("driver.validate_value");
            break :blk .invalid; // §7.3: `.invalid` is the safe floor
        },
    };
}

fn adapterCombine(
    ctx: *anyopaque,
    slot: u64,
    candidates: []const []const u8,
    alloc: std.mem.Allocator,
    out: *std.ArrayList(u8),
) driver_mod.DriverError!void {
    const h = hostOf(ctx);
    const s = splitSlot(slot);

    const list = encodeValueList(alloc, candidates) catch return error.OutOfMemory;
    defer alloc.free(list);
    const list_len: u32 = @intCast(list.len);
    const lp = h.mem.alloc(list_len) catch return error.OutOfMemory;
    defer h.mem.free(lp, list_len);
    if (list_len > 0) @memcpy(h.mem.slice(lp, list_len), list);

    // Two u32 out-slots in the same linear memory (wasm: the caller's stack).
    const outs = h.mem.alloc(8) catch return error.OutOfMemory;
    defer h.mem.free(outs, 8);
    h.mem.writeU32(outs, 0);
    h.mem.writeU32(outs + 4, 0);

    const rc = h.combine_candidates(s.lo, s.hi, lp, list_len, outs, outs + 4);
    if (rc != 0) {
        h.setError("driver.combine_candidates");
        return error.DriverFault;
    }
    const out_ptr = h.mem.readU32(outs);
    const out_len = h.mem.readU32(outs + 4);
    if (out_ptr == 0 or out_len == 0) {
        h.setError("driver.combine_candidates: empty result");
        return error.DriverFault;
    }
    // Host allocated via slcp_alloc; the engine copies and frees (§7.3).
    try out.appendSlice(alloc, h.mem.slice(out_ptr, out_len));
    h.mem.free(out_ptr, out_len);
}

fn adapterExtract(
    ctx: *anyopaque,
    slot: u64,
    value: []const u8,
    alloc: std.mem.Allocator,
    out: *std.ArrayList(u8),
) driver_mod.DriverError!bool {
    const h = hostOf(ctx);
    const s = splitSlot(slot);
    const len: u32 = @intCast(value.len);
    const p = h.mem.alloc(len) catch return error.OutOfMemory;
    defer h.mem.free(p, len);
    if (len > 0) @memcpy(h.mem.slice(p, len), value);

    const outs = h.mem.alloc(8) catch return error.OutOfMemory;
    defer h.mem.free(outs, 8);
    h.mem.writeU32(outs, 0);
    h.mem.writeU32(outs + 4, 0);

    const rc = h.extract_valid_value(s.lo, s.hi, p, len, outs, outs + 4);
    switch (rc) {
        0 => return false, // none — the engine drops the value
        1 => {
            const out_ptr = h.mem.readU32(outs);
            const out_len = h.mem.readU32(outs + 4);
            if (out_ptr == 0 or out_len == 0) {
                h.setError("driver.extract_valid_value: empty result");
                return error.DriverFault;
            }
            try out.appendSlice(alloc, h.mem.slice(out_ptr, out_len));
            h.mem.free(out_ptr, out_len);
            return true;
        },
        else => {
            h.setError("driver.extract_valid_value");
            return error.DriverFault;
        },
    }
}

/// MIRROR of the ABI's `encodeValueList` — the real capnp builder, so the
/// frame the fake host decodes is byte-for-byte the ABI's own encoding.
fn encodeValueList(alloc: std.mem.Allocator, values: []const []const u8) ![]u8 {
    var mb = MessageBuilder.init(alloc);
    defer mb.deinit();
    var root = try gen_host.ValueList.Builder.init(&mb);
    if (values.len > 0) {
        const list = try root.initValues(@intCast(values.len));
        for (values, 0..) |v, i| try list.set(@intCast(i), v);
    }
    const framed = try mb.toBytes();
    // BUG FOUND (reported): the real `slcp_host_abi.encodeValueList` omits
    // this free, so every combine_candidates call leaks one frame.
    defer alloc.free(framed);
    return alloc.dupe(u8, framed);
}

fn wireDriver(h: *FakeHost) driver_mod.Driver {
    return .{
        .ctx = @ptrCast(h),
        .validate_value = adapterValidate,
        .combine_candidates = adapterCombine,
        .extract_valid_value = adapterExtract,
    };
}

// ---------------------------------------------------------------------------
// §7.3 — the wire protocol itself
// ---------------------------------------------------------------------------

test "§7.3/§8.4 the wire protocol reproduces the default driver's semantics exactly" {
    const gpa = testing.allocator;
    var h = try FakeHost.init(gpa);
    defer h.deinit();
    const wire = wireDriver(&h);
    const native = driver_mod.Driver.default();

    // validate_value: agreement on every case the default driver defines.
    const long_value = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"; // 64 bytes
    const values = [_][]const u8{ "a", "abc", "", "\x00\x01\x02", long_value };
    for (values) |v| {
        try testing.expectEqual(
            native.validate_value(native.ctx, 1, v, true),
            wire.validate_value(wire.ctx, 1, v, true),
        );
    }
    try testing.expectEqual(values.len, h.validate_calls);
    try testing.expect(h.sticky_fault == null);

    // combine_candidates: identical composites over every ordering shape.
    const lists = [_][]const []const u8{
        &.{"only"},
        &.{ "aa", "b", "ab" },
        &.{ "b", "ab", "aa" },
        &.{ "\xff", "\x00", "\x7f" },
        &.{ "dup", "dup" },
        &.{ "", "a" },
    };
    for (lists) |cands| {
        var w: std.ArrayList(u8) = .empty;
        defer w.deinit(gpa);
        var n: std.ArrayList(u8) = .empty;
        defer n.deinit(gpa);
        try wire.combine_candidates(wire.ctx, 42, cands, gpa, &w);
        try native.combine_candidates(native.ctx, 42, cands, gpa, &n);
        try testing.expectEqualSlices(u8, n.items, w.items);
    }
    try testing.expectEqual(lists.len, h.combine_calls);

    // Every host allocation was copied and freed by the engine side (§7.3).
    try testing.expectEqual(@as(usize, 0), h.mem.liveCount());
    try testing.expect(h.sticky_fault == null);

    // extract_valid_value: the default driver has no extractor; the wire
    // driver's "none" (rc 0) is the same observable — no value.
    try testing.expect(native.extract_valid_value == null);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try testing.expectEqual(false, try wire.extract_valid_value.?(wire.ctx, 1, "v", gpa, &out));
    try testing.expectEqual(@as(usize, 0), out.items.len);
    try testing.expectEqual(@as(usize, 0), h.mem.liveCount());
}

test "§7.3 u64 slots cross losslessly as (lo, hi) u32 halves" {
    const gpa = testing.allocator;
    var h = try FakeHost.init(gpa);
    defer h.deinit();
    const wire = wireDriver(&h);

    const slots = [_]u64{ 0, 1, 0xffff_ffff, 0x1_0000_0000, 0xdead_beef_cafe_f00d, std.math.maxInt(u64) };
    for (slots) |s| {
        _ = wire.validate_value(wire.ctx, s, "v", true);
        try testing.expectEqual(s, h.last_slot);

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try wire.combine_candidates(wire.ctx, s, &.{"v"}, gpa, &out);
        try testing.expectEqual(s, h.last_slot);

        var eout: std.ArrayList(u8) = .empty;
        defer eout.deinit(gpa);
        _ = try wire.extract_valid_value.?(wire.ctx, s, "v", gpa, &eout);
        try testing.expectEqual(s, h.last_slot);
    }

    // is_nomination crosses as 0/1, both directions.
    _ = wire.validate_value(wire.ctx, 1, "v", true);
    try testing.expectEqual(@as(u32, 1), h.last_is_nomination);
    _ = wire.validate_value(wire.ctx, 1, "v", false);
    try testing.expectEqual(@as(u32, 0), h.last_is_nomination);
    try testing.expectEqual(@as(usize, 0), h.mem.liveCount());
}

test "§7.3 combine's ValueList frame carries the candidates verbatim, in order" {
    const gpa = testing.allocator;
    var h = try FakeHost.init(gpa);
    defer h.deinit();
    const wire = wireDriver(&h);

    const cands = [_][]const u8{ "alpha", "", "\x00\xff", "omega" };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try wire.combine_candidates(wire.ctx, 1, &cands, gpa, &out);
    try testing.expectEqual(cands.len, h.last_candidates);
    try testing.expectEqualSlices(u8, "omega", out.items);

    // The frame really is the capnp encoding: decode it independently.
    const frame = try encodeValueList(gpa, &cands);
    defer gpa.free(frame);
    var msg = try Message.init(gpa, frame, .{});
    defer msg.deinit();
    const r = try gen_host.ValueList.Reader.init(&msg);
    const list = try r.getValues();
    try testing.expectEqual(@as(u32, cands.len), list.len());
    for (cands, 0..) |c, i| try testing.expectEqualSlices(u8, c, try list.get(@intCast(i)));

    // Zero candidates encode as an absent pointer and the host rejects them —
    // the same answer the §8.4 default gives (`candidates.len == 0` → fault).
    h.sticky_fault = null;
    try testing.expectError(error.DriverFault, wire.combine_candidates(wire.ctx, 1, &.{}, gpa, &out));
    try testing.expectEqualStrings("driver.combine_candidates", h.sticky_fault.?);
    try testing.expectEqual(@as(usize, 0), h.last_candidates);
    try testing.expectEqual(@as(usize, 0), h.mem.liveCount());
}

test "§7.3 validate_value fault codes surface as a fault and floor the verdict at invalid" {
    const gpa = testing.allocator;
    var h = try FakeHost.init(gpa);
    defer h.deinit();
    const wire = wireDriver(&h);

    // 0/1/2 are the defined verdicts and set no fault.
    for ([_]ValidatePolicy{ .default_84, .maybe_valid }) |p| {
        h.validate_policy = p;
        h.sticky_fault = null;
        _ = wire.validate_value(wire.ctx, 1, "v", true);
        try testing.expect(h.sticky_fault == null);
    }
    try testing.expectEqual(driver_mod.Validity.maybe_valid, wire.validate_value(wire.ctx, 1, "v", true));

    // 3 and anything above it are driver faults: recorded, and floored to
    // `.invalid` so a faulting driver can never widen what the engine accepts.
    for ([_]ValidatePolicy{ .fault_code, .high_fault_code }) |p| {
        h.validate_policy = p;
        h.sticky_fault = null;
        try testing.expectEqual(driver_mod.Validity.invalid, wire.validate_value(wire.ctx, 1, "v", true));
        try testing.expectEqualStrings("driver.validate_value", h.sticky_fault.?);
    }
    try testing.expectEqual(@as(usize, 0), h.mem.liveCount());
}

test "§7.3 combine faults: nonzero rc, null result pointer, and empty result are all DriverFault" {
    const gpa = testing.allocator;
    var h = try FakeHost.init(gpa);
    defer h.deinit();
    const wire = wireDriver(&h);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    h.combine_policy = .fault_rc;
    h.sticky_fault = null;
    try testing.expectError(error.DriverFault, wire.combine_candidates(wire.ctx, 1, &.{"a"}, gpa, &out));
    try testing.expectEqualStrings("driver.combine_candidates", h.sticky_fault.?);
    try testing.expectEqual(@as(usize, 0), out.items.len);

    h.combine_policy = .null_ptr;
    h.sticky_fault = null;
    try testing.expectError(error.DriverFault, wire.combine_candidates(wire.ctx, 1, &.{"a"}, gpa, &out));
    try testing.expectEqualStrings("driver.combine_candidates: empty result", h.sticky_fault.?);
    try testing.expectEqual(@as(usize, 0), out.items.len);

    h.combine_policy = .empty_len;
    h.sticky_fault = null;
    try testing.expectError(error.DriverFault, wire.combine_candidates(wire.ctx, 1, &.{"a"}, gpa, &out));
    try testing.expectEqualStrings("driver.combine_candidates: empty result", h.sticky_fault.?);
    try testing.expectEqual(@as(usize, 0), out.items.len);

    // FINDING (reported, not asserted as desirable): on the empty-result path
    // the host DID call slcp_alloc, and neither the ABI nor this mirror frees
    // that allocation — a nonzero pointer with a zero length leaks one host
    // allocation per fault. It is bounded by the fault being terminal for the
    // input, so the ledger below records it rather than failing the test.
    try testing.expectEqual(@as(usize, 1), h.mem.liveCount());
}

test "§7.3 extract_valid_value: none drops the value, some copies-and-frees, other codes fault" {
    const gpa = testing.allocator;
    var h = try FakeHost.init(gpa);
    defer h.deinit();
    const wire = wireDriver(&h);
    const extract = wire.extract_valid_value.?;

    // 0 = none: no value, no fault, nothing appended (the value is dropped).
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try out.appendSlice(gpa, "pre-existing");
        h.extract_policy = .none;
        try testing.expectEqual(false, try extract(wire.ctx, 5, "candidate", gpa, &out));
        try testing.expectEqualStrings("pre-existing", out.items); // untouched
        try testing.expect(h.sticky_fault == null);
    }
    // 1 = some: the host's allocation is copied out and freed by the engine.
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        h.extract_policy = .echo;
        try testing.expectEqual(true, try extract(wire.ctx, 5, "candidate", gpa, &out));
        try testing.expectEqualStrings("candidate", out.items);
        try testing.expectEqual(@as(usize, 0), h.mem.liveCount());
    }
    // anything else = driver fault.
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        h.extract_policy = .fault_rc;
        h.sticky_fault = null;
        try testing.expectError(error.DriverFault, extract(wire.ctx, 5, "v", gpa, &out));
        try testing.expectEqualStrings("driver.extract_valid_value", h.sticky_fault.?);
    }
    // 1 with an empty result is a fault, not an empty value.
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        h.extract_policy = .empty_some;
        h.sticky_fault = null;
        try testing.expectError(error.DriverFault, extract(wire.ctx, 5, "v", gpa, &out));
        try testing.expectEqualStrings("driver.extract_valid_value: empty result", h.sticky_fault.?);
    }
}

// ---------------------------------------------------------------------------
// §7.3 against a REAL engine — the imports on the actual protocol path
// ---------------------------------------------------------------------------

/// A single-node 1-of-{self} configuration: nomination reaches candidate
/// confirmation on the node's own statement, so `combine_candidates` is
/// invoked on the real path with one push.
fn selfEngine(gpa: std.mem.Allocator, h: *FakeHost) !engine.Engine {
    const seed: [32]u8 = @splat(0x42);
    const pk = try crypto.publicKeyFromSeed(seed);
    const vals = try gpa.alloc(qset.NodeId, 1);
    vals[0] = pk;
    var qs = qset.QuorumSetOwned{
        .threshold = 1,
        .validators = vals,
        .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
    };
    errdefer qs.deinit(gpa);
    try qset.validateAndNormalize(gpa, &qs);
    return engine.Engine.init(gpa, .{
        .network_id = crypto.networkIdFromPassphrase("abi-fake-host v1"),
        .node_id = pk,
        .secret_seed = seed,
        .quorum_set = qs,
        .strict_canonical = true,
        .limits = .{},
    }, wireDriver(h));
}

fn drain(eng: *engine.Engine) void {
    while (eng.popEffect()) |_| eng.commitEffect();
}

test "§7.3 a real engine drives all three imports through the wire protocol" {
    const gpa = testing.allocator;
    var h = try FakeHost.init(gpa);
    defer h.deinit();
    var eng = try selfEngine(gpa, &h);
    defer eng.deinit();

    try eng.pushInput(.{ .nominate = .{ .slot = 1, .value = "the-value", .prev_value = "" } });

    var externalized: ?[]u8 = null;
    defer if (externalized) |v| gpa.free(v);
    while (eng.popEffect()) |eff| {
        if (eff.* == .externalized and externalized == null) {
            externalized = try gpa.dupe(u8, eff.externalized.bytes);
        }
        eng.commitEffect();
    }

    // The imports really were exercised on the protocol path...
    try testing.expect(h.validate_calls > 0);
    try testing.expect(h.combine_calls > 0);
    try testing.expectEqual(@as(u64, 1), h.last_slot);
    try testing.expect(h.sticky_fault == null);
    // ...and every buffer the host allocated was copied out and freed.
    try testing.expectEqual(@as(usize, 0), h.mem.liveCount());
    try testing.expectEqual(false, eng.stats().failed);

    // A 1-of-{self} slot needs no peers: the ballot protocol carries the
    // composite the wire combine produced all the way to externalize.
    for (0..8) |_| {
        if (externalized != null) break;
        try eng.pushInput(.{ .timer_fired = .{ .slot = 1, .timer = .ballot } });
        while (eng.popEffect()) |eff| {
            if (eff.* == .externalized and externalized == null) {
                externalized = try gpa.dupe(u8, eff.externalized.bytes);
            }
            eng.commitEffect();
        }
    }
    try testing.expect(externalized != null);
    try testing.expect(externalized.?.len > 0);
    try testing.expectEqual(false, eng.stats().failed);
    try testing.expectEqual(@as(usize, 0), h.mem.liveCount());
}

test "§7.3 a combine fault abandons the input: sticky failure, no corrupted state" {
    const gpa = testing.allocator;
    var h = try FakeHost.init(gpa);
    defer h.deinit();
    h.combine_policy = .fault_rc;
    var eng = try selfEngine(gpa, &h);
    defer eng.deinit();

    // The nominate reaches candidate confirmation, calls combine, and the
    // host faults: the pipeline maps DriverFault → EngineFailed and marks the
    // engine sticky-failed (§7.2) instead of continuing on partial state.
    try testing.expectError(
        error.EngineFailed,
        eng.pushInput(.{ .nominate = .{ .slot = 1, .value = "the-value", .prev_value = "" } }),
    );
    try testing.expect(h.combine_calls > 0);
    try testing.expectEqualStrings("driver.combine_candidates", h.sticky_fault.?);
    try testing.expectEqual(true, eng.stats().failed);

    // Sticky: every later input is refused with the same error, and no
    // further driver call is made.
    const calls_after = h.combine_calls + h.validate_calls;
    try testing.expectError(error.EngineFailed, eng.pushInput(.{ .purge_slots = .{ .max_slot = 1 } }));
    try testing.expectError(
        error.EngineFailed,
        eng.pushInput(.{ .nominate = .{ .slot = 2, .value = "another", .prev_value = "" } }),
    );
    try testing.expectEqual(calls_after, h.combine_calls + h.validate_calls);

    // Whatever effects were queued before the fault stay drainable and the
    // engine tears down leak-free (std.testing.allocator is the witness).
    drain(&eng);
    try testing.expectEqual(@as(usize, 0), eng.effects.len());
    // The faulting rc path allocated nothing host-side.
    try testing.expectEqual(@as(usize, 0), h.mem.liveCount());
}

test "§7.3 an oversized combine result is a fault, not a wire-cap violation" {
    const gpa = testing.allocator;
    var h = try FakeHost.init(gpa);
    defer h.deinit();
    h.combine_policy = .oversized;
    var eng = try selfEngine(gpa, &h);
    defer eng.deinit();

    // §4.4: a composite over max_value_bytes is a fatal driver error — the
    // engine must never put it on the wire.
    try testing.expectError(
        error.EngineFailed,
        eng.pushInput(.{ .nominate = .{ .slot = 1, .value = "the-value", .prev_value = "" } }),
    );
    try testing.expectEqual(true, eng.stats().failed);
    try testing.expect(h.combine_calls > 0);
    drain(&eng);
}

test "§7.3 a validate fault does not fail the engine: the value is simply invalid" {
    const gpa = testing.allocator;
    var h = try FakeHost.init(gpa);
    defer h.deinit();
    h.validate_policy = .fault_code;
    var eng = try selfEngine(gpa, &h);
    defer eng.deinit();

    // `.invalid` is the safe floor (§7.3): the engine refuses to promote the
    // value, never reaches combine, and stays usable.
    try eng.pushInput(.{ .nominate = .{ .slot = 1, .value = "the-value", .prev_value = "" } });
    drain(&eng);
    try testing.expect(h.validate_calls > 0);
    try testing.expectEqual(@as(usize, 0), h.combine_calls);
    try testing.expectEqualStrings("driver.validate_value", h.sticky_fault.?);
    try testing.expectEqual(false, eng.stats().failed);

    // Still accepting input after the fault.
    try eng.pushInput(.{ .purge_slots = .{ .max_slot = 1 } });
    drain(&eng);
    try testing.expectEqual(@as(usize, 0), h.mem.liveCount());
}

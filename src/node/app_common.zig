//! app_common.zig — machinery shared by the typed application adapters
//! (`app_node.zig`'s `AppNode(App)` and `owned_app_node.zig`'s
//! `OwnedAppNode(App)`): the R8 `Options` mirror, the §8.5 recovery-slot
//! predicate, the create-time failure reporter, and the teaching texts the
//! two adapters report identically.
//!
//! This module is internal: `node.zig` and `lib.zig` do not re-export it, so
//! none of it is public API. Both adapters import it directly.

const std = @import("std");
const node = @import("node.zig");

/// The two `node.Options` fields a typed adapter owns itself: it compiles the
/// app into the driver and installs its own delivery hook.
pub const owned_option_fields = [_][]const u8{ "driver", "delivery" };

pub fn isOwnedOptionField(comptime name: []const u8) bool {
    inline for (owned_option_fields) |o| if (std.mem.eql(u8, name, o)) return true;
    return false;
}

/// The field lists of a typed adapter's `Options`: every `node.Options` field
/// except `driver` and `delivery`, with the SAME types and defaults — taken
/// from `node.Options` itself, so a field added to the bytes-level node appears
/// in the mirror automatically. The `@Struct` call itself lives in the
/// adapter's own `Options` decl (not here) so the reified type's `@typeName`
/// is the public path `…AppNode(App).Options…`, not a private helper's name:
/// the Stable API snapshot pins that spelling on the `create` line.
/// `checkOptionsParity` is the comptime guard that the mirror really is
/// field-for-field the bytes-level set minus the two.
pub const MirrorFields = struct {
    names: []const [:0]const u8,
    types: []const type,
    attrs: []const std.builtin.Type.Struct.FieldAttributes,
};

pub fn mirrorOptionFields() MirrorFields {
    const info = @typeInfo(node.Options).@"struct";
    comptime var names: []const [:0]const u8 = &.{};
    comptime var types: []const type = &.{};
    comptime var attrs: []const std.builtin.Type.Struct.FieldAttributes = &.{};
    inline for (info.field_names, info.field_types, info.field_attrs) |name, FT, attr| {
        if (isOwnedOptionField(name)) continue;
        names = names ++ [_][:0]const u8{name};
        types = types ++ [_]type{FT};
        attrs = attrs ++ [_]std.builtin.Type.Struct.FieldAttributes{attr};
    }
    return .{ .names = names, .types = types, .attrs = attrs };
}

/// Comptime parity: (a) every non-owned `node.Options` field exists in the
/// mirror with an identical type and an identical default (or identically
/// none); (b) the mirror has no other fields; (c) the two owned fields are
/// really absent. A drift in either direction is a compile error naming the
/// field. `options_name` is the adapter's public spelling ("AppNode.Options"
/// / "OwnedAppNode.Options") for those messages.
pub fn checkOptionsParity(comptime Mirror: type, comptime options_name: []const u8) void {
    const src = @typeInfo(node.Options).@"struct";
    const dst = @typeInfo(Mirror).@"struct";
    comptime var expected: usize = 0;
    inline for (src.field_names, src.field_types, src.field_attrs) |name, FT, attr| {
        if (isOwnedOptionField(name)) {
            if (@hasField(Mirror, name))
                @compileError(options_name ++ " must not carry `" ++ name ++ "` (the typed adapter supplies it).");
            continue;
        }
        expected += 1;
        if (!@hasField(Mirror, name))
            @compileError(options_name ++ " is missing node.Options field `" ++ name ++ "`.");
        const idx = std.meta.fieldIndex(Mirror, name).?;
        if (dst.field_types[idx] != FT)
            @compileError(options_name ++ " field `" ++ name ++ "` has type " ++ @typeName(dst.field_types[idx]) ++ ", node.Options has " ++ @typeName(FT) ++ ".");
        const have_default = dst.field_attrs[idx].default_value_ptr != null;
        const want_default = attr.default_value_ptr != null;
        if (have_default != want_default)
            @compileError(options_name ++ " field `" ++ name ++ "` default presence differs from node.Options.");
        if (want_default) {
            const a = attr.defaultValue(FT).?;
            const b = dst.field_attrs[idx].defaultValue(FT).?;
            if (!std.meta.eql(a, b))
                @compileError(options_name ++ " field `" ++ name ++ "` default differs from node.Options.");
        }
    }
    if (dst.field_names.len != expected)
        @compileError(options_name ++ " carries a field node.Options does not have.");
}

pub const create_log = std.log.scoped(.slcp_create);

/// A typed adapter's `create` failure reporter: same contract as the Node's —
/// the paragraph goes into `diagnostic` when given, else to the create log at
/// err level. Generic over the error so each adapter's `CreateError` member
/// coerces at the `return`.
pub fn fail(diag: ?*node.Diagnostic, err: anytype, comptime fmt: []const u8, args: anytype) @TypeOf(err) {
    var local: node.Diagnostic = .{};
    const d = diag orelse &local;
    d.set(fmt, args);
    if (diag == null) create_log.err("{s}", .{d.message()});
    return err;
}

/// §8.5 delta-app recipe: can a `State` persisted at slot `s0` hand off to
/// this Node? A snapshot at 0 claims nothing. Otherwise either the retained
/// local journal must continue it, or an explicit start at its exact
/// successor declares that the application verified an external checkpoint;
/// the separate recovery check also requires its final Command when the
/// journal cannot supply a newer predecessor.
pub fn initialSlotCanStart(s0: u64, tail: ?node.Node.JournalTail, start_slot: u64) bool {
    if (s0 == 0) {
        if (start_slot != 1) return false;
        const t = tail orelse return true;
        return t.contiguous_from == 1;
    }
    const successor = std.math.add(u64, s0, 1) catch return false;
    if (start_slot == successor) {
        const t = tail orelse return true;
        return t.last <= s0 or t.contiguous_from <= successor;
    }
    const t = tail orelse return false;
    if (t.contiguous_from > successor or s0 > t.last) return false;
    // The default lets Node derive the successor from the journal. An
    // explicit start after replay may name only the exact tail successor;
    // anything farther would silently skip a slot after the recovered tail.
    if (start_slot == 1) return true;
    const tail_successor = std.math.add(u64, t.last, 1) catch return false;
    return start_slot == tail_successor;
}

/// The teaching text for a journaled value the current `Command` cannot
/// decode (design §8.5: command evolution is consensus surface).
pub const undecodable_fmt = "slot {d}: journaled value ({d} bytes) does not decode as {s} — the Command type changed since this data_dir was written. Restore the old Command definition, or start a fresh data_dir under a NEW `network` passphrase (command evolution is consensus surface, §8.5).";

/// The teaching text for an out-of-order delivery to an app that declared
/// `initialSlot`-style contiguous state transitions.
pub const delivery_gap_fmt = "slot {d} arrived after applied slot {d}, but {s}.initialSlot() declares contiguous state transitions; the missing slot cannot be skipped, so the typed node is stopping before applying the out-of-order command.";

/// The teaching text for a `combine` whose result does not self-validate
/// (§8.5: the composite must be `.valid`, or `.maybe_valid` when this node is
/// behind); the node goes inert with DriverFault rather than balloting a
/// value every peer rejects.
pub const bad_composite_fmt = "{s}.combine returned a Command that its own validate judges .invalid (slot {d}) — the composite must self-validate (§8.5); the node goes inert (DriverFault) instead of balloting a value every peer would reject.";

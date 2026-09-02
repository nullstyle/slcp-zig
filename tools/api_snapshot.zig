//! Public API snapshot tool — two-tier (Stable / Experimental).
//!
//! A port of capnp-zig's tools/api_snapshot.zig (design §13.8, §14-M6: "API
//! snapshot gates (capnp-zig's `check-api` pattern)"). Walks the `slcp`
//! module's `pub` declaration tree at comptime and emits a sorted,
//! line-oriented description of the API surface: declaration paths plus
//! type/function signatures. Each declaration is assigned a stability TIER by
//! `tierIsStable` and routed to one of two files:
//!
//!   docs/api-snapshot.txt              — STABLE, the FROZEN contract. Any
//!                                        drift here fails `check-api` (RED).
//!   docs/api-snapshot-experimental.txt — EXPERIMENTAL, not frozen. Refreshed
//!                                        in place by local `check-api`; CI's
//!                                        strict mode fails when the committed
//!                                        file is stale.
//!
//!   zig build api-snapshot                        # regenerate BOTH files
//!   zig build check-api                           # fail ONLY on Stable drift;
//!                                                 # refresh the experimental file
//!   zig build -Dstrict-experimental=true check-api # CI (ubuntu): fail on Stable
//!                                                 # drift OR a stale committed
//!                                                 # experimental file
//!   zig build api-closure                         # fail when a Stable signature
//!                                                 # mentions an Experimental type
//!
//! Two things differ from the capnp-zig original:
//!
//!   * The wasm host ABI (src/wasm/slcp_host_abi.zig) is part of the frozen
//!     contract but CANNOT be imported natively — it pins
//!     `std.heap.wasm_allocator` and its `export fn` decls are always analyzed
//!     (see the tests/abi section of build.zig). So the ABI surface is read
//!     as TEXT at runtime and rendered as `slcp-abi.*` lines that flow through
//!     the same tier routing as the comptime walk. That is why every run step
//!     of this tool reads files the build graph does not declare, and why each
//!     carries `setCwd` + `has_side_effects` (HANDOFF §6).
//!   * `slcp.core.capnpc` — the re-exported capnp-zig module — is on a skip
//!     list. It is upstream's surface, frozen by upstream's own snapshot.
//!
//! Stability tiers live in docs/stability.md, which is authoritative for the
//! categorization below. Categorizer contract: `tierIsStable` DEFAULTS every
//! path to Experimental. A declaration is Stable ONLY when its path matches an
//! explicit rule in `stable_rules`. This makes "accidentally freezing
//! something new" a non-event: a brand-new symbol lands in the Experimental
//! file until someone deliberately adds a Stable rule for it.
//!
//! The rule list below is the v0.1.0 freeze (M6 stage S6). Generic entry
//! points (`AppNode`, `Codec`) are pinned through REFERENCE INSTANTIATIONS
//! over the §0 `Counter` app (`reference_instantiations`), so the surface a
//! consumer actually calls — `AppNode(Counter).create/propose/waitApplied`,
//! `Codec(Counter.Command).encode/decode` — is walked like any declaration.

const std = @import("std");
const slcp = @import("slcp");

/// Depth of the whole-tree walk from the `slcp` root. The deepest frozen
/// declaration today is 5 segments (`slcp.core.engine.Effect.SlotBytes.slot`);
/// 8 keeps headroom (`slcp.AppNode(Counter).Applied.state`).
const max_depth = 8;

// ---------------------------------------------------------------------------
// Tier categorizer.
//
// A rule matches on the declaration PATH (the text left of the first ": " in a
// rendered line), never on the signature. Two match kinds:
//
//   .prefix — path equals the rule OR begins with `rule ++ "."`. Freezes a
//             whole subtree (a module, or a type and all its members/fields).
//   .exact  — path equals the rule exactly. Freezes ONE symbol without
//             dragging in its siblings, its fields, or an enclosing
//             container's other members.
//
// The list below is the FULL Stable contract as of v0.1.0 (S6 freeze).
// ---------------------------------------------------------------------------

const MatchKind = enum { prefix, exact };
const Rule = struct { kind: MatchKind, path: []const u8 };

fn p(path: []const u8) Rule {
    return .{ .kind = .prefix, .path = path };
}
fn e(path: []const u8) Rule {
    return .{ .kind = .exact, .path = path };
}

/// Paths whose SUBTREE is not walked (the container line itself still
/// renders, so the re-export is visible). `slcp.core.capnpc` is capnp-zig's
/// whole public surface: frozen by upstream's own `check-api`, and its
/// `serialization`/`rpc` trees would dwarf ours in the experimental file.
const skip_paths = [_][]const u8{
    "slcp.core.capnpc",
};

/// Exclusion overrides: paths docs/stability.md explicitly names as
/// Experimental. Checked FIRST and force Experimental regardless of any
/// Stable rule. Two uses: holding one member out of a `p()` subtree
/// (`Diagnostic.set`), and recording a deliberate NON-promotion of an entry
/// point whose rendered line would pin nothing — a function whose error set
/// is `anyerror` today. `qset.canonicalBytes` inherits capnp-zig's builder
/// errors (`initValidators` resolves to `anyerror`), and `hashNormalized`,
/// `validateAndNormalize` (inner-set ordering hashes) and `Engine.init`
/// (local qset hash) all run through it, so none can carry an explicit set
/// without a behaviour-changing error mapping. Freezing `anyerror!T` would
/// document a contract nobody can `switch` on; these stay Experimental until
/// they have real sets. Rule-liveness applies here too.
const experimental_overrides = [_]Rule{
    // Node-internal writer of the create() failure message (S3: the buffer
    // and `message()` are the consumer's side; `set` is ours).
    e("slcp.node.Diagnostic.set"),
    // `anyerror!` today (see above).
    e("slcp.core.qset.validateAndNormalize"),
    e("slcp.core.qset.hashNormalized"),
    e("slcp.core.qset.canonicalBytes"),
    e("slcp.core.engine.Engine.init"),
};

/// The reference application for the generic entry points: the §0 program's
/// `Counter` (examples/counter/src/main.zig), kept byte-identical so the
/// instantiation pinned here is the one the README's quickstart compiles.
const Counter = struct {
    pub const State = struct { count: u64 = 0 };
    pub const Command = struct { next: u64 };

    pub fn validate(state: State, cmd: Command) slcp.Validity {
        if (cmd.next == state.count + 1) return .valid;
        if (cmd.next > state.count + 1) return .maybe_valid; // this node may be behind
        return .invalid;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = state;
        return .{ .count = cmd.next };
    }
};

/// Generic entry points (`fn (type) type`) render as one opaque line — the
/// INSTANTIATED surface a consumer actually calls is invisible to the walk.
/// Each reference instantiation is walked as a synthetic root under the path
/// given here, so its members are pinned like any other declaration.
/// ORDER MATTERS: the walk's `seen` set is shared, and `AppNode(Counter).codec`
/// IS `Codec(Counter.Command)` — listing the codec first puts its members
/// under their own root instead of under `slcp.AppNode(Counter).codec`.
const RefInst = struct { path: []const u8, ty: type };
const reference_instantiations = [_]RefInst{
    .{ .path = "slcp.Codec(Counter.Command)", .ty = slcp.Codec(Counter.Command) },
    .{ .path = "slcp.AppNode(Counter)", .ty = slcp.AppNode(Counter) },
};

const stable_rules = [_]Rule{
    // --- slcp: the omakase bytes-level node (§11.2). `Node` is frozen EXACTLY
    //     so its fields of internal state (queues, mutexes, threads) stay out
    //     of the contract; the lifecycle + I/O methods are frozen one by one.
    //     The top-level `slcp.Node` / `slcp.NodeOptions` aliases are frozen as
    //     lines too; members render under the canonical `slcp.node.*` path
    //     because the walk reaches `node` (the file) before the alias. ---
    e("slcp.Node"),
    e("slcp.NodeOptions"),
    e("slcp.node.Node"),
    e("slcp.node.Node.create"),
    e("slcp.node.Node.deinit"),
    e("slcp.node.Node.propose"),
    e("slcp.node.Node.waitExternalized"),
    e("slcp.node.Node.stats"),
    e("slcp.node.Node.boundPort"),
    e("slcp.node.Node.allocator"),
    // PREFIX: config/value structs a consumer constructs or reads, whose
    // FIELDS and DEFAULTS are therefore part of the contract.
    p("slcp.node.Node.WaitOptions"),
    p("slcp.node.Options"),
    p("slcp.node.Externalized"),
    // The error taxonomy consumers `switch` on, and the two ways to read a
    // create() failure: the `Diagnostic` buffer (`Options.diagnostic`; its
    // `set` is held out above) and the static `explain`. Everything an
    // `Options` field reaches is Stable (docs/stability.md): `Diagnostic`,
    // `DeliveryHook` (a vtable shape is a contract like `Driver`'s), `Quorum`.
    e("slcp.node.CreateError"),
    e("slcp.node.Error"),
    e("slcp.node.ProposeError"),
    p("slcp.node.Diagnostic"),
    e("slcp.node.explain"),
    e("slcp.node.Node.explain"),
    p("slcp.node.DeliveryHook"),
    e("slcp.DeliveryHook"),

    // --- Quorum UX (§12): the spec type and its constructors (whole module —
    //     `twoThirdsOf`, `majorityOf`, `of`, `ofSets`, JSON in/out, `toOwned`),
    //     the node-id helpers, and the top-level aliases. `lint_report` (the
    //     CLI's rendering) stays Experimental. ---
    p("slcp.core.quorum"),
    p("slcp.Quorum"),
    e("slcp.NodeId"),
    e("slcp.nodeId"),
    e("slcp.parseNodeId"),

    // --- keys UX (§11): the key-file entry points, the pair they yield, and
    //     the named error sets (explicit since S6 — an inferred set that
    //     follows std's fs vocabulary is not a contract). ---
    p("slcp.keys.KeyPair"),
    e("slcp.keys.loadOrCreate"),
    e("slcp.keys.load"),
    e("slcp.keys.createNew"),
    e("slcp.keys.ephemeral"),
    e("slcp.keys.Error"),
    e("slcp.keys.DeriveError"),
    e("slcp.keys.LoadError"),
    e("slcp.keys.MintError"),
    e("slcp.keys.LoadOrCreateError"),
    e("slcp.keys.CreateNewError"),

    // --- The typed layer (§8.5): the two generic entry points as lines, and
    //     their reference instantiations over `Counter`. `AppNode(Counter)`
    //     is exact (its fields are engine-thread state) with the lifecycle +
    //     I/O methods one by one; `Options` / `Applied` are prefix (a
    //     consumer constructs / reads them); `State` / `Command` pin the
    //     aliases the methods are typed against (closure). `codec` and
    //     `apply_in_place` stay Experimental. ---
    e("slcp.AppNode"),
    e("slcp.Codec"),
    e("slcp.AppNode(Counter)"),
    e("slcp.AppNode(Counter).create"),
    e("slcp.AppNode(Counter).deinit"),
    e("slcp.AppNode(Counter).propose"),
    e("slcp.AppNode(Counter).waitApplied"),
    e("slcp.AppNode(Counter).haltError"),
    e("slcp.AppNode(Counter).driver"),
    e("slcp.AppNode(Counter).raw"),
    e("slcp.AppNode(Counter).State"),
    e("slcp.AppNode(Counter).Command"),
    e("slcp.AppNode(Counter).WaitOptions"),
    p("slcp.AppNode(Counter).Options"),
    p("slcp.AppNode(Counter).Applied"),
    e("slcp.AppNode(Counter).CreateError"),
    e("slcp.AppNode(Counter).ProposeError"),
    e("slcp.AppNode(Counter).WaitError"),
    p("slcp.Codec(Counter.Command)"),
    // Top-level aliases of the driver vocabulary (same types as
    // `slcp.core.driver.*`; the alias lines pin the spelling).
    e("slcp.Validity"),
    e("slcp.Driver"),
    e("slcp.DriverError"),

    // --- Driver vtable (§8.2): the frozen host-language contract. PREFIX on
    //     `Driver` pins the vtable field shapes + `default()`; R16 keeps a
    //     future `driver.Checked` Experimental (a sibling — never swept). ---
    p("slcp.core.driver.Driver"),
    p("slcp.core.driver.Validity"),
    e("slcp.core.driver.DriverError"),

    // --- Sans-io engine (§5): the power-user escape hatch. `Engine` exact
    //     (internal fields out), five of its six entry points (`init` is
    //     `anyerror!` — see `experimental_overrides`), and the input/effect
    //     vocabulary as whole subtrees (union variants + payload fields are
    //     the contract). ---
    e("slcp.core.engine.Engine"),
    e("slcp.core.engine.Engine.deinit"),
    e("slcp.core.engine.Engine.pushInput"),
    e("slcp.core.engine.Engine.popEffect"),
    e("slcp.core.engine.Engine.commitEffect"),
    e("slcp.core.engine.Engine.stats"),
    p("slcp.core.engine.Input"),
    p("slcp.core.engine.Effect"),
    p("slcp.core.engine.Config"),
    p("slcp.core.engine.InputStatus"),
    p("slcp.core.engine.PhaseKind"),
    p("slcp.core.engine.TimerId"),
    p("slcp.core.engine.Stats"),
    e("slcp.core.engine.EngineError"),
    e("slcp.core.engine.PushError"),
    e("slcp.core.engine.timeoutMs"),
    // The frozen wire limits (§4.5) and the tunable `Limits` struct.
    p("slcp.core.limits"),

    // --- Quorum set value type (§4.3/§12): what `Config.quorum_set` is
    //     built from (`Quorum.toOwned`). PREFIX on the owned tree (its three
    //     fields are the shape a consumer constructs), the error set and the
    //     frozen constants. `validateAndNormalize` / `hashNormalized` /
    //     `canonicalBytes` are `anyerror!` today (see
    //     `experimental_overrides`); the lint surface (`lint`, `LintFinding`,
    //     `LintCode`, ...) is Experimental — its wire form is frozen by
    //     host.capnp and vectors/lint.json, not by the Zig names. ---
    p("slcp.core.qset.QuorumSetOwned"),
    e("slcp.core.qset.Error"),
    e("slcp.core.qset.NodeId"),
    e("slcp.core.qset.max_depth"),
    e("slcp.core.qset.max_total_validators"),

    // --- The wasm host ABI (§7): every export, every driver import, and the
    //     ABI version, rendered from the module's TEXT (see the module doc). ---
    p("slcp-abi"),
};

/// Prefix of the runtime-rendered ABI lines. Rules under it are checked for
/// liveness at RUNTIME (`checkAbiRuleLiveness`) because the entries do not
/// exist at comptime.
const abi_prefix = "slcp-abi";
const abi_source_path = "src/wasm/slcp_host_abi.zig";

/// The §7.2 negotiation constants pinned from the ABI module's text, by VALUE
/// (`pub const <name>: <type> = <literal>;`). `abi_version` is mandatory (a
/// source without it is `AbiVersionMissing`); the others render when present.
/// Bumping `abi_max_version` or flipping a `feature_flags` bit is a contract
/// change a host negotiates on — it must show in the Stable diff.
const abi_pinned_consts = [_][]const u8{ "abi_version", "abi_min_version", "abi_max_version", "feature_flags" };

/// `pub const <pinned name>: ...` → the text after `pub const `, else null.
fn pinnedAbiConst(line: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, "pub const ")) return null;
    const body = line["pub const ".len..];
    for (abi_pinned_consts) |name| {
        if (std.mem.startsWith(u8, body, name) and body.len > name.len and body[name.len] == ':') return body;
    }
    return null;
}

fn matchesRule(path: []const u8, rules: []const Rule) bool {
    for (rules) |rule| {
        switch (rule.kind) {
            .exact => if (std.mem.eql(u8, path, rule.path)) return true,
            .prefix => {
                if (std.mem.eql(u8, path, rule.path)) return true;
                if (path.len > rule.path.len and
                    std.mem.startsWith(u8, path, rule.path) and
                    path[rule.path.len] == '.') return true;
            },
        }
    }
    return false;
}

/// The one categorizer: comptime for walked declarations, runtime for the
/// ABI text lines. Explicit Experimental overrides win over any Stable rule.
fn tierIsStable(path: []const u8) bool {
    if (matchesRule(path, &experimental_overrides)) return false;
    return matchesRule(path, &stable_rules);
}

fn isSkipped(path: []const u8) bool {
    for (skip_paths) |s| {
        if (std.mem.eql(u8, path, s)) return true;
    }
    return false;
}

fn isContainer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"enum", .@"union", .@"opaque" => true,
        else => false,
    };
}

fn containerKind(comptime T: type) []const u8 {
    return switch (@typeInfo(T)) {
        .@"struct" => "struct",
        .@"enum" => "enum",
        .@"union" => "union",
        .@"opaque" => "opaque",
        else => unreachable,
    };
}

/// Skip recursing into types that are not ours (std re-exports etc.).
///
/// KNOWN LIMITATION (inherited): on this toolchain `@typeName` renders std
/// types module-relative (`mem.Allocator`, `Io`, `array_list.Aligned(u8,null)`),
/// so only the root re-exports are caught by name. The tree has no `pub`
/// re-export of a std type today; if one appears, its members land as noise
/// in the EXPERIMENTAL file (never silently in the contract), which is the
/// benign failure direction.
fn foreignType(comptime T: type) bool {
    const name = @typeName(T);
    return std.mem.startsWith(u8, name, "std.") or
        std.mem.startsWith(u8, name, "builtin.") or
        std.mem.eql(u8, name, "std") or
        std.mem.eql(u8, name, "builtin") or
        T == std or T == std.builtin;
}

fn contains(comptime seen: []const type, comptime T: type) bool {
    for (seen) |S| {
        if (S == T) return true;
    }
    return false;
}

/// Render a function signature, expanding any inferred error set.
///
/// `@typeName` renders an inferred error set as the self-referential expression
/// `@typeInfo(@typeInfo(@TypeOf(f)).@"fn".return_type.?).error_union.error_set`,
/// which is IDENTICAL no matter what the set contains — so adding, removing,
/// or renaming an error would pass the gate unchanged while breaking every
/// consumer's `catch |err| switch (err)`. Expanding the set to a sorted
/// `error{...}` list makes those changes visible.
///
/// `anytype` parameters remain unpinned: they are genuinely unresolved until
/// instantiation, so a signature containing one pins only its arity.
fn renderErrorSet(comptime E: type) []const u8 {
    const info = @typeInfo(E).error_set;
    const names = info.error_names orelse return "anyerror";

    comptime var sorted: []const []const u8 = &.{};
    for (names) |name| sorted = sorted ++ [_][]const u8{name};
    // Insertion sort: the rendered set must not depend on declaration order.
    comptime var i: usize = 1;
    inline while (i < sorted.len) : (i += 1) {
        comptime var j = i;
        inline while (j > 0 and std.mem.lessThan(u8, sorted[j], sorted[j - 1])) : (j -= 1) {
            const swapped = sorted[j - 1];
            var next: []const []const u8 = sorted[0 .. j - 1];
            next = next ++ [_][]const u8{sorted[j]} ++ [_][]const u8{swapped};
            if (j + 1 < sorted.len) next = next ++ sorted[j + 1 ..];
            sorted = next;
        }
    }

    comptime var out: []const u8 = "error{";
    for (sorted, 0..) |name, idx| {
        if (idx != 0) out = out ++ ",";
        out = out ++ name;
    }
    return out ++ "}";
}

fn renderFnType(comptime FnType: type) []const u8 {
    const fn_info = @typeInfo(FnType).@"fn";
    // A GENERIC function's inferred error set cannot be resolved here: it
    // depends on the instantiation, and asking for it is a compile error
    // ("cannot resolve inferred error set of generic function type"). Those
    // lines keep the opaque rendering and stay unpinned.
    if (fn_info.is_generic) return @typeName(FnType);
    const ret = fn_info.return_type orelse return @typeName(FnType);
    switch (@typeInfo(ret)) {
        .error_union => |eu| {
            // Rebuild the signature with the expanded set. The parameter list is
            // taken verbatim from @typeName so `anytype`/`comptime` render
            // exactly as before and only the error set changes.
            const full = @typeName(FnType);
            const open = std.mem.indexOfScalar(u8, full, '(') orelse return full;
            // Match the parameter list's OWN closing paren by depth. A plain
            // lastIndexOf(')') lands inside the rendered return type — which for
            // an inferred error set is itself a paren-heavy expression — and
            // splices that fragment into the output.
            comptime var depth: usize = 0;
            comptime var close: ?usize = null;
            inline for (full[open..], open..) |ch, idx| {
                if (ch == '(') depth += 1;
                if (ch == ')') {
                    depth -= 1;
                    if (depth == 0) {
                        close = idx;
                        break;
                    }
                }
            }
            const close_idx = close orelse return full;
            const params = full[open .. close_idx + 1];
            return "fn " ++ params ++ " " ++ renderErrorSet(eu.error_set) ++ "!" ++ @typeName(eu.payload);
        },
        else => return @typeName(FnType),
    }
}

/// Render a field's default-value initializer, or "" when it has none.
///
/// The default VALUE matters, not just its presence: changing
/// `Options.max_value_bytes` from 4096 to another number is a behavior change
/// for every consumer who relied on it, and a name-only snapshot could not see
/// it. Values are rendered for the scalar kinds where a default is meaningful
/// and comparable; anything else records that a default exists without trying
/// to spell it, which still pins presence.
fn defaultSuffix(
    comptime FieldType: type,
    comptime attrs: std.builtin.Type.Struct.FieldAttributes,
) []const u8 {
    const value = attrs.defaultValue(FieldType) orelse return "";
    return " = " ++ renderValue(FieldType, value);
}

/// Render a comptime-known default. Optionals are unwrapped rather than
/// reported as merely present. Aggregates render as `<default>` — their own
/// fields are pinned separately by their own snapshot lines.
fn renderValue(comptime T: type, comptime value: T) []const u8 {
    return switch (@typeInfo(T)) {
        .int, .comptime_int => std.fmt.comptimePrint("{d}", .{value}),
        .float, .comptime_float => std.fmt.comptimePrint("{d}", .{value}),
        .bool => if (value) "true" else "false",
        .@"enum" => "." ++ @tagName(value),
        .void => "{}",
        .optional => |oi| if (value) |inner| renderValue(oi.child, inner) else "null",
        else => "<default>",
    };
}

/// Emit one line per field/enumerant of a container.
///
/// The walker enumerates DECLARATIONS only, so without this every frozen
/// struct would be pinned by name alone: removing a field from `Options`,
/// reordering a union, or changing a default would be invisible to
/// `check-api`. Fields render under the container's path, so the existing
/// tier rules route them — a `.prefix` rule sweeps its type's fields into the
/// contract, while a `.exact` rule (e.g. `Node` itself) deliberately does not.
fn fieldEntries(
    comptime T: type,
    comptime path: []const u8,
    comptime entries: *[]const Entry,
) void {
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            for (info.field_names, info.field_types, info.field_attrs) |name, FieldType, attrs| {
                const fpath = path ++ "." ++ name;
                entries.* = entries.* ++ [_]Entry{.{
                    .path = fpath,
                    .line = fpath ++ ": field " ++ @typeName(FieldType) ++ defaultSuffix(FieldType, attrs),
                }};
                if (isAnonymousStruct(FieldType)) fieldEntries(FieldType, fpath, entries);
            }
        },
        .@"union" => |info| {
            for (info.field_names, info.field_types) |name, FieldType| {
                const fpath = path ++ "." ++ name;
                entries.* = entries.* ++ [_]Entry{.{
                    .path = fpath,
                    .line = fpath ++ ": variant " ++ @typeName(FieldType),
                }};
                // An anonymous payload (`nominate: struct { slot, value, ... }`)
                // has no declaration path of its own, so its fields would be
                // invisible — renaming `prev_value` would pass the gate. Pin
                // them under the variant's path instead.
                if (isAnonymousStruct(FieldType)) fieldEntries(FieldType, fpath, entries);
            }
        },
        .@"enum" => |info| {
            for (info.field_names, info.field_values) |name, value| {
                const fpath = path ++ "." ++ name;
                entries.* = entries.* ++ [_]Entry{.{
                    .path = fpath,
                    .line = fpath ++ ": enumerant = " ++ std.fmt.comptimePrint("{d}", .{value}),
                }};
            }
        },
        else => {},
    }
}

/// A compiler-named anonymous struct (`Outer__struct_NNNN`): reachable only
/// through the field/variant that declares it.
fn isAnonymousStruct(comptime T: type) bool {
    return @typeInfo(T) == .@"struct" and std.mem.indexOf(u8, @typeName(T), "__struct_") != null;
}

/// Render a `pub const` declaration's VALUE when it is a comparable scalar.
/// The frozen wire limits (`limits.frozen_max_value_bytes_cap = 65536`) are a
/// contract by their numbers, not their types; a type-only line would let a
/// limit change pass the gate.
fn constSuffix(comptime T: type, comptime value: T) []const u8 {
    return switch (@typeInfo(T)) {
        .int, .comptime_int, .bool, .@"enum" => " = " ++ renderValue(T, value),
        else => "",
    };
}

/// A rendered declaration line plus the path that produced it (kept so the
/// categorizer can route lines after they are collected).
const Entry = struct { path: []const u8, line: []const u8 };

fn walk(
    comptime T: type,
    comptime path: []const u8,
    comptime depth: usize,
    comptime seen: *[]const type,
    comptime entries: *[]const Entry,
) void {
    if (depth >= max_depth) return;
    if (contains(seen.*, T)) return;
    seen.* = seen.* ++ [_]type{T};

    for (std.meta.declarations(T)) |decl_name| {
        const decl_path = path ++ "." ++ decl_name;
        const D = @field(T, decl_name);
        const DType = @TypeOf(D);

        if (DType == type) {
            if (isContainer(D)) {
                entries.* = entries.* ++ [_]Entry{.{ .path = decl_path, .line = decl_path ++ ": " ++ containerKind(D) }};
                if (!foreignType(D) and !isSkipped(decl_path)) {
                    fieldEntries(D, decl_path, entries);
                    walk(D, decl_path, depth + 1, seen, entries);
                }
            } else {
                // A typedef whose value is a function (or a pointer to one) is
                // still a signature consumers code against — expand its error
                // set too, rather than leaving the opaque @typeName rendering.
                const rendered = switch (@typeInfo(D)) {
                    .@"fn" => renderFnType(D),
                    .pointer => |pi| if (@typeInfo(pi.child) == .@"fn")
                        "*const " ++ renderFnType(pi.child)
                    else
                        @typeName(D),
                    else => @typeName(D),
                };
                entries.* = entries.* ++ [_]Entry{.{ .path = decl_path, .line = decl_path ++ ": type = " ++ rendered }};
            }
        } else if (@typeInfo(DType) == .@"fn") {
            entries.* = entries.* ++ [_]Entry{.{ .path = decl_path, .line = decl_path ++ ": " ++ renderFnType(DType) }};
        } else {
            entries.* = entries.* ++ [_]Entry{.{
                .path = decl_path,
                .line = decl_path ++ ": const " ++ @typeName(DType) ++ constSuffix(DType, D),
            }};
        }
    }
}

const all_entries: []const Entry = blk: {
    @setEvalBranchQuota(20_000_000);
    var seen: []const type = &.{};
    var entries: []const Entry = &.{};
    walk(slcp, "slcp", 0, &seen, &entries);
    for (reference_instantiations) |ri| {
        entries = entries ++ [_]Entry{.{ .path = ri.path, .line = ri.path ++ ": " ++ containerKind(ri.ty) }};
        fieldEntries(ri.ty, ri.path, &entries);
        walk(ri.ty, ri.path, 0, &seen, &entries);
    }
    break :blk entries;
};

/// Every rule must name a declaration that actually exists.
///
/// A rule for a symbol that was never there (or has since been renamed) is
/// silent: it documents a contract nobody can rely on, and it would mask a
/// typo in a future promotion. This assertion makes the rules list
/// self-validating (in capnp-zig it found a frozen `Peer.run` that was not a
/// method on `Peer` at all). Rules under `slcp-abi` are checked at runtime
/// instead, against the parsed ABI text.
fn ruleMatchesAnyDeclaration(comptime rule: Rule) bool {
    for (all_entries) |entry| {
        switch (rule.kind) {
            .exact => if (std.mem.eql(u8, entry.path, rule.path)) return true,
            .prefix => {
                if (std.mem.eql(u8, entry.path, rule.path)) return true;
                if (entry.path.len > rule.path.len and
                    std.mem.startsWith(u8, entry.path, rule.path) and
                    entry.path[rule.path.len] == '.') return true;
            },
        }
    }
    return false;
}

fn isAbiRule(rule: Rule) bool {
    return std.mem.eql(u8, rule.path, abi_prefix) or
        std.mem.startsWith(u8, rule.path, abi_prefix ++ ".");
}

comptime {
    @setEvalBranchQuota(40_000_000);
    var dead: []const u8 = "";
    for (stable_rules) |rule| {
        if (isAbiRule(rule)) continue;
        if (!ruleMatchesAnyDeclaration(rule)) dead = dead ++ "\n  stable_rules: " ++ rule.path;
    }
    for (experimental_overrides) |rule| {
        if (isAbiRule(rule)) continue;
        if (!ruleMatchesAnyDeclaration(rule)) dead = dead ++ "\n  experimental_overrides: " ++ rule.path;
    }
    if (dead.len != 0) {
        @compileError("api_snapshot: rule(s) match no declaration — remove them or fix the path:" ++ dead);
    }
}

// ---------------------------------------------------------------------------
// Closure gate: is the frozen surface closed under its own signatures?
//
// A Stable entry point whose signature mentions an Experimental type is only
// nominally frozen: the type can change shape under it at any 0.x bump while
// `check-api` stays green, because the Stable *line* never moved. Worse, when
// no Stable API can construct that type, the frozen entry point is unusable
// on its own terms. `zig build api-closure` fails when one does.
//
// KNOWN BLIND SPOT: a generic parameter (`anytype`) has no type to resolve, so
// such signatures are SKIPPED rather than cleared.
// ---------------------------------------------------------------------------

/// A container type the walk reached, plus whether any path reaching it is
/// Stable. Re-exports mean one type can sit at several paths; reachable via a
/// Stable path is what puts it in the contract.
const TypeTier = struct { ty: type, stable: bool };

fn collectTypes(
    comptime T: type,
    comptime path: []const u8,
    comptime depth: usize,
    comptime seen: *[]const type,
    comptime out: *[]const TypeTier,
) void {
    if (depth >= max_depth) return;
    if (contains(seen.*, T)) return;
    seen.* = seen.* ++ [_]type{T};

    for (std.meta.declarations(T)) |decl_name| {
        const decl_path = path ++ "." ++ decl_name;
        const D = @field(T, decl_name);
        if (@TypeOf(D) != type) continue;
        if (!isContainer(D)) continue;
        out.* = out.* ++ [_]TypeTier{.{ .ty = D, .stable = tierIsStable(decl_path) }};
        if (!foreignType(D) and !isSkipped(decl_path)) collectTypes(D, decl_path, depth + 1, seen, out);
    }
}

const type_tiers: []const TypeTier = blk: {
    @setEvalBranchQuota(40_000_000);
    var seen: []const type = &.{};
    var out: []const TypeTier = &.{};
    collectTypes(slcp, "slcp", 0, &seen, &out);
    for (reference_instantiations) |ri| {
        out = out ++ [_]TypeTier{.{ .ty = ri.ty, .stable = tierIsStable(ri.path) }};
        collectTypes(ri.ty, ri.path, 0, &seen, &out);
    }
    break :blk out;
};

/// Strip the wrappers a signature puts around a nominal type.
fn peel(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .pointer => |pi| peel(pi.child),
        .optional => |oi| peel(oi.child),
        .error_union => |eu| peel(eu.payload),
        else => T,
    };
}

/// `null` when the type is not one of ours (std type, primitive, capnp-zig).
fn tierOfType(comptime T: type) ?bool {
    const P = peel(T);
    var found: ?bool = null;
    for (type_tiers) |entry| {
        if (entry.ty == P) {
            if (entry.stable) return true; // any Stable path wins
            found = false;
        }
    }
    return found;
}

const Violation = struct { decl: []const u8, offender: []const u8, role: []const u8 };

/// Walk again, this time checking each Stable function's signature. The check
/// has to happen inside the walk: that is the only place a declaration and its
/// snapshot path are both in hand.
fn collectClosure(
    comptime T: type,
    comptime path: []const u8,
    comptime depth: usize,
    comptime seen: *[]const type,
    comptime out: *[]const Violation,
) void {
    if (depth >= max_depth) return;
    if (contains(seen.*, T)) return;
    seen.* = seen.* ++ [_]type{T};

    for (std.meta.declarations(T)) |decl_name| {
        const decl_path = path ++ "." ++ decl_name;
        const D = @field(T, decl_name);
        const DType = @TypeOf(D);

        if (DType == type) {
            if (isContainer(D) and !foreignType(D) and !isSkipped(decl_path)) {
                collectClosure(D, decl_path, depth + 1, seen, out);
            }
            continue;
        }
        if (@typeInfo(DType) != .@"fn") continue;
        if (!tierIsStable(decl_path)) continue;

        const fn_info = @typeInfo(DType).@"fn";
        if (fn_info.is_generic) continue;

        // A method that takes or returns its OWN enclosing type is not a
        // closure violation: `Node.propose(self: *Node, ...)` is the frozen
        // method of a type deliberately frozen only at its entry points — the
        // receiver is the same declaration cluster, not an unfrozen
        // dependency a consumer must obtain elsewhere.
        for (fn_info.param_types) |maybe_pt| {
            const PT = maybe_pt orelse continue;
            if (peel(PT) == T) continue;
            if (tierOfType(PT)) |is_stable| {
                if (!is_stable) out.* = out.* ++ [_]Violation{.{
                    .decl = decl_path,
                    .offender = @typeName(peel(PT)),
                    .role = "parameter",
                }};
            }
        }
        if (fn_info.return_type) |RT| {
            if (peel(RT) != T) {
                if (tierOfType(RT)) |is_stable| {
                    if (!is_stable) out.* = out.* ++ [_]Violation{.{
                        .decl = decl_path,
                        .offender = @typeName(peel(RT)),
                        .role = "return",
                    }};
                }
            }
        }
    }
}

const closure_violations: []const Violation = blk: {
    @setEvalBranchQuota(40_000_000);
    var seen: []const type = &.{};
    var out: []const Violation = &.{};
    collectClosure(slcp, "slcp", 0, &seen, &out);
    for (reference_instantiations) |ri| {
        collectClosure(ri.ty, ri.path, 0, &seen, &out);
    }
    break :blk out;
};

/// Split the flat entry list into the two tiers at comptime.
const stable_lines: []const []const u8 = blk: {
    @setEvalBranchQuota(20_000_000);
    var stable: []const []const u8 = &.{};
    for (all_entries) |entry| {
        if (tierIsStable(entry.path)) {
            stable = stable ++ [_][]const u8{entry.line};
        }
    }
    break :blk stable;
};

const experimental_lines: []const []const u8 = blk: {
    @setEvalBranchQuota(20_000_000);
    var experimental: []const []const u8 = &.{};
    for (all_entries) |entry| {
        if (!tierIsStable(entry.path)) {
            experimental = experimental ++ [_][]const u8{entry.line};
        }
    }
    break :blk experimental;
};

// ---------------------------------------------------------------------------
// The wasm host ABI, from TEXT.
//
// One line per `export fn` (`slcp-abi.export.<name>: fn (...) <ret>`), one per
// `extern "<module>" fn` driver import
// (`slcp-abi.import.<module>.<name>: fn (...) <ret>`), plus the negotiation
// constants (`slcp-abi.abi_version: const u32 = <n>`, `abi_min_version`,
// `abi_max_version`, `feature_flags` — `abi_pinned_consts`). The parser is
// deliberately line-oriented and strict: an export or import whose signature
// does not close on the line that opens it is an error, never a silently
// truncated line — a truncated signature would freeze the wrong contract.
// ---------------------------------------------------------------------------

const AbiParseError = error{
    AbiSignatureSpansLines,
    AbiVersionMissing,
    /// `@export(...)` in the ABI source: a real wasm export whose name the
    /// text never spells next to a signature, so the line parser cannot
    /// render it. Spell it `export fn` instead.
    AbiExportViaBuiltin,
    /// `export var` / `export const`: a data symbol, not part of the §7 fn
    /// surface and not renderable as a `fn` line.
    AbiExportNotFn,
    /// The tokenizer counted more `export fn` than the line parser rendered:
    /// a spelling the parser does not know. Never a silent miss.
    AbiExportUnparsed,
    OutOfMemory,
};

/// `pub export fn` / `pub extern "…"` are the same exports as the bare
/// spellings: `pub` only widens the Zig-side visibility. Strip it so both
/// render (S8 D10 finding: a `pub export fn` shipped unfrozen and unlisted).
fn stripPub(line: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, line, "pub ")) line["pub ".len..] else line;
}

/// The line parser's self-check: tokenize the source (comments and string
/// literals fall away) and count every `export` keyword that opens a
/// function. Any other export shape is refused outright: `@export(...)`
/// (`AbiExportViaBuiltin`) and `export var`/`export const`
/// (`AbiExportNotFn`). The caller compares the count against the lines it
/// rendered, so a spelling the line parser does not know can never ship as a
/// silently unfrozen export.
fn countExportFns(gpa: std.mem.Allocator, src: []const u8) error{ OutOfMemory, AbiExportViaBuiltin, AbiExportNotFn }!usize {
    const z = try gpa.dupeSentinel(u8, src, 0);
    defer gpa.free(z);
    var tok = std.zig.Tokenizer.init(z);
    var count: usize = 0;
    var after_export = false;
    while (true) {
        const t = tok.next();
        if (t.tag == .eof) break;
        if (after_export) {
            if (t.tag != .keyword_fn) return error.AbiExportNotFn;
            count += 1;
        }
        after_export = t.tag == .keyword_export;
        if (t.tag == .builtin and std.mem.eql(u8, z[t.loc.start..t.loc.end], "@export")) {
            return error.AbiExportViaBuiltin;
        }
    }
    return count;
}

/// The signature must open and close on this line and end with `terminator`
/// (`{` for an export body, `;` for an extern prototype). Returns it with the
/// terminator and surrounding whitespace stripped.
fn oneLineSignature(text: []const u8, terminator: u8) error{AbiSignatureSpansLines}![]const u8 {
    if (text.len == 0 or text[text.len - 1] != terminator) return error.AbiSignatureSpansLines;
    const sig = std.mem.trim(u8, text[0 .. text.len - 1], " \t");
    var depth: isize = 0;
    var saw_open = false;
    for (sig) |c| {
        if (c == '(') {
            depth += 1;
            saw_open = true;
        } else if (c == ')') {
            depth -= 1;
        }
    }
    if (!saw_open or depth != 0) return error.AbiSignatureSpansLines;
    return sig;
}

/// Render the frozen ABI surface from the module's source text. Lines come
/// back in source order; the caller owns each line and the slice.
fn renderAbiLines(gpa: std.mem.Allocator, src: []const u8) AbiParseError![][]u8 {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |l| gpa.free(l);
        out.deinit(gpa);
    }
    var saw_version = false;
    var exports_rendered: usize = 0;
    var it = std.mem.splitScalar(u8, src, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        const decl = stripPub(line);
        if (std.mem.startsWith(u8, decl, "export fn ")) {
            const sig = try oneLineSignature(decl["export fn ".len..], '{');
            const name_len = std.mem.indexOfScalar(u8, sig, '(') orelse return error.AbiSignatureSpansLines;
            try out.append(gpa, try std.fmt.allocPrint(gpa, "{s}.export.{s}: fn {s}", .{
                abi_prefix, sig[0..name_len], sig[name_len..],
            }));
            exports_rendered += 1;
        } else if (std.mem.startsWith(u8, decl, "extern \"")) {
            const rest = decl["extern \"".len..];
            const q = std.mem.indexOfScalar(u8, rest, '"') orelse return error.AbiSignatureSpansLines;
            const module = rest[0..q];
            const after = rest[q + 1 ..];
            if (!std.mem.startsWith(u8, after, " fn ")) return error.AbiSignatureSpansLines;
            const sig = try oneLineSignature(after[" fn ".len..], ';');
            const name_len = std.mem.indexOfScalar(u8, sig, '(') orelse return error.AbiSignatureSpansLines;
            try out.append(gpa, try std.fmt.allocPrint(gpa, "{s}.import.{s}.{s}: fn {s}", .{
                abi_prefix, module, sig[0..name_len], sig[name_len..],
            }));
        } else if (pinnedAbiConst(line)) |raw_body| {
            // `pub const abi_version: u32 = 1;` → `slcp-abi.abi_version: const u32 = 1`
            // (same shape for abi_min_version / abi_max_version / feature_flags).
            const body = std.mem.trim(u8, raw_body, "; \t");
            const colon = std.mem.indexOf(u8, body, ": ") orelse return error.AbiSignatureSpansLines;
            try out.append(gpa, try std.fmt.allocPrint(gpa, "{s}.{s}: const {s}", .{
                abi_prefix, body[0..colon], body[colon + 2 ..],
            }));
            if (std.mem.eql(u8, body[0..colon], "abi_version")) saw_version = true;
        }
    }
    if (!saw_version) return error.AbiVersionMissing;
    const exports_in_source = try countExportFns(gpa, src);
    if (exports_in_source != exports_rendered) {
        std.debug.print(
            "api-snapshot: {s}: the tokenizer sees {d} `export fn` but the line parser rendered {d} — an export spelling the parser does not know\n",
            .{ abi_source_path, exports_in_source, exports_rendered },
        );
        return error.AbiExportUnparsed;
    }
    return out.toOwnedSlice(gpa);
}

fn freeAbiLines(gpa: std.mem.Allocator, lines: [][]u8) void {
    for (lines) |l| gpa.free(l);
    gpa.free(lines);
}

fn abiLinePath(line: []const u8) []const u8 {
    const colon = std.mem.indexOf(u8, line, ": ") orelse return line;
    return line[0..colon];
}

/// The runtime half of the rule-liveness assertion: every `slcp-abi` rule
/// must match at least one parsed ABI line.
fn checkAbiRuleLiveness(abi_lines: []const []u8) error{DeadAbiRule}!void {
    var dead = false;
    inline for (.{ stable_rules, experimental_overrides }) |rules| {
        for (rules) |rule| {
            if (!isAbiRule(rule)) continue;
            var live = false;
            for (abi_lines) |line| {
                if (matchesRule(abiLinePath(line), &.{rule})) {
                    live = true;
                    break;
                }
            }
            if (!live) {
                std.debug.print("api-snapshot: rule matches no ABI declaration — remove it or fix the path: {s}\n", .{rule.path});
                dead = true;
            }
        }
    }
    if (dead) return error.DeadAbiRule;
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// std type spellings that name the SAME logical type with a different path
/// per platform. `@typeName` reports the resolved declaration, so without this
/// the rendered surface differs by the OS that generated it and no staleness
/// gate can run in CI. Concretely: `std.posix.sockaddr` resolves through
/// translate-c on macOS (`c.sockaddr__struct_*`, after the numeric suffix is
/// normalized) and through `os.linux.sockaddr` on Linux. Longest/base forms
/// come first: replacing the base rewrites the `.in`/`.in6` members with it.
const platform_type_aliases = [_]struct { from: []const u8, to: []const u8 }{
    .{ .from = "c.sockaddr__struct_*", .to = "posix.sockaddr" },
    .{ .from = "os.linux.sockaddr", .to = "posix.sockaddr" },
    .{ .from = "os.darwin.sockaddr", .to = "posix.sockaddr" },
    .{ .from = "os.windows.ws2_32.sockaddr", .to = "posix.sockaddr" },
};

fn canonicalizePlatformTypes(allocator: std.mem.Allocator, line: []u8) ![]u8 {
    var current = line;
    for (platform_type_aliases) |alias| {
        if (std.mem.indexOf(u8, current, alias.from) == null) continue;
        const size = std.mem.replacementSize(u8, current, alias.from, alias.to);
        const next = try allocator.alloc(u8, size);
        _ = std.mem.replace(u8, current, alias.from, alias.to, next);
        allocator.free(current);
        current = next;
    }
    return current;
}

/// Copy `line` with every `__struct_<digits>` collapsed to `__struct_*`, then
/// canonicalize platform type spellings. Those suffixes are compiler-assigned
/// anonymous-type counters (the `Input`/`Effect` union payload structs render
/// as `engine.engine.Input__struct_NNNN`): they shift whenever unrelated code
/// changes and differ between targets, so keeping them verbatim would make
/// the snapshot churn without any API change.
fn normalizeLine(allocator: std.mem.Allocator, line: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const marker = "__struct_";
    var rest = line;
    while (std.mem.indexOf(u8, rest, marker)) |idx| {
        var end = idx + marker.len;
        while (end < rest.len and std.ascii.isDigit(rest[end])) end += 1;
        try out.appendSlice(allocator, rest[0 .. idx + marker.len]);
        try out.append(allocator, '*');
        rest = rest[end..];
    }
    try out.appendSlice(allocator, rest);
    return canonicalizePlatformTypes(allocator, try out.toOwnedSlice(allocator));
}

fn renderSnapshot(
    allocator: std.mem.Allocator,
    lines: []const []const u8,
    header: []const u8,
) ![]u8 {
    const normalized = try allocator.alloc([]u8, lines.len);
    var normalized_count: usize = 0;
    defer {
        for (normalized[0..normalized_count]) |line| allocator.free(line);
        allocator.free(normalized);
    }
    for (lines) |line| {
        normalized[normalized_count] = try normalizeLine(allocator, line);
        normalized_count += 1;
    }
    std.mem.sort([]u8, normalized[0..normalized_count], {}, lessThan);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, header);
    for (normalized[0..normalized_count]) |line| {
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

const stable_header =
    \\# STABLE public API snapshot — the FROZEN contract.
    \\# Generated by `zig build api-snapshot`. A diff here is a breaking API
    \\# change: `zig build check-api` fails (RED) until it is reviewed against
    \\# docs/stability.md and this file is committed.
    \\# The categorizer lives in tools/api_snapshot.zig (`stable_rules`).
    \\# `slcp-abi.*` lines are the wasm host ABI, rendered from
    \\# src/wasm/slcp_host_abi.zig's text (the module cannot be imported natively).
    \\
;

const experimental_header =
    \\# EXPERIMENTAL public API surface — informational, NOT frozen.
    \\# Generated by `zig build api-snapshot`; regenerated on every `check-api`.
    \\# Drift here does NOT fail the default gate (CI's ubuntu job passes
    \\# -Dstrict-experimental=true so the committed copy cannot go stale). Do not
    \\# rely on any symbol below across releases; only docs/api-snapshot.txt is
    \\# a contract.
    \\
;

const stable_path_default = "docs/api-snapshot.txt";
const experimental_path_default = "docs/api-snapshot-experimental.txt";

fn writeFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

/// Diff `rendered` against the on-disk `path`; on mismatch print every
/// drifting line (capped). Returns true when they match.
fn diffAndReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    rendered: []const u8,
) !bool {
    const existing = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024 * 1024)) catch |err| {
        std.debug.print(
            "api-snapshot: cannot read {s}; run `zig build api-snapshot` to create it ({})\n",
            .{ path, err },
        );
        return error.ApiSnapshotMissing;
    };
    defer allocator.free(existing);

    if (std.mem.eql(u8, existing, rendered)) return true;

    var existing_it = std.mem.splitScalar(u8, existing, '\n');
    var rendered_it = std.mem.splitScalar(u8, rendered, '\n');
    var line_no: usize = 1;
    // Report EVERY drifting line (capped), not just the first: platform-
    // render drifts are same-line substitutions scattered through the file,
    // and first-only reporting costs one full CI round trip per line. An
    // insertion/deletion makes every later line "drift"; the cap keeps that
    // cascade readable.
    var drifts: usize = 0;
    const max_reported = 25;
    while (true) : (line_no += 1) {
        const a = existing_it.next();
        const b = rendered_it.next();
        if (a == null and b == null) break;
        const a_line = a orelse "<end of snapshot>";
        const b_line = b orelse "<end of live surface>";
        if (!std.mem.eql(u8, a_line, b_line)) {
            drifts += 1;
            if (drifts <= max_reported) {
                std.debug.print(
                    "api-snapshot: drift in {s} at line {}:\n  snapshot: {s}\n  live:     {s}\n",
                    .{ path, line_no, a_line, b_line },
                );
            }
        }
    }
    if (drifts > max_reported) {
        std.debug.print(
            "api-snapshot: ... and {} more drifting lines (an insertion or deletion cascades; regenerate to resolve)\n",
            .{drifts - max_reported},
        );
    }
    return false;
}

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const io = init.io;

    var mode: enum { check, write, closure } = .check;
    var strict_experimental = false;
    var stable_path: []const u8 = stable_path_default;
    var experimental_path: []const u8 = experimental_path_default;

    // initAllocator is the cross-platform form. The iterator stays alive for
    // all of main because --path captures a slice of its buffer.
    var iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer iter.deinit();
    _ = iter.skip();
    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--write")) {
            mode = .write;
        } else if (std.mem.eql(u8, arg, "--check")) {
            mode = .check;
        } else if (std.mem.eql(u8, arg, "--closure")) {
            mode = .closure;
        } else if (std.mem.eql(u8, arg, "--strict-experimental")) {
            strict_experimental = true;
        } else if (std.mem.eql(u8, arg, "--path")) {
            stable_path = iter.next() orelse return error.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--experimental-path")) {
            experimental_path = iter.next() orelse return error.InvalidArgument;
        } else {
            std.debug.print("api-snapshot: unknown argument: {s}\n", .{arg});
            return error.InvalidArgument;
        }
    }

    if (mode == .closure) {
        if (closure_violations.len == 0) {
            std.debug.print("api-closure: OK — the frozen surface is closed under its own signatures\n", .{});
            return;
        }
        std.debug.print(
            "api-closure: {d} Stable declaration(s) mention an Experimental type.\n" ++
                "Each is an API decision: promote the type, or narrow the entry point.\n\n",
            .{closure_violations.len},
        );
        for (closure_violations) |v| {
            std.debug.print("  {s}\n    {s}: {s}\n", .{ v.decl, v.role, v.offender });
        }
        std.debug.print(
            "\nNOTE: signatures with an `anytype` parameter are skipped — there is no\n" ++
                "type to resolve until instantiation.\n",
            .{},
        );
        return error.StableSurfaceNotClosed;
    }

    // The ABI half of the surface: read the module text (relative to the
    // build root — the run step pins cwd) and route each line by tier.
    const abi_src = std.Io.Dir.cwd().readFileAlloc(io, abi_source_path, allocator, .limited(4 * 1024 * 1024)) catch |err| {
        std.debug.print("api-snapshot: cannot read {s} ({}); run from the repository root\n", .{ abi_source_path, err });
        return error.AbiSourceMissing;
    };
    defer allocator.free(abi_src);
    const abi_lines = try renderAbiLines(allocator, abi_src);
    defer freeAbiLines(allocator, abi_lines);
    try checkAbiRuleLiveness(abi_lines);

    var stable_all: std.ArrayList([]const u8) = .empty;
    defer stable_all.deinit(allocator);
    var experimental_all: std.ArrayList([]const u8) = .empty;
    defer experimental_all.deinit(allocator);
    try stable_all.appendSlice(allocator, stable_lines);
    try experimental_all.appendSlice(allocator, experimental_lines);
    for (abi_lines) |line| {
        if (tierIsStable(abiLinePath(line))) {
            try stable_all.append(allocator, line);
        } else {
            try experimental_all.append(allocator, line);
        }
    }

    const stable_rendered = try renderSnapshot(allocator, stable_all.items, stable_header);
    defer allocator.free(stable_rendered);
    const experimental_rendered = try renderSnapshot(allocator, experimental_all.items, experimental_header);
    defer allocator.free(experimental_rendered);

    switch (mode) {
        // Handled above, before the snapshots are rendered.
        .closure => unreachable,
        .write => {
            try writeFile(io, stable_path, stable_rendered);
            try writeFile(io, experimental_path, experimental_rendered);
            std.debug.print(
                "api-snapshot: wrote {} stable lines to {s}, {} experimental lines to {s}\n",
                .{ stable_all.items.len, stable_path, experimental_all.items.len, experimental_path },
            );
        },
        .check => {
            if (strict_experimental) {
                // Strict mode (CI ubuntu, R20): the Experimental file is not
                // a frozen contract, but the COMMITTED snapshot must match the
                // tree — otherwise the "informational" surface silently goes
                // stale and platform-dependent renderings slip through
                // unnoticed. Drift is RED with a refresh instruction, not a
                // review one.
                const experimental_ok = try diffAndReport(allocator, io, experimental_path, experimental_rendered);
                if (!experimental_ok) {
                    std.debug.print(
                        "api-snapshot: EXPERIMENTAL surface drifted from the committed {s}. Not a frozen contract — refresh it: run `zig build api-snapshot` and commit the result.\n",
                        .{experimental_path},
                    );
                    return error.ExperimentalSnapshotDrift;
                }
            } else {
                // The Experimental file is informational: refresh it in place
                // so it never goes stale, but its content does not fail the
                // default gate. A drift is still WORTH A LINE so a developer
                // sees the refresh happened.
                const was_current = std.Io.Dir.cwd().readFileAlloc(io, experimental_path, allocator, .limited(16 * 1024 * 1024)) catch null;
                defer if (was_current) |c| allocator.free(c);
                const same = if (was_current) |c| std.mem.eql(u8, c, experimental_rendered) else false;
                if (!same) {
                    writeFile(io, experimental_path, experimental_rendered) catch |err| {
                        std.debug.print(
                            "api-snapshot: note: could not refresh {s} ({}); continuing\n",
                            .{ experimental_path, err },
                        );
                    };
                    std.debug.print("api-snapshot: warning: refreshed the (non-frozen) {s}; commit it\n", .{experimental_path});
                }
            }

            // The Stable file is the frozen contract: drift here is RED.
            const stable_ok = try diffAndReport(allocator, io, stable_path, stable_rendered);
            if (!stable_ok) {
                std.debug.print(
                    "api-snapshot: STABLE public API surface changed. This is a frozen contract. Review against docs/stability.md, then run `zig build api-snapshot` and commit the result.\n",
                    .{},
                );
                return error.ApiSnapshotDrift;
            }
            std.debug.print(
                "api-snapshot: OK ({} stable declarations frozen; {} experimental {s})\n",
                .{ stable_all.items.len, experimental_all.items.len, if (strict_experimental) @as([]const u8, "verified") else "refreshed" },
            );
        },
    }
}

// ---------------------------------------------------------------------------
// Unit tests (`zig build api-snapshot-tests`, part of `zig build test`).
// ---------------------------------------------------------------------------

// Non-vacuity: ablating the insertion sort in `renderErrorSet` renders the
// declaration order (`Zed,Alpha,Mid`) and this fails.
test "renderErrorSet sorts error names regardless of declaration order" {
    try std.testing.expectEqualStrings(
        "error{Alpha,Mid,Zed}",
        comptime renderErrorSet(error{ Zed, Alpha, Mid }),
    );
}

// Non-vacuity: ablating the `__struct_` digit collapse leaves `__struct_27173`
// in the output; dropping the `os.linux.sockaddr` alias leaves it unrewritten.
// Either turns this red.
test "normalizeLine collapses anonymous-struct counters and canonicalizes platform sockaddr spellings" {
    const gpa = std.testing.allocator;
    const out = try normalizeLine(gpa, "x.y: variant engine.Input__struct_27173 os.linux.sockaddr.in");
    defer gpa.free(out);
    try std.testing.expectEqualStrings("x.y: variant engine.Input__struct_* posix.sockaddr.in", out);
}

// Non-vacuity: pointing a rule at a renamed path (`slcp.node.Node.creat`)
// makes the first `expect` red; removing the field-exclusion semantics of
// `.exact` (treating it as a prefix) makes the `Node.gpa` line red.
test "tier categorizer: exact rules do not sweep fields, prefix rules do, ABI lines route by path" {
    try std.testing.expect(tierIsStable("slcp.node.Node.create"));
    try std.testing.expect(tierIsStable("slcp.node.Node"));
    try std.testing.expect(!tierIsStable("slcp.node.Node.gpa"));
    try std.testing.expect(tierIsStable("slcp.node.Options.peers"));
    try std.testing.expect(tierIsStable("slcp.core.limits.Limits.max_value_bytes"));
    try std.testing.expect(!tierIsStable("slcp.overlay.Overlay"));
    try std.testing.expect(tierIsStable("slcp-abi.export.slcp_alloc"));
    try std.testing.expect(!tierIsStable("slcp-abinot.export.slcp_alloc"));
}

const abi_fixture =
    \\//! fixture
    \\pub const abi_version: u32 = 7;
    \\pub const abi_min_version: u32 = 1;
    \\
    \\/// doc comment with fn words in it: export fn not_a_decl(x: u32) u32 {
    \\export fn slcp_alloc(len: u32) u32 {
    \\    return 0;
    \\}
    \\export fn slcp_engine_pop_effect(handle: u32, out_ptr_ptr: u32, out_len_ptr: u32) u32 {
    \\    return 0;
    \\}
    \\const imports = struct {
    \\    extern "slcp_driver" fn validate_value(slot_lo: u32, slot_hi: u32, ptr: u32, len: u32, is_nomination: u32) u32;
    \\};
    \\
;

// Non-vacuity: dropping the `extern "` arm loses the import line (4 ≠ 5);
// dropping `abi_min_version` from `abi_pinned_consts` loses lines[1] (the
// pre-S6 parser pinned only `abi_version`); rendering a const without the
// `const ` marker or with the `;` kept fails the string compare.
test "ABI text parser renders exports, driver imports and the negotiation consts from an inline fixture" {
    const gpa = std.testing.allocator;
    const lines = try renderAbiLines(gpa, abi_fixture);
    defer freeAbiLines(gpa, lines);
    try std.testing.expectEqual(@as(usize, 5), lines.len);
    try std.testing.expectEqualStrings("slcp-abi.abi_version: const u32 = 7", lines[0]);
    try std.testing.expectEqualStrings("slcp-abi.abi_min_version: const u32 = 1", lines[1]);
    try std.testing.expectEqualStrings("slcp-abi.export.slcp_alloc: fn (len: u32) u32", lines[2]);
    try std.testing.expectEqualStrings(
        "slcp-abi.export.slcp_engine_pop_effect: fn (handle: u32, out_ptr_ptr: u32, out_len_ptr: u32) u32",
        lines[3],
    );
    try std.testing.expectEqualStrings(
        "slcp-abi.import.slcp_driver.validate_value: fn (slot_lo: u32, slot_hi: u32, ptr: u32, len: u32, is_nomination: u32) u32",
        lines[4],
    );
}

// Non-vacuity: a const outside `abi_pinned_consts` (`version_string`, or a
// name that merely STARTS with a pinned one) must not render — treating the
// list as a prefix match makes the length expect red.
test "ABI text parser pins only the four negotiation consts" {
    const gpa = std.testing.allocator;
    const fixture =
        \\pub const abi_version: u32 = 1;
        \\pub const abi_version_string = "x";
        \\pub const version_string = "slcp-core";
        \\pub const feature_flags: u64 = 0b101;
        \\
    ;
    const lines = try renderAbiLines(gpa, fixture);
    defer freeAbiLines(gpa, lines);
    try std.testing.expectEqual(@as(usize, 2), lines.len);
    try std.testing.expectEqualStrings("slcp-abi.abi_version: const u32 = 1", lines[0]);
    try std.testing.expectEqualStrings("slcp-abi.feature_flags: const u64 = 0b101", lines[1]);
}

// Non-vacuity: removing the terminator check in `oneLineSignature` makes the
// parser emit a truncated `slcp_multi(` line instead of erroring.
test "ABI text parser refuses a signature that spans lines" {
    const gpa = std.testing.allocator;
    const fixture =
        \\pub const abi_version: u32 = 1;
        \\export fn slcp_multi(
        \\    a: u32,
        \\) u32 {
        \\    return a;
        \\}
        \\
    ;
    try std.testing.expectError(error.AbiSignatureSpansLines, renderAbiLines(gpa, fixture));
}

// Non-vacuity (S8 D10 "ABI text parser misses `pub export fn` and
// `@export`"): before the fix the first fixture rendered ONE line (the const)
// — a `pub export fn` shipped in slcp_core.wasm unfrozen and unlisted while
// check-api stayed green — and the second returned OK instead of an error.
// Dropping `stripPub` makes the length expect red (1 ≠ 3); dropping the
// tokenizer cross-check lets the `@export` fixture render.
test "ABI text parser accepts `pub export fn` / `pub extern` and refuses `@export` and `export var`" {
    const gpa = std.testing.allocator;
    const pub_fixture =
        \\pub const abi_version: u32 = 1;
        \\pub export fn slcp_pub_export(x: u32) u32 {
        \\    return x;
        \\}
        \\const imports = struct {
        \\    pub extern "slcp_driver" fn pub_import(a: u32) u32;
        \\};
        \\
    ;
    const lines = try renderAbiLines(gpa, pub_fixture);
    defer freeAbiLines(gpa, lines);
    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings("slcp-abi.export.slcp_pub_export: fn (x: u32) u32", lines[1]);
    try std.testing.expectEqualStrings("slcp-abi.import.slcp_driver.pub_import: fn (a: u32) u32", lines[2]);

    const builtin_fixture =
        \\pub const abi_version: u32 = 1;
        \\fn hidden() callconv(.c) u32 {
        \\    return 0;
        \\}
        \\comptime {
        \\    @export(&hidden, .{ .name = "slcp_hidden" });
        \\}
        \\
    ;
    try std.testing.expectError(error.AbiExportViaBuiltin, renderAbiLines(gpa, builtin_fixture));

    const var_fixture =
        \\pub const abi_version: u32 = 1;
        \\export var slcp_counter: u32 = 0;
        \\
    ;
    try std.testing.expectError(error.AbiExportNotFn, renderAbiLines(gpa, var_fixture));
}

// Non-vacuity: removing the `saw_version` requirement lets a source with no
// `abi_version` render (an empty contract) instead of failing.
test "ABI text parser requires abi_version" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.AbiVersionMissing, renderAbiLines(gpa, "export fn f() void {\n}\n"));
}

// Non-vacuity: the counts are the frozen §7 surface (design §14-M4);
// deleting one `export fn` from src/wasm/slcp_host_abi.zig, adding a fourth
// driver import, or changing `feature_flags` from 0b101 turns this red. Reads
// the real file relative to the build root (the run step pins cwd +
// has_side_effects).
test "real src/wasm/slcp_host_abi.zig renders 23 exports + 3 imports + the 4 negotiation consts" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const src = try std.Io.Dir.cwd().readFileAlloc(io, abi_source_path, gpa, .limited(4 * 1024 * 1024));
    defer gpa.free(src);
    const lines = try renderAbiLines(gpa, src);
    defer freeAbiLines(gpa, lines);

    var exports: usize = 0;
    var imports: usize = 0;
    var versions: usize = 0;
    var flags: usize = 0;
    for (lines) |line| {
        if (std.mem.startsWith(u8, line, "slcp-abi.export.")) exports += 1;
        if (std.mem.startsWith(u8, line, "slcp-abi.import.slcp_driver.")) imports += 1;
        if (std.mem.eql(u8, line, "slcp-abi.abi_version: const u32 = 1")) versions += 1;
        if (std.mem.eql(u8, line, "slcp-abi.abi_min_version: const u32 = 1")) versions += 1;
        if (std.mem.eql(u8, line, "slcp-abi.abi_max_version: const u32 = 1")) versions += 1;
        if (std.mem.eql(u8, line, "slcp-abi.feature_flags: const u64 = 0b101")) flags += 1;
    }
    try std.testing.expectEqual(@as(usize, 23), exports);
    try std.testing.expectEqual(@as(usize, 3), imports);
    try std.testing.expectEqual(@as(usize, 3), versions);
    try std.testing.expectEqual(@as(usize, 1), flags);
    try std.testing.expectEqual(@as(usize, 30), lines.len);
    // Every ABI line is Stable under `p("slcp-abi")`, and the rule is live.
    for (lines) |line| try std.testing.expect(tierIsStable(abiLinePath(line)));
    try checkAbiRuleLiveness(lines);
}

// Non-vacuity: the comptime walk must reach the frozen declarations —
// if `skip_paths` or `max_depth` ever hid `slcp.node.Node.propose`, the
// rule-liveness assertion would fail to compile first; this pins the
// rendered line's SHAPE (an expanded error set, never the opaque
// `@typeInfo(...)` spelling) so a regression in `renderFnType` is caught
// without a snapshot file. Ablation: return `@typeName(FnType)` from the
// `.error_union` arm of `renderFnType` and the `@typeInfo` check fails.
test "the walked surface renders Node.propose with an expanded error set" {
    var found = false;
    for (stable_lines) |line| {
        if (std.mem.startsWith(u8, line, "slcp.node.Node.propose: fn (")) {
            found = true;
            try std.testing.expect(std.mem.indexOf(u8, line, "@typeInfo") == null);
            try std.testing.expect(std.mem.indexOf(u8, line, " error{") != null);
        }
    }
    try std.testing.expect(found);
}

fn stableLineWithPrefix(comptime prefix: []const u8) ?[]const u8 {
    for (stable_lines) |line| {
        if (std.mem.startsWith(u8, line, prefix)) return line;
    }
    return null;
}

// Non-vacuity (plan S6 test 1): removing either entry from
// `reference_instantiations`, listing `AppNode(Counter)` BEFORE the codec
// (its members then render under `slcp.AppNode(Counter).codec.*` and the
// `Codec(Counter.Command).encode` prefix is absent), or dropping the
// `e("slcp.AppNode(Counter).propose")` rule makes the matching `expect` red.
// The error-set checks pin that the typed layer's explicit sets survive the
// walk (an `anyerror!` here would freeze nothing).
test "the Stable lines pin AppNode(Counter).create/propose/waitApplied and Codec(Counter.Command).encode/decode" {
    const create = stableLineWithPrefix("slcp.AppNode(Counter).create: fn (") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, create, "CommandExceedsMaxValueBytes") != null);
    try std.testing.expect(std.mem.indexOf(u8, create, "UndecodableExternalizedValue") != null);
    try std.testing.expect(std.mem.indexOf(u8, create, "anyerror") == null);
    const propose = stableLineWithPrefix("slcp.AppNode(Counter).propose: fn (") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, propose, "error{OutOfMemory,ValueEmpty,ValueTooLarge,WatcherCannotPropose}!void") != null);
    const wait = stableLineWithPrefix("slcp.AppNode(Counter).waitApplied: fn (") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, wait, "error{NodeHalted}!?") != null);
    try std.testing.expect(stableLineWithPrefix("slcp.Codec(Counter.Command).encode: fn (") != null);
    try std.testing.expect(stableLineWithPrefix("slcp.Codec(Counter.Command).decode: fn (") != null);
    // The typed node's own fields are engine-thread state, never frozen.
    try std.testing.expect(stableLineWithPrefix("slcp.AppNode(Counter).state: field") == null);
    try std.testing.expect(!tierIsStable("slcp.AppNode(Counter).codec"));
}

// Non-vacuity: deleting `e("slcp.core.qset.canonicalBytes")` from
// `experimental_overrides` while re-adding its old Stable rule makes the
// first expect red; the `anyerror` scan is the reason those overrides exist —
// if a Stable FUNCTION line ever renders `anyerror!`, the freeze is pinning a
// contract nobody can `switch` on, and this test names the line. Callback
// FIELDS are exempt on purpose: `DeliveryHook.on_externalized` is
// `anyerror!void` because the app supplies the error (§8.5), and that is the
// contract.
test "no Stable function line renders an anyerror error set; the anyerror entry points are held out by override" {
    try std.testing.expect(!tierIsStable("slcp.core.qset.canonicalBytes"));
    try std.testing.expect(!tierIsStable("slcp.core.engine.Engine.init"));
    try std.testing.expect(tierIsStable("slcp.core.engine.Engine.pushInput"));
    try std.testing.expect(!tierIsStable("slcp.node.Diagnostic.set"));
    try std.testing.expect(tierIsStable("slcp.node.Diagnostic.message"));
    for (stable_lines) |line| {
        const sep = std.mem.indexOf(u8, line, ": ") orelse continue;
        if (!std.mem.startsWith(u8, line[sep + 2 ..], "fn (")) continue;
        if (std.mem.indexOf(u8, line, " anyerror!") != null) {
            std.debug.print("Stable function line with an anyerror set: {s}\n", .{line});
            return error.TestUnexpectedResult;
        }
    }
}

# Stability

What a consumer of `slcp-zig` may rely on across releases, how that promise is
enforced, and how a symbol gets promoted. This file is the review reference
`zig build check-api` points at when it goes red.

**Status: FROZEN for v0.1.0 (M6 stage S6).** The Stable list below is the
contract the `0.1.x` line keeps. Changing a Stable line is a breaking change
(see "Semver, pre-1.0").

## The two tiers, and how they are enforced

Every `pub` declaration reachable from the `slcp` module is in exactly one of
two tiers. The categorizer is `stable_rules` in `tools/api_snapshot.zig`; it
**defaults every path to Experimental**, so a brand-new symbol *outside* every
`p()` subtree lands in the Experimental file until someone writes a rule for
it. The default does **not** protect additions *inside* a prefix rule: a new
`pub` declaration under a `p()` subtree — a function added to
`slcp.core.quorum`, a field added to `node.Options`, a member added to
`Codec(Counter.Command)` — matches the existing rule and
**is Stable the moment it is committed**, with no new rule and nothing else
flagging it. The only guard is that `check-api` goes red until
`docs/api-snapshot.txt` is regenerated; the tool reports such a line as
`NEW Stable line` and asks whether freezing it is intended. Review every
added Stable line as a promotion (see "Promoting a symbol"), never as a
refresh chore.

| Tier | File | Gate |
|---|---|---|
| **Stable** — the frozen contract | `docs/api-snapshot.txt` | `zig build check-api` (inside `zig build test`) is RED on any drift, on every OS. |
| **Experimental** — may change at any 0.x bump | `docs/api-snapshot-experimental.txt` | Refreshed in place by `check-api`; CI's `test` job runs `-Dstrict-experimental=true` on both ubuntu and macOS, which is RED when the committed file is stale. |

A third, implicit tier is **Internal**: anything not `pub`, plus test-only
code. It never appears in either file.

Three further gates keep the frozen file honest:

- `zig build api-closure` (inside `test`) fails when a Stable **function
  signature** mentions an Experimental type. A frozen entry point that takes
  an unfrozen type is only nominally frozen — the type can change shape under
  it while `check-api` stays green — and if no Stable API can construct the
  type, the entry point is unusable on its own terms.
- A comptime **rule-liveness assertion**: a `stable_rules` or
  `experimental_overrides` entry that matches no declaration is a compile
  error. A rule for a renamed symbol cannot silently document a contract
  nobody can rely on.
- The tool's own unit tests assert that the rendered Stable lines contain
  `slcp.AppNode(Counter).create/propose/waitApplied` and
  `slcp.Codec(Counter.Command).encode/decode`, and that **no Stable function
  line renders an `anyerror!` set** (such a line pins no error contract; see
  "Held out").

Snapshot lines pin more than names: struct **fields and their default
values**, union variants, enumerant values, `pub const` scalar values (the
frozen wire limits, the auto-codec's encoded `size`), and **fully expanded
error sets** (an inferred `!T` is rendered as a sorted `error{...}` list, so
adding or renaming an error a consumer might `switch` on is visible).

### The closure rule for `Options`

**Anything reachable from a Stable `Options` field is Stable.** A consumer
who constructs `slcp.node.Options` (or `AppNode(App).Options`) names every
type those fields carry, so `Quorum`, `node.Diagnostic`, `node.DeliveryHook`
and `Driver` are all in the contract — that is why S6 promoted them.
`api-closure` enforces this mechanically **for function signatures only**
(parameters and return types of Stable functions); field types are covered
by the snapshot lines themselves (a field's type is part of its line, so a
swap to an unfrozen type shows up as a Stable diff) and by this rule as a
review obligation, not by an automated check.

### Generic entry points are pinned by reference instantiation

`slcp.AppNode` and `slcp.Codec` are `fn (comptime type) type`: the walk sees
one opaque line each, and the surface a consumer calls is invisible. The tool
therefore instantiates both over the §0 program's `Counter` (byte-identical
to `examples/counter/src/main.zig`) and walks `slcp.AppNode(Counter)` and
`slcp.Codec(Counter.Command)` as synthetic roots. Their member lines —
`create`, `propose`, `waitApplied`, the `Options` mirror field by field, the
`CreateError` / `ProposeError` / `WaitError` sets, `encode` / `decode` /
`order` / `size` — are the frozen contract for every instantiation, since the
generic body is the same code.

## What is Stable (v0.1.0)

Grouped by area. "prefix" means the type and all of its members/fields are
frozen; "exact" means the one symbol only (its fields stay Experimental).

**The typed layer (`slcp.AppNode`, `slcp.Codec`, design §8.5)**
- `AppNode(Counter)` (exact — its fields are engine-thread state) with
  `create`, `deinit`, `propose`, `waitApplied`, `haltError`, `driver`,
  `raw`; the `State` / `Command` / `WaitOptions` aliases; `Options` and
  `Applied` (prefix); `CreateError`, `ProposeError`, `WaitError`.
- `Codec(Counter.Command)` (prefix): `encode`, `decode`, `order`, `size`,
  `is_custom`, `Value`.
- `slcp.Validity`, `slcp.Driver`, `slcp.DriverError`, `slcp.DeliveryHook`
  (the top-level alias lines; the shapes are frozen under
  `slcp.core.driver.*` / `slcp.node.DeliveryHook`).

**The omakase node (`slcp.node`, re-exported as `slcp.Node` / `slcp.NodeOptions`)**
- `Node` (exact) with `create`, `deinit`, `propose`, `waitExternalized`,
  `stats`, `boundPort`, `allocator`, `explain`; the module-level `explain`.
- `Node.WaitOptions`, `Options`, `Externalized`, `DeliveryHook`,
  `Diagnostic` (prefix — `Diagnostic.set` is held out, see below): the
  option/value structs a consumer builds or reads, including every default
  (`strict_canonical = true`, `max_value_bytes = 4096`, `start_slot = 1`,
  `include_self = true`, …). `DeliveryHook` is a vtable shape, a contract
  like `Driver`'s.
- `CreateError`, `Error`, `ProposeError`: the error taxonomy consumers
  `switch` on.

**Quorum UX (`slcp.core.quorum`, re-exported as `slcp.Quorum` /
`slcp.NodeId` / `slcp.nodeId` / `slcp.parseNodeId`, design §12)**
- The whole module (prefix): `Quorum` with `twoThirdsOf`, `majorityOf`, `of`,
  `ofSets`, `twoThirdsOfSets`, `fromJson`, `writeJson`, `toOwned`,
  `containsNode`, `memberCount`, `JsonError`; `nodeId`, `nodeIdHex`,
  `parseNodeId`, `ParseNodeIdError`, `NodeId`.

**Keys (`slcp.keys`, design §11)**
- `KeyPair` (prefix), `loadOrCreate`, `load`, `createNew`, `ephemeral`, and
  the named error sets `Error`, `DeriveError`, `LoadError`, `MintError`,
  `LoadOrCreateError`, `CreateNewError`. The three entry points carry
  **explicit** sets since S6 (signature-only annotations: each is the union
  of what the body's callees declare, so behaviour is unchanged) — an
  inferred set that silently follows std's file-system vocabulary is not a
  contract.

**Driver vtable (`slcp.core.driver`, design §8.2)**
- `Driver` (prefix: the vtable field shapes and `default()`), `Validity`
  (prefix), `DriverError`. `driver.Checked` and its two message constants
  are Experimental (R16).

**Sans-io engine (`slcp.core.engine`, design §5) — the power-user escape hatch**
- `Engine` (exact) with `deinit`, `pushInput`, `popEffect`, `commitEffect`,
  `stats`. **`Engine.init` is held out** (see below).
- `Input`, `Effect`, `Config`, `InputStatus`, `PhaseKind`, `TimerId`, `Stats`
  (prefix): the input/effect vocabulary, variant by variant.
- `EngineError`, `PushError`, `timeoutMs`.
- `slcp.core.limits` (whole module): the frozen wire limits and `Limits`.

**Quorum set value type (`slcp.core.qset`)**
- `QuorumSetOwned` (prefix: the three fields a consumer constructs — built
  from a `Quorum` via `toOwned`), `Error`, `NodeId`, `max_depth`,
  `max_total_validators`. `validateAndNormalize`, `hashNormalized` and
  `canonicalBytes` are **held out** (below).

**The wasm host ABI (`slcp-abi.*`, design §7)**
- Every `export fn`, every `extern "slcp_driver"` import, and the four
  negotiation constants by value: `abi_version`, `abi_min_version`,
  `abi_max_version`, `feature_flags`. These lines are rendered from the TEXT
  of `src/wasm/slcp_host_abi.zig` (the module pins `std.heap.wasm_allocator`
  and cannot be imported natively), and the runtime half of the liveness
  assertion checks the `slcp-abi` rule against the parsed file.

## Held out: entry points whose error set is `anyerror` today

`experimental_overrides` in the tool names five paths that a reader would
expect in the Stable list and that are deliberately **not**:

- `slcp.core.qset.canonicalBytes`, `hashNormalized`, `validateAndNormalize`
  and `slcp.core.engine.Engine.init`. `canonicalBytes` builds the canonical
  message through capnp-zig's builder, whose `initValidators` resolves to
  `anyerror`; `hashNormalized` wraps it, `validateAndNormalize` orders inner
  sets by their hashes, and `Engine.init` hashes the local qset. None can
  carry an explicit set without a behaviour-changing error mapping, and a
  frozen `anyerror!T` line documents a contract nobody can `switch` on. They
  stay Experimental until they have real sets (a v0.2 item); the rest of
  the `Engine` surface and the `QuorumSetOwned` shape are frozen, and the
  Stable way to obtain a validated set is `Quorum.toOwned` + `Node.create`
  / `AppNode(App).create`, which validate internally and report through
  `CreateError`.
- `slcp.node.Diagnostic.set`: the node-internal writer of the `create()`
  failure message. The buffer and `message()` are the consumer's side.

## What is Experimental (and why)

- `slcp.overlay`, `slcp.timers`, `slcp.store`, `slcp.wire`: the node's
  internals, public only as escape hatches. Their shapes follow the
  implementation.
- `slcp.lint_report`: the CLI's rendering of lint findings. The lint
  **codes** are frozen by `schema/host.capnp` and `vectors/lint.json`, not
  by these Zig names.
- `slcp.core.qset.lint*`, `LintFinding`, `LintCode`, `minBlockingSize`,
  `criticalNodes`, `fromReader`, `exciseNode`, `clone`: the lint surface and
  the reader-taking functions (which expose generated types).
- `slcp.core.driver.Checked` and its `validate_divergence_msg` /
  `combine_divergence_msg` (R16).
- `slcp.app_node` (the module path; `max_encoded_bytes`, `codec`,
  `apply_in_place` on an instantiation): implementation detail of the typed
  layer. The typed layer's contract is the `slcp.AppNode(Counter)` /
  `slcp.Codec(Counter.Command)` lines.
- `slcp.node.Node`'s fields, `slcp.AppNode(Counter)`'s fields: internal
  state.
- `slcp.core.gen.*` (generated by capnpc-zig from `schema/*.capnp`): the
  **wire format** is frozen by the schema and the conformance vectors, not
  by the Zig accessor names.
- `slcp.core.{canonical, crypto, statement, stored, values, local_node, slot,
  nomination, ballot, pending, qset_store, emit, host_codec}`: engine
  internals reachable through the `core` escape hatch.
- `slcp.core.capnpc`: capnp-zig's own module, re-exported. Frozen by
  **upstream's** snapshot gate; not walked here.
- The `slcp` CLI's `--help` text and exit codes: documented in the README
  and checked by docs-smoke, but not part of the library snapshot.

## Platform support

| Leg | Gate |
|---|---|
| Linux x86_64 (ubuntu-latest) | `test` (incl. `check-api -Dstrict-experimental=true`, `api-closure`, `docs-smoke`), `wasm`, `wasm-diff`, `e2e`, `example-smoke`, `fmt-check`, `gen-check`. |
| macOS arm64 (macos-latest) | `test` (incl. `check-api -Dstrict-experimental=true` — strict on both files since CI run 33567835014 showed both OSes render the experimental file identically, R20), `api-closure`, `docs-smoke`, `wasm`, `wasm-diff`, `example-smoke`. |
| wasm32-freestanding | the ABI artifact (`zig build wasm`) + its differential replay. |

Platform-dependent spellings of the same std type are canonicalized by
`platform_type_aliases` in the tool (today: the `sockaddr` family), so the
Stable file is byte-identical across the matrix.

## Promoting a symbol

**Additions under an existing prefix rule need no step 1** — they are already
Stable (see "The two tiers"). `check-api` reports them as `NEW Stable line`;
apply steps 2 and 3 to them exactly as to a new rule, and if the addition was
not meant to be frozen, either move it out of the subtree or hold it out with
an `experimental_overrides` entry, with a comment saying why.

1. Add a rule to `stable_rules` — `p("path")` to freeze a subtree,
   `e("path")` for one symbol — with a comment saying *why* the shape is a
   contract (a struct consumers construct → prefix; a type with internal
   fields → exact + its methods). A generic entry point needs a reference
   instantiation in `reference_instantiations` (order matters there; the
   comment explains).
2. `zig build api-closure`: if the new entry point mentions an Experimental
   type, decide — promote the type, or narrow the entry point. If the
   rendered line says `anyerror!`, give the function an explicit error set
   first; the tool's tests refuse an `anyerror!` Stable function line.
3. `zig build api-snapshot`, review the diff of `docs/api-snapshot.txt` line
   by line, commit both files with the rule.

Demoting or changing a Stable line is a breaking change: it needs a
CHANGELOG entry and, pre-1.0, a minor version bump.

## Semver, pre-1.0

`0.x.y`: `y` bumps never change a Stable line; `x` bumps may, each change
listed in the CHANGELOG with the `check-api` diff as its evidence. The
Experimental file carries no promise at all.

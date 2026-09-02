# slcp-zig

> ## ⚠️ This is a vibe-coded project. Do not use it.
>
> All of the code in this repository was written by an AI coding agent under
> the direction of one person, as an experiment. It has **not** been reviewed
> or validated for anyone else's use. The author has not yet confirmed that it
> holds up in their own deployments.
>
> **Do not depend on this code, run it in production, or trust it with anything
> you care about.** No support is offered. APIs, wire formats, and on-disk
> formats may change without notice. This notice will be updated if and when
> that changes.

## What SLCP is

SLCP (**S**tellar-**L**ike **C**onsensus **P**rotocol) is a clean-room
implementation of SCP-style federated Byzantine agreement, built on Cap'n
Proto. It is **not** wire-compatible with Stellar and does not try to be:
new wire format (Cap'n Proto, not XDR), new preimages, no interop.
stellar-core is the line-level *oracle* for the state machines, not a peer.

The library is two layers in one package:

- **`slcp-core`** — a sans-io, deterministic consensus engine: inputs in,
  effects out, no clock, no sockets, no allocator surprises. It compiles to
  `wasm32-freestanding` and is pinned by cross-implementation conformance
  vectors (`vectors/`), so a second implementation can be checked against
  it byte for byte.
- **`slcp`** — the native "omakase" node on top of the engine: a TCP flood
  overlay, a real-clock timer wheel, crash-safe write-ahead persistence, an
  Ed25519 key file, quorum linting at startup, and two app-facing APIs — the
  typed `slcp.AppNode(App)` (a pure `validate` / `apply` state machine over
  an auto-derived canonical encoding) and the bytes-level `slcp.Node`.

The program every design decision is derived from is a replicated counter on
three hobbyist machines: each proposes "the count becomes N+1", the network
externalizes one value per slot, every machine applies it. If one of the
three is down, the other two carry on (2-of-3); if two are down, the survivor
halts — waiting without a quorum is *correct* FBA behaviour, not a bug.

## Status

- **v0.1.0 is being prepared** — see the notice above. Nothing here is
  supported.
- The engine (`slcp-core`) has run a deterministic 1000-seed simulation
  matrix with Byzantine actors, a fuzz suite, a native-vs-wasm differential
  replay, and a real-socket 4-node end-to-end cluster with kill/restart and
  partition/heal (`zig build e2e`).
- The public surface is split into **Stable** and **Experimental** tiers
  (`docs/stability.md`): the Stable API is frozen by a snapshot
  (`zig build check-api`); everything Experimental may change in any release.
- Pre-1.0 semver: `0.x.y` — `y` bumps never change a Stable line, `x` bumps
  may.
- **No transport authentication in v1.** The overlay is TCP in the clear;
  signatures protect statements, not the port. Run nodes on a private
  network or a WireGuard mesh — read `docs/threat-model.md` before you open a
  listen port.
- **One identity, one process.** A node locks its `.data_dir` while it runs
  (a second start on the same directory is `DataDirBusy`) and the directory
  is bound to its key on first start (`DataDirOtherNode`) — but nothing can
  stop a *copied* key file from signing on two machines. Never copy
  `slcp.key` or `slcp-data/`; mint one key per machine with `slcp key new`.

## Quickstart: the typed counter

`examples/counter/src/main.zig` is the whole program. `zig build test`
compiles this exact file (`counter-intree`) and `zig build docs-smoke`
byte-compares the block below against it, so what you read is what builds:

<!-- snippet: examples/counter/src/main.zig -->
```zig
const std = @import("std");
const slcp = @import("slcp");

// Deployment facts — edit these five lines per machine.
// Each pk_* is the `public key:` line of `slcp key show slcp.key` on that machine.
const pk_a = slcp.nodeId("0101010101010101010101010101010101010101010101010101010101010101");
const pk_b = slcp.nodeId("0202020202020202020202020202020202020202020202020202020202020202");
const pk_c = slcp.nodeId("0303030303030303030303030303030303030303030303030303030303030303");

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

pub fn main(init: std.process.Init) !void {
    const node = try slcp.AppNode(Counter).create(init.gpa, init.io, .{
        .network = "my-counter-app v1", // passphrase → 32-byte networkId; never transmitted
        .key_file = "slcp.key", // ed25519 seed; created on first run (0600)
        .listen_port = 7311,
        .peers = &.{ "b.example.com:7311", "c.example.com:7311" },
        .quorum = slcp.Quorum.twoThirdsOf(&.{ pk_a, pk_b, pk_c }), // self auto-included
        .data_dir = "slcp-data", // created on first run
    });
    defer node.deinit();

    try node.propose(.{ .next = 1 });
    while (try node.waitApplied(.{ .timeout_ms = null })) |ext| {
        std.debug.print("slot {d}: count = {d}\n", .{ ext.slot, ext.state.count });
        try node.propose(.{ .next = ext.state.count + 1 });
    }
}
```
<!-- /snippet -->

What the program relies on:

- **`AppNode(App)` checks the contract at compile time.** `App` declares a
  `State`, a `Command`, a pure `validate(state, cmd) slcp.Validity` and a
  pure `apply(state, cmd) State` (optionally `combine`, `initialState`,
  `initialSlot`, and
  an `encode`/`decode` pair). Every violation is a teaching compile error
  with the wanted signature, not a vtable type mismatch.
- **`slcp.Codec(Command)` derives the wire encoding**: fields in declaration
  order, big-endian, signed ints sign-bit-biased, so *byte order equals
  numeric order* and the default "highest proposal wins" combine is
  semantically right. Floats, pointers, slices, optionals and unions are
  rejected at compile time with the reason and the workaround.
- **It agrees on values, never on operations.** `Command` is "the count
  becomes `next`", not "add one": operations break under combine (two
  proposers both adding one collapse to a single increment) and under journal
  replay (a restarted node re-applies only the journal tail onto
  `initialState()`, so a delta loses every increment before the compaction
  floor); values survive both.
- **`apply` runs on the engine thread**, after the journal append and before
  the next input; `waitApplied` hands the user thread a value copy of the
  state. Keep `apply` fast and pure. The node holds the next slot's votes
  until it has applied the slot before them, so `validate` always judges a
  value exactly one slot ahead of `State`; `.maybe_valid` is for anything
  further ahead (a node still catching up).
- **A restart replays the journal**: `State` is `initialState()` plus the
  replayed tail of `slcp-data/externalized.log`, so the process resumes at
  the count it last saw and its first (stale) proposal is simply judged
  `.invalid` by the others.

The consumer `build.zig` that goes with it (the example is a standalone
package that depends on this repo by path; a real deployment pins a release
tarball instead — see *Using slcp-zig as a dependency*):

<!-- snippet: examples/counter/build.zig -->
```zig
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const slcp_dep = b.dependency("slcp", .{ .target = target, .optimize = optimize });
    const exe = b.addExecutable(.{ .name = "counter", .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "slcp", .module = slcp_dep.module("slcp") }},
    }) });
    b.installArtifact(exe);
    b.installArtifact(slcp_dep.artifact("slcp")); // the lint/key CLI rides along: zig-out/bin/slcp
    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    b.step("run", "Run the counter node").dependOn(&run.step);
}
```
<!-- /snippet -->

`examples/counter/README.md` walks through deploying it on three VPSes in
ten commands (mint a key per machine with `slcp key new`, exchange the three
public keys, edit the five deployment lines, run) and lists the common
stalls. `zig build example-smoke` performs that procedure on one machine —
three consumer builds, three processes over loopback, `SIGKILL` and restart
of one of them — and is the proof that the published program runs verbatim.

## Quickstart: a bytes-level Node

The same counter over `slcp.Node`, for apps that already speak bytes or
share a hand-specified encoding with peers in another language. There is no
typed contract: the value is whatever bytes you propose, the default driver
accepts any non-empty value and picks the lexicographically greatest
candidate, and decoding what the network externalized is your job:

<!-- snippet: examples/bytes_node.zig -->
```zig
//! The bytes-level quickstart (README "Quickstart: a bytes-level Node"):
//! the replicated counter of examples/counter again, but over `slcp.Node`
//! with the default driver and a hand-rolled 8-byte big-endian encoding
//! instead of the typed `AppNode` + auto-codec.
//!
//! Compile-only: `zig build docs-smoke` (part of `zig build test`) builds
//! this file against the in-tree `slcp` module so the README block cannot
//! rot; it is never run here (it would dial example.com).

const std = @import("std");
const slcp = @import("slcp");

// Deployment facts — edit per machine, exactly as in examples/counter.
const pk_a = slcp.nodeId("0101010101010101010101010101010101010101010101010101010101010101");
const pk_b = slcp.nodeId("0202020202020202020202020202020202020202020202020202020202020202");
const pk_c = slcp.nodeId("0303030303030303030303030303030303030303030303030303030303030303");

// The value the network agrees on is "the count becomes N": 8 bytes,
// big-endian, so byte order equals numeric order and the default driver's
// highest-candidate-wins combine picks the largest proposed count.
fn encode(count: u64) [8]u8 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, count, .big);
    return buf;
}

fn decode(value: []const u8) ?u64 {
    if (value.len != 8) return null;
    return std.mem.readInt(u64, value[0..8], .big);
}

pub fn main(init: std.process.Init) !void {
    const node = try slcp.Node.create(init.gpa, init.io, .{
        .network = "my-bytes-app v1", // passphrase → 32-byte networkId; never transmitted
        .key_file = "slcp.key", // ed25519 seed; created on first run (0600)
        .listen_port = 7311,
        .peers = &.{ "b.example.com:7311", "c.example.com:7311" },
        .quorum = slcp.Quorum.of(2, &.{ pk_a, pk_b, pk_c }), // explicit 2-of-3; self auto-included
        .data_dir = "slcp-data", // created on first run
        // .driver = null → the default: any non-empty value is valid, the
        // lexicographically greatest candidate wins (docs/driver-upgrade.md).
    });
    defer node.deinit();

    var count: u64 = 0;
    try node.propose(&encode(count + 1));
    while (node.waitExternalized(.{ .timeout_ms = null })) |ext| {
        defer node.allocator().free(ext.value); // the value is owned by the caller
        // Bytes the network already agreed on must decode: a mismatch is a
        // codec/version bug, not a value to skip.
        count = decode(ext.value) orelse return error.UndecodableExternalizedValue;
        std.debug.print("slot {d}: count = {d}\n", .{ ext.slot, count });
        try node.propose(&encode(count + 1));
    }
}
```
<!-- /snippet -->

This file is **compile-only**: `zig build docs-smoke` builds it against the
in-tree module (so the block above cannot rot) but never runs it. The
loopback proof of the node layer is `zig build e2e` and the counter's
`zig build example-smoke`.

`slcp.Node.create(gpa, io, options)` takes every option below (the typed
`AppNode(App).create` takes the same set minus `.driver` and `.delivery`,
which it supplies itself). Every misconfiguration is refused with a specific
error and a one-paragraph message naming the offending option — pass a
`.diagnostic` to receive it (the pattern is in `docs/driver-upgrade.md`).
`slcp.Node.explain(err)` gives the static text for a `Node.create` error. It
does not accept an `AppNode(App).CreateError`, which adds three members of
its own — `CommandExceedsMaxValueBytes`, `InitialSlotOutsideJournal` and
`UndecodableExternalizedValue`, all always reported through `.diagnostic` — so
narrow first:
`switch (err) { error.CommandExceedsMaxValueBytes, error.InitialSlotOutsideJournal, error.UndecodableExternalizedValue => "app-level", else => |e| slcp.Node.explain(e) }`.

| Option | Default | Meaning |
|---|---|---|
| `.network` | required | Passphrase, hashed into the 32-byte networkId that keeps unrelated networks apart. Never transmitted. Must be non-empty. |
| `.key_file` | `null` | Path of the Ed25519 seed (raw 32 bytes, minted with mode 0600). Loaded, or minted on first run. The usual identity source. A file readable by group or other is refused at `create` with `KeyFileTooPermissive` — the message names the mode and the `chmod 600` that fixes it (ssh-style). |
| `.secret_seed` | `null` | The 32-byte seed itself, instead of `.key_file` (one of the two, never both). |
| `.node_id` | `null` | Optional; when given it must be the public key of the seed (a mismatch is refused). |
| `.quorum` | required | The quorum spec: `slcp.Quorum.twoThirdsOf(&.{ … })` (the blessed default), `majorityOf`, `of(t, &.{ … })`, or nested `ofSets` / `twoThirdsOfSets`. Validated, normalized and linted at `create`. |
| `.include_self` | `true` | Add this node to the top-level validators when it is absent from the whole tree (logged). `false` opts out with a warning. |
| `.allow_unsafe_quorum` | `false` | Start even when the lint reports an ERROR (a sub-majority threshold — a fork machine). The errors are still logged. |
| `.listen_port` | required | TCP port to listen on; `0` binds an ephemeral port (`boundPort()` tells you which). |
| `.peers` | `&.{}` | `"host:port"` strings to dial: IPv4/IPv6 literals (`[v6]:port`) or hostnames. List the *other* nodes only. |
| `.data_dir` | required | Directory for the write-ahead logs and the identity marker; created on first run, then bound to this network and key. |
| `.watcher` | `false` | No key, ephemeral node id, never signs, never proposes — a node that only follows. |
| `.strict_canonical` | `true` | Reject statements whose bytes are not the canonical encoding (protocol §4.2). |
| `.max_value_bytes` | `4096` | Largest value `propose` accepts, in `[1, 65536]`. |
| `.start_slot` | `1` | First slot to nominate for; must be above the journal high-water mark of an existing data dir. |
| `.driver` | `null` | Application driver vtable (`slcp.Driver`); `null` is the default driver described in `docs/driver-upgrade.md`. |
| `.delivery` | `null` | Engine-thread delivery hook (`slcp.DeliveryHook`) instead of the `waitExternalized` queue; what `AppNode` installs for itself. |
| `.diagnostic` | `null` | Where `create` writes its failure message (`*slcp.node.Diagnostic`). |

## The `slcp` CLI

`zig build cli` installs `zig-out/bin/slcp` (a consumer package gets the
same binary through `slcp_dep.artifact("slcp")`, as the example's
`build.zig` shows). Three verbs:

- `slcp key new <file>` — mint an Ed25519 key file (raw 32-byte seed, mode
  0600) and print its public key, which is the node id. Never overwrites.
- `slcp key show <file>` — print the public key of an existing key file.
- `slcp lint-quorum <quorum.json> [--self <hex64>]` — validate and lint a
  quorum spec (`{"threshold":T,"validators":[<hex64>…],"innerSets":[…]}`):
  prints the normalized tree, its hash, the minimum blocking-set size, the
  critical nodes and every finding. Exit 0 clean or warnings, 1 lint errors,
  2 bad input (or a report that could not be written to stdout).
  `docs/quorum-recipes.md` holds three copy-paste specs with the exact output
  each one produces.

`slcp --help` prints the same list (so does `--help` after any verb, and it
never touches a file); `slcp --version` prints the package version.

## Building and testing

The toolchain is pinned in `mise.toml` to one exact Zig nightly,
`0.17.0-dev.1786+75044cb04` (`build.zig.zon` carries only a floor, which
`build.zig` enforces at comptime — an older Zig stops with a one-line
message naming the floor instead of failing somewhere inside `std.Io`).
With
[mise](https://mise.jdx.dev) installed:

```sh
mise install
mise exec -- zig build test
```

| Step | What it runs |
|---|---|
| `zig build test` | The gate: engine unit tests, conformance-vector replay, framing vectors, engine end-to-end, node-layer tests, ABI conformance, sim smoke matrix, fuzz smoke, the wasm differential (when the artifact is present), CLI tests, the AppNode expected-fail compiles, the example's in-tree compile, and the docs gate below. |
| `zig build docs-smoke` | The docs gate (part of `test`): README and `docs/` snippets byte-equal to the files they quote, recipe outputs byte-equal to the real CLI, every documented build step / recipe / CLI verb exists, enum arms and version pins match the source. Prints `[docs-smoke] checks=N failures=M`. |
| `zig build e2e` | The 4-node real-socket cluster: 200 slots, kill/restart (with a gap-jump and a rejoin-voting check), partition/heal, one equivocator, and two nodes restarting together three times. About two and a half minutes. |
| `zig build liveness-tests` | Part of `test`: real engines through the real `AppNode` driver on a deterministic bus, with the node's hold gate in front of each — the double-crash schedules that halt without the gate and converge with it. |
| `zig build example-smoke` | Builds `examples/counter` three times as a consumer package and runs the three counters over loopback with a `SIGKILL` + restart. Not part of `test`. |
| `zig build cli` | Build and install `zig-out/bin/slcp`. |
| `zig build wasm` / `zig build wasm-diff` | Build `slcp_core.wasm` and replay the trace vectors natively and in wasm, comparing effects byte for byte. |
| `zig build sim-matrix` / `zig build byz-matrix` | The full 1000-seed simulation and Byzantine matrices (long). |
| `zig build vectors` | Regenerate `vectors/` (a protocol event — never casually). |
| `zig build check-api` / `zig build api-snapshot` | Compare / regenerate the API snapshots in `docs/`. |

`just test`, `just e2e`, `just docs-smoke`, `just example-smoke` and friends
are the same steps with the flags CI uses; `just gen` regenerates `src/gen/`
from `schema/` with the capnpc-zig plugin and `just gen-check` fails on
drift.

## Using slcp-zig as a dependency

Pin an **immutable release tag** by its tarball URL — never a branch or a
bare commit — and let `zig fetch` record the content hash in your
`build.zig.zon`:

```sh
zig fetch --save=slcp https://github.com/nullstyle/slcp-zig/archive/refs/tags/v0.1.0.tar.gz
```

The hash `zig fetch` records for v0.1.0 is `slcp-0.1.0-p1Kf2mJnEwBKcaQ_OIRLIUCqCheAsWHROjZeUtKJkUfQ`
(computed from the tagged tree with `just release-hash`; the same value is in
`CHANGELOG.md`, and `just verify-release-hash 0.1.0` re-checks it against the
published tarball). If your `build.zig.zon` shows a different hash for that
URL, you did not fetch this release.

Keep the `--save`. On this Zig a bare `zig fetch <archive-url>` (no `--save`)
prints the right hash but stores the archive double-nested in the global
cache, and later builds that need that package fail with `hash mismatch …
N-V-…` until `zig fetch --save` runs again or `$ZIG_GLOBAL_CACHE_DIR/p/<hash>.tar.gz`
is deleted. To only print a hash, use `just pkg-hash <tarball|url>` from a
checkout; it fetches into a throwaway cache.

Then in `build.zig`:

```zig
const slcp_dep = b.dependency("slcp", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("slcp", slcp_dep.module("slcp"));
b.installArtifact(slcp_dep.artifact("slcp")); // optional: the CLI next to your binary
```

`slcp_dep.module("slcp")` is the native node layer (it re-exports the engine
as `slcp.core`); `slcp_dep.module("slcp-core")` is the engine alone, for
wasm or for a host that brings its own I/O. The package ships `build.zig`,
`build.zig.zon`, `src/` and `schema/` only; capnp-zig is its one dependency
and is fetched the same way.

## API stability

The public surface is split into two tiers, and a gate inside `zig build
test` keeps the split honest:

- **Stable** — `docs/api-snapshot.txt`, the frozen contract for the `0.1.x`
  line: the typed `AppNode` / `Codec` layer (pinned through a reference
  instantiation over the counter above), `Node` and its `Options` with every
  default, the `Quorum` spec and node-id helpers, the key-file entry points
  with explicit error sets, the `Driver` vtable, the sans-io engine's
  input/effect vocabulary, and the wasm host ABI. `zig build check-api` is
  red on any drift, on every OS.
- **Experimental** — `docs/api-snapshot-experimental.txt`, everything else
  that is `pub` (overlay, store, timers, wire, lint report, generated code,
  engine internals). It may change at any `0.x` bump; the file is refreshed
  by `check-api` and checked for staleness on both CI test legs (ubuntu and
  macOS run `-Dstrict-experimental=true`).

`zig build api-closure` (also inside `test`) refuses a Stable function whose
signature mentions an Experimental type. The tiers, the held-out entry points
(those whose error set is still `anyerror`), and the promotion procedure are
in [`docs/stability.md`](docs/stability.md).

## Documentation

- `docs/protocol.md` — the normative byte-level definition of SLCP v1 as a
  citation index: domain tags, canonical form, quorum sets, leader election,
  frozen limits, statement sanity, the engine boundary, overlay and
  persistence formats. Literals are copied from the source, and the docs
  gate checks them.
- `docs/threat-model.md` — what signatures protect, what a malicious peer
  can do, why the listen port is an internal service in v1.
- `docs/quorum-recipes.md` — three copy-paste quorum specs with their exact
  lint output, what each lint code means, and two anti-recipes.
- `docs/driver-upgrade.md` — from the default driver to the typed `AppNode`
  to the raw `Driver` vtable, and why evolving a `Command` is a network
  version event.
- `docs/determinism.md` — the rules `validate` / `apply` / `combine` must
  obey, and how violations show up.
- `docs/stability.md` — the Stable / Experimental tiers and how the API
  snapshot enforces them.
- `examples/counter/README.md` — the three-VPS deployment walkthrough.
- `vectors/` — the cross-implementation conformance vectors; when prose and
  vectors disagree, the vectors win.

## Project layout

```
build.zig, build.zig.zon   modules "slcp-core" (wasm-safe) and "slcp" (native); exe "slcp"
Justfile, mise.toml        recipes and the single Zig pin
schema/                    slcp.capnp (signed types, frozen), overlay.capnp, host.capnp
src/
  lib_core.zig             root of slcp-core
  lib.zig                  root of slcp (re-exports core + node)
  engine/                  the sans-io engine: slots, nomination, ballots, qsets, sanity
  node/                    overlay, timers, store, keys, Node, AppNode + Codec, lint report
  cli/                     the slcp CLI
  wasm/                    the frozen WASM host ABI over the core
  gen/                     checked-in capnpc-zig output (just gen; drift-checked in CI)
sim/                       deterministic multi-node simulator with Byzantine actors
tests/                     vector replay, framing vectors, engine e2e, fuzz, ABI, cluster e2e,
                           AppNode expected-fail compiles
tools/                     vector generator, API snapshot, example-smoke, docs-smoke
vectors/                   conformance vectors (the definition; prose is commentary)
examples/                  counter/ (the §0 program as a consumer package), bytes_node.zig
docs/                      the documents listed above + the API snapshots
```

## License

No license is granted yet. See the notice at the top of this file.

# counter — the 40-line replicated counter on three machines

This is the program every part of slcp-zig is derived from (design §0): three
hobbyist VPSes agree, slot by slot, on a counter that goes 1, 2, 3, … Each
machine proposes "the count becomes N+1"; the network externalizes one value
per slot; every machine applies it and proposes the next. If one of the three
machines is down, the other two carry on (2-of-3). If two are down, the
survivor waits — halting without a quorum is *correct* federated-Byzantine-
agreement behaviour, not a bug.

`src/main.zig` is the whole program. It is the same file that the root README
and the design document quote, byte for byte, and `zig build test` in this
repo compiles it (`counter-intree`), so it cannot rot:

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

`init.gpa` / `init.io` are Zig 0.17's process-provided allocator and I/O
implementation (`pub fn main(init: std.process.Init)`); the node owns its
threads, sockets, timers and logs underneath. The **five deployment lines**
are the three `const pk_* = …` lines, `.listen_port` and `.peers` — the only
lines that differ between machines. Everything else ships verbatim.

Two things the program does on purpose:

- **It agrees on values, never on operations.** `Command` is "the count
  becomes `next`", not "add one": under the default highest-value-wins
  combine two "add one" proposals collapse to a single increment, and under
  replay after a crash only the journal tail is re-applied onto
  `initialState()`, so a delta would lose every increment before the
  compaction floor; values survive both.
- **Its first proposal after a restart is stale.** A restarted process
  proposes `{ .next = 1 }` again while the network is at slot 30. The other
  nodes judge it `.invalid` (`validate` sees `next < count + 1`), the
  restarted node replays its journal, catches up and proposes the right value
  next. The loopback smoke below kills a node with `SIGKILL` to prove it.

## Three VPSes in ten commands

You need three Linux boxes (any cloud, any size) that can reach each other on
TCP port 7311 — a private network or a WireGuard mesh is strongly recommended
(see *Security* below). Call them **a**, **b** and **c**. Repeat steps 1–5 on
every box.

1. **Install the pinned Zig with [mise](https://mise.jdx.dev).** slcp-zig
   tracks one exact nightly; anything else may not compile.

   ```sh
   curl https://mise.run | sh
   mise use -g zig@0.17.0-dev.1786+75044cb04
   ```

2. **Create the package** and replace the generated `build.zig` with this one
   (it builds the counter and installs the `slcp` CLI next to it):

   ```sh
   mkdir counter && cd counter && zig init
   ```

   `build.zig`:

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

3. **Pin slcp-zig** by release tag (immutable tarball; `zig fetch` records the
   content hash in `build.zig.zon`):

   ```sh
   zig fetch --save=slcp https://github.com/nullstyle/slcp-zig/archive/refs/tags/v0.1.0.tar.gz
   ```

4. **Paste the program** above into `src/main.zig` (replace what `zig init`
   generated; delete `src/root.zig` and the library lines `zig init` put in
   `build.zig` if you kept any), then build once:

   ```sh
   zig build
   ```

   That fetches capnp-zig (slcp's one dependency), compiles everything and
   installs `zig-out/bin/counter` and `zig-out/bin/slcp`.

5. **Mint this machine's identity** — an Ed25519 seed in a `0600` file that
   the program reads as `.key_file = "slcp.key"`:

   ```sh
   ./zig-out/bin/slcp key new slcp.key
   ```

   It prints one line, `public key: <64 hex chars>`. That hex is this
   machine's node id. (`./zig-out/bin/slcp key show slcp.key` prints it again
   later.) **Never copy `slcp.key` between machines and never commit it.**

6. **Exchange the three public keys** out of band (chat, email — they are
   public). Every machine needs all three.

7. **Edit the five deployment lines** in `src/main.zig` — on every machine:

   - `pk_a`, `pk_b`, `pk_c` := the three public keys, the **same three on
     every machine, in the same order**. The quorum
     `twoThirdsOf(&.{ pk_a, pk_b, pk_c })` is then 2-of-3 and lists yourself,
     which is what you want: every machine lints the same shape at startup.
     (A node absent from its own quorum is auto-added; with three machines
     `twoThirdsOf` over only the *other* two still comes out 2-of-3, but on
     a four-machine network the same mistake — 2-of-3 over the others, plus
     self — is 2-of-4, a sub-majority the node refuses as `UnsafeQuorum`.)
   - `.listen_port` := `7311` on every machine (or any port ≥ 1024 you open
     in the firewall).
   - `.peers` := the **other two** machines as `"host:port"` — hostnames or
     IP literals; IPv6 in brackets (`"[2001:db8::2]:7311"`). On **a** that is
     `&.{ "b.example.com:7311", "c.example.com:7311" }`, on **b** it is a and
     c, and so on. A loopback literal with your own port (`127.0.0.1:7311`)
     is refused at startup (`PeerIsSelf`); your own public hostname is not
     detected — leave yourself out.

   Leave `.network` identical everywhere: the passphrase is hashed into the
   32-byte network id that keeps unrelated slcp networks from talking to each
   other. It is never sent over the wire.

8. **Run** (ReleaseSafe: bounds checks stay on, the binary is fast):

   ```sh
   zig build -Doptimize=ReleaseSafe run
   ```

   Start the three within about a minute of each other; a node that comes up
   first just waits.

9. **Read the log.** Everything goes to stderr. The first lines on **a**:

   ```
   info(slcp_create): node a2c97f11…28ef8b listening on port 7311; dialing 2 peer(s)
   warning(slcp_overlay): overlay: peer 'b.example.com:7311' unreachable (ConnectionRefused); retrying with backoff (1s..60s)
   warning(slcp_overlay): overlay: peer 'c.example.com:7311' unreachable (ConnectionRefused); retrying with backoff (1s..60s)
   info(slcp_node): peer 1 up (1 live connection(s); 2 peer(s) configured)
   info(slcp_node): peer 2 up (2 live connection(s); 2 peer(s) configured)
   slot 1: count = 1
   slot 2: count = 2
   slot 3: count = 3
   ```

   The `unreachable` warnings are normal while the other boxes are still
   starting (the dialer retries with backoff; the warning repeats every 8th
   failure, not every retry). Once two nodes see each other, slots start
   externalizing — with the default timers a slot every fraction of a second
   on a LAN. Later you will also see `peer 3 up (3 live connection(s); …)`
   and `peer 4 up (4 …)`: every pair of nodes keeps one connection in each
   direction (each dials the other), so a full three-node mesh shows up to
   four live connections per node. `peer N down (…)` is logged when one
   drops; the node reconnects by itself.

10. **Kill one and watch.** `Ctrl-C` **c**: **a** and **b** keep counting
    (2-of-3 tolerates one crash). Restart **c** with the same command: its
    log replays the slots it already had from `slcp-data/` (the same
    `slot N: count = N` lines again), then it catches up and rejoins. Kill a
    **second** node and the survivor stops printing — that is the quorum
    protecting you from a fork — and, every 60 s:

    ```
    info(slcp_node): 0 live connection(s) to 2 configured peer(s) — consensus needs a quorum; waiting
    ```

## Common stalls

| Symptom | Cause | Fix |
|---|---|---|
| `slot` lines stop; `… consensus needs a quorum; waiting` every 60 s | Only one of three nodes is up. 2-of-3 halts by design. | Start a second node. |
| `peer 'b.example.com:7311' unreachable (ConnectionRefused)` forever | Firewall, or the other node is not running / listens on another port. | Open TCP 7311 on all three; check `ss -ltnp` on the peer. |
| `unreachable (UnknownHostName)` | DNS. | Use the IP literal in `.peers`, or fix `/etc/hosts`. |
| Startup error `UnsafeQuorum` | The quorum shape is a fork machine (e.g. 1-of-3, or `twoThirdsOf` over the other nodes only — 2-of-4 once self is auto-added on a four-machine network). | List all three keys, yourself included; keep `twoThirdsOf`. Lint a JSON spec any time with `./zig-out/bin/slcp lint-quorum quorum.json` (see `docs/recipes/`). |
| Startup error `QuorumThresholdOutOfRange` | A level's threshold is outside [1, member count]: 0, or larger than the number of members it lists — a `Quorum.of(t, …)` typo. (Auto-adding yourself never changes the threshold, so listing another key does not cure it.) | Use `twoThirdsOf` (it derives the threshold from the list), or pick a threshold between 1 and the member count. |
| Startup error `DataDirOtherNetwork` / `DataDirOtherNode` | `slcp-data/` was written by a different `.network` or a different key. | Use a fresh `.data_dir` — never reuse one across identities. (A data dir binds to network + key on the very first start attempt, even one that fails later.) |
| Startup error `DataDirBusy` | Another live process holds `slcp-data/` (this node was started twice, or a copy of the program runs from the same directory). | Stop the duplicate; one identity runs once. The lock dies with the process, so a restart after a crash needs no cleanup. |
| Startup error `KeyFileBad` / `KeyFileAccessDenied` / `KeyFileDirMissing` | `slcp.key` is not a raw 32-byte seed, is unreadable, or its directory does not exist. | `slcp key new slcp.key` in the directory you run from; check permissions (0600). |
| Startup error `KeyFileTooPermissive` | `slcp.key` is readable by group or other (mode 0644, say): it was copied or restored with a loose mode (`slcp key new` mints it 0600), and like ssh the node refuses a seed other accounts can read. | `chmod 600 slcp.key` and start again (the message spells out the exact command). |
| `externalized gap: slots A..B unrecoverable; resuming delivery at C` | A node was down for more than 16 slots; the others have already compacted those slots and cannot answer for them. | Expected: the node skips the gap and continues from the live frontier. The log is loud on purpose. |
| `warning(slcp_overlay): overlay: rejecting peer, network_id_prefix mismatch` | `.network` differs between machines. | Make `.network` byte-identical everywhere. |
| Two nodes stop agreeing with each other, or one keeps rejecting the other's statements | The same `slcp.key` runs in two processes (a copied directory, or a node started twice). One identity must never run twice: a second process from the same directory reads the same `slcp-data/` too, and on macOS it even binds the same port. | Stop the duplicate. Every machine mints its own key with `slcp key new`. |

Startup errors come with a one-paragraph explanation naming the offending
option: pass a `.diagnostic` to `create` and print `diag.message()` (the
pattern is in `docs/driver-upgrade.md`). `slcp.Node.explain(err)` does not
accept an `AppNode(Counter).CreateError` — it has no arm for the three
`AppNode`-only members, `CommandExceedsMaxValueBytes`,
`InitialSlotOutsideJournal` and `UndecodableExternalizedValue` — so narrow
with a `switch` on those three first if you want the static text (the
top-level README shows the idiom).

## Security

The overlay has **no transport authentication or encryption** in v1: any host
that can reach port 7311 can connect, claim any node id in its Hello, and
burn your per-peer budgets. Envelope signatures keep it from forging
statements (safety), but it can degrade liveness. Run the three nodes on a
private network — a [WireGuard](https://www.wireguard.com/) mesh between the
VPSes is the standard answer — and bind `.peers` to those addresses. See the
threat model in the repo docs.

## The loopback smoke (what CI runs)

`zig build example-smoke` from the repo root does the whole procedure on one
machine: it builds this directory three times as a *consumer* package (a
nested `zig build -Doptimize=ReleaseSafe` per scratch copy under
`.zig-cache/example-smoke/node{0,1,2}`, the repo as a path dependency), mints
three key files, rewrites **exactly the five deployment lines** per copy
(ports 47311–47313, the other two as `127.0.0.1:port`), runs the three
binaries, `SIGKILL`s node0 at `count = 8`, restarts it from its `slcp-data/`,
checks `count == slot` and cross-node agreement on every printed line, and
stops when every node has printed 20 slots:

```
[example-smoke] node0 reached count 8: SIGKILL + restart from the same data_dir
[example-smoke] nodes=3 slots=20 count=20
```

`zig build example-build` runs only the nested builds (does the published
example still build as a consumer?). Both take `-- --slots N --keep
--deadline-s S`; `--keep` leaves the scratch dirs for inspection. Neither is
part of `zig build test` — that only compiles the program (`counter-intree`)
and runs the rewriter's unit tests.

## Files

- `src/main.zig` — the program.
- `build.zig`, `build.zig.zon` — a consumer package that depends on the repo
  by path (`../..`). A real deployment uses the `zig fetch --save=slcp` tag
  pin instead (step 3).
- `slcp.key`, `slcp-data/`, `zig-out/`, `.zig-cache/` are git-ignored here.
  Never commit a key file.

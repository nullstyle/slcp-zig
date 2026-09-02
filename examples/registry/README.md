# registry — signed transactions, transaction sets and a header chain on slcp

The second example, and the first step of the examples roadmap (E1): a
**replicated name registry** with the shape of stellar-core and none of the
money. Principals hold Ed25519 keys and sign transactions that carry a
per-account sequence number; each slot's value is a **transaction set**; a
node applies the agreed set to a bounded, sorted state and advances a ledger
**header hash chain**; the state is snapshotted after every slot; a
localhost **RPC** takes transactions from a small CLI. Three nodes, three
processes, one binary.

Where `examples/counter` is the 40-line program, this one is four files:

| File | What |
|---|---|
| `src/registry.zig` | the pure state machine — transactions, sets, `validate` / `combine` / `apply`, the header chain, the snapshot format; standard library only, no I/O |
| `src/app.zig` | the `slcp.AppNode` adapter (custom codec, in-place `apply`, `initialState` + `initialSlot` from a snapshot) and a live 2-of-2 test |
| `src/rpc.zig` | the RPC: a line protocol on 127.0.0.1 (`head`, `get`, `account`, `submit`) and its client |
| `src/main.zig` | the process: `registry node …` and the client verbs `submit`, `get`, `account`, `head` |

Everything the node agrees on is deterministic and bounded; the limits are
printed at startup:

| Limit | Value |
|---|---|
| transactions per set | 32 (a full set is 7521 bytes; the node raises `max_value_bytes` to 8192) |
| accounts / names | 64 / 128 (bounded plain-data state, about 20 KB) |
| name / value | `[a-z0-9-]`, 1..32 bytes / any bytes, 0..64 |
| pending queue | 256 |
| cadence | busy slots ≥ 1 s apart (`--min-slot-ms`); idle heartbeat every 3 s (`--heartbeat-ms`) |

## How it works

**Transactions.** 235 bytes, one fixed layout: `source` (32-byte public key),
`seq` (u64, 1 to 2⁶⁴−2), `op` (claim · set · transfer · release), a name, a value,
a `to` key, and a 64-byte signature over
`SHA-256("REGISTRY-TX-V1" ‖ network_id ‖ the 171 unsigned bytes)` where
`network_id = SHA-256("REGISTRY-NET-V1" ‖ the --network passphrase)`. That
digest is the transaction id. A transaction signed for one passphrase is
invalid on every other network. Every field has exactly one canonical
spelling (zero padding, per-op rules), so a set decodes to null or to the
one transaction its bytes mean.

**Transaction sets.** The value the network agrees on: a count byte and up
to 32 transactions, strictly ascending by (source, seq). The empty set is
the single byte `00`, a legal value, so idle slots close. This is a custom
codec (`encode` / `decode` on the app) because the auto-codec cannot encode
variable-length data.

**`validate`.** Every signature verifies; per source the sequence numbers
form a contiguous run starting at the account's `seq + 1` (a run that starts
*ahead* is `.maybe_valid` — this node may be behind — never `.invalid`; a
replay or a gap inside a run is `.invalid`); a new source when the account
table is full is `.invalid`.

**`combine`.** The union of every candidate set, deduplicated by (source,
seq), sorted, filtered to what applies cleanly on this state, capped at 32.
Two nodes proposing different transactions for one slot get both applied.

**`apply`.** In set order: the account's `seq` becomes the transaction's,
**even when the operation fails** (stellar-core's rule; it is what keeps
`validate` and `apply` in agreement), then the operation runs — `claim` a
free name, `set` its value or `transfer` it or `release` it as its owner —
and its result (`ok`, `name_taken`, `not_owner`, `no_such_name`,
`registry_full`) is recorded. Then the header advances:
`slot += 1`, `prev_hash = hash`, `txset_hash = SHA-256(set)`,
`state_root = SHA-256(the sorted accounts and names)`,
`hash = SHA-256("REGISTRY-HDR-V1" ‖ slot ‖ prev_hash ‖ txset_hash ‖ state_root)`.
Three nodes that applied the same history print the same `head`.

**Snapshots and restart.** After every applied slot the node writes
`<data-dir>/snapshot` atomically (write, fsync, rename): the header, the
state, a checksum. On start it reads the snapshot into `initialState()`,
names its slot in `initialSlot()`, and the library replays only the journal
slots above it — the §8.5 delta-app recipe. A node that comes back within
the library's 16-slot answering window is handed the slots it missed by its
peers and catches up. One that stayed away longer is told
`externalized gap: slots A..B unrecoverable` by the library and handed a
later slot: `apply` refuses a set that does not fit its state (the header
does not advance), the node loop sees the slot mismatch, prints it and
exits with code 3 rather than run on a wrong state. Away for more than
about 80 slots (the library's 64-slot hold window on top of the 16) and the
node is not even told: the statements it needs are dropped silently, so it
sits at its old slot — the node loop prints a warning every 60 s when no
slot has applied. Both are the first thing the next step (E2, history
archives) closes. A node stopped before its first applied slot restarts
from genesis and is fine; a data dir whose journal was compacted but whose
snapshot is missing is refused (the missing slots cannot be rebuilt).

**Cadence.** After each applied slot a node proposes exactly once for the
next: right away when it has pending transactions (after `--min-slot-ms`),
otherwise at the idle heartbeat. There is no transaction flooding in E1, so
a transaction submitted to one node lands in the first slot whose round-1
leader is that node — about three heartbeats on average, sometimes ten.
E2's flooding removes the wait; until then, lower `--heartbeat-ms` if you
want latency and raise it if you want a longer answering window (it is 16
heartbeats of idle time).

**RPC.** One request line, one response line, on 127.0.0.1 only:

```
head                → head slot=<n> hash=<hex64> accounts=<n> names=<n> pending=<n> network=<hex64>
get <name>          → entry name=<name> owner=<hex64> value=<hex>   |   none
account <hex64>     → account key=<hex64> seq=<n> next=<n>
submit <hex470>     → ok txid=<hex64>   |   err <code> <text>
```

`submit` decodes, verifies the signature, requires `seq == next`, refuses
duplicates and a full queue (`bad_request`, `bad_tx`, `bad_sig`, `bad_seq`,
`queue_full`, `duplicate`). The CLI's `submit` verb does the whole dance:
it asks the node for `head` (the network id) and `account` (the next seq),
builds and signs the transaction with your key file, and sends it.

## Three machines

Same shape as `examples/counter/README.md`: three Linux boxes **a**, **b**,
**c** that reach each other on TCP 7411 (a private network or a WireGuard
mesh — see *Security*). On every box:

1. **Install the pinned Zig with [mise](https://mise.jdx.dev):**

   ```sh
   curl https://mise.run | sh
   mise use -g zig@0.17.0-dev.1786+75044cb04
   ```

2. **Get the example.** Clone the repository and build in place (the example
   depends on the repository by path, `../..`):

   ```sh
   git clone https://github.com/nullstyle/slcp-zig && cd slcp-zig/examples/registry
   zig build -Doptimize=ReleaseSafe
   ```

   Or copy `examples/registry/` anywhere and pin the release instead of the
   path — delete the `.slcp = .{ .path = "../.." }` line from
   `build.zig.zon` and run
   `zig fetch --save=slcp https://github.com/nullstyle/slcp-zig/archive/refs/tags/v0.1.0.tar.gz`
   (the example uses only the Stable API of that release). Either way you
   get `zig-out/bin/registry` and `zig-out/bin/slcp`.

3. **Mint this machine's node key** (an Ed25519 seed, mode 0600; never copy
   it between machines, never commit it):

   ```sh
   ./zig-out/bin/slcp key new node.key
   ```

   It prints `public key: <64 hex chars>`. Exchange the three public keys
   out of band.

4. **Write the quorum spec** — the same file on every machine. Start from
   `docs/recipes/three-friends-2of3.json` and put the three node keys in
   (`slcp lint-quorum quorum.json` tells you what you wrote):

   ```json
   {
     "threshold": 2,
     "validators": [ "<pk of a>", "<pk of b>", "<pk of c>" ],
     "innerSets": []
   }
   ```

5. **Run the node** (on **a**; on **b** and **c** the two `--peer`s are the
   other two):

   ```sh
   ./zig-out/bin/registry node --network "my registry v1" --key node.key --data-dir data \
       --quorum quorum.json --listen 7411 --rpc 7412 \
       --peer b.example.com:7411 --peer c.example.com:7411
   ```

   `--network` must be identical everywhere (it is hashed into two network
   ids, the library's and the registry's; neither is ever sent). The first
   lines:

   ```
   registry: node d4f7315f…985e58 listening on port 7411; 2 peer(s); data in data; starting from genesis at slot 0
   registry: limits: 32 txs per set, 64 accounts, 128 names, 256 pending; busy slots every >= 1000 ms, idle heartbeat every 3000 ms
   registry: rpc listening on 127.0.0.1:7412
   slot 1: txs=0 ok=0 head=bc04bd8fd3648822
   slot 2: txs=0 ok=0 head=eb61ccf8f5344ee1
   ```

   The `peer … unreachable` warnings while the other boxes start, the
   `peer N up` lines, and the "consensus needs a quorum; waiting" line when
   two of three are down are the library's, explained in the counter's
   README. `head=` is the first 16 hex characters of the header hash: the
   same on every machine at the same slot, or something is wrong.

6. **Use it.** Anyone with a key file and access to a node's RPC port is a
   client:

   ```sh
   ./zig-out/bin/slcp key new alice.key
   ./zig-out/bin/registry submit --key alice.key --rpc 127.0.0.1:7412 claim alice
   ./zig-out/bin/registry get --rpc 127.0.0.1:7412 alice
   ```

   ```
   ok txid=14cf0fae34470ba07d874c40664849f208e306736fc93777e0f5640e91d8d1ad
   entry name=alice owner=ec18c4a9102f6f4c6b4ede60df68bc8193f3410752cbbf5cc8980e5a02b373ba value=
   ```

   `ok` means *queued*; the entry appears a few slots later, on every node.
   Then `set alice hello` (values are shown as hex: `value=68656c6c6f`),
   `transfer alice <bob's public key>`, `release alice`. A second `claim
   alice` from another key is accepted at submit, applied with the result
   `name_taken`, and consumes that account's sequence number — exactly like
   a failed Stellar transaction. `registry head` shows the slot, the header
   hash and the pending count; `registry account <hex64>` the applied `seq`
   and the `next` one to use.

7. **Kill one and restart it.** Ctrl-C (or `kill -9`) **c**; **a** and **b**
   carry on (2-of-3). Start **c** again with the same command:

   ```
   registry: node 84a5a57d…dcfff2 listening on port 7411; 2 peer(s); data in data; starting from the snapshot at slot 19
   slot 20: txs=1 ok=1 head=e4bfe24da8622d9e
   slot 21: txs=0 ok=0 head=abb082fa9a8e87bd
   …
   slot 24: txs=0 ok=0 head=8a5b103ab7569f8d
   ```

   It came back from its snapshot, was handed the slots it missed by its
   peers, and prints the same heads as the others. It also votes again: a
   transaction submitted to the restarted node lands like any other. Stay
   away longer than 16 slots (48 s of idle heartbeats, or 16 busy slots)
   and it exits with code 3 instead — see *Limits*.

## Limits — what E1 does not do

These are the gaps this step records for E2 (examples-roadmap.md §2.1);
each one is deliberate:

- **No transaction flooding.** A transaction is known only to the node it
  was submitted to until that node leads a nomination round. Latency is a
  few heartbeats; a node that is down takes its queue with it (resubmit).
- **No history.** A node that misses more than the answering window (16
  slots) cannot rebuild its state: it exits with code 3 when the library
  hands it a slot past the gap, or, more than ~80 slots behind, it waits
  forever and warns every 60 s (the library drops far-ahead statements
  silently). A `<data-dir>` whose journal was compacted but whose
  `snapshot` is missing is refused. Start it over with a fresh
  `--data-dir` only when the whole network starts over.
- **Bounded state.** 64 accounts, 128 names, 32 transactions per slot. The
  typed layer copies the state after every applied slot and `initialState()`
  cannot read a file, which is why the state is plain data and the snapshot
  is loaded through a global before the node starts.
- **No close time, no upgrades, no quotas, no watcher nodes, no HTTP.**
  E2 and E3.

## Security

Everything in the counter's *Security* section applies: the overlay has no
transport authentication or encryption in v1 — run the nodes on a private
network. In addition: the RPC binds 127.0.0.1 only and is unauthenticated,
so **every local user of the machine can submit**. They cannot forge a
transaction (only a holder of a key signs for its account) but they can
fill the 256-entry queue, and they can occupy the RPC: it serves at most 64
connections at a time (the 65th is closed at accept) and drops a connection
that stays silent for 30 s, so the worst case is a stalled RPC, never a
stalled node. A second node on a busy RPC port is refused at start. Keep
client key files 0600; the registry never reads them — only
`registry submit` does, on the client's machine.

## The loopback smoke (what CI runs)

`zig build registry-smoke` from the repository root does the whole
procedure on one machine: one nested consumer build of this directory
(ReleaseSafe), three node keys and two client keys, a 2-of-3 `quorum.json`,
three nodes on ports 47411–47413 (RPC 47421–47423), then the acceptance
script — alice claims `alice`, bob's conflicting claim is applied as
`name_taken`, `set`, a second name, `transfer`, identical heads on all three
nodes, node2 `SIGKILL`ed and restarted from its snapshot and journal,
catching up to the same head, and a `release` submitted to the restarted
node applied everywhere. Evidence line on stdout:

```
[registry-smoke] nodes=3 txs=7 slots=N head=<hex16>
```

`zig build registry-build` runs only the nested build; `-- --keep` leaves
the scratch under `.zig-cache/registry-smoke/`. Neither is part of
`zig build test` — that runs `registry-tests` (the pure module, the RPC, and
a live 2-of-2 pair with a restart from a snapshot, about two seconds) and
compiles the program (`registry-intree`). Inside this directory,
`zig build test` runs the same tests as a consumer.

## Files

- `src/registry.zig`, `src/app.zig`, `src/rpc.zig`, `src/main.zig` — above.
- `build.zig`, `build.zig.zon` — a consumer package that depends on the
  repository by path (`../..`); pin a release tag instead for a deployment.
- `node.key`, `*.key`, `data/`, `zig-out/`, `.zig-cache/` are git-ignored.
  Never commit a key file.

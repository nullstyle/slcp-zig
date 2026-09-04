# registry — signed transactions, transaction sets and a header chain on slcp

The second example, now covering E1, E2a transaction flooding, and E2b
authenticated checkpoint catch-up from the examples roadmap: a **replicated
name registry** with the shape of
stellar-core and none of the money. Principals hold Ed25519 keys and sign
transactions that carry a per-account sequence number; accepted transactions
flood between validators before nomination; each slot's value is a
**transaction set**; a node applies the agreed set to a bounded, sorted state
and advances a ledger **header hash chain**; the state is snapshotted after
every slot; a localhost **RPC** takes transactions from a small CLI. Three
nodes, three processes, one binary.

Where `examples/counter` is the 40-line program, this one is five files:

| File | What |
|---|---|
| `src/registry.zig` | the pure state machine — transactions, sets, `validate` / `combine` / `apply`, the header chain, the snapshot format; standard library only, no I/O |
| `src/app.zig` | the `slcp.AppNode` adapter (custom codec, in-place `apply`, and `initialState` / `initialSlot` / `initialCommand` from boot state) and a live 2-of-2 test |
| `src/rpc.zig` | the shared RPC/gossip transaction-admission boundary, a line protocol on 127.0.0.1 (`head`, `get`, `account`, `submit`), and its client |
| `src/history.zig` | the quorum-authenticated checkpoint archive, validator vote format, trusted signing fence, and hostile-storage tests |
| `src/main.zig` | the process, checkpoint boot/publication, bounded gossip drain/reflood loop, and the client verbs `submit`, `get`, `account`, `head` |

Everything the node agrees on is deterministic and bounded. Domain and cadence
limits are printed at startup; the transport/gossip bounds are fixed in code:

| Limit | Value |
|---|---|
| transactions per set | 32 (a full set is 7521 bytes; the node raises `max_value_bytes` to 8192) |
| accounts / names | 64 / 128 (bounded plain-data state, about 20 KB) |
| name / value | `[a-z0-9-]`, 1..32 bytes / any bytes, 0..64 |
| pending queue | 256 |
| application-message payload / inbox | 64 KiB / 1024 messages or 16 MiB (lazy opt-in, best effort) |
| outbound application writer per peer | 256 messages or 1 MiB; 256 items / 4 MiB of the unchanged aggregate stay reserved for ordinary traffic |
| gossip work | immediate flood on acceptance, 1 s reflood while pending, at most 64 receives per main-loop tick |
| cadence | busy slots ≥ 1 s apart (`--min-slot-ms`); idle heartbeat every 3 s (`--heartbeat-ms`) |
| history cadence | every 8 slots by default; configurable from 1 through the 16-slot live answering window |

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

**Snapshots, checkpoints, and restart.** After every applied slot the node
writes `<data-dir>/snapshot` with a random temporary file → write → `fsync`
and successful `F_FULLFSYNC` on macOS → atomic replace → data-directory
`fsync`. At every non-genesis slot, Snapshot V2 contains the header, state,
exact transaction set agreed at that slot, and checksum; the set is outside
`state_root` but bound to `txset_hash`. Slot 0 accepts only canonical empty
genesis with an all-zero header and no set. On an ordinary restart it reads
that snapshot into
`initialState()`, names its slot in `initialSlot()`, exposes the set through
`initialCommand()`, and the library replays only newer journal slots. A node
that returns within the library's 16-slot answering window catches up from
peers in the usual way. Non-genesis Snapshot V1 remains readable only for local
journal-backed restart; external history accepts V2 only, because the imported
state must carry its own exact final transaction set. Slot 0 is never a history
checkpoint.

`--history-dir <dir>` adds long-outage recovery without trusting that shared
directory. At each `--checkpoint-every N` boundary (default 8, allowed 1..16)
a validator signs
`SHA-256("REGISTRY-CKPT-V1" || network_id || slot || head_hash || snapshot_hash)`.
Snapshots, immutable votes, and mutable per-validator latest pointers live in
the network-scoped shared archive. On import, malformed or torn objects are
ignored and unique valid signers must satisfy this process's current local
quorum set. Quorum policy is never read from the archive. Each validator also
keeps an independent durable signing fence under
`<data-dir>/history-signing`; it refuses same-slot equivocation or a lower
slot even if the shared archive asks for one.

Post-start checkpoint publication runs on a dedicated worker with one
newest-wins pending State. The cadence loop first makes the ordinary snapshot
durable, then only enqueues the due checkpoint. Slow or failing archive I/O
therefore does not block consensus, RPC, or gossip; availability failures retry
after a short delay or are superseded by a newer checkpoint. A signing-fence,
certified-fork, state-integrity, or trusted-fence I/O failure is safety-critical
and stops the node. Post-start fatal paths drain RPC handlers, stop the node,
then hard-exit without voluntarily joining the publisher. This removes the
userspace shutdown wait after consensus has stopped, though the OS may still
delay final reaping of a thread stuck inside a kernel syscall.

Startup searches at or above `max(local snapshot slot, --history-min-slot)`.
A newer certified checkpoint through H replaces the local snapshot only after
`AppNode.create` accepts the checked handoff `.start_slot = H + 1` and seeds
nomination with the exact set externalized at H. A newer local journal value
supersedes that seed; a same-slot mismatch fails startup. Live peers then
supply H+1 through the current frontier, so H must still be within their
16-slot answering window; keeping the checkpoint cadence at most 16 provides
that bridge while a quorum is publishing normally. The explicit minimum is
the anti-rollback control: signatures prove who attested state, not that an
untrusted archive showed you its newest state.

Candidate discovery reads the derived latest pointer for each validator in
the local quorum instead of scanning the archive. Startup accepts at most 16
distinct valid pointer assertions; a larger set is
`TooManyCheckpointCandidates` and fails closed rather than allowing unbounded
cross-reads or selecting from an incomplete fork set. This is an availability
bound, not a claim that shared storage will show every signed checkpoint.

A certificate over a higher isolated snapshot is a quorum attestation, not an
ancestry proof back to your lower local head. Import therefore makes the same
assumption as live consensus: the configured quorum will not certify a
conflicting registry history. Two simultaneously discoverable certified
assertions at one slot fail closed. Separately, if the selected authenticated
checkpoint is at the eligible local snapshot's slot, their heads must agree.
Those checks are not an arbitrary or continuous runtime fork detector: a
withheld object or a validator's newer latest pointer can hide an older
alternative. Complete header/transaction-set history is needed to prove every
intervening link.

A process that encounters an unrecoverable gap while running still exits with
code 3 rather than apply a discontinuous transaction set. Restart it after a
recent certificate exists. This archive stores checkpoint state, not every
intermediate transaction set or header, so it is not standalone ledger replay
and cannot recover without a live peer holding the short post-checkpoint tail.
A node stopped before its first slot still restarts from genesis; a compacted
journal without either a usable local snapshot or configured certified
history is refused.

**Cadence and flooding.** After each applied slot a node proposes exactly once
for the next: right away when it has pending transactions (after
`--min-slot-ms`), otherwise at the idle heartbeat. A transaction accepted from
RPC or gossip is immediately published to every capable connected peer. Each
peer runs the same canonical/signature/sequence/cap admission before adding it
to its pending queue and explicitly publishing it onward; rejected bytes are
never amplified. Pending transactions are reflooded every second until pruned
after application or supersession. The transport is best-effort and
non-durable, but once the transaction has reached a live validator it can be
proposed in the next eligible slot even if the submission node then dies.

**RPC.** One request line, one response line, on 127.0.0.1 only:

```
head                → head slot=<n> hash=<hex64> accounts=<n> names=<n> pending=<n> network=<hex64>
get <name>          → entry name=<name> owner=<hex64> value=<hex>   |   none
account <hex64>     → account key=<hex64> seq=<n> next=<n>
submit <hex470>     → ok txid=<hex64>   |   err <code> <text>
```

`submit` decodes the exact canonical 235-byte transaction, verifies its
network-bound signature, requires `seq == next`, and refuses duplicates or a
full queue (`bad_request`, `bad_tx`, `bad_sig`, `bad_seq`, `queue_full`,
`duplicate`). Gossip input uses that same admission function. Acceptance adds
the transaction locally and immediately floods the canonical bytes after the
shared-state lock is released. The CLI's `submit` verb does the whole dance:
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

   After v0.2.0 is tagged, you can instead copy `examples/registry/` anywhere
   and pin that release: delete the `.slcp = .{ .path = "../.." }` line from
   `build.zig.zon` and run
   `zig fetch --save=slcp https://github.com/nullstyle/slcp-zig/archive/refs/tags/v0.2.0.tar.gz`
   (the example uses only the unchanged Stable API). Either way you
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

   To enable E2b, provision a durable shared or correctly mirrored filesystem
   whose contents are visible to all three validators and append:

   ```sh
   --history-dir /mnt/registry-history --checkpoint-every 8
   ```

   The path need not have the same spelling on every machine, but it must
   expose the same archive. The immediate parents of both `--history-dir` and
   `--data-dir` must already be real directories on durable storage. The
   process creates their final components and synchronizes each parent entry,
   then creates and synchronizes `<data-dir>/history-signing`. Keep the shared
   archive outside the entire `--data-dir`: startup compares pinned filesystem
   identities and rejects equal paths, aliases, and either ancestor direction
   before creating an archive namespace. The archive also may not contain the
   validator key's pinned parent; the key must be a regular file, not a
   symlink. Sharing a broader parent with a sibling archive is fine. History
   mode also requires this machine's validator key to appear explicitly in
   `quorum.json` (the example above already does). It is supported only on
   Linux and macOS, where the implementation provides the required directory
   durability barriers.

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

   `ok` means *queued and flooded*; under a connected healthy quorum the
   entry appears in the next eligible slot on every node. Then `set alice
   hello` (values are shown as hex: `value=68656c6c6f`),
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
   transaction submitted to the restarted node floods to the other validators
   and lands in the next eligible slot like any other. Without
   `--history-dir`, staying away longer than 16 slots still leaves it unable
   to rejoin. With history enabled, restart it with the same archive; optionally
   add `--history-min-slot <known-good-slot>` to refuse any older view. It
   authenticates the newest eligible checkpoint, restores its exact final
   transaction set as nomination context, starts at its successor, and catches
   the remaining short tail from a live peer.

## Limits — what E2 still does not do

Transaction flooding and authenticated checkpoint catch-up close two gaps
recorded by E1. These remaining limits are deliberate:

- **Flooding is best-effort, not history.** Pending queues and the generic
  Node inbox are memory-only. Immediate publication plus a 1 s reflood heals
  ordinary loss and reconnects; once another validator admits a transaction,
  loss of the submission node does not lose it. If the source dies before any
  peer admits the bytes, or every holder restarts before application, resubmit.
- **Checkpoints are not replayable history.** The archive contains certified
  snapshots, not all headers and transaction sets. Recovery still needs a
  checkpoint no more than 15 slots behind a live peer and that peer must help
  agree the short tail. An untrusted archive can hide or withhold valid data;
  `--history-min-slot` prevents accepting an older view but cannot make a
  missing checkpoint appear. Per-validator latest pointers may also hide an
  older certificate after validators advance at different rates, and more
  than 16 distinct valid startup candidates is a fail-closed availability
  error. Without history, the original 16-slot limit remains. A compacted
  journal without a usable snapshot/checkpoint is refused.
- **Bounded state.** 64 accounts, 128 names, 32 transactions per slot. The
  typed layer copies the state after every applied slot and `initialState()`
  cannot read a file, which is why the state is plain data and the snapshot
  is loaded through a global before the node starts.
- **No close time, no upgrades, no quotas, no watcher nodes, no HTTP.**
  The remainder of E2 and E3.

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

Application-message frames are also unauthenticated opaque bytes. The generic
Node drops an app frame when its sender did not negotiate feature bit 0, caps
each payload at 64 KiB, retains none until the registry opts in, bounds the
active inbox to 1,024 items / 16 MiB, and never auto-relays receipt. Outbound
app frames may use at most 256 writer items / 1 MiB per peer and cannot consume
the 256-item / 4 MiB ordinary reserve; app pressure drops that frame without
disconnecting the peer. The registry drains at most 64 messages per main-loop
tick and routes each through the same exact canonical decoding,
network-signature verification, next-seq, duplicate, and 256-pending checks as
RPC. Only accepted canonical bytes are explicitly flooded and reflooded. A
reachable attacker can still consume the transport budgets and force bounded
parse/signature work, which is another reason the listen port remains an
internal service.

**Checkpoint storage has two different trust domains.** Treat the shared
`--history-dir` as fully hostile: an archive writer may delete, replay,
truncate, rename, or replace objects; create symlinks, directories, FIFOs, or
other special files at expected names; withhold newer attestations; and arrange
many valid old latest pointers. The reader pins no-follow directory handles,
opens generated basenames nonblocking, accepts regular files only, validates
every path/content/signature/network/head/snapshot relationship, uses only the
local quorum policy, and caps startup candidates at 16. Those checks protect
state integrity; archive manipulation can still deny recovery or publication.

The signing fence at `<data-dir>/history-signing` is trusted validator safety
state, like the validator key. Keep it local, writable only by that validator,
preserve it across restarts or host migration, and never share, mirror, delete,
or restore it independently to an older version while retaining the key. The
implementation rejects filesystem-identity or ancestor overlap between the
archive and the whole private data root. It also rejects an archive that
contains the validator key's pinned parent, requires a regular non-symlink key,
and binds Node's later key-file read to the identity already used for history
signing. It does not create your filesystem access policy. Before publishing a
shared vote it durably records and synchronizes both the immutable per-slot
fence and the high-water fence, including their containing directories; a
retry repeats those directory barriers. Failure of `fsync`, the checked macOS
`F_FULLFSYNC`, or a directory barrier in that trusted phase is explicitly
fail-stop; the same low-level error in the shared archive remains an
availability failure for retry or supersession. Ordinary snapshot failure also
stops the registry. Post-start fatal paths drain RPC handlers, stop the
consensus node, and then hard-exit without joining the publisher; ordinary
cleanup still stops the node before any worker join. The OS can still delay
final reaping of a kernel-stuck filesystem thread.
In history mode, the immediate parent of `--data-dir` must already exist on
durable storage; the process creates or opens the final data-dir component and
synchronizes that entry before opening the signing tree. History mode refuses
to start on platforms other than Linux and macOS, where this crash-durability
contract is implemented.

## The loopback smoke (what CI runs)

`zig build registry-smoke` from the repository root does the whole procedure
on one machine: one nested consumer build of this directory (ReleaseSafe),
three node keys and two client keys, a 2-of-3 `quorum.json`, one shared archive,
and three nodes on ports 47411–47413 (RPC 47421–47423). The overlay is a
deliberate line, node2→node1→node0. For the E2a witness, node2's nomination
cadence is disabled, a transaction is submitted only there, and the harness
requires `pending=1` at both one-hop node1 and two-hop node0 while all heads
remain at S. It then `SIGKILL`s node2 and requires both survivors' own slot
lines to report `slot S+1: txs=1`, proving propagation before consensus and
survival of the source's death. Node2 subsequently restarts and participates
in the remaining ordinary registry operations.

For E2b, the harness records a durable outage origin, stops node2 again, and
requires node0 and node1 to externalize at least 201 new transaction-free
slots. It then kills node0, lets buffered work drain, freezes node1's exact
head H, and recomputes the newest checkpoint both survivors signed no more
than 15 slots behind H (at least one must have observed it certified). Node2
restarts with that Snapshot V2 as its minimum, finite nomination cadence, and
node1 as its sole live peer. It must explicitly report a history-checkpoint
boot, restore the exact checkpoint transaction set as nomination context,
catch node1's exact H/hash through a tail shorter than 16 slots, and then be a
necessary voter with node1 for transaction 8 in exactly H+1. Finally node0
rejoins and all three must agree on the transaction state and head. Evidence
line on stdout:

```
[registry-smoke] nodes=3 txs=8 slots=N head=<hex16>
```

`zig build registry-build` runs only the nested build; `-- --keep` leaves
the scratch under `.zig-cache/registry-smoke/`. Neither is part of
`zig build test` — that runs `registry-tests` (the pure module, the RPC, and
a live 2-of-2 pair with restart) and compiles the program (`registry-intree`).
Inside this directory, `zig build test` runs the same tests as a consumer.
The current 66-test root also covers history and boot selection, snapshot and
directory durability, publisher failure policy, quorum evaluation, tampering,
rollback, torn objects, hostile namespaces, special files, candidate bounds,
and fork discovery.

## Files

- `src/registry.zig`, `src/app.zig`, `src/rpc.zig`, `src/history.zig`,
  `src/main.zig` — above.
- `build.zig`, `build.zig.zon` — a consumer package that depends on the
  repository by path (`../..`); pin a release tag instead for a deployment.
- `node.key`, `*.key`, `data/`, `zig-out/`, `.zig-cache/` are git-ignored.
  Never commit a key file.

# registry — signed transactions, timed ledger values and a header chain on slcp

The second example covers E1, E2a transaction flooding, E2b authenticated
checkpoint catch-up, E2c deterministic close time, and E2d replayable history
from the examples roadmap: a **replicated name registry** with the shape of
stellar-core and none of the money. Principals hold Ed25519 keys and sign
transactions that carry a per-account sequence number; accepted transactions
flood between validators before nomination; each slot's **ledger value**
contains an agreed close time and transaction set; a node applies it to a
bounded, sorted state and advances a timed ledger **header hash chain**; every
applied slot gets an immutable ledger record and quorum-certifiable history
tip; a localhost **RPC** takes transactions from a small CLI. Three nodes,
three processes, one binary.

Where `examples/counter` is the 40-line program, this one is five files:

| File | What |
|---|---|
| `src/registry.zig` | the pure state machine — transactions, sets, `validate` / `combine` / `apply`, the header chain, the snapshot format; standard library only, no I/O |
| `src/app.zig` | the `slcp.OwnedAppNode` adapter (custom codec, in-place `apply`, `initialSlot` / `initialCommand` from the loaded state, and the boot state passed to `create` as its context — no process global) and a live 2-of-2 test |
| `src/rpc.zig` | the shared RPC/gossip transaction-admission boundary, a line protocol on 127.0.0.1 (`head`, `get`, `account`, `submit`), and its client |
| `src/history.zig` | the quorum-authenticated replayable-history archive, ledger/tip-vote formats, trusted signing fence, and hostile-storage tests |
| `src/main.zig` | the process, history replay/publication, bounded gossip drain/reflood loop, and the client verbs `submit`, `get`, `account`, `head` |

Everything the node agrees on is deterministic and bounded. Domain and cadence
limits are printed at startup; the transport/gossip bounds are fixed in code:

| Limit | Value |
|---|---|
| transactions per set | 32 (a full set is 7521 bytes; a full tagged ledger value is 7547 bytes; the node raises `max_value_bytes` to 8192) |
| accounts / names | 64 / 128 (about 19 KB serialized state-root payload; about 27 KB in-memory State including its last LedgerValue) |
| name / value | `[a-z0-9-]`, 1..32 bytes / any bytes, 0..64 |
| pending queue | 256 |
| application-message payload / inbox | 64 KiB / 1024 messages or 16 MiB (lazy opt-in, best effort) |
| outbound application writer per peer | 256 messages or 1 MiB; 256 items / 4 MiB of the unchanged aggregate stay reserved for ordinary traffic |
| gossip work | immediate flood on acceptance, 1 s reflood while pending, at most 64 receives per main-loop tick |
| cadence | busy slots ≥ 1 s apart (`--min-slot-ms`); idle heartbeat every 3 s (`--heartbeat-ms`) |
| snapshot-anchor cadence | every 8 slots by default; `--checkpoint-every` accepts 1 through 64 |

## How it works

**Transactions.** 235 bytes, one fixed layout: `source` (32-byte public key),
`seq` (u64, 1 to 2⁶⁴−2), `op` (claim · set · transfer · release), a name, a value,
a `to` key, and a 64-byte signature over
`SHA-256("REGISTRY-TX-V1" ‖ network_id ‖ the 171 unsigned bytes)` where
`network_id = SHA-256("REGISTRY-NET-V2" ‖ G:u64be ‖ the --network
passphrase)` and `G` is `--genesis-close-time`. That digest is the transaction
id. A transaction signed for one `(passphrase, G)` pair is invalid on every
other registry network. Every field has exactly one canonical spelling (zero
padding, per-op rules), so a set decodes to null or to the one transaction its
bytes mean.

**Ledger values and transaction sets.** A `TxSet` is a count byte and up to
32 transactions, strictly ascending by (source, seq); its canonical empty
form is the single byte `00`. The consensus value is
`LedgerValue { close_time, txs }`, encoded exactly as
`"REGISTRY-VALUE-V1\n" ‖ close_time:u64be ‖ TxSet`. The disjoint tag prevents
old bare-TxSet bytes from acquiring a new meaning. This is a custom codec
(`encode` / `decode` on the app) because the auto-codec cannot encode
variable-length data.

**`validate`.** Let the local head be slot/time `(H,T)`, the checked slot be
`S`, and `d = S-H`. `S <= H` is invalid. The proposed close time must lie in
`[T+d,T+60d]`; an unrepresentable lower bound is invalid and the upper bound
saturates at `u64` maximum. Every signature verifies; per source the sequence
numbers form a contiguous run starting at the account's `seq + 1` (a replay
or gap inside a run is invalid), and a new source when the account table is
full is invalid. For the immediate successor, a run starting ahead is invalid
because it cannot apply now. A structurally sound value for a later slot is
`.maybe_valid` because this node does not yet know the intervening state.
`App.validate` receives `S` through `slcp.ValueContext`; it reads no clock.

**`combine`.** The minimum candidate close time plus the union of every
candidate set, deduplicated by (source, seq), sorted, filtered to what applies
cleanly on this state, capped at 32. Two nodes proposing different
transactions for one slot get both applied. The result is invariant under
permutation and duplicate candidates as one n-ary operation; the bounded pool
does not promise recursive pairwise associativity.

**`apply`.** Only a clean immediate successor whose close time is in
`(T,T+60]` changes state. In set order: the account's `seq` becomes the
transaction's,
**even when the operation fails** (stellar-core's rule; it is what keeps
`validate` and `apply` in agreement), then the operation runs — `claim` a
free name, `set` its value or `transfer` it or `release` it as its owner —
and its result (`ok`, `name_taken`, `not_owner`, `no_such_name`,
`registry_full`) is recorded. Then the header advances:
`slot += 1`, `prev_hash = hash`, `txset_hash = SHA-256(set)`,
`state_root = SHA-256(the sorted accounts and names)`,
`hash = SHA-256("REGISTRY-HDR-V2" ‖ network_id ‖ slot ‖ close_time ‖
prev_hash ‖ txset_hash ‖ state_root)`.
Three nodes that applied the same history print the same `head`.

**Snapshots, history, and restart.** After every applied slot the node
writes `<data-dir>/snapshot` with a random temporary file → write → `fsync`
and successful `F_FULLFSYNC` on macOS → atomic replace → data-directory
`fsync`. Snapshot V3 contains the header, state, exact `LedgerValue` agreed at
that slot, and checksum; the value is outside `state_root`, while its time and
transaction-set hash are bound to the header. Slot 0 has no predecessor value
but does have a real header: it commits to the network id, `G`, and empty state
root with zero previous/transaction hashes. On an ordinary restart the node
reads that snapshot into `initialState()`, names its slot in `initialSlot()`,
exposes the exact ledger value through `initialCommand()`, and the library
replays only newer journal slots. The native Node answering window is
configurable from 1 through 62 slots; this example deliberately leaves it at
the default 16. A node that returns within those 16 slots can catch up when
enough reachable validators provide every missing slot before the local
horizon is crossed; authenticated archive replay is the mechanism for longer
outages. Snapshot V3 is the sole accepted format; pre-E2c V1/V2 snapshots lack
the timed predecessor value and are
rejected. Before selecting either a local or authenticated boot state, the
process also requires slot zero to equal configured G exactly and a later head
to remain inside the cumulative `[G+slot,G+60·slot]` interval. Slot 0 is never
a history anchor or tip.

`--history-dir <dir>` adds long-outage recovery without trusting that shared
directory. Every applied non-genesis slot gets an immutable ledger record that
binds the network id, the complete Header V2, and the exact canonical
`LedgerValue`; the record format is independent of anchor cadence. Slot 1 and
every `--checkpoint-every N` boundary (default 8, allowed 1..64) are
deterministic Snapshot V3 anchor slots. Once a newly applied state reaches one,
each validator signs a `REGISTRY-HIST-V1` assertion over that exact tip and
every subsequent tip, binding its slot/head, anchor slot/head/snapshot digest,
and N so validators with different anchor policies cannot certify one apparent
tip. Each such slot can therefore become a quorum-certified history tip rather
than only a periodic checkpoint. On every fresh non-genesis `history-v1`
activation, the existing base is not republished or treated as
continuity-proven, even at slot 1 or an N boundary. Every newly applied
successor gets a ledger record immediately; attestation starts only when one
reaches the next deterministic anchor and continues at every slot thereafter.

Ledgers, anchors, immutable votes, and mutable per-validator latest pointers
live below the network's shared `history-v1` namespace. On import, malformed,
torn, or missing objects yield no recovery; unique valid signers must satisfy
this process's current local quorum set. Quorum policy is never read from the
archive. Each validator keeps an independent durable per-slot signing fence
below `<data-dir>/history-signing/.../history-v1`; it refuses same-slot
equivocation or a lower slot even if the shared archive asks for one. That
trusted tree also persists the configured anchor policy and a durable ordered
publication outbox.

After each application transition, the process first stages the full pending
Snapshot V3 state in that crash-durable outbox and synchronizes its admitted
watermark; only then may the ordinary local snapshot advance. A dedicated
worker publishes the oldest entry, advances the durable published watermark,
and removes it only after success. A retryable shared-history failure stays at
the head and successors cannot overtake it.

Before creating the real peer-connected Node, startup validates the trusted
outbox. With no unfinished certified adoption, it synchronously drains every
admitted entry before consulting mutable shared history. A persisted adoption
target T instead displaces any shared proof U before the operator floor is
applied; the floor is then enforced against T, so a too-old T stops boot rather
than being silently replaced by U. Startup completes T in an isolated no-peer
AppNode: it validates the local journal as T's exact continuation, writes T as
the ordinary snapshot and confirms its marker, then stages the journal
successors and snapshots their final state. It synchronously publishes that
continuation, re-runs shared recovery from the installed frontier, and may
prepare a newer U before creating the real peer-connected Node. Any newly
selected U is likewise
written and confirmed before its journal successors enter the outbox. During
either startup journal replay only, a full outbox may synchronously publish its
oldest entry and retry admission; at runtime a full 64-state backlog is
fail-stop. The background publisher starts only after RPC binds. A trusted
publication gap, outbox or signing-fence corruption/unavailability, invalid
state, or certified fork is likewise fail-stop. Post-start fatal paths drain
RPC handlers, stop the node, then hard-exit without voluntarily joining the
publisher. This removes the
userspace shutdown wait after consensus has stopped, though the OS may still
delay final reaping of a thread stuck inside a kernel syscall.

Confirmation writes domain-separated trusted boot provenance before removing
an adoption marker. Once established by certified history, that provenance
advances only after an exact represented outbox state is also durable as the
ordinary snapshot. A later restart can therefore use the confirmed state with
its explicit successor handoff even if shared latest pointers are withheld.
Merely activating a fresh history tree from a local snapshot does not confer
that trust; it still needs normal journal continuity until independently
certified.

After any pending adoption and backlog are reconciled, startup searches shared
history at or above `max(installed snapshot slot, --history-min-slot)`.
For a quorum-certified tip H, it loads the signed Snapshot V3 anchor, follows
the immutable ledger ancestry backward without gaps, and replays forward to H.
Each value must validate for its exact slot, application must reproduce the
entire recorded header and last value, and the final hash must equal the signed
tip. Replay is bounded by the configured anchor interval: at most `N-1`
records after an anchor, hence at most 63. The replay-complete state at H then
passes the checked `AppNode` handoff with `.start_slot = H + 1` and the exact
ledger value at H; it can be installed and served without a live peer. For an
ordinary shared-history selection, a newer eligible local snapshot remains
preferred, a same-slot head mismatch fails, and a newer valid local journal
may continue the selected state. The explicit minimum is the anti-rollback
control: signatures prove who attested state, not that an untrusted archive
showed you its newest state.

Snapshot anchors accelerate startup but do not reset continuity. Before a
validator signs an anchor-slot tip assertion, publication reconstructs the
anchor's own transition from the preceding segment and checks its complete
header, exact last value, and Snapshot V3. Startup need only materialize the
asserted anchor and its bounded suffix; the certified assertion and publisher
checks carry continuity across that boundary under the quorum-safety
assumption.

Shared candidate discovery then reads the derived latest pointer for each
validator in the local quorum instead of scanning the archive. Startup accepts
at most 16 distinct valid pointer assertions; a larger set is
`TooManyCheckpointCandidates` and fails closed rather than allowing unbounded
cross-reads or selecting from an incomplete fork set. This is an availability
bound, not a claim that shared storage will show every signed history tip.

A certified tip is a current-quorum attestation. Its immutable records prove
the contiguous ancestry from its signed anchor to that tip, but not ancestry
back to an unrelated older local head. Import therefore still assumes that the
configured quorum will not certify conflicting registry histories. Two
simultaneously discoverable certified assertions at one slot fail closed.
Separately, if the selected authenticated tip is at the eligible local
snapshot's slot, their heads must agree. Those checks are not an arbitrary or
continuous runtime fork detector: a withheld object or a validator's newer
latest pointer can hide an older alternative.

A process whose native node abandons a live-delivery gap still exits with code
3 rather than apply a discontinuous ledger value. This does not claim the
history is globally unavailable: restart it after a certified history tip
covering the gap is available. A node stopped before its first slot still
restarts from genesis; a compacted journal without either a usable local
snapshot or configured certified history is refused. The shared history
archive grows until an explicit retention design exists.

**Cadence, time, and flooding.** After each applied slot a node proposes
exactly once for the next: right away when it has pending transactions (after
`--min-slot-ms`), otherwise at the idle heartbeat. Proposal construction alone
samples Unix/POSIX whole seconds (leap seconds ignored), applies the optional
`--proposal-clock-offset-s`, and clamps the result to `[T+1,T+60]`. Received
values, combination, application, replay, and history recovery never read
local time. The minimum-time combination rule makes honest skew converge, but
the result is an agreed bounded logical time—not an authenticated UTC oracle.
A Byzantine quorum can choose any chain that advances 1..60 seconds per slot.
A transaction accepted from
RPC or gossip is immediately published to every capable connected peer. Each
peer runs the same canonical/signature/sequence/cap admission before adding it
to its pending queue and explicitly publishing it onward; rejected bytes are
never amplified. Pending transactions are reflooded every second until pruned
after application or supersession. The transport is best-effort and
non-durable, but once the transaction has reached a live validator it can be
proposed in the next eligible slot even if the submission node then dies.

**RPC.** One request line, one response line, on 127.0.0.1 only:

```
head                → head slot=<n> close_time=<unix-seconds> hash=<hex64> accounts=<n> names=<n> pending=<n> network=<hex64>
get <name>          → entry name=<name> owner=<hex64> value=<hex>   |   none
account <hex64>     → account key=<hex64> seq=<n> next=<n>
submit <hex470>     → ok txid=<hex64>   |   err <code> <text>
```

`submit` decodes the exact canonical 235-byte transaction, verifies its
network-bound signature, requires `seq == next`, and refuses duplicates or a
full queue (`bad_request`, `bad_tx`, `bad_sig`, `bad_seq`, `queue_full`,
`duplicate`). Clients do not provide a close time; extra request tokens are
rejected, and validators construct that field only when proposing a ledger.
Gossip input uses that same admission function. Acceptance adds
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

   This E2d example uses post-v0.2 Experimental `ValueContext`, application
   messaging, and recovery seams, plus application-owned replayable history.
   If you move it out of the repository, pin a
   future revision that contains E2c rather than the v0.2.0 package; it must
   also contain E2d. The build produces `zig-out/bin/registry` and
   `zig-out/bin/slcp`.

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
   ./zig-out/bin/registry node --network "my registry e2c" \
       --genesis-close-time 1788480000 --key node.key --data-dir data \
       --quorum quorum.json --listen 7411 --rpc 7412 \
       --peer b.example.com:7411 --peer c.example.com:7411
   ```

   Choose `--genesis-close-time` once, near network birth, as a Unix/POSIX
   whole-second value below `u64` maximum; leap seconds are ignored. Both it
   and the nonempty `--network` string must be identical everywhere and must
   be preserved on every restart. Their canonical binary descriptor is hashed
   into the raw SLCP identity and the registry transaction identity; neither
   full id is sent. `--proposal-clock-offset-s` defaults to zero and exists for
   clock-skew testing/operations, not as shared configuration. The first
   lines look like:

   ```
   registry: node d4f7315f…985e58 listening on port 7411; 2 peer(s); data in data; starting from genesis at slot 0 close_time=1788480000
   registry: limits: 32 txs per set, 64 accounts, 128 names, 256 pending; busy slots every >= 1000 ms, idle heartbeat every 3000 ms
   registry: rpc listening on 127.0.0.1:7412
   slot 1: close_time=1788480060 txs=0 ok=0 head=<hash16>
   slot 2: close_time=1788480120 txs=0 ok=0 head=<hash16>
   ```

   The `peer … unreachable` warnings while the other boxes start, the
   `peer N up` lines, and the "consensus needs a quorum; waiting" line when
   two of three are down are the library's, explained in the counter's
   README. `head=` is the first 16 hex characters of the header hash: the
   same on every machine at the same slot, or something is wrong.

   **E2c is a hard epoch, not an in-place upgrade.** The coordinated
   `REGISTRY-NET-V2`, `REGISTRY-VALUE-V1`, `REGISTRY-HDR-V2`, Snapshot V3,
   and checkpoint V2 formats do not reinterpret pre-E2c storage. Use a fresh
   `--data-dir` for every validator, which also creates fresh SLCP logs and
   history-signing state. An existing physical `--history-dir` may be reused
   only as a container: the new network id selects a distinct namespace and
   old checkpoints are not imported. If the identity guard were bypassed, an
   old bare-TxSet journal would fail decoding rather than be wrapped silently.
   Carrying application state across this boundary requires an explicit
   migration that this example does not implement.

   **E2d does not create another SLCP network epoch.** The network descriptor,
   LedgerValue, Header V2, and Snapshot V3 stay unchanged. Instead, both the
   shared archive and trusted signing tree enter a separate `history-v1`
   namespace with new ledger and tip-vote formats. Pre-E2d checkpoint-only
   archive objects and signing fences are not reinterpreted. See
   [`ADR 0002`](../../docs/adr/0002-registry-replayable-history.md).

   To enable replayable-history recovery, provision a durable shared or
   correctly mirrored filesystem whose contents are visible to all three
   validators and append:

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
   close time, hash, and pending count; `registry account <hex64>` the applied
   `seq` and the `next` one to use.

7. **Kill one and restart it.** Ctrl-C (or `kill -9`) **c**; **a** and **b**
   carry on (2-of-3). Start **c** again with the same command:

   ```
   registry: node 84a5a57d…dcfff2 listening on port 7411; 2 peer(s); data in data; starting from the snapshot at slot 19 close_time=1788481140
   slot 20: close_time=1788481200 txs=1 ok=1 head=<hash16>
   slot 21: close_time=1788481260 txs=0 ok=0 head=<hash16>
   …
   slot 24: close_time=1788481440 txs=0 ok=0 head=<hash16>
   ```

   It came back from its snapshot, was handed the slots it missed by its
   peers, and prints the same heads as the others. It also votes again: a
   transaction submitted to the restarted node floods to the other validators
   and lands in the next eligible slot like any other. Without
   `--history-dir`, staying away longer than 16 slots still leaves it unable
   to rejoin. With history enabled, restart it with the same archive; optionally
   add `--history-min-slot <known-good-slot>` to refuse any older view. It
   selects the newest eligible quorum-certified history tip that it can fully
   replay. An unfinished trusted adoption must first pass the configured floor,
   complete in an isolated no-peer startup phase, publish any continuing local
   journal, and only then recheck shared history for a newer tip. It checks the
   selected Snapshot V3 anchor against the immutable anchor record and strictly
   replays every later ledger record through the exact tip. It restores that
   tip's final LedgerValue
   (time plus transaction set) as
   nomination context and starts at its successor. Recovery to the certified
   tip does not require a live peer.

## Limits — what E2 still does not do

Transaction flooding, authenticated recovery, deterministic close time, and
bounded replayable history close the four corresponding gaps recorded by E1.
These remaining limits are deliberate:

- **Flooding is best-effort, not history.** Pending queues and the generic
  Node inbox are memory-only. Immediate publication plus a 1 s reflood heals
  ordinary loss and reconnects; once another validator admits a transaction,
  loss of the submission node does not lose it. If the source dies before any
  peer admits the bytes, or every holder restarts before application, resubmit.
- **Replay is bounded and availability is external.** Each history tip is
  replayable only from its signed Snapshot V3 anchor; the configured interval
  bounds that suffix to at most 63 ledger applications. An untrusted archive
  can hide, withhold, or delete any required anchor, ledger, or vote;
  `--history-min-slot` prevents accepting an older view but cannot make missing
  data appear. Per-validator latest pointers may hide an older certificate
  after validators advance at different rates, and more than 16 distinct valid
  startup candidates is a fail-closed availability error. Without history,
  this binary's default 16-slot native answering window is its bounded
  live-peer catch-up horizon. A compacted journal without a usable local
  snapshot or certified history is refused.
- **History has no retention policy yet.** Immutable shared ledgers and votes,
  periodic anchors, and trusted per-slot signing/frontier evidence grow with
  publication. A blocked publication head retries in order from the durable
  outbox; if live consensus fills its 64-state backlog before storage recovers,
  the registry stops rather than discard a history record or let a successor
  overtake it. Boot-time journal replay may publish one oldest entry
  synchronously when it needs that capacity for the exact next successor.
- **Bounded state.** 64 accounts, 128 names, 32 transactions per slot. The
  typed layer copies the state after every applied slot and `initialState()`
  cannot read a file, which is why the state is plain data and the snapshot
  is loaded through a global before the node starts.
- **No heap state, generic archive protocol, upgrades, quotas, watcher nodes,
  or HTTP.** The remainder of E2 and E3. The application-owned archive does
  not make history a generic SLCP protocol. The native Node now offers a
  configurable bounded answering window and Experimental catch-up telemetry;
  this example keeps the 16-slot default and relies on its authenticated
  archive for long-outage recovery.

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

**Replayable-history storage has two different trust domains.** Treat the shared
`--history-dir` as fully hostile: an archive writer may delete, replay,
truncate, rename, or replace objects; create symlinks, directories, FIFOs, or
other special files at expected names; withhold newer attestations; and arrange
many valid old latest pointers. The reader pins no-follow directory handles,
opens generated basenames nonblocking, accepts regular files only, validates
every path/content/signature/network/anchor/ledger/tip relationship, strictly
replays the selected anchor-to-tip chain, uses only the local quorum policy,
and caps startup candidates at 16. Those checks protect state integrity;
archive manipulation can still deny recovery or publication. Mutable latest
pointers are only bounded discovery hints, never a freshness oracle. Shared
ledgers, anchors, and votes are not pruned yet, so operators must also provision
and monitor storage growth.

The signing fence at `<data-dir>/history-signing` is trusted validator safety
state, like the validator key. Keep it local, writable only by that validator,
preserve it across restarts or host migration, and never share, mirror, delete,
or restore it independently to an older version while retaining the key. The
tree also persists the anchor cadence and the admitted/published watermarks and
full pending Snapshot V3 states of the ordered outbox. Startup resolves a
persisted adoption target in an isolated no-peer phase before mutable shared
history, stages and snapshots its exact journal continuation, drains that work,
and only then considers a newer shared tip. It confirms each certified
selection in the ordinary snapshot before admitting its journal successors.
The implementation rejects filesystem-identity or ancestor overlap between the
archive and the whole private data root. It also rejects an archive that
contains the validator key's pinned parent, requires a regular non-symlink key,
and binds Node's later key-file read to the identity already used for history
signing. It does not create your filesystem access policy. Before publishing a
shared vote it durably records and synchronizes both the immutable per-slot
fence and the high-water fence, including their containing directories; a
retry repeats those directory barriers. Failure of `fsync`, the checked macOS
`F_FULLFSYNC`, or a directory barrier in that trusted phase is explicitly
fail-stop; the same low-level error in the shared archive remains an
availability failure for ordered retry at the durable outbox head. If the
64-state backlog fills during live operation, the registry stops rather than
skip history; boot-time journal replay may publish one oldest entry to make
room for the exact next successor. Staging
and synchronizing an applied state happens before the ordinary local snapshot
advances; failure of either trusted step stops the registry. Post-start fatal
paths drain RPC handlers, stop the consensus node, and then hard-exit without
joining the publisher; ordinary
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

For the E2c/E2d temporal and history witness, the three validators use
proposal-clock offsets of -30/0/+30 seconds and a 64-slot archive-anchor
interval. The harness records a durable outage origin, stops node2 again, and
requires node0 and node1 to externalize at least 201 new transaction-free
slots. The survivors must then agree on an exact non-anchor tip assertion H
that both signed, that one observed as quorum-certified, and that lies at least
17 ledger records beyond anchor A.
That span is deliberately larger than this registry binary's default 16-slot
native answering window. The harness then stops **both** survivors. With both
peers dead, node2 restarts with floor H, must report strict archive replay from
A through H, and must expose H's exact hash and close time over RPC before any
peer returns.
Only then does node1 restart. Node2 is a necessary voter with node1 for
transaction 8 in the first later transaction-bearing ledger; every optional
intervening ledger must appear on both logs, be empty, and extend one complete
temporal chain.

Across the run, each RPC head and durable slot line for the same ledger must
agree on close time, every adjacent time step is 1..60 seconds, and every
observed slot lies in the cumulative interval anchored at G. Finally node0
rejoins, all three agree on transaction state/head/time, and a process-level
probe proves that the same human passphrase with `G+1` is refused against the
old data directory as `DataDirOtherNetwork`. Evidence line on stdout:

```
[registry-smoke] nodes=3 txs=8 slots=N head=<hex16>
```

`zig build registry-build` runs only the nested build; `-- --keep` leaves
the scratch under `.zig-cache/registry-smoke/`. Neither is part of
`zig build test` — that runs `registry-tests` (the pure module, the RPC, and
a live 2-of-2 pair with restart) and compiles the program (`registry-intree`).
Inside this directory, `zig build test` runs the same tests as a consumer.
The focused registry suite covers history and boot selection, timed
value/header/snapshot invariants, strict replay, directory durability,
publisher ordering and failure policy, quorum evaluation, tampering, rollback,
torn objects, hostile namespaces, special files, candidate bounds, and fork
discovery. A separate `registry-smoke-tests` target pins the harness predicates
and argument rewrites. The final E2d run passed 99/99 focused registry tests,
25/25 smoke-harness tests, and the real three-node peerless-recovery smoke; its
exact process evidence is recorded in the repository
[`STATUS.md`](../../STATUS.md).

## Files

- `src/registry.zig`, `src/app.zig`, `src/rpc.zig`, `src/history.zig`,
  `src/main.zig` — above.
- `build.zig`, `build.zig.zon` — a consumer package that depends on the
  repository by path (`../..`); pin a release tag instead for a deployment.
- `node.key`, `*.key`, `data/`, `zig-out/`, `.zig-cache/` are git-ignored.
  Never commit a key file.

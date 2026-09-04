# Threat model (v1)

What SLCP v1 protects, what it deliberately does not, and what that means for
how you deploy it. Read this before exposing a listen port. Sources are cited
the same way as in `docs/protocol.md`; the budgets and rules below are copied
from the code, not remembered.

## 1. What signatures protect

Every statement is an Ed25519 signature over
`SHA-256("SLCP-STMT-V1" ‖ networkId ‖ statementBytes)` (`src/crypto.zig`;
protocol §4), where `statementBytes` is the canonical Cap'n Proto encoding of
the `Statement` and `networkId` is derived from your passphrase and never
transmitted. That gives you:

- **Authenticity and integrity of every statement.** A statement is attributed
  to exactly the key that signed it; a modified byte fails verification.
- **Network binding.** An envelope from a node on a different passphrase — or
  a replay from another SLCP network — has a different digest and fails as
  `invalid_signature` (protocol §11). No parsing of its content is ever
  trusted.
- **Agreement among intact nodes**, in the FBA sense: nodes that are not
  Byzantine externalize the same value for each slot **provided** the
  Byzantine set lies within a dispensable set (DSet) of your configuration
  **and quorum intersection holds** across the network's quorum slices
  (design §4.2, §13.2). The second condition is a property of everybody's
  configuration together, and nothing in this library can check it — see §4.

Signatures do **not** protect liveness (§5), the transport (§2), or your own
driver's determinism (`docs/determinism.md`).

## 2. **No transport authentication in v1.**

TCP in the clear. The `Hello` frame is unauthenticated: its `nodeId`,
`currentSlot`, `listenPort`, and `featureFlags` fields are advisory hints, and
`networkIdPrefix` (the first 8 bytes of the networkId) is a fast
wrong-network disconnect, **not a secret and not authentication**
(`schema/overlay.capnp`, protocol §12). Consequences:

- Anyone who can reach the listen port can connect, claim any `nodeId` in
  `Hello`, advertise any feature bits, and send any negotiated frame.
  An `appMessage` from a peer that omitted feature bit 0 is dropped, but an
  attacker can simply advertise the bit; it is capability negotiation, not
  authorization.
- They cannot forge a statement (signatures, §1), but they can burn every
  per-peer budget in §3 and use the two unauthenticated answer paths
  (`getQset`, `getSlotState`) as amplification.
- Traffic is readable on the wire: statement and application-message contents
  are not confidential.

**Deployment guidance — treat the listen port as an internal service:**

- Run the nodes on a private network or a **WireGuard** mesh (or any
  equivalent authenticated tunnel: Tailscale, an IPsec VPN, an SSH tunnel per
  peer), and bind or firewall `listen_port` to the peer addresses only.
- **Never expose the port to the Internet.** A public listener in v1 is an
  invitation to keep your reader threads and write queues busy.
- The node dials only the addresses you listed in `.peers`. `Hello.listenPort`
  is sent but never used to dial (as built, `src/node/overlay.zig`), so an
  unauthenticated Hello cannot make your node connect anywhere.

Planned v2 (design §1 non-goals, §16): an authenticated transport
(Noise-IK or TLS with NodeId-bound certificates) behind the same
protocol-agnostic transport seam. `docs-smoke` requires this section's
heading so the warning cannot be edited away.

## 3. What a malicious peer can do

Per-peer budgets, copied from `src/node/overlay.zig` and `src/node/wire.zig`
(protocol §12):

| What the peer can burn | Bound |
|---|---|
| inbound bytes | `inbound_rate_soft_cap_bytes_per_s = 256 * 1024` per peer (soft cap; a breach is a strike) |
| unanswered requests | `max_outstanding_requests = 64` |
| strikes before disconnect | `max_budget_strikes = 32` |
| concurrent inbound connections (all peers together) | `max_inbound_conns = 128`; over-cap accepts are closed before any allocation |
| our aggregate write queue toward a peer that stops reading | `max_write_queue_items = 1024` / `max_write_queue_bytes = 16 MiB`; ordinary overflow ⇒ disconnect |
| application subset of that write queue | `max_app_write_queue_items = 256` / `max_app_write_queue_bytes = 1 MiB`; app pressure drops only that frame |
| aggregate capacity unavailable to application frames | `reserved_write_queue_items = 256` / `reserved_write_queue_bytes = 4 MiB` for ordinary/consensus traffic |
| a connection that never sends `Hello` | `handshake_timeout_s` = 10 s absolute deadline on the read operation |
| frame size | `max_frame_bytes = 1 MiB`; larger ⇒ framing error ⇒ disconnect |
| one decoded application message | `max_app_message_bytes = 64 KiB`; larger ⇒ codec rejection |

After transport decoding, the native Engine-input queue is independently
bounded to 1,024 items / 16 MiB. Network work is capped at 960 items / 15 MiB,
leaving 64 items / 1 MiB for local progress; network admission losses are
visible through `Node.ingressStats()`. Admission fails closed under host
allocation pressure, including hold-gate metadata decoding, so an old envelope
cannot bypass the floor through a second parse attempt. A coalesced purge
watermark lives outside those budgets and overtakes the FIFO. The host therefore rechecks its
monotonic purge floor when applying queued work: late peer or held envelopes
and an overtaken local nomination cannot recreate a retired slot. This
apply-time check is essential—enqueue-time admission can become stale while
the item waits behind attacker-controlled traffic. On restart, the same floor
is reconstructed from the journal high-water mark and explicit `start_slot`
before any own statement is restored or network input is accepted. Own-log
records below it are skipped, so an uncompacted disk tail cannot consume the
Engine slot budget with retired history.

The separate application-message inbox is lazy and global, not one allocation
per connection. Until the application first calls `waitAppMessage`, received
payloads are dropped without retaining bytes or hashes. Afterwards it owns at
most 1,024 messages / 16 MiB, drops newcomers on cap or allocation pressure,
and deduplicates payload digests by SHA-256 only while one copy remains queued.
`Node.appMessageStats()` exposes receiving state, queue use, drops, and
queue-resident duplicates. Taking a message removes that digest, deliberately
allowing the same bytes to arrive again for application-controlled retry.
FIFO churn does not shift the live queue on every delivery: a head index and
amortized compaction cap physical item storage at 2,048 entries. Shutdown
closes waiter admission and drains admitted waiters before freeing the inbox.

Outbound application traffic is opportunistic on every connection. Its
256-item / 1 MiB subset and the 256-item / 4 MiB ordinary reserve sit inside,
not in addition to, the unchanged 1,024-item / 16 MiB aggregate writer cap.
Application pressure drops the app frame without closing the socket; it
cannot consume the reserve, and app enqueue itself never takes the ordinary
overflow-disconnect path. The shared FIFO still gives already-queued app bytes
a bounded position ahead of later consensus output.

**Amplification surfaces.** `getQset` (answered with one cached qset frame,
bounded by depth ≤ 4 / ≤ 255 validators) and `getSlotState` (answered with at
most 64 of *our own* envelopes). Both are **per-request fan-out only**:
requests are never relayed, so one request yields at most one reply from the
node it was sent to. `dontHave` is ignored by the receiver (as built).

Opaque `appMessage` frames have no SLCP signature or built-in authorization.
The generic Node only queues them and **never auto-relays receipt**, so hostile
bytes do not gain a library-level flood path. An application that explicitly
republishes becomes responsible for first checking its canonical form,
network binding, signature or other authentication, replay rules, and local
capacity. Invalid or rejected input must stop at that boundary.

**Parking caps** (`src/engine/limits.zig`, `src/engine/pending.zig`): an
envelope citing an unknown qset hash parks until the qset arrives —
`max_pending_envelopes = 1024`, `max_pending_bytes = 8 MiB`, `max_per_node =
4`, FIFO eviction (each eviction is a `phase_event(parked_evicted)`).
EXTERNALIZE statements never park.

**Engine quorum-set cache** (`src/engine/qset_store.zig`): the configured
`max_cached_qsets` bound includes the mandatory local set and every distinct
qset carried by a live stored remote NOMINATE, PREPARE, or CONFIRM statement.
EXTERNALIZE uses a synthetic sender singleton, so its commit-qset hash is not a
live cache reference. The local set is permanently pinned and live statement
references are never eviction victims. A qset rotation may use exactly one
additional active entry while multiple old statements move from A to X;
unrelated new references and a second overflow are rejected as `over_limit`.
Thus for a nonzero configured bound N, steady live retention is at most N
qsets, or N + 1 while that one rotation is incomplete. A fetched qset is
separately leased only for its replay input, so
the absolute resident-cache peak is N + 2 when a different response arrives
during an incomplete rotation; releasing the input lease immediately evicts
that unreferenced response. `max_cached_qsets = 0` is a special local-only
mode: rotation overflow is disabled, steady residency is exactly the local
qset, and one fetched in-flight response can make the transient peak two.
Native request correlation prevents unsolicited or malformed qset frames from
reaching either the Engine or persistence.

**Node qset answering cache** (`src/node/qset_disk_cache.zig`): the on-disk
`qsets/` cache is independent of Engine residency and bounded to 1,024 managed
entries including the pinned local set, 64 MiB of logical payload bytes, and 1
MiB per entry. Runtime remote eviction is FIFO; restart keeps the newest
`(mtime, hash)` entries under both budgets with O(cap) selection memory.
Atomic rename avoids successful partial writes, and any write/cleanup failure
disables later writes for that Node lifetime. Reads are length-capped and
semantically revalidate the qset hash before serving. Failures become misses
and sticky Experimental `Node.storageStats()` counters, never consensus-fatal
state. Residual disk usage is filesystem allocation overhead, unrelated names
the cache deliberately preserves, and at most one new owned temp after a live
filesystem failure prevents both completion and cleanup; operators should
still alert on degradation.

Cache files and directory renames are not fsync'd. A crash or power loss can
therefore lose or corrupt an entry or leave a temporary file. Startup cleanup
and semantic verification reduce those outcomes to cache misses; the fsync'd
consensus logs are separate and unaffected. Reconciliation memory is O(the
1,024-entry cap), but its CPU and I/O scan every `qsets/` directory entry and
cleanup may rescan after deletions. An old unbounded cache or operator-created
names can therefore delay startup even though retained cache state is bounded;
keep `data_dir` operator-owned and do not co-locate other files in `qsets/`.

Statement identity remains exact: graph reachability is derived from the
union of the exact qsets on all live non-EXTERNALIZE statements, not a
process-global "last advertisement," and every quorum calculation uses the
statement's exact qset or EXTERNALIZE's synthetic singleton. The *published
relevance graph* is exact at a
checkpoint but deliberately conservative between checkpoints. Pure additions
chase only the newly added hash. An ordinary last node→hash removal leaves the
old nodes in a superset and opens a 64-update generation instead of traversing
the entire graph on attacker-controlled replacement traffic. There are no
relevance false negatives. A recently disconnected signer is a temporary
false positive: its valid input may be held, parked, stored, forwarded, and
processed, but its stale graph edge cannot make that signer count in an exact
quorum calculation.

The periodic exact checkpoint occurs on the generation's 64th qualifying
update. Successful statement-reference updates qualify. So does each
signature-verified unknown-qset envelope that reaches the Engine from a signer
already in the published graph: the Engine advances the counter and rechecks
exact membership when necessary **before slot admission and parking**. This
prevents Engine-level unknown-qset parking churn from preserving a stale
member, without letting an arbitrary outside key force rebuild work. Qset
replay batches and every slot purge are exact checkpoints as well. Known-qset
input rejected before a reference commit—including stale, live-slot, or
capacity rejects—does not qualify. A future-slot envelope intercepted by the
native hold buffer does not qualify until it is released to the Engine either;
while held, replacement, window, entry, and byte caps bound it. Therefore the
generation can remain conservative indefinitely in wall-clock time and total
received inputs if none of the qualifying events occurs; 64 is a mutation/
growth bound, not an input-duration claim. Such rejected traffic adds no qset
reference, pending envelope, or live statement; any slot admitted before a
later budget rejection remains under `max_live_slots`. The input still consumes
bounded verification and parsing CPU.

Memory remains bounded during the grace generation. For a nonzero configured
cache bound N, the active graph-contributing set is at most N + 1 qset bodies
(including the sole rotation overflow). At most one body can retire per
qualifying reference update, so an ordinary generation adds validator ids from
at most 64 retired bodies: at most 16,320 ids / 510 KiB of raw 32-byte keys,
plus hash-table overhead. A qset replay batch starts from that bounded graph;
because every waiter taken by one response cites the same newly fetched hash,
the batch can add at most one more body before its exact final rebuild. The
published graph therefore contains at most `1 + 255 * (N + 1 + 64)` ids outside
replay and at most `1 + 255 * (N + 2 + 64)` transiently during replay, with the
leading one for the explicit local-node root and duplicates reducing the
result. False-positive statements remain under `max_live_slots` and the 20 MiB
stored-statement budget; unknown-qset parking remains under 1,024 entries /
8 MiB / four per signer; the native hold buffer remains under 1,024 entries /
8 MiB; and exact qset refcounts and cache capacity are unchanged.

An exact rebuild's work is bounded by unique live node/hash associations under
the stored-statement budget and at most N + 1 active qsets × 255 validators.
Each distinct reachable qset body is walked once and each validator enters the
frontier once. Thus the periodic full traversal costs O(W) once per 64
qualifying updates rather than once per replacement (amortized O(W/64)), at
the cost of a deterministic O(W) latency spike on the checkpointing input.
The rebuild stages a new graph, frontier, and per-traversal hash-dedup set next
to the old published graph, so its transient allocation is O(old graph + W)
under the node-count bounds above. Slot purge batches all retired references
into one rebuild, and a qset response
publishes one exact post-replay graph after processing up to the 1,024 parked-
envelope cap. An exact rebuild is staged before publication: allocation failure
leaves the old conservative graph intact and the generation counter saturated
for a retry, then becomes a terminal sticky Engine failure. Reference mutations
already committed remain ownership-safe, and a pre-parking failure frees its
decoded statement. An old qset may already be evicted once its last live
reference is gone, but graph state stores only node IDs—not borrowed qset
pointers—so teardown remains ownership-safe even if graph publication fails.

**Hold buffer** (`src/node/node.zig` `HoldBuffer`, M6 S8b; protocol §12):
inbound statements of every kind (EXTERNALIZE included) for slots beyond
the delivery frontier + 1 are parked host-side until the node has applied
the slot before them, or until a v-blocking set of the local quorum set has
sent EXTERNALIZE for that slot (catch-up). **Only signers inside the currently
published transitive quorum graph are held**: a stranger's statement goes
straight to the engine's relevance filter below and is dropped statelessly,
so an unauthenticated connection with random keys cannot occupy a single entry
(the S8b review filled the first version's 1024 entries that way). During a
conservative generation, a recently disconnected signer is a bounded false
positive and may enter this buffer; once held, its entry follows the normal
replacement, window, and release rules even if a later checkpoint prunes the
signer. Every parked statement was **signature-verified first** (a forged
signer cannot
occupy or displace a genuine member's entry); the buffer is bounded to a
**64-slot window** past the frontier, **1024 entries / 8 MiB** in total,
one entry per (slot, signer, kind) — a chatty honest sender replaces its
own entry, never accumulates — and a cap breach drops the newcomer. What is
left to fill it is a quorum member's key, and a member can send at most
(64 slots × 4 kinds) entries; the caps are a backstop, and every drop is
re-sent by the sender's 3 s anti-entropy re-flood. The catch-up release
trusts exactly what SCP's accept rule trusts (a v-blocking set), so a
single byzantine member cannot make a node look ahead of its frontier.
Held statements are neither relayed nor answered, so a lagging node also
stops propagating the next slot's statements until it catches up (a slower
relay in sparse topologies; invisible on the full-mesh deployments).

**Relevance filter** (protocol §4 step 8): statements whose signer is outside
the published transitive quorum graph of your configuration are `ignored`
before any per-slot state is allocated. The graph is exact at checkpoints and
a conservative superset between them, as described above: an arbitrary
stranger with a valid key cannot make you store anything, while a recently
disconnected signer can consume only the already bounded false-positive
resources. A checkpoint rejects its new inputs; state already admitted during
the grace period leaves through its normal purge, eviction, or release path.

**Stored-statement budget** (`max_stored_statement_bytes = 20 MiB`,
`max_live_slots = 64`): the latest-per-(node, protocol) storage is bounded
engine-wide; an over-budget statement is `over_limit`.

**Counter inflation.** There is deliberately **no receive-side cap** on ballot
counters (a cap would let an attacker freeze honest nodes at the cap). The
exposure is the timeout schedule: `timeout(n) = min(1000·(n+1), cap)` with
`cap = 60_000` ms frozen (protocol §7–§8), so the worst an inflator does is
push honest ballot timers to 60 s. **Measured: zero movement of honest
counters** by a sub-v-blocking adversary (M3, `sim/byzantine.zig` "counter
inflator" tests, and the 1000-seed `byz-matrix`).

**Equivocation.** A signer that sends two contradictory statements for one
slot: storage is latest-per-node by freshness (protocol §10), the FBA quorum
math treats each statement on its own, and the e2e test `an equivocating
quorum member cannot fork the honest nodes` pins that its values never win
while the Byzantine set stays within a DSet.

**Non-canonical encodings.** Rejected by default (`strict_canonical = true`):
a statement whose bytes are not the unique canonical spelling is `insane`
even though its signature verifies (protocol §4 step 7). Lenient mode exists
for interop debugging only; both modes are safe (`sim/byzantine.zig`
"non-canonical encoder").

**Qset liars.** A qset hash that never resolves, or a qset that does not
match its hash, leaves the referencing envelope parked until eviction;
nothing else is affected. Qset size and depth are bounded by the frozen
wire limits, and `slcp_qset_hash` / the node only accept qsets that validate
and normalize. A Node also reparses and hashes a remote disk-cache entry before
answering `getQset`; same-sized corruption is invalidated as a miss. A peer
receiving any cached response independently performs the same validation, so
cache corruption is an availability loss rather than a consensus-integrity
path.

**Signature forgery / wrong network.** `invalid_signature`, never processed
(`sim/byzantine.zig` "sig forger").

## 4. What linting cannot protect

`slcp lint-quorum` and the lint run inside `Node.create` (design §12,
`src/engine/qset.zig` `lint`) check exactly two things:

1. **Top-level threshold sanity of *your own* configuration**: a
   sub-majority top level (`sub_majority_threshold`, an error), a top level
   below two-thirds (`below_two_thirds`), and a top level that needs every
   member (`all_members_critical`).
2. **Tree-wide critical validators** (`critical_node`): any single node
   whose outage alone makes your tree unsatisfiable, at any depth.

They **never** reason about other nodes' configurations. **Cross-node quorum
intersection is unverified** — deciding whether every pair of quorums in the
whole network overlaps in an honest node is NP-hard in general (design §1),
and this library does not attempt it. So:

- Two nodes can each pass lint and still, together, form a network with
  disjoint quorums. Agreement then fails silently: both halves externalize
  different values and neither sees a protocol violation.
- A **sub-majority threshold is a fork machine** on its own: with `t <=
  n/2` two disjoint subsets of your own slice each satisfy it, so two
  quorums can exist with no node in common. That is why it is the one lint
  *error*.
- `allow_unsafe_quorum = true` turns that error into a warning (logged at
  WARN with the suffix `(.allow_unsafe_quorum = true: starting anyway)`)
  and makes forks your problem. Use it for local experiments, never for a
  network other people rely on.

Keep configurations symmetric and small until you have a reason not to: if
every node lists the same validators with the same threshold (the three
recipes in `docs/quorum-recipes.md`), quorum intersection holds by
construction as long as `t > n/2`.

## 5. Availability: the halt failure class

Halting without a quorum is **correct** federated-Byzantine-agreement
behaviour, not a bug: a node that cannot hear from a quorum of its slice
must not externalize, or it could disagree with the nodes it cannot hear.
The lint prints the consequence in your own numbers on every level:

> `t-of-n; halts if any n − t + 1 of these n are offline`

and `min blocking set: K node(s)` is the smallest number of validators
whose simultaneous outage halts you anywhere in the tree
(`qset.minBlockingSize`). A 2-of-3 network halts when **two** nodes are
down; a 3-of-3 network halts when **one** is.

The reference incident is the **May 2019 Stellar network halt**: enough
validators went offline that the remaining ones could not form a quorum, and
the network stopped for about two hours until nodes returned — the public
post-mortem is Stellar's "May 15th Network Halt" blog post. That is one
sentence of history, not a claim about SLCP: the point is that a correctly
configured FBA network stops rather than forks, and yours will too.

**The mute-node halt class (closed, M6 S8b).** A typed app whose
`validate` reads `State` (the §0 counter: `.maybe_valid` for "ahead of my
count") and a node that is one slot behind when the next slot's NOMINATE
arrives: the engine caches the per-slot verdict and `fully_validated` is
sticky, so that node would never vote for that slot — and n − t + 1 such
nodes (two nodes restarting mid-slot on a 2-of-3 deployment) halted the
network forever with everyone live and caught up. The host now feeds SCP
only the current slot (protocol §12 hold rule, stellar-core's Herder shape):
`apply(N)` always precedes every `validate` for N + 1, so the verdict is
computed against the applied state. The one way a slot is judged early is
the catch-up release, which needs a v-blocking set of EXTERNALIZEs for it —
a slot the network has finished and can never need this node's vote on —
so a node behind by more than one slot is passive only for slots that are
already decided, never mute on one still in progress. (The S8b review
refuted the first version, which let any lone EXTERNALIZE through: one
peer's EXTERNALIZE(N + 1) reaching a node one slot behind muted it for
N + 1 and, with that peer dead and two others restarting, halted a 3-of-4
network with three live nodes.) Pinned by `zig build liveness-tests` (the
double-crash and the lone-EXTERNALIZE schedules halt with the gate off and
converge with it on) and by the e2e restart scenarios.

**Nomination participation rule** (design §11; the number-one "my network is
stuck" cause): consensus for a slot advances only while a quorum of
validators have proposals queued. A validator with nothing to propose is not
a failure, but it does not drive the slot either — the §0 counter program
proposes again after every applied slot for exactly this reason. A 1-of-1
self quorum lints with a warning and does externalize (dev / smoke use), but
a restart story needs at least two proposers.

## 6. Consensus-log persistence failure ⇒ inert

The write-ahead discipline (design §10, `src/node/node.zig` `dispatch` /
`markFailed`): `persist_own_envelope` appends and fsyncs `own.log` **before**
the paired `broadcast_envelope` is sent. If that append fails (ENOSPC, I/O
error), or the `externalized.log` journal append fails, the node latches
**inert**: no further inputs are applied, no further effects are dispatched,
`waitExternalized` / `waitApplied` waiters are woken (the typed node reports
`error.NodeHalted`; `haltError()` names the cause). A node that cannot
persist must go silent — broadcasting an unpersisted statement is Byzantine
after the next crash (it could re-emit an older, conflicting statement).

The best-effort qset answering cache is deliberately outside this rule. Its
local qset stays pinned in memory; remote read/write failures become misses,
set `Node.storageStats().qset_cache_degraded`, and may disable later cache
writes without stopping consensus.

- **Torn tail** (the file ends mid-record): repaired on recovery by
  truncating to the valid prefix; the node stays a validator. Safe because a
  torn final record was never broadcast.
- **Corrupt `own.log`** (a complete record fails its crc): the log is
  untrusted and the node runs as a **watcher for its lifetime** (v1
  as-built) — it can never emit a statement older than one it already
  broadcast, because it never emits.
- **Uncompacted valid tail**: recovery derives the same 16-slot answering
  floor used during live delivery (or the later explicit `start_slot`) and
  restores only own statements at or above it. The full retained externalized
  journal tail is still replayed to the application for slot-level dedup.
- Cost: every own emission pays a disk sync (`fsync`, plus `F_FULLFSYNC` on
  macOS for the key file). On slow disks this throttles ballot rounds
  (design §16); acceptable at seconds-scale slots.

## 7. Keys

- The Ed25519 seed lives in process memory for the node's lifetime — and,
  for the WASM build, in the module's linear memory (design §6). Anything
  that can read the process can sign as the node.
- On disk: `key_file` is exactly 32 raw seed bytes, mode `0600`, created
  atomically and durably (`src/node/keys.zig`). `Node.create` refuses a
  file of any other length (`KeyFileBad`) so a typo cannot mint a second
  identity, and `slcp key new` never overwrites. The mode is enforced at
  mint time AND at load time (S8b, user decision): a seed copied in by
  `cp`/`scp` or restored under umask 022 arrives `0644`, and `Node.create`
  / `AppNode.create` then **refuse to start** with `KeyFileTooPermissive`,
  ssh-style — the diagnostic names the mode, the path and the
  `chmod 600 <path>` that fixes it, because a seed every account in the
  group or on the machine can read is not one node's identity. `slcp key
  show` still prints the public key of such a file, with the same warning.
- The `identity` marker binds a `data_dir` to one (network, key) pair on
  the first create attempt (protocol §13): moving a data_dir under another
  key is `DataDirOtherNode`. The marker does **not** stop the *same* key
  from starting twice; the `lock` file does: `Store.open` holds an
  exclusive `flock` on `data_dir/lock` for the node's lifetime, so a second
  process (or a second node in the same process) over one data_dir is
  `DataDirBusy`, not two signers appending to one `own.log`.
- Neither guard reaches a **copied** data_dir or key file: the same
  `key_file` run from two directories, or on two machines, is two live
  signers with one identity — equivocation by operator error, which no peer
  can tell from a Byzantine node. Never copy `slcp.key` or `slcp-data/`;
  mint one key per machine (`slcp key new`). On macOS the duplicate would
  even bind the same `listen_port` (`reuse_address` sets `SO_REUSEPORT`
  there), so a port collision is not a signal you can rely on.
- No HSM / external signer in v1: ABI feature bit 1 (`external_signer`) is
  reserved and OFF.

## 8. Out of scope

Not addressed by v1 and not claimed:

- **Flow control and fairness** beyond the per-peer budgets in §3.
- **Peer discovery** — you list peers explicitly; there is no gossip of
  addresses.
- **History / archival** — the answering window is 16 slots; a node that
  falls further behind resyncs from the current state, it does not replay
  history.
- **DoS resistance beyond budgets** — a well-provisioned attacker on the
  port can degrade liveness of a small network (§2 is the mitigation).
- **Driver nondeterminism** — a `validate` / `combine` / `apply` that gives
  different answers on different nodes forks or diverges the network with
  no protocol-level signal; see `docs/determinism.md`.
- **Confidentiality** of statement contents.

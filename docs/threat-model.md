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
`currentSlot` and `listenPort` fields are advisory hints, and
`networkIdPrefix` (the first 8 bytes of the networkId) is a fast
wrong-network disconnect, **not a secret and not authentication**
(`schema/overlay.capnp`, protocol §12). Consequences:

- Anyone who can reach the listen port can connect, claim any `nodeId` in
  `Hello`, and send any frame.
- They cannot forge a statement (signatures, §1), but they can burn every
  per-peer budget in §3 and use the two unauthenticated answer paths
  (`getQset`, `getSlotState`) as amplification.
- Traffic is readable on the wire: statement contents are not confidential.

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

Per-peer budgets, copied from `src/node/overlay.zig` (protocol §12):

| What the peer can burn | Bound |
|---|---|
| inbound bytes | `inbound_rate_soft_cap_bytes_per_s = 256 * 1024` per peer (soft cap; a breach is a strike) |
| unanswered requests | `max_outstanding_requests = 64` |
| strikes before disconnect | `max_budget_strikes = 32` |
| concurrent inbound connections (all peers together) | `max_inbound_conns = 128`; over-cap accepts are closed before any allocation |
| our write queue toward a peer that stops reading | `max_write_queue_items = 1024` / `max_write_queue_bytes = 16 MiB`; overflow ⇒ disconnect |
| a connection that never sends `Hello` | `handshake_timeout_s` = 10 s absolute deadline on the read operation |
| frame size | `max_frame_bytes = 1 MiB`; larger ⇒ framing error ⇒ disconnect |

**Amplification surfaces.** `getQset` (answered with one cached qset frame,
bounded by depth ≤ 4 / ≤ 255 validators) and `getSlotState` (answered with at
most 64 of *our own* envelopes). Both are **per-request fan-out only**:
requests are never relayed, so one request yields at most one reply from the
node it was sent to. `dontHave` is ignored by the receiver (as built).

**Parking caps** (`src/engine/limits.zig`, `src/engine/pending.zig`): an
envelope citing an unknown qset hash parks until the qset arrives —
`max_pending_envelopes = 1024`, `max_pending_bytes = 8 MiB`, `max_per_node =
4`, FIFO eviction (each eviction is a `phase_event(parked_evicted)`).
EXTERNALIZE statements never park.

**Relevance filter** (protocol §4 step 8): statements whose signer is outside
the transitive quorum graph of your configuration are `ignored` before any
per-slot state is allocated — a stranger with a valid key cannot make you
store anything.

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
and normalize.

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

**Nomination participation rule** (design §11; the number-one "my network is
stuck" cause): consensus for a slot advances only while a quorum of
validators have proposals queued. A validator with nothing to propose is not
a failure, but it does not drive the slot either — the §0 counter program
proposes again after every applied slot for exactly this reason. A 1-of-1
self quorum lints with a warning and does externalize (dev / smoke use), but
a restart story needs at least two proposers.

## 6. Persistence failure ⇒ inert

The write-ahead discipline (design §10, `src/node/node.zig` `dispatch` /
`markFailed`): `persist_own_envelope` appends and fsyncs `own.log` **before**
the paired `broadcast_envelope` is sent. If that append fails (ENOSPC, I/O
error), or the `externalized.log` journal append fails, the node latches
**inert**: no further inputs are applied, no further effects are dispatched,
`waitExternalized` / `waitApplied` waiters are woken (the typed node reports
`error.NodeHalted`; `haltError()` names the cause). A node that cannot
persist must go silent — broadcasting an unpersisted statement is Byzantine
after the next crash (it could re-emit an older, conflicting statement).

- **Torn tail** (the file ends mid-record): repaired on recovery by
  truncating to the valid prefix; the node stays a validator. Safe because a
  torn final record was never broadcast.
- **Corrupt `own.log`** (a complete record fails its crc): the log is
  untrusted and the node runs as a **watcher for its lifetime** (v1
  as-built) — it can never emit a statement older than one it already
  broadcast, because it never emits.
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

# SLCP v1 protocol (normative)

This is the byte-level definition of SLCP v1 as a **citation index**: every
section names the source file that implements it and the vector file that
pins it. Where a fact is a literal (a domain tag, a preimage layout, a limit,
an enum arm) it is **copied** from the source, never paraphrased — Appendix A
lists exactly which sections are copies, and `zig build docs-smoke` (M6 S5b)
checks the enum arms and the tag literals against the code.

SLCP is a clean-room SCP-style federated Byzantine agreement protocol. It is
**not** Stellar-compatible: new wire format (Cap'n Proto, not XDR), new
preimages, no interop (design §1). stellar-core is the line-level *oracle*
for the state machines, not a peer.

## 0. Status and scope

- **`vectors/` is the definition; this prose is commentary** (design §13.4).
  When they disagree, the vectors win and this file has a bug.
- Overlay `protocolVersion = 1` (`src/node/wire.zig`: `pub const
  protocol_version: u32 = 1;`, carried in `Hello.protocolVersion`).
- **Raising any frozen number in §8 is a protocol-version event** (design
  §4.5), as is any change to a signed type (§3) or a domain tag (§2). See §15.
- Tiers of normativity used below:
  - *Consensus-normative*: bytes that are signed or hashed. Two nodes that
    disagree here cannot form a network (§1–§10).
  - *Engine-normative*: the input → effect contract every host must replay
    byte-identically (§11), pinned by the trace vectors.
  - *Host-normative for v1*: overlay and persistence formats that a second
    host implementation must match to interoperate (§12–§13).
  - *Non-normative*: `phase_event` effects, log text, CLI output.

## 1. networkId

Source: `src/crypto.zig` (`networkIdFromPassphrase`, `tag_network`).
Vector: `vectors/crypto.json` → `networkIds` (3 cases; e.g. passphrase
`"my-counter-app v1"` → `ba521500e3f3a00474d967e35089ee77e3ea0c1a628d25e1952a72f7e864a9dd`).

```
networkId = SHA-256("SLCP-NET-V1\x00" ‖ passphraseUtf8)
```

- The passphrase is pure configuration (`Node.Options.network`). The 32-byte
  networkId is mixed into every statement digest (§4) and **never
  transmitted**.
- `Hello.networkIdPrefix` carries only the **first 8 bytes** (§12) — a fast
  wrong-network disconnect, not a secret and not authentication.
- The empty passphrase is legal at this layer (vector case 3); `Node.create`
  refuses it (`NetworkPassphraseEmpty`) because it is never what a user means.

## 2. Domain-tag registry

Source: `src/crypto.zig` lines 9–13 (copied). Pinned by the crypto.zig test
`domain tags are 12 bytes and distinct`. **Frozen: never reused, never
resized.** Every tag is exactly 12 bytes; the two shorter names are padded
with NUL bytes to 12.

| Zig constant    | Literal                 | Hex                          | Used by |
|-----------------|-------------------------|------------------------------|---------|
| `tag_statement` | `"SLCP-STMT-V1"`        | `534c43502d53544d542d5631`   | statement digest (§4) |
| `tag_qset`      | `"SLCP-QSET-V1"`        | `534c43502d515345542d5631`   | qsetHash (§5) |
| `tag_gi`        | `"SLCP-GI-V1\x00\x00"`  | `534c43502d47492d56310000`   | leader election Gi (§7) |
| `tag_network`   | `"SLCP-NET-V1\x00"`     | `534c43502d4e45542d563100`   | networkId (§1) |

```zig
// src/crypto.zig — copied
pub const tag_statement: *const [12]u8 = "SLCP-STMT-V1";
pub const tag_qset: *const [12]u8 = "SLCP-QSET-V1";
pub const tag_gi: *const [12]u8 = "SLCP-GI-V1\x00\x00";
pub const tag_network: *const [12]u8 = "SLCP-NET-V1\x00";
```

## 3. Signed types (`schema/slcp.capnp`)

Source: `schema/slcp.capnp` (copied verbatim below). Generated bindings:
`src/gen/slcp.zig`. Vectors: `vectors/sanity.json` → `cases` (decode /
canonicality) and `statements` (§9).

The file header states the evolution rule: **appending any field reachable
from `Statement` changes canonical encodings and is therefore a consensus
version bump** — new domain tags, coordinated upgrade — never transparent
capnp evolution. No non-zero defaults anywhere (canonical encoding is
value-XOR-default, so a default change would silently change preimages).

```capnp
@0xd9ec6f612289f92e;
# slcp.capnp — SIGNED consensus types. FROZEN ON PUBLISH.
#
# EVOLUTION RULE: appending any field reachable from Statement changes
# canonical encodings and is therefore a CONSENSUS VERSION BUMP (new domain
# tags, coordinated upgrade) — never transparent capnp evolution.
# No non-zero defaults anywhere in this file: canonical encoding is
# value-XOR-default, so a default change would silently change preimages.
# See claude-design.md §4.

struct Ballot {
  counter @0 :UInt32;   # MUST be >= 1 on the wire. counter==0 is the engine-internal
                        # bottom placeholder and is NEVER transmitted (isSane rejects).
  value   @1 :Data;     # opaque; length in [1, maxValueBytes]
}

struct QuorumSet {
  threshold  @0 :UInt32;            # 1 <= threshold <= len(validators) + len(innerSets)
  validators @1 :List(Data);        # 32-byte ed25519 pubkeys, strictly ascending, unique
  innerSets  @2 :List(QuorumSet);   # sorted ascending by qsetHash; depth <= 4;
                                    # total validator entries across tree <= 255;
                                    # no duplicate node anywhere in the tree
}

struct Nomination {
  quorumSetHash @0 :Data;           # 32 bytes
  votes    @1 :List(Data);          # values; strictly ascending byte order (implies dedup);
                                    # nonempty; <= 64 entries
  accepted @2 :List(Data);          # same ordering rules; <= 64 entries.
                                    # Engine-emitted statements satisfy accepted ⊆ votes
                                    # (accepting adds to both sets, stellar-core semantics).
                                    # NOT disjoint — disjointness would break superset
                                    # freshness. Receivers require only sortedness.
}

struct Prepare {
  quorumSetHash @0 :Data;
  ballot        @1 :Ballot;
  prepared      @2 :Ballot;   # ABSENT POINTER == unset. Present => counter >= 1.
  preparedPrime @3 :Ballot;   # same; sanity: preparedPrime ⋦ prepared
                              # (strictly less AND value-incompatible)
  nC @4 :UInt32;              # 0 == unset; nC != 0 => nH != 0 and nC <= nH <= ballot.counter
  nH @5 :UInt32;              # 0 == unset; nH != 0 => prepared set and nH <= prepared.counter
}

struct Confirm {
  quorumSetHash @0 :Data;
  ballot    @1 :Ballot;       # counter >= 1
  nPrepared @2 :UInt32;       # >= 1
  nCommit   @3 :UInt32;       # sanity: 1 <= nCommit <= nH <= ballot.counter
  nH        @4 :UInt32;
}

struct Externalize {
  commit              @0 :Ballot;  # counter >= 1
  nH                  @1 :UInt32;  # >= commit.counter
  commitQuorumSetHash @2 :Data;    # qset used during CONFIRM (audit/reconstruction);
                                   # quorum math treats the sender as singleton {sender, 1}
}

struct Statement {
  nodeId    @0 :Data;         # 32-byte ed25519 pubkey of the signer
  slotIndex @1 :UInt64;
  pledges :union {
    unset       @2 :Void;     # discriminant 0: an all-zero message decodes here — REJECTED
    nominate    @3 :Nomination;
    prepare     @4 :Prepare;
    confirm     @5 :Confirm;
    externalize @6 :Externalize;
  }
}

struct Envelope {
  statementBytes @0 :Data;    # canonical flat capnp encoding of a Statement (§4.2);
                              # the signature covers THESE bytes — verifiers never
                              # re-canonicalize on the hot path
  signature      @1 :Data;    # 64-byte ed25519 over the digest in §4.2
}
```

**Three deliberate sanity rules stricter than stellar-core** (design §4.1;
`src/engine/statement.zig` module doc): nomination `votes` must be nonempty;
`preparedPrime` requires `prepared`; CONFIRM requires `nPrepared >= 1` and
`nCommit >= 1`. Their arms are flagged in §9.

## 4. Canonical form and the statement preimage

Sources: `src/canonical.zig` (header), `src/crypto.zig` (`statementDigest`,
`sign`, `verify`), `src/engine/pipeline.zig` (module doc: the receive order).
Vectors: `vectors/crypto.json` → `statements` (statementBytes, digest,
signature per case), `vectors/sanity.json` → `cases` (canonical / decodes
flags).

- **statementBytes** = the official Cap'n Proto canonical form of the
  `Statement`, produced by capnp-zig's schema-free `canonical` module
  (`capnpc.canonical.canonicalizeFlat`; the signing hot path uses
  `canonicalizeFlatFromBuilder`): a bare single segment, **no segment table**,
  byte-identical to `capnp convert binary:canonical`. Decoding uses the
  validating flat entry point `Message.initFlat`.
- **Preimage and digest** (copied from `src/crypto.zig`):

  ```
  digest = SHA-256("SLCP-STMT-V1" ‖ networkId ‖ statementBytes)
  ```

- **Signature**: Ed25519 (RFC 8032, deterministic) over the **32-byte
  digest** — never over the raw preimage (`crypto.zig` `sign`). Verification
  is over the **received** `statementBytes`; verifiers never re-canonicalize
  on the hot path.
- A wrong-network envelope implicitly fails verification: its digest differs.

**Normative receive order for `envelope_received`** (copied from the
`src/engine/pipeline.zig` module doc; design §4.2 with the one mechanical
reordering the design permits — the statement must be decoded before the
signature can be checked, because the verifying key *is* `statement.nodeId`):

```
 1. frame cap (§4.5) → insane
 2. validating decode of the Envelope frame (§4.5 ValidationOptions,
    nesting 32, traversal scaled to the frame cap) → insane
 3. statementBytes cap / signature length → insane
 4. validating flat decode of statementBytes (Message.initFlat) → insane
 5. checkStatementSane → insane
 6. Ed25519 verify over the RECEIVED statementBytes (§4.2; wrong-network
    envelopes implicitly fail — their digests differ) → invalid_signature
 7. strictCanonical structural walk on the SAME parse (§4.2) → insane
 8. relevance: sender outside the transitive quorum graph (§5.4) → ignored
 9. slot admission (max_live_slots; existing slots always accept) →
    over_limit
10. freshness vs the per-(node, protocol) latest via stored.isNewerOwned
    (§5.4 partial orders) → stale
11. qset resolution: unknown non-EXTERNALIZE qset hash parks (§5.4;
    EXTERNALIZE never parks — singleton qset) → parked_awaiting_qset /
    over_limit (per-node cap); evictions of PAST inputs emit
    phase_event(parked_evicted), never a second input_status
12. stored-bytes budget (§5.1 max_stored_statement_bytes) → over_limit
13. setAdvertised + storeLatest + forward_envelope (freshness advanced ⇒
    relay, §5.3) + protocol dispatch → applied
```

`strict_canonical` defaults to `true` (`Node.Options.strict_canonical`,
`EngineConfig.strictCanonical`). Turning it off is an interop-debugging aid
only: a non-canonical spelling of a statement is still signed by its sender
and still verifies, but strict receivers reject it as `insane`.

## 5. Quorum sets

Source: `src/engine/qset.zig` (`Error`, `validateAndNormalize`,
`canonicalBytes`, `hashNormalized`), `src/crypto.zig` (`qsetHash`).
Vectors: `vectors/qset.json` → `cases` (input → normalized + hash) and
`rejections` (each rejection names its error).

**Validation error names** (copied from `qset.zig` `pub const Error`):

```zig
pub const Error = error{
    EmptyQuorumSet,
    ThresholdOutOfRange,
    DepthExceeded,
    TooManyValidators,
    DuplicateNode,
    BadValidatorLength,
};
```

- `EmptyQuorumSet` — a level with no validators and no inner sets.
- `ThresholdOutOfRange` — threshold outside `[1, len(validators) + len(innerSets)]`.
- `DepthExceeded` — nesting deeper than `max_depth = 4` (§8).
- `TooManyValidators` — more than `max_total_validators = 255` validator
  entries across the whole tree (§8).
- `DuplicateNode` — the same node anywhere in the tree, at any level.
- `BadValidatorLength` — a validator entry that is not exactly 32 bytes
  (raised by `fromReader` when parsing the wire form).

`validateAndNormalize` is **reject, not repair**: it normalizes in place and
then validates the whole tree.

**Normalization** (design §4.3; `qset.zig`):

1. `validators` sorted ascending by bytes, unique.
2. A singleton inner set `{ threshold 1, [x] }` is flattened into its
   parent's `validators`.
3. `innerSets` sorted ascending by their `qsetHash`.
4. No present-but-empty `innerSets` pointer (an empty list is encoded as an
   absent pointer so the canonical bytes are unique).

**qsetHash** (copied from `src/crypto.zig` `qsetHash`; the canonical bytes
come from `qset.canonicalBytes`, which is `canonicalFlat` of the normalized
tree):

```
qsetHash = SHA-256("SLCP-QSET-V1" ‖ canonicalFlat(normalized qset))
```

No networkId is mixed in: qsets are network-independent, cacheable data.
This hash is what `Nomination.quorumSetHash` / `Prepare.quorumSetHash` /
`Confirm.quorumSetHash` / `Externalize.commitQuorumSetHash` carry, what
`getQset` requests by, and what `qsets/<hex64>.bin` is named by (§13).

**Lint** (design §12; `qset.zig` `lint`, `LintCode`, `minBlockingSize`) is
*not* consensus-normative — it judges the local configuration — but its
findings cross the WASM ABI (`slcp_lint_qset`, §14) as `host.capnp`
`LintFinding` frames, so the codes are frozen by ordinal. Copied from
`qset.zig`:

```zig
/// Ordinals are the wire `LintFinding.code` (host.capnp) — append-only.
pub const LintCode = enum {
    sub_majority_threshold, // error: two disjoint "quorums" can exist in your own slice
    below_two_thirds, // warning: threshold < ceil(2n/3) — weak Byzantine margin
    all_members_critical, // warning: threshold == n — any single member offline halts you
    critical_node, // warning: THIS validator is in every slice — it alone offline halts you
};
```

- `sub_majority_threshold` (error): `2t < n + 1` at the top level.
- `below_two_thirds` (warning): `t < ceil(2n/3)` at the top level.
- `all_members_critical` (warning): `t == n` and `n > 1` at the top level.
- `critical_node` (warning, one per node, ascending by bytes): a validator
  anywhere in the tree whose outage alone makes the tree unsatisfiable
  (`criticalNodes` / `isSatisfiableWithout`).
- `minBlockingSize(qs)`: the size of the smallest set of validators whose
  simultaneous outage makes the tree unsatisfiable — validator → 1, set →
  the sum of the `n − t + 1` smallest member costs. Reported by
  `slcp lint-quorum` as `min blocking set`.

Findings are emitted in a fixed order (the three top-level codes at most
once each in enum order, then `critical_node` per critical validator) so
the output is byte-stable. Vector: `vectors/lint.json` (8 cases, each with
`minBlocking` and `findings`). Lint never reasons about other nodes' qsets
(no cross-node intersection analysis — see `docs/threat-model.md` §4 and
`docs/quorum-recipes.md`).

## 6. Self-excision for leader weights

Source: `src/engine/qset.zig` (`exciseNode`), `src/engine/nomination.zig`
(module doc, `LeaderRound.qs`, `weight`). Vector: `vectors/leader.json`
(its `note`: every result is computed over the self-excised round qset).

Leader weights for **other** nodes are computed over the **self-excised**
local qset — stellar-core `normalizeQSet(myQSet, &localID)` semantics:

- At every level where the local node appears in `validators` it is removed
  and **that level's threshold is decremented** by the number of entries
  removed.
- The copy is re-run through `validateAndNormalize` (singleton-inner
  flattening + canonical ordering).
- The result is **null** when the excised tree is unusable — the whole set
  emptied (a singleton-self qset), or some level's threshold fell to 0 or its
  member list emptied. With a null excised set every node but the local one
  weighs 0.
- The local node never consults the tree: its own weight is pinned to
  `maxInt(u64)` ("local node is in all quorum sets").

## 7. Leader election

Source: `src/crypto.zig` (`gi`, `GiTag`), `src/engine/nomination.zig`
(`isNeighbor`, `priority`, `roundLeader`, `RoundLeaders`, `pickLeaderValue`),
`src/engine/local_node.zig` (`nodeWeight`), `src/engine/engine.zig`
(`timeoutMs`). Vectors: `vectors/crypto.json` → `gi` (6 cases),
`vectors/leader.json` → `cases` (9) and `valuePicks` (5).

**Gi preimage layout** (copied from `src/crypto.zig`):

```
Gi(tag, m) = first 8 bytes big-endian of
  SHA-256("SLCP-GI-V1\x00\x00" ‖ slot:u64be ‖ prevValue ‖ tag:u32be ‖ round:u32be ‖ m)
```

with `pub const GiTag = enum(u32) { neighbor = 1, priority = 2, value_hash = 3 };`.

The layout is pinned independently of `crypto.zig` by its test
`gi byte layout pinned against hand-derived literal` (expected value derived
with python3 hashlib, copied here):

```
Inputs: tag = priority (2), slot = 1, prevValue = "prev", round = 0, m = "node".
preimage = 534c43502d47492d56310000              ("SLCP-GI-V1\0\0")
           0000000000000001                      (slot 1, u64 BE)
           70726576                              ("prev")
           00000002                              (tag 2 priority, u32 BE)
           00000000                              (round 0, u32 BE)
           6e6f6465                              ("node")
sha256(preimage) = e5f9611891f28bf7ca6316e709df83dc02b3212692be2db991b15dfa46186914
gi = first 8 bytes big-endian = 0xe5f9611891f28bf7
```

**Rules** (`nomination.zig`, `local_node.zig`):

- `weight(v)`: `nodeWeight` over the excised tree (§6) — the product of
  `threshold / members` along the nesting path from the root to the node,
  fixed-point with `1.0 == maxInt(u64)`, floor at each level; first match
  wins (validators before inner sets); 0 when absent. Self = `maxInt(u64)`.
- `v` is a **neighbor** this round iff `weight(v) > 0` and
  `Gi(1, v) <= weight(v)` (inclusive, as in the oracle).
- `priority(v)` = `Gi(2, v)` if neighbor, else 0.
- The round leader is the maximum-priority candidate among the local node
  first, then every node of the excised tree in declaration order; **ties
  resolve to the lowest NodeId** (the oracle keeps the whole tied set; a
  64-bit tie is a ~2^-64 event). No candidate with priority > 0 ⇒ no leader
  this round (fast-forward).
- **Accumulating leaders**: the leader set only grows across rounds; a round
  whose leader is already followed adds nothing.
- **Value pick**: among the leader's `accepted` (falling back to `votes` only
  when no valid accepted value existed), the value with the maximum
  `Gi(3, value)`; **ties keep the later index** (the oracle's
  `curHash >= newHash`).
- **Timeout schedule** (copied from `engine.zig`):
  `timeout(n) = min(1000·(n+1), cap)` ms, `cap = timeout_cap_ms` (60 s by
  default and by frozen maximum, §8).

## 8. Frozen wire limits

Source: `src/engine/limits.zig` (copied). Vector: `vectors/sanity.json`
(the `statements` section exercises the value-length and list-length
limits).

**Protocol-frozen constants** — raising any of them is a protocol-version
event:

| Constant | Value | Meaning |
|---|---|---|
| `frozen_max_value_bytes_cap` | `65536` | hard cap on `max_value_bytes` (64 KiB) |
| `frozen_max_nomination_values` | `64` | `votes` / `accepted` entries each |
| `frozen_max_qset_depth` | `4` | `= qset.max_depth` |
| `frozen_max_qset_validators` | `255` | `= qset.max_total_validators` |
| `frozen_max_statement_bytes` | `256 * 1024` | largest `statementBytes` (256 KiB) |
| `frozen_max_frame_bytes` | `1024 * 1024` | largest overlay frame (1 MiB, §12) |
| `frozen_timeout_cap_ms` | `60_000` | timeout schedule cap (60 s) |

**Engine configuration** (`Limits`, "configuration, not protocol" — the
omakase defaults):

```zig
pub const Limits = struct {
    max_value_bytes: u32 = 4096, // config may lower; never above frozen cap
    max_nomination_values: u32 = frozen_max_nomination_values,
    max_pending_envelopes: u32 = 1024,
    max_pending_bytes: u32 = 8 * 1024 * 1024,
    max_live_slots: u32 = 64,
    max_cached_qsets: u32 = 1024,
    timeout_cap_ms: u32 = frozen_timeout_cap_ms,
    max_stored_statement_bytes: u32 = 20 * 1024 * 1024,
};
```

`limits.validate` is the rule: configuration may **lower** `max_value_bytes`,
`max_nomination_values` and `timeout_cap_ms`, never raise them past the
frozen caps, and never set them to 0 (`BadValueBytes`, `BadNominationValues`,
`BadTimeoutCap`). In `host.capnp` `Limits`, `0` means "engine default".

## 9. Statement sanity

Source: `src/engine/statement.zig` (`InsaneReason`, `checkStatementSane`).
Vector: `vectors/sanity.json` → `statements` (27 cases; every arm has at
least one case; the `insane` field is the arm's `@tagName`, so renaming an
arm is a vector-regeneration event).

`checkStatementSane` returns the **first** failing rule in a fixed check
order (the vectors pin that order). The 20 arms, copied from
`statement.zig` in declaration order, with the check that raises each:

| Arm | Raised when |
|---|---|
| `decode_error` | capnp traversal failed mid-walk (defense in depth — callers run the validating decode first) |
| `bad_node_id_length` | `nodeId` is not exactly 32 bytes |
| `unset_pledges` | pledges union discriminant 0 (an all-zero message decodes here) |
| `unknown_pledges_tag` | pledges union discriminant above any known arm |
| `bad_quorum_set_hash_length` | `quorumSetHash` / `commitQuorumSetHash` is not exactly 32 bytes |
| `bad_value_length` | a ballot value or nomination value has length outside `[1, limits.max_value_bytes]` |
| `zero_ballot_counter` | a present ballot has `counter == 0` |
| `empty_votes` | nomination `votes` empty — **STRICTER** than stellar-core |
| `unsorted_votes` | nomination `votes` not strictly ascending byte order |
| `too_many_votes` | nomination `votes` exceed `limits.max_nomination_values` |
| `unsorted_accepted` | nomination `accepted` not strictly ascending byte order |
| `too_many_accepted` | nomination `accepted` exceed `limits.max_nomination_values` |
| `prepared_prime_without_prepared` | `preparedPrime` present without `prepared` — **STRICTER** than stellar-core |
| `prepared_prime_not_less_and_incompatible` | `!(preparedPrime ⋦ prepared)`: must be `<=` AND value-incompatible |
| `bad_prepare_nh` | `nH != 0` without `prepared`, or `nH > prepared.counter` |
| `bad_prepare_nc` | `nC != 0` without (`nH != 0` and `nC <= nH <= ballot.counter`) |
| `zero_confirm_n_prepared` | CONFIRM `nPrepared == 0` — **STRICTER** than stellar-core |
| `zero_confirm_n_commit` | CONFIRM `nCommit == 0` — **STRICTER** than stellar-core |
| `bad_confirm_counters` | CONFIRM `!(nCommit <= nH <= ballot.counter)` |
| `bad_externalize_nh` | EXTERNALIZE `nH < commit.counter` |

Check order per pledge kind (from `checkInner`): nodeId length → union tag →
(nominate) qset hash → votes empty → votes count → votes sorted/length →
accepted count → accepted sorted/length; (prepare) qset hash → ballot →
prepared → preparedPrime → prime-without-prepared → less-and-incompatible →
nH → nC; (confirm) qset hash → ballot → nPrepared → nCommit → counters;
(externalize) commit qset hash → commit ballot → nH. Note the ordering
nuance visible in the vectors: for a nomination, `too_many_votes` is checked
*before* the per-entry length/sortedness of `votes`.

Receivers require only sortedness of `accepted`: `accepted ⊆ votes` is an
emitter property, **not** checked here. Unknown qset hashes are **not**
insane — they park (§4 step 11).

## 10. Freshness

Source: `src/engine/statement.zig` (`isNewerStatement`,
`isNewerNomination`, `compareBallots`). Vector: `vectors/traces/insane-and-stale.bin`
(the `stale` / `ignored` input_status paths).

`isNewerStatement(old, new)` is true iff `new` strictly supersedes `old` in
its protocol's partial order (same node, same slot):

- Nomination and ballot statements never compare newer against each other.
- **Nomination**: both `votes` and `accepted` must be superset-or-equal of
  the old lists, and at least one must strictly grow.
- **Ballot**: statement type `PREPARE < CONFIRM < EXTERNALIZE`. Within a
  type: PREPARE by lexicographic `(ballot, prepared, preparedPrime, nH)`
  with absent < present; CONFIRM by `(ballot, nPrepared, nH)`; ballots
  compare by `(counter, value bytes)`.
- **Two EXTERNALIZE statements are never newer** than each other ("can't have
  duplicate EXTERNALIZE").

Engine freshness is the only dedup: hosts keep no seen-cache (§12 relay).
Watchdog lesson (HANDOFF §6): the engine legitimately re-emits EXTERNALIZE
for a slot with a grown `nH`, so two of a node's EXTERNALIZE envelopes may
differ in bytes without either being "newer". Judge EXTERNALIZE pairs by
**committed value** — different values are a fork; different `nH` is normal.

## 11. Engine boundary

Source: `src/engine/engine.zig` (`Input`, `Effect`, `InputStatus`,
`PhaseKind`, `Config`, `TimerId`), `src/engine/host_codec.zig` (the
host.capnp codec and trace format), `schema/host.capnp`. Vectors:
`vectors/traces/*.bin` with `vectors/traces/FORMAT.md`.

**Contract** (§5.1, copied from the `engine.zig` module doc): feed exactly
ONE input via `pushInput`, then drain ALL effects (`popEffect` →
`commitEffect` two-phase, borrowed until commit) before the next input.
Exactly one `input_status` effect per input, always the **final** effect of
its drain. Effects appear in the normative order — in particular
`persist_own_envelope` always precedes the `broadcast_envelope` for the same
statement. The engine is a pure function of `(config, input sequence)` →
effect sequence, modulo the driver (§8 of the design), whose calls are
deterministic by contract (`docs/determinism.md`).

Copied from `src/engine/engine.zig`:

```zig
pub const TimerId = enum(u8) { nomination = 0, ballot = 1 };

/// §5.2 — the input union. Byte slices are BORROWED for the duration of the
/// pushInput call; the engine copies what it keeps.
pub const Input = union(enum) {
    /// Raw Envelope frame bytes from the network (untrusted).
    envelope_received: struct { bytes: []const u8 },
    /// Host timer (slot, id) armed by an earlier arm_timer effect has fired.
    timer_fired: struct { slot: u64, timer: TimerId },
    /// Application proposes: start/continue nomination for `slot`.
    nominate: struct { slot: u64, value: []const u8, prev_value: []const u8 },
    /// Host answers an earlier request_qset effect.
    qset_received: struct { bytes: []const u8 },
    /// Startup only, before any other input: replay own persisted envelope.
    restore_own_envelope: struct { bytes: []const u8 },
    /// Drop all state for slots < max_slot (checkpoint / GC).
    purge_slots: struct { max_slot: u64 },
};

pub const InputStatus = enum(u16) {
    applied,
    stale,
    invalid_signature,
    insane,
    parked_awaiting_qset,
    over_limit,
    ignored,
};

pub const PhaseKind = enum(u16) {
    nominating,
    candidate_updated,
    started_ballot,
    accepted_prepared,
    confirmed_prepared,
    accepted_commit,
    heard_from_quorum,
    parked_evicted,
};

/// §5.3 — the effect union. Byte payloads are OWNED by the effect queue;
/// borrowed by the host between popEffect and commitEffect.
pub const Effect = union(enum) {
    pub const SlotBytes = struct { slot: u64, bytes: []u8 };

    persist_own_envelope: SlotBytes,
    broadcast_envelope: SlotBytes,
    forward_envelope: SlotBytes,
    arm_timer: struct { slot: u64, timer: TimerId, delay_ms: u32 },
    cancel_timer: struct { slot: u64, timer: TimerId },
    request_qset: struct { hash: [32]u8 },
    externalized: SlotBytes,
    input_status: struct { code: InputStatus },
    phase_event: struct { slot: u64, kind: PhaseKind, detail: u64 },
    ...
};

pub const Config = struct {
    network_id: [32]u8,
    node_id: [32]u8,
    /// null => watcher mode: full tracking, zero emissions.
    secret_seed: ?[32]u8,
    /// Pre-validated + normalized (qset.validateAndNormalize).
    quorum_set: qset.QuorumSetOwned,
    strict_canonical: bool = true,
    limits: limits_mod.Limits = .{},
};
```

**`InputStatus` meanings** (the §4 receive order names which step yields
each):

| Arm | Meaning |
|---|---|
| `applied` | the input changed engine state (or was a well-formed no-op the protocol accepted) |
| `stale` | an envelope not newer than the stored latest for its (node, protocol) (§10) |
| `invalid_signature` | Ed25519 verification over the received `statementBytes` failed (wrong key, wrong network, tampered bytes) |
| `insane` | frame cap, decode, sanity (§9) or strict-canonical failure |
| `parked_awaiting_qset` | the statement references an unknown qset hash; parked, `request_qset` emitted |
| `over_limit` | a budget refused it: live-slot cap, parking caps, stored-bytes budget |
| `ignored` | the signer is outside the transitive quorum graph (relevance filter), or the input is otherwise irrelevant |

`phase_event` is **non-normative** (observability): the trace vectors mark it
as OBSERVABLE (record kind 3) and a replay may pin or ignore it. Everything
else is NORMATIVE (kind 2) and must replay byte-exactly.

**SLCPTRC1 trace format** (copied from `vectors/traces/FORMAT.md`; the
normative definition lives in the `host_codec.zig` header):

```
magic   : 8 bytes ASCII "SLCPTRC1"
records : until EOF, each
  kind    : u8
  len     : u32 little-endian
  payload : len bytes — one framed host.capnp message
            (capnp segment table + content)
```

| kind | payload            | role                                            |
|------|--------------------|-------------------------------------------------|
| 0    | EngineConfig frame | exactly one, always the first record            |
| 1    | Input frame        | fed to the engine in record order               |
| 2    | Effect frame       | NORMATIVE: replay must match byte-exactly       |
| 3    | Effect frame       | OBSERVABLE (`phase_event` only): replay may pin or ignore |

The effect records of one input sit between that input's record and the next
input record, in engine queue order; the input's single `input_status` effect
is always the last of them. Limits fields in the EngineConfig are written as
actual values (0 = engine default). Scenarios: `single-node-1of1.bin`,
`insane-and-stale.bin`, `qset-park-resume.bin`, `timer-bump.bin`.

**Failure discipline** (§7.2): any `EffectQueue` budget breach
(`max_effects = 4096`, `max_bytes = 16 MiB`), OOM, or non-protocol error
marks the engine failed (sticky); `pushInput` then always returns
`error.EngineFailed`.

## 12. Overlay

Source: `schema/overlay.capnp` (copied), `src/node/wire.zig` (frame codec),
`src/node/overlay.zig` (sockets, budgets, backoff), `src/node/node.zig`
(relay policy, catch-up, anti-entropy). Vector:
`vectors/framing/framing_fixtures.json` (the capnp segment framing, vendored
verbatim from capnp-zig — see `vectors/framing/PROVENANCE.md`).

Flood gossip over TCP with **standard capnp segment framing** (unpacked,
stream-delimited; capnp-zig's `rpc.wire.framing.Framer` with
`overlay.framer_options`), **1 MiB frame cap**. Deliberately not capnp RPC.
Symmetric: every node listens *and* dials.

```capnp
@0xd1e0e224689f7c4d;
# overlay.capnp — transport frames. Normal append-only capnp evolution.
# TRUST MODEL: only envelope signatures are authenticated. Hello fields are
# unauthenticated hints. See claude-design.md §9.

using Slcp = import "slcp.capnp";

struct Frame { union {
  unset        @0 :Void;              # rejected
  hello        @1 :Hello;             # first frame each direction, exactly once
  envelope     @2 :Slcp.Envelope;
  getQset      @3 :Data;              # 32-byte hash
  qset         @4 :Slcp.QuorumSet;
  dontHave     @5 :DontHave;          # negative reply — requesters never hang
  getSlotState @6 :UInt64;            # 0 = "latest externalized you have"
  slotState    @7 :SlotState;
  ping         @8 :UInt64;
  pong         @9 :UInt64;
}}

struct Hello {
  protocolVersion @0 :UInt32;         # = 1
  networkIdPrefix @1 :Data;           # first 8 bytes of networkId — fast wrong-network
                                      # disconnect; not a secret, not authentication
  nodeId          @2 :Data;           # advisory, UNAUTHENTICATED
  currentSlot     @3 :UInt64;         # advisory
  listenPort      @4 :UInt16;         # for reciprocal dialing
}

struct DontHave  { kind @0 :UInt8; id @1 :Data; }
struct SlotState { slot @0 :UInt64; envelopes @1 :List(Slcp.Envelope); }  # <= 64 envelopes
```

**Hello semantics** (`overlay.zig` `runConnection`): each side sends its own
Hello first, then reads the peer's first frame, which must be a Hello with
`protocolVersion == 1` and a matching `networkIdPrefix` — otherwise
disconnect. `nodeId`, `currentSlot` and `listenPort` are unauthenticated
hints. There is **no transport authentication in v1** — see
`docs/threat-model.md`.

**Frame codec rules** (`wire.zig` header — the one place these conversions
live): an `envelope` frame carries a nested `Slcp.Envelope`, but the engine
speaks *standalone framed Envelope message bytes*; encode copies the two Data
fields (`statementBytes`, `signature`) into the nested struct and decode
re-serializes them back into a standalone message. The envelope frame is
never signed over its own framing — only `statementBytes` are — so the
re-serialization is safe by construction. `qset` frames get the same
treatment (bounded by depth ≤ 4, ≤ 255 validators). `slotState` carries at
most `max_slot_state_envelopes = 64` envelopes.

**Budgets** (copied from `src/node/overlay.zig` constants):

| Constant | Value |
|---|---|
| `default_read_buffer_size` | `256 * 1024` |
| `inbound_rate_soft_cap_bytes_per_s` | `256 * 1024` (256 KiB/s per peer, soft) |
| `max_outstanding_requests` | `64` |
| `max_frame_bytes` | `1 << 20` (1 MiB) |
| `max_write_queue_items` / `max_write_queue_bytes` | `1024` / `16 * 1024 * 1024` (overflow ⇒ disconnect) |
| `max_inbound_conns` | `128` (over-cap accepts closed before any allocation) |
| `handshake_timeout_s` | 10 s, as an `std.Io.Timeout` on the read operation (absolute across the whole handshake) |
| `max_budget_strikes` | `32` consecutive breaches ⇒ disconnect |
| reconnect backoff | exponential 1 s → 60 s (`max_backoff_shift = 6`, capped) plus deterministic per-peer jitter < 1 s (Wyhash over the attempt counter — no clock, no RNG) |

**Relay policy — as built** (`src/node/node.zig` `dispatch`, `onRecv`,
`onPeerUp`, `resyncLoop`; this is normative for v1 and supersedes design
§9.2's request_qset bullet):

- `broadcast_envelope` → send to **all** connected peers.
- Inbound `envelope` → `envelope_received` input → the engine emits
  `forward_envelope` iff the envelope advanced per-node freshness (§10) →
  relay to all peers **except the source**. Engine freshness *is* the dedup;
  hosts keep no seen-cache.
- `request_qset` → **broadcast `getQset` to all connected peers** (any holder
  answers; parked envelopes resolve on the first `qset` reply). The design's
  source-first / round-robin-on-`dontHave` / give-up-after-3 policy was not
  implemented.
- `dontHave` is **ignored** (the flood covers the requester; parked envelopes
  expire by the parking caps).
- `getQset` is answered from the persisted qset cache (§13) or with
  `dontHave{kind 0, id = hash}`. Only qsets the node itself **requested** are
  persisted on receipt (disk-fill guard); the engine is always fed.
- `getSlotState(s)` is answered with up to 64 of the node's **own** latest
  envelopes (ballot statements preferred) for the requested window; `0`
  means "latest externalized you have". Requests are never relayed.
- **On connect** (after the Hello exchange): send own latest envelopes for
  all live slots to that peer, then `getSlotState(0)`. Externalized slots
  keep answering with EXTERNALIZE statements for the 16-slot answering window
  (§13).
- **Periodic anti-entropy** (`resync_interval_ms = 3_000`): every 3 s each
  node re-floods its own latest envelopes for live slots and broadcasts
  `getSlotState(0)`. The engine emits only on state change, so this is the
  liveness backstop after a partition heals with connections intact; receivers
  dedup via freshness, so there is no relay amplification.
- Zero-frame placeholder envelopes the engine emits as self-records are
  dropped at the single `emitEnvelope` chokepoint (HANDOFF §6: a contract,
  not an optimization).
- `ping` is answered with `pong` of the same payload; `pong` is ignored.

## 13. Persistence

Source: `src/node/store.zig` (header + `Recovery`), `src/node/node.zig`
(identity marker, `purge_window`, compaction), `src/node/keys.zig`.
**No vector yet** — the cross-language on-disk fixture is the deferred Deno
track's guard; until then `store.zig`'s tests (round-trip, last-wins dedup,
torn tail, crc) are the pin.

**`data_dir` layout** (as built, M6):

```
slcp-data/
  identity           # slcp-identity-v1 marker: binds the dir to (network, key)
  own.log            # append-only: (u64 slot, u32 len, envelope bytes, u32 crc32); fsync'd
  externalized.log   # append-only: (u64 slot, u32 len, value, u32 crc32); fsync'd —
                     # the app-visible journal AND the crash-fallback slot bound
  qsets/<hex64>.bin  # verified foreign qset cache (best-effort, no fsync)
  own.log.compact / externalized.log.compact   # compaction scratch (harmless leftovers)
```

**Record framing** (both logs; copied from the `store.zig` header):
little-endian `u64` slot, little-endian `u32` payload length, `len` payload
bytes, little-endian `u32` crc32 (IEEE, over `slot ++ len ++ payload`).
`own.log` payloads are standalone framed Envelope message bytes;
`externalized.log` payloads are the raw externalized value bytes.

**Recovery classification** (`store.zig` header):

- **Torn tail** — the file physically ends mid-record (short header, or the
  declared payload+crc extends past EOF). The routine power-loss artifact:
  persist-precedes-broadcast means a torn final record was never broadcast,
  so the valid prefix is fully trustworthy. `recover()` truncates the log
  back to the prefix and sets `torn_tail_repaired`; the node stays a
  validator (loud log).
- **True corruption** — a structurally complete record whose crc mismatches.
  The log is untrusted (`own_log_corrupt`); the log is still truncated to the
  prefix before the bad record. For `own.log` the v1 fallback is **watcher
  mode for the node's lifetime** (design §10 as-built).
- `own.log` records are deduplicated to the **last record per (slot, kind)**,
  kind ∈ {`nom`, `ballot`} (the ballot family = prepare / confirm /
  externalize), returned ascending by (slot, kind).
- `externalized.log` yields `externalized_hwm` (highest valid slot) and
  `ext_tail` (the compaction-bounded valid records, last-wins per slot).

**Identity marker** (`node.zig`, M6): the file `identity` in `data_dir`,
format copied from the source:

```
slcp-identity-v1\n<hex16 of networkId[0..8]>\n<hex64 node_id>\n
```

Written on the **first create attempt** (before `Store.open` and before
listening — so a data_dir is bound to its network + key even if that create
later fails), compared on every later create: a different network prefix is
`DataDirOtherNetwork`, a different node id is `DataDirOtherNode`, a malformed
marker is `DataDirUnusable`. A watcher skips the node-id comparison (its id
is ephemeral).

**Restart order** (`Node.create`, M6 S3): (1) the delivery frontier comes
from the journal high-water mark; (2) the journal tail is replayed to the app
through the single delivery chokepoint in ascending slot order; (3) then the
`own.log` latest records are fed as `restore_own_envelope` inputs before any
other input; (4) go live: listen, engine thread, anti-entropy thread.

**Write path**: `persist_own_envelope` → append + fsync `own.log` → only then
the paired `broadcast_envelope`. A failed append latches the node **inert**
(no further inputs, no further effects, app waiters woken): a node that
cannot persist must go silent. `externalized` → append + fsync
`externalized.log` → deliver to the app.

**GC / answering window**: `purge_window = 16`. When the delivered frontier
`F >= 16`, the node issues `purge_slots(F − 15)` and compacts both logs to
`slot >= F − 15` (atomic temp-file + fsync + rename-over). A catch-up gap
wider than the window is declared unrecoverable and skipped loudly.

**Qset cache**: `qsets/<lower-case hex of qsetHash>.bin` holds the framed
`QuorumSet` message bytes; best-effort, no fsync, written only for hashes the
node requested.

**Key file** (`keys.zig` header): exactly **32 raw seed bytes** (not hex),
mode `0600`, created atomically and durably (temp file → fsync, plus
`F_FULLFSYNC` on macOS → link into place). Any other length is
`error.BadKeyFile`; `createNew` never overwrites (`KeyFileExists`). The
public key (node id) is derived from the seed.

## 14. WASM host ABI summary

Source: `src/wasm/slcp_host_abi.zig` (copied export/import lines),
`schema/host.capnp`. Frozen-surface parse: `tests/abi/abi_contract_test.zig`
(and `docs/api-snapshot.txt`'s `slcp-abi.*` lines). Rationale: design §7.

Boundary payloads are capnp-encoded `host.capnp` messages (§11), so the
export surface stays small and the same frames double as the trace-vector
artifacts. All scalars are `u32`; `u64` slots cross as `(lo, hi)` pairs.

- `abi_version = 1`, `abi_min_version = 1`, `abi_max_version = 1`.
- `feature_flags = 0b101`: bit 0 = driver imports required (this ABI is NOT
  zero-import), bit 1 = external_signer (reserved, OFF in v1), bit 2 = lint
  exports present.
- `version_string = "slcp-core " ++ zig_version_string`.

**The 23 exports** (copied from the `export fn` lines):

```zig
export fn slcp_alloc(len: u32) u32
export fn slcp_free(ptr: u32, len: u32) void
export fn slcp_buf_free(ptr: u32, len: u32) void
export fn slcp_abi_version() u32
export fn slcp_abi_min_version() u32
export fn slcp_abi_max_version() u32
export fn slcp_feature_flags_lo() u32
export fn slcp_feature_flags_hi() u32
export fn slcp_version_string(out_ptr_ptr: u32, out_len_ptr: u32) void
export fn slcp_last_error_code() u32
export fn slcp_last_error_ptr() u32
export fn slcp_last_error_len() u32
export fn slcp_clear_error() void
export fn slcp_error_take(out3: u32) void
export fn slcp_engine_new(config_ptr: u32, config_len: u32) u32
export fn slcp_engine_free(handle: u32) void
export fn slcp_engine_push_input(handle: u32, ptr: u32, len: u32) u32
export fn slcp_engine_pop_effect(handle: u32, out_ptr_ptr: u32, out_len_ptr: u32) u32
export fn slcp_engine_pop_commit(handle: u32) void
export fn slcp_engine_effect_count(handle: u32) u32
export fn slcp_engine_effect_bytes(handle: u32) u32
export fn slcp_qset_hash(ptr: u32, len: u32, out32_ptr: u32) u32
export fn slcp_lint_qset(ptr: u32, len: u32, out_ptr_ptr: u32, out_len_ptr: u32) u32
```

**The 3 driver imports** (module `"slcp_driver"`, copied; synchronous
because SCP calls the driver *inside* envelope processing):

```zig
/// 0 invalid | 1 maybeValid | 2 valid | 3 DRIVER FAULT
extern "slcp_driver" fn validate_value(slot_lo: u32, slot_hi: u32, ptr: u32, len: u32, is_nomination: u32) u32;
/// `list` is a ValueList frame; host writes the result via slcp_alloc and
/// stores (ptr, len) in the out params. Nonzero return = driver fault.
extern "slcp_driver" fn combine_candidates(slot_lo: u32, slot_hi: u32, list_ptr: u32, list_len: u32, out_ptr_ptr: u32, out_len_ptr: u32) u32;
/// 0 none | 1 some | other = driver fault
extern "slcp_driver" fn extract_valid_value(slot_lo: u32, slot_hi: u32, ptr: u32, len: u32, out_ptr_ptr: u32, out_len_ptr: u32) u32;
```

**Memory contract** (module doc): every buffer the host hands IN is copied
before the call returns; every buffer handed OUT is either **BORROWED**
(`slcp_engine_pop_effect`: valid until `slcp_engine_pop_commit`) or **OWNED**
by the host (`slcp_lint_qset`, `slcp_version_string`: release with
`slcp_buf_free`). Error text from `slcp_last_error_ptr` / `slcp_error_take`
is STATIC (never freed). `slcp_alloc(0)` returns a valid nonzero pointer.

**Sticky error codes** (`ErrorCode`, cleared before each mutating call):
`none = 0`, `out_of_memory = 1`, `bad_handle = 2`, `decode_failed = 3`,
`engine_failed = 4`, `invalid_config = 5`, `invalid_qset = 6`,
`effect_budget = 7`, `driver_fault = 8`, `no_effect = 9`. An out-of-range
driver return is a `driver_fault`; a `combine_candidates` /
`extract_valid_value` that returns an empty result is also a fault.

## 15. Version events

- **Consensus version bump** (new domain tags, new networkId, coordinated
  upgrade): any change to a `schema/slcp.capnp` field reachable from
  `Statement` or `Envelope`; any frozen limit in §8; any domain tag in §2;
  the Gi layout (§7) or the digest preimage (§4); any change to an
  `AppNode` `Command`'s encoding (auto-codec field order/width, or a custom
  codec) — see `docs/driver-upgrade.md` §5.
- **Free, append-only evolution**: `schema/overlay.capnp` and
  `schema/host.capnp` (unsigned; non-zero defaults allowed), the WASM ABI
  (versioned by `abi_version` with min/max negotiation), the `LintCode`
  enum (append-only ordinals), on-disk record kinds.
- Overlay `protocolVersion` is bumped only for incompatible frame changes.

## Appendix A — copied, not paraphrased

What `zig build docs-smoke` (M6 S5b) enforces against this file, and what a
maintainer must re-copy from source rather than edit by hand:

| Section | Copied from | Pinned by |
|---|---|---|
| §1 networkId preimage, §2 the four tag literals + hex | `src/crypto.zig` | `vectors/crypto.json`, crypto.zig tag test; docs-smoke tag needles |
| §3 signed struct blocks | `schema/slcp.capnp` | `vectors/sanity.json` |
| §4 digest line, receive order | `src/crypto.zig`, `src/engine/pipeline.zig` | `vectors/crypto.json` `statements` |
| §5 error names, `LintCode` arms | `src/engine/qset.zig` | `vectors/qset.json`, `vectors/lint.json`; docs-smoke enum needles |
| §7 Gi layout + hand-derived hex | `src/crypto.zig` | `vectors/crypto.json` `gi`, `vectors/leader.json` |
| §8 frozen limits table + `Limits` defaults | `src/engine/limits.zig` | `vectors/sanity.json`; docs-smoke needles `65536` / `4096` / `255` / `60_000` |
| §9 the 20 `InsaneReason` arms | `src/engine/statement.zig` | `vectors/sanity.json` `statements`; docs-smoke enum needles |
| §11 `Input` / `Effect` / `InputStatus` / `PhaseKind` / `Config`, SLCPTRC1 | `src/engine/engine.zig`, `vectors/traces/FORMAT.md` | `vectors/traces/*.bin`; docs-smoke enum needles |
| §12 `overlay.capnp`, budget constants | `schema/overlay.capnp`, `src/node/overlay.zig` | `vectors/framing/framing_fixtures.json` |
| §13 record framing, identity marker | `src/node/store.zig`, `src/node/node.zig` | store.zig tests (no vector yet) |
| §14 the 23 exports, 3 imports, flags, error codes | `src/wasm/slcp_host_abi.zig` | `tests/abi/abi_contract_test.zig`, `docs/api-snapshot.txt` |

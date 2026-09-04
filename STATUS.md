# Project Status

**Snapshot date:** 2026-09-03

This file distinguishes released code, the prior v0.2.0 candidate, and current
feature work. It is a snapshot, not a guarantee of fitness: this remains an
experimental project, no production use is recommended, and no license is
granted.

## Repository baseline

| State | Revision | What it contains |
|---|---|---|
| Released | `v0.1.0` at `916907a` (2026-09-01) | First engine, native node, typed application layer, CLI, examples/counter, protocol docs, conformance and release gates. |
| Pre-sprint `main` baseline | `cf3b84b` (2026-09-02), two commits after the tag | Post-tag documentation corrections plus E1 of the examples track: `examples/registry`. |
| Hardening baseline | local `main` at `87d7083` (2026-09-03) | Exact qset lifecycle, bounded native ingress, restart/purge hardening, stronger fuzz/E2E evidence, canonical project state, and its recorded proof. |
| Package payload freeze | `1b68041` (not pushed or tagged) | Adds the bounded best-effort on-disk qset answering cache and its Experimental diagnostics on top of the hardening baseline. |
| Local repository candidate | code tip `0f39869` plus hash-neutral release records (not pushed or tagged) | Retains the frozen package payload and fixes the example registry's detached RPC-handler teardown race found during release ablation. |
| E2a implementation and proof | `50456f7` through `0932a83` (including smoke `6899855`, legacy-Hello test `2051f5b`, and waiter/FIFO hardening `0932a83`) | Adds negotiated, bounded Experimental application-message transport, registry-controlled flooding, deterministic source-death proof, outbound isolation, and race-safe inbox teardown. |
| Package manifest | version `0.2.0` | `v0.1.0` remains the latest release until the candidate is pushed, passes CI on its exact commit, and is tagged. |

The v0.1.0 evidence and limitations are recorded in
[`CHANGELOG.md`](CHANGELOG.md). The committed E1 scope is summarized in
[`docs/examples-roadmap.md`](docs/examples-roadmap.md).

## Current feature work: E2a transaction flooding

E2a is the first delivered slice of the examples roadmap's second stage. It
adds append-only overlay negotiation (`Hello.featureFlags` bit 0 and
`Frame.appMessage` arm 10) plus Experimental native Node
`publishAppMessage`, `waitAppMessage`, and `appMessageStats` entry points. The
inbox is lazy opt-in, capped at 64 KiB per payload and 1,024 items / 16 MiB in
total, and deduplicates by SHA-256 only while a copy remains queued. Delivery
is best-effort and non-durable. The generic Node does not auto-relay; the
application validates and explicitly republishes accepted messages. App frames
from a peer that did not negotiate feature bit 0 are dropped. Per connection,
outbound app traffic is capped at 256 writer items / 1 MiB inside the unchanged
1,024-item / 16 MiB aggregate, with 256 items / 4 MiB kept unavailable to app
traffic. App pressure drops only that frame and does not disconnect the peer
or consume the ordinary/consensus reserve.

Inbox shutdown atomically closes new waiter admission and drains all waiters
that crossed that gate before teardown. FIFO delivery uses a head index rather
than shifting attacker-controlled queue contents on every receive; live
retention remains capped at 1,024 messages and physical item storage at twice
that bound during churn.

The registry now gives RPC and gossip bytes one admission path: exact
canonical transaction encoding, registry-network signature, next sequence,
duplicate, and pending-cap checks. An accepted transaction is flooded
immediately after the shared-state lock is released, every accepting node
relays it under the same policy, and pending bytes are reflooded every second.
The main loop drains at most 64 gossip messages per tick.

The strengthened smoke is green as a deterministic application-transport
witness. In a three-node line, a nomination-disabled end node submitted one
transaction; both survivors reported it pending at S=6 after 224 ms; the
source was killed; and both survivors printed `slot 7: txs=1` for S+1=7. The
source then restarted and caught up in 219 ms. The complete run finished in
59 s with `[registry-smoke] nodes=3 txs=7 slots=8 head=6420b17d5a264ddd`.
The result proves next-eligible-slot inclusion and survival of the submission
node once propagation has occurred. It is fresh post-candidate evidence; the
ledger in the prior-candidate section below remains historical and is not
being reused as proof of E2a.

No Stable API declaration changes in E2a. The new Node methods, result types,
statistics, wire module details, and schema-generated accessors are
Experimental; the signed consensus schema and sans-I/O Engine are unchanged.

## Prior v0.2.0 candidate record

The candidate combines the completed correctness and boundedness sprint with
a second storage-boundary sprint. This is still not a release or deployment
claim.

The sprint scope is:

- make quorum-set cache lifetime follow live non-EXTERNALIZE statement
  references and evaluate each such statement against the exact quorum set it
  advertises; EXTERNALIZE keeps its protocol-defined sender singleton;
- publish Engine-derived node statistics only at completed engine-input
  boundaries, while keeping the independent fatal-failure latch immediate;
- bound native engine ingress by item and byte budgets while reserving room
  for local progress inputs, and expose drop/pressure counters as
  Experimental diagnostics;
- reject peer statements below the host purge floor, including statements
  that were held before the floor advanced, and reject local nominations that
  a priority purge overtook in the ordinary queue; reconstruct that floor
  before restart restoration from both the journal frontier and explicit
  `start_slot`, skip retired own-log records, and advance the floor only
  monotonically;
- fail closed when hold-gate metadata allocation is unavailable, so pressure
  cannot turn stale network work into a second Engine parse attempt;
- reject a peer ballot incompatible with a local EXTERNALIZE before replacing
  the peer's previous valid statement or releasing its quorum-set reference;
- accept quorum-set responses only for outstanding requests while preserving
  retry behavior under queue pressure;
- persist only validated, requested remote quorum sets whose response entered
  the bounded engine queue; keep the local quorum set pinned in memory, and
  cap the complete answering cache at 1,024 entries, 64 MiB of logical payload
  bytes, and 1 MiB per entry;
- reconcile the cache with memory proportional to the entry cap, use FIFO
  eviction during a run and `(mtime, hash)` order after restart, write through
  same-directory temporary files plus rename, and revalidate a cached frame's
  normalized quorum-set hash before serving it;
- keep cache failure outside the consensus-critical `Store`: storage damage
  becomes a miss plus sticky `Node.storageStats()` diagnostics, the local
  answer remains available, and a mutation failure disables later writes for
  that process;
- treat only exact lowercase cache names as owned, preserve unrelated names,
  mixed-case aliases, and directories, and use no-follow/beneath-constrained
  filesystem operations so cleanup removes exact symlinks rather than their
  targets;
- strengthen input-sequence fuzz diversity and retain deterministic smoke
  coverage;
- keep the example registry RPC server and its allocator alive until every
  detached handler finishes teardown, while counting teardown-in-progress
  handlers against the 64-connection cap;
- replace external milestone/session notes with concise canonical repository
  context (`CONTEXT.md`, `DESIGN.md`, this file, and the examples roadmap).

Workspace hygiene completed alongside the sprint: 213 legacy
`.claude/worktrees/*` checkouts and 212 merged local branches were removed
after a verified recovery archive was written outside the repository. Ten
unmerged branches and one unrelated external detached worktree were preserved.
Loose milestone-era planning files were moved to a named historical archive;
active source and docs no longer depend on them.

No Stable interface changed: the 290-declaration Stable snapshot is byte-for-
byte unchanged. The 1,409-declaration Experimental snapshot was regenerated
and reviewed. The removal of Experimental `Store.putQset` / `Store.getQset`
and the addition of `Node.storageStats()` make this a pre-1.0 minor release;
the migration is recorded in `CHANGELOG.md`.

## Prior v0.2.0 verification ledger

These fields intentionally describe the integrated candidate tree, not the
v0.1.0 release run. Before the package freeze, the ordinary full graph was
green at 84/84 steps and 485/486 tests, with one expected platform skip. A
first clean cold preflight passed at `e529dcc` under an unprescribed shell Zig,
but its following ablation exposed a pre-existing registry RPC teardown race,
so that run was superseded by the code fix. A post-fix cold run at `472f0a2`
passed under another unprescribed shell Zig and remains supplemental evidence.
The final cold preflight passed at clean `0f52660` under the Zig prescribed by
`mise.toml`.

| Gate | Pinned candidate result |
|---|---|
| Package payload freeze | PASS — `1b68041`; tree clean before hashing |
| Repository code candidate | PASS — `0f39869`; focused lifecycle fix committed separately from the cache sprint |
| Formatting and whitespace (`zig fmt`, `git diff --check`) | PASS |
| Focused engine tests | PASS — 162 core, 13 vector, 4 framing-vector, and 1 engine end-to-end test |
| Focused qset-cache tests | PASS — 21/21, including capacity/byte churn, restart, corruption, allocation failure, case aliases, and root/final/temp symlinks |
| Full node tests | PASS — 151 passed, 1 expected platform skip |
| Fuzz smoke and saved-input replay | PASS — 8 smoke tests; all 3 saved streams replayed to exhaustion (14/8/13 inputs) |
| Stable/Experimental API snapshot review | PASS — 290 Stable unchanged; 1,409 Experimental verified; API closure green |
| Registry RPC lifecycle | PASS — 20/20 in the pinned cold graph and 20 consecutive focused repetitions; one-line cap and stop-wait ablations failed at their exact assertions before the pinned preflight |
| Full strict test gate | PASS — clean pinned cold preflight at `0f52660`: 100/100 steps, 497/498 tests, 1 expected platform skip, zero cached summary steps; GREEN in 682 s |
| WASM build and native/WASM differential replay | PASS — 4 traces / 32 normative / 9 observable effects; 300 fuzz iterations, 4,277 inputs, 9,616 effects |
| Deterministic and Byzantine matrices | PASS — 15,000 simulation cells in 411,250 ms; 1,000 seeds × 2 Byzantine actors |
| Real-socket end-to-end cluster | PASS — 7/7 in 2 minutes, including restart and gap recovery cases |
| Counter consumer smoke | PASS — 3 nodes, 20 slots, count 20; fetched-package repeat also green |
| Registry consumer smoke | PASS — 3 nodes, 7 transactions, 13 slots, kill/restart/catch-up, agreed head `706d31eb6eef28d3` |
| Release ablations | PASS — all five prescribed one-file mutations produced their intended red under `mise exec` and were restored; docs-smoke and check-api then reran green |
| Long fuzz run | NOT RUN for v0.2.0 — advisory |
| Release/package preflight | PASS — pinned cold run passed 7/7 hash self-tests and archive consumer build/smoke; pinned release-hash and local Git-archive verification agree on `slcp-0.2.0-p1Kf2gxUFgBmvfCp_MHA1hyQKEsMH9lovB-4R4TKoR-_` |
| Candidate CI / tag | NOT RUN / NOT CUT — local work has not been pushed |
| Three-machine deployment acceptance | NOT RUN — requires external machines |

The first fresh-cache run exposed a real restart race: a priority purge could
overtake a queued local nomination, which could then recreate a purged engine
slot. Further red/green probes found that an oldest-first retained journal
could refill the bounded live set before reaching its useful tail, the first
post-restart delivery could lower an explicit `start_slot` floor, and metadata
allocation failure could bypass the host's stale-envelope gate. Each path now
has a failing-before/passing-after regression.

A statement-level probe also found that a newer incompatible peer ballot could
replace an older valid statement before being rejected, losing both prior
evidence and its qset reference. Compatibility is now checked before storage,
and the previous statement survives rejection. The restart end-to-end witness
was made deterministic and proves fresh participation by externalizing a value
introduced only after the restarted node becomes necessary for quorum. Those
findings and their full preflight/long-fuzz proof belong to the committed
`9d21b00` / `87d7083` hardening baseline; the candidate ledger above does not
reuse those release-gate results.

The first v0.2.0 ablation run exposed an independent registry-example race:
`Server.stop` could observe an empty socket list and free its allocator while
the last detached handler was still closing and destroying its `Conn`.
`active_conn_threads` is now the lifetime barrier and the admission bound. A
test-only scheduler gate makes both old conditions deterministically red; the
focused registry suite passed 20 consecutive repetitions before the
post-fix cold runs, and the integrated suite passes under the prescribed Zig.

## Known boundaries after E2a

- Transport remains unauthenticated and unencrypted; deploy behind a private
  network or authenticated tunnel.
- Quorum linting cannot prove intersection across independently configured
  nodes.
- The native node retains only a bounded recent answering window; long-gap
  state transfer and history archives are future work.
- The qset cache bounds owned logical payloads, not filesystem allocation:
  directory metadata, block rounding, operator-owned unrelated/mixed-case
  names, and at most one newly stranded atomic-write temp per Node lifetime
  after a live failure are outside the 64 MiB counter. Cache writes are
  atomically renamed but not fsync'd, so a crash can lose or corrupt an entry;
  this becomes a miss, not consensus-log damage. Startup scan time is
  proportional to all directory entries and cleanup may rescan after deletion.
  Do not co-locate other data in `qsets/`, and monitor the filesystem as well
  as `Node.storageStats()`.
- Typed application restart still depends on an application snapshot plus the
  retained journal tail for delta-like state.
- Fixed ports in some smoke and end-to-end harnesses require those suites to
  run without competing copies, especially on macOS.
- One identity must never run on two machines; local locking cannot detect a
  copied key or data directory.
- E2a transaction flooding is delivered, but E2 history archives,
  checkpoint/state transfer, heap-sized state, and close time remain future
  work; E3 remains planned.
- Licensing remains an explicit owner decision; this repository grants none.

## Reading order

1. [`README.md`](README.md) for user-facing setup and warnings.
2. [`CONTEXT.md`](CONTEXT.md) for the shared vocabulary.
3. [`DESIGN.md`](DESIGN.md) for architecture and invariants.
4. [`docs/protocol.md`](docs/protocol.md) for normative protocol details.
5. [`docs/threat-model.md`](docs/threat-model.md) before deployment.
6. [`docs/stability.md`](docs/stability.md) before changing public symbols.

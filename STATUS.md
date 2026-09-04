# Project Status

**Snapshot date:** 2026-09-03

This file distinguishes released code, the pre-sprint baseline, and the local
v0.2.0 candidate. It is a snapshot, not a guarantee of fitness: this remains
an experimental project, no production use is recommended, and no license is
granted.

## Repository baseline

| State | Revision | What it contains |
|---|---|---|
| Released | `v0.1.0` at `916907a` (2026-09-01) | First engine, native node, typed application layer, CLI, examples/counter, protocol docs, conformance and release gates. |
| Pre-sprint `main` baseline | `cf3b84b` (2026-09-02), two commits after the tag | Post-tag documentation corrections plus E1 of the examples track: `examples/registry`. |
| Hardening baseline | local `main` at `87d7083` (2026-09-03) | Exact qset lifecycle, bounded native ingress, restart/purge hardening, stronger fuzz/E2E evidence, canonical project state, and its recorded proof. |
| Local release candidate | package/source freeze `1b68041` (not pushed or tagged) | Adds the bounded best-effort on-disk qset answering cache and its Experimental diagnostics on top of the hardening baseline. |
| Package manifest | version `0.2.0` | `v0.1.0` remains the latest release until the candidate is pushed, passes CI on its exact commit, and is tagged. |

The v0.1.0 evidence and limitations are recorded in
[`CHANGELOG.md`](CHANGELOG.md). The committed E1 scope is summarized in
[`docs/examples-roadmap.md`](docs/examples-roadmap.md).

## Current v0.2.0 candidate

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

## Current verification ledger

These fields intentionally describe the integrated candidate tree, not the
v0.1.0 release run. Before the candidate commit, the ordinary full graph was
green at 84/84 steps and 485/486 tests, with one expected platform skip. The
v0.2.0 cold preflight, package hash, and ablations are recorded here only after
they run against a clean committed candidate.

| Gate | Current sprint result |
|---|---|
| Package/source freeze | PASS — `1b68041`; tree clean before hashing |
| Formatting and whitespace (`zig fmt`, `git diff --check`) | PASS |
| Focused engine tests | PASS — 162 core, 13 vector, 4 framing-vector, and 1 engine end-to-end test |
| Focused qset-cache tests | PASS — 21/21, including capacity/byte churn, restart, corruption, allocation failure, case aliases, and root/final/temp symlinks |
| Full node tests | PASS — 151 passed, 1 expected platform skip |
| Fuzz smoke and saved-input replay | PASS — 8 smoke tests; all 3 saved streams replayed to exhaustion (14/8/13 inputs) |
| Stable/Experimental API snapshot review | PASS — 290 Stable unchanged; 1,409 Experimental verified; API closure green |
| Full strict test gate | PASS — ordinary graph 84/84 steps; 485/486 tests with 1 expected skip; cold v0.2.0 preflight pending |
| WASM build and native/WASM differential replay | PENDING candidate cold preflight |
| Deterministic and Byzantine matrices | PENDING candidate cold preflight |
| Real-socket end-to-end cluster | PENDING candidate cold preflight |
| Counter consumer smoke | PENDING candidate cold preflight |
| Registry consumer smoke | PENDING candidate cold preflight |
| Long fuzz run | NOT RUN for v0.2.0 — advisory |
| Release/package preflight | Package hash recorded as `slcp-0.2.0-p1Kf2gxUFgBmvfCp_MHA1hyQKEsMH9lovB-4R4TKoR-_`; cold package preflight pending |
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

## Known boundaries after this sprint

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
- The E2 and E3 example stages remain plans, not implemented features.
- Licensing remains an explicit owner decision; this repository grants none.

## Reading order

1. [`README.md`](README.md) for user-facing setup and warnings.
2. [`CONTEXT.md`](CONTEXT.md) for the shared vocabulary.
3. [`DESIGN.md`](DESIGN.md) for architecture and invariants.
4. [`docs/protocol.md`](docs/protocol.md) for normative protocol details.
5. [`docs/threat-model.md`](docs/threat-model.md) before deployment.
6. [`docs/stability.md`](docs/stability.md) before changing public symbols.

# Project Status

**Snapshot date:** 2026-09-03

This file distinguishes released code, the pre-sprint baseline, and the
current committed-but-unreleased hardening state. It is a snapshot, not a
guarantee of fitness: this remains an experimental project, no production use
is recommended, and no license is granted.

## Repository baseline

| State | Revision | What it contains |
|---|---|---|
| Released | `v0.1.0` at `916907a` (2026-09-01) | First engine, native node, typed application layer, CLI, examples/counter, protocol docs, conformance and release gates. |
| Pre-sprint `main` baseline | `cf3b84b` (2026-09-02), two commits after the tag | Post-tag documentation corrections plus E1 of the examples track: `examples/registry`. |
| Hardening implementation baseline | `9d21b00` (2026-09-03) | Exact qset lifecycle, bounded native ingress, restart/purge hardening, stronger fuzz/E2E evidence, and canonical project state. |
| Package manifest | version `0.1.0` | The post-tag work is Unreleased; no newer release has been cut. |

The v0.1.0 evidence and limitations are recorded in
[`CHANGELOG.md`](CHANGELOG.md). The committed E1 scope is summarized in
[`docs/examples-roadmap.md`](docs/examples-roadmap.md).

## Current hardening sprint

Current `main` contains the completed correctness and boundedness sprint below.
Its local verification matrix is green; this is still not a release or
deployment claim.

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
byte unchanged. The 1,401-declaration Experimental snapshot was regenerated
and reviewed for the new diagnostics.

## Current verification ledger

These fields intentionally describe the integrated sprint tree, not historical
release runs. The final fresh-cache `just preflight` ran immediately before
implementation commit `9d21b00` and completed in 863 seconds: 100/100 build
steps succeeded and 475/476 tests passed, with one expected platform skip.

| Gate | Current sprint result |
|---|---|
| Formatting and whitespace (`zig fmt`, `git diff --check`) | PASS |
| Focused engine tests | PASS — 162 core, 13 vector, 4 framing-vector, and 1 engine end-to-end test |
| Focused node tests | PASS — 130 passed, 1 expected platform skip |
| Fuzz smoke and saved-input replay | PASS — 8 smoke tests; all 3 saved streams replayed to exhaustion (14/8/13 inputs) |
| Stable/Experimental API snapshot review | PASS — 290 Stable unchanged; 1,401 Experimental refreshed; API closure green |
| Full strict test gate | PASS — strict Experimental gate green; fresh preflight 475/476 with 1 expected skip |
| WASM build and native/WASM differential replay | PASS — 4 traces, 32 normative effects, 9 observable effects; 300 differential fuzz iterations |
| Deterministic and Byzantine matrices | PASS — 15,000 simulator cells; 1,000 seeds against each of 2 Byzantine actors |
| Real-socket end-to-end cluster | PASS — 7/7 scenarios, including non-vacuous fresh-vote restart proof |
| Counter consumer smoke | PASS — 3 nodes, 20 slots, final count 20, including restart |
| Registry consumer smoke | PASS — 3 nodes, 7 transactions, 32 slots, including restart catch-up |
| Long fuzz run | PASS — input sequence 1,014,851 runs; decoder 1,000,392; codec 1,000,064 new runs (2,000,101 cumulative); no failure |
| Release/package preflight | PASS — clean committed archive, extracted consumer build, and restart smoke green; `slcp-0.1.0-p1Kf2tpbFQAjYQFqdjjC0NT_u_O6GO-dKZbH1TlyKCWD` |
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
introduced only after the restarted node becomes necessary for quorum. The
full preflight and long fuzz campaign above are the final post-fix runs.

## Known boundaries after this sprint

- Transport remains unauthenticated and unencrypted; deploy behind a private
  network or authenticated tunnel.
- Quorum linting cannot prove intersection across independently configured
  nodes.
- The native node retains only a bounded recent answering window; long-gap
  state transfer and history archives are future work.
- Verified qsets are bounded in memory, but persisted `qsets/` cache files are
  not yet pruned. A reachable signer that repeatedly rotates through valid,
  requested qsets can grow disk usage; operators must monitor that directory.
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

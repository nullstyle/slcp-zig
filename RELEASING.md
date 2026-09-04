# Releasing slcp-zig

The checklist for cutting a tagged release, top to bottom, and the run log of
each release cut with it. [`DESIGN.md`](DESIGN.md) “Verification model” is
the rationale; this file is the procedure. The ceremony is adapted from
capnp-zig's `RELEASING.md`, whose
v0.4.0 was tagged three minutes before its own CI went red — every step here
that can be mechanized is (`Justfile`, M6:release anchor; `.github/workflows/
release.yml`).

## Semver classification (pre-1.0)

Decide the bump before editing anything.

| Change | Bump |
|---|---|
| Any change to a line of `docs/api-snapshot.txt` (the frozen Stable surface): a `node.Options` field, a `CreateError` member, a `keys` error set, the ABI constants | **minor** |
| A Zig toolchain bump that renames a `std.fs` error. `keys.load` / `createNew` / `loadOrCreate` carry named error sets that are unions of std fs sets, so the rename turns `check-api` red — that is a Stable change, not noise | **minor** |
| Breaking change to an Experimental surface (`docs/api-snapshot-experimental.txt`), a schema append, a vector regeneration | **minor** |
| Additive declarations on any tier | **minor** |
| Bug fixes, docs, internal refactors | **patch** |

A minor bump with breaking content needs a `### Breaking` heading in
`CHANGELOG.md` with a **Migration** paragraph.

## The ceremony, in order

Every command runs from the repo root with the `mise.toml` Zig on PATH
(`mise exec -- just …`, or a shell where `mise` is activated).

### 1. Preconditions

```bash
git switch main && git pull --rebase
git status --short          # must be empty
```

- [ ] Tree clean, `main` up to date with `origin/main`.
- [ ] `[Unreleased]` or the staged `X.Y.Z` section in `CHANGELOG.md` covers
      every commit since the last tag (`git log --oneline <last-tag>..HEAD`).
- [ ] The bump is classified per the table.

### 2. Version sweep

```bash
$EDITOR build.zig.zon        # .version = "X.Y.Z"
zig build docs-smoke         # red until every pin follows
```

A `.version` bump must update **README.md**, **examples/counter/README.md**,
**examples/registry/README.md** (all carry the `refs/tags/vX.Y.Z.tar.gz`
install pin — docs-smoke checks every tag pin in every active doc against the
manifest) **and CHANGELOG.md**
(the dated section and the link footer; `release-tag-check` and `release.yml`
both grep for them).

### 3. Cold preflight

```bash
just preflight               # ~15 min; keeps preflight.log (gitignored)
```

`just preflight` runs `zig build preflight` (test, e2e, wasm-diff,
byz-matrix, sim-matrix, example-smoke, registry-smoke) from a **fresh `--cache-dir`**, then
greps each gate's evidence line out of the `--summary all` log, then runs
`just fmt-check`, `just ci-lint`, `just gen-check-pinned`,
`just pkg-hash-check` and `just package-preflight`. It is red when any gate
fails, when any evidence line is missing, or when a step in the summary block
reads ` cached`. What it greps (prefixes only, deliberately):

| Evidence line | Why a prefix |
|---|---|
| `Build Summary: N/N steps succeeded` | N grows with every stage |
| `sim-matrix: 15000 cells green` | the ` in N ms` tail varies |
| `byz-matrix: 1000 seeds x 2 actors green` | |
| `[wasm-diff] traces=4 ` / `[wasm-diff] fuzz iters=300 ` | |
| `[example-smoke] nodes=3 slots=` | `count=` may exceed `slots=` on a fast box |
| `[registry-smoke] nodes=3 txs=` | `txs=` is the count of distinct transactions (7 in the script; a lost race can add one), `slots=` and `head=` vary per run |
| `[docs-smoke] checks=N failures=0` | N grows |
| `api-snapshot: OK (` | the tail reads `refreshed)` locally and `verified)` under `-Dstrict-experimental=true` |

Things that look wrong and are not:

- **`failed command: … slcp-wasm-diff` / `slcp-api-snapshot-tests` /
  `slcp-node-tests` lines are NOT failures.** The build runner prints
  `failed command:` for any step that wrote to stderr, passing ones included.
  Never grep for it; the exit code and the summary line are the verdict.
- **`zig build e2e` must run alone.** The cluster uses fixed ports
  (39100–39504) and on macOS `SO_REUSEPORT` lets a second run bind the same
  ports and contaminate the first. Do not run two preflights, or a preflight
  and an e2e, concurrently on one machine.
- **gen-check goes through the pinned plugin.** `just gen-check-pinned`
  builds `capnpc-zig` from the capnp-zig package `build.zig.zon` pins
  (`zig-pkg/capnpc_zig-<version>-<hash>/`, `ZIG_LOCAL_PKG_DIR` pointed at the
  repo's `zig-pkg/`) and runs `just gen-check` with `CAPNPC_ZIG` set to it.
  A `capnpc-zig` on PATH is never the right one (S6 found `src/gen` had been
  produced by a stale hand-installed build). Needs `capnp` (brew/apt); the
  version used is printed on the OK line and recorded in the run log below.
- A stale `zig-out/bin/slcp_core.wasm` makes the soft wasm-diff inside `test`
  red after any frame-layout change; `just vectors-sweep` is the cure.

Advisory, never blocking, outcomes recorded in the run log:
`zig build test -Doptimize=ReleaseFast`; `just fuzz-long 1M` (the limit is
iterations, K/M/G suffixes).

### 4. Ablations — prove each gate can go red

Once per release, each of the five: start from a clean committed candidate →
mutate → `git diff --stat` must be non-empty (a prior release audit caught
two vacuous passes this way) → run the gate → quote the red line → restore the
exact mutation. Do not stack ablations or run one over unrelated work.

1. Flip one byte in `vectors/lint.json` → `zig build test` red (vectors).
2. Delete one `pub const` from `src/lib.zig` → `zig build check-api` red.
3. Change one character inside README's counter snippet → `zig build
   docs-smoke` red.
4. Change `price: f64` to `price: u64` in
   `tests/appnode_errors/err_float_command.zig` → `zig build appnode-errors`
   red (the case no longer produces its intended float error). Deleting the
   field is not equivalent: it triggers the separate zero-size error.
5. Add 100 to both generated peer destinations in
   `tools/example_smoke.zig`'s rewrite → `zig build example-smoke` red by
   timeout. One bad route is insufficient because the remaining 2-of-3 path
   can relay traffic.

### 5. Record the package hash BEFORE the tag

```bash
just release-hash            # clean tree; prints slcp-X.Y.Z-<hash> for HEAD
```

Paste the value into README's "Using slcp-zig as a dependency" pin block and
into the `## [X.Y.Z]` section of `CHANGELOG.md`. **README.md, CHANGELOG.md,
docs/ and everything else outside `.paths` (= `build.zig`, `build.zig.zon`,
`src`, `schema` and the one `tests/appnode_errors/cases.zig` that `build.zig`
imports) are not in the package, so recording the hash is hash-neutral**;
re-run `just release-hash` after the commit and check it did not move. Never
record a hash and then touch a file inside `.paths`. Everything `build.zig`
imports or embeds MUST be inside `.paths`, or a tarball consumer cannot
compile `build.zig` at all — `package-preflight` is the gate for that, and
it went red exactly this way at v0.1.0 (run log).

`release-hash` is `git archive HEAD` (no `--prefix`) hashed through
`tools/pkg_hash.sh` in a throwaway global cache — never `zig fetch .` (copies
the whole tree, worktrees and caches included, before filtering) and never a
bare `zig fetch <archive>` against the real cache (on Zig 0.17.0-dev.1786 it
poisons `~/.cache/zig/p/<hash>.tar.gz` for single-root-dir archives; pinned by
`just pkg-hash-check` and the v0.1.0 run log below).

### 6. Land, wait for CI, tag

```bash
git commit -am "release: vX.Y.Z"
git push
gh run watch                 # every job green — the release commit itself
just release-tag-check X.Y.Z # the dry run of every refusal
just release-tag X.Y.Z "one-line theme"
```

**Tag only on green CI.** `release-tag` refuses a dirty tree, a `.version`
mismatch, a missing `## [X.Y.Z] - date` section or `[X.Y.Z]:` footer, a
README without the `slcp-X.Y.Z-<hash>` line or a CHANGELOG without the same
hash, an existing tag, a red `docs-smoke`, a HEAD not on `origin/main`, and a
HEAD whose CI runs are not all `success` (`gh api … actions/runs?head_sha=`).
Never `git tag` by hand. `.github/workflows/release.yml` re-audits every `v*`
tag push (green CI on the sha, tag == `.version`, CHANGELOG section +
footer, README/CHANGELOG hash == the tagged package's hash) so a tag cut any
other way is red on the release page.

### 7. Post-tag

```bash
just verify-release-hash X.Y.Z   # fetches the published tarball as a consumer
```

- [ ] The hash `zig fetch --save` records from the real
      `archive/refs/tags/vX.Y.Z.tar.gz` equals the one in README.md and
      CHANGELOG.md. A mismatch is a docs-only follow-up commit on `main`
      (hash-neutral by the `.paths` rule), never a re-tag.
- [ ] GitHub Release `vX.Y.Z` created from the CHANGELOG section (the
      vibe-coded notice stays on top of the release notes).
- [ ] `just two-machine` — the §14 accept on real machines, from the tag
      tarball; the evidence (three `public key:` lines, the three five-line
      deployment blocks, 20 consecutive `slot N: count = N` lines per
      machine, the hash) goes into this version's run log, or “not yet run”
      is written there explicitly. A failure ships as the next patch release.
- [ ] Record-keeping sweep: update `CHANGELOG.md`, `STATUS.md`, canonical
      repository docs, and upstream drafts sent as messages (never issues).

---

## Run log

### v0.2.0 — 2026-09-03 (local candidate; not tagged)

Machine: Darwin 25.6.0 arm64, 18 logical cores; Zig
`0.17.0-dev.1786+75044cb04` via mise; supplemental shell-toolchain runs used
`0.17.0-dev.1999+b70499234`; `capnp` 1.5.0; `just` 1.58.0.

Lineage: released `v0.1.0` at `916907a`; `origin/main` at `cf3b84b`;
committed hardening implementation `9d21b00` with proof record `87d7083`;
package payload freeze `1b68041`; recorded-hash commit `e529dcc`; repository
code candidate `0f39869`.

**Semver.** Minor. The Stable snapshot remains byte-for-byte unchanged at 290
declarations. Experimental `Store.putQset` / `Store.getQset` were removed and
Experimental storage diagnostics were added; `CHANGELOG.md` carries Breaking
and Migration text.

**Development evidence.** Before candidate freeze, `zig build test --summary
all` passed 84/84 steps and 485/486 tests with one expected platform skip;
node tests were 151 pass + 1 skip, including 21/21 focused qset-cache tests.
Strict API verification passed at 290 Stable / 1,409 Experimental declarations,
and docs-smoke passed 432 checks. After the release ablation exposed the RPC
race, the focused registry suite passed 20/20, then 20 consecutive repetitions;
both the old list-length admission rule and the old stop condition were
reintroduced independently and failed at their intended deterministic
assertions. The post-fix ordinary graph passed under the prescribed toolchain
at 84/84 steps and 486/487 tests with one expected platform skip. These are
development checks, not the final cold release preflight.

**Candidate freeze.** `1b68041` freezes every intended file inside `.paths`,
including the new qset-cache source, manifest, snapshots, and packaged test.
`0f39869` is the repository code tip: it adds the registry RPC lifecycle fix
and deterministic regression under `examples/`, outside `.paths`. No packaged
file has changed since `1b68041`; changing one would restart the hash and
release proof.

**Cold preflight, run 1 (superseded).** Clean `e529dcc` was green in 832 s
under the newer shell Zig:
100/100 build steps, 496/497 tests with one expected skip, all
matrices/differential tests,
consumer smokes, E2E, generation, lint, documentation, and package checks
passed. The following vector ablation also surfaced a flaky registry allocator
crash; a focused loop reproduced it and `0f39869` fixes it. That first run is
therefore superseded.

**Cross-version cold preflight (supplemental).** Clean `472f0a2` (code tip
`0f39869`) passed from a fresh cache under the newer shell Zig: `preflight:
GREEN in 813 s`. Evidence: `Build Summary: 100/100
steps succeeded; 497/498 tests passed (1 skipped)` with zero cached summary
steps; `sim-matrix: 15000 cells green in 418372 ms`; `byz-matrix: 1000 seeds x
2 actors green`; WASM differential replay reported 4 traces, 32 normative and
9 observable effects, then 300 fuzz iterations / 4,277 inputs / 9,616 effects;
counter smoke reported 3 nodes / 20 slots / count 21; registry smoke reported
3 nodes / 7 transactions / 25 slots and an agreed `fd4549af656c99d4` head;
docs-smoke passed 432 checks; Stable/Experimental API counts were 290/1,409.
The real-socket E2E suite passed 7/7 in 2 minutes; node tests passed 151 + one
expected privileged-port skip; registry tests passed 20/20. Formatting,
actionlint, pinned generation (capnp 1.5.0), 7/7 package-hash checks, and the
archive consumer build/smoke all passed. Package preflight reproduced the
recorded hash. Because the command did not run through `mise exec`, this is
useful cross-version evidence but not the release preflight required above.

**Pinned cold preflight.** PENDING. Run `mise exec -- just preflight` alone
from a clean committed candidate and record its uncached evidence.

**Cross-version ablations (supplemental).** Each started at clean `472f0a2`,
showed a one-file non-empty diff, failed under the newer shell Zig for the
intended reason, and was restored before the next:

1. `vectors/lint.json`, first finding threshold `1` → `9`: `zig build test`
   failed both findings replay and ABI agreement with `expected 9, found 1`.
2. `src/lib.zig`, removed `DeliveryHook` plus its doc comment: `zig build
   check-api` failed its live Stable rule at `stable_rules:
   slcp.DeliveryHook`.
3. README counter snippet, port `7311` → `7312`: `zig build docs-smoke`
   reported the first difference at example line 29 / doc line 103 and
   `checks=432 failures=1`.
4. `err_float_command.zig`, `price: f64` → `u64`: `zig build
   appnode-errors` failed because the pinned “floats are NONDETERMINISTIC”
   diagnostic was not found (`22/24` steps, the one intended failure).
5. `tools/example_smoke.zig`, both generated peer destinations `+ 100`: all
   three counts stayed zero through `deadline of 180 s expired`, followed by
   `[example-smoke] FAILED: Deadline`.

After restoration the tree was clean at `472f0a2`; docs-smoke and check-api
were explicitly rerun green. Repeat all five through `mise exec` before this
candidate is release-ready.

**Hash.** `just release-hash` on clean source freeze `1b68041` produced
`slcp-0.2.0-p1Kf2gxUFgBmvfCp_MHA1hyQKEsMH9lovB-4R4TKoR-_`. README and
CHANGELOG carry it. Re-runs at clean `472f0a2`, after the registry and
hash-neutral documentation commits, were unchanged. `git archive HEAD` fed to
`just verify-release-hash 0.2.0 <archive>` produced the same hash and found it
in both files. These checks used the newer shell Zig; repeat the hash and
archive-consumer checks through `mise exec`.

**Land / CI / tag.** NOT DONE. The candidate has not been pushed and `v0.2.0`
does not exist. The local `release-tag-check 0.2.0` passed its clean-tree,
version, changelog, hash, absent-tag, and 432-check documentation guards, then
refused exactly at `HEAD is not on origin/main — push first and wait for CI`;
that supplemental dry run also used the newer shell Zig. The prescribed-
toolchain dry run remains pending.

**Advisory.** ReleaseFast and long fuzz: NOT RUN for this candidate.

**Post-tag.** NOT RUN: published-tarball hash verification, GitHub Release,
and external multi-machine acceptance remain post-tag work.

### v0.1.0 — 2026-09-01

Machine: the author's Mac (Darwin 25.6.0, 18 cores), Zig
`0.17.0-dev.1786+75044cb04` via mise, `capnp` 1.5.0 (brew), `just` 1.49.0.

Branch `m6/s9-release` from `main` @ `7fe0fe8`. Commits: `a8425a3` (preflight
step + recipes), `d850028` (packaging fix, below), `7dc6e24` (hash into
README/CHANGELOG + docs-smoke needle), `83d0b9a` (this file + release.yml),
`d2fb9ff` (upstream 07). The tag itself is cut by the orchestrating session
after CI is green on the pushed branch.

**Preflight run 1** (HEAD `a8425a3`, fresh cache, 20:01–20:11): every
build-graph gate green — `Build Summary: 92/92 steps succeeded; 396/397 tests
passed (1 skipped)`, `sim-matrix: 15000 cells green in 425679 ms`,
`byz-matrix: 1000 seeds x 2 actors green`, `[wasm-diff] traces=4 …`,
`[wasm-diff] fuzz iters=300 …`, `[example-smoke] nodes=3 slots=20 count=20`,
`[docs-smoke] checks=388 failures=0`, `api-snapshot: OK (290 stable
declarations frozen; 1378 experimental refreshed)`; fmt-check, ci-lint,
`gen-check-pinned: OK (capnpc_zig-0.16.0-nUduFXLZ…; capnp Cap'n Proto
version 1.5.0)`, `[pkg-hash-check] checks=7 failures=0` — then **RED at
`package-preflight`**:

```
error: adding cwd …/counter/zig-pkg/slcp-0.1.0-p1Kf2sZN…/tests/appnode_errors/cases.zig to cache failed: FileNotFound
```

`build.zig` `@import`s `tests/appnode_errors/cases.zig` (S8 fix-21,
`ff8ca94`) while `.paths` excluded `tests/`, so a tarball consumer could not
compile `build.zig` at all. Every path-dependency build (example-smoke, CI)
had passed because a path dep does not apply `.paths`; fix-21 landed after
fix-22 wrote `package-preflight`, and nobody ran the two together. Fixed in
`d850028`: the one file joins `.paths` (rule, now in the manifest comment:
everything `build.zig` imports or embeds must be in the package) and
`package-preflight` asserts it is present and that `tests/` ships exactly
that file. `just package-preflight` on `d850028`: `package-preflight: OK
slcp-0.1.0-p1Kf2mJnEwBKcaQ_OIRLIUCqCheAsWHROjZeUtKJkUfQ` (88 s warm).

**Preflight run 2** (HEAD `d2fb9ff`, the release tree, fresh cache):
`preflight: GREEN in 616 s`. Evidence lines: `Build Summary: 92/92 steps
succeeded; 396/397 tests passed (1 skipped)` · `sim-matrix: 15000 cells green
in 417078 ms` · `byz-matrix: 1000 seeds x 2 actors green` · `[wasm-diff]
traces=4 normative_effects=32 observable_effects=9` · `[wasm-diff] fuzz
iters=300 inputs=4277 effects=9616 …` · `[example-smoke] nodes=3 slots=20
count=20` · `[docs-smoke] checks=393 failures=0` · `api-snapshot: OK (290
stable declarations frozen; 1378 experimental refreshed)` · `run test
slcp-e2e 7 pass (7 total) 2m` · zero ` cached` lines in the summary block ·
`gen-check-pinned: OK (capnpc_zig-0.16.0-nUduFXLZNgAmDvsQZOn7lNOEtNbRBYquaALRB24zUAvS;
capnp Cap'n Proto version 1.5.0)` · `[pkg-hash-check] checks=7 failures=0` ·
`package-preflight: OK slcp-0.1.0-p1Kf2mJnEwBKcaQ_OIRLIUCqCheAsWHROjZeUtKJkUfQ`.
Per-step: core-tests 134 (2 s), node-tests 110 + 1 skip (22 s),
liveness-tests 7 (19 s), sim-tests 36 (9 s), wasm-diff 4 (2 s ×2),
example-smoke 39 s, byz-matrix 12 s, sim-matrix 6 min, e2e 2 min. The log
also carries `failed command: … slcp-e2e …` for the PASSING e2e step — the
stderr echo described above, not a failure.

**Ablations** (each on committed code; `git diff --stat` quoted; reverted
with `git checkout --`, tree clean after each):

1. `vectors/lint.json`, one byte (`"threshold": 1` → `9` at offset 784):
   `vectors/lint.json | 2 +-` → `zig build test` exit 1 in 17 s:
   `error: 'vectors_test.test.lint vectors: findings replay' failed` and
   `error: 'abi_contract_test.test.§7.2/§12 lint frame and vectors/lint.json
   agree' failed: expected 9, found 1`.
2. `src/lib.zig`, `pub const DeliveryHook = node.DeliveryHook;` deleted with
   its doc comment: `src/lib.zig | 3 ---` → `zig build check-api` exit 1:
   `tools/api_snapshot.zig:670:9: error: api_snapshot: rule(s) match no
   declaration — remove them or fix the path: stable_rules:
   slcp.DeliveryHook` (the rule-liveness compile error, as S6 recorded).
   Deleting only the declaration line first gave `src/lib.zig:59:1: error:
   documentation comments cannot be attached to tests` — red, but the
   compiler's, not the gate's; hence the redo.
3. `README.md` line 101 inside the counter snippet, `7311` → `7312`:
   `README.md | 2 +-` → `zig build docs-smoke` exit 1: `[FAIL] README.md:71:
   snippet examples/counter/src/main.zig is byte-equal to the file (first
   difference at body offset 1280 = examples/counter/src/main.zig:29, doc
   line 101; …)`.
4. `tests/appnode_errors/err_float_command.zig`, `price: f64` → `price: u64`
   (the case now compiles): `… | 2 +-` → `zig build appnode-errors` exit 1,
   `Build Summary: 22/24 steps succeeded (1 failed)`, `========= should
   contain: … floats are NONDETERMINISTIC across nodes … but not found`.
   The plan's literal form (delete the field) is also red but for the wrong
   reason — the empty struct hits the zero-size teaching error (`… encodes to
   0 bytes; the engine rejects empty values (§8.4) — add a field.`), so the
   type change is the honest ablation.
5. `tools/example_smoke.zig`, both rewritten peer ports `+100`:
   `tools/example_smoke.zig | 2 +-` → `zig build example-smoke` exit 1 in
   222 s: `[example-smoke] deadline of 180 s expired`, `[example-smoke]
   FAILED: Deadline`. (One wrong port per node is NOT enough: the flood
   relay through the node both others still reach keeps 2-of-3 live.)

Also, for the new docs-smoke needle: one character off in CHANGELOG's hash →
`[FAIL] CHANGELOG.md:0: carries README's package hash …`; README's hash line
renamed to `slcp-0.0.9-` → `[FAIL] README.md:0: package hash line
`slcp-0.1.0-<hash>` present`; both reverted, `checks=393 failures=0` after.

**Hash.** `just release-hash` on the clean tree at `d850028` and again at
`d2fb9ff` (after the README/CHANGELOG/RELEASING/upstream-07 commits):
`slcp-0.1.0-p1Kf2mJnEwBKcaQ_OIRLIUCqCheAsWHROjZeUtKJkUfQ` both times —
recording it was hash-neutral, as `.paths` promises. `just
verify-release-hash 0.1.0 <git-archive-HEAD tarball>` (the pre-tag dry run):
`README.md carries …`, `CHANGELOG.md carries …`, exit 0. The post-tag run
against the real tarball URL is the orchestrator's.

**release-tag-check dry run** (`just release-tag-check 0.1.0` on the branch):
clean tree, `.version`, CHANGELOG section + footer, hash in both files, tag
absent and `[docs-smoke] checks=393 failures=0` all passed; refused at
`ERROR: HEAD is not on origin/main — push first and wait for CI` (correct:
nothing is pushed yet). The `gh api` verdict expression, run by hand against
`main` @ `7fe0fe8`: `GREEN` (run 33588850689).

**Advisory.** `zig build test -Doptimize=ReleaseFast --summary all`: `Build
Summary: 78/78 steps succeeded; 385/386 tests passed (1 skipped)`, exit 0,
49 s (run concurrently with preflight 1; not a mandatory gate yet — promote
after a second green). `just fuzz-long 200K` (126 s): decode 202116 runs
(1884/14035 edges) and codec 200158 runs (99/9077 edges) clean; **input-seq
FAILED at run 20955** (of 200K; 2532/14289 edges): `failed with
error.OwnStatementNotMonotonic` — `tests/fuzz/input_seq_fuzz.zig:117`, the
§13.1 harness invariant "own emitted statement not strictly newer than
previous (isNewerStatement order violated)" (`sim/invariants.zig:118`) —
`input saved to .zig-cache/f/crash` (1024 bytes, sha256
`86afba4c7658c3c88f594abc64b9310ec1b7c88dc83c8748cdb830c66a2bf51b`, now
tracked as `tests/fuzz/crash/input-seq-1.bin`). `zig build
--fuzz` exited 0 regardless, so the original `fuzz-long` recipe was green
on a red target; it now greps the report and is red (commit below).
UNCONFIRMED and not investigated in S9 (engine/harness semantics are out of
the release stage's scope): the initial audit observed that `isNewerStatement`
returns false for ANY two EXTERNALIZEs while the engine legitimately
re-emits EXTERNALIZE with a grown `nH`, and the fuzz target replays
`restore_own_envelope` — a harness false positive of exactly that class is
the first hypothesis; a real own-statement regression is the second. The
build runner's `--seed` cannot be passed through `zig build`, so the run is
not replayable by seed; the saved input is the repro. Re-run `just fuzz-long 50K` (32 s, the corpus preserved in `.zig-cache/f/`):
input-seq FAILED again with the same error at run 33490 (12.5K further
runs) on a DIFFERENT input (sha256 `2d05cef1cfd3a1bf…`, now tracked as
`tests/fuzz/crash/input-seq-2.bin`) — a recurring
class, not a corpus replay — and the amended recipe exited 1
(`fuzz-long: a fuzz target FAILED …`), its own red proven. A third
distinct input (sha256 `2307f4ae0f8c9e77…`, now tracked as
`tests/fuzz/crash/input-seq-3.bin`, byte-identical to main's
`.zig-cache/f/crash` when the fix branch forked) was preserved from a later
run.
A 1M-iteration or overnight run is a post-tag v0.1.x task (R21).

**Fuzz finding settled** (branch `m6/s9-fuzz`, before the tag). Replay
tooling first: the fuzzer logs every value it hands the Smith in the
`Smith{ .in = bytes }` encoding and the runner copies the failing stream
to `.zig-cache/f/crash`, so `zig build fuzz-replay -- <file.bin>` feeds it
back through the target's own eos-gated `run` with a per-input trace
(`tests/fuzz/input_seq_replay.zig`). The three inputs are committed
byte-identical as `tests/fuzz/crash/input-seq-{1,2,3}.bin` (sha256
`86afba4c…`, `2d05cef1…`, `2307f4ae…`). Verdict — a **harness artifact**,
the auditor's EXTERNALIZE hypothesis refuted, two independent skeptics
(one trying to prove an engine bug, one a harness artifact) agreeing:
inputs 1 and 3 both carry an own NOMINATE for slot 7, an applied
`purge_slots max_slot=8`, then `nominate slot=7` with a fresh value; the
engine drops slot 7 on the purge (design §10 GC, `pipeline.handlePurge`)
and re-creates it from empty state on the next nominate
(`getOrCreateSlot` → `nomination.nominateInternal`), so the fresh slot's
first NOMINATE votes `{b}` are not a superset of the forgotten `{a}` —
`stored.isNewerOwned`'s nomination arm answers false and the harness
tracker, which never forgot slot 7, fired. stellar-core does the same
(`SCP::nominate` → `getSlot(slotIndex, true)` constructs a new Slot after
`purgeSlotsOutsideRange` erased it; `NominationProtocol::emitNomination`
emits on a null `mLastEnvelope`), and no M6/S8 change is on the path.
Neither pair is an EXTERNALIZE pair and no `restore_own_envelope` sits
between either (input 3's restore is for slot 5). Input 2 is a 512-byte
truncated prefix (the runner's crash writer buffer): its stream is
exhausted after 8 inputs — which already contain own NOMINATE slot 7 then
`purge_slots 8` — so it cannot be settled from the bytes. Fix (harness
only, `sim/invariants.zig` + the fuzz target; no `src/` change — but
`build.zig` is inside `.paths` and gained the `sim-tests` and `fuzz-replay`
steps, so the package hash MOVED to
`slcp-0.1.0-p1Kf2iJtEwBe2gyU1SFRaJQ3tqSh-XMOTSwxmp4pxgKz` (`just
release-hash` on the branch head; main's `1eb4e04` still hashes to the
`…p1Kf2mJn…` value above) and README.md + CHANGELOG.md were re-recorded to
it in the audit — step 5 must be re-run on the final pre-tag HEAD): the invariants `Tracker` forgets slots below an APPLIED
`purge_slots` (`Tracker.purgeBelow`, mirroring the engine and
`node.zig`'s `pruneOwnLatest`), and own EXTERNALIZE pairs are judged by
committed value exactly as the e2e watchdog does (different value =
fork, red; same value with grown `nH` = legal) while every other pair
keeps the strict `isNewerStatement` order. Pinned red-then-green: the
regression-corpus test (`slcp-fuzz-input-seq`, inside `zig build test`
and `fuzz-smoke`) failed `OwnStatementNotMonotonic` on inputs 1 and 3
with purge-forgetting disabled and passes with it; the synthetic-fork
test in `sim/invariants.zig` (`zig build sim-tests`) failed under the
strict comparator on the same-value nH re-emit and passes with the
committed-value rule, while the fork, a stale PREPARE, a backward phase,
a non-growing NOMINATE and mixed protocols stay red. The three inputs
also seed the target's corpus, so every non-fuzz run of the target
replays them and coverage-guided runs start from the purge → re-nominate
shape. Gates on the branch: `zig build test --summary all` → `Build
Summary: 78/78 steps succeeded; 343/348 tests passed (5 skipped)`,
`[docs-smoke] checks=393 failures=0`; `zig build fuzz-smoke` 7/7, 4/4;
`zig build sim-tests` 39/39; `zig build wasm && zig build wasm-diff` →
`[wasm-diff] traces=4 normative_effects=32 observable_effects=9` ·
`[wasm-diff] fuzz iters=300 …`; `zig build byz-matrix` → `1000 seeds x
2 actors green`; `just fuzz-long 100K` (70 s, cache preserved) → decode
`Runs: 0 -> 101866`, `Coverage … 1867/14035`; input-seq `Runs: 0 ->
104013`, `Coverage … 2811/15164 (18.54%)`; codec `Runs: 0 -> 100055`;
`fuzz-long: 100K iterations, no failure`. Not settled here: the
deterministic 5000-iteration smoke is degenerate under `Smith{ .in =
random bytes }` (every range-limited draw collapses to its minimum and
the first `slice` swallows the buffer, so it only ever runs `nominate
slot=1 value=<empty>`); its non-vacuity gate counts steps, not
diversity — a v0.1.x ticket, the corpus replay above is what now covers
the purge shape deterministically.

**Not done here** (the orchestrator's half of S9): push, CI on the branch,
merge to `main`, `just release-tag 0.1.0 "omakase polish"`, `just
verify-release-hash 0.1.0`, the GitHub Release, `just two-machine`, and the
canonical context/status sweep.

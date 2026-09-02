# Releasing slcp-zig

The checklist for cutting a tagged release, top to bottom, and the run log of
each release cut with it. Design §13.9 is the rationale; this file is the
procedure. The ceremony is adapted from capnp-zig's `RELEASING.md`, whose
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
- [ ] `[Unreleased]` in `CHANGELOG.md` covers every commit since the last tag
      (`git log --oneline <last-tag>..HEAD`).
- [ ] The bump is classified per the table.

### 2. Version sweep

```bash
$EDITOR build.zig.zon        # .version = "X.Y.Z"
zig build docs-smoke         # red until every pin follows
```

A `.version` bump must update **README.md**, **examples/counter/README.md**
(both carry the `refs/tags/vX.Y.Z.tar.gz` install pin — docs-smoke checks
every tag pin in every active doc against the manifest) **and CHANGELOG.md**
(the dated section and the link footer; `release-tag-check` and `release.yml`
both grep for them).

### 3. Cold preflight

```bash
just preflight               # ~15 min; keeps preflight.log (gitignored)
```

`just preflight` runs `zig build preflight` (test, e2e, wasm-diff,
byz-matrix, sim-matrix, example-smoke) from a **fresh `--cache-dir`**, then
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

Once per release, each of the five: mutate → `git diff --stat` must be
non-empty (HANDOFF §7: a verification that passed vacuously twice in one
session) → run the gate → quote the red line → `git checkout -- <file>`.
Ablate committed code only: `git checkout -- <file>` reverts the whole file.

1. Flip one byte in `vectors/lint.json` → `zig build test` red (vectors).
2. Delete one `pub const` from `src/lib.zig` → `zig build check-api` red.
3. Change one character inside README's counter snippet → `zig build
   docs-smoke` red.
4. Delete the float field from `tests/appnode_errors/err_float_command.zig`
   → `zig build appnode-errors` red (the case no longer produces its error).
5. Set one peer port wrong in `tools/example_smoke.zig`'s rewrite →
   `zig build example-smoke` red by timeout.

### 5. Record the package hash BEFORE the tag

```bash
just release-hash            # clean tree; prints slcp-X.Y.Z-<hash> for HEAD
```

Paste the value into README's "Using slcp-zig as a dependency" pin block and
into the `## [X.Y.Z]` section of `CHANGELOG.md`. **README.md, CHANGELOG.md,
docs/ and everything else outside `.paths` (= `build.zig`, `build.zig.zon`,
`src`, `schema`) are not in the package, so recording the hash is
hash-neutral**; re-run `just release-hash` after the commit and check it did
not move. Never record a hash and then touch `build.zig`, `build.zig.zon`,
`src/` or `schema/`.

`release-hash` is `git archive HEAD` (no `--prefix`) hashed through
`tools/pkg_hash.sh` in a throwaway global cache — never `zig fetch .` (copies
the whole tree, worktrees and caches included, before filtering) and never a
bare `zig fetch <archive>` against the real cache (on Zig 0.17.0-dev.1786 it
poisons `~/.cache/zig/p/<hash>.tar.gz` for single-root-dir archives; HANDOFF
§6, `just pkg-hash-check`).

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
      machine, the hash) goes into HANDOFF §4, or "not yet run" is written
      there explicitly. A failure ships as vX.Y.Z+1.
- [ ] Record-keeping sweep: design doc §14/§15/§16, HANDOFF, memory file,
      upstream drafts sent as messages (never issues).

---

## Run log

### v0.1.0 — 2026-09-01

Machine: the author's Mac (Darwin 25.6.0, 18 cores), Zig
`0.17.0-dev.1786+75044cb04` via mise, `capnp` 1.5.0 (brew), `just` 1.49.0.
Branch `m6/s9-release` from `main` @ `7fe0fe8`; `preflight`/recipes commit
`a8425a3`.

RUN_LOG_PLACEHOLDER

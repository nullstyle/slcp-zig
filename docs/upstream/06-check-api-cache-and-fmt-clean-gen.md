# M6 upstream ask: `check-api` can be answered from cache, and codegen output is not `zig fmt`-clean

*From: slcp-zig M6 (omakase polish + release), 2026-09-01.*
*Both findings came out of porting your `tools/api_snapshot.zig` as our own
API-freeze gate and wiring a first CI matrix. One is a gate that can pass
vacuously; the other is a paper cut every downstream with a `fmt-check` job
will hit.*

## Finding 1 (gate correctness): which artifact-reading run steps the cache can answer

`build/build_impl.zig:799-830` gives `api-snapshot`, `check-api` and
`api-closure` a `setCwd(b.path("."))` but NOT `has_side_effects = true`. The
tool reads `docs/api-snapshot.txt` (and the experimental file) at runtime;
neither is a declared build input. We went in expecting the classic hole —
"same binary, same args → replay the previous pass, so a hand-edited snapshot
stays green" — and measured it on the ported tool instead of assuming it.
The result is more specific than the folklore, and worth having precisely:

- **Plain exe run steps are safe by construction, not by intent.** The build
  runner (lib/compiler/Maker/Step/Run.zig:253-259 at 0.17.0-dev.1786) treats a
  Run step with `.infer_from_args` stdio, no output-file args and no captured
  stdio as side-effectful, so it is never cache-hit. Removing the flag from
  our `check-api` exe step and hand-editing a Stable line: red on the very
  next run. Your three steps are in this category today.
- **Test-binary run steps are NOT.** `.zig_test` (and `.check`) stdio is
  cacheable. Our `api-snapshot-tests` step reads
  `src/wasm/slcp_host_abi.zig` at runtime; without the flag the second run
  prints `cached` and never executes. That is the class that bit our vector
  and ABI gates in M4/M5 (the v0.1.0 `RELEASING.md` run log records that "a corrupted or regenerated artifact
  leaves the previous pass standing").
- **The exe steps flip into the cacheable category silently** the moment
  someone adds `expectExitCode(...)` / `addCheck(...)` (stdio becomes
  `.check`) or a `captureStdOut()` — both plausible edits to a gate — and
  from then on a hand-edited `docs/api-snapshot.txt` is answered from the
  previous pass.

With the flag set on our steps, a hand-edited Stable line is red on two
consecutive `check-api` runs and `api-snapshot` restores the file
byte-identically (sha256 checked), so the gate is proven, not presumed.

**Ask:** add `has_side_effects = true` to the three api-snapshot run steps
(and to `check-api-experimental` / the `-Dquic=true` twins) as a stated
invariant rather than an accident of stdio mode — two lines each, no
behavior change today. More importantly, audit every **`addTest`-backed**
gate whose test binary reads a committed artifact (`check-generated`'s
fixtures, the docs-snippet tests, the QUIC evidence roots,
`package-preflight`): those are the ones the cache can answer right now.

## Finding 2 (paper cut): `capnpc-zig` output fails `zig fmt --check`

All three of our generated files (`src/gen/{slcp,overlay,host}.zig`, from
capnpc-zig v0.16.0) are flagged by `zig fmt --check`. The diff is
whitespace-only and uniform — a stray blank line before a closing `}`:

```
$ zig fmt --stdin < src/gen/slcp.zig | diff src/gen/slcp.zig -
35d34
<
57d55
<
94d91
<
...
```

Six occurrences per file, always the same shape (the blank line between the
last member and the container's closing brace). Consequences downstream:

- `zig fmt --check src` cannot be a CI job; every consumer has to enumerate
  the hand-written trees or `--exclude` the generated directory (our
  `Justfile` `fmt-check` does the former). That exclusion silently also
  exempts any hand-written file someone later drops into `src/gen`.
- A consumer who runs `zig fmt src/` as a habit produces a permanent diff
  against regenerated output, and the `gen-check` drift job
  (`just gen && git diff --exit-code src/gen`) then flags the *formatter's*
  change as generator drift.

**Ask:** make the generator's output fmt-clean — either drop the trailing
blank line at the emitter, or run the finished text through
`std.zig.Ast.render` before writing (which also future-proofs the output
against formatter changes). A `zig fmt --check` over the generated fixtures
in your own test suite would keep it that way.

## Finding 3 (note, not an ask): `capnp -o<lang>` plugin naming

Not about capnp-zig's code, but worth a line in its README's "using the
plugin" section: `capnp compile -o<lang>` treats a bare word as the plugin
`capnpc-<lang>` on `$PATH`, and only a path containing a slash as an exact
executable. `-ocapnpc-zig:out` therefore looks for `capnpc-capnpc-zig`. Our
`just gen` now reads a `CAPNPC_ZIG` env var (defaulting to `zig`) so CI can
point at a freshly built plugin by absolute path; a sentence in your docs
would save the next downstream the same ten minutes.

## Context for prioritization

- Finding 1 is a real hole in a gate you rely on: cheap to fix, and the same
  two lines protect every artifact-reading gate in the tree.
- Finding 2 costs every downstream a bespoke `fmt-check` recipe forever;
  fixing it once at the emitter removes the class.
- Finding 3 is documentation.

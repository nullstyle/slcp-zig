# Replace native Cap'n Proto tools with capnp-wasm

Status: implemented and merged into both local and remote `main` branches,
2026-09-14: [SLCP `d5809f6`](https://github.com/nullstyle/slcp-zig/commit/d5809f65fe841c46eb31da0cfb7370adba9213cb)
and [bucketlist `830de28`](https://github.com/nullstyle/bucketlist-zig/commit/830de283657a385fec06ebd49cc49adecdd0aa9a).
The draft PRs are closed and the migration branches are removed.

## Implementation result

- Published the approved [compiler-only archive](https://github.com/nullstyle/slcp-zig/releases/tag/capnp-wasm-tools-v0.1.0-rc.2)
  from clean capnp-wasm source `0c45c08`. Both consumers lock its archive,
  manifest, compiler, and include hashes. Anonymous fresh-cache download passes.
- Added the packaged Wasmtime launcher, isolated generator builds from existing
  v0.16.0/v0.18.0 source pins, staged generation, and read-only drift checks.
  Generated files remain byte-identical. No capnp-zig source change was needed.
- Added the required six-case canonical-reference gate and Linux/macOS CI with
  native compiler commands disabled. Local fixture/tool absence, malformed-input,
  integrity, path, and preservation checks pass.
- Clean SLCP migration: 114/114 build steps, 651 tests passed, six optional skips;
  required 2+4 canonical cases and WASM build pass. Fresh package preflight passes,
  including the three-node/20-slot consumer smoke.
- Bucketlist: 137 tests, extracted ReleaseSafe package tests and three consumers,
  and generation in paths containing spaces with native tools disabled pass.
- Both consumers' Linux/macOS WASM generation gates passed. Bucketlist's full
  [hosted CI run](https://github.com/nullstyle/bucketlist-zig/actions/runs/34922485068)
  passed on both platforms.
- A separate SLCP follow-up (`d5809f6`) fixes the pre-existing missing libc
  dependency in the Registry's executable/test build modules. The reported
  Linux compiler failure was reproduced locally; the standalone Linux
  cross-build and all 105 macOS Registry tests pass after the four declarations.
- At final SLCP commit `d5809f6`, both hosted WASM tooling gates and the Linux
  end-to-end/format gates pass. The [Linux Registry smoke](https://github.com/nullstyle/slcp-zig/actions/runs/34923109190/job/104235367053)
  now builds but exposes a separate existing runtime failure:
  `DirectorySyncFailed` at durable data-directory startup. The existing
  directory-open options leave `.iterate` false, which the pinned Zig uses
  to select Linux `O_PATH` handles. Registry durability code remains outside
  this compiler-toolchain migration.

The subsequent application portability fix, `875bb54`, changes the Registry's
synced directory handles to readable descriptors. A real Linux regression
captured `EBADF` from the former `O_PATH` handles and now passes with the new
open options, including archive publication and snapshot replacement. Managed
adaptivity and its journal are integrated separately in `ae8d1ff`; their
verification is recorded in [project status](../../STATUS.md).

The SLCP PR was assembled in a clean worktree so the existing unrelated
adaptivity changes remain outside this migration. Hosted matrix validation is
recorded on the PRs. The sections below retain the implementation rationale.

## Decision

Use `capnp-wasm`'s reference compiler under Wasmtime, followed by a WASI build of
the **same capnpc-zig release that supplies each consumer's runtime**. Use the
same compiler module for canonicalization tests.

```text
schema snapshot
  -> capnp.wasm compile -o-
  -> unpacked CodeGeneratorRequest
  -> capnpc-zig.wasm built from the consumer's pinned dependency
  -> staged generated files -> comparison or publication

framed test message -> capnp.wasm convert binary:canonical -> reference bytes
```

This replaces native `capnp` installation in SLCP's development and CI flows.
The schema parser remains the reference Cap'n Proto implementation, compiled
to WASM. SLCP continues to use capnp-zig for its application runtime.

Keep SLCP's v0.16.0 and bucketlist's v0.18.0 generator/runtime pairs. The
capnp-wasm bundle contains a generator from commit `0fb8df4`, newer than the
v0.18.0 release despite the manifest still saying 0.18.0. It emits newer APIs
and requires its matching runtime, even with reflection disabled. The producer documents this in `generators/zig/README.md`.
An application runtime upgrade is a separate change with separate validation.

No capnp-zig implementation change is needed for SLCP's existing generator to
run in WASI: that exact source was successfully compiled and executed during
planning. A supported standalone build target in capnp-zig would improve the
ongoing workflow, as described below.

## Verified starting point

| Item | Observed value |
| --- | --- |
| capnp-wasm checkout | Producer checkout, clean at `b8d8e3f8aca919ecef03ab41bed97dbf3d3c6e4a` |
| Compiler source | Reference Cap'n Proto `851c45bb39c34c3f20f9d9ebe9f34a7e39109b6f`; reports `2.0-dev` |
| Wasmtime | `48.0.1`, already pinned by capnp-wasm and current capnp-zig |
| Compiler module | 3,005,266 bytes; SHA-256 `5429b7277b18b6e3f65430068ac41ac327ef8dd359603955f16ec576e0c3a14a` |
| SLCP generator/runtime | v0.16.0, selected by `build.zig.zon` package hash |
| SLCP Zig | `0.17.0-dev.1786+75044cb04`, selected by `mise.toml` |
| bucketlist generator/runtime | v0.18.0, selected by its `build.zig.zon` package hash |

Executed probes:

- WASM compiler -> pinned native v0.16.0 generator: `slcp.zig`, `overlay.zig`,
  and `host.zig` all match checked-in `src/gen` byte for byte.
- WASM compiler -> pinned **WASI v0.16.0 generator**: the same three files all
  match byte for byte. The plugin was built directly from the fetched package's
  `src/main.zig`, with `-target wasm32-wasi -O ReleaseSafe --stack 8388608`.
- Both statement vectors produce the same canonical bytes through native
  capnp 1.5.0, capnp.wasm, and the checked-in goldens.
- All four quorum-set input vectors produce matching native/WASM canonical
  bytes. The probe prepared identical framed inputs with native `capnp encode`;
  the migrated gate must consume the Zig test's existing framed inputs.
- WASM compiler -> pinned WASI v0.18.0 generator -> bucketlist's pinned
  `zig fmt`: `proof.zig` matches tracked `src/proof_gen.zig` byte for byte.
  Raw generation differs by 21 blank lines, so formatting is part of this
  consumer's reproduction recipe. SLCP's generated files remain unformatted.

These planning probes are feasibility checks on the present schemas/vectors, not a full
application test run or a claim of compatibility for every Cap'n Proto feature.

## Tooling interface and ownership

Use Wasmtime's existing command-module interface. The public TypeScript SDK
currently exposes compile/generate but not canonical conversion; using its
internal runner would couple the migration to an unsupported interface.
The producer documents that interface in `sdk/typescript/README.md`.

- **capnp-wasm owns** compiler artifacts, standard include schemas, provenance,
  and a small reusable launcher around Wasmtime. Package the launcher beside
  the artifacts; it handles the pinned runner, exception support, guest root,
  binary streams, and exit status. Start with the macOS/Linux environments used
  by SLCP. This does not require changing the browser SDK.
- **capnp-zig owns** its generator and a standalone way to build it for WASI.
  It must remain buildable without fetching capnp-wasm or configuring the RPC
  dependency graph. Keep compiler-host orchestration out of its runtime.
- **Consumers own** their schema roots, requested files, generator flags,
  output filenames, package pins, and compare-versus-write policy.

The launcher should expose two operations: run the packaged compiler with an
explicit staged workspace, or run an explicitly selected generator module with
a private output directory and request on stdin. Forward arguments as an argv
array. Do not emulate the entire native `capnp` CLI or globally shadow `capnp`
on PATH. In particular, generation is two separately checked commands:

1. `capnp.wasm compile --no-standard-import -I/include --src-prefix=/src -o- ...`
2. `capnpc-zig.wasm`, receiving the saved request through stdin.

WASM guest subprocess launch is deliberately rejected. Every command needs a
guest filesystem mounted at `/`, including `--version` and schema-free
conversion. Standardized exception handling must be enabled with
`-W exceptions=y`. These are verified port requirements, documented in the producer's
`patches/capnproto/README.md`.

## Implementation sequence

### 1. Produce and pin a consumable compiler package

In capnp-wasm, package the small launcher with the existing release archive
format. Choose an exact clean source commit, prepare its archive, verify it,
and deliver it at an immutable artifact URL. A GitHub release asset is the
default distribution choice; registry publication is unnecessary for this use.

The existing local `0.1.0-rc.1` archive records source commit `baaac124`, not
current HEAD. Prepare a fresh candidate after committing launcher changes;
do not label the existing archive as a build of HEAD. The package format
already records per-file hashes, source provenance, reference revisions, and
licenses, as documented in the producer's `docs/releases.md`.

Add a compiler-toolchain lock in SLCP under `tools/` containing the archive URL,
archive SHA-256, source commit, expected compiler-module digest, and include
inventory identity. Pin Wasmtime in `mise.toml`. Resolve the generator version
from `build.zig.zon` and Zig from `mise.toml`; avoid second independent pins.

Bootstrap should verify the archive before extraction, reject unsafe archive
paths, verify the extracted inventory, and install into a content-addressed
cache. Local development may explicitly select an extracted local package;
CI uses the locked archive. Record the selected identity in gate output.
Neither consumer CI nor ordinary generation should build the full C++/Rust/Go
producer toolchain or depend on an absolute sibling checkout path.

Acceptance: a fresh macOS/Linux workspace can fetch, verify, and execute the
compiler with native `capnp` absent; corrupted and wrong-identity artifacts fail.
Missing tools never trigger an implicit native fallback.

### 2. Build a generator matching the consumer

For SLCP, resolve the v0.16.0 source package exactly as `gen-check-pinned` does
today, then directly build `src/main.zig` as WASI with the repository's Zig pin.
Use ReleaseSafe and the tested 8 MiB stack. Cache by source package hash, Zig
version, target, optimization, stack size, and generator-affecting options.
Use the resulting module instead of the newer generator bundled by capnp-wasm.

In capnp-zig, add a supported standalone generator build entry point and a WASI
smoke test if maintaining this workflow upstream. A small packaged build file
under `build/` can avoid configuring the full library/RPC graph; preserve the
existing root build-step contract. Document the equivalent direct-source
command for consumers pinned to releases predating this entry point.
No changes to `src/main.zig` or runtime behavior are currently indicated.

Acceptance: native/WASI generation from the same pinned source agrees, and a
small generated-code consumer compiles against that same runtime. Do not
upgrade SLCP's dependency just to obtain the convenience build entry point.

### 3. Replace SLCP generation and drift checking

Change [Justfile generation](../../Justfile) and
[gen-check-pinned](../../Justfile) to invoke one
consumer-owned generation driver. Keep the existing recipe names.

The driver should:

1. Verify the compiler package and resolve/build the pinned generator.
2. Snapshot `schema/` at guest `/src` and the locked standard includes at
   `/include`, preserving relative import paths and binary file contents.
3. Compile the three entrypoints in the existing order; retain stdout as a
   binary request and report diagnostics on stderr.
4. Run the generator in an empty temporary output directory.
5. Validate the complete expected output set and paths before touching
   `src/gen`. Handle missing and extra files, not only changed contents.
6. In `gen`, install the validated results. In `gen-check` and
   `gen-check-pinned`, compare with the current checkout and fail without
   rewriting it. This also detects unstaged changes that today's
   regenerate-then-diff recipe can overwrite.

Acceptance: all three files remain byte-identical; the second run is clean.
Malformed schemas, unresolved imports, a failing generator, and an unexpected
output leave `src/gen` intact. Paths containing spaces and imported schemas
must work. Failure in compilation must prevent generation from starting.

### 4. Replace the canonicalization test command and CI setup

Change [vectors_test.zig](../../tests/vectors_test.zig)
to invoke the explicitly configured WASM tool through the launcher. Preserve
binary stdin/stdout, the `binary:canonical` conversion, the schema/type, and
the byte comparisons against the Zig runtime. Keep the reference computation
independent of `capnpc.canonical`.

Add a dedicated required canonical-reference gate. It must report executed
statement/qset case counts and fail when the package, Wasmtime, or vector
fixtures are missing. Assert coverage of the expected cases (currently two
statements and four quorum sets); an empty case list or skipped differential
test cannot satisfy this gate.
Ordinary package consumers may continue building/testing without developer
tooling; make any local skip explicit. Supply the launcher/tool configuration
from `build.zig`, including the declared inputs needed for correct caching.

Replace SLCP's `setup-capnp` action with verified artifact setup and the
Wasmtime pin. Remove apt/brew Cap'n Proto installation. Run generation drift
and the required canonical-reference gate on Linux and macOS, with native
`capnp` absent. Keep checked-in generated sources in published packages.
Update README, mise comments, and the active RELEASING procedure. Historical
release records describing capnp 1.5.0 remain historical records.

Acceptance: existing byte comparisons pass, and deliberately missing tooling
or fixtures, and empty case lists, fail the required CI gate. Package preflight
still succeeds with no compiler
installation or sibling source checkout available.

### 5. Apply the same generation workflow to bucketlist

Use bucketlist's own v0.18.0 generator/runtime pair. Add explicit generation and
read-only drift recipes for `schema/proof.capnp`; stage the generator's
`proof.zig`, format it with bucketlist's pinned Zig, and map it to the tracked
`src/proof_gen.zig` only after successful generation and formatting.
Use the same compiler package and launcher as SLCP. Do not rewrite older SLCP
companion dependency pins.

Acceptance: generated proof bindings agree, the `bucketlist-proofs` roundtrip
and verification tests pass, and the core/store modules remain free of this
development tooling. Verify that release/preflight inputs include whatever
the new recipe requires; ordinary consumer builds still use tracked bindings.

### 6. Final gates and delivery

- Run the focused generation, canonical-reference, and proof-codec tests first.
- Run SLCP's required test/API gates and WASM build after its test wiring changes.
- Run applicable package preflights from fresh extracted packages and clean
  compiler caches, with native `capnp` unavailable.
- Run Linux/macOS CI using only the locked compiler artifact, pinned Wasmtime,
  and per-consumer generator build. Check for leftover active invocations of
  `capnp`, `capnpc`, apt/brew setup, and stale version checks.
- If adding the capnp-zig standalone target, run its focused generator/WASI
  consumer tests and required repository checks. Follow that repository's
  commit/push procedure for owned code changes.

Land reviewable changes in dependency order: compiler package/launcher,
optional capnp-zig build convenience, SLCP tooling, then bucketlist tooling.
The consumer commits record the actual published artifact URL/digest; local
scratch paths are evidence only. Existing unrelated work in the SLCP checkout
must not be included in these commits.

## If extending the migration to capnp-zig's own development tooling

This is a wider follow-on than SLCP requires. The main callers are already
concentrated in
`tests/serialization/support/capnp_cli.zig` in capnp-zig.
That helper must support compilation, conversion, and `eval` through the same
explicit compiler selection. Additional callers include the Justfiles,
`tools/package_preflight.zig`, `tools/reflection_performance.py`, and
`tests/serialization/codegen_rpc_paths_test.zig`.

Its current native installer and identity gate live in `tools/bootstrap_capnp.py`,
`tools/capnp-toolchain.json`, mise tasks, and `.github/actions/setup-capnp`.
Changing those alone would leave hardcoded commands and version checks behind.
Regenerate/review reflection-containing fixtures under one chosen compiler
revision: compiler metadata can affect generated bytes even when field layouts
agree.

Keep C++ runtime interoperability as a distinct test configuration. Reflection,
generic RPC, streaming RPC, and Docker peers link/use native C++ libraries;
capnp-wasm is a synchronous command port and does not replace those libraries.
Select compiler/generator versions compatible with each oracle's runtime, and
retain independent oracle coverage. Windows and the Go/Rust/Python Docker
lanes need their own migration validation before claiming that all capnp-zig
development paths are free of native compiler tooling.

## Completion criteria

For SLCP and bucketlist generation/reference gates, native `capnp` installation
is unnecessary; all required commands use a verified capnp-wasm compiler and a
generator matching the consumer runtime. Current schemas and signed/hash
vectors keep their bytes. Drift checking cannot erase local changes. CI can
obtain the same artifacts without this machine's checkout layout. Application
runtime dependencies and ordinary consumer build requirements are preserved.

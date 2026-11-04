# SLCP conformance artifact

This artifact has its own SHA-256 identity, profile and complete file inventory.
It is separate from the ordinary Zig dependency package, whose export paths
remain unchanged. The artifact contains a self-contained Git bundle for the
exact clean committed reference, portable schemas/vectors/expected outcomes,
the native `SLCPRUN1` runner, the WASM ABI v1 executable and JSONL host, and
source-pinned tool/dependency metadata. It requires no sibling repository or
unpublished branch. It does require the identified build/runtime tools and
network access for pinned public dependencies and schema tools on a cold run.

Build from a clean committed source checkout (untracked notes are excluded):

```sh
mise exec -- python3 tools/conformance.py pack --reference HEAD --output /tmp/slcp-conformance.tgz
```

The command builds the reference executables, then prints the archive SHA-256.
Keep that digest through a trusted channel: a self-authored manifest is an
integrity inventory, not proof of publisher authenticity. Repeating with the
same inputs normalizes archive ordering, timestamps and gzip metadata; tool
and target executable identities are recorded, not assumed interchangeable.
The pack command refuses tracked source changes or a reference other than the
checked-out commit, and never includes untracked files.

Given the externally recorded digest:

```sh
mise exec -- python3 tools/conformance.py verify /tmp/slcp-conformance.tgz --sha256 DIGEST
mise exec -- python3 tools/conformance.py qualify /tmp/slcp-conformance.tgz --sha256 DIGEST --destination /tmp/slcp-qualified
```

`verify` checks the archive digest, regular-file-only safe paths, bounded
expanded bytes, exact inventory, lengths and per-file hashes before extraction.
`restore` accepts the same arguments as `qualify`, but only restores and checks
the exact Git commit/tree and the portable inputs against that source.
The destination must not exist. Neither operation substitutes public main.

`qualify` restores into a new destination and uses fresh local/global Zig,
package and Cap'n Proto caches. It requires the source's exact Zig/Wasmtime
pins, the recorded Node version, and the native executable's OS/architecture.
Python's actual version is recorded; the tool uses its standard library.
It bootstraps the integrity-checked schema compiler, runs every required
vector/native/WASM/canonical gate, and runs the packaged native executable.
It then compares the packaged native executable with the packaged WASM module
through the packaged JSONL host. This `packaged-cross-target` gate uses those
artifact files directly, so rebuilding good source cannot conceal a broken or
substituted packaged WASM executable. Its final `SLCPRUN1-CROSS-TARGET` receipt
must show positive success, logical-budget, fatal, retained-partial-effect and
sticky-failure coverage, plus driver isolation and explicit-zero incompatibility.
Nonzero exits and skipped required tests fail qualification. Commands,
runtime versions, exit statuses and log digests are retained in
`qualification.json` and `logs/`; inspect these receipts when assessing a run.
An unavailable tool is a failure, never a successful skipped gate.
Only the declared static `SLCP-v1-static-strict-default-driver+SLCPRUN1` profile
and its complete required-gate set are supported. Unknown profiles, unknown or
missing required gates and duplicate declarations are rejected before restoring
an artifact. A new profile requires an explicit verifier update.

The source `mise.toml`, dependency archive URL/package hash and independently
hashed compiler/generator locks are under `pins/`. Generated source is part
of the exact reference Git tree. Fixture files preserve their own provenance;
the artifact does not reclassify reported outcomes as freshly tested results.
The manifest records the actual executable hashes and native target.

The native runner's separate profile can express explicit zero limits and
fatal/partial outcomes. WASM ABI v1 retains zero-means-default configuration;
it cannot represent that native explicit-zero case. Existing `SLCPTRC1`
schemas/bytes and ordinary package behavior remain unchanged. Wire, engine,
managed application and storage qualification are different claims; this
artifact does not qualify managed socket lifecycles, history/checkpoint trust,
storage interchange or physical power-loss behavior. Parity is not an
independent proof of consensus safety or deployment acceptance.

The repository grants no license yet. Its source README notice remains in the
Git bundle; this packaging adds no redistribution permission or runtime license.
Dependency/tool terms remain those of their respective owners. Producing this
local artifact does not publish it or change upstream refs.

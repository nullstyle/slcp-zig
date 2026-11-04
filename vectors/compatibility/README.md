# Additive SLCP v1 compatibility corpus

These fixed witnesses supplement the original generated vectors and four
SLCPTRC1 traces. They preserve current acceptance, hashes, signed bytes and
exact unsigned effect construction at `346d3ec67f5917f579e4d7505b3b1abb3194d898`,
Zig 0.17.0 and capnp-zig v0.21.0. The original generator does not overwrite
these imported/independently constructed expectations.

| File | Cases | Portable expectation |
|---|---:|---|
| `ed25519-provider.json` | 12 | Provider signature acceptance; arbitrary messages, separate from SLCP envelopes. |
| `envelope-signatures.json` | 5 | Original received statement bytes, verification and ordinary receive status. |
| `wrappers.json` | 5 | Construction recipes, exact lengths, segment counts and SHA-256; complete bytes for small examples. |
| `qsets.json` | 13 | Legacy/standard standalone and nested inputs, normalized hash and typed-reader acceptance. |
| `decoder.json` | 25 | Bounded eager whole-graph acceptance with explicit decoder options. |
| `receive.json` | 10 | Ordinary receive and startup restore status precedence, with direct limit overrides explicitly distinguished from v1 wire config. |

Each file retains provenance and a version where applicable; the provider file
is the original submitted matrix with its toolchain source hash. Parser error
names in `zigDiagnostic` are implementation diagnostics, not portable error
codes. Acceptance, normalized hashes, exact bytes and Engine statuses carry
the shared expectations. Unknown fixture options and missing files fail checks.

```sh
zig build signature-vectors wire-compatibility --summary all
```

Both gates are in `zig build test` and `vector-conformance`. The independent
Rust checker accepts an explicit corpus path; it does not require an implicit
sibling checkout. Run in the Rust repository:

```sh
cargo run --locked -p slcp-core --example check-upstream-compatibility -- /absolute/path/to/this/corpus
```

Its optional `--zig-wasm /absolute/path/to/slcp-zig` also sends the complete
envelopes through the actual Zig WASM ABI. The checker uses Rust builders,
parser and Engine; agreement with a pinned implementation is parity evidence.
Finite fixtures do not establish an independent consensus or cryptographic
audit. See the [signature contract](../../docs/signature-acceptance.md),
[wire contract](../../docs/wire-compatibility.md),
[versioned runner](../../docs/runner-conformance.md) and
[conformance artifact](../../conformance/README.md).

# SLCP v1 wire compatibility witnesses

The [compatibility corpus](../vectors/compatibility/) makes the existing Zig
construction and acceptance rules independently executable. It addresses
[#4](https://github.com/nullstyle/slcp-zig/issues/4) without changing schemas,
signed domains, decoder acceptance, or the four frozen engine traces. Run:

```sh
zig build wire-compatibility --summary all
```

The gate requires every corpus file. Missing files fail; they never count as
skipped qualification. The baseline is `346d3ec67f5917f579e4d7505b3b1abb3194d898`,
Zig 0.17.0 and capnp-zig v0.21.0. The handwritten core paths are unchanged by
the later native durability fix. Dependency-specific legacy-pointer results
refer to this pin; the older public dependency was not rerun for this corpus.

## Unsigned wrappers and signed payloads

[wrappers.json](../vectors/compatibility/wrappers.json) supplies exact
construction recipes, lengths, segment counts and SHA-256 digests. Small
examples also include complete bytes. Every repetition recipe means precisely
`payloadLength` copies of `payloadByte`, with no terminator.

The current [host codec](../src/engine/host_codec.zig) constructs a fresh root
then allocates its active union object and fields in source order. The pinned
builder grows segment zero. An independent builder must reserve enough initial
space to reproduce that layout when claiming byte-exact engine conformance.
Canonicalizing an unsigned wrapper or accepting a builder's different default
segment allocation does not satisfy that claim. This preserves the existing
[trace effect comparison](../vectors/traces/FORMAT.md); no semantic-only mode
is introduced.

The retained large EXTERNALIZED witness contains slot 123 and 65,536 bytes of
`ab`: 65,584 framed bytes, SHA-256
`bb2230b9d92d9481d3c9b0b253b24c447948f87b1baacef5c10c03e48443b6e0`.
Additional recipes cover a large three-envelope overlay slot-state reply,
host framing whose total size exceeds the network-frame cap, and the exact
difference between absent and present-empty nomination predecessor pointers.
Both predecessor spellings decode to empty bytes; the host encoder emits the
present pointer. The absent spelling is an accepted-input witness, not a new
encoder rule.

The overlay recipe uses arbitrary opaque statement bytes and a repeated
signature to isolate layout and byte preservation. It does not claim those
payloads are valid signed SLCP statements. The host-wrapper witness likewise
separates successful host decoding from the Engine's rejection of its invalid
contained network envelope. Host framing and contained-network limits apply
at different boundaries.

## Historical qsets and typed far-pointer resolution

[qsets.json](../vectors/compatibility/qsets.json) retains the exact historical
double-far inline-composite input from the port report. It is accepted at the
pinned dependency, as are its nested overlay/configuration forms and a standard
equivalent spelling. They normalize to:

```text
87fd73190029d95c3e5bdc73af651ad6bb16a862547eeb6fb140c4f929e60842
```

The corpus also rejects malformed landing-pointer types, nested double-far
landing pads, invalid segment IDs, invalid tag types and negative element
counts. Canonical emission and legacy input acceptance remain separate rules;
support for a standard spelling does not authorize dropping the retained
legacy spelling.

The generic graph walk accepts the bounded three-hop chain in this corpus,
while the typed qset reader rejects it at its separate two-hop resolution cap.
An implementation must preserve that distinction when claiming this pinned
profile; a generic parser's successful walk does not establish typed qset
acceptance. The gate exercises [qset normalization](../src/engine/qset.zig),
[host configuration decoding](../src/engine/host_codec.zig) and the actual
[overlay codec](../src/node/wire.zig).

## Bounded whole-graph validation

[decoder.json](../vectors/compatibility/decoder.json) specifies raw flat or
framed bytes, pointer depth, traversal-word budget and acceptance. It tests
malformed unknown pointer fields, cycles, depth boundaries, aliases, Void
lists, zero-width inline-composite amplification, far chains and framing
failures. These exercise the [validating SLCP entry point](../src/canonical.zig)
and its pinned dependency, rather than a lazy traversal of known schema fields.

Work is charged on each visit, including aliased targets. The alias witness
requires four units: its two pointer slots plus one payload word on each
visit. It accepts at four and rejects at three. A Void list and a zero-width
struct list each consume one traversal unit per logical element despite
their tiny physical representation. Inline-composite element count has its
own default 8 Mi-element cap, independently of the traversal budget. Far
landing pads consume one or two words; pointer-following depth is separately
bounded.

`expectedAccepted` is the cross-implementation verdict. `zigDiagnostic` records
the pinned Zig parser's diagnostic spelling and is checked by the Zig runner;
other implementations need not use those error names. The deliberately
truncated oversized-word declaration records truncation precedence and does
not isolate the total-segment-word cap. The corpus is finite regression
coverage, not a parser or cryptographic audit.

## Receive and restore precedence

[receive.json](../vectors/compatibility/receive.json) contains complete config
and input frames independently constructed with the Rust implementation's
builders. Each case starts a fresh Engine. Its intended verdict was checked
in Rust before writing the fixture, then replayed by the Zig gate through the
ordinary Engine API.

The witnesses pin these [pipeline boundaries](../src/engine/pipeline.zig):

- Ordinary receive performs sanity, signature, strict canonicality and
  relevance before slot admission. A bad signature wins over noncanonicality
  or irrelevance; malformed nomination shape wins before signature checking.
- Startup restore checks ownership before signature after sanity. Its
  non-own/bad-signature witness is ignored.
- Relevance precedes the slot budget; unresolved qsets and stored-statement
  budgets can precede application rejection at their respective boundaries.

Every input must emit exactly one final status. `limitsOverride` applies to
the direct Engine configuration after decoding; it is necessary to represent
explicit zero for the two budget cases. Zero on the unchanged host wire still
means the default and is not reinterpreted by this fixture format.

The noncanonical statement is signed over its original padded bytes. These
cases preserve signature checking over received bytes before strict
canonicality; rebuilding or normalizing signed statement bytes would change
the verdict and violate the existing contract.

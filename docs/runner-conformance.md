# Versioned native runner controls

`SLCPRUN1` is an additive JSON conformance-fixture format. It preserves the
existing `host.capnp` schema, WASM ABI v1 and SLCPTRC1 traces. It records exact
configuration, input outcomes and normative effects that v1 trace records
cannot fully express. Run it with:

```sh
zig build conformance-runner
zig-out/bin/slcp-conformance-runner vectors/runner/SLCPRUN1.json
zig build runner-conformance --summary all
```

The executable requires one fixture path. Missing files, unknown fields,
unsupported formats, malformed inputs and mismatched expectations fail with
nonzero exit. Its JSONL output is a diagnostic receipt; qualification requires
a successful process exit and the final `SLCPRUN1` `result: "PASS"` record with
positive case and input counts. Earlier output alone is not a completed gate.

## Configuration presence

A fixture has `format: "SLCPRUN1"` and a nonempty `cases` array. Each case names
a base v1 `config` frame in hex, optional `limits` overrides, `expect_limits`,
a driver profile and `steps`. The base config retains existing v1 decoding:
zero fields mean Engine defaults. In the separate override object:

| Value | Meaning |
|---|---|
| Field absent or `null` | Inherit the decoded base configuration. |
| Integer `0` | Pass exact zero to the direct native Engine API. |
| Nonzero UInt32 | Pass the exact supplied limit. |

For example, `"limits": {"max_cached_qsets": 0}` selects the direct API's
local-only qset cache. It still keeps the mandatory local qset. Exact zero is
represented even for a limit where it is invalid: `max_value_bytes: 0` must
produce the expected `BadValueBytes` initialization failure, not defaults.
`expect_limits` checks effective values before construction; `init_error`,
when present, requires that exact initialization failure. All eight existing
Limits fields are supported. An unknown field is an error.

Successful case receipts expose the effective limits and a `v1_config` frame
only when every configured limit is nonzero. A null `v1_config` marks the
configuration unrepresentable by WASM ABI v1. Cross-target qualification must
report that scope explicitly; it must not translate explicit zero into default.
No new WASM export, feature bit or signed-data version is allocated here.

## Push outcomes and effects

Each step contains an existing v1 `Input` frame in `input`, an expected
`push_error` (null for success or an Engine error name), the expected sticky
`failed` state and exact ordered normative `effects` as hex frames. The runner
computes the transition, compares all normative frames and returns observable
phase frames separately.

`push_error` is independent of effect draining. A fatal operation can have
queued a partial prefix and lack the final `input_status`. All effects from
that failed operation are diagnostic and have `disposition: "discard"`; hosts
must not persist, broadcast, arm timers or deliver application work from that
prefix. A repeated push against the failed Engine must return `EngineFailed`.
The fixture records both outcomes. The Engine's existing queue semantics remain
unchanged; the runner supplies an explicit host disposition.

The `default` driver retains ordinary semantics. The separately named
`combine_fault` test driver validates normally and deterministically returns
`DriverFault` from candidate combination. Its singleton fixture produces
`EngineFailed` after six normative effects, with no final input status, then
refuses the next input. Those bytes are retained as fixed additive expectations.
They do not replace any original golden trace.

Effect serialization encodes the borrowed head before committing it. A failed
allocation leaves that head uncommitted. The runner then destroys the affected
instance and fails the process; a host must not continue after publishing an
incomplete encoded drain. A failure-injection unit test exercises the actual
encoder with a failing allocator and verifies queue/head preservation.

## Target memory and logical limits

| Profile | Configured bounds and observed gate |
|---|---|
| Native `SLCPRUN1` | Native allocator; fixture input at most 32 MiB, 64 cases, 4,096 steps per case, and 64 MiB of encoded hex per drain. Step scratch storage is released between inputs. Physical allocation failure exits unsuccessfully. |
| WASM ABI v1 | Initial linear memory 4 MiB, maximum 64 MiB. Encoding scratch and retained Engine state share that memory. Host-side buffers are additional. |
| Engine effect queue, both targets | At most 4,096 effects and 16 MiB of queued byte payloads. These logical limits do not bound total process or linear-memory use. |

The shared fixture checks defaults, null inheritance, explicit zero, a nonzero
local-slot budget with `over_limit` refusal, invalid explicit-zero config, and
fatal/partial/sticky behavior. The native/WASM check replays representable cases
through actual WASM imports and compares normative frames and push outcomes.
Explicit-zero cases remain native-only. Logical refusal is distinct from
recoverable allocator failure, failed serialization and process/runtime abort.
The serialization test is software allocation-failure evidence; physical OOM
stress and equal native/WASM physical memory behaviour are not claimed.

Keep this runner control version, the wire/Engine profile, fixture manifest
and executable-reference identity separate. A new outcome or configuration
meaning requires an explicit runner version change rather than reinterpretation
of the original v1 traces.

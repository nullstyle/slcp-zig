# Native persistence acknowledgements

The `SLCP-native-durability-v1` host profile requires successful file sync and,
on macOS, successful `F_FULLFSYNC` before acknowledging consensus persistence.
There is no best-effort fallback when macOS rejects the media-flush request.
This tightens failure handling without changing journal bytes, signed data or
the Engine/WASM interfaces.

The profile covers the native Store, managed journal and key-file publication
on Linux and macOS local filesystems supporting the required barriers. It
assumes exclusive ownership of the signing identity and storage, and that the
filesystem and device honour successful synchronization requests. Network
filesystems, copied signing keys, administrator rollback and dishonest devices
do not acquire stronger guarantees from these calls.

## Successful barriers

For existing file contents, the writer completes buffered writes, calls file
sync, and on macOS checks `F_FULLFSYNC`. Creation and replacement additionally
synchronize the containing directory after publishing the filename. macOS then
performs a checked media flush on the published file after directory sync;
flushing the file before the rename alone is insufficient for that ordering.
Directory descriptors use ordinary directory sync, not `F_FULLFSYNC` on a
directory handle.

The convenience native Store also synchronizes the containing directory chain
for its automatically created data directory. Managed Journal callers retain
their existing obligation to supply a durably provisioned directory. Key-file
parents must already exist and be durably provisioned; creation and loading
confirm the key contents and its containing entry before returning an identity. A key left named by an
unacknowledged publication is loaded and synchronized, never overwritten with a
fresh identity.

## Failure and recovery

A write or barrier failure is an uncertain outcome: bytes or a replacement name
may already exist. It is not permission to reuse an assumed old state. Store
and Journal instances refuse further operations after uncertain persistence
failure; close, reopen and recover before continuing. Deterministic capacity
refusal before journal I/O leaves its instance usable.

The Node stops processing after failed own-envelope or externalized-value
persistence. It releases neither the dependent broadcast nor application
delivery. An uncertain compaction barrier also stops the affected writer and
Node. Managed hosts acknowledge a persistence effect to Session only after the
Store call succeeds. A failed key barrier returns no signing identity.

Key APIs map barrier failures to their existing `InputOutput` error; native
Store maps them to its existing `IoFailed`. Managed Journal exposes the failed
barrier and latches the instance failed. These results do not tell the caller
that an append definitely did not reach storage.

## Qualification boundary

The failure-injection tests replace syscall results at the private durability
boundary while exercising actual files, append/recovery, publication and host
effect dispatch. They cover ordinary file sync, macOS media flush and directory
sync failures, including barriers after publication and reopen after uncertain
appends. Existing torn-tail and complete-corruption recovery tests remain
separate checks.

These are software failure and process-recovery tests. Actual controlled
physical power-loss testing remains pending; successful syscall tests do not
establish that hardware result.

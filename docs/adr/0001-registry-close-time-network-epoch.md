# Bind registry close time to a hard network epoch

Status: accepted

The registry carries `close_time` in each consensus `LedgerValue`, validates it
from replicated state plus `ValueContext.slot`, and combines competing values
by choosing the minimum proposed time alongside the canonical transaction
union. A process may sample Unix time only to construct its own proposal,
clamped to the next ledger's legal `(T, T + 60]` interval; validation,
combination, and application never read a local clock. This gives every node
one monotonically increasing, bounded logical ledger time without claiming
that consensus proves truthful UTC—a Byzantine quorum can choose any legal
time chain.

The operator chooses one genesis close time `G`, which is part of the
canonical registry network descriptor and the real slot-zero header. E2c
versions the ledger value, network, header, snapshot, and checkpoint domains
together and deliberately treats the result as a hard application epoch.
Pre-E2c snapshots, bare-transaction-set journals, checkpoint votes, and
signing-fence state are not silently migrated; nodes start with fresh private
data under the new identity, while a shared archive root merely gains a new
network-id namespace.

## Considered options

- Using local time inside validation was rejected because identical bytes
  could receive different verdicts at different nodes.
- Deriving time only from slot number was rejected because it cannot track
  real elapsed time after stalls without an arbitrary permanent cadence.
- A median or other quorum-time estimator was deferred: it adds policy and
  attack surface without making UTC trustworthy.
- Reinterpreting old storage in place was rejected because a partial migration
  could bind the wrong previous value, header domain, or signing fence to the
  new epoch.

## Consequences

All validators must preserve the same `(passphrase, G)` pair across restarts;
changing either creates another network and the identity guard rejects the old
data directory. Honest clock skew is absorbed by deterministic bounds and the
minimum combine rule, but operators must treat close time as agreed metadata,
not a time oracle. State continuity across the E2c boundary requires an
explicit future migration design rather than implicit compatibility.

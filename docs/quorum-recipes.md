# Quorum recipes

Three copy-paste quorum configurations, what each one tolerates, and the
exact lint output it produces. The JSON blocks are byte-identical to the
files under `docs/recipes/` and the output blocks are the real stdout of
`slcp lint-quorum` — `zig build docs-smoke` (M6 S5b) re-runs the CLI and
byte-compares, so what you read here is what the tool prints.

The keys in every recipe are the vectors' placeholder keys (`0101…`,
`0202…`, …) so the hashes are reproducible. **Replace them with the output
of `slcp key show <file>`** (or `slcp key new <file>` on first run) for each
of your nodes.

## 0. How to read a recipe

**The spec format** (`src/quorum.zig` `fromJson` — the one JSON reader the
CLI, the tests and the vector generator share):

```
{"threshold": T, "validators": [<hex64>, ...], "innerSets": [<spec>, ...]}
```

A level is satisfied when `T` of its members agree, where a member is a
validator *or* an inner set (which counts when it is itself satisfied).
`innerSets` is optional; **any other key is rejected** (`slcp lint-quorum`
exits 2 naming it, with a `did you mean` hint) — a tolerated typo such as
`innersets` or `inner_sets` would silently drop every nested org and lint a
flatter quorum as OK. The same shape in Zig is `slcp.Quorum`:

```zig
slcp.Quorum.twoThirdsOf(&.{ pk_a, pk_b, pk_c })   // ceil(2n/3)-of-n — the blessed default
slcp.Quorum.majorityOf(&.{ ... })                  // floor(n/2)+1 of n
slcp.Quorum.of(2, &.{ pk_a, pk_b, pk_c })           // explicit t-of-n
slcp.Quorum.ofSets(2, &.{ org_a, org_b, org_c })    // t of these inner sets
```

where each `pk_x` is `slcp.nodeId("<hex64>")` (comptime) or
`try slcp.parseNodeId(hex)` (runtime).

**Self-inclusion.** `Node.create` adds your own node id to the top-level
validators when it is absent from the whole tree (`include_self = true`,
the default; an info log line). **List yourself among the validators** in
the recipe, the way the §0 counter program lists all three of `pk_a, pk_b,
pk_c` — then auto-inclusion is a no-op and every node runs the identical
tree. If you list only the *other* nodes, `twoThirdsOf` computes `t` over
`n` and auto-inclusion makes it `t-of-(n+1)`: on a flat 2-of-3 that becomes
2-of-4, which is sub-majority and refused (`UnsafeQuorum`). You can see
that with `--self`, which does what `Node.create` does:

```text
$ slcp lint-quorum docs/recipes/three-friends-2of3.json --self 0404…0404
note: added self 0404…0404 to the top-level quorum
quorum: 2-of-4; halts if any 3 of these 4 are offline
...
ERROR sub_majority_threshold: 2-of-4 is below a majority, ...
result: 1 error(s), 1 warning(s)     (exit 1)
```

`include_self = false` opts out (a warning: your statements then never form
part of any quorum — fine for a follower). Watchers never include
themselves.

**The availability sentence.** Every level of the report ends with
`halts if any n − t + 1 of these n are offline`, and `min blocking set` is
the smallest number of validators anywhere in the tree whose simultaneous
outage halts you. Halting without a quorum is *correct* behaviour
(`docs/threat-model.md` §5), so read that sentence as your operational
budget.

- **Crash tolerance = liveness**: `n − t` members may be offline and the
  level still reaches `t`.
- **Byzantine tolerance = safety**: the report's `below_two_thirds` warning
  prints it (`lint_report.byzantineTolerance`: `min(2t − n − 1, n − t)`) —
  the number of members that may lie while every two quorums still overlap
  in an honest one *and* the honest remainder still reaches `t`.

Every finding line ends with `if any K of these N nodes are offline, your
network halts`, and there the numbers are **nodes of the whole tree**, not
members of one level: `N` is every validator in the tree and `K` is the
fewest outages that halt you whichever nodes they hit
(`N − smallest slice + 1`; `lint_report.minSliceSize`). On a flat set that
is the same `n − t + 1`; on the `2-of-{2-of-3 × 3}` variant below it is
`any 6 of these 9` while `min blocking set` is 4 — the two bracket your
budget (the worst four nodes halt you; any six do).

**The intersection caveat.** Lint judges *your* configuration: top-level
threshold sanity plus tree-wide critical validators. It never checks that
your slices intersect other nodes' slices (`docs/threat-model.md` §4). Keep
every node on the same recipe and that property holds by construction.

**Running it:**

```text
$ zig build                      # installs zig-out/bin/slcp
$ ./zig-out/bin/slcp lint-quorum docs/recipes/three-friends-2of3.json
```

Exit 0 = clean or warnings only, 1 = lint errors (the node would refuse to
start without `allow_unsafe_quorum`), 2 = bad input — or a report that could
not be written to stdout, so `slcp lint-quorum q.json > report.txt || exit`
never leaves an empty report behind with a 0.

## 1. Three friends (2-of-3)

<!-- snippet: docs/recipes/three-friends-2of3.json -->
```json
{
  "threshold": 2,
  "validators": [
    "0101010101010101010101010101010101010101010101010101010101010101",
    "0202020202020202020202020202020202020202020202020202020202020202",
    "0303030303030303030303030303030303030303030303030303030303030303"
  ],
  "innerSets": []
}
```

In Zig: `slcp.Quorum.twoThirdsOf(&.{ pk_a, pk_b, pk_c })` — `ceil(2·3/3) = 2`.

- Tolerates **1 crash**, **0 Byzantine**.
- **If any 2 of these 3 are offline, your network halts.**
- No node is critical; the minimum blocking set is 2.

The lint output:

<!-- output: lint-quorum docs/recipes/three-friends-2of3.json -->
```text
quorum: 2-of-3; halts if any 2 of these 3 are offline
  0101010101010101010101010101010101010101010101010101010101010101
  0202020202020202020202020202020202020202020202020202020202020202
  0303030303030303030303030303030303030303030303030303030303030303
hash: 6125525525c7e57dc1dbc7f7f23161f7f3b4e6262c0c1f082fa31e75e3372fc9
min blocking set: 2 node(s)
critical nodes: none
result: OK
```

This is the hobbyist default: three VPSes, one down for maintenance, the
other two keep going. Two down and it stops — and starts again by itself
when one returns.

## 2. Five nodes (4-of-5)

<!-- snippet: docs/recipes/five-nodes-4of5.json -->
```json
{
  "threshold": 4,
  "validators": [
    "0101010101010101010101010101010101010101010101010101010101010101",
    "0202020202020202020202020202020202020202020202020202020202020202",
    "0303030303030303030303030303030303030303030303030303030303030303",
    "0404040404040404040404040404040404040404040404040404040404040404",
    "0505050505050505050505050505050505050505050505050505050505050505"
  ],
  "innerSets": []
}
```

In Zig: `slcp.Quorum.twoThirdsOf(&.{ pk_a, pk_b, pk_c, pk_d, pk_e })` —
`ceil(2·5/3) = ceil(10/3) = 4`.

- Tolerates **1 crash**, **1 Byzantine** (`min(2·4 − 5 − 1, 5 − 4) = 1`).
- **If any 2 of these 5 are offline, your network halts.**
- No node is critical; the minimum blocking set is 2.

The lint output:

<!-- output: lint-quorum docs/recipes/five-nodes-4of5.json -->
```text
quorum: 4-of-5; halts if any 2 of these 5 are offline
  0101010101010101010101010101010101010101010101010101010101010101
  0202020202020202020202020202020202020202020202020202020202020202
  0303030303030303030303030303030303030303030303030303030303030303
  0404040404040404040404040404040404040404040404040404040404040404
  0505050505050505050505050505050505050505050505050505050505050505
hash: 3d0ccd9092bd6da7424fcde071442bbfd3c0e520cce55637996fe8c3d87f519a
min blocking set: 2 node(s)
critical nodes: none
result: OK
```

Five nodes buys you one liar, not more crashes: the two-thirds rule spends
the extra members on safety. If you want two crashes tolerated instead,
`3-of-5` is a majority (no error) but prints `below_two_thirds` — with
threshold 3 you tolerate 0 Byzantine nodes, 2 crashes (that is the
`vectors/lint.json` case "below-two-thirds 3-of-5").

## 3. Three orgs × two nodes (2-of-3 orgs, majority within each)

<!-- snippet: docs/recipes/three-orgs-2of3-majority.json -->
```json
{
  "threshold": 2,
  "validators": [],
  "innerSets": [
    {
      "threshold": 2,
      "validators": [
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0202020202020202020202020202020202020202020202020202020202020202"
      ]
    },
    {
      "threshold": 2,
      "validators": [
        "0303030303030303030303030303030303030303030303030303030303030303",
        "0404040404040404040404040404040404040404040404040404040404040404"
      ]
    },
    {
      "threshold": 2,
      "validators": [
        "0505050505050505050505050505050505050505050505050505050505050505",
        "0606060606060606060606060606060606060606060606060606060606060606"
      ]
    }
  ]
}
```

In Zig:

```zig
slcp.Quorum.ofSets(2, &.{ slcp.Quorum.of(2, &.{ a1, a2 }), slcp.Quorum.of(2, &.{ b1, b2 }), slcp.Quorum.of(2, &.{ c1, c2 }) })
```

An org **counts only when both of its nodes agree** (majority of two is
two); the network needs two of the three orgs.

- Tolerates **one whole org offline**, or **one node anywhere** (its org
  drops out, the other two orgs still satisfy 2-of-3).
- **Two nodes in different orgs offline ⇒ halt** — that is the
  `min blocking set: 2` line below: the cheapest way to lose two orgs is
  one node from each.
- Tolerates **1 Byzantine node** (safety): a liar takes at most its own
  org's vote with it, and any two orgs overlap in an honest one.
- **No `critical_node` warnings**: losing any single node loses exactly
  one 2-of-2 org, and 2-of-3 orgs still satisfies. (Every node is critical
  *to its org*, but not to the tree, and the lint reports tree-wide
  criticality.)

The lint output:

<!-- output: lint-quorum docs/recipes/three-orgs-2of3-majority.json -->
```text
quorum: 2-of-3; halts if any 2 of these 3 are offline
  set: 2-of-2; halts if any 1 of these 2 are offline
    0505050505050505050505050505050505050505050505050505050505050505
    0606060606060606060606060606060606060606060606060606060606060606
  set: 2-of-2; halts if any 1 of these 2 are offline
    0101010101010101010101010101010101010101010101010101010101010101
    0202020202020202020202020202020202020202020202020202020202020202
  set: 2-of-2; halts if any 1 of these 2 are offline
    0303030303030303030303030303030303030303030303030303030303030303
    0404040404040404040404040404040404040404040404040404040404040404
hash: d84177939120976f0026982fd41d3d9441dda15b69c4b8f82e26fc73d29252f4
min blocking set: 2 node(s)
critical nodes: none
result: OK
```

**Why inner 1-of-2 would be a fork machine.** If each org were `1-of-2`, a
quorum would be "one node from each of two orgs". Then `{a1, b1}` and
`{a2, b2}` are both quorums with **no node in common**: each can
externalize a different value for the same slot with every signature valid.
Majority-within-each-org (2-of-2 here) is what forces any two quorums to
share a node. The `sub_majority_threshold` check applies only to the top
level (like `below_two_thirds` and `all_members_critical`): this inner
`1-of-2` tree prints three `set: 1-of-2` lines and `result: OK`, exit 0.
Inner levels are your responsibility, which is why the recipe writes them
out.

**Recommendation: three nodes per org.** With `2-of-2` orgs a single node
down removes its whole org, and the minimum blocking set is only 2. The
`2-of-{2-of-3 × 3}` variant — each org `2-of-3`, network `2-of-3` orgs —
tolerates one node per org *and* one whole org, and its minimum blocking
set rises to 4 (two nodes in each of two orgs). That variant's normalized
form and hash are pinned in `vectors/qset.json` ("nested 3 orgs") and its
lint result in `vectors/lint.json` ("nested 3 orgs 2-of-3 majority within
(clean)", `minBlocking: 4`).

## 4. What the lint codes mean

The four codes, in the order `qset.lint` emits them (copied from
`src/engine/qset.zig` `LintCode`; the exact wording of each line is in
`src/node/lint_report.zig` `writeFinding`). Every line ends with the
availability sentence in your own numbers.

| Code | Level | Condition (top level `t`-of-`n`) | The line says |
|---|---|---|---|
| `sub_majority_threshold` | **error** | `2t < n + 1` | `t-of-n is below a majority, so two disjoint "quorums" can form inside your own slice (a fork machine); use a threshold of at least floor(n/2)+1` |
| `below_two_thirds` | warning | `t < ceil(2n/3)` | `threshold t is below ceil(2n/3) = …  — with n validators and threshold t you tolerate B Byzantine nodes, n−t crashes` |
| `all_members_critical` | warning | `t == n`, `n > 1` | `threshold t equals the member count, so every one of the n members is critical` |
| `critical_node` | warning (one per node) | the node's outage alone makes the whole tree unsatisfiable | `<hex64> is in every slice; it alone offline halts you` |

An **error** makes `Node.create` fail with `UnsafeQuorum` (the message is
the report). `allow_unsafe_quorum = true` starts anyway and logs each error
at WARN with the suffix `(.allow_unsafe_quorum = true: starting anyway)` —
for local experiments only (`docs/threat-model.md` §4). Warnings are logged
and the node starts.

The report also prints `hash:` (the `qsetHash` of the normalized tree,
`docs/protocol.md` §5 — every node on the same recipe prints the same hash,
which is the quickest way to check that they are), `min blocking set:`
(`qset.minBlockingSize`) and `critical nodes:`.

## 5. Anti-recipes

Both inputs are cases in `vectors/lint.json`; the outputs below were
captured from the CLI over those inputs (they are not recipe files, so
`docs-smoke` does not re-run them).

**1-of-3** (`"sub-majority 1-of-3"`) — the fork machine. Exit 1; the node
refuses to start:

```text
quorum: 1-of-3; halts if any 3 of these 3 are offline
  0101010101010101010101010101010101010101010101010101010101010101
  0202020202020202020202020202020202020202020202020202020202020202
  0303030303030303030303030303030303030303030303030303030303030303
hash: 6f2aac5ff472907447c339880353636a9ee2c8567bb72796b18e6fd4ce6c9e68
min blocking set: 3 node(s)
critical nodes: none
ERROR sub_majority_threshold: 1-of-3 is below a majority, so two disjoint "quorums" can form inside your own slice (a fork machine); use a threshold of at least 2; if any 3 of these 3 nodes are offline, your network halts
WARNING below_two_thirds: threshold 1 is below ceil(2n/3) = 2 — with 3 validators and threshold 1 you tolerate 0 Byzantine nodes, 2 crashes; if any 3 of these 3 nodes are offline, your network halts
result: 1 error(s), 1 warning(s)
```

**3-of-3** (`"all-critical 3-of-3"`) — every node critical. Exit 0, but
one node down halts you:

```text
quorum: 3-of-3; halts if any 1 of these 3 are offline
  0101010101010101010101010101010101010101010101010101010101010101
  0202020202020202020202020202020202020202020202020202020202020202
  0303030303030303030303030303030303030303030303030303030303030303
hash: 48cf54947d6a105888d1482df5f9917801316a34765dca60986da811d3d2637c
min blocking set: 1 node(s)
critical nodes: 0101010101010101010101010101010101010101010101010101010101010101 0202020202020202020202020202020202020202020202020202020202020202 0303030303030303030303030303030303030303030303030303030303030303
WARNING all_members_critical: threshold 3 equals the member count, so every one of the 3 members is critical; if any 1 of these 3 nodes are offline, your network halts
WARNING critical_node: 0101010101010101010101010101010101010101010101010101010101010101 is in every slice; it alone offline halts you; if any 1 of these 3 nodes are offline, your network halts
WARNING critical_node: 0202020202020202020202020202020202020202020202020202020202020202 is in every slice; it alone offline halts you; if any 1 of these 3 nodes are offline, your network halts
WARNING critical_node: 0303030303030303030303030303030303030303030303030303030303030303 is in every slice; it alone offline halts you; if any 1 of these 3 nodes are offline, your network halts
result: 0 error(s), 4 warning(s)
```

Both fix the same way: `twoThirdsOf`, i.e. 2-of-3.

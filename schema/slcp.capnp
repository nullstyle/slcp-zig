@0xd9ec6f612289f92e;
# slcp.capnp — SIGNED consensus types. FROZEN ON PUBLISH.
#
# EVOLUTION RULE: appending any field reachable from Statement changes
# canonical encodings and is therefore a CONSENSUS VERSION BUMP (new domain
# tags, coordinated upgrade) — never transparent capnp evolution.
# No non-zero defaults anywhere in this file: canonical encoding is
# value-XOR-default, so a default change would silently change preimages.
# See DESIGN.md "Protocol data and evolution" and docs/protocol.md §§3–5.

struct Ballot {
  counter @0 :UInt32;   # MUST be >= 1 on the wire. counter==0 is the engine-internal
                        # bottom placeholder and is NEVER transmitted (isSane rejects).
  value   @1 :Data;     # opaque; length in [1, maxValueBytes]
}

struct QuorumSet {
  threshold  @0 :UInt32;            # 1 <= threshold <= len(validators) + len(innerSets)
  validators @1 :List(Data);        # 32-byte ed25519 pubkeys, strictly ascending, unique
  innerSets  @2 :List(QuorumSet);   # sorted ascending by qsetHash; depth <= 4;
                                    # total validator entries across tree <= 255;
                                    # no duplicate node anywhere in the tree
}

struct Nomination {
  quorumSetHash @0 :Data;           # 32 bytes
  votes    @1 :List(Data);          # values; strictly ascending byte order (implies dedup);
                                    # nonempty; <= 64 entries
  accepted @2 :List(Data);          # same ordering rules; <= 64 entries.
                                    # Engine-emitted statements satisfy accepted ⊆ votes
                                    # (accepting adds to both sets, stellar-core semantics).
                                    # NOT disjoint — disjointness would break superset
                                    # freshness. Receivers require only sortedness.
}

struct Prepare {
  quorumSetHash @0 :Data;
  ballot        @1 :Ballot;
  prepared      @2 :Ballot;   # ABSENT POINTER == unset. Present => counter >= 1.
  preparedPrime @3 :Ballot;   # same; sanity: preparedPrime ⋦ prepared
                              # (strictly less AND value-incompatible)
  nC @4 :UInt32;              # 0 == unset; nC != 0 => nH != 0 and nC <= nH <= ballot.counter
  nH @5 :UInt32;              # 0 == unset; nH != 0 => prepared set and nH <= prepared.counter
}

struct Confirm {
  quorumSetHash @0 :Data;
  ballot    @1 :Ballot;       # counter >= 1
  nPrepared @2 :UInt32;       # >= 1
  nCommit   @3 :UInt32;       # sanity: 1 <= nCommit <= nH <= ballot.counter
  nH        @4 :UInt32;
}

struct Externalize {
  commit              @0 :Ballot;  # counter >= 1
  nH                  @1 :UInt32;  # >= commit.counter
  commitQuorumSetHash @2 :Data;    # qset used during CONFIRM (audit/reconstruction);
                                   # quorum math treats the sender as singleton {sender, 1}
}

struct Statement {
  nodeId    @0 :Data;         # 32-byte ed25519 pubkey of the signer
  slotIndex @1 :UInt64;
  pledges :union {
    unset       @2 :Void;     # discriminant 0: an all-zero message decodes here — REJECTED
    nominate    @3 :Nomination;
    prepare     @4 :Prepare;
    confirm     @5 :Confirm;
    externalize @6 :Externalize;
  }
}

struct Envelope {
  statementBytes @0 :Data;    # canonical flat capnp encoding of a Statement (§4.2);
                              # the signature covers THESE bytes — verifiers never
                              # re-canonicalize on the hot path
  signature      @1 :Data;    # 64-byte ed25519 over the digest in §4.2
}

@0xb6651e61a62e69c5;
# host.capnp — engine boundary (EngineConfig, Input, Effect).
# Versioned with the WASM ABI; append-only evolution. NOT signed data, so
# non-zero defaults are allowed here. See DESIGN.md "WASM module" and
# docs/protocol.md §14.

using Slcp = import "slcp.capnp";

struct EngineConfig {
  networkId  @0 :Data;            # 32 bytes
  nodeId     @1 :Data;            # 32 bytes (watcher: ephemeral random, host-generated)
  secretSeed @2 :Data;            # 32 bytes; empty => watcher mode
  quorumSet  @3 :Slcp.QuorumSet;
  limits     @4 :Limits;
  strictCanonical @5 :Bool = true; # §4.2 receive-side canonicality check (default on)
}

struct Limits {                   # 0 == engine default (§4.5 wire limits + §5.1 engine caps)
  maxValueBytes @0 :UInt32;  maxNominationValues @1 :UInt32;
  maxPendingEnvelopes @2 :UInt32;  maxPendingBytes @3 :UInt32;
  maxLiveSlots @4 :UInt32;  maxCachedQsets @5 :UInt32;  timeoutCapMs @6 :UInt32;
  maxStoredStatementBytes @7 :UInt32;
}

struct Input { union {
  unset @0 :Void;
  envelopeReceived @1 :Data;      # Envelope frame bytes
  timerFired @2 :TimerKey;
  nominate @3 :Nominate;
  qsetReceived @4 :Data;          # QuorumSet frame bytes
  restoreOwnEnvelope @5 :Data;
  purgeSlots @6 :UInt64;
}}

struct Effect { union {
  unset @0 :Void;
  persistOwnEnvelope @1 :SlotBytes;
  broadcastEnvelope @2 :SlotBytes;
  forwardEnvelope @3 :SlotBytes;
  armTimer @4 :ArmTimer;
  cancelTimer @5 :TimerKey;
  requestQset @6 :Data;           # 32-byte hash
  externalized @7 :SlotBytes;
  inputStatus @8 :UInt16;
  phaseEvent @9 :PhaseEvent;
}}

struct TimerKey  { slot @0 :UInt64; timer @1 :UInt8; }
struct SlotBytes { slot @0 :UInt64; bytes @1 :Data; }
struct ArmTimer  { slot @0 :UInt64; timer @1 :UInt8; delayMs @2 :UInt32; }
struct Nominate  { slot @0 :UInt64; value @1 :Data; prevValue @2 :Data; }
struct PhaseEvent { slot @0 :UInt64; kind @1 :UInt16; detail @2 :UInt64; }
struct ValueList { values @0 :List(Data); }   # combine_candidates input frame (§7.3)

# Quorum-set lint diagnostics (§12), returned by the ABI's slcp_lint_qset so
# every host renders byte-identical findings. Codes mirror qset.LintCode.
struct LintFinding {
  level     @0 :UInt8;    # 0 = error (refuse to start), 1 = warning
  code      @1 :UInt16;   # qset.LintCode ordinal
  members   @2 :UInt32;   # top-level member count n
  threshold @3 :UInt32;
  node      @4 :Data;     # 32 bytes, present only for code == critical_node (3); ABSENT pointer otherwise
}
struct LintDiagnostics { findings @0 :List(LintFinding); }

@0xd1e0e224689f7c4d;
# overlay.capnp — transport frames. Normal append-only capnp evolution.
# TRUST MODEL: only envelope signatures are authenticated. Hello fields are
# unauthenticated hints. See DESIGN.md "Trust and operations" and
# docs/threat-model.md.

using Slcp = import "slcp.capnp";

struct Frame { union {
  unset        @0 :Void;              # rejected
  hello        @1 :Hello;             # first frame each direction, exactly once
  envelope     @2 :Slcp.Envelope;
  getQset      @3 :Data;              # 32-byte hash
  qset         @4 :Slcp.QuorumSet;
  dontHave     @5 :DontHave;          # negative reply — requesters never hang
  getSlotState @6 :UInt64;            # 0 = "latest externalized you have"
  slotState    @7 :SlotState;
  ping         @8 :UInt64;
  pong         @9 :UInt64;
  appMessage   @10 :Data;             # opaque application payload; <= 64 KiB
}}

struct Hello {
  protocolVersion @0 :UInt32;         # = 1
  networkIdPrefix @1 :Data;           # first 8 bytes of networkId — fast wrong-network
                                      # disconnect; not a secret, not authentication
  nodeId          @2 :Data;           # advisory, UNAUTHENTICATED
  currentSlot     @3 :UInt64;         # advisory
  listenPort      @4 :UInt16;         # for reciprocal dialing
  featureFlags    @5 :UInt64;         # advisory capability bits; unknown bits ignored
}

struct DontHave  { kind @0 :UInt8; id @1 :Data; }
struct SlotState { slot @0 :UInt64; envelopes @1 :List(Slcp.Envelope); }  # <= 64 envelopes

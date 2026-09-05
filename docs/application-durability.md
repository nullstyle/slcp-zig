# Asynchronous application publication

Applications that publish state after the delivery callback returns can opt
into Experimental local journal protection through
`Node.createWithRecovery(..., .{ .retain_until_durable = true, ... })`.
Supply `previous_value` from the same trusted application checkpoint used to
restore state. Its slot initializes the durable application watermark; no
value means genesis at zero. A non-genesis `start_slot` without a supplied
checkpoint is rejected. Existing checkpoint/journal overlap validation still
applies, and the application's recovery hook remains responsible for proving
that its checkpoint and retained replay suffix form an acceptable continuation.

After the application has durably published complete state and the exact
previous value for slot S, call `Node.acknowledgeDurable(S)` from a user or
publisher thread. Queue admission, merge completion, or an in-memory commit
alone is insufficient. Admission is allocation-free and uses one coalesced
control slot independent of the ordinary FIFO's capacity. Repeated equal
requests succeed; decreasing requests return `DurabilityRegression`.

Success means the acknowledgement was admitted. The engine applies it after
the current input and delivery callback finish; `Node.durableApplicationSlot()`
returns the last applied watermark, or null when the option is disabled. A
publisher may finish before its delivery callback returns: retain that pending
acknowledgement and retry `AheadOfDelivery` later. `DurabilityDisabled`,
`NodeClosed`, and `NodeFailed` report cases where admission cannot proceed.
Stop all callers before destroying the Node, as with its other operations.

For an opted-in node, local journal compaction never removes records after
the durable watermark; it may retain older records for the normal answering target or
until the next compaction. The ordinary sixty-four-slot compaction cadence
still advances its target. A later acknowledgement can release a target held
back by application publication; it does not move that target on every slot.
For example, a checkpoint at 7 retains replay from 8 when delivery reaches 64.
Acknowledging 64 can release the deferred target to 49. Delivery and
acknowledgement of 65 then keep 49 until another ordinary cadence target is due.

This changes local log retention only. Peer answering/cache and Engine
retention, the Stable `answering_window_slots` default and range, and ordered
delivery's gap policy are unchanged. The application must enforce any stronger
continuity requirement and bound its unpublished queue; a stalled publisher
can otherwise grow local logs. Acknowledgements are trusted application
assertions, not proof that a value was agreed on or that storage is durable.

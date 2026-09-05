# Keep asynchronous application recovery behind an explicit durable watermark

Status: accepted
Date: 2026-09-04

An asynchronous application can accept a journaled delivery before its own
snapshot is durable. Compacting solely at the answering window can then erase
the replay suffix needed after a crash. Experimental
`RecoveryOptions.retain_until_durable` opts into a local journal retention
constraint initialized from the application's trusted `previous_value`
checkpoint, or zero at genesis. The application acknowledges only completed
durable publication, and the engine clamps journal compaction at the earlier
of its normal target and the durable watermark's successor.

Acknowledgements use one coalesced control slot outside the ordinary input
budget. Admission and engine application are distinct: a successful
`acknowledgeDurable` call admits work; `durableApplicationSlot` observes the
engine-applied watermark. Monotonic requests cannot pass successful delivery.
A publisher that completes before its callback returns retries
`AheadOfDelivery`. Acknowledgements release a deferred cadence target without
turning ordinary compaction into a rewrite on every delivered slot.

Increasing the answering window was rejected because journal recovery has a
different lifetime from bounded peer assistance and Engine state. This option
does not change the Stable sixteen-slot default, range 1..62, Engine/cache
retention, network answering, or gap abandonment. All existing callers remain
unchanged unless they opt in.

The application owns the truth of its acknowledgement, continuity checks on
recovery, and bounds on unpublished work. A false acknowledgement can destroy
its recovery path; an indefinitely stalled publisher retains more local log
data. The watermark is neither an archive protocol nor a consensus certificate.

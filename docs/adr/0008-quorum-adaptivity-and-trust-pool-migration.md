# Freeze slot policy and certify trust-pool succession

Status: accepted
Date: 2026-09-11

Applications need runtime quorum changes and authority replacement before the
broker substrate is built. We admit local revisions under an immutable anchor
trust floor, freeze each admitted slot's quorum, and install revisions through
a durable prepare/commit boundary. This gives a tractable honest-intersection
argument across different local revision histories. An unreachable validator
does not authorize reducing the floor, and a future revision cannot repair an
already stalled slot whose original fault assumptions no longer hold.

Replacing anchors uses a managed sequential Session and a terminal old-domain
decision binding the successor policy and application checkpoint. A certificate
of prior-policy anchor EXTERNALIZE signatures authorizes the derived successor
domain. Honest signers durably retire before releasing a terminal EXTERNALIZE;
recovery recognizes that persisted statement even without a later application
journal entry. Successor installation must be durable before signing resumes.
This permits completely disjoint successor pools while retaining authorization
by the prior pool. Losing that prior quorum may prevent migration.

Arbitrary mutation of the Engine's current quorum, independent local lint,
wall-clock switching, and recreation under a new network ID were rejected:
none alone preserves the history or establishes unique successor authority.
The managed profile deliberately forbids future-slot admission and native
gap-jump catch-up. Applications supply deterministic authorization and state
checkpoints; transports and placement policy remain outside consensus. The
interfaces are Experimental and leave the existing Stable wire/host ABI intact.

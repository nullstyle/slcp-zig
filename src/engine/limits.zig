//! Frozen wire limits (§4.5) and configurable engine caps (§5.1).
//! The `frozen_*` constants are protocol MUSTs — raising any of them is a
//! protocol-version event; the sanity vectors pin them. `Limits` fields are
//! per-engine configuration: 0-in-host.capnp means "engine default", and
//! config may lower `max_value_bytes` but never raise it past the frozen cap.

/// Protocol-frozen constants (§4.5). Never configuration.
pub const frozen_max_value_bytes_cap: u32 = 65536;
pub const frozen_max_nomination_values: u32 = 64; // votes / accepted each
pub const frozen_max_qset_depth: u32 = 4; // = qset.max_depth
pub const frozen_max_qset_validators: u32 = 255; // = qset.max_total_validators
pub const frozen_max_statement_bytes: u32 = 256 * 1024;
pub const frozen_max_frame_bytes: u32 = 1024 * 1024;
pub const frozen_timeout_cap_ms: u32 = 60_000;

/// Engine configuration (§5.1); defaults are the omakase profile.
pub const Limits = struct {
    max_value_bytes: u32 = 4096, // config may lower; never above frozen cap
    max_nomination_values: u32 = frozen_max_nomination_values,
    max_pending_envelopes: u32 = 1024,
    max_pending_bytes: u32 = 8 * 1024 * 1024,
    max_live_slots: u32 = 64,
    // Direct Engine configs may use 0 for a local-only cache;
    // qset_store.Store reserves the one mandatory local entry. host.capnp 0
    // still decodes as default.
    max_cached_qsets: u32 = 1024,
    timeout_cap_ms: u32 = frozen_timeout_cap_ms,
    max_stored_statement_bytes: u32 = 20 * 1024 * 1024,
};

pub const ValidateError = error{ BadValueBytes, BadNominationValues, BadTimeoutCap };

/// Engine-config gate (M2 `Config` calls this before `Engine.init`): config
/// may lower limits, never raise them past the frozen §4.5 caps.
pub fn validate(l: Limits) ValidateError!void {
    if (l.max_value_bytes == 0 or l.max_value_bytes > frozen_max_value_bytes_cap) return error.BadValueBytes;
    if (l.max_nomination_values == 0 or l.max_nomination_values > frozen_max_nomination_values) return error.BadNominationValues;
    if (l.timeout_cap_ms == 0 or l.timeout_cap_ms > frozen_timeout_cap_ms) return error.BadTimeoutCap;
}

test "validate rejects limits above frozen caps" {
    const std = @import("std");
    try validate(Limits{});
    try std.testing.expectError(error.BadValueBytes, validate(.{ .max_value_bytes = 100_000 }));
    try std.testing.expectError(error.BadNominationValues, validate(.{ .max_nomination_values = 200 }));
    try std.testing.expectError(error.BadTimeoutCap, validate(.{ .timeout_cap_ms = 61_000 }));
}

test "defaults respect frozen caps" {
    const std = @import("std");
    const l = Limits{};
    try std.testing.expect(l.max_value_bytes <= frozen_max_value_bytes_cap);
    try std.testing.expect(l.max_nomination_values <= frozen_max_nomination_values);
}

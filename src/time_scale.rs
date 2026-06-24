//! Process-global test-time-scale lever.
//!
//! A single process-wide multiplier on the time-based durations the sync stack
//! owns, so the time-dependent sync test suite runs faster and less flakily
//! (e.g. `OBSIDIAN_MEMORY_TIME_SCALE=0.1` turns a 30s sync-flag TTL into 3s).
//! It is the *general* lever for durations that lack a per-component test setter;
//! components with explicit setters (the supervisor/reconcile interval setters)
//! keep using those for precise control, and this fills the gap for everything
//! else.
//!
//! ## Production safety — the property that gates everything
//!
//! With no scale ever seeded (production: desktop app and daemon),
//! [`time_scale`] returns exactly `1.0` and [`scaled`] / [`scaled_ms`] take an
//! early-return identity branch — the returned value is the base UNCHANGED, with
//! no float arithmetic applied. Production timing is therefore bit-identical to a
//! build without this module. [`MAX_SCALE`] is `1.0`, making this a speed-up-only
//! lever: even a *set* scale can only shrink a duration, never lengthen it, so a
//! misconfigured env var can at worst speed tests up.
//!
//! ## Seeding
//!
//! This module uses only [`OnceLock`] and [`std::time::Duration`] and reads NO
//! environment variable (the `OBSIDIAN_MEMORY_TIME_SCALE` read lives in
//! sync-daemon's `startup_inner`, never here). The daemon seeds the scale once at
//! startup; any process that never seeds observes the `1.0` default.

use std::sync::OnceLock;
use std::time::Duration;

/// The process-global scale, seeded once at daemon startup. Unseeded → `1.0`.
static TIME_SCALE: OnceLock<f64> = OnceLock::new();

/// Minimum allowed scale. Below this, durations risk rounding to zero and
/// producing busy-loops, so we clamp up to keep every scaled duration positive.
pub const MIN_SCALE: f64 = 0.001;

/// Maximum allowed scale. Pinned to `1.0` to make this a speed-up-only lever:
/// scaling can never lengthen a duration past its declared base, so it can never
/// introduce longer-than-designed timeouts. (Raise this if a future need to slow
/// durations arises; default-deny is the safe start.)
pub const MAX_SCALE: f64 = 1.0;

/// Clamp a raw scale into `[MIN_SCALE, MAX_SCALE]`, mapping any non-finite input
/// (NaN / ±inf) to `MIN_SCALE`. `f64::clamp` PROPAGATES NaN rather than pinning
/// it to a bound, so a bare clamp would let a NaN through and panic the later
/// `Duration::mul_f64`; we sanitize non-finite values first so every scale used
/// downstream is finite and in range.
fn sanitize_scale(scale: f64) -> f64 {
    if scale.is_finite() {
        scale.clamp(MIN_SCALE, MAX_SCALE)
    } else {
        MIN_SCALE
    }
}

/// Seed the process-global time scale. Idempotent: the FIRST call wins and later
/// calls are ignored; returns whether this call set the value. The input is
/// clamped to `[MIN_SCALE, MAX_SCALE]` (non-finite input maps to `MIN_SCALE`).
/// Call once at daemon startup. A process that never seeds keeps the `1.0`
/// default.
pub fn set_time_scale(scale: f64) -> bool {
    TIME_SCALE.set(sanitize_scale(scale)).is_ok()
}

/// The active multiplier. Defaults to `1.0` (production / unseeded) so prod
/// timing is NEVER altered. Always finite and within `[MIN_SCALE, MAX_SCALE]`.
pub fn time_scale() -> f64 {
    *TIME_SCALE.get().unwrap_or(&1.0)
}

/// Scale a base `Duration` by an explicit scale. Pure — does not read the global,
/// so it is safe to call from parallel unit tests. At scale `1.0` it returns the
/// base IDENTICAL (the production-safety invariant). Saturating, never panics.
pub fn scaled_with(base: Duration, scale: f64) -> Duration {
    let s = sanitize_scale(scale);
    if s == 1.0 {
        return base; // exact identity — the prod path
    }
    base.mul_f64(s)
}

/// Scale a raw millisecond count by an explicit scale (for the daemon's `u64`
/// backoff math). Pure — does not read the global. At scale `1.0` it returns the
/// input unchanged. Saturating cast, never panics, min 0.
pub fn scaled_ms_with(base_ms: u64, scale: f64) -> u64 {
    let s = sanitize_scale(scale);
    if s == 1.0 {
        return base_ms; // exact identity — the prod path
    }
    (base_ms as f64 * s) as u64
}

/// Scale a base `Duration` by the active process-global multiplier. At the
/// default scale `1.0` (production / unseeded) this returns the base UNCHANGED.
pub fn scaled(base: Duration) -> Duration {
    scaled_with(base, time_scale())
}

/// Scale a raw millisecond count by the active process-global multiplier. At the
/// default scale `1.0` (production / unseeded) this returns the input unchanged.
pub fn scaled_ms(base_ms: u64) -> u64 {
    scaled_ms_with(base_ms, time_scale())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests exercise the PURE `_with` helpers with an explicit scale and
    // never touch the `TIME_SCALE` global, so they are safe to run in parallel.
    // The global-seeding path (`set_time_scale` first-wins) is covered by the
    // dedicated integration test (`tests/time_scale.rs`), which owns its own
    // process so the first-wins OnceLock is isolated.

    #[test]
    fn identity_at_scale_one() {
        // Prod-safety: scale 1.0 returns the base bit-identical, no float math.
        let base = Duration::from_secs(30);
        assert_eq!(scaled_with(base, 1.0), base);
    }

    #[test]
    fn speeds_up_duration() {
        assert_eq!(
            scaled_with(Duration::from_secs(30), 0.1),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn clamps_zero_to_min_keeping_duration_positive() {
        // A scale of 0 would zero the duration and busy-loop; the clamp to
        // MIN_SCALE keeps it strictly positive.
        let scaled = scaled_with(Duration::from_secs(30), 0.0);
        assert!(scaled > Duration::ZERO);
        assert_eq!(scaled, Duration::from_secs(30).mul_f64(MIN_SCALE));
    }

    #[test]
    fn clamps_above_max_to_identity() {
        // Speed-up-only invariant: a scale above MAX_SCALE clamps to 1.0, so the
        // result is the base unchanged — never lengthened.
        let base = Duration::from_secs(30);
        assert_eq!(scaled_with(base, 100.0), base);
    }

    #[test]
    fn scales_raw_millis() {
        assert_eq!(scaled_ms_with(60_000, 0.1), 6_000);
        assert_eq!(scaled_ms_with(60_000, 1.0), 60_000);
    }

    #[test]
    fn handles_non_finite_and_negative_without_panic() {
        // NaN and negative scales clamp to a finite in-range value and never
        // panic. (f64::clamp maps NaN to the lower bound, MIN_SCALE.)
        let base = Duration::from_secs(30);
        let from_nan = scaled_with(base, f64::NAN);
        assert!(from_nan > Duration::ZERO);
        assert_eq!(from_nan, base.mul_f64(MIN_SCALE));

        let from_negative = scaled_with(base, -5.0);
        assert!(from_negative > Duration::ZERO);
        assert_eq!(from_negative, base.mul_f64(MIN_SCALE));

        // ms variant: same clamp behavior, no panic.
        assert_eq!(
            scaled_ms_with(60_000, f64::NAN),
            (60_000_f64 * MIN_SCALE) as u64
        );
        assert_eq!(
            scaled_ms_with(60_000, -5.0),
            (60_000_f64 * MIN_SCALE) as u64
        );
    }
}

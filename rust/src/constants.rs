//! Canonical home for shared constants. One source of truth, imported by every module.

use ruint::aliases::U256;

/// Default independent maps per epoch — mirrors constants.py `DEFAULT_N_MAPS` (decision #2, 4 maps).
pub const DEFAULT_N_MAPS: usize = 4;

// ---- grid constants (mirror engine.py exactly) ----
pub(crate) const M: u128 = (1u128 << 127) - 1; // Mersenne prime M127
pub(crate) const HALF: u128 = M / 2; // 2^126 - 1

/// u128 → U256 helper used by engine, utils, ctr, and any module that needs big-int math.
#[inline]
pub(crate) fn u(v: u128) -> U256 {
    U256::from_limbs([v as u64, (v >> 64) as u64, 0, 0])
}

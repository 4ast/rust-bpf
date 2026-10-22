// SPDX-License-Identifier: GPL-2.0
//
// lib/ravg_impl.bpf.h: running average with a half life. The value is fixed
// point with RAVG_FRAC_BITS bits behind the point.

use crate::*;

pub const RAVG_VAL_BITS: u32 = 44;
pub const RAVG_FRAC_BITS: u32 = 20;
const ONE: u64 = 1 << RAVG_FRAC_BITS;

#[derive(Clone, Copy, Default)]
pub struct Ravg {
    /// current value
    val: u64,
    /// since when
    val_at: u64,
    /// what the periods before the current one add up to
    old: u64,
    /// the current period
    cur: u64,
}

fn decay(v: u64, shift: u64) -> u64 {
    u32::try_from(shift).ok().and_then(|shift| v.checked_shr(shift)).unwrap_or(0)
}

/// @dur as a fraction of @half_life
fn normalize_dur(dur: u64, half_life: u64) -> u64 {
    if dur < half_life { ((dur << RAVG_FRAC_BITS) + half_life - 1) / half_life } else { ONE }
}

impl Ravg {
    /// The value was `self.val` until @now and is @new_val from here on.
    pub fn accumulate(&mut self, new_val: u64, now: u64, half_life: u64) {
        // It may be difficult for the caller to guarantee monotonic progress.
        let now = max(now, self.val_at);

        if now != self.val_at {
            let seq_delta = now / half_life - self.val_at / half_life;

            // Decay ->old and fold ->cur into it.
            if seq_delta > 0 {
                self.old = decay(self.old, seq_delta).saturating_add(decay(self.cur, seq_delta));
                self.cur = 0;
            }

            if self.val != 0 && seq_delta > 0 {
                // the oldest period, which may be partial
                let dur = normalize_dur(half_life - self.val_at % half_life, half_life);
                self.old = self.old.saturating_add(self.val * decay(dur, seq_delta));

                // the full periods in the middle: 1/2 + 1/4 + ...
                if seq_delta > 1 {
                    self.old = self.old.saturating_add(self.val * (ONE - decay(ONE, seq_delta - 1)));
                }

                self.cur += self.val * normalize_dur(now % half_life, half_life);
            } else if self.val != 0 {
                self.cur += self.val * normalize_dur(now - self.val_at, half_life);
            }
        }

        self.val = min(new_val, (1 << RAVG_VAL_BITS) - 1);
        self.val_at = now;
    }

    pub fn read(&self, now: u64, half_life: u64) -> u64 {
        let now = max(now, self.val_at);
        let elapsed = now % half_life;

        // Accumulate the ongoing period into a temporary copy.
        let mut trd = *self;
        trd.accumulate(0, now, half_life);

        // At the beginning of a period the average is ->old. At the beginning
        // of the next it is old / 2 + cur / 2. In between blend the two.
        if elapsed == 0 {
            return trd.old;
        }
        let progress = normalize_dur(elapsed, half_life);
        let old = ((trd.old as u128 * (ONE - progress / 2) as u128) >> RAVG_FRAC_BITS) as u64;
        old + trd.cur / 2
    }

    /// The integer part.
    pub fn read_int(&self, now: u64, half_life: u64) -> u64 { self.read(now, half_life) >> RAVG_FRAC_BITS }
}

/// The average of a CPU. Its CPU and the timer update it. Like in C nothing
/// keeps them apart: the worst case is a sample that counts twice or not at all.
#[derive(Default)]
pub struct RavgCell(UnsafeCell<Ravg>);

unsafe impl Sync for RavgCell {}

impl RavgCell {
    /// Accumulates and returns the new average.
    pub fn update(&self, new_val: u64, now: u64) -> u64 {
        let ravg = unsafe { &mut *self.0.get() };
        ravg.accumulate(new_val, now, LAVD_RAVG_HALFLIFE_NS);
        ravg.read_int(now, LAVD_RAVG_HALFLIFE_NS)
    }
}

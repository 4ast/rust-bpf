// SPDX-License-Identifier: GPL-2.0
//
// lat_cri.bpf.c: how latency critical a task is, and from that its virtual
// deadline.
// Copyright (c) 2023-2025 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

use crate::*;

#[inline(never)]
fn log2x(v: u64) -> u64 { v.checked_ilog2().unwrap_or(0) as u64 }

impl TaskCtx {
    /// Prioritize a task by what it is and by who woke it up.
    fn calc_weight_factor(&mut self, p: Task) -> u64 {
        use TaskFlags as F;
        let flags = &mut self.flags;

        // Who woke the task is used once. A hard interrupt counts for more than
        // a soft one.
        let by_irq = if flags.take(F::WOKEN_BY_HARDIRQ) {
            LAVD_LC_WEIGHT_BOOST_HIGHEST
        } else if flags.take(F::WOKEN_BY_SOFTIRQ) {
            LAVD_LC_WEIGHT_BOOST_HIGH
        } else {
            0
        };

        let boosts = [
            (flags.contains(F::IS_WAKEUP), LAVD_LC_WEIGHT_BOOST_REGULAR),
            (flags.contains(F::IS_SYNC_WAKEUP), LAVD_LC_WEIGHT_BOOST_REGULAR),
            (flags.take(F::WOKEN_BY_RT_DL), LAVD_LC_WEIGHT_BOOST_HIGH),
            (p.is_kthread(), LAVD_LC_WEIGHT_BOOST_MEDIUM),
            (flags.contains(F::KSOFTIRQD), LAVD_LC_WEIGHT_BOOST_HIGH),
            (p.is_kernel_worker(), LAVD_LC_WEIGHT_BOOST_REGULAR),
            (flags.contains(F::IS_AFFINITIZED), LAVD_LC_WEIGHT_BOOST_REGULAR),
            (flags.contains(F::IS_EFFECTIVELY_PINNED) || p.is_migration_disabled(), LAVD_LC_WEIGHT_BOOST_MEDIUM),
            (flags.take(F::NEED_LOCK_BOOST), LAVD_LC_WEIGHT_BOOST_REGULAR),
        ];
        let weight_boost = 1 + by_irq + boosts.iter().filter(|(on, _)| *on).map(|(_, boost)| boost).sum::<u64>();

        // Respect nice priority.
        p.weight() * weight_boost + 1
    }

    fn calc_wait_factor(&self) -> u64 { min(self.wait_freq, LAVD_LC_FREQ_MAX) + 1 }
    fn calc_wake_factor(&self) -> u64 { min(self.wake_freq, LAVD_LC_FREQ_MAX) + 1 }

    /// The shorter the run time, the more latency critical.
    fn calc_reverse_runtime_factor(&self) -> u64 {
        time_delta(LAVD_LC_RUNTIME_MAX, self.avg_runtime_invr) / LAVD_SLICE_MIN_NS_DFL + 1
    }

    fn calc_sum_runtime_factor(&self, p: Task) -> u64 {
        let runtime = max(self.avg_runtime_invr, self.acc_runtime_invr);
        let sum = max(self.run_freq, 1) * max(runtime, 1);
        (sum >> LAVD_SHIFT) * p.weight()
    }

    fn calc_lat_cri(&mut self, p: Task) {
        // A task is more latency critical as its wait or wake frequencies
        // (i.e., wait_freq and wake_freq) are higher, and its run time shorter.
        let wait_ft = self.calc_wait_factor();
        let wake_ft = self.calc_wake_factor();
        let runtime_ft = self.calc_reverse_runtime_factor();
        let weight_ft = self.calc_weight_factor(p);

        // Wake and wait frequencies represent how much a task is in the middle
        // of a chain. The distributions are skewed, hence the logarithm.
        let log_wwf = log2x(wait_ft * wake_ft);
        let mut lat_cri = log_wwf + log2x(runtime_ft * weight_ft);
        lat_cri *= lat_cri;

        // Inherit some of the criticality of waker and wakee.
        let lat_cri_giver = self.lat_cri_waker + self.lat_cri_wakee;
        if lat_cri_giver > 2 * lat_cri {
            let giver_inh = (lat_cri_giver - 2 * lat_cri) >> LAVD_LC_INH_GIVER_SHIFT;
            let receiver_max = lat_cri >> LAVD_LC_INH_RECEIVER_SHIFT;
            lat_cri += min(giver_inh, receiver_max);
        }

        self.lat_cri = lat_cri;
        self.lat_cri_waker = 0;
        self.lat_cri_wakee = 0;
        self.normalized_lat_cri = normalize_lat_cri(lat_cri);

        // A task that is in the middle of a chain and uses a lot of CPU time
        // belongs on a big core.
        self.perf_cri = if HAVE_LITTLE_CORE.on() {
            log_wwf + log2x(self.calc_sum_runtime_factor(p))
        } else {
            LAVD_SCALE
        };
    }

    /// Penalty for a task that got more than its share: [100%, 200%].
    fn calc_greedy_penalty(&mut self, p: Task) -> u64 {
        let avg_svc_time = SYS_STAT.avg_svc_time_iwgt.get();
        let lag_max = max(p.scale_by_weight_inverse(LAVD_TASK_LAG_MAX), 1) as i64;
        let mut lag = avg_svc_time.wrapping_sub(self.svc_time_iwgt) as i64;

        self.flags.set(TaskFlags::IS_GREEDY, lag < 0);
        if lag > lag_max {
            // Don't let a task that slept for long collect credit for ever.
            self.svc_time_iwgt = avg_svc_time.wrapping_sub(lag_max as u64);
        }
        lag = lag.clamp(-lag_max, lag_max);

        let penalty = (((lag_max - lag) as u64) << LAVD_SHIFT) / lag_max as u64;
        LAVD_SCALE + (penalty >> LAVD_LC_GREEDY_SHIFT)
    }

    fn calc_adjusted_runtime(&self) -> u64 {
        // Prefer a short-running (avg_runtime) and recently woken-up
        // (acc_runtime) task.
        LAVD_ACC_RUNTIME_MAX + min(self.acc_runtime_invr, LAVD_ACC_RUNTIME_MAX)
    }

    fn calc_virtual_deadline_delta(&mut self, p: Task) -> u64 {
        self.calc_lat_cri(p);
        let greedy_penalty = self.calc_greedy_penalty(p);
        let adjusted_runtime = self.calc_adjusted_runtime();

        ((adjusted_runtime * greedy_penalty) / max(self.lat_cri, 1)) >> LAVD_SHIFT
    }

    /// The virtual deadline of the task.
    #[inline(never)]
    pub fn calc_when_to_run(&mut self, p: Task) -> u64 {
        // Before enqueueing a task to a run queue, we should decide when a
        // task should be scheduled.
        let dl_delta = self.calc_virtual_deadline_delta(p);
        CUR_LOGICAL_CLK.get() - calc_compete_window() + dl_delta
    }
}

/// How far behind the logical clock a deadline may be. The more tasks wait, the
/// less a newcomer may jump the queue.
fn calc_compete_window() -> u64 {
    let nr_q = SYS_STAT.nr_queued_task.get();
    let nr_c = NR_CPUS_ONLN.get();
    if nr_q > nr_c { (LAVD_DL_COMPETE_WINDOW * nr_c) / nr_q } else { LAVD_DL_COMPETE_WINDOW }
}

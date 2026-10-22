// SPDX-License-Identifier: GPL-2.0
//
// balance.bpf.c: which compute domains give tasks away and which take them,
// and where a CPU gets its next task from.
// Copyright (c) 2025 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

use crate::*;

#[inline(never)]
fn calc_mig_delta(base_share_invr: u64, nz_qlen: u64, mig_delta_factor: u64) -> u64 {
    if mig_delta_factor > 0 {
        return base_share_invr * mig_delta_factor / LAVD_SCALE;
    }

    // The more domains have tasks waiting, the narrower the band in which a
    // domain is left alone.
    base_share_invr >> match nz_qlen {
        n if n >= SYS_STAT.nr_active_cpdoms.get() => LAVD_CPDOM_MIG_SHIFT_OL,
        0 => LAVD_CPDOM_MIG_SHIFT_UL,
        _ => LAVD_CPDOM_MIG_SHIFT,
    }
}

/// What plan_x_cpdom_migration() found out about the system.
struct LoadSummary {
    total_load_invr: u64,
    total_cap_sum: u64,
    /// number of domains with tasks in their queues
    nz_qlen: u64,
    mig_delta_factor: u64,
}

impl Cpdom {
    /// Decides on the role of the domain. Returns whether it is a stealee.
    #[inline(never)]
    fn classify(&self, sum: &LoadSummary) -> bool {
        let nr_active_cpus = self.nr_active_cpus.get();
        let nr_active_cpdoms = SYS_STAT.nr_active_cpdoms.get();
        let load_invr = self.load_invr.get();
        let mut fair_share_invr = 0;

        let (stealer_threshold, stealee_threshold) = if NO_FAST_LB.on() && nr_active_cpdoms > 0 {
            let avg = sum.total_load_invr / nr_active_cpdoms;
            let x_mig_delta = calc_mig_delta(avg, sum.nz_qlen, sum.mig_delta_factor);
            (avg - x_mig_delta, avg + x_mig_delta)
        } else if nr_active_cpus > 0 && sum.total_cap_sum > 0 {
            // The share of the load that matches the share of the capacity.
            fair_share_invr = sum.total_load_invr * self.cap_sum_active_cpus.get() / sum.total_cap_sum;
            let base_share_invr = match sum.total_load_invr - fair_share_invr {
                0 => fair_share_invr,
                other_share_invr => min(fair_share_invr, other_share_invr),
            };
            let x_mig_delta = calc_mig_delta(base_share_invr, sum.nz_qlen, sum.mig_delta_factor);
            (fair_share_invr - x_mig_delta, fair_share_invr + x_mig_delta)
        } else {
            (0, 0)
        };

        // Under-loaded and active: half of what is missing may come in.
        if nr_active_cpus > 0 && load_invr <= stealer_threshold {
            self.set_role(Some(fair_share_invr.saturating_sub(load_invr) / 2), None);
            return false;
        }

        // Over-loaded, or not active at all, with tasks waiting: half of what
        // is too much may leave.
        if nr_active_cpus == 0 || load_invr >= stealee_threshold {
            let budget = load_invr.saturating_sub(fair_share_invr) / 2;
            if self.qload_invr.get() != 0 && budget != 0 {
                self.set_role(None, Some(budget));
                return true;
            }
        }

        self.set_role(None, None);
        false
    }
}

/// From the timer.
#[inline(never)]
pub fn plan_x_cpdom_migration() {
    let mut sum = LoadSummary {
        total_load_invr: 0,
        total_cap_sum: 0,
        nz_qlen: 0,
        mig_delta_factor: (MIG_DELTA_PCT.get() << LAVD_SHIFT) / 100,
    };
    let mut max_avg_util_wall = 0;
    let mut overflow_running = false;

    // The load of every active domain.
    for cpdomc in cpdoms() {
        let nr_active_cpus = cpdomc.nr_active_cpus.get() as u64;
        if nr_active_cpus == 0 {
            // Tasks run on overflow CPUs of a domain that should be empty.
            overflow_running |= cpdomc.cur_util_wall_sum.get() > 0;
            continue;
        }

        let util = (cpdomc.avg_util_wall_sum.get() << LAVD_SHIFT) / nr_active_cpus;
        max_avg_util_wall = max(max_avg_util_wall, util >> LAVD_SHIFT);

        let (load_invr, queued) = if NO_FAST_LB.on() {
            let qlen = cpdomc.nr_queued_task.get();
            (util + (qlen << (LAVD_SHIFT * 3)) / max(cpdomc.cap_sum_active_cpus.get(), 1), qlen)
        } else {
            let qload = cpdomc.qload_invr.get();
            (cpdomc.avg_util_invr_sum.get() + qload, qload)
        };
        cpdomc.load_invr.set(load_invr);
        sum.nz_qlen += (queued != 0) as u64;
        sum.total_load_invr += load_invr;
        sum.total_cap_sum += cpdomc.cap_sum_active_cpus.get();
    }

    // Nothing to gain when the system is mostly idle.
    let lb_low_util_wall = LB_LOW_UTIL_WALL.get();
    let busy = lb_low_util_wall == 0 || max_avg_util_wall >= lb_low_util_wall;
    let nr_stealee = if busy { cpdoms().iter().filter(|cpdomc| cpdomc.classify(&sum)).count() as u64 } else { 0 };

    if nr_stealee > 0 || (busy && overflow_running) {
        SYS_STAT.nr_stealee.set(nr_stealee);
    } else if SYS_STAT.nr_stealee.take() > 0 {
        cpdoms().iter().for_each(|cpdomc| cpdomc.set_role(None, None));
    }
}

/// When a task would be done: what is queued and the task itself, spread over
/// the capacity.
#[inline(never)]
fn calc_comp_time(task_svc_invr: u64, queued_svc_invr: u64, cap_sum: u64, nr_cpus: u64) -> u64 {
    if cap_sum == 0 {
        return LAVD_COMP_TIME_INF;
    }
    ((queued_svc_invr + task_svc_invr * nr_cpus) * LAVD_SCALE) / cap_sum
}

#[inline(never)]
pub fn calc_comp_time_on_cpdom(task_svc_invr: u64, cpdomc: &Cpdom) -> u64 {
    let mut cap_sum = cpdomc.cap_sum_active_cpus.get();
    let mut nr_cpus = cpdomc.nr_active_cpus.get() as u64;

    if !OVRFLW_COUNTED_ACTIVE.on() {
        cap_sum += cpdomc.cap_sum_overflow_cpus.get();
        nr_cpus += cpdomc.nr_overflow_cpus.get();
    }
    calc_comp_time(task_svc_invr, cpdomc.qload_svc_invr.get(), cap_sum, nr_cpus)
}

/// The load of the task at the head of a queue.
#[inline(never)]
fn dsq_peek_task_load(dsq: LavdDsq) -> u64 {
    dsq.dsq().peek().and_then(find_task_ctx).map_or(0, |taskc| taskc.load_metric())
}

impl Cpdom {
    /// The queue of the domain that has the most in it.
    #[inline(never)]
    fn pick_most_loaded_dsq(&self) -> Option<LavdDsq> {
        let slow = NO_FAST_LB.on();

        let cpdom_dsq = use_cpdom_dsq().then(|| {
            (if slow { self.dsq().nr_queued() } else { self.qload_invr.get() }, self.dsq())
        });
        let cpu_dsqs = is_per_cpu_dsq_migratable().then(|| self.all_cpus.iter()).into_iter().flatten()
            .filter_map(|cpu| cpu_ctxs().get(cpu as usize))
            .map(|cpuc| {
                let dsq = cpu_to_dsq(cpuc.cpu_id);
                (if slow { dsq.nr_queued() + cpuc.local_dsq().nr_queued() } else { cpuc.qload_invr.get() }, dsq)
            });

        // The queue of the domain unless a CPU has strictly more.
        cpdom_dsq.into_iter().chain(cpu_dsqs)
            .reduce(|best, dsq| if dsq.0 > best.0 { dsq } else { best })
            .map(|(_, dsq)| dsq)
    }

    /// Moves a task from the fullest queue of @self to the local queue and
    /// charges it to the budgets.
    fn give_task_to(&self, stealer: &Cpdom) -> bool {
        let Some(dsq) = self.pick_most_loaded_dsq() else { return false };
        let task_load = if NO_FAST_LB.on() { None } else { Some(dsq_peek_task_load(dsq)) };

        if !dsq.dsq().move_to_local() {
            return false;
        }
        if let Some(task_load) = task_load {
            self.decrement_stealee_budget(task_load);
            stealer.decrement_stealer_budget(task_load);
        }
        true
    }

    /// A stealer looks for a stealee, the closest first.
    fn try_to_steal_task(&self) -> bool {
        let nr_active_cpus = self.nr_active_cpus.get() as u64;
        if nr_active_cpus == 0 {
            return false;
        }

        // Probabilistically make a go or no go decision to avoid the
        // thundering herd problem.
        if NO_FAST_LB.on() && !prob_x_out_of_y(1, nr_active_cpus * LAVD_CPDOM_MIG_PROB_FT) {
            return false;
        }

        for ring in self.neighbors.iter().take_while(|ring| !ring.is_empty()) {
            let stolen = ring.iter().filter_map(|&id| cpdoms().get(id as usize))
                .filter(|pick| pick.is_stealee.on() && pick.stealee_budget_invr.get() > 0)
                .find(|pick| pick.give_task_to(self));

            if let Some(pick) = stolen {
                if NO_FAST_LB.on() {
                    pick.is_stealee.turn(false);
                    self.is_stealer.turn(false);
                }
                return true;
            }

            // Farther away it gets expensive: go on with a low probability.
            if !prob_x_out_of_y(1, LAVD_CPDOM_MIG_PROB_FT) {
                break;
            }
        }
        false
    }

    /// Rather than going idle take anything from anybody.
    fn force_to_steal_task(&self) -> bool { self.neighbors().any(|pick| pick.give_task_to(self)) }

    /// CPUs that interrupts keep busy leave the tasks that preemption hurts to
    /// the others, as long as there are others and that queue is the shorter.
    fn can_consume_steady_dsq(&self, cpuc: &CpuCtx) -> bool {
        !cpuc.is_turbulent()
            || self.dsq().nr_queued() > self.turb_dsq().nr_queued()
            || self.nr_steady_cpus.get() == 0
    }
}

/// Gets the next task for this CPU. Returns whether there is one.
#[inline(never)]
pub fn consume_task(cpuc: &CpuCtx) -> bool {
    let Some(cpdomc) = cpuc.cpdom() else { return false };

    // If the current compute domain is a stealer, try to steal a task from any
    // of the stealee domains.
    if nr_cpdoms() > 1 && cpdomc.is_stealer.on() && cpdomc.try_to_steal_task() {
        return true;
    }

    // The queues of this CPU, the one with the earliest deadline first.
    let mut dsqs = [
        (use_per_cpu_dsq(), cpu_to_dsq(cpuc.cpu_id)),
        (use_cpdom_dsq() && cpdomc.can_consume_steady_dsq(cpuc), cpdomc.dsq()),
        (use_cpdom_dsq(), cpdomc.turb_dsq()),
    ].map(|(usable, dsq)| (usable.then(|| dsq.peek_vtime()).flatten(), dsq));
    dsqs.sort_unstable_by_key(|(vtime, _)| vtime.unwrap_or(u64::MAX));

    if dsqs.iter().any(|(vtime, dsq)| vtime.is_some() && dsq.dsq().move_to_local()) {
        return true;
    }

    nr_cpdoms() > 1 && MIG_DELTA_PCT.get() == 0 && cpdomc.force_to_steal_task()
}

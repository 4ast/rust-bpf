// SPDX-License-Identifier: GPL-2.0
//
// sys_stat.bpf.c: every 10 msec a timer adds up what the CPUs have counted and
// derives from it what the rest of the scheduler steers by.
// Copyright (c) 2023, 2024 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>
//
// C tells the time of tasks, interrupts and higher scheduling classes apart by
// rq->clock_task and rq->clock_pelt. Here everything that a CPU did and that
// our tasks did not account for is "steal".

use crate::*;

/// What one round collects.
#[derive(Default)]
struct SysStatCtx {
    now: u64,
    duration_wall: u64,
    idle_total_wall: u64,
    compute_total_invr: u64,
    tot_task_time_iwgt: u64,
    tsct_spike_invr: u64,
    nr_queued_task: u64,
    max_lat_cri: u64,
    avg_lat_cri: u64,
    sum_lat_cri: u64,
    nr_sched: u64,
    nr_preempt: u64,
    nr_perf_cri: u64,
    nr_lat_cri: u64,
    nr_x_migration: u64,
    nr_big: u64,
    nr_pc_on_big: u64,
    nr_lc_on_big: u64,
    min_perf_cri: u64,
    avg_perf_cri: u64,
    max_perf_cri: u64,
    sum_perf_cri: u64,
}

impl Cpdom {
    fn reset_sums(&self) {
        [
            &self.cur_util_wall_sum, &self.avg_util_wall_sum, &self.cur_util_invr_sum, &self.avg_util_invr_sum,
            &self.avg_steal_util_invr_sum, &self.avg_dom_pinned_util_invr_sum, &self.util_sum_steady,
            &self.util_sum_turb, &self.cap_sum_steady, &self.cap_sum_turb,
        ].into_iter().for_each(|sum| sum.set(0));
        self.nr_steady_cpus.set(0);
        self.nr_turb_cpus.set(0);
    }

    /// All the tasks that wait for a CPU of this domain.
    fn count_queued_tasks(&self) -> u64 {
        let shared = if use_cpdom_dsq() { self.dsq().nr_queued() + self.turb_dsq().nr_queued() } else { 0 };
        let per_cpu = self.all_cpus.iter().map(|cpu| {
            let own = use_per_cpu_dsq() && cpu == get_primary_cpu(cpu);
            Dsq::local_on(cpu).nr_queued() + if own { cpu_to_dsq(cpu).nr_queued() } else { 0 }
        }).sum::<u64>();
        shared + per_cpu
    }

    /// Moves the line between the tasks for steady and for turbulent CPUs so
    /// that both kinds are loaded as wanted.
    fn update_vuln_thresh(&self) {
        let (cap_steady, cap_turb) = (self.cap_sum_steady.get(), self.cap_sum_turb.get());
        let thresh = self.vuln_thresh.get();

        if self.nr_turb_cpus.get() == 0 || cap_turb == 0 {
            self.vuln_thresh.set(0);
        } else if cap_steady > 0 {
            let load_high = (self.util_sum_steady.get() << LAVD_SHIFT) / cap_steady;
            let load_low = (self.util_sum_turb.get() << LAVD_SHIFT) / cap_turb;
            let target = (load_high * LAT_LOAD_TARGET_PCT.get()) / 100;

            if load_low > target && thresh > 0 {
                self.vuln_thresh.set(thresh - 1);
            } else if load_low < target && thresh < LAVD_VULN_THRESH_MAX {
                self.vuln_thresh.set(thresh + 1);
            }
        }
    }
}

impl CpuCtx {
    /// Closes the books on an idle period that is still going on.
    fn fold_idle_time(&self, now: u64) {
        for _ in 0..LAVD_MAX_RETRY {
            let old_clk = self.idle_start_clk.get();
            if old_clk == 0 || time_after(old_clk, now) {
                break;
            }
            if self.idle_start_clk.cas(old_clk, now) {
                self.idle_total_wall.add(time_delta(now, old_clk));
                break;
            }
        }
    }
}

impl SysStatCtx {
    fn new() -> SysStatCtx {
        let now = scx_now();
        let duration_wall = max(time_delta(now, SYS_STAT.last_update_clk.get()), 1);
        SYS_STAT.last_update_clk.set(now);
        SysStatCtx { now, duration_wall, min_perf_cri: LAVD_SCALE, ..Default::default() }
    }

    /// @time as a share of the interval
    fn util(&self, time: u64) -> u64 { (time << LAVD_SHIFT) / self.duration_wall }

    /// How busy the CPU was and with what.
    fn collect_util(&mut self, cpuc: &CpuCtx) {
        // A boosted slice is for when nobody waits.
        if cpuc.nr_pinned_tasks.get() > 0 || !can_boost_slice() || cpuc.local_dsq().nr_queued() > 0 {
            shrink_boosted_slice_remote(cpuc, self.now);
        }

        self.tot_task_time_iwgt += cpuc.tot_task_time_iwgt.take();

        cpuc.fold_idle_time(self.now);
        let compute_wall = time_delta(self.duration_wall, cpuc.idle_total_wall.get());

        // What the CPU did for others.
        let steal_time_wall = time_delta(compute_wall, cpuc.tot_task_time_wall.take());
        let steal_time_invr = min(cpuc.wall_to_invr(steal_time_wall), compute_wall);
        cpuc.cur_steal_util_wall.set(self.util(steal_time_wall));
        cpuc.avg_steal_util_wall.set(asym_avg(cpuc.avg_steal_util_wall.get(), cpuc.cur_steal_util_wall.get()));
        cpuc.cur_steal_util_invr.set(self.util(steal_time_invr));
        cpuc.avg_steal_util_invr.set(asym_avg(cpuc.avg_steal_util_invr.get(), cpuc.cur_steal_util_invr.get()));

        let avg_irq = cpuc.avg_irq_steal_ravg.update(cpuc.cur_steal_util_invr.get(), self.now);
        cpuc.lat_headroom.set(LAVD_SCALE.saturating_sub(avg_irq));

        // All of it.
        cpuc.cur_util_wall.set(self.util(compute_wall));
        cpuc.avg_util_wall.set(asym_avg(cpuc.avg_util_wall.get(), cpuc.cur_util_wall.get()));

        let compute_invr = min(cpuc.tot_task_time_invr.take() + steal_time_invr, compute_wall);
        cpuc.cur_util_invr.set(self.util(compute_invr));
        cpuc.avg_util_invr.set(asym_avg(cpuc.avg_util_invr.get(), cpuc.cur_util_invr.get()));

        cpuc.calc_cpuperf_target();

        // The part that cannot leave the domain.
        let dom_pinned_invr = min(cpuc.tot_dom_pinned_task_time_invr.take(), compute_wall);
        cpuc.avg_dom_pinned_util_invr.set(asym_avg(cpuc.avg_dom_pinned_util_invr.get(), self.util(dom_pinned_invr)));

        if let Some(cpdomc) = cpdoms().get(cpuc.cpdom_id as usize) {
            cpdomc.cur_util_wall_sum.bump(cpuc.cur_util_wall.get());
            cpdomc.avg_util_wall_sum.bump(cpuc.avg_util_wall.get());
            cpdomc.cur_util_invr_sum.bump(cpuc.cur_util_invr.get());
            cpdomc.avg_util_invr_sum.bump(cpuc.avg_util_invr.get());
            cpdomc.avg_steal_util_invr_sum.bump(cpuc.avg_steal_util_invr.get());
            cpdomc.avg_dom_pinned_util_invr_sum.bump(cpuc.avg_dom_pinned_util_invr.get());
        }

        // When a CPU is almost full, the demand is likely higher than that.
        self.compute_total_invr += compute_invr;
        if cpuc.cur_util_wall.get() > LAVD_CC_UTIL_SPIKE {
            self.tsct_spike_invr += compute_invr;
        }
    }

    /// What the CPU counted while scheduling.
    fn collect_counters(&mut self, cpuc: &CpuCtx) {
        cpuc.update_effective_capacity();

        if cpuc.big_core {
            self.nr_big += cpuc.nr_sched.get();
            self.nr_pc_on_big += cpuc.nr_perf_cri.get();
            self.nr_lc_on_big += cpuc.nr_lat_cri.get();
        }
        self.nr_perf_cri += cpuc.nr_perf_cri.take();
        self.nr_lat_cri += cpuc.nr_lat_cri.take();
        self.nr_x_migration += cpuc.nr_x_migration.take();
        self.sum_lat_cri += cpuc.sum_lat_cri.take();
        self.nr_sched += cpuc.nr_sched.take();
        self.nr_preempt += cpuc.nr_preempt.take();
        self.max_lat_cri = max(self.max_lat_cri, cpuc.max_lat_cri.take());

        if HAVE_LITTLE_CORE.on() {
            self.min_perf_cri = min(self.min_perf_cri, cpuc.min_perf_cri.get());
            cpuc.min_perf_cri.set(LAVD_SCALE);
            self.max_perf_cri = max(self.max_perf_cri, cpuc.max_perf_cri.take());
            self.sum_perf_cri += cpuc.sum_perf_cri.take();
        }
    }

    /// Do interrupts leave the CPU alone?
    fn collect_turbulence(&mut self, cpuc: &CpuCtx) {
        let steady = !cpuc.is_turbulent();
        if steady { STEADY_CPUS.set(cpuc.cpu_id) } else { STEADY_CPUS.clear(cpuc.cpu_id) }

        if let Some(cpdomc) = cpdoms().get(cpuc.cpdom_id as usize) {
            let (util_sum, cap_sum, nr_cpus) = if steady {
                (&cpdomc.util_sum_steady, &cpdomc.cap_sum_steady, &cpdomc.nr_steady_cpus)
            } else {
                (&cpdomc.util_sum_turb, &cpdomc.cap_sum_turb, &cpdomc.nr_turb_cpus)
            };
            util_sum.bump(cpuc.util_est.get());
            cap_sum.bump(cpuc.max_capacity);
            nr_cpus.bump(1);
        }

        self.idle_total_wall += cpuc.idle_total_wall.take();
    }

    #[inline(never)]
    fn collect(&mut self) {
        for cpdomc in cpdoms() {
            cpdomc.reset_sums();
            cpdomc.nr_queued_task.set(cpdomc.count_queued_tasks());
            self.nr_queued_task += cpdomc.nr_queued_task.get();
        }

        cpu_ctxs().iter().for_each(|cpuc| self.collect_util(cpuc));
        cpu_ctxs().iter().for_each(|cpuc| self.collect_counters(cpuc));
        cpu_ctxs().iter().for_each(|cpuc| self.collect_turbulence(cpuc));
    }

    #[inline(never)]
    fn calc(&mut self) {
        static CNT: AtomicU64 = AtomicU64::new(0);
        let s = &SYS_STAT;
        let have_little_core = HAVE_LITTLE_CORE.on();

        let duration_total_wall = max(self.duration_wall * NR_CPUS_ONLN.get(), 1);
        let compute_total_wall = time_delta(duration_total_wall, self.idle_total_wall);
        let cur_util_wall = (compute_total_wall << LAVD_SHIFT) / duration_total_wall;

        // The invariant utilization cannot be above the one by the wall clock.
        let mut cur_util_invr = (self.compute_total_invr << LAVD_SHIFT) / duration_total_wall;
        if cur_util_invr > cur_util_wall {
            cur_util_invr = min(s.avg_util_invr.get(), cur_util_wall);
        }
        let scu_spike_invr = (self.tsct_spike_invr << (LAVD_SHIFT - 1)) / duration_total_wall;
        let cur_util_invr = min(cur_util_invr + scu_spike_invr, LAVD_SCALE);

        if self.nr_sched == 0 || compute_total_wall == 0 {
            // Nothing was scheduled: keep what we have.
            self.max_lat_cri = s.max_lat_cri.get();
            self.avg_lat_cri = s.avg_lat_cri.get();
            self.min_perf_cri = s.min_perf_cri.get();
            self.max_perf_cri = s.max_perf_cri.get();
            self.avg_perf_cri = s.avg_perf_cri.get();
        } else {
            self.avg_lat_cri = self.sum_lat_cri / self.nr_sched;
            self.avg_perf_cri = self.sum_perf_cri / self.nr_sched;
        }

        s.avg_util_wall.set(asym_avg(s.avg_util_wall.get(), cur_util_wall));
        s.avg_util_invr.set(asym_avg(s.avg_util_invr.get(), cur_util_invr));
        s.max_lat_cri.set(avg(s.max_lat_cri.get(), self.max_lat_cri));
        s.avg_lat_cri.set(avg(s.avg_lat_cri.get(), self.avg_lat_cri));
        s.thr_lat_cri.set(s.max_lat_cri.get()
            - (s.max_lat_cri.get().saturating_sub(s.avg_lat_cri.get()) >> PREEMPT_SHIFT.get()));

        if have_little_core {
            s.min_perf_cri.set(avg(s.min_perf_cri.get(), self.min_perf_cri));
            s.avg_perf_cri.set(avg(s.avg_perf_cri.get(), self.avg_perf_cri));
            s.max_perf_cri.set(avg(s.max_perf_cri.get(), self.max_perf_cri));
        }

        let avg_svc_time_iwgt = self.tot_task_time_iwgt.checked_div(self.nr_sched).unwrap_or(0);
        s.avg_svc_time_iwgt.set(avg(s.avg_svc_time_iwgt.get(), avg_svc_time_iwgt));
        s.nr_queued_task.set(avg(s.nr_queued_task.get(), self.nr_queued_task));

        // Half the statistics every now and then, so that they follow the load.
        let counters = [
            (&s.nr_sched, self.nr_sched), (&s.nr_preempt, self.nr_preempt),
            (&s.nr_perf_cri, self.nr_perf_cri), (&s.nr_lat_cri, self.nr_lat_cri),
            (&s.nr_x_migration, self.nr_x_migration), (&s.nr_big, self.nr_big),
            (&s.nr_pc_on_big, self.nr_pc_on_big), (&s.nr_lc_on_big, self.nr_lc_on_big),
        ];
        let decay = CNT.get() == LAVD_SYS_STAT_DECAY_TIMES;
        CNT.set(if decay { 0 } else { CNT.get() + 1 });
        if decay {
            POWER_MODE_NS.iter().for_each(|mode_ns| mode_ns.sub(mode_ns.get() / 2));
        }
        for (total, new) in counters {
            total.set((total.get() >> decay as u32) + new);
        }

        cpdoms().iter().for_each(Cpdom::update_vuln_thresh);
        update_power_mode_time();
    }
}

/// The time slice such that every waiting task gets to run within the targeted
/// latency.
fn calc_sys_time_slice() {
    let slice_wall = match SYS_STAT.nr_queued_task.get() {
        0 => SLICE_MAX_NS.get(),
        nr_q => ((LAVD_TARGETED_LATENCY_NS * SYS_STAT.nr_active.get()) / nr_q)
            .clamp(SLICE_MIN_NS.get(), max(SLICE_MIN_NS.get(), SLICE_MAX_NS.get())),
    };
    SYS_STAT.slice_wall.set(avg(SYS_STAT.slice_wall.get(), slice_wall));
}

#[inline(never)]
pub fn update_sys_stat() {
    let mut c = SysStatCtx::new();
    c.collect();
    c.calc();

    if IS_AUTOPILOT_ON.on() {
        do_autopilot();
    }
    if !NO_CORE_COMPACTION.on() {
        do_core_compaction();
    }
    if REINIT_CPUMASK_FOR_PERFORMANCE.on() {
        REINIT_CPUMASK_FOR_PERFORMANCE.turn(false);
        reinit_active_cpumask_for_performance();
    }

    calc_sys_time_slice();
    update_thr_perf_cri();

    if nr_cpdoms() > 1 {
        plan_x_cpdom_migration();
    }
}

bpf_timer_map!(lavd_update_timer, update_timer, 1);

extern "C" fn update_timer_cb(_map: *mut u8, _key: *mut u32, timer: *mut bpf_timer) -> i32 {
    if !catch_panic!(update_sys_stat) {
        scx_error!("panic in update_sys_stat()");
    }

    if Timer::from_ptr(timer).is_none_or(|timer| timer.start(LAVD_SYS_STAT_INTERVAL_NS, 0).is_err()) {
        scx_error!("Failed to arm update timer");
    }
    0
}

pub fn init_sys_stat(now: u64) -> Result {
    SYS_STAT.last_update_clk.set(now);
    SYS_STAT.nr_active.set(NR_CPUS_ONLN.get());
    SYS_STAT.slice_wall.set(SLICE_MAX_NS.get());
    SYS_STAT.nr_active_cpdoms.set(cpdoms().iter().filter(|cpdomc| cpdomc.nr_active_cpus.get() > 0).count() as u64);

    update_timer().init(0, CLOCK_BOOTTIME, update_timer_cb)?.start(LAVD_SYS_STAT_INTERVAL_NS, 0)
}

pub fn exit_sys_stat() { update_timer().cancel_all(); }

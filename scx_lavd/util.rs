// SPDX-License-Identifier: GPL-2.0
//
// util.bpf.c: averages, what kind of task this is, which queue it goes to.
// Copyright (c) 2023, 2024 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

use crate::*;

const PF_IO_WORKER: u32 = 0x0000_0010;

pub fn time_delta(after: u64, before: u64) -> u64 { after.saturating_sub(before) }

/// Exponential weighted moving average: (1 - 1/2^decay) of old, the rest new.
fn ewma(old: u64, new: u64, decay: u32) -> u64 { (old - (old >> decay)) + (new >> decay) }

#[inline(never)]
pub fn avg(old: u64, new: u64) -> u64 { ewma(old, new, 3) }

/// Increase fast but decrease slowly.
#[inline(never)]
pub fn asym_avg(old: u64, new: u64) -> u64 {
    if old < new { ewma(new, old, 2) } else { ewma(old, new, 3) }
}

/// The average of a frequency, given the time since the last event.
#[inline(never)]
pub fn avg_freq(old_freq: u64, interval: u64) -> u64 {
    ewma(old_freq, LAVD_TIME_ONE_SEC / max(interval, 1), 3)
}

#[inline(never)]
pub fn prob_x_out_of_y(x: u64, y: u64) -> bool { x >= y || (random() as u64 % y) < x }

// ── Kinds of tasks ───────────────────────────────────────────────────

pub trait LavdTask: Copy {
    fn is_kernel_worker(self) -> bool;
    fn is_ksoftirqd(self) -> bool;
    fn is_permanently_pinned(self) -> bool;
    fn is_rt_or_dl(self) -> bool;
}

impl LavdTask for Task {
    fn is_kernel_worker(self) -> bool { self.flags() & (PF_WQ_WORKER | PF_IO_WORKER) != 0 }
    #[inline(never)]
    fn is_ksoftirqd(self) -> bool { self.is_kthread() && self.comm().starts_with(b"ksoftirqd/") }
    fn is_permanently_pinned(self) -> bool { self.nr_cpus_allowed() == 1 }
    fn is_rt_or_dl(self) -> bool { self.prio() < MAX_RT_PRIO }
}

#[inline(never)]
pub fn is_rt_or_dl_task_running(cpu: i32) -> bool { cpu_curr(cpu).is_some_and(Task::is_rt_or_dl) }

impl TaskCtx {
    pub fn is_effectively_pinned(&self) -> bool { self.flags.contains(TaskFlags::IS_EFFECTIVELY_PINNED) }
    pub fn is_affinitized(&self) -> bool { self.flags.contains(TaskFlags::IS_AFFINITIZED) }
    pub fn is_lat_cri(&self) -> bool { self.lat_cri >= SYS_STAT.avg_lat_cri.get() }
    pub fn have_scheduled(&self) -> bool { self.slice_wall != 0 }
    pub fn load_metric(&self) -> u64 { self.util_est }

    /// Derives the flags that depend on where the task may run.
    #[inline(never)]
    pub fn set_affinity_flags(&mut self, cpumask: Cpumask) {
        let weight = cpumask.weight();
        let is_affinitized = weight != NR_CPU_IDS.get();
        let allowed = || cpu_ctxs().iter().filter(|cpuc| cpumask.test(cpuc.cpu_id));

        // Confined to one compute domain? Only if there is more than one.
        let dom_pinned = nr_cpdoms() > 1 && is_affinitized && {
            let mut doms = allowed().map(|cpuc| cpuc.cpdom_id);
            doms.next().is_some_and(|first| doms.all(|id| id == first))
        };

        self.flags.set(TaskFlags::IS_EFFECTIVELY_PINNED, weight == 1);
        self.flags.set(TaskFlags::IS_AFFINITIZED, is_affinitized);
        self.flags.set(TaskFlags::ON_BIG, allowed().any(|cpuc| cpuc.big_core));
        self.flags.set(TaskFlags::ON_LITTLE, allowed().any(|cpuc| !cpuc.big_core));
        self.flags.set(TaskFlags::DOMAIN_PINNED, dom_pinned);
    }

    /// How much of its working set a task still finds in the caches of @cpu_id.
    pub fn cpu_warmth(&self, cpu_id: i32, now: u64) -> u64 {
        let heat = self.cpu_heat;
        if heat == 0 || self.cpu_id != cpu_id {
            return 0;
        }
        let away_ns = time_delta(now, self.last_stopping_clk);
        if away_ns >= LAVD_CPU_WARM_LIFETIME_NS {
            return 0;
        }
        heat - (heat * away_ns) / LAVD_CPU_WARM_LIFETIME_NS
    }

    pub fn update_cpu_warmth(&mut self, cpuc: &CpuCtx, slice_used: u64, now: u64) {
        let gain = (min(slice_used, LAVD_CPU_WARM_SAT_NS) * LAVD_SCALE) / LAVD_CPU_WARM_SAT_NS;
        let kept = if self.prev_cpu_id == cpuc.cpu_id { self.cpu_warmth(cpuc.cpu_id, now) } else { 0 };
        self.cpu_heat = min(kept + gain, LAVD_SCALE);
        self.last_stopping_clk = now;
    }

    /// Is it worth waiting for @cpu, where the caches are warm?
    pub fn warm_cpu_wait_ok(&self, cpu: i32, now: u64) -> bool {
        let Some(cpuc) = get_cpu_ctx_id(cpu) else { return false };
        let heat = self.cpu_warmth(cpu, now);
        let budget = (WARM_CPU_NS.get() * (LAVD_SCALE + heat)) >> LAVD_SHIFT;
        let wait = time_delta(cpuc.est_stopping_clk.get(), now)
            + cpu_to_dsq(cpu).nr_queued() * SYS_STAT.slice_wall.get();
        wait <= budget
    }
}

pub fn can_boost_slice() -> bool {
    SYS_STAT.avg_util_wall.get() <= LAVD_SLICE_BOOST_UTIL_WALL
        && SYS_STAT.nr_queued_task.get() <= SYS_STAT.nr_active.get()
}

pub fn use_full_cpus() -> bool { SYS_STAT.nr_active.get() >= NR_CPUS_ONLN.get() }

pub fn normalize_lat_cri(lat_cri: u64) -> u64 {
    match SYS_STAT.max_lat_cri.get() {
        0 => 0,
        max if lat_cri >= max => LAVD_SCALE,
        max => (lat_cri << LAVD_SHIFT) / max,
    }
}

// ── Hyperthreads and queues ──────────────────────────────────────────

/// User space fills cpu_sibling[] in C. Here hyperthreads are neighbours.
pub fn get_sibling_cpu(cpu: i32) -> i32 {
    if SMT_ACTIVE.on() && (cpu ^ 1) < nr_cpus() { cpu ^ 1 } else { cpu }
}

pub fn get_primary_cpu(cpu: i32) -> i32 { min(cpu, get_sibling_cpu(cpu)) }

pub fn cpu_to_dsq(cpu: i32) -> LavdDsq { LavdDsq::Cpu(get_primary_cpu(cpu)) }

impl CpuCtx {
    /// The queues that this CPU takes tasks from.
    fn queues(&self) -> impl Iterator<Item = Dsq> {
        let cpdom = use_cpdom_dsq().then_some(self.cpdom_id);
        [
            Some(self.local_dsq()),
            cpdom.map(|id| LavdDsq::Cpdom(id).dsq()),
            cpdom.map(|id| LavdDsq::CpdomTurb(id).dsq()),
            use_per_cpu_dsq().then(|| cpu_to_dsq(self.cpu_id).dsq()),
        ].into_iter().flatten()
    }

    /// Is anything waiting that this CPU would run?
    #[inline(never)]
    pub fn queued_on_cpu(&self) -> bool { self.queues().any(|dsq| dsq.nr_queued() > 0) }

    #[inline(never)]
    pub fn is_congested(&self) -> bool {
        self.queues().map(Dsq::nr_queued).sum::<u64>() >= LAVD_CPU_CONGESTED_THRES
    }
}

/// The queue for a task that was placed on @cpuc.
pub fn get_target_dsq(cpuc: &CpuCtx, taskc: &TaskCtx) -> LavdDsq {
    if PER_CPU_DSQ.on() || (PINNED_SLICE_NS.get() != 0 && taskc.is_effectively_pinned()) {
        return cpu_to_dsq(cpuc.cpu_id);
    }

    let vulnerable = cpuc.cpdom().is_some_and(|cpdomc| {
        preemption_vulnerability(taskc.normalized_lat_cri, taskc.util_est) >= cpdomc.vuln_thresh.get()
    });
    if vulnerable { LavdDsq::Cpdom(cpuc.cpdom_id) } else { LavdDsq::CpdomTurb(cpuc.cpdom_id) }
}

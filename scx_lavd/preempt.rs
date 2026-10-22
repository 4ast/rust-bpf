// SPDX-License-Identifier: GPL-2.0
//
// preempt.bpf.c: find a CPU whose task should make way for a more latency
// critical one, and cut time slices short.

use crate::*;

/// What decides who may preempt whom.
#[derive(Clone, Copy)]
struct Preemption {
    est_stopping_clk: u64,
    lat_cri: u64,
}

pub fn get_est_stopping_clk(taskc: &TaskCtx, now: u64) -> u64 {
    now + min(taskc.avg_runtime_wall, taskc.slice_wall)
}

impl Preemption {
    fn of_task(taskc: &TaskCtx, now: u64) -> Preemption {
        Preemption { est_stopping_clk: get_est_stopping_clk(taskc, now), lat_cri: taskc.lat_cri }
    }

    fn of_cpu(cpuc: &CpuCtx) -> Preemption {
        Preemption { est_stopping_clk: cpuc.est_stopping_clk.get(), lat_cri: cpuc.lat_cri.get() }
    }

    /// More latency critical, and done before the other would be.
    fn can_kick(&self, other: &Preemption) -> bool {
        self.lat_cri > other.lat_cri && self.est_stopping_clk < other.est_stopping_clk
    }

    /// Never a task of a higher scheduling class, never a lock holder.
    fn can_kick_cpu(&self, cpuc: &CpuCtx) -> bool {
        !is_rt_or_dl_task_running(cpuc.cpu_id)
            && !cpuc.is_lock_holder_running()
            && self.can_kick(&Preemption::of_cpu(cpuc))
    }
}

fn is_worth_kick_other_task(taskc: &TaskCtx) -> bool { taskc.lat_cri >= SYS_STAT.thr_lat_cri.get() }

/// The power of two random choices: of two CPUs that can be preempted, take
/// the one whose task gives way more easily.
fn find_victim_cpu(cpus: &CpuSet, preferred_cpu: i32, taskc: &TaskCtx, now: u64) -> Option<&'static CpuCtx> {
    let prm_task = Preemption::of_task(taskc, now);

    let preferred = usize::try_from(preferred_cpu).ok().and_then(|cpu| cpu_ctxs().get(cpu));
    let random = (0..cpus.weight())
        .filter_map(|_| cpus.any_distribute())
        .filter(|&cpu| cpu != preferred_cpu)
        .filter_map(|cpu| cpu_ctxs().get(cpu as usize))
        .filter(|cpuc| cpuc.is_online.on());

    preferred.into_iter().chain(random)
        .filter(|cpuc| prm_task.can_kick_cpu(cpuc))
        .take(2)
        .reduce(|a, b| if Preemption::of_cpu(a).can_kick(&Preemption::of_cpu(b)) { a } else { b })
}

/// Shortens the slice of the task on @victim_cpuc rather than sending an IPI.
#[inline(never)]
fn ask_cpu_yield_after(victim_cpuc: &CpuCtx, new_slice: u64) {
    let rcu = rcu_read_lock();
    let Some(victim_p) = rcu.cpu_curr(victim_cpuc.cpu_id) else { return };

    let old = victim_cpuc.est_stopping_clk.get();
    if old == 0 {
        return;
    }

    // Slice 0 would be taken for "refill". The CAS makes sure that only one
    // CPU preempts the victim.
    if new_slice <= 1 {
        if victim_cpuc.est_stopping_clk.cas(old, 0) {
            victim_p.set_slice(1);
        }
    } else if victim_p.slice() > new_slice {
        victim_p.set_slice(new_slice);
    }
}

/// From the timer: back to the regular time slice.
pub fn shrink_boosted_slice_remote(cpuc: &CpuCtx, now: u64) {
    cpuc.reset_flag(TaskFlags::SLICE_BOOST);

    let pinned_slice = PINNED_SLICE_NS.get();
    let target_slice_wall = if pinned_slice != 0 && cpuc.nr_pinned_tasks.get() != 0 {
        pinned_slice
    } else {
        SYS_STAT.slice_wall.get()
    };

    match time_delta(target_slice_wall, time_delta(now, cpuc.running_clk.get())) {
        0 => kick_cpu(cpuc.cpu_id, SCX_KICK_PREEMPT),
        new_slice_wall => ask_cpu_yield_after(cpuc, new_slice_wall),
    }
    cpuc.nr_preempt.bump(1);
}

pub fn shrink_slice_at_tick(p: Task, cpuc: &CpuCtx, now: u64) {
    let ub_wall = match PINNED_SLICE_NS.get() {
        0 => SYS_STAT.slice_wall.get(),
        pinned_slice => min(pinned_slice, SYS_STAT.slice_wall.get()),
    };

    p.set_slice(time_delta(ub_wall, time_delta(now, cpuc.running_clk.get())));
    cpuc.reset_flag(TaskFlags::SLICE_BOOST);
    cpuc.nr_preempt.bump(1);
}

/// The CPU to preempt for @taskc and the slice to leave to its task.
fn pick_victim(p: Task, taskc: &TaskCtx, preferred_cpu: i32, cpdom_id: u32) -> Option<(&'static CpuCtx, u64)> {
    let now = scx_now();
    let slice_wall = SYS_STAT.slice_wall.get();

    // A task with a boosted slice on the CPU that we would like to have?
    let boosted = (!NO_SLICE_BOOST.on() && preferred_cpu >= 0)
        .then(|| get_cpu_ctx_id(preferred_cpu)).flatten()
        .filter(|cpuc| cpuc.test_flag(TaskFlags::SLICE_BOOST));
    if let Some(cpuc_victim) = boosted {
        let duration_wall = time_delta(now, cpuc_victim.running_clk.get());

        // It had a regular slice: it goes now if it can be preempted at all.
        if duration_wall >= slice_wall && Preemption::of_task(taskc, now).can_kick_cpu(cpuc_victim) {
            cpuc_victim.reset_flag(TaskFlags::SLICE_BOOST);
            return Some((cpuc_victim, 0));
        }

        // A task that cannot go elsewhere: the victim gets the rest of a
        // regular slice.
        if taskc.is_affinitized() {
            cpuc_victim.reset_flag(TaskFlags::SLICE_BOOST);
            return Some((cpuc_victim, time_delta(slice_wall, duration_wall)));
        }
    }

    // Look in the compute domain of the task.
    let cpus = CpuSet::new();
    cpus.assign_and(&get_cpdom(cpdom_id)?.cpus, p.cpus());
    find_victim_cpu(&cpus, preferred_cpu, taskc, now).map(|cpuc| (cpuc, 0))
}

#[inline(never)]
pub fn try_find_and_kick_victim_cpu(p: Task, taskc: &TaskCtx, preferred_cpu: i32, cpdom_id: u32) {
    // Don't even try to perform expensive preemption for greedy tasks.
    if taskc.flags.contains(TaskFlags::IS_GREEDY) || !is_worth_kick_other_task(taskc) {
        return;
    }

    if let Some((cpuc_victim, new_slice_wall)) = pick_victim(p, taskc, preferred_cpu, cpdom_id) {
        ask_cpu_yield_after(cpuc_victim, new_slice_wall);
        if let Some(cpuc_cur) = get_cpu_ctx() {
            cpuc_cur.nr_preempt.bump(1);
        }
    }
}

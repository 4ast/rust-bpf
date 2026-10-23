// SPDX-License-Identifier: GPL-2.0
//
// scx_lavd: Latency-criticality Aware Virtual Deadline scheduler.
//
// A task that is in the middle of a chain of tasks (it is woken up often and
// wakes others up often) and that runs for a short time is latency critical.
// The more critical, the earlier its virtual deadline. On top of that: time
// slices that follow the load, preemption of less critical tasks, core
// compaction (as few active CPUs as the load needs), big and little cores,
// queues per compute domain with load balancing between them, and separate
// queues for CPUs that interrupts keep busy.
//
// Rust port of scheds/rust/scx_lavd/src/bpf, module by module:
//
//   lavd.bpf.h, intf.h    scx_lavd/types.rs
//   util.bpf.c            scx_lavd/util.rs
//   lib/ravg_impl.bpf.h   scx_lavd/ravg.rs
//   lat_cri.bpf.c         scx_lavd/lat_cri.rs
//   preempt.bpf.c         scx_lavd/preempt.rs
//   idle.bpf.c            scx_lavd/idle.rs
//   power.bpf.c           scx_lavd/power.rs
//   balance.bpf.c         scx_lavd/balance.rs
//   sys_stat.bpf.c        scx_lavd/sys_stat.rs
//   lock.bpf.c            scx_lavd/lock.rs
//   introspec.bpf.c       scx_lavd/introspec.rs
//   main.bpf.c            this file
// Copyright (c) 2023, 2024 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>
//
// - cpu_ctx_stor (per-CPU array map)    -> Vec<CpuCtx>
// - cpdom_ctxs[], neighbor_ids[]        -> Vec<Cpdom>, Vec<Vec<u32>>
// - scx_task_alloc() (arena)            -> TaskMap<TaskCtx>
// - volatile, READ_ONCE(), __sync_*()   -> atomics behind the trait Shared
// - kptr cpumasks, global and scratch   -> CpuSet, members of PickCtx
// - flag words and their helpers        -> TaskFlags
// - -ENOENT, out parameters, gotos      -> Option, Picked, Sticky, early returns
// - dsq ids made with macros            -> enum LavdDsq
// - queued_in_cpdom_id + two snapshots  -> Option<QueuedLoad>
//
// User space provides the topology in C. Here ops.init() puts CPDOM_CPUS
// consecutive CPUs of a NUMA node with the same capacity into a compute domain,
// takes the capacities from scx_bpf_cpuperf_cap() and orders the CPUs by them.
//
// Missing:
// - lib/cgroup_bw: cpu.max (enable_cpu_bw) and with it the cgroup ops
// - the energy model (pco_table from user space): the no_use_em case is ported
// - rq->clock_task, rq->clock_pelt: invariant time is wall clock time scaled by
//   capacity and current frequency, steal time is not split into interrupts
//   and higher scheduling classes
// - bpf_in_hardirq() and friends (preempt_count is a per-CPU kernel variable):
//   of "woken by an interrupt" only "woken by ksoftirqd" is left
// - cpufreq policy and hw_pressure in the effective capacity
// - the per-CPU cache of the last task context: it needs the contexts to be
//   freed after an RCU grace period
//
// The programs that are not struct_ops (futex tracing, sched_switch, execve) are
// optional like in C. `bpftool struct_ops register` leaves them out:
//   scxload -e lavd_fexit -e lavd_sched_switch -e lavd_tp_sys_enter_exec bld/scx_lavd.o

#![no_std]
#![no_main]
#![allow(dead_code, internal_features)]

extern crate alloc;

#[macro_use]
mod scx_common;

#[path = "scx_lavd/balance.rs"] mod balance;
#[path = "scx_lavd/idle.rs"] mod idle;
#[path = "scx_lavd/introspec.rs"] mod introspec;
#[path = "scx_lavd/lat_cri.rs"] mod lat_cri;
#[path = "scx_lavd/lock.rs"] mod lock;
#[path = "scx_lavd/power.rs"] mod power;
#[path = "scx_lavd/preempt.rs"] mod preempt;
#[path = "scx_lavd/ravg.rs"] mod ravg;
#[path = "scx_lavd/sys_stat.rs"] mod sys_stat;
#[path = "scx_lavd/types.rs"] mod types;
#[path = "scx_lavd/util.rs"] mod util;

// What every module sees, like the headers that every C file includes.
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::cmp::{max, min, Reverse};
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering::Relaxed};
use balance::*;
use idle::*;
use introspec::*;
use power::*;
use preempt::*;
use ravg::*;
use scx_common::*;
use sys_stat::*;
use types::*;
use util::*;

// ── Configuration (const volatile equivalents) ───────────────────────

tunables! { "lavd",
    SLICE_MIN_NS: AtomicU64 = LAVD_SLICE_MIN_NS_DFL;
    SLICE_MAX_NS: AtomicU64 = LAVD_SLICE_MAX_NS_DFL;
    /// Slice for all tasks of a CPU on which pinned tasks wait. 0: off.
    PINNED_SLICE_NS: AtomicU64 = 0;
    /// How much of the distance between the average and the maximum latency
    /// criticality a task has to cover to preempt others: 1 - 1/2^shift.
    PREEMPT_SHIFT: AtomicU32 = 6;
    /// Load of the turbulent CPUs in percent of the load of the steady ones.
    LAT_LOAD_TARGET_PCT: AtomicU64 = 100;
    /// Fixed band for load balancing in percent. 0: it follows the load.
    MIG_DELTA_PCT: AtomicU64 = 0;
    /// Balance by queue length, one migration per domain and round.
    NO_FAST_LB: AtomicBool = false;
    NO_OVRFLW_EXTEND: AtomicBool = false;
    /// How long a task may wait for the CPU where its caches are warm. 0: off.
    WARM_CPU_NS: AtomicU64 = 0;
    /// No load balancing below this utilization.
    LB_LOW_UTIL_WALL: AtomicU64 = p2s(25);
    /// Below this utilization a task goes to the local queue of its CPU.
    LB_LOCAL_DSQ_UTIL_WALL: AtomicU64 = p2s(10);
    /// Migrate when the task would be done this much earlier. User space sets
    /// it to 0 on a machine with one kind of cores.
    XMIG_MIN_GAIN_NS: AtomicU64 = 0;
    NO_WAKE_SYNC: AtomicBool = false;
    NO_SLICE_BOOST: AtomicBool = false;
    PER_CPU_DSQ: AtomicBool = false;
    IS_AUTOPILOT_ON: AtomicBool = true;
    NO_PREEMPTION: AtomicBool = false;
    NO_CORE_COMPACTION: AtomicBool = false;
    NO_FREQ_SCALING: AtomicBool = false;

    // topology
    /// CPUs per compute domain.
    CPDOM_CPUS: AtomicU32 = 4;
    /// CPUs 2n and 2n + 1 are hyperthreads of a core.
    SMT_ACTIVE: AtomicBool = false;
    /// CPUs with at least this capacity are turbo cores. 0: there are none.
    TURBO_CAPACITY: AtomicU64 = 0;
}

// ── Clocks, time slices, statistics of a task ────────────────────────

/// The logical clock follows the deadlines of the tasks that get to run, the
/// slower the more tasks wait.
fn advance_cur_logical_clk(p: Task) {
    let vlc = p.dsq_vtime();
    let mut clc = CUR_LOGICAL_CLK.get();

    for _ in 0..LAVD_MAX_RETRY {
        if vlc <= clc {
            return;
        }
        let delta = (vlc - clc) / max(SYS_STAT.nr_queued_task.get(), 1);
        match CUR_LOGICAL_CLK.compare_exchange(clc, clc + delta, Relaxed, Relaxed) {
            Ok(_) => return,
            Err(cur) => clc = cur,
        }
    }
}

impl TaskCtx {
    fn new(now: u64) -> TaskCtx {
        let slice_wall = SYS_STAT.slice_wall.get();
        TaskCtx {
            flags: TaskFlags::default(),
            slice_wall: 0,
            last_measured_wall_clk: 0,
            last_measured_exec: 0,
            acc_runtime_wall: 0,
            acc_runtime_invr: 0,
            svc_time_iwgt: SYS_STAT.avg_svc_time_iwgt.get(),
            lat_cri: 0,
            normalized_lat_cri: 0,
            lat_cri_waker: 0,
            lat_cri_wakee: 0,
            perf_cri: 0,
            cpdom_id: 0,
            suggested_cpu_id: 0,
            pinned_cpu_id: None,
            last_running_clk: now,
            run_freq: 0,
            wait_freq: 0,
            wake_freq: 0,
            avg_runtime_invr: slice_wall,
            avg_runtime_wall: slice_wall,
            last_runnable_clk: now,
            last_quiescent_clk: now,
            cgrp_id: 0,
            last_slice_used_wall: 0,
            cpu_id: 0,
            prev_cpu_id: 0,
            queued_in_cpdom: None,
            queued_on_cpu: None,
            waker_pid: 0,
            util_est: 0,
            avg_util_ravg: Ravg::default(),
            last_stopping_clk: now,
            cpu_heat: 0,
        }
    }

    fn calc_time_slice(&mut self, cpuc: &CpuCtx) -> u64 {
        let sys_slice = SYS_STAT.slice_wall.get();
        let pinned_waiting = cpuc.nr_pinned_tasks.get() > 0;
        let pinned_slice = PINNED_SLICE_NS.get();

        // Pinned tasks wait for this CPU and cannot go elsewhere: be brief.
        let boosted = if pinned_slice != 0 && pinned_waiting {
            self.slice_wall = min(pinned_slice, sys_slice);
            false
        } else if NO_SLICE_BOOST.on() || pinned_waiting || self.avg_runtime_wall < sys_slice {
            self.slice_wall = sys_slice;
            false
        } else if can_boost_slice() {
            // The system is not loaded: let the task finish what it usually
            // does in one go.
            self.slice_wall = (self.avg_runtime_wall + LAVD_SLICE_BOOST_BONUS)
                .clamp(SLICE_MIN_NS.get(), LAVD_SLICE_BOOST_MAX);
            true
        } else if self.lat_cri > SYS_STAT.avg_lat_cri.get() {
            // It is loaded: a bonus for the latency critical only.
            let bonus = (sys_slice * self.lat_cri) / (SYS_STAT.avg_lat_cri.get() + 1);
            let upper = max(SLICE_MIN_NS.get(), min(self.avg_runtime_wall, sys_slice * 2));
            self.slice_wall = (sys_slice + bonus).clamp(SLICE_MIN_NS.get(), upper);
            true
        } else {
            self.slice_wall = sys_slice;
            false
        };

        self.flags.set(TaskFlags::SLICE_BOOST, boosted);
        self.slice_wall
    }

    fn update_stat_for_running(&mut self, p: Task, cpuc: &CpuCtx, now: u64) {
        self.avg_util_ravg.accumulate(LAVD_SCALE, now, LAVD_RAVG_HALFLIFE_NS);

        // How often the task gets scheduled.
        if self.have_scheduled() {
            let wait_period = time_delta(now, self.last_quiescent_clk);
            let interval = self.avg_runtime_invr + wait_period;
            if interval > 0 {
                self.run_freq = avg_freq(self.run_freq, interval);
            }
        }

        self.prev_cpu_id = self.cpu_id;
        self.cpu_id = cpuc.cpu_id;

        // The wake up is over.
        self.flags.remove(TaskFlags::IS_WAKEUP | TaskFlags::IS_SYNC_WAKEUP);

        self.last_running_clk = now;
        self.last_measured_wall_clk = now;
        self.last_measured_exec = p.sum_exec_runtime();

        cpuc.util_est.set(cpuc.avg_util_ravg.update(LAVD_SCALE, now));

        // A lock that was taken before is old news.
        self.reset_lock_futex_boost(cpuc);

        cpuc.max_lat_cri.raise_to(self.lat_cri);
        cpuc.sum_lat_cri.bump(self.lat_cri);
        cpuc.nr_sched.bump(1);

        if HAVE_LITTLE_CORE.on() {
            cpuc.max_perf_cri.raise_to(self.perf_cri);
            cpuc.min_perf_cri.lower_to(self.perf_cri);
            cpuc.sum_perf_cri.bump(self.perf_cri);
        }

        // What others need to know to preempt this CPU.
        cpuc.flags.set(self.flags.0);
        cpuc.lat_cri.set(self.lat_cri);
        cpuc.running_clk.set(now);
        cpuc.est_stopping_clk.set(get_est_stopping_clk(self, now));

        if self.is_lat_cri() {
            cpuc.nr_lat_cri.bump(1);
        }
        if is_perf_cri(self) {
            cpuc.nr_perf_cri.bump(1);
        }
        if cpu_ctxs().get(self.prev_cpu_id as usize).is_some_and(|prev| prev.cpdom_id != cpuc.cpdom_id) {
            cpuc.nr_x_migration.bump(1);
        }
    }

    /// Charges the time since the last measurement to the task and its CPU.
    fn account_task_runtime(&mut self, p: Task, cpuc: &CpuCtx, now: u64) {
        let exec_now = p.sum_exec_runtime();

        // Time that interrupts took is not in sum_exec_runtime.
        let task_time_wall = if self.last_measured_wall_clk == 0 || self.last_measured_exec == 0 {
            0
        } else {
            min(time_delta(now, self.last_measured_wall_clk), time_delta(exec_now, self.last_measured_exec))
        };
        let task_time_invr = cpuc.wall_to_invr(task_time_wall);
        let task_time_iwgt = task_time_invr / max(p.weight(), 1);

        cpuc.tot_task_time_wall.bump(task_time_wall);
        cpuc.tot_task_time_iwgt.bump(task_time_iwgt);
        cpuc.tot_task_time_invr.bump(task_time_invr);
        if self.flags.contains(TaskFlags::DOMAIN_PINNED) {
            cpuc.tot_dom_pinned_task_time_invr.bump(task_time_invr);
        }

        self.acc_runtime_wall += task_time_wall;
        self.acc_runtime_invr += task_time_invr;
        self.svc_time_iwgt += task_time_iwgt;
        self.last_measured_wall_clk = now;
        self.last_measured_exec = exec_now;
    }

    /// The slice is over but the task goes on.
    fn update_stat_for_refill(&mut self, p: Task, cpuc: &CpuCtx) -> u64 {
        let now = scx_now();
        self.account_task_runtime(p, cpuc, now);
        self.avg_runtime_wall = avg(self.avg_runtime_wall, self.acc_runtime_wall);
        self.avg_runtime_invr = avg(self.avg_runtime_invr, self.acc_runtime_invr);
        now
    }

    fn update_stat_for_stopping(&mut self, p: Task, cpuc: &CpuCtx) {
        let now = self.update_stat_for_refill(p, cpuc);

        cpuc.util_est.set(cpuc.avg_util_ravg.update(0, now));

        self.last_slice_used_wall = time_delta(now, self.last_running_clk);
        self.update_cpu_warmth(cpuc, self.last_slice_used_wall, now);

        // A task that joins later starts from here.
        CUR_SVC_TIME_IWGT.raise_to(self.svc_time_iwgt);

        self.reset_lock_futex_boost(cpuc);
    }

    // ── The load in the queues ───────────────────────────────────────

    fn queued_load(&self, id: u32) -> QueuedLoad {
        QueuedLoad { id, load: self.load_metric(), svc: self.avg_runtime_invr }
    }

    fn account_queued_load(&mut self, cpdom_id: u32) {
        if self.queued_in_cpdom.is_some() {
            return;
        }
        if let Some(cpdomc) = cpdoms().get(cpdom_id as usize) {
            let q = self.queued_load(cpdom_id);
            cpdomc.qload_invr.add(q.load);
            cpdomc.qload_svc_invr.add(q.svc);
            self.queued_in_cpdom = Some(q);
        }
    }

    fn account_queued_load_pcpu(&mut self, primary_cpu: i32) {
        if self.queued_on_cpu.is_some() {
            return;
        }
        if let Some(cpuc) = usize::try_from(primary_cpu).ok().and_then(|cpu| cpu_ctxs().get(cpu)) {
            let q = self.queued_load(primary_cpu as u32);
            cpuc.qload_invr.add(q.load);
            cpuc.qload_svc_invr.add(q.svc);
            self.queued_on_cpu = Some(q);
        }
    }

    /// The task left the queues, for a CPU or for good.
    fn unaccount_queued_load(&mut self) {
        if let Some((q, cpdomc)) = self.queued_in_cpdom.take().and_then(|q| Some((q, cpdoms().get(q.id as usize)?))) {
            cpdomc.qload_invr.sub(q.load);
            cpdomc.qload_svc_invr.sub(q.svc);
        }
        if let Some((q, cpuc)) = self.queued_on_cpu.take().and_then(|q| Some((q, cpu_ctxs().get(q.id as usize)?))) {
            cpuc.qload_invr.sub(q.load);
            cpuc.qload_svc_invr.sub(q.svc);
        }
    }

    /// A pinned task waits for @cpuc from now on.
    fn pin_to(&mut self, cpuc: &CpuCtx) {
        if self.is_effectively_pinned() && self.pinned_cpu_id.is_none() {
            self.pinned_cpu_id = Some(cpuc.cpu_id);
            cpuc.nr_pinned_tasks.add(1);
        }
    }

    fn unpin(&mut self) {
        if let Some(cpuc) = self.pinned_cpu_id.take().and_then(get_cpu_ctx_id) {
            cpuc.nr_pinned_tasks.sub(1);
        }
    }
}

/// Straight to the local queue: the CPU is idle and nothing waits for it, or it
/// has so little to do that a shared queue only costs.
fn can_direct_dispatch(cpuc: &CpuCtx, is_cpu_idle: bool) -> bool {
    if is_cpu_idle && !cpuc.queued_on_cpu() {
        return true;
    }
    let util = LB_LOCAL_DSQ_UTIL_WALL.get();
    util > 0 && cpuc.avg_util_wall.get() < util && !cpuc.is_congested() && !is_rt_or_dl_task_running(cpuc.cpu_id)
}

// ── Callbacks ────────────────────────────────────────────────────────

bpf_prog!("struct_ops/lavd_select_cpu",
fn lavd_select_cpu(p: Task, prev_cpu: i32, wake_flags: u64) -> i32 {
    let (Some(taskc), Some(cpuc_cur)) = (get_task_ctx(p), get_cpu_ctx()) else { return prev_cpu };

    taskc.flags.set(TaskFlags::IS_SYNC_WAKEUP, wake_flags & SCX_WAKE_SYNC != 0);
    if Task::current().is_ksoftirqd() {
        taskc.flags.insert(TaskFlags::WOKEN_BY_SOFTIRQ);
        taskc.flags.remove(TaskFlags::WOKEN_BY_HARDIRQ);
    }

    let picked = pick_idle_cpu(p, &mut PickCtx::new(taskc, cpuc_cur, prev_cpu, wake_flags), true);
    let cpu_id = if picked.cpu >= 0 { picked.cpu } else { prev_cpu };
    taskc.suggested_cpu_id = cpu_id;
    taskc.flags.set(TaskFlags::IDLE_CPU_PICKED, picked.is_idle);

    if picked.is_idle {
        let Some(cpuc) = get_cpu_ctx_id(cpu_id) else { return cpu_id };

        // If there is an idle CPU and nothing in its queues, skip ops.enqueue().
        if can_direct_dispatch(cpuc, true) {
            p.set_dsq_vtime(taskc.calc_when_to_run(p));
            p.set_slice(LAVD_SLICE_MAX_NS_DFL);
            taskc.account_queued_load(cpuc.cpdom_id);
            taskc.account_queued_load_pcpu(get_primary_cpu(cpuc.cpu_id));
            p.dsq_insert(SCX_DSQ_LOCAL, LAVD_SLICE_MAX_NS_DFL, 0);
        }
    }
    cpu_id
});

/// A CPU that the task may use: the suggested one if that is still good.
fn valid_suggested_cpu(p: Task, taskc: &mut TaskCtx) -> i32 {
    let cpu = taskc.suggested_cpu_id;
    if cpu < 0 || cpu >= nr_cpus() || !p.cpus().test(cpu) {
        taskc.suggested_cpu_id = p.cpus().first();
    }
    taskc.suggested_cpu_id
}

bpf_prog!("struct_ops/lavd_enqueue",
fn lavd_enqueue(p: Task, enq_flags: u64) {
    let (Some(taskc), Some(cpuc_cur)) = (get_task_ctx(p), get_cpu_ctx()) else { return };
    let task_cpu = p.cpu();

    // A higher scheduling class took the CPU: the task comes back with what is
    // left of its slice.
    if enq_flags & SCX_ENQ_REENQ != 0 {
        let cpu = valid_suggested_cpu(p, taskc);
        let Some(cpuc) = get_cpu_ctx_id(cpu) else { return };

        let vtime = taskc.calc_when_to_run(p);
        p.set_dsq_vtime(vtime);
        p.dsq_insert_vtime(get_target_dsq(cpuc, taskc).dsq().0, p.slice(), vtime, enq_flags);
        if !NO_PREEMPTION.on() {
            try_find_and_kick_victim_cpu(p, taskc, cpu, cpuc.cpdom_id);
        }
        return;
    }

    taskc.flags.set(TaskFlags::IS_WAKEUP, enq_flags & SCX_ENQ_WAKEUP != 0);

    // Calculate when a task can be scheduled. The slice is decided when it
    // starts to run.
    let vtime = taskc.calc_when_to_run(p);
    let slice = LAVD_SLICE_MIN_NS_DFL;
    p.set_dsq_vtime(vtime);
    p.set_slice(slice);

    // Find a proper DSQ for the task, which is either the task's associated
    // compute domain or its alternative domain where the task has a chance to
    // run.
    let picked = if enq_flags & SCX_ENQ_CPU_SELECTED == 0 {
        let prev_cpu = if p.cpus().test(task_cpu) { task_cpu } else { p.cpus().first() };
        pick_idle_cpu(p, &mut PickCtx::new(taskc, cpuc_cur, prev_cpu, 0), false)
    } else {
        Picked { cpu: task_cpu, is_idle: taskc.flags.take(TaskFlags::IDLE_CPU_PICKED) }
    };
    let cpu = picked.cpu;
    let Some(cpuc) = get_cpu_ctx_id(cpu) else { return };

    taskc.suggested_cpu_id = cpu;
    taskc.cpdom_id = cpuc.cpdom_id;
    taskc.flags.remove(TaskFlags::MIGRATION_AGGRESSIVE);
    taskc.pin_to(cpuc);

    let warm = taskc.flags.take(TaskFlags::WARM_CPU);
    if can_direct_dispatch(cpuc, picked.is_idle) {
        p.dsq_insert(SCX_DSQ_LOCAL_ON | cpu as u64, slice, enq_flags);
        taskc.account_queued_load_pcpu(get_primary_cpu(cpu));
    } else {
        let dsq = if warm { cpu_to_dsq(cpu) } else { get_target_dsq(cpuc, taskc) };
        p.dsq_insert_vtime(dsq.dsq().0, slice, vtime, enq_flags);
        if let LavdDsq::Cpu(primary_cpu) = dsq {
            taskc.account_queued_load_pcpu(primary_cpu);
        }
    }
    taskc.account_queued_load(cpuc.cpdom_id);

    // If there is an idle CPU for the task, kick it up now so that it can
    // consume the task immediately. Otherwise somebody may have to make way.
    if picked.is_idle {
        kick_cpu(cpu, SCX_KICK_IDLE);
    } else if !NO_PREEMPTION.on() {
        try_find_and_kick_victim_cpu(p, taskc, cpu, cpuc.cpdom_id);
    }
});

/// Is the task on a CPU right now? Then ops.running() has done the accounting.
fn is_curr(p: Task) -> bool { cpu_curr(p.cpu()) == Some(p) }

bpf_prog!("struct_ops/lavd_dequeue",
fn lavd_dequeue(p: Task, _deq_flags: u64) {
    if let Some(taskc) = find_task_ctx(p) {
        if !is_curr(p) {
            taskc.unaccount_queued_load();
        }
    }
});

/// Nothing better to do: @prev goes on with a new slice.
#[inline(never)]
fn consume_prev(prev: Option<Task>, cpuc: &CpuCtx) {
    let Some(prev) = prev.filter(|prev| prev.is_queued()) else { return };
    let Some(taskc_prev) = get_task_ctx(prev) else { return };

    taskc_prev.update_stat_for_refill(prev, cpuc);
    prev.set_slice(taskc_prev.calc_time_slice(cpuc));

    // One extra slice for a lock holder, not more.
    if cpuc.is_lock_holder_running() {
        taskc_prev.reset_lock_futex_boost(cpuc);
    }
    cpuc.flags.set(taskc_prev.flags.0);
}

/// Are there tasks in the queue that no active or overflow CPU can run? Extends
/// the overflow set for them. Returns whether @cpu is now in it.
#[inline(never)]
fn scan_dsq_for_ovflw_ext(dsq: LavdDsq, cpu: i32) -> bool {
    let mut it = DsqIterState::new();

    for p in it.iter(dsq.dsq(), 0) {
        let Some(p) = TaskRef::from_pid(p.pid()) else { continue };

        // Where the task has to go, and whether that CPU joins the overflow set.
        let (new_cpu, join) = if p.is_permanently_pinned() {
            (p.cpu(), true)
        } else if p.is_migration_disabled() {
            (p.cpu(), false)
        } else {
            let served = find_task_ctx(*p).is_some_and(|taskc| {
                !taskc.is_affinitized() || ACTIVE_CPUS.intersects(p.cpus()) || OVRFLW_CPUS.intersects(p.cpus())
            });
            match (served, find_cpu_in(p.cpus())) {
                (false, Some(new_cpu)) => (new_cpu, true),
                _ => continue,
            }
        };

        let was_in = join && ovrflw_test_and_set(new_cpu);
        if new_cpu == cpu {
            return true;
        }
        if !was_in {
            kick_cpu(new_cpu, SCX_KICK_IDLE);
        }
    }
    false
}

/// May a CPU that is neither active nor overflow take tasks nevertheless?
fn inactive_cpu_may_consume(cpu: i32, cpuc: &CpuCtx, prev: Option<Task>) -> bool {
    // Tasks wait in its own queue.
    if use_per_cpu_dsq() && cpu_to_dsq(cpu).nr_queued() > 0 {
        ovrflw_test_and_set(cpu);
        return true;
    }

    // The task that ran here cannot run elsewhere.
    if let Some(prev) = prev {
        if prev.is_permanently_pinned() {
            ovrflw_test_and_set(cpu);
            return true;
        }
        if prev.is_migration_disabled() {
            return true;
        }
        let stuck = get_task_ctx(prev).is_some_and(|taskc| taskc.is_affinitized())
            && prev.cpus().test(cpu)
            && !ACTIVE_CPUS.intersects(prev.cpus())
            && !OVRFLW_CPUS.intersects(prev.cpus());
        if stuck {
            ovrflw_test_and_set(cpu);
            return true;
        }
    }

    // A task in the queues of the domain cannot.
    use_cpdom_dsq()
        && (scan_dsq_for_ovflw_ext(LavdDsq::Cpdom(cpuc.cpdom_id), cpu)
            || scan_dsq_for_ovflw_ext(LavdDsq::CpdomTurb(cpuc.cpdom_id), cpu))
}

bpf_prog!("struct_ops/lavd_dispatch",
fn lavd_dispatch(cpu: i32, prev: Option<Task>) {
    let Some(cpuc) = get_cpu_ctx_id(cpu) else { return };

    // A lock holder goes on so that it releases the lock soon.
    if cpuc.is_lock_holder_running() && prev.is_some_and(Task::is_queued) {
        consume_prev(prev, cpuc);
        return;
    }

    // With core compaction only active and overflow CPUs take tasks.
    let may_consume = use_full_cpus() || ACTIVE_CPUS.test(cpu) || OVRFLW_CPUS.test(cpu)
        || inactive_cpu_may_consume(cpu, cpuc, prev);

    if may_consume && !consume_task(cpuc) {
        consume_prev(prev, cpuc);
    }
});

bpf_prog!("struct_ops/lavd_runnable",
fn lavd_runnable(p: Task, enq_flags: u64) {
    let Some(p_taskc) = get_task_ctx(p) else { return };

    // The run time counts from the moment the task wakes up.
    p_taskc.acc_runtime_wall = 0;
    p_taskc.acc_runtime_invr = 0;

    // Only a real wake up tells who depends on whom.
    if enq_flags & SCX_ENQ_WAKEUP == 0 || enq_flags & (SCX_ENQ_PREEMPT | SCX_ENQ_REENQ | SCX_ENQ_LAST) != 0 {
        return;
    }

    // Waker and wakee have to be related: siblings, both in the kernel or both
    // in user space.
    let waker = Task::current();
    if waker.is_ksoftirqd() || p.real_parent() != waker.real_parent() || p.is_kthread() != waker.is_kthread() {
        return;
    }

    p_taskc.flags.set(TaskFlags::WOKEN_BY_RT_DL, waker.is_rt_or_dl());

    let Some(waker_taskc) = find_task_ctx(waker) else { return };

    // How often the waker wakes others up.
    let now = scx_now();
    let interval = time_delta(now, waker_taskc.last_runnable_clk);
    if interval >= LAVD_LC_WAKE_INTERVAL_MIN {
        waker_taskc.wake_freq = avg_freq(waker_taskc.wake_freq, interval);
        waker_taskc.last_runnable_clk = now;
    }

    // Propagate the latency criticality along the chain, both ways.
    p_taskc.lat_cri_waker = waker_taskc.lat_cri;
    waker_taskc.lat_cri_wakee = max(waker_taskc.lat_cri_wakee, p_taskc.lat_cri);
    p_taskc.waker_pid = waker.pid();
});

bpf_prog!("struct_ops/lavd_running",
fn lavd_running(p: Task) {
    let now = scx_now();
    let (Some(cpuc), Some(taskc)) = (get_cpu_ctx_task(p), get_task_ctx(p)) else { return };

    taskc.unaccount_queued_load();

    // The kernel queued the task by itself, e.g. while the scheduler is being
    // loaded: it has no deadline yet.
    if p.slice() == SCX_SLICE_DFL {
        p.set_dsq_vtime(CUR_LOGICAL_CLK.get());
    }

    p.set_slice(taskc.calc_time_slice(cpuc));
    advance_cur_logical_clk(p);
    taskc.update_stat_for_running(p, cpuc, now);
    cpuc.update_cpuperf_target();

    // If there is a relevant introspection command with @p, process it.
    try_proc_introspec_cmd(p, taskc, cpuc);
});

bpf_prog!("struct_ops/lavd_tick",
fn lavd_tick(p: Task) {
    let (Some(cpuc), Some(taskc)) = (get_cpu_ctx_task(p), get_task_ctx(p)) else { return };

    let now = scx_now();
    taskc.account_task_runtime(p, cpuc, now);

    // Pinned tasks started to wait in the meantime.
    if cpuc.nr_pinned_tasks.get() > 0 {
        shrink_slice_at_tick(p, cpuc, now);
    }
});

bpf_prog!("struct_ops/lavd_stopping",
fn lavd_stopping(p: Task, _runnable: bool) {
    let (Some(cpuc), Some(taskc)) = (get_cpu_ctx_task(p), get_task_ctx(p)) else { return };
    taskc.update_stat_for_stopping(p, cpuc);
});

bpf_prog!("struct_ops/lavd_quiescent",
fn lavd_quiescent(p: Task, deq_flags: u64) {
    let (Some(cpuc), Some(taskc)) = (get_cpu_ctx_task(p), get_task_ctx(p)) else { return };

    cpuc.flags.set(0);
    taskc.unpin();

    // If a task @p is dequeued from a run queue for some other reason other
    // than going to sleep, it is an implementation-level side effect.
    if deq_flags & SCX_DEQ_SLEEP == 0 {
        return;
    }

    let now = scx_now();
    taskc.avg_util_ravg.accumulate(0, now, LAVD_RAVG_HALFLIFE_NS);
    taskc.util_est = taskc.avg_util_ravg.read_int(now, LAVD_RAVG_HALFLIFE_NS);

    // How often the task waits for something.
    let interval = time_delta(now, taskc.last_quiescent_clk);
    if interval > 0 {
        taskc.wait_freq = avg_freq(taskc.wait_freq, interval);
        taskc.last_quiescent_clk = now;
    }
});

impl CpuCtx {
    fn set_online(&self, online: bool) {
        if let Some(cpdomc) = self.cpdom() {
            if online { cpdomc.cpus.set(self.cpu_id) } else { cpdomc.cpus.clear(self.cpu_id) }
        }
        if online { ONLINE_CPUS.set(self.cpu_id) } else { ONLINE_CPUS.clear(self.cpu_id) }

        self.idle_start_clk.set(0);
        self.running_clk.set(0);
        self.reset_preemption_info();
        self.is_online.turn(online);

        if online {
            NR_CPUS_ONLN.add(1);
            TOTAL_MAX_CAPACITY.add(self.max_capacity);
        } else {
            NR_CPUS_ONLN.sub(1);
            TOTAL_MAX_CAPACITY.sub(self.max_capacity);
        }
        update_autopilot_high_cap();
        update_sys_stat();
    }
}

bpf_prog!("struct_ops/lavd_cpu_online",
fn lavd_cpu_online(cpu: i32) {
    if let Some(cpuc) = get_cpu_ctx_id(cpu) {
        cpuc.set_online(true);
    }
});

bpf_prog!("struct_ops/lavd_cpu_offline",
fn lavd_cpu_offline(cpu: i32) {
    if let Some(cpuc) = get_cpu_ctx_id(cpu) {
        cpuc.set_online(false);
    }
});

bpf_prog!("struct_ops/lavd_update_idle",
fn lavd_update_idle(cpu: i32, idle: bool) {
    let Some(cpuc) = get_cpu_ctx_id(cpu) else { return };
    let now = scx_now();

    if idle {
        // The CPU is entering into the idle state.
        cpuc.idle_start_clk.set(now);
        cpuc.reset_preemption_info();
        return;
    }

    // The CPU is exiting from the idle state. The timer may be closing the
    // books on the same period.
    for _ in 0..LAVD_MAX_RETRY {
        let old_clk = cpuc.idle_start_clk.get();
        if old_clk == 0 {
            break;
        }
        if cpuc.idle_start_clk.cas(old_clk, 0) {
            if !time_after(old_clk, now) {
                cpuc.idle_total_wall.add(time_delta(now, old_clk));
            }
            break;
        }
    }
});

bpf_prog!("struct_ops/lavd_set_cpumask",
fn lavd_set_cpumask(p: Task, cpumask: Cpumask) {
    if let Some(taskc) = get_task_ctx(p) {
        taskc.set_affinity_flags(cpumask);
    }
});

bpf_prog!("struct_ops/lavd_cpu_release",
fn lavd_cpu_release(_cpu: i32, _args: *const u8) {
    // When a CPU is released to serve higher priority scheduler class, requeue
    // the tasks in a local DSQ to the global enqueue.
    reenqueue_local();
});

extern "C" {
    fn scx_bpf_dsq_reenq(dsq_id: u64, reenq_flags: u64);
}

/// ops.cpu_release() is on its way out. This does the same.
bpf_prog!("?tp_btf/sched_switch",
fn lavd_sched_switch(_preempt: bool, prev: Task, next: Task, _prev_state: u32) {
    if next.is_rt_or_dl() && !prev.is_rt_or_dl() {
        unsafe { scx_bpf_dsq_reenq(SCX_DSQ_LOCAL, 0) };
    }
});

/// At execve() a task has nothing in the caches: the cheapest moment to move
/// it out of a domain that has too much to do.
fn set_aggressive_migration() {
    if nr_cpdoms() == 1 {
        return;
    }
    let Some((cpuc, taskc)) = get_cpu_ctx().zip(TASK_CTXS.get_irqs_on(Task::current())) else { return };

    if cpuc.cpdom().is_some_and(|cpdc| cpdc.is_stealee.on()) {
        taskc.flags.insert(TaskFlags::MIGRATION_AGGRESSIVE);
        kick_cpu(cpuc.cpu_id, SCX_KICK_PREEMPT);
    }
}

bpf_prog!("?tracepoint/syscalls/sys_enter_execve",
fn lavd_tp_sys_enter_execve() {
    set_aggressive_migration();
});

bpf_prog!("?tracepoint/syscalls/sys_enter_execveat",
fn lavd_tp_sys_enter_execveat() {
    set_aggressive_migration();
});

bpf_prog!("struct_ops/lavd_enable",
fn lavd_enable(p: Task) {
    if let Some(taskc) = get_task_ctx(p) {
        taskc.svc_time_iwgt = CUR_SVC_TIME_IWGT.get();
    }
});

bpf_prog!("struct_ops.s/lavd_init_task",
fn lavd_init_task(p: Task, args: InitTaskArgs) -> Result {
    let now = scx_now();

    // A child is likely to behave like its parent.
    let parent_pid = p.real_parent().map(Task::pid);
    let inherited = parent_pid.and_then(|pid| with_irqs_off(|| TASK_CTXS.get_pid(pid).cloned()));
    let mut taskc = inherited.unwrap_or_else(|| TaskCtx::new(now));

    taskc.suggested_cpu_id = p.cpu();
    taskc.pinned_cpu_id = None;
    taskc.queued_in_cpdom = None;
    taskc.queued_on_cpu = None;
    taskc.cgrp_id = args.cgroup().map_or(0, Cgroup::id);
    taskc.cpu_heat = 0;
    taskc.last_stopping_clk = now;
    {
        // ops.init_task() can sleep: p->cpus_ptr is only good under RCU.
        let _rcu = rcu_read_lock();
        taskc.set_affinity_flags(p.cpus());
    }
    taskc.flags.set(TaskFlags::KSOFTIRQD, p.is_ksoftirqd());

    TASK_CTXS.insert(p, taskc);
    Ok(())
});

bpf_prog!("struct_ops/lavd_exit_task",
fn lavd_exit_task(p: Task, _args: *const u8) {
    if let Some(taskc) = find_task_ctx(p) {
        if !is_curr(p) {
            taskc.unaccount_queued_load();
        }
    }
    TASK_CTXS.remove(p);
});

bpf_prog!("struct_ops/lavd_dump_task",
fn lavd_dump_task(_dctx: *const u8, p: Task) {
    let Some(taskc) = find_task_ctx(p) else { return };

    let _ = writeln!(ScxDump, "  \\_ slice: {}   vtime: {}/{}   lat_cri: {}/{}   perf_cri: {}/{}",
                     taskc.slice_wall, p.dsq_vtime(), CUR_LOGICAL_CLK.get(),
                     taskc.lat_cri, SYS_STAT.avg_lat_cri.get(), taskc.perf_cri, SYS_STAT.avg_perf_cri.get());
    let _ = writeln!(ScxDump, "  \\_ cpdom_id: {}   scpu: {}   cgroup: {}   flags: {:#x}",
                     taskc.cpdom_id, taskc.suggested_cpu_id, taskc.cgrp_id, taskc.flags.0);
});

/// What user space calls to switch the power profile.
bpf_prog!("syscall",
fn lavd_set_power_profile(power_mode: u32) -> Result {
    do_set_power_profile(PowerMode::try_from(power_mode)?);
    Ok(())
});

/// Asks for records about the next @nr tasks that get scheduled. In C user space
/// writes to intrspc.
bpf_prog!("syscall",
fn lavd_introspec_sched_n(nr: u64) {
    INTRSPC.arg.set(nr);
    INTRSPC.cmd.set(if nr > 0 { LAVD_CMD_SCHED_N } else { LAVD_CMD_NOP });
});

// ── Init ─────────────────────────────────────────────────────────────

fn create_dsq(dsq: LavdDsq, node: i32) -> Result {
    dsq.dsq().create(node).inspect_err(|_| scx_error!("Failed to create a DSQ %llu", dsq.dsq().0))
}

/// The CPUs and the compute domains they are in.
fn init_topology(online: Cpumask) -> Result<(Vec<Cpdom>, Vec<CpuCtx>)> {
    let nr_cpus = min(nr_cpu_ids() as usize, MAX_CPUS) as i32;
    let cpdom_cpus = CPDOM_CPUS.get().max(1);
    let max_capacity = (0..nr_cpus).map(|cpu| cpuperf_cap(cpu) as u64).max().unwrap_or(LAVD_SCALE);
    let turbo_capacity = TURBO_CAPACITY.get();

    let mut cpdoms: Vec<Cpdom> = Vec::new();
    let mut cpus: Vec<CpuCtx> = Vec::with_capacity(nr_cpus as usize);

    for cpu in 0..nr_cpus {
        let node = cpu_node(cpu);
        let capacity = cpuperf_cap(cpu) as u64;
        let big_core = capacity == max_capacity;

        let fits = cpdoms.last().is_some_and(|d| {
            d.numa_id == node && d.is_big == big_core && d.all_cpus.weight() < cpdom_cpus
        });
        if !fits {
            if cpdoms.len() == LAVD_CPDOM_MAX_NR {
                scx_error!("Too many compute domains");
                return Err(EINVAL);
            }
            cpdoms.push(Cpdom::new(cpdoms.len() as u32, node, big_core));
        }
        let cpdomc = cpdoms.last().ok_or(ENOMEM)?;
        let is_online = online.test(cpu);

        cpdomc.all_cpus.set(cpu);
        if is_online {
            cpdomc.cpus.set(cpu);
            cpdomc.nr_active_cpus.bump(1);
            cpdomc.cap_sum_active_cpus.bump(capacity);
        }

        cpus.push(CpuCtx {
            cpu_id: cpu,
            cpdom_id: cpdomc.id,
            max_capacity: capacity,
            big_core,
            turbo_core: turbo_capacity != 0 && capacity >= turbo_capacity,
            is_online: AtomicBool::new(is_online),
            effective_capacity: AtomicU64::new(capacity),
            est_stopping_clk: AtomicU64::new(SCX_SLICE_INF),
            min_perf_cri: AtomicU64::new(LAVD_SCALE),
            max_freq: AtomicU64::new(LAVD_SCALE),
            lat_headroom: AtomicU64::new(LAVD_SCALE),
            cpuperf_cur: AtomicU64::new(SCX_CPUPERF_ONE),
            cpuperf_target: AtomicU64::new(SCX_CPUPERF_ONE),
            ..Default::default()
        });
    }

    Ok((cpdoms, cpus))
}

/// Who is close to whom: first the domains of the same node, then the others,
/// each time going round from the domain itself so that not everybody turns to
/// the same neighbour first.
fn init_neighbors(cpdoms: &mut [Cpdom]) -> Result {
    let nr = cpdoms.len();
    let kinds: Vec<(i32, bool)> = cpdoms.iter().map(|d| (d.numa_id, d.is_big)).collect();

    for cpdomc in cpdoms.iter_mut() {
        let id = cpdomc.id as usize;
        let others = || (1..nr).map(|d| (id + d) % nr);
        let same_node = |other: &usize| kinds[*other].0 == cpdomc.numa_id;

        cpdomc.alt_id = others().find(|&other| kinds[other].1 != cpdomc.is_big).unwrap_or(id) as u32;
        cpdomc.neighbors = [
            others().filter(same_node).map(|other| other as u32).collect::<Vec<u32>>(),
            others().filter(|other| !same_node(other)).map(|other| other as u32).collect(),
        ].into_iter().filter(|ring| !ring.is_empty()).collect();
    }
    Ok(())
}

/// The sets of CPUs and what adds up over all CPUs.
fn init_cpu_sets(cpus: &[CpuCtx]) {
    let capacity_of = |big_only: bool| cpus.iter().filter(|c| c.big_core || !big_only).map(|c| c.max_capacity).sum::<u64>();

    for cpuc in cpus {
        if cpuc.is_online.on() {
            ONLINE_CPUS.set(cpuc.cpu_id);
            ACTIVE_CPUS.set(cpuc.cpu_id);
            STEADY_CPUS.set(cpuc.cpu_id);
        }
        if cpuc.big_core { BIG_CPUS.set(cpuc.cpu_id) } else { HAVE_LITTLE_CORE.turn(true) }
        if cpuc.turbo_core {
            TURBO_CPUS.set(cpuc.cpu_id);
            HAVE_TURBO_CORE.turn(true);
        }
    }

    NR_CPU_IDS.set(cpus.len() as u32);
    NR_CPUS_ONLN.set(ONLINE_CPUS.weight() as u64);
    TOTAL_MAX_CAPACITY.set(capacity_of(false));
    DEFAULT_BIG_CORE_SCALE.set((capacity_of(true) << LAVD_SHIFT) / max(capacity_of(false), 1));
    ONE_LITTLE_MAX_CAPACITY.set(cpus.iter().map(|c| c.max_capacity).min().unwrap_or(LAVD_SCALE));
}

/// In which order CPUs get activated: to save power the weak ones first.
fn init_cpu_order(cpus: &[CpuCtx]) -> [Vec<u16>; 2] {
    let mut powersave: Vec<u16> = cpus.iter().map(|c| c.cpu_id as u16).collect();
    let mut performance = powersave.clone();
    let capacity = |cpu: u16| cpus[cpu as usize].max_capacity;

    powersave.sort_unstable_by_key(|&cpu| (capacity(cpu), cpu));
    performance.sort_unstable_by_key(|&cpu| (Reverse(capacity(cpu)), cpu));
    [powersave, performance]
}

bpf_prog!("struct_ops.s/lavd_init",
fn lavd_init() -> Result {
    let now = scx_now();

    let (mut cpdoms, cpus) = {
        let online = ScxCpumask::online();
        init_topology(*online)?
    };
    init_neighbors(&mut cpdoms)?;
    init_cpu_sets(&cpus);

    if use_cpdom_dsq() {
        cpdoms.iter().try_for_each(|d| create_dsq(d.dsq(), d.numa_id).and_then(|_| create_dsq(d.turb_dsq(), d.numa_id)))?;
    }
    if use_per_cpu_dsq() {
        cpus.iter().filter(|c| c.cpu_id == get_primary_cpu(c.cpu_id))
            .try_for_each(|c| create_dsq(cpu_to_dsq(c.cpu_id), cpu_node(c.cpu_id)))?;
    }

    let order = init_cpu_order(&cpus);
    unsafe {
        *CPU_ORDER.get_mut() = order;
        *CPDOMS.get_mut() = cpdoms;
        *CPU_CTXS.get_mut() = cpus;
    }

    init_autopilot_caps();
    CUR_LOGICAL_CLK.set(LAVD_DL_COMPETE_WINDOW);
    CUR_SVC_TIME_IWGT.set(0);
    init_sys_stat(now)
});

bpf_prog!("struct_ops/lavd_exit",
fn lavd_exit(_ei: *const ScxExitInfo) {
    exit_sys_stat();
});

scx_ops_define!(lavd_ops, name: b"lavd",
    flags: SCX_OPS_ENQ_EXITING | SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_MIGRATION_DISABLED | SCX_OPS_KEEP_BUILTIN_IDLE,
    timeout_ms: 30000,
    select_cpu: lavd_select_cpu,
    enqueue: lavd_enqueue,
    dequeue: lavd_dequeue,
    dispatch: lavd_dispatch,
    runnable: lavd_runnable,
    running: lavd_running,
    tick: lavd_tick,
    stopping: lavd_stopping,
    quiescent: lavd_quiescent,
    cpu_online: lavd_cpu_online,
    cpu_offline: lavd_cpu_offline,
    update_idle: lavd_update_idle,
    set_cpumask: lavd_set_cpumask,
    cpu_release: lavd_cpu_release,
    enable: lavd_enable,
    init_task: lavd_init_task,
    exit_task: lavd_exit_task,
    dump_task: lavd_dump_task,
    init: lavd_init,
    exit: lavd_exit,
);

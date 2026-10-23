// SPDX-License-Identifier: GPL-2.0
//
// scx_bpfland: a vruntime-based sched-ext scheduler that prioritizes
// interactive workloads.
//
// Rust port of scheds/rust/scx_bpfland/src/bpf/main.bpf.c.
// Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
//
// - BPF_MAP_TYPE_TASK_STORAGE          -> TaskMap<TaskCtx>
// - BPF_MAP_TYPE_PERCPU_ARRAY          -> [BpfCell<CpuCtx>; MAX_CPUS]
// - struct bpf_cpumask __kptr *        -> CpuSet (primary domain),
//                                         Option<Box<CpuSet>> (SMT siblings)
// - const volatile tunables            -> atomics with the defaults of C
// - preferred_cpus[], cpu_capacity[]   -> Topology, probed in ops.init().
//                                         User space fills them in C.
// - ops flags                          -> constants. User space sets them in C.
//
// Simplified: a pick in the primary domain walks the CpuSet instead of calling
// scx_bpf_select_cpu_and(), which wants a cpumask of the kernel. "Same LLC" is
// "same NUMA node": C reads the per-CPU variable sd_llc_id. The fallback for
// kernels without scx_bpf_select_cpu_and(), debug messages, UEI and the
// counters that C declares but never updates are dropped.

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::{max, min, Reverse};
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering::Relaxed};
use scx_common::*;

/// Maximum time a task can wait in the scheduler's queue before triggering a
/// stall.
const STARVATION_MS: u64 = 5000;

/// Maximum rate of task wakeups/sec (tasks with a higher rate are capped to
/// this value).
///
/// Note that the wakeup rate is evaluate over a period of 100ms, so this
/// number must be multiplied by 10 to determine the actual limit in
/// wakeups/sec.
const MAX_WAKEUP_FREQ: u64 = 64;

// ── Configuration (const volatile equivalents) ───────────────────────

/// A default that the ops flags depend on.
const NUMA_DEFAULT: bool = true;

tunables! { "bpfland",
    /// Default task time slice.
    SLICE_MAX: AtomicU64 = NSEC_PER_MSEC;
    /// Default minimum time slice.
    SLICE_MIN: AtomicU64 = 0;
    /// Maximum time slice lag.
    ///
    /// Increasing this value can help to increase the responsiveness of
    /// interactive tasks at the cost of making regular and newly created tasks
    /// less responsive (0 = disabled).
    SLICE_LAG: AtomicU64 = 40 * NSEC_PER_MSEC;
    /// Ignore synchronous wakeup events.
    NO_WAKE_SYNC: AtomicBool = false;
    /// Force tasks with a high rate of enqueues/sec to stay on the same CPU to
    /// reduce contention on the node DSQs.
    STICKY_TASKS: AtomicBool = true;
    /// When enabled always dispatch per-CPU kthreads directly.
    LOCAL_KTHREADS: AtomicBool = true;
    /// Prioritize per-CPU tasks (tasks that can only run on a single CPU).
    LOCAL_PCPU: AtomicBool = true;
    /// The CPU frequency performance level: a negative value will not affect the
    /// performance level and will be ignored.
    CPUFREQ_PERF_LVL: AtomicI64 = 0;
    /// Enable preferred cores prioritization.
    PREFERRED_IDLE_SCAN: AtomicBool = false;
    /// Throttle the CPUs by injecting @throttle_ns idle time every @slice_max.
    THROTTLE_NS: AtomicU64 = 0;
    /// Primary domain includes all CPU.
    PRIMARY_ALL: AtomicBool = true;
    /// CPUs in the system have SMT is enabled.
    SMT_ENABLED: AtomicBool = true;
    /// NUMA rebalancing. The ops flags have to agree, hence the constant.
    NUMA_ENABLED: AtomicBool = NUMA_DEFAULT;
}

fn slice_max() -> u64 { SLICE_MAX.load(Relaxed) }
fn slice_lag() -> u64 { SLICE_LAG.load(Relaxed) }
fn primary_all() -> bool { PRIMARY_ALL.load(Relaxed) }
fn smt_enabled() -> bool { SMT_ENABLED.load(Relaxed) }
fn numa_enabled() -> bool { NUMA_ENABLED.load(Relaxed) }

// ── Statistics ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Stat {
    KthreadDispatches,
    DirectDispatches,
    SharedDispatches,
    NrStats,
}

static STATS: [AtomicU64; Stat::NrStats as usize] =
    [const { AtomicU64::new(0) }; Stat::NrStats as usize];

impl Stat {
    fn inc(self) { STATS[self as usize].fetch_add(1, Relaxed); }
}

// ── Global state (all in arena) ──────────────────────────────────────

/// Amount of currently running tasks.
static NR_RUNNING: AtomicU64 = AtomicU64::new(0);
/// Amount of online CPUs.
static NR_ONLINE_CPUS: AtomicU64 = AtomicU64::new(0);
/// Maximum possible CPU number.
static NR_CPU_IDS: AtomicU64 = AtomicU64::new(0);
/// Current global vruntime.
static VTIME_NOW: AtomicU64 = AtomicU64::new(0);
/// The CPUs are in the idle part of the throttling cycle.
static CPUS_THROTTLED: AtomicBool = AtomicBool::new(false);

/// Mask of CPUs that the scheduler can use until the system becomes
/// saturated, at which point tasks may overflow to other available CPUs.
static PRIMARY: CpuSet = CpuSet::new();

/// Timer used to inject idle cycles when CPU throttling is enabled.
bpf_timer_map!(bpfland_throttle_timer, throttle_timer, 1);

fn max_cpus() -> usize { min(NR_CPU_IDS.load(Relaxed) as usize, MAX_CPUS) }

/// What C gets from user space in preferred_cpus[] and cpu_capacity[].
struct Topology {
    /// Capacity of every CPU.
    capacity: Vec<u32>,
    /// CPUs sorted by their capacity in descendent order.
    preferred: Vec<i32>,
}

impl Topology {
    fn probe(nr_cpus: usize) -> Self {
        let capacity: Vec<u32> = (0..nr_cpus as i32).map(cpuperf_cap).collect();
        let mut preferred: Vec<i32> = (0..nr_cpus as i32).collect();
        preferred.sort_by_key(|&cpu| Reverse(capacity[cpu as usize]));
        Topology { capacity, preferred }
    }

    fn capacity(&self, cpu: i32) -> Option<u32> { self.capacity.get(cpu as usize).copied() }
}

static TOPOLOGY: BpfCell<Option<Topology>> = BpfCell::new(None);

fn topology() -> Option<&'static Topology> { TOPOLOGY.get().as_ref() }

// ── Per-CPU context ──────────────────────────────────────────────────

struct CpuCtx {
    tot_runtime: u64,
    prev_runtime: u64,
    last_running: u64,
    perf_lvl: u64,
    smt: Option<Box<CpuSet>>,
}

static CPU_CTXS: [BpfCell<CpuCtx>; MAX_CPUS] = [const {
    BpfCell::new(CpuCtx { tot_runtime: 0, prev_runtime: 0, last_running: 0, perf_lvl: 0, smt: None })
}; MAX_CPUS];

/// Return a CPU context.
fn try_lookup_cpu_ctx(cpu: i32) -> Option<&'static mut CpuCtx> {
    let cctx = CPU_CTXS.get(usize::try_from(cpu).ok()?)?;
    Some(unsafe { cctx.get_mut() })
}

// ── Per-task context ─────────────────────────────────────────────────

#[derive(Default)]
struct TaskCtx {
    awake_vtime: u64,
    last_run_at: u64,
    wakeup_freq: u64,
    last_woke_at: u64,
    avg_runtime: u64,
}

static TASK_CTXS: TaskMap<TaskCtx> = TaskMap::new();

impl TaskCtx {
    /// Return true if the task should be forced to stay on the same CPU,
    /// false otherwise.
    fn is_sticky(&self) -> bool {
        STICKY_TASKS.load(Relaxed) && self.avg_runtime < 10 * NSEC_PER_USEC
    }
}

// ── DSQs ─────────────────────────────────────────────────────────────

/// Return the DSQ of the corresponding @cpu.
fn cpu_dsq(cpu: i32) -> Dsq { Dsq(cpu as u64) }

/// Return the DSQ of the NUMA node of @cpu.
fn node_dsq(cpu: i32) -> Dsq { Dsq(NR_CPU_IDS.load(Relaxed) + cpu_node(cpu) as u64) }

/// Tasks waiting for @cpu.
fn nr_waiting(cpu: i32) -> u64 { cpu_dsq(cpu).nr_queued() + node_dsq(cpu).nr_queued() }

// ── CPU state checks ─────────────────────────────────────────────────

/// Return the cpumask of idle CPUs within the NUMA node that contains @cpu.
///
/// If NUMA support is disabled, @cpu is ignored.
fn get_idle_cpumask(cpu: i32) -> ScxCpumask {
    if numa_enabled() { ScxCpumask::idle_node(cpu_node(cpu)) } else { ScxCpumask::idle() }
}

/// Return the cpumask of fully idle SMT cores within the NUMA node that
/// contains @cpu.
fn get_idle_smtmask(cpu: i32) -> ScxCpumask {
    if numa_enabled() { ScxCpumask::idle_smt_node(cpu_node(cpu)) } else { ScxCpumask::idle_smt() }
}

/// Return true if @cpu is valid, otherwise trigger an error and return false.
fn is_cpu_valid(cpu: i32) -> bool {
    let valid = usize::try_from(cpu).is_ok_and(|cpu| cpu < max_cpus());
    if !valid {
        scx_error!("invalid CPU id: %d", cpu);
    }
    valid
}

/// Return true if @this_cpu and @that_cpu are in the same LLC, false
/// otherwise.
fn cpus_share_cache(this_cpu: i32, that_cpu: i32) -> bool {
    if this_cpu == that_cpu {
        return true;
    }
    is_cpu_valid(this_cpu) && is_cpu_valid(that_cpu) && cpu_node(this_cpu) == cpu_node(that_cpu)
}

/// Return true if @this_cpu is faster than @that_cpu, false otherwise.
fn is_cpu_faster(this_cpu: i32, that_cpu: i32) -> bool {
    if this_cpu == that_cpu || !is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu) {
        return false;
    }
    topology().is_some_and(|t| t.capacity(this_cpu) > t.capacity(that_cpu))
}

/// Return the SMT sibling CPU of a @cpu.
fn smt_sibling(cpu: i32) -> i32 {
    try_lookup_cpu_ctx(cpu)
        .and_then(|cctx| cctx.smt.as_ref())
        .and_then(|smt| smt.first())
        .unwrap_or(cpu)
}

/// Return true if the CPU is part of a fully busy SMT core, false otherwise.
///
/// If SMT is disabled or SMT contention avoidance is disabled, always return
/// false (since there's no SMT contention or it's ignored).
fn is_smt_contended(cpu: i32) -> bool {
    if !smt_enabled() {
        return false;
    }
    // If the sibling SMT CPU is not idle and there are other full-idle SMT
    // cores available, consider the current CPU as contended.
    let idle_mask = get_idle_cpumask(cpu);
    !idle_mask.test(smt_sibling(cpu)) && !idle_mask.is_empty()
}

/// Return true in case of a task wakeup, false otherwise.
fn is_wakeup(wake_flags: u64) -> bool { wake_flags & SCX_WAKE_TTWU != 0 }

// ── Idle CPU selection ───────────────────────────────────────────────

/// Try to pick the best idle CPU based on the preferred ranking, out of
/// @primary if there is one, out of the full-idle SMT cores if @smt is given.
fn pick_idle_cpu_pref_smt(p: Task, prev_cpu: i32, is_prev_allowed: bool,
                          primary: Option<&CpuSet>, smt: Option<Cpumask>) -> Option<i32> {
    let eligible = |cpu: i32| {
        primary.is_none_or(|m| m.test(cpu)) && smt.is_none_or(|m| m.test(cpu))
    };

    if is_prev_allowed && eligible(prev_cpu) && test_and_clear_cpu_idle(prev_cpu) {
        return Some(prev_cpu);
    }

    topology()?.preferred.iter().copied()
        .filter(|&cpu| cpu != prev_cpu && p.cpus().test(cpu))
        .find(|&cpu| eligible(cpu) && test_and_clear_cpu_idle(cpu))
}

/// Return the optimal idle CPU for task @p or None if no idle CPU is found.
fn pick_idle_cpu_scan(p: Task, prev_cpu: i32) -> Option<i32> {
    let is_prev_allowed = p.cpus().test(prev_cpu);
    let primary = (!primary_all()).then_some(&PRIMARY);
    let smt_ref = smt_enabled().then(|| get_idle_smtmask(prev_cpu));
    let smt = smt_ref.as_deref().copied();

    // If the task can't migrate, there's no point looking for other CPUs.
    if p.is_pcpu() && test_and_clear_cpu_idle(prev_cpu) {
        return Some(prev_cpu);
    }

    let pick = |primary, smt| pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, primary, smt);

    // A full-idle core in the primary domain, then any idle CPU there...
    primary
        .and_then(|_| smt.and_then(|_| pick(primary, smt)).or_else(|| pick(primary, None)))
        // ... then any full-idle core in the system...
        .or_else(|| smt.and_then(|_| pick(None, smt)))
        // ... then any idle CPU in the system.
        .or_else(|| pick(None, None))
}

/// Pick an optimal idle CPU for task @p (as close as possible to @prev_cpu).
fn pick_idle_cpu(p: Task, mut prev_cpu: i32, this_cpu: Option<i32>,
                 mut wake_flags: u64) -> Option<i32> {
    // Use lightweight idle CPU scanning when preferred idle scan is enabled.
    if PREFERRED_IDLE_SCAN.load(Relaxed) {
        return pick_idle_cpu_scan(p, prev_cpu);
    }

    // Clear the wake sync bit if synchronous wakeups are disabled.
    if NO_WAKE_SYNC.load(Relaxed) {
        wake_flags &= !SCX_WAKE_SYNC;
    }

    // On wakeup if the waker's CPU is faster than the wakee's CPU, try to
    // move the wakee closer to the waker.
    //
    // In presence of hybrid cores this helps to naturally migrate tasks over
    // to the faster cores.
    if let Some(this_cpu) = this_cpu
        .filter(|&cpu| primary_all() && is_wakeup(wake_flags) && is_cpu_faster(cpu, prev_cpu))
    {
        // If both the waker's CPU and the wakee's CPU are in the same LLC
        // and the wakee's CPU is a fully idle SMT core, don't migrate.
        if cpus_share_cache(this_cpu, prev_cpu) && !is_smt_contended(prev_cpu) &&
           test_and_clear_cpu_idle(prev_cpu) {
            return Some(prev_cpu);
        }
        prev_cpu = this_cpu;
    }

    // If a primary domain is defined, try to pick an idle CPU from there
    // first.
    let in_primary = || {
        PRIMARY.iter_from(prev_cpu)
            .filter(|&cpu| p.cpus().test(cpu))
            .find(|&cpu| test_and_clear_cpu_idle(cpu))
    };

    (!primary_all()).then(in_primary).flatten()
        // Pick any idle CPU usable by the task.
        .or_else(|| p.select_cpu_and(prev_cpu, wake_flags, p.cpus(), 0))
}

// ── Deadline and time slice ──────────────────────────────────────────

/// Calculate and return the virtual deadline for the given task.
///
///  The deadline is defined as:
///
///    deadline = vruntime + awake_vtime
///
/// Here, `vruntime` represents the task's total accumulated runtime,
/// inversely scaled by its weight, while `awake_vtime` accounts the runtime
/// accumulated since the last sleep event, also inversely scaled by the
/// task's weight.
///
/// Fairness is driven by `vruntime`, while `awake_vtime` helps prioritize
/// tasks that sleep frequently and use the CPU in short bursts (resulting in
/// a small `awake_vtime` value), which are typically latency critical.
///
/// Additionally, to prevent over-prioritizing tasks that sleep for long
/// periods of time, the maximum vruntime they can accumulate while sleeping
/// is limited to @slice_lag, which is also scaled based on the task's weight
/// and on its wakeup frequency.
fn task_dl(p: Task, cpu: i32, tctx: &mut TaskCtx) -> u64 {
    // Reference queue depth: how many tasks would take 1/10 the SLA to drain
    // at average slice usage.
    const STARVATION_THRESH: u64 = STARVATION_MS * NSEC_PER_MSEC / 10;
    let q_thresh = max(STARVATION_THRESH / slice_max(), 1);

    let nr_queued = nr_waiting(cpu);
    let awake_max = p.scale_by_weight_inverse(slice_lag());

    // Queue pressure factor = q_thresh / (q_thresh + nr_queued), applied to
    // the lag scale.
    //
    // Emergency clamp: if queued work (q * slice_max) already spans the
    // starvation window, stop boosting vruntime credit.
    let lag_scale = if nr_queued * slice_max() >= STARVATION_THRESH {
        1
    } else {
        max(max(tctx.wakeup_freq, 1) * q_thresh / (q_thresh + nr_queued), 1)
    };

    // Cap the vruntime credit of a sleeper in function of @slice_lag and
    // @lag_scale.
    let vtime_min = VTIME_NOW.load(Relaxed).wrapping_sub(p.scale_by_weight(slice_lag() * lag_scale));
    if time_before(p.dsq_vtime(), vtime_min) {
        p.set_dsq_vtime(vtime_min);
    }

    // Cap the partial accumulated vruntime since last sleep to @slice_lag.
    if time_after(tctx.awake_vtime, awake_max) {
        tctx.awake_vtime = awake_max;
    }

    p.dsq_vtime().wrapping_add(tctx.awake_vtime)
}

/// Return a time slice scaled by the task's weight.
fn task_slice(p: Task, cpu: i32) -> u64 {
    // Adjust time slice in function of the task's priority and the amount of
    // tasks waiting to be dispatched, but never assign a time slice smaller
    // than @slice_min.
    max(p.scale_by_weight(slice_max()) / max(nr_waiting(cpu), 1), SLICE_MIN.load(Relaxed))
}

/// Where ops.enqueue() and ops.select_cpu() can put a task.
enum Target {
    /// The local DSQ of the CPU the task is on, ahead of the deadline order.
    Local,
    /// The DSQ of a CPU, in deadline order.
    Cpu(i32),
    /// The DSQ of the node of a CPU, in deadline order.
    Node(i32),
}

fn dispatch_to(p: Task, tctx: &mut TaskCtx, target: Target, enq_flags: u64) {
    match target {
        Target::Local => p.dsq_insert(SCX_DSQ_LOCAL, task_slice(p, p.cpu()), enq_flags),
        Target::Cpu(cpu) =>
            p.dsq_insert_vtime(cpu_dsq(cpu).0, task_slice(p, cpu), task_dl(p, cpu, tctx), enq_flags),
        Target::Node(cpu) =>
            p.dsq_insert_vtime(node_dsq(cpu).0, task_slice(p, cpu), task_dl(p, cpu, tctx), enq_flags),
    }
}

// ── struct_ops callbacks ─────────────────────────────────────────────

// Pick a target CPU for a task which is being woken up.
//
// If a task is dispatched here, ops.enqueue() will be skipped: task will be
// dispatched directly to the CPU returned by this callback.
bpf_prog!("struct_ops/bpfland_select_cpu",
fn bpfland_select_cpu(p: Task, prev_cpu: i32, wake_flags: u64) -> i32 {
    let this_cpu = Some(this_cpu()).filter(|&cpu| p.cpus().test(cpu));

    // Make sure @prev_cpu is usable, otherwise try to move close to the
    // waker's CPU. If the waker's CPU is also not usable, then pick the first
    // usable CPU.
    let prev_cpu = if p.cpus().test(prev_cpu) {
        prev_cpu
    } else {
        this_cpu.unwrap_or_else(|| p.cpus().first())
    };

    // Try to find an idle CPU and dispatch the task directly to the target
    // CPU.
    let Some(cpu) = pick_idle_cpu(p, prev_cpu, this_cpu, wake_flags) else {
        return prev_cpu;
    };
    if let Some(tctx) = TASK_CTXS.get(p) {
        dispatch_to(p, tctx, Target::Cpu(cpu), 0);
        Stat::DirectDispatches.inc();
    }
    cpu
});

/// Return true if the task should attempt a migration, false otherwise.
fn task_should_migrate(p: Task, enq_flags: u64) -> bool {
    // If @sticky_tasks is enabled, attempt a migration only on wakeup (task
    // was not running) and only if ops.select_cpu() has not been called.
    // Otherwise, always attempt a migration unless ops.select_cpu() already
    // handled it.
    enq_flags & SCX_ENQ_CPU_SELECTED == 0 && (!STICKY_TASKS.load(Relaxed) || !p.is_running())
}

// Dispatch all the other tasks that were not dispatched directly in
// select_cpu().
bpf_prog!("struct_ops/bpfland_enqueue",
fn bpfland_enqueue(p: Task, enq_flags: u64) {
    let prev_cpu = p.cpu();
    let Some(tctx) = TASK_CTXS.get(p) else { return };

    // If the task is marked as sticky due to excessive rescheduling
    // activity, dispatch it directly to the same CPU to reduce the locking
    // pressure on the per-CPU and per-node DSQs.
    if tctx.is_sticky() {
        dispatch_to(p, tctx, Target::Local, enq_flags);
        Stat::DirectDispatches.inc();
        return;
    }

    // If @local_kthread is specified dispatch per-CPU kthreads directly on
    // their assigned CPU bypassing the per-CPU and per-node DSQs.
    if LOCAL_KTHREADS.load(Relaxed) && p.is_kthread() && p.nr_cpus_allowed() == 1 {
        dispatch_to(p, tctx, Target::Local, enq_flags);
        Stat::KthreadDispatches.inc();
        return;
    }

    // If the task can only run on the current CPU, dispatch it to the
    // corresponding per-CPU DSQ.
    //
    // This does not cause starvation for tasks in per-node DSQs, since
    // ops.dispatch() always picks the task with the earliest deadline between
    // per-node and per-CPU DSQs.
    //
    // However, if @local_pcpu is enabled, per-CPU tasks are dispatched
    // directly to SCX_DSQ_LOCAL, which can lead to starvation, but it also
    // grants them higher priority, which can improve performance for certain
    // workloads.
    if p.is_pcpu() {
        let target = if LOCAL_PCPU.load(Relaxed) { Target::Local } else { Target::Cpu(prev_cpu) };
        dispatch_to(p, tctx, target, enq_flags);
        Stat::DirectDispatches.inc();
        return;
    }

    // Attempt to dispatch directly to an idle CPU if ops.select_cpu() was
    // skipped.
    if task_should_migrate(p, enq_flags) || is_smt_contended(prev_cpu) {
        if let Some(cpu) = pick_idle_cpu(p, prev_cpu, None, 0) {
            dispatch_to(p, tctx, Target::Cpu(cpu), enq_flags);
            Stat::DirectDispatches.inc();
            if prev_cpu != cpu || !p.is_running() {
                kick_cpu(cpu, SCX_KICK_IDLE);
            }
            return;
        }
    }

    // Dispatch the task to the node DSQ, using the deadline-based scheduling.
    dispatch_to(p, tctx, Target::Node(prev_cpu), enq_flags);
    Stat::SharedDispatches.inc();

    // No need to kick the CPU if ops.select_cpu() has been called.
    if task_should_migrate(p, enq_flags) {
        kick_cpu(prev_cpu, SCX_KICK_IDLE);
    }
});

/// Return true if the task can keep running on its current CPU from
/// ops.dispatch(), false if the task should migrate.
fn keep_running(p: Task, cpu: i32) -> bool {
    // Do not keep running if the task doesn't need to run.
    if !p.is_queued() {
        return false;
    }
    // If the task can only run on this CPU, keep it running.
    if p.is_pcpu() {
        return true;
    }
    // If the task is not running in a full-idle SMT core and there are
    // full-idle SMT cores available in the system, give it a chance to
    // migrate elsewhere.
    !is_smt_contended(cpu)
}

bpf_prog!("struct_ops/bpfland_dispatch",
fn bpfland_dispatch(cpu: i32, prev: Option<Task>) {
    // The first task of each queue, with the queue it waits in.
    let head = |dsq: Dsq| dsq.peek().map(|p| (p.dsq_vtime(), dsq));
    let (local, node) = (head(cpu_dsq(cpu)), head(node_dsq(cpu)));

    // Let the CPU go idle if the system is throttled.
    if CPUS_THROTTLED.load(Relaxed) {
        return;
    }

    // Try to consume the first task either from the per-CPU DSQ or the
    // per-node DSQ, picking the one with the minimum deadline first. On a
    // tie the per-CPU DSQ wins.
    let mut queues = [local, node];
    queues.sort_by_key(|q| q.map_or(u64::MAX, |(deadline, _)| deadline));
    if queues.iter().flatten().any(|&(_, dsq)| dsq.move_to_local()) {
        return;
    }

    // If the current task expired its time slice and no other task wants to
    // run, simply replenish its time slice and let it run for another round
    // on the same CPU.
    if let Some(prev) = prev.filter(|&prev| keep_running(prev, cpu)) {
        prev.set_slice(task_slice(prev, cpu));
    }
});

/// Update CPU load and scale target performance level accordingly.
fn update_cpu_load(p: Task) {
    let now = now();
    let cpu = p.cpu();
    let Some(cctx) = try_lookup_cpu_ctx(cpu) else { return };

    // Evaluate dynamic cpuperf scaling factor using the average CPU
    // utilization, normalized in the range [0 .. SCX_CPUPERF_ONE].
    let delta_t = if now > cctx.last_running { now - cctx.last_running } else { 1 };

    // Refresh target performance level, if utilization is above 75% bump up
    // the performance level to the max.
    let delta_runtime = cctx.tot_runtime - cctx.prev_runtime;
    cctx.perf_lvl = match min(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE) {
        lvl if lvl >= SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4 => SCX_CPUPERF_ONE,
        lvl => lvl,
    };

    // Refresh the dynamic cpuperf scaling factor if needed.
    if CPUFREQ_PERF_LVL.load(Relaxed) < 0 {
        cpuperf_set(cpu, cctx.perf_lvl);
    }

    cctx.last_running = now;
    cctx.prev_runtime = cctx.tot_runtime;
}

bpf_prog!("struct_ops/bpfland_running",
fn bpfland_running(p: Task) {
    NR_RUNNING.fetch_add(1, Relaxed);

    let Some(tctx) = TASK_CTXS.get(p) else { return };

    // Save a timestamp when the task begins to run (used to evaluate the
    // used time slice).
    tctx.last_run_at = now();

    // Adjust target CPU frequency before the task starts to run.
    update_cpu_load(p);

    // Update current system's vruntime.
    if time_before(VTIME_NOW.load(Relaxed), p.dsq_vtime()) {
        VTIME_NOW.store(p.dsq_vtime(), Relaxed);
    }
});

// Update task statistics when the task is releasing the CPU (either
// voluntarily or because it expires its assigned time slice).
bpf_prog!("struct_ops/bpfland_stopping",
fn bpfland_stopping(p: Task, _runnable: bool) {
    let now = now();

    NR_RUNNING.fetch_sub(1, Relaxed);

    let Some(tctx) = TASK_CTXS.get(p) else { return };

    // Evaluate the used time slice.
    let slice = now - tctx.last_run_at;

    // Update average runtime per scheduling cycle for sticky task detection.
    tctx.avg_runtime = calc_avg(tctx.avg_runtime, slice);

    // Update the vruntime and the total accumulated runtime since last sleep.
    let delta_vtime = p.scale_by_weight_inverse(slice);
    p.set_dsq_vtime(p.dsq_vtime().wrapping_add(delta_vtime));
    tctx.awake_vtime += delta_vtime;

    // Update CPU runtime.
    if let Some(cctx) = try_lookup_cpu_ctx(p.cpu()) {
        cctx.tot_runtime += now - cctx.last_running;
    }
});

bpf_prog!("struct_ops/bpfland_runnable",
fn bpfland_runnable(p: Task, _enq_flags: u64) {
    let now = now();
    let Some(tctx) = TASK_CTXS.get(p) else { return };

    tctx.awake_vtime = 0;

    // Update the task's wakeup frequency based on the time since the last
    // wakeup, then cap the result to avoid large spikes.
    let delta_t = if now > tctx.last_woke_at { now - tctx.last_woke_at } else { 1 };
    tctx.wakeup_freq = min(update_freq(tctx.wakeup_freq, delta_t), MAX_WAKEUP_FREQ);
    tctx.last_woke_at = now;
});

bpf_prog!("struct_ops/bpfland_enable",
fn bpfland_enable(p: Task) {
    // Initialize the task vruntime to the current global vruntime.
    p.set_dsq_vtime(VTIME_NOW.load(Relaxed));
});

bpf_prog!("struct_ops/bpfland_init_task",
fn bpfland_init_task(p: Task, _args: *const ScxInitTaskArgs) -> i32 {
    TASK_CTXS.insert(p, TaskCtx::default());
    0
});

// Task storage goes away with the task. A tree has to be told.
bpf_prog!("struct_ops/bpfland_exit_task",
fn bpfland_exit_task(p: Task, _args: *const u8) {
    TASK_CTXS.remove(p);
});

// ── Syscall handlers (SEC("syscall")) ────────────────────────────────

#[repr(C)]
struct DomainArg {
    cpu_id: i32,
    sibling_cpu_id: i32,
}

#[repr(C)]
struct CpuArg {
    cpu_id: i32,
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn bpfland_enable_sibling_cpu(input: &DomainArg) -> i32 {
    let Some(cctx) = try_lookup_cpu_ctx(input.cpu_id) else { return -ENOENT.0 };
    cctx.smt.get_or_insert_with(|| Box::new(CpuSet::new())).set(input.sibling_cpu_id);
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn bpfland_enable_primary_cpu(input: &CpuArg) -> i32 {
    // Enable the target CPU in the primary scheduling domain. If the target
    // CPU is a negative value, clear the whole mask (this can be used to
    // reset the primary domain).
    match input.cpu_id {
        cpu if cpu < 0 => PRIMARY.clear_all(),
        cpu => PRIMARY.set(cpu),
    }
    0
}

// ── Init ─────────────────────────────────────────────────────────────

/// Initialize cpufreq performance level on all the online CPUs.
fn init_cpuperf_target() {
    let online = ScxCpumask::online();
    let perf_lvl = match CPUFREQ_PERF_LVL.load(Relaxed) {
        lvl if lvl < 0 => SCX_CPUPERF_ONE,
        lvl => min(lvl as u64, SCX_CPUPERF_ONE),
    };

    (0..nr_cpu_ids() as i32)
        .filter(|&cpu| online.test(cpu))
        .for_each(|cpu| cpuperf_set(cpu, perf_lvl));
}

/// Throttle timer used to inject idle time across all the CPUs.
extern "C" fn throttle_timerfn(_map: *mut u8, _key: *mut u32, timer: *mut bpf_timer) -> i32 {
    let throttled = CPUS_THROTTLED.load(Relaxed);

    // Stop the CPUs sending a preemption IPI (SCX_KICK_PREEMPT) if we need to
    // interrupt the running tasks and inject the idle sleep.
    //
    // Otherwise, send a wakeup IPI to resume from the injected idle sleep.
    let (flags, duration) = if throttled {
        (SCX_KICK_IDLE, slice_max())
    } else {
        (SCX_KICK_PREEMPT, THROTTLE_NS.load(Relaxed))
    };

    // Flip the throttled state.
    CPUS_THROTTLED.store(!throttled, Relaxed);

    (0..NR_CPU_IDS.load(Relaxed) as i32).for_each(|cpu| kick_cpu(cpu, flags));

    // Re-arm the duty-cycle timer setting the runtime or the idle time
    // duration.
    if Timer::from_ptr(timer).is_none_or(|t| t.start(duration, 0).is_err()) {
        scx_error!("Failed to re-arm duty cycle timer");
    }
    0
}

fn create_dsq(dsq: Dsq, node: i32) -> Result {
    dsq.create(node).inspect_err(|e| scx_error!("failed to create DSQ %llu: %d", dsq.0, -e.0))
}

bpf_prog!("struct_ops.s/bpfland_init",
fn bpfland_init() -> Result {
    // Initialize amount of online and possible CPUs.
    NR_ONLINE_CPUS.store(ScxCpumask::online().weight() as u64, Relaxed);
    NR_CPU_IDS.store(nr_cpu_ids() as u64, Relaxed);

    // Initialize CPUs and NUMA properties.
    init_cpuperf_target();
    *unsafe { TOPOLOGY.get_mut() } = Some(Topology::probe(max_cpus()));

    // Create the per-CPU DSQs, then the per-node DSQs.
    (0..nr_cpu_ids() as i32).try_for_each(|cpu| create_dsq(cpu_dsq(cpu), cpu_node(cpu)))?;
    (0..nr_node_ids() as i32)
        .try_for_each(|node| create_dsq(Dsq(NR_CPU_IDS.load(Relaxed) + node as u64), node))?;

    // Fire the throttle timer if CPU throttling is enabled.
    if THROTTLE_NS.load(Relaxed) != 0 {
        throttle_timer()
            .init(0, CLOCK_BOOTTIME, throttle_timerfn)
            .and_then(|timer| timer.start(slice_max(), 0))
            .inspect_err(|_| scx_error!("Failed to arm throttle timer"))?;
    }

    Ok(())
});

bpf_prog!("struct_ops/bpfland_exit",
fn bpfland_exit(_ei: *const ScxExitInfo) {
    throttle_timer().cancel_all();
});

scx_ops_define!(bpfland_ops, name: b"bpfland",
    flags: SCX_OPS_ENQ_EXITING | SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_MIGRATION_DISABLED |
           SCX_OPS_ALLOW_QUEUED_WAKEUP |
           if NUMA_DEFAULT { SCX_OPS_BUILTIN_IDLE_PER_NODE } else { 0 },
    timeout_ms: STARVATION_MS as u32,
    select_cpu: bpfland_select_cpu,
    enqueue: bpfland_enqueue,
    dispatch: bpfland_dispatch,
    running: bpfland_running,
    stopping: bpfland_stopping,
    runnable: bpfland_runnable,
    enable: bpfland_enable,
    init_task: bpfland_init_task,
    exit_task: bpfland_exit_task,
    init: bpfland_init,
    exit: bpfland_exit,
);

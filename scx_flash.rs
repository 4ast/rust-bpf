// SPDX-License-Identifier: GPL-2.0
//
// scx_flash: a scheduler that focuses on fairness and performance
// predictability, with an EDF policy whose deadlines depend on how often a
// task sleeps, and a plain round-robin mode.
//
// Rust port of scheds/rust/scx_flash/src/bpf/main.bpf.c.
// Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
//
// - `if (rr_sched)` all over the ops   -> trait Policy, implemented by
//                                         RoundRobin and Deadline, used
//                                         through &dyn Policy
// - BPF_MAP_TYPE_TASK_STORAGE          -> TaskMap<TaskCtx>
// - BPF_MAP_TYPE_CGRP_STORAGE          -> SpinLock<BTreeMap<u64, u32>> keyed by
//                                         cgroup id, plus ops.cgroup_exit()
// - BPF_MAP_TYPE_PERCPU_ARRAY          -> [BpfCell<CpuCtx>; MAX_CPUS]
// - struct bpf_cpumask __kptr *        -> CpuSet, Option<Box<CpuSet>>
// - three maps with one timer each     -> one map with the two timers in use
//
// Simplified like scx_bpfland.rs: the primary domain is walked instead of
// passed to scx_bpf_select_cpu_and(), no fallback for old kernels, no debug
// messages, no UEI.

#![no_std]
#![no_main]
#![feature(panic_can_unwind)]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::cmp::{max, min};
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering::Relaxed};
use scx_common::*;

const CGROUP_WEIGHT_DFL: u32 = 100;
const CONFIG_HZ: u64 = 100;
const MAX_WAKEUP_FREQ: u64 = 100;
const SLICE_MIN_NS: u64 = 10 * NSEC_PER_USEC;

/// Return the time interval between two ticks in ns.
const fn tick_interval_ns() -> u64 { NSEC_PER_SEC / CONFIG_HZ }

// Thresholds for applying hysteresis to CPU performance scaling:
//  - CPUFREQ_LOW_THRESH: below this level, reduce performance to minimum
//  - CPUFREQ_HIGH_THRESH: above this level, raise performance to maximum
//
// Values between the two thresholds retain the current smoothed performance
// level.
const CPUFREQ_LOW_THRESH: u64 = SCX_CPUPERF_ONE / 4;
const CPUFREQ_HIGH_THRESH: u64 = SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4;

// ── Configuration (const volatile equivalents) ───────────────────────

/// A default that the ops flags depend on.
const NUMA_DISABLED_DEFAULT: bool = false;

tunables! { "flash",
    /// Enable round-robin mode.
    RR_SCHED: AtomicBool = false;
    /// Throttle tasks that abuse the wakeup-frequency boost.
    WAKEUP_THROTTLE: AtomicBool = false;
    /// Primary domain includes all CPU.
    PRIMARY_ALL: AtomicBool = true;
    /// Default task time slice.
    SLICE_MAX: AtomicU64 = 700 * NSEC_PER_USEC;
    /// Maximum runtime budget that a task can accumulate while sleeping (used to
    /// determine the task's minimum vruntime).
    SLICE_LAG: AtomicU64 = 20 * NSEC_PER_MSEC;
    /// Enable tickless mode.
    TICKLESS_SCHED: AtomicBool = false;
    /// The CPU frequency performance level: a negative value will not affect the
    /// performance level and will be ignored.
    CPUFREQ_PERF_LVL: AtomicI64 = 0;
    /// Throttle the CPUs by injecting @throttle_ns idle time every @slice_max.
    THROTTLE_NS: AtomicU64 = 0;
    /// CPUs in the system have SMT is enabled.
    SMT_ENABLED: AtomicBool = true;
    /// Disable NUMA optimizations. The ops flags have to agree, hence the
    /// constant.
    NUMA_DISABLED: AtomicBool = NUMA_DISABLED_DEFAULT;
}

fn slice_max() -> u64 { SLICE_MAX.load(Relaxed) }
fn slice_lag() -> u64 { SLICE_LAG.load(Relaxed) }
fn throttle_ns() -> u64 { THROTTLE_NS.load(Relaxed) }
fn primary_all() -> bool { PRIMARY_ALL.load(Relaxed) }
fn cpufreq_dynamic() -> bool { CPUFREQ_PERF_LVL.load(Relaxed) < 0 }

// ── Global state (all in arena) ──────────────────────────────────────

static NR_KTHREAD_DISPATCHES: AtomicU64 = AtomicU64::new(0);
static NR_DIRECT_DISPATCHES: AtomicU64 = AtomicU64::new(0);
static NR_SHARED_DISPATCHES: AtomicU64 = AtomicU64::new(0);
/// Amount of currently running tasks.
static NR_RUNNING: AtomicU64 = AtomicU64::new(0);
/// Amount of online CPUs.
static NR_ONLINE_CPUS: AtomicU64 = AtomicU64::new(0);
/// Maximum possible CPU number.
static NR_CPU_IDS: AtomicU64 = AtomicU64::new(0);
/// Current global vruntime.
static VTIME_NOW: AtomicU64 = AtomicU64::new(0);

static CPUS_THROTTLED: AtomicBool = AtomicBool::new(false);

fn is_throttled() -> bool { throttle_ns() != 0 && CPUS_THROTTLED.load(Relaxed) }

/// Mask of CPUs that the scheduler can use until the system becomes
/// saturated, at which point tasks may overflow to other available CPUs.
static PRIMARY: CpuSet = CpuSet::new();

bpf_timer_map!(flash_timers, timers, 2);
/// Timer used to preempt CPUs in tickless mode.
const TICKLESS_TIMER: u32 = 0;
/// Timer used to inject idle cycles when CPU throttling is enabled.
const THROTTLE_TIMER: u32 = 1;

fn all_cpus() -> core::ops::Range<i32> { 0..NR_CPU_IDS.load(Relaxed) as i32 }
fn node_dsq(cpu: i32) -> Dsq { Dsq(cpu_node(cpu) as u64) }

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

// ── Per-cgroup context: tracks the cgroup's cpu.weight ───────────────

static CGRP_WEIGHTS: SpinLock<BTreeMap<u64, u32>> = SpinLock::new(BTreeMap::new());

/// The cgroup ops run with interrupts on.
fn with_cgrp_weights<R>(f: impl FnOnce(&mut BTreeMap<u64, u32>) -> R) -> R {
    CGRP_WEIGHTS.with_irqs_off(f)
}

fn cgrp_weight(cgrp: Option<Cgroup>) -> u32 {
    cgrp.and_then(|cgrp| with_cgrp_weights(|weights| weights.get(&cgrp.id()).copied()))
        .unwrap_or(CGROUP_WEIGHT_DFL)
}

// ── Per-task context ─────────────────────────────────────────────────

struct TaskCtx {
    /// Timestamp when the task started to run on a CPU (used to evaluate the
    /// consumed time slice).
    last_run_at: u64,
    /// Task wakeup frequency.
    wakeup_freq: u64,
    last_woke_at: u64,
    /// EWMA of observed runtime slice.
    slice_ns_ewma: Option<u64>,
    /// cgroup weight (cpu.weight).
    cgweight: u32,
}

static TASK_CTXS: TaskMap<TaskCtx> = TaskMap::new();

/// A task together with its effective weight, which incorporates the weight
/// of its cgroup:
///
///   task_nice_weight * cgroup_weight / CGROUP_WEIGHT_DFL
///
/// This ensures tasks in a cgroup with weight 200 get twice the CPU time of
/// tasks in a cgroup with the default weight (100).
#[derive(Clone, Copy)]
struct Weighted {
    p: Task,
    weight: u64,
}

impl Weighted {
    fn new(p: Task) -> Self {
        let cgw = TASK_CTXS.get(p).map_or(CGROUP_WEIGHT_DFL, |tctx| tctx.cgweight);
        Weighted { p, weight: p.weight() * cgw as u64 / CGROUP_WEIGHT_DFL as u64 }
    }

    fn scale(self, value: u64) -> u64 { value * self.weight / CGROUP_WEIGHT_DFL as u64 }

    fn scale_inverse(self, value: u64) -> u64 {
        (value * CGROUP_WEIGHT_DFL as u64).checked_div(self.weight).unwrap_or(value)
    }

    /// Return the time slice that can be assigned to a task.
    fn slice(self) -> u64 {
        if TICKLESS_SCHED.load(Relaxed) { SCX_SLICE_INF } else { self.scale(slice_max()) }
    }
}

fn task_slice(p: Task) -> u64 { Weighted::new(p).slice() }

/// Return task deadline in function of the accumulated vruntime, limiting the
/// maximum amount of credit a task can accumulate while sleeping to prevent
/// starvation.
///
/// The amount of time budget accumulated while tasks are sleeping is inversely
/// proportional to the accumulated runtime (in this way tasks that sleep
/// frequently accumulate less runtime and they also have a larger budget).
fn task_dl(p: Task, tctx: &TaskCtx, enq_flags: u64) -> u64 {
    let vtime = p.dsq_vtime();
    if enq_flags & SCX_ENQ_REENQ != 0 {
        return vtime;
    }

    let lag_scale = max(tctx.wakeup_freq, 1);
    let vsleep_max = Weighted::new(p).scale(slice_lag() * lag_scale);
    let vtime_min = VTIME_NOW.load(Relaxed).wrapping_sub(vsleep_max);
    let vtime = if time_before(vtime, vtime_min) { vtime_min } else { vtime };

    // Penalize tasks that are abusing the wakeup frequency prioritization by
    // charging them @slice_lag, excluding per-CPU kthreads, which may
    // legitimately exhibit sleep-intensive behavior.
    let abuser = WAKEUP_THROTTLE.load(Relaxed) &&
        (!p.is_kthread() || p.nr_cpus_allowed() > 1) &&
        tctx.slice_ns_ewma.is_some_and(|slice| slice < SLICE_MIN_NS);

    if abuser { vtime.wrapping_add(slice_lag()) } else { vtime }
}

// ── Idle CPU selection ───────────────────────────────────────────────

/// Find an idle CPU in the system.
///
/// NOTE: the idle CPU selection doesn't need to be formally perfect, it is
/// totally fine to accept racy conditions and potentially make mistakes, by
/// picking CPUs that are not idle or even offline, the logic has been designed
/// to handle these mistakes in favor of a more efficient response and a
/// reduced scheduling overhead.
fn pick_idle_cpu(p: Task, prev_cpu: i32, wake_flags: u64) -> Option<i32> {
    // Don't trust user-space about waker releasing the CPU: if it doesn't, we
    // may have latency issues, so it's safer to just ignore the hint.
    let wake_flags = wake_flags & !SCX_WAKE_SYNC;

    let in_primary = if primary_all() {
        None
    } else {
        PRIMARY.iter_from(prev_cpu)
            .filter(|&cpu| p.cpus().test(cpu))
            .find(|&cpu| test_and_clear_cpu_idle(cpu))
    };

    in_primary.or_else(|| p.select_cpu_and(prev_cpu, wake_flags, p.cpus(), 0))
}

/// Return the cpumask of idle CPUs within the NUMA node that contains @cpu.
///
/// If NUMA support is disabled, @cpu is ignored.
fn get_idle_cpumask(cpu: i32) -> ScxCpumask {
    if NUMA_DISABLED.load(Relaxed) { ScxCpumask::idle() } else { ScxCpumask::idle_node(cpu_node(cpu)) }
}

/// Return the SMT sibling of @cpu, or @cpu if SMT is disabled.
fn smt_sibling(cpu: i32) -> i32 {
    try_lookup_cpu_ctx(cpu)
        .and_then(|cctx| cctx.smt.as_ref())
        .and_then(|smt| smt.first())
        .unwrap_or(cpu)
}

/// Return true if @cpu is in a partially-idle SMT core, false otherwise.
fn is_smt_contended(cpu: i32) -> bool {
    if !SMT_ENABLED.load(Relaxed) {
        return false;
    }
    // If the sibling SMT CPU is not idle and there are other full-idle SMT
    // cores available, consider the current CPU as contended.
    let idle_mask = get_idle_cpumask(cpu);
    !idle_mask.test(smt_sibling(cpu)) && !idle_mask.is_empty()
}

/// Return true if @p is running on a primary CPU (or can't run on a primary
/// CPU due to affinity constraints), false otherwise.
fn is_primary_cpu(p: Task, cpu: i32) -> bool {
    primary_all() || PRIMARY.test(cpu) || !PRIMARY.intersects(p.cpus())
}

// ── The two scheduling policies ──────────────────────────────────────

trait Policy: Sync {
    /// Whether ops.select_cpu() dispatches even when no CPU is idle.
    fn always_direct(&self) -> bool;
    fn enqueue(&self, p: Task, prev_cpu: i32, enq_flags: u64);
    fn running(&self, p: Task);
    fn stopping(&self, p: Task, now: u64);
    fn runnable(&self, p: Task);
    fn enable(&self, p: Task);
}

struct RoundRobin;
struct Deadline;

fn policy() -> &'static dyn Policy {
    if RR_SCHED.load(Relaxed) { &RoundRobin } else { &Deadline }
}

impl Policy for RoundRobin {
    fn always_direct(&self) -> bool { true }

    fn enqueue(&self, p: Task, prev_cpu: i32, enq_flags: u64) {
        if !p.is_running() || enq_flags & SCX_ENQ_REENQ != 0 {
            if p.is_pcpu() {
                if test_and_clear_cpu_idle(prev_cpu) {
                    kick_cpu(prev_cpu, SCX_KICK_IDLE);
                }
            } else if let Some(cpu) = pick_idle_cpu(p, prev_cpu, 0) {
                p.dsq_insert(Dsq::local_on(cpu).0, task_slice(p), enq_flags);
                kick_cpu(cpu, SCX_KICK_IDLE);
                return;
            }
        }
        p.dsq_insert(SCX_DSQ_LOCAL, task_slice(p), enq_flags);
    }

    fn running(&self, _p: Task) {}
    fn stopping(&self, _p: Task, _now: u64) {}
    fn runnable(&self, _p: Task) {}
    fn enable(&self, _p: Task) {}
}

impl Deadline {
    /// Attempt to dispatch a task directly to its assigned CPU.
    ///
    /// Return true if the task is dispatched, false otherwise.
    fn try_direct_dispatch(p: Task, prev_cpu: i32, enq_flags: u64, is_running: bool) -> bool {
        // If throttling is enabled always dispatch critical kernel threads
        // directly to prevent throttling the entire system.
        if throttle_ns() > 0 && p.is_kthread() && p.nr_cpus_allowed() == 1 {
            p.dsq_insert(SCX_DSQ_LOCAL, task_slice(p), enq_flags);
            NR_KTHREAD_DISPATCHES.fetch_add(1, Relaxed);
            if !is_running {
                kick_cpu(prev_cpu, SCX_KICK_IDLE);
            }
            return true;
        }

        // ops.select_cpu() has looked for an idle CPU already.
        if !is_running && enq_flags & SCX_ENQ_CPU_SELECTED != 0 &&
           (!is_smt_contended(prev_cpu) || p.is_pcpu()) &&
           enq_flags & SCX_ENQ_REENQ == 0 {
            return false;
        }

        let idle_cpu = if p.is_pcpu() {
            test_and_clear_cpu_idle(prev_cpu).then_some(prev_cpu)
        } else {
            pick_idle_cpu(p, prev_cpu, 0)
        };
        let Some(cpu) = idle_cpu else { return false };

        p.dsq_insert(Dsq::local_on(cpu).0, task_slice(p), 0);
        NR_DIRECT_DISPATCHES.fetch_add(1, Relaxed);
        if cpu != prev_cpu || !is_running {
            kick_cpu(cpu, SCX_KICK_IDLE);
        }
        true
    }
}

impl Policy for Deadline {
    fn always_direct(&self) -> bool { false }

    fn enqueue(&self, p: Task, prev_cpu: i32, enq_flags: u64) {
        let is_running = p.is_running();

        if Self::try_direct_dispatch(p, prev_cpu, enq_flags, is_running) {
            return;
        }

        if let Some(tctx) = TASK_CTXS.get(p) {
            p.dsq_insert_vtime(node_dsq(prev_cpu).0, task_slice(p),
                               task_dl(p, tctx, enq_flags), enq_flags);
            NR_SHARED_DISPATCHES.fetch_add(1, Relaxed);
            if !is_running && enq_flags & SCX_ENQ_CPU_SELECTED == 0 {
                kick_cpu(prev_cpu, SCX_KICK_IDLE);
            }
        }
    }

    fn running(&self, p: Task) {
        // Update current system's vruntime.
        if time_before(VTIME_NOW.load(Relaxed), p.dsq_vtime()) {
            VTIME_NOW.store(p.dsq_vtime(), Relaxed);
        }
    }

    fn stopping(&self, p: Task, now: u64) {
        let Some(tctx) = TASK_CTXS.get(p) else { return };

        // Evaluate the used time slice and its average.
        let slice = max(now - tctx.last_run_at, 1);
        tctx.slice_ns_ewma = Some(tctx.slice_ns_ewma.map_or(slice, |avg| calc_avg(avg, slice)));

        // Update the vruntime.
        p.set_dsq_vtime(p.dsq_vtime().wrapping_add(Weighted::new(p).scale_inverse(slice)));
    }

    fn runnable(&self, p: Task) {
        let now = now();
        let Some(tctx) = TASK_CTXS.get(p) else { return };

        // Update the task's wakeup frequency.
        let delta_t = now - tctx.last_woke_at;
        tctx.wakeup_freq = min(update_freq(tctx.wakeup_freq, delta_t), MAX_WAKEUP_FREQ);
        tctx.last_woke_at = now;
    }

    fn enable(&self, p: Task) { p.set_dsq_vtime(VTIME_NOW.load(Relaxed)); }
}

// ── struct_ops callbacks ─────────────────────────────────────────────

// Pick a target CPU for a task which is being woken up.
//
// If a task is dispatched here, ops.enqueue() will be skipped: task will be
// dispatched directly to the CPU returned by this callback.
bpf_prog!("struct_ops/flash_select_cpu",
fn flash_select_cpu(p: Task, prev_cpu: i32, wake_flags: u64) -> i32 {
    if is_throttled() {
        return prev_cpu;
    }

    let idle_cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
    if idle_cpu.is_some() || policy().always_direct() {
        p.dsq_insert(SCX_DSQ_LOCAL, task_slice(p), 0);
        NR_DIRECT_DISPATCHES.fetch_add(1, Relaxed);
    }
    idle_cpu.unwrap_or(prev_cpu)
});

bpf_prog!("struct_ops/flash_enqueue",
fn flash_enqueue(p: Task, enq_flags: u64) {
    policy().enqueue(p, p.cpu(), enq_flags);
});

/// Return true if the task can keep running on its current CPU from
/// ops.dispatch(), false if the task should migrate.
fn keep_running(p: Task, cpu: i32) -> bool {
    p.is_queued() &&
        (p.nr_cpus_allowed() == 1 || (is_primary_cpu(p, cpu) && !is_smt_contended(cpu)))
}

bpf_prog!("struct_ops/flash_dispatch",
fn flash_dispatch(cpu: i32, prev: Option<Task>) {
    let dsq = node_dsq(cpu);
    let keep = prev.filter(|&prev| keep_running(prev, cpu));

    if is_throttled() {
        return;
    }

    // Let @prev go on if its vruntime, with the time it has just used, is
    // still ahead of the first task in the queue.
    if let Some((prev, tctx)) = keep.and_then(|prev| Some((prev, TASK_CTXS.get(prev)?))) {
        let q_vtime = dsq.peek().map_or(u64::MAX, |q| q.dsq_vtime());
        let slice = now() - tctx.last_run_at;
        let prev_vtime = prev.dsq_vtime().wrapping_add(Weighted::new(prev).scale_inverse(slice));

        if prev_vtime < q_vtime {
            prev.set_slice(task_slice(prev));
            return;
        }
    }

    if dsq.move_to_local() {
        return;
    }

    if let Some(prev) = keep {
        prev.set_slice(task_slice(prev));
    }
});

/// Update CPU load and scale target performance level accordingly.
fn update_cpu_load(p: Task) {
    let now = now();
    let cpu = p.cpu();
    let Some(cctx) = try_lookup_cpu_ctx(cpu) else { return };

    // Evaluate dynamic cpuperf scaling factor using the average CPU
    // utilization, normalized in the range [0 .. SCX_CPUPERF_ONE].
    let Some(load) = ((cctx.tot_runtime - cctx.prev_runtime) * SCX_CPUPERF_ONE)
        .checked_div(now - cctx.last_running) else { return };

    // Smooth out the performance level, then apply the hysteresis.
    cctx.perf_lvl = calc_avg(min(load, SCX_CPUPERF_ONE), cctx.perf_lvl);
    cpuperf_set(cpu, match cctx.perf_lvl {
        CPUFREQ_HIGH_THRESH.. => SCX_CPUPERF_ONE,
        ..=CPUFREQ_LOW_THRESH => SCX_CPUPERF_ONE / 2,
        lvl => lvl,
    });

    cctx.last_running = now;
    cctx.prev_runtime = cctx.tot_runtime;
}

bpf_prog!("struct_ops/flash_running",
fn flash_running(p: Task) {
    NR_RUNNING.fetch_add(1, Relaxed);

    let Some(tctx) = TASK_CTXS.get(p) else { return };

    // Save a timestamp when the task begins to run (used to evaluate the used
    // time slice).
    tctx.last_run_at = now();

    // Adjust target CPU frequency before the task starts to run.
    if cpufreq_dynamic() {
        update_cpu_load(p);
    }

    policy().running(p);
});

// Update task statistics when the task is releasing the CPU (either
// voluntarily or because it expires its assigned time slice).
bpf_prog!("struct_ops/flash_stopping",
fn flash_stopping(p: Task, _runnable: bool) {
    let now = now();

    NR_RUNNING.fetch_sub(1, Relaxed);

    policy().stopping(p, now);

    // Update CPU runtime.
    if cpufreq_dynamic() {
        if let Some(cctx) = try_lookup_cpu_ctx(p.cpu()) {
            cctx.tot_runtime += now - cctx.last_running;
        }
    }
});

bpf_prog!("struct_ops/flash_runnable",
fn flash_runnable(p: Task, _enq_flags: u64) {
    policy().runnable(p);
});

bpf_prog!("struct_ops/flash_enable",
fn flash_enable(p: Task) {
    policy().enable(p);
});

bpf_prog!("struct_ops/flash_cgroup_init",
fn flash_cgroup_init(cgrp: Cgroup, args: CgroupInitArgs) -> i32 {
    with_cgrp_weights(|weights| weights.insert(cgrp.id(), args.weight()));
    0
});

// Cgroup storage goes away with the cgroup. A tree has to be told.
bpf_prog!("struct_ops/flash_cgroup_exit",
fn flash_cgroup_exit(cgrp: Cgroup) {
    with_cgrp_weights(|weights| weights.remove(&cgrp.id()));
});

bpf_prog!("struct_ops/flash_cgroup_set_weight",
fn flash_cgroup_set_weight(cgrp: Cgroup, weight: u32) {
    with_cgrp_weights(|weights| {
        if let Some(w) = weights.get_mut(&cgrp.id()) {
            *w = weight;
        }
    });
});

bpf_prog!("struct_ops/flash_cgroup_move",
fn flash_cgroup_move(p: Task, _from: Cgroup, to: Cgroup) {
    if let Some(tctx) = TASK_CTXS.get(p) {
        tctx.cgweight = cgrp_weight(Some(to));
    }
});

bpf_prog!("struct_ops/flash_init_task",
fn flash_init_task(p: Task, args: InitTaskArgs) -> i32 {
    TASK_CTXS.insert(p, TaskCtx {
        last_run_at: 0,
        wakeup_freq: 0,
        last_woke_at: 0,
        slice_ns_ewma: None,
        cgweight: cgrp_weight(args.cgroup()),
    });
    0
});

bpf_prog!("struct_ops/flash_exit_task",
fn flash_exit_task(p: Task, _args: *const u8) {
    TASK_CTXS.remove(p);
});

// ── Syscall handlers (SEC("syscall")) ────────────────────────────────

#[repr(C)]
struct DomainArg {
    lvl_id: i32,
    cpu_id: i32,
    sibling_cpu_id: i32,
}

#[repr(C)]
struct CpuArg {
    cpu_id: i32,
}

fn enable_sibling_cpu(input: &DomainArg) -> Result {
    let cctx = try_lookup_cpu_ctx(input.cpu_id).ok_or(ENOENT)?;
    let mask = match input.lvl_id {
        0 => &mut cctx.smt,
        _ => return Err(EINVAL),
    };
    mask.get_or_insert_with(|| Box::new(CpuSet::new())).set(input.sibling_cpu_id);
    Ok(())
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn flash_enable_sibling_cpu(input: &DomainArg) -> i32 {
    enable_sibling_cpu(input).ret()
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn flash_enable_primary_cpu(input: &CpuArg) -> i32 {
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

    all_cpus().filter(|&cpu| online.test(cpu)).for_each(|cpu| cpuperf_set(cpu, perf_lvl));
}

fn rearm(timer: *mut bpf_timer, duration: u64) -> Result {
    Timer::from_ptr(timer).ok_or(EINVAL)?.start(duration, 0)
}

/// Tickless timer: preempt the tasks that have used up their time slice, on
/// the CPUs where other tasks are waiting.
extern "C" fn tickless_timerfn(_map: *mut u8, _key: *mut u32, timer: *mut bpf_timer) -> i32 {
    all_cpus()
        // Ignore CPU if idle task is running.
        .filter_map(|cpu| Some((cpu, cpu_curr(cpu).filter(|p| !p.is_idle_task())?)))
        // Ignore CPUs without any task waiting.
        .filter(|&(cpu, _)| node_dsq(cpu).nr_queued() != 0 || Dsq::local_on(cpu).nr_queued() != 0)
        .filter(|(_, p)| p.slice() == SCX_SLICE_INF)
        .filter_map(|(_, p)| TaskRef::from_pid(p.pid()))
        .for_each(|p| {
            if TASK_CTXS.get(*p).is_some_and(|tctx| now() - tctx.last_run_at > slice_max()) {
                p.set_slice(0);
            }
        });

    if rearm(timer, tick_interval_ns()).is_err() {
        scx_error!("Failed to re-arm tickless timer");
    }
    0
}

/// Throttle timer used to inject idle time across all the CPUs.
extern "C" fn throttle_timerfn(_map: *mut u8, _key: *mut u32, timer: *mut bpf_timer) -> i32 {
    let throttled = is_throttled();

    // Stop the CPUs sending a preemption IPI (SCX_KICK_PREEMPT) if we need to
    // interrupt the running tasks and inject the idle sleep.
    //
    // Otherwise, send a wakeup IPI to resume from the injected idle sleep.
    let (flags, duration) = if throttled {
        (SCX_KICK_IDLE, slice_max())
    } else {
        (SCX_KICK_PREEMPT, throttle_ns())
    };

    // Flip the throttled state.
    CPUS_THROTTLED.store(!throttled, Relaxed);

    all_cpus().for_each(|cpu| kick_cpu(cpu, flags));

    // Re-arm the duty-cycle timer setting the runtime or the idle time
    // duration.
    if rearm(timer, duration).is_err() {
        scx_error!("Failed to re-arm duty cycle timer");
    }
    0
}

bpf_prog!("struct_ops.s/flash_init",
fn flash_init() -> Result {
    // Initialize amount of online and possible CPUs.
    NR_ONLINE_CPUS.store(ScxCpumask::online().weight() as u64, Relaxed);
    NR_CPU_IDS.store(nr_cpu_ids() as u64, Relaxed);

    // Initialize CPUs and NUMA properties.
    init_cpuperf_target();

    // Create the per-node DSQs.
    (0..nr_node_ids() as i32).try_for_each(|node| {
        Dsq(node as u64).create(node)
            .inspect_err(|e| scx_error!("failed to create DSQ %d: %d", node, -e.0))
    })?;

    let arm = |idx, cb| timers().init(idx, CLOCK_MONOTONIC, cb)?.start(tick_interval_ns(), 0);

    if TICKLESS_SCHED.load(Relaxed) {
        arm(TICKLESS_TIMER, tickless_timerfn)
            .inspect_err(|_| scx_error!("Failed to arm tickless timer"))?;
    }
    if throttle_ns() != 0 {
        arm(THROTTLE_TIMER, throttle_timerfn)
            .inspect_err(|_| scx_error!("Failed to arm throttle timer"))?;
    }

    Ok(())
});

bpf_prog!("struct_ops/flash_exit",
fn flash_exit(_ei: *const ScxExitInfo) {
    timers().cancel_all();
});

scx_ops_define!(flash_ops, name: b"flash",
    flags: SCX_OPS_ENQ_EXITING | SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_MIGRATION_DISABLED |
           SCX_OPS_ALLOW_QUEUED_WAKEUP |
           if NUMA_DISABLED_DEFAULT { 0 } else { SCX_OPS_BUILTIN_IDLE_PER_NODE },
    timeout_ms: 5000,
    select_cpu: flash_select_cpu,
    enqueue: flash_enqueue,
    dispatch: flash_dispatch,
    running: flash_running,
    stopping: flash_stopping,
    runnable: flash_runnable,
    enable: flash_enable,
    cgroup_init: flash_cgroup_init,
    cgroup_exit: flash_cgroup_exit,
    cgroup_set_weight: flash_cgroup_set_weight,
    cgroup_move: flash_cgroup_move,
    init_task: flash_init_task,
    exit_task: flash_exit_task,
    init: flash_init,
    exit: flash_exit,
);

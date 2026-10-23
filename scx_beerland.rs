// SPDX-License-Identifier: GPL-2.0
//
// scx_beerland: BPF-Enhanced Execution Runtime Locality-Aware Non-blocking
// Dispatcher. One DSQ per CPU in vruntime order, idle CPUs steal the task with
// the earliest vruntime.
//
// Rust port of scheds/rust/scx_beerland/src/bpf/main.bpf.c.
//
// - BPF_MAP_TYPE_TASK_STORAGE           -> TaskMap<TaskCtx>
// - BPF_MAP_TYPE_PERCPU_ARRAY cpu_ctx   -> [BpfCell<CpuCtx>; MAX_CPUS]
// - BPF_MAP_TYPE_ARRAY cpu_busy_until   -> a field of CpuCtx
// - struct bpf_cpumask __kptr *         -> CpuSet, Option<Box<CpuSet>>
// - u64 vruntimes compared with time_before() -> Vtime, whose Ord wraps
// - sleep_vlag + has_sleep_vlag         -> Option<i64>
// - cpu_capacity[]                      -> Vec<u32> probed in ops.init()
//
// Simplified like scx_bpfland.rs: the primary domain is walked instead of
// passed to scx_bpf_select_cpu_and(), same LLC means same NUMA node, no
// fallback for old kernels, no UEI. MAX_CPUS is 1024, not 4096. primary_all
// is true by default: there is no user space to fill the primary domain.

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::ops::{Add, Sub};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use scx_common::*;

// ── Configuration (const volatile equivalents) ───────────────────────

/// A default that the ops flags depend on.
const NUMA_DEFAULT: bool = true;

tunables! { "beerland",
    /// Default time slice.
    SLICE_NS: AtomicU64 = NSEC_PER_MSEC;
    /// Maximum time slice lag.
    ///
    /// Increasing this value can help to increase the responsiveness of
    /// interactive tasks at the cost of making regular and newly created tasks
    /// less responsive (0 = disabled).
    SLICE_LAG: AtomicU64 = 40 * NSEC_PER_MSEC;
    /// CPUs in the system have SMT is enabled.
    SMT_ENABLED: AtomicBool = true;
    /// Enable NUMA optimizations. The ops flags have to agree, hence the constant.
    NUMA_ENABLED: AtomicBool = NUMA_DEFAULT;
    /// Accounted CPU time threshold to decide whether a time slice marks its CPU
    /// as a remote dispatch source. 0 disables filtering.
    BUSY_THRESHOLD: AtomicU64 = 0;
    /// Set to true when the primary domain includes all the CPUs.
    PRIMARY_ALL: AtomicBool = true;
}

fn slice_ns() -> u64 { SLICE_NS.load(Relaxed) }
fn primary_all() -> bool { PRIMARY_ALL.load(Relaxed) }

// ── Virtual time ─────────────────────────────────────────────────────

/// A point in virtual time. The counter wraps, so the order is that of
/// time_before(): by the sign of the difference.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Vtime(u64);

impl Ord for Vtime {
    fn cmp(&self, other: &Self) -> Ordering { (*self - *other).cmp(&0) }
}

impl PartialOrd for Vtime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Add<u64> for Vtime {
    type Output = Vtime;
    fn add(self, delta: u64) -> Vtime { Vtime(self.0.wrapping_add(delta)) }
}

impl Sub<u64> for Vtime {
    type Output = Vtime;
    fn sub(self, delta: u64) -> Vtime { Vtime(self.0.wrapping_sub(delta)) }
}

impl Sub<i64> for Vtime {
    type Output = Vtime;
    fn sub(self, delta: i64) -> Vtime { Vtime(self.0.wrapping_sub(delta as u64)) }
}

/// The lag of one point behind another.
impl Sub for Vtime {
    type Output = i64;
    fn sub(self, other: Vtime) -> i64 { self.0.wrapping_sub(other.0) as i64 }
}

/// Current system vruntime.
static VTIME_NOW: AtomicU64 = AtomicU64::new(0);

impl Vtime {
    fn now() -> Vtime { Vtime(VTIME_NOW.load(Relaxed)) }

    /// Return true if a task with this vruntime is eligible to run at the
    /// current system vruntime.
    fn is_eligible(self) -> bool { self <= Vtime::now() }
}

/// What the scheduler wants to know about a task beyond what Task offers.
trait BeerTask: Copy {
    fn vtime(self) -> Vtime;
    fn set_vtime(self, vtime: Vtime);
    fn lag_limit(self) -> u64;
    fn is_cpu_allowed(self, cpu: i32) -> bool;
    fn usable_cpu(self, cpu: i32) -> i32;
}

impl BeerTask for Task {
    fn vtime(self) -> Vtime { Vtime(self.dsq_vtime()) }
    fn set_vtime(self, vtime: Vtime) { self.set_dsq_vtime(vtime.0) }

    /// How far the vruntime of the task can drift from the system vruntime.
    fn lag_limit(self) -> u64 { self.scale_by_weight_inverse(SLICE_LAG.load(Relaxed)) }

    /// Return true if the task can run on @cpu, false otherwise.
    fn is_cpu_allowed(self, cpu: i32) -> bool {
        self.nr_cpus_allowed() as u64 == NR_CPU_IDS.load(Relaxed) || self.cpus().test(cpu)
    }

    /// Return the target @cpu if it's usable by the task, or the first CPU
    /// usable.
    fn usable_cpu(self, cpu: i32) -> i32 {
        if self.cpus().test(cpu) { cpu } else { self.cpus().first() }
    }
}

// ── Global state (all in arena) ──────────────────────────────────────

/// Maximum amount of CPUs supported by the system.
static NR_CPU_IDS: AtomicU64 = AtomicU64::new(0);

/// Subset of CPUs to prioritize.
static PRIMARY: CpuSet = CpuSet::new();

/// Cache CPU capacity values.
static CPU_CAPACITY: BpfCell<Vec<u32>> = BpfCell::new(Vec::new());

static NR_LOCAL_DISPATCH: AtomicU64 = AtomicU64::new(0);
static NR_REMOTE_DISPATCH: AtomicU64 = AtomicU64::new(0);
static NR_KEEP_RUNNING: AtomicU64 = AtomicU64::new(0);

// ── Per-CPU context ──────────────────────────────────────────────────

struct CpuCtx {
    smt: Option<Box<CpuSet>>,
    last_run_at: u64,
    /// Fast event-driven per-CPU busy state. This reacts within a scheduling
    /// slice.
    busy_until: AtomicU64,
}

static CPU_CTXS: [BpfCell<CpuCtx>; MAX_CPUS] = [const {
    BpfCell::new(CpuCtx { smt: None, last_run_at: 0, busy_until: AtomicU64::new(0) })
}; MAX_CPUS];

/// Return a CPU context.
fn try_lookup_cpu_ctx(cpu: i32) -> Option<&'static mut CpuCtx> {
    let cctx = CPU_CTXS.get(usize::try_from(cpu).ok()?)?;
    Some(unsafe { cctx.get_mut() })
}

/// Return true if @cpu is marked busy enough to steal from.
fn is_cpu_busy(cpu: i32, now: u64) -> bool {
    if BUSY_THRESHOLD.load(Relaxed) == 0 {
        return true;
    }
    try_lookup_cpu_ctx(cpu).is_some_and(|cctx| time_before(now, cctx.busy_until.load(Relaxed)))
}

fn mark_cpu_busy(cpu: i32, now: u64) {
    if let Some(cctx) = try_lookup_cpu_ctx(cpu) {
        cctx.busy_until.store(now + slice_ns(), Relaxed);
    }
}

// ── Per-task context ─────────────────────────────────────────────────

#[derive(Default)]
struct TaskCtx {
    last_cputime: u64,
    /// Virtual lag saved when the task went to sleep.
    sleep_vlag: Option<i64>,
}

static TASK_CTXS: TaskMap<TaskCtx> = TaskMap::new();

/// Clamp saved virtual lag so sleepers carry bounded credit or debt.
fn clamp_sleep_vlag(p: Task, vlag: i64) -> i64 {
    let limit = p.lag_limit() as i64;
    vlag.clamp(-limit, limit)
}

impl TaskCtx {
    fn used_enough_cpu_time(&self, p: Task, runtime: u64) -> bool {
        runtime != 0 &&
            p.cputime() - self.last_cputime >= runtime * BUSY_THRESHOLD.load(Relaxed) / 1024
    }

    /// Save bounded virtual lag for voluntary sleepers.
    ///
    /// Positive lag means the task slept behind vtime_now (credit), negative
    /// lag means it slept ahead of vtime_now (debt).
    fn save_sleep_vlag(&mut self, p: Task) {
        let vlag = clamp_sleep_vlag(p, Vtime::now() - p.vtime());
        self.sleep_vlag = Some(vlag);
        p.set_vtime(Vtime::now() - vlag);
    }

    /// Re-align a waking task's vruntime to the current vtime_now, applying
    /// its saved virtual lag.
    ///
    /// Positive lag preserves bounded sleep credit, negative lag preserves
    /// bounded sleep debt.
    fn apply_sleep_vlag(&mut self, p: Task) -> Vtime {
        if let Some(vlag) = self.sleep_vlag.take() {
            p.set_vtime(Vtime::now() - clamp_sleep_vlag(p, vlag));
        }
        p.vtime()
    }

    /// Evaluate the deadline of task @p.
    fn deadline(&mut self, p: Task) -> Vtime {
        let was_sleeper = self.sleep_vlag.is_some();
        let vtime = self.apply_sleep_vlag(p);

        // A task waking from sleep already had its vruntime re-aligned to
        // vtime_now in apply_sleep_vlag(), bounded by the sleep virtual lag
        // clamp, so there is nothing more to do for it here.
        if was_sleeper {
            return vtime;
        }

        // Otherwise bound how far a continuously runnable task's vruntime can
        // fall behind the global vtime.
        //
        // A task that keeps running on a heavily contended CPU accumulates
        // vruntime much more slowly than the rest of the system. Without this
        // floor its low vruntime keeps undercutting other tasks queued on the
        // same per-CPU DSQ, which can starve them indefinitely and trip the
        // runnable task stall watchdog.
        //
        // The bound is symmetric with the sleep virtual lag clamp, so that
        // awake and sleeping tasks can drift from vtime_now by the same
        // amount.
        let vtime_min = Vtime::now() - p.lag_limit();
        if vtime < vtime_min {
            p.set_vtime(vtime_min);
        }
        vtime.max(vtime_min)
    }
}

/// Return @p's vruntime including runtime accumulated since it started
/// running.
///
/// @last_run_at is sourced from the per-CPU context rather than @p's context,
/// so this can be called on the current task of a remote CPU.
fn task_current_vtime(p: Task, last_run_at: u64) -> Vtime {
    let running_for = match last_run_at {
        0 => 0,
        t => now().saturating_sub(t),
    };
    p.vtime() + p.scale_by_weight_inverse(running_for)
}

/// Return true if an eligible sleeper should preempt @curr on wakeup.
fn should_preempt_curr(curr: Task, curr_cpu: i32, dl: Vtime, is_sleep_wakeup: bool) -> bool {
    if !is_sleep_wakeup || !dl.is_eligible() {
        return false;
    }

    // Only preempt tasks managed by sched_ext. A task that isn't (or is no
    // longer) scheduled by sched_ext has a zero dsq_vtime: it is set to a
    // non-zero system vruntime in ops.enable() and reset in ops.disable().
    //
    // Tasks in higher scheduling classes (stop, deadline, RT) can't be
    // preempted by us anyway. The idle task doesn't need SCX_ENQ_PREEMPT
    // either: a regular scx_bpf_dsq_insert() followed by the idle kick is
    // enough to take the CPU out of idle and run the waking task. So for both
    // cases we fall back to a regular vtime enqueue.
    if curr.dsq_vtime() == 0 {
        return false;
    }

    let last_run_at = try_lookup_cpu_ctx(curr_cpu).map_or(0, |cctx| cctx.last_run_at);
    let curr_vtime = task_current_vtime(curr, last_run_at);

    !curr_vtime.is_eligible() || dl < curr_vtime
}

// ── CPU state checks ─────────────────────────────────────────────────

/// Return true if @this_cpu and @that_cpu are in the same LLC, false
/// otherwise.
fn cpus_share_cache(this_cpu: i32, that_cpu: i32) -> bool {
    this_cpu == that_cpu || cpu_node(this_cpu) == cpu_node(that_cpu)
}

/// Return true if @this_cpu is faster than @that_cpu, false otherwise.
fn is_cpu_faster(this_cpu: i32, that_cpu: i32) -> bool {
    let capacity = |cpu: i32| CPU_CAPACITY.get().get(cpu as usize);
    this_cpu != that_cpu && capacity(this_cpu) > capacity(that_cpu)
}

/// Return the SMT sibling CPU of a @cpu, or @cpu if SMT is disabled.
fn smt_sibling(cpu: i32) -> i32 {
    try_lookup_cpu_ctx(cpu)
        .and_then(|cctx| cctx.smt.as_ref())
        .and_then(|smt| smt.first())
        .unwrap_or(cpu)
}

/// Return the cpumask of idle CPUs within the NUMA node that contains @cpu.
///
/// If NUMA support is disabled, @cpu is ignored.
fn get_idle_cpumask(cpu: i32) -> ScxCpumask {
    if NUMA_ENABLED.load(Relaxed) { ScxCpumask::idle_node(cpu_node(cpu)) } else { ScxCpumask::idle() }
}

/// Return true if the CPU is part of a fully busy SMT core, false otherwise.
fn is_smt_contended(cpu: i32) -> bool {
    if !SMT_ENABLED.load(Relaxed) {
        return false;
    }
    // If the sibling SMT CPU is not idle and there are other full-idle SMT
    // cores available, consider the current CPU as contended.
    let idle_mask = get_idle_cpumask(cpu);
    !idle_mask.test(smt_sibling(cpu)) && !idle_mask.is_empty()
}

/// Return true if we should attempt a task migration to an idle CPU from
/// ops.enqueue(), false otherwise.
fn try_migrate(p: Task, prev_cpu: i32, enq_flags: u64) -> bool {
    // Migrate if one of the following conditions is true:
    //  - migration was not attempted already via ops.select_cpu(),
    //  - the CPU is contended by other tasks,
    //  - SMT is enabled and the SMT core is contended by other tasks.
    (!p.is_running() && enq_flags & SCX_ENQ_CPU_SELECTED == 0) ||
        cpu_dsq(prev_cpu).peek().is_some() ||
        is_smt_contended(prev_cpu)
}

/// Return true if @cpu is in the primary domain, false otherwise.
fn is_primary_cpu(cpu: i32) -> bool { primary_all() || PRIMARY.test(cpu) }

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
    if is_smt_contended(cpu) {
        return false;
    }
    // If the task is not in the primary domain, give it a chance to migrate.
    is_primary_cpu(cpu) || !PRIMARY.intersects(p.cpus())
}

fn cpu_dsq(cpu: i32) -> Dsq { Dsq(cpu as u64) }

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
extern "C" fn beerland_enable_sibling_cpu(input: &DomainArg) -> i32 {
    let Some(cctx) = try_lookup_cpu_ctx(input.cpu_id) else { return -ENOENT.0 };
    cctx.smt.get_or_insert_with(|| Box::new(CpuSet::new())).set(input.sibling_cpu_id);
    0
}

/// Called from user-space to add CPUs to the the primary domain.
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn beerland_enable_primary_cpu(input: &CpuArg) -> i32 {
    PRIMARY.set(input.cpu_id);
    0
}

// ── Idle CPU selection ───────────────────────────────────────────────

/// Pick an optimal idle CPU for task @p (as close as possible to @prev_cpu).
fn pick_idle_cpu(p: Task, prev_cpu: i32, wake_flags: u64) -> Option<i32> {
    // If a primary domain is defined, try to pick an idle CPU from there
    // first.
    if !primary_all() {
        let cpu = PRIMARY.iter_from(prev_cpu)
            .filter(|&cpu| p.cpus().test(cpu))
            .find(|&cpu| test_and_clear_cpu_idle(cpu));
        if cpu.is_some() {
            return cpu;
        }
    }

    // Pick any idle CPU usable by the task.
    p.select_cpu_and(prev_cpu, wake_flags, p.cpus(), 0)
}

// ── struct_ops callbacks ─────────────────────────────────────────────

// Called on task wakeup to give the task a chance to migrate to an idle CPU.
bpf_prog!("struct_ops/beerland_select_cpu",
fn beerland_select_cpu(p: Task, prev_cpu: i32, wake_flags: u64) -> i32 {
    let this_cpu = this_cpu();
    let mut prev_cpu = prev_cpu;

    // On wakeup if the waker's CPU is faster than the wakee's CPU, try to
    // move the wakee closer to the waker.
    if wake_flags & SCX_WAKE_TTWU != 0 && is_cpu_faster(this_cpu, prev_cpu) &&
       p.is_cpu_allowed(this_cpu) {
        // If both the waker's CPU and the wakee's CPU are in the same LLC and
        // the wakee's CPU is a fully idle SMT core, don't migrate.
        if p.is_cpu_allowed(prev_cpu) && cpus_share_cache(this_cpu, prev_cpu) &&
           !is_smt_contended(prev_cpu) && test_and_clear_cpu_idle(prev_cpu) {
            p.dsq_insert(SCX_DSQ_LOCAL, slice_ns(), 0);
            return prev_cpu;
        }
        prev_cpu = this_cpu;
    }

    // Try to find an optimal idle CPU for the task. If no idle CPU is found,
    // keep using the same one.
    pick_idle_cpu(p, prev_cpu, wake_flags)
        .inspect(|_| p.dsq_insert(SCX_DSQ_LOCAL, slice_ns(), 0))
        .unwrap_or(prev_cpu)
});

// Called when a task expired its time slice and still needs to run or on
// wakeup when there's no idle CPU available.
bpf_prog!("struct_ops/beerland_enqueue",
fn beerland_enqueue(p: Task, enq_flags: u64) {
    let prev_cpu = p.usable_cpu(p.cpu());
    let Some(tctx) = TASK_CTXS.get(p) else { return };

    let is_wakeup = enq_flags & SCX_ENQ_WAKEUP != 0 && tctx.sleep_vlag.is_some();
    let dl = tctx.deadline(p);

    // Attempt a migration to an idle CPU if possible.
    if try_migrate(p, prev_cpu, enq_flags) {
        let cpu = if p.is_pcpu() {
            test_and_clear_cpu_idle(prev_cpu).then_some(prev_cpu)
        } else {
            pick_idle_cpu(p, prev_cpu, 0)
        };

        if let Some(cpu) = cpu {
            p.dsq_insert(Dsq::local_on(cpu).0, slice_ns(), enq_flags);
            if prev_cpu != cpu || !p.is_running() {
                kick_cpu(cpu, SCX_KICK_IDLE);
            }
            return;
        }
    }

    // Keep running on the same CPU.
    let preempt_wakeup = match cpu_curr(prev_cpu) {
        Some(curr) if should_preempt_curr(curr, prev_cpu, dl, is_wakeup) => {
            p.dsq_insert(Dsq::local_on(prev_cpu).0, slice_ns(), enq_flags | SCX_ENQ_PREEMPT);
            true
        }
        Some(_) => {
            p.dsq_insert_vtime(cpu_dsq(prev_cpu).0, slice_ns(), dl.0, enq_flags);
            false
        }
        None => {
            p.dsq_insert(Dsq::local_on(prev_cpu).0, slice_ns(), enq_flags);
            false
        }
    };

    if !preempt_wakeup && enq_flags & SCX_ENQ_CPU_SELECTED == 0 {
        kick_cpu(prev_cpu, SCX_KICK_IDLE);
    }
});

/// Try to steal the runnable task with the earliest vruntime and dispatch it
/// on @dst_cpu.
fn try_steal_task(dst_cpu: i32) -> bool {
    let now = now();
    let nr_cpus = NR_CPU_IDS.load(Relaxed) as i32;

    // Offset the scan by @dst_cpu so that, on ties, different CPUs start
    // probing from different positions instead of all favoring the lowest CPU
    // ID.
    (dst_cpu..dst_cpu + nr_cpus)
        .map(|cpu| if cpu >= nr_cpus { cpu - nr_cpus } else { cpu })
        .filter(|&cpu| is_cpu_busy(cpu, now))
        .filter_map(|cpu| {
            let p = cpu_dsq(cpu).peek().filter(|p| p.cpus().test(dst_cpu))?;
            Some((p.dsq_vtime(), cpu))
        })
        .min_by_key(|&(vtime, _)| vtime)
        .is_some_and(|(_, cpu)| cpu_dsq(cpu).move_to_local())
}

// Called when a CPU becomes available: dispatch the next task on the CPU or
// let the CPU go idle.
bpf_prog!("struct_ops/beerland_dispatch",
fn beerland_dispatch(cpu: i32, prev: Option<Task>) {
    let keep = prev.filter(|&prev| keep_running(prev, cpu));

    if try_steal_task(cpu) {
        NR_REMOTE_DISPATCH.fetch_add(1, Relaxed);
        return;
    }

    if cpu_dsq(cpu).move_to_local() {
        NR_LOCAL_DISPATCH.fetch_add(1, Relaxed);
        return;
    }

    // If the current task expired its time slice and no other task wants to
    // run, simply replenish its time slice and let it run for another round
    // on the same CPU.
    if let Some(prev) = keep {
        prev.set_slice(slice_ns());
        NR_KEEP_RUNNING.fetch_add(1, Relaxed);
    }
});

bpf_prog!("struct_ops/beerland_running",
fn beerland_running(p: Task) {
    let Some(tctx) = TASK_CTXS.get(p) else { return };

    // Save a timestamp when the task begins to run, used to evaluate the used
    // time slice in ops.stopping() and to estimate this task's current
    // vruntime from a remote CPU in should_preempt_curr().
    if let Some(cctx) = try_lookup_cpu_ctx(p.cpu()) {
        cctx.last_run_at = now();
    }
    tctx.last_cputime = p.cputime();

    // Re-apply vlag here for tasks that have been directly dispatched,
    // bypassing the per-CPU DSQ.
    let vtime = tctx.apply_sleep_vlag(p);

    // Update current system's vruntime.
    if Vtime::now() < vtime {
        VTIME_NOW.store(vtime.0, Relaxed);
    }
});

bpf_prog!("struct_ops/beerland_stopping",
fn beerland_stopping(p: Task, runnable: bool) {
    let Some(cctx) = try_lookup_cpu_ctx(p.cpu()) else { return };
    let Some(tctx) = TASK_CTXS.get(p) else { return };

    // Evaluate the used time slice.
    let now = now();
    let slice = now - cctx.last_run_at;

    if BUSY_THRESHOLD.load(Relaxed) != 0 && runnable && tctx.used_enough_cpu_time(p, slice) {
        mark_cpu_busy(this_cpu(), now);
    }

    // Update the vruntime.
    p.set_vtime(p.vtime() + p.scale_by_weight_inverse(slice));
});

bpf_prog!("struct_ops/beerland_quiescent",
fn beerland_quiescent(p: Task, deq_flags: u64) {
    let Some(tctx) = TASK_CTXS.get(p) else { return };

    if deq_flags & SCX_DEQ_SLEEP != 0 {
        tctx.save_sleep_vlag(p);
    }
});

bpf_prog!("struct_ops/beerland_enable",
fn beerland_enable(p: Task) {
    p.set_vtime(Vtime::now());
});

bpf_prog!("struct_ops/beerland_disable",
fn beerland_disable(p: Task) {
    // Reset the task's vruntime when it leaves sched_ext, so that it is no
    // longer mistaken for a sched_ext task by should_preempt_curr() while it
    // runs under a different scheduling class.
    p.set_vtime(Vtime(0));
});

bpf_prog!("struct_ops/beerland_init_task",
fn beerland_init_task(p: Task, _args: *const ScxInitTaskArgs) -> i32 {
    TASK_CTXS.insert(p, TaskCtx::default());
    0
});

bpf_prog!("struct_ops/beerland_exit_task",
fn beerland_exit_task(p: Task, _args: *const u8) {
    TASK_CTXS.remove(p);
});

bpf_prog!("struct_ops/beerland_exit",
fn beerland_exit(_ei: *const ScxExitInfo) {
});

bpf_prog!("struct_ops.s/beerland_init",
fn beerland_init() -> Result {
    let nr_cpus = nr_cpu_ids() as i32;
    NR_CPU_IDS.store(nr_cpus as u64, Relaxed);

    *unsafe { CPU_CAPACITY.get_mut() } = (0..nr_cpus).map(cpuperf_cap).collect();

    (0..nr_cpus).try_for_each(|cpu| cpu_dsq(cpu).create(cpu_node(cpu)))
});

scx_ops_define!(beerland_ops, name: b"beerland",
    flags: SCX_OPS_ENQ_EXITING | SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_MIGRATION_DISABLED |
           SCX_OPS_ALWAYS_ENQ_IMMED | SCX_OPS_ALLOW_QUEUED_WAKEUP |
           if NUMA_DEFAULT { SCX_OPS_BUILTIN_IDLE_PER_NODE } else { 0 },
    timeout_ms: 5000,
    select_cpu: beerland_select_cpu,
    enqueue: beerland_enqueue,
    dispatch: beerland_dispatch,
    running: beerland_running,
    stopping: beerland_stopping,
    quiescent: beerland_quiescent,
    enable: beerland_enable,
    disable: beerland_disable,
    init_task: beerland_init_task,
    exit_task: beerland_exit_task,
    init: beerland_init,
    exit: beerland_exit,
);

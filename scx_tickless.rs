// SPDX-License-Identifier: GPL-2.0
//
// scx_tickless: a scheduler that routes all scheduling events through a pool
// of primary CPUs, so that the other CPUs can run tasks with an infinite time
// slice and no tick.
//
// Rust port of scheds/rust/scx_tickless/src/bpf/main.bpf.c.
// Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
//
// - BPF_MAP_TYPE_TASK_STORAGE     -> TaskMap<TaskCtx>
// - BPF_MAP_TYPE_ARRAY cpu_ctx    -> a map with the timers alone, and a CpuSet
//                                    of the CPUs whose timer is initialized
// - primary_cpumask (kptr)        -> CpuSet
// - preferred_cpus[]              -> Vec<i32>, sorted by capacity in ops.init().
//                                    User space fills it in C.
// - bpf_for_each(scx_dsq)         -> DsqIter, an Iterator
// - bpf_task_from_pid()/release   -> TaskRef, released by Drop
// - CONFIG_HZ (__kconfig)         -> a constant
//
// Without user space: CPU 0 is the primary CPU unless enable_primary_cpu was
// called, and ops.dispatch() of a primary CPU starts its timer, which is what
// the start_timer syscall program pinned to that CPU is for in C. UEI is
// dropped.

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::vec::Vec;
use core::cmp::Reverse;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use scx_common::*;

const SHARED_DSQ: Dsq = Dsq(0);
const CONFIG_HZ: u64 = 1000;

// ── Configuration (const volatile equivalents) ───────────────────────

tunables! { "tickless",
    SMT_ENABLED: AtomicBool = false;
    SLICE_NS: AtomicU64 = 20 * NSEC_PER_MSEC;
    TICK_FREQ: AtomicU64 = 0;
}

// ── Statistics ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Stat {
    Ticks,
    Preemptions,
    DirectDispatches,
    TimerDispatches,
    PrimaryDispatches,
    NrStats,
}

static STATS: [AtomicU64; Stat::NrStats as usize] =
    [const { AtomicU64::new(0) }; Stat::NrStats as usize];

impl Stat {
    fn inc(self) { STATS[self as usize].fetch_add(1, Relaxed); }
}

// ── Global state ─────────────────────────────────────────────────────

/// CPUs sorted by their capacity in descendent order.
static PREFERRED_CPUS: BpfCell<Vec<i32>> = BpfCell::new(Vec::new());

/// CPUs assigned to handle scheduling events.
static PRIMARY: CpuSet = CpuSet::new();

/// One timer per CPU. Only the ones of the primary CPUs are used.
bpf_timer_map!(tickless_timers, timers, MAX_CPUS);
static TIMER_INITIALIZED: CpuSet = CpuSet::new();
static TIMER_STARTED: CpuSet = CpuSet::new();

/// Keep track of the current global vruntime.
///
/// The vuntime is defined as the task's runtime inversely scaled using the
/// task's weight (priority).
static VTIME_NOW: AtomicU64 = AtomicU64::new(0);

/// Return a random CPU from the pool of CPUs dedicated to process scheduling
/// events.
fn pick_primary_cpu() -> Result<i32> {
    PRIMARY.any_distribute().ok_or(ENOENT)
        .inspect_err(|_| scx_error!("Primary CPUs not initialized"))
}

// ── Per-task context ─────────────────────────────────────────────────

#[derive(Default)]
struct TaskCtx {
    /// Timestamp (in ns) when the task ran last time.
    last_run_at: u64,

    /// Sum of the task's runtime from when it becomes runnable (ready to run
    /// on a CPU) to when the task voluntarily releases the CPU (either by
    /// completing its execution or waiting for an event).
    exec_runtime: u64,

    /// Task's deadline, defined as:
    ///
    ///   deadline = vruntime + exec_vruntime
    ///
    /// Here, vruntime represents the task's total runtime, scaled inversely
    /// by its weight, while exec_vruntime accounts for the vruntime
    /// accumulated from the moment the task becomes runnable until it
    /// voluntarily releases the CPU.
    ///
    /// Fairness is ensured through vruntime, whereas exec_vruntime helps in
    /// prioritizing latency-sensitive tasks: tasks that are frequently
    /// blocked waiting for an event (typically latency sensitive) will
    /// accumulate a smaller exec_vruntime, compared to tasks that
    /// continuously consume CPU without interruption.
    deadline: u64,
}

static TASK_CTXS: TaskMap<TaskCtx> = TaskMap::new();

impl TaskCtx {
    /// Update and return the task's deadline.
    fn update_deadline(&mut self, p: Task) -> u64 {
        // Limit the amount of vtime budget that an idling task can accumulate
        // to prevent excessive prioritization of sleeping tasks.
        let vtime_min = VTIME_NOW.load(Relaxed).wrapping_sub(SLICE_NS.load(Relaxed));
        if time_before(self.deadline, vtime_min) {
            self.deadline = vtime_min;
        }

        // Add the execution vruntime to the deadline.
        self.deadline.wrapping_add(p.scale_by_weight_inverse(self.exec_runtime))
    }
}

/// Return the time interval between two ticks in ns.
fn tick_interval_ns() -> u64 {
    NSEC_PER_SEC / match TICK_FREQ.load(Relaxed) {
        0 => CONFIG_HZ,
        freq => freq,
    }
}

/// Return true if the waker commits to release the CPU after waking up @p,
/// false otherwise.
fn is_wake_sync(wake_flags: u64) -> bool {
    wake_flags & SCX_WAKE_SYNC != 0 && !Task::current().is_exiting()
}

bpf_prog!("struct_ops/tickless_select_cpu",
fn tickless_select_cpu(_p: Task, prev_cpu: i32, wake_flags: u64) -> i32 {
    // Consider sync wakeups almost like a function call and try to route the
    // wakee to the waker's CPU.
    if is_wake_sync(wake_flags) {
        return this_cpu();
    }

    // Always route wakeups to a CPU from the primary group to minimize noise
    // on the other CPUs.
    //
    // Also make sure to lock the selected CPU, so that it's not picked when
    // distributing tasks in dispatch_all_cpus().
    pick_primary_cpu().inspect(|&cpu| { test_and_clear_cpu_idle(cpu); }).unwrap_or(prev_cpu)
});

bpf_prog!("struct_ops/tickless_enqueue",
fn tickless_enqueue(p: Task, enq_flags: u64) {
    // Insert the task to the shared queue.
    if let Some(tctx) = TASK_CTXS.get(p) {
        p.dsq_insert_vtime(SHARED_DSQ.0, SCX_SLICE_INF, tctx.update_deadline(p), enq_flags);
    }
});

/// Who distributes the tasks.
#[derive(Clone, Copy, PartialEq)]
enum Caller {
    Dispatch,
    Timer,
}

/// Try to consume a task from the shared queue and dispatch on a target @cpu.
///
/// Return true if a task was dispatched, false otherwise.
fn dispatch_cpu(cpu: i32, from: Caller) -> bool {
    let _rcu = rcu_read_lock();
    let mut state = DsqIterState::new();
    let mut queue = state.iter(SHARED_DSQ, 0);

    while let Some(p) = queue.next() {
        // This is a workaround for the BPF verifier's pointer validation
        // limitations. Once the verifier gets smarter we can remove this
        // bpf_task_from_pid().
        let Some(p) = TaskRef::from_pid(p.pid()) else { continue };

        if !p.cpus().test(cpu) {
            continue;
        }

        // If there's an eligible task in the SHARED_DSQ that can run on this
        // CPU, clear the CPU's idle state and dispatch the task. Otherwise,
        // immediately give up and move to the next CPU, since the goal is to
        // avoid contention as much as possible, so that tasks can keep using
        // their infinite time slice.
        //
        // However, if the first eligible task in the SHARED_DSQ is a per-CPU
        // task, dispatch it regardless of the CPU's idle state, since
        // contention is unavoidable in this case (the task can only run on
        // this CPU). Then the currently running task will be made preemptible
        // by the BPF timer, changing its time slice from SCX_SLICE_INF to a
        // finite slice_ns.
        //
        // In this way we can still minimize CPU contention without
        // introducing starvation for per-CPU tasks.
        if !test_and_clear_cpu_idle(cpu) && !p.is_pcpu() {
            break;
        }

        if !queue.move_to(*p, Dsq::local_on(cpu), 0) {
            continue;
        }

        match from {
            Caller::Dispatch => Stat::PrimaryDispatches.inc(),
            Caller::Timer => Stat::TimerDispatches.inc(),
        }
        return true;
    }

    false
}

/// Consume tasks from the shared queue and distribute them evenly across the
/// available CPUs.
///
/// If @do_idle_smt is true, consider only full-idle SMT cores.
///
/// Return true when no task is left in the queue.
fn dispatch_all_cpus(do_idle_smt: bool, from: Caller) -> bool {
    if SHARED_DSQ.nr_queued() == 0 {
        return true;
    }
    if !SMT_ENABLED.load(Relaxed) && do_idle_smt {
        return false;
    }

    let mask = do_idle_smt.then(ScxCpumask::idle_smt);

    PREFERRED_CPUS.get().iter().copied()
        // Try to lock the first idle CPU available and attempt to dispatch a
        // task.
        .filter(|&cpu| mask.as_ref().is_none_or(|mask| mask.test(cpu)))
        // Wakeup the selected CPU, if no task is dispatched the CPU will
        // automatically reset its idle state.
        .inspect(|&cpu| kick_cpu(cpu, SCX_KICK_IDLE))
        // Do not distribute tasks to the primary CPUs, keep them as a last
        // resort.
        .filter(|&cpu| !PRIMARY.test(cpu))
        // Consume a task from the shared DSQ and dispatch it to the target
        // CPU. Stop dispatching if all the pending tasks have been
        // distributed.
        .any(|cpu| {
            dispatch_cpu(cpu, from);
            SHARED_DSQ.nr_queued() == 0
        })
}

bpf_callback!(fn sched_timerfn(_map: *mut u8, _key: *mut u32, timer: *mut bpf_timer) -> i32 {
    // Dispatch tasks on the available CPUs.
    if !dispatch_all_cpus(true, Caller::Timer) {
        dispatch_all_cpus(false, Caller::Timer);
    }

    // Check if we need to preempt the running tasks.
    {
        let rcu = rcu_read_lock();

        (0..nr_cpu_ids() as i32)
            // Ignore CPU if idle task is running.
            .filter_map(|cpu| Some((cpu, rcu.cpu_curr(cpu).filter(|p| !p.is_idle_task())?)))
            // Ignore CPUs without any task waiting.
            .filter(|&(cpu, _)| {
                Dsq::local_on(cpu).nr_queued() != 0 || SHARED_DSQ.nr_queued() != 0
            })
            // Set a finite time slice to the running task, so that it can be
            // preempted.
            .filter(|(_, p)| p.slice() == SCX_SLICE_INF)
            .for_each(|(_, p)| {
                p.set_slice(SLICE_NS.load(Relaxed));
                Stat::Preemptions.inc();
            });
    }

    if let Some(timer) = Timer::from_ptr(timer) {
        let _ = timer.start(tick_interval_ns(), 0);
    }
    0
});

/// Initialize the BPF timer on a target CPU.
fn init_timer(cpu: i32) -> Result {
    if !PRIMARY.test(cpu) {
        return Err(EINVAL);
    }
    if TIMER_INITIALIZED.test(cpu) {
        return Ok(());
    }
    timers().init(cpu as u32, CLOCK_MONOTONIC, sched_timerfn)?;
    TIMER_INITIALIZED.set(cpu);
    Ok(())
}

/// Start the already-initialized BPF timer on a target CPU.
fn start_timer_on_cpu(cpu: i32) -> Result {
    if !PRIMARY.test(cpu) || !TIMER_INITIALIZED.test(cpu) {
        return Err(EINVAL);
    }
    timers().get(cpu as u32).ok_or(ENOENT)?.start(tick_interval_ns(), 0)
}

bpf_prog!("struct_ops/tickless_dispatch",
fn tickless_dispatch(cpu: i32, prev: Option<Task>) {
    if PRIMARY.test(cpu) {
        // Nobody calls start_timer for us.
        if !TIMER_STARTED.test(cpu) && start_timer_on_cpu(cpu).is_ok() {
            TIMER_STARTED.set(cpu);
        }

        // Try to bounce all the queued tasks to the available tickless CPUs
        // first.
        if !dispatch_all_cpus(true, Caller::Dispatch) {
            dispatch_all_cpus(false, Caller::Dispatch);
        }
    }

    // Consume a task from the shared DSQ.
    //
    // This applies also to primary CPUs: if there are still tasks in the
    // shared DSQ after distributing them to the tickless CPUs, primary CPUs
    // will also start consuming them.
    if SHARED_DSQ.move_to_local() {
        Stat::DirectDispatches.inc();
        return;
    }

    // Keep running the previous task if it still wants to run.
    if let Some(prev) = prev.filter(|prev| prev.is_queued()) {
        prev.set_slice(SCX_SLICE_INF);
    }
});

// Task @p is ready to run.
bpf_prog!("struct_ops/tickless_runnable",
fn tickless_runnable(p: Task, _enq_flags: u64) {
    // Reset the execution runtime, as we are starting the task either from
    // the beginning of its lifetime or after it has been blocked.
    if let Some(tctx) = TASK_CTXS.get(p) {
        tctx.exec_runtime = 0;
    }
});

// Task @p is about to start running on a CPU.
bpf_prog!("struct_ops/tickless_running",
fn tickless_running(p: Task) {
    let Some(tctx) = TASK_CTXS.get(p) else { return };

    // Update the run timestamp (used to evaluate the used time slice).
    tctx.last_run_at = scx_now();

    // Update the global vruntime as a new task is starting to use a CPU.
    if time_before(VTIME_NOW.load(Relaxed), tctx.deadline) {
        VTIME_NOW.store(tctx.deadline, Relaxed);
    }
});

bpf_prog!("struct_ops/tickless_tick",
fn tickless_tick(_p: Task) {
    Stat::Ticks.inc();
});

// Task @p is about to release the CPU.
bpf_prog!("struct_ops/tickless_stopping",
fn tickless_stopping(p: Task, _runnable: bool) {
    let Some(tctx) = TASK_CTXS.get(p) else { return };

    // Evaluate the time slice used by the task.
    let slice = scx_now() - tctx.last_run_at;

    // Update task's execution time (exec_runtime), but never account more
    // than 1s of runtime to prevent excessive de-prioritization of
    // CPU-intensive tasks (which could lead to starvation).
    if tctx.exec_runtime < NSEC_PER_SEC {
        tctx.exec_runtime += slice;
    }

    // Update task's vruntime.
    tctx.deadline = tctx.deadline.wrapping_add(p.scale_by_weight_inverse(slice));
});

// Task @p is entering the BPF scheduler.
bpf_prog!("struct_ops/tickless_enable",
fn tickless_enable(p: Task) {
    // Initialize the task vruntime to the current global vruntime.
    if let Some(tctx) = TASK_CTXS.get(p) {
        tctx.deadline = VTIME_NOW.load(Relaxed);
    }
});

// Task @p is created.
bpf_prog!("struct_ops/tickless_init_task",
fn tickless_init_task(p: Task, _args: *const ScxInitTaskArgs) -> i32 {
    TASK_CTXS.insert(p, TaskCtx::default());
    0
});

bpf_prog!("struct_ops/tickless_exit_task",
fn tickless_exit_task(p: Task, _args: *const u8) {
    TASK_CTXS.remove(p);
});

// ── Syscall handlers (SEC("syscall")) ────────────────────────────────

#[repr(C)]
struct CpuArg {
    cpu_id: i32,
}

/// Add a CPU to the pool of CPUs dedicated to process scheduling events.
///
/// If the target CPU is a negative value, clear the whole mask (this can be
/// used to reset the primary group).
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn tickless_enable_primary_cpu(input: &CpuArg) -> i32 {
    match input.cpu_id {
        cpu if cpu < 0 => PRIMARY.clear_all(),
        cpu => PRIMARY.set(cpu),
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn tickless_start_timer(input: &CpuArg) -> i32 {
    if input.cpu_id != this_cpu() {
        return -EINVAL.0;
    }
    start_timer_on_cpu(input.cpu_id).ret()
}

bpf_prog!("struct_ops.s/tickless_init",
fn tickless_init() -> Result {
    SHARED_DSQ.create(-1)?;

    let mut cpus: Vec<i32> = (0..nr_cpu_ids().min(MAX_CPUS as u32) as i32).collect();
    cpus.sort_unstable_by_key(|&cpu| Reverse(cpuperf_cap(cpu)));
    *unsafe { PREFERRED_CPUS.get_mut() } = cpus;

    if PRIMARY.is_empty() {
        PRIMARY.set(0);
    }
    PRIMARY.iter().try_for_each(init_timer)
});

bpf_prog!("struct_ops/tickless_exit",
fn tickless_exit(_ei: *const ScxExitInfo) {
    timers().cancel_all();
});

scx_ops_define!(tickless_ops, name: b"tickless",
    flags: SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_MIGRATION_DISABLED | SCX_OPS_ALLOW_QUEUED_WAKEUP,
    timeout_ms: 5000,
    select_cpu: tickless_select_cpu,
    enqueue: tickless_enqueue,
    dispatch: tickless_dispatch,
    runnable: tickless_runnable,
    running: tickless_running,
    tick: tickless_tick,
    stopping: tickless_stopping,
    enable: tickless_enable,
    init_task: tickless_init_task,
    exit_task: tickless_exit_task,
    init: tickless_init,
    exit: tickless_exit,
);

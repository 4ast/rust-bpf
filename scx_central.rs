// SPDX-License-Identifier: GPL-2.0
//
// scx_central: a central FIFO sched_ext scheduler which demonstrates the
// following:
//
// a. Making all scheduling decisions from one CPU:
//
//    The central CPU is the only one making scheduling decisions. All other
//    CPUs kick the central CPU when they run out of tasks to run.
//
//    There is one global queue and the central CPU schedules all CPUs by
//    dispatching from the global queue to each CPU's local dsq from
//    dispatch().
//
// b. Tickless operation
//
//    All tasks are dispatched with the infinite slice which allows stopping
//    the ticks on CONFIG_NO_HZ_FULL kernels running with the proper nohz_full
//    parameter.
//
//    Periodic switching is enforced by a periodic timer checking all CPUs and
//    preempting them as necessary.
//
// c. Preemption
//
//    Kthreads are unconditionally queued to the head of a matching local dsq
//    and dispatched with SCX_DSQ_PREEMPT. This ensures that a kthread is
//    always prioritized over user threads, which is required for ensuring
//    forward progress as e.g. the periodic timer may run on a ksoftirqd and if
//    the ksoftirqd gets starved by a user thread, there may not be anything
//    else to vacate that user thread.
//
// Rust port of tools/sched_ext/scx_central.bpf.c.
// Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
// Copyright (c) 2022 Tejun Heo <tj@kernel.org>
// Copyright (c) 2022 David Vernet <dvernet@meta.com>
//
// - BPF_MAP_TYPE_QUEUE central_q        -> SpinLock<VecDeque<i32>>
// - RESIZABLE_ARRAY cpu_gimme_task,
//   cpu_started_at                      -> Vec<CpuState>, sized in ops.init()
// - bpf_task_from_pid()/release         -> TaskRef, released by Drop
// - UEI is dropped

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering::Relaxed};
use scx_common::*;

const FALLBACK_DSQ: Dsq = Dsq(0);
const TIMER_INTERVAL_NS: u64 = NSEC_PER_MSEC;
const CENTRAL_Q_MAX: usize = 4096;

tunables! { "central",
    CENTRAL_CPU: AtomicI32 = 0;
    SLICE_NS: AtomicU64 = SCX_SLICE_DFL;
}

fn central_cpu() -> i32 { CENTRAL_CPU.load(Relaxed) }

static TIMER_PINNED: AtomicBool = AtomicBool::new(true);
static TIMER_STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
enum Stat {
    Total,
    Locals,
    LostPids,
    Timers,
    Dispatches,
    Mismatches,
    Retries,
    Overflows,
    NrStats,
}

static STATS: [AtomicU64; Stat::NrStats as usize] =
    [const { AtomicU64::new(0) }; Stat::NrStats as usize];

impl Stat {
    fn inc(self) -> u64 { STATS[self as usize].fetch_add(1, Relaxed) }
    fn get(self) -> u64 { STATS[self as usize].load(Relaxed) }
}

/// The pids of the tasks waiting for a CPU.
static CENTRAL_Q: SpinLock<VecDeque<i32>> = SpinLock::new(VecDeque::new());
static NR_QUEUED: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct CpuState {
    /// The CPU has run out of tasks. Central's is never set.
    gimme_task: AtomicBool,
    /// When the task on the CPU started to run. 0 indicates idle.
    started_at: AtomicU64,
}

static CPUS: BpfCell<Vec<CpuState>> = BpfCell::new(Vec::new());

fn cpu_state(cpu: i32) -> Option<&'static CpuState> { CPUS.get().get(usize::try_from(cpu).ok()?) }

bpf_timer_map!(central_timer, timers, 1);

bpf_prog!("struct_ops/central_select_cpu",
fn central_select_cpu(_p: Task, _prev_cpu: i32, _wake_flags: u64) -> i32 {
    // Steer wakeups to the central CPU as much as possible to avoid disturbing
    // other CPUs. It's safe to blindly return the central cpu as select_cpu()
    // is a hint and if @p can't be on it, the kernel will automatically pick a
    // fallback CPU.
    central_cpu()
});

/// bpf_map_push_elem() of a queue map fails when the queue is full.
fn central_q_push(pid: i32) -> Result {
    let mut q = CENTRAL_Q.lock();
    if q.len() >= CENTRAL_Q_MAX {
        return Err(EBUSY);
    }
    q.push_back(pid);
    Ok(())
}

bpf_prog!("struct_ops/central_enqueue",
fn central_enqueue(p: Task, enq_flags: u64) {
    Stat::Total.inc();

    // Push per-cpu kthreads at the head of local dsq's and preempt the
    // corresponding CPU. This ensures that e.g. ksoftirqd isn't blocked behind
    // other threads which is necessary for forward progress guarantee as we
    // depend on the BPF timer which may run from ksoftirqd.
    if p.is_kthread() && p.nr_cpus_allowed() == 1 {
        Stat::Locals.inc();
        p.dsq_insert(SCX_DSQ_LOCAL, SCX_SLICE_INF, enq_flags | SCX_ENQ_PREEMPT);
        return;
    }

    if central_q_push(p.pid()).is_err() {
        Stat::Overflows.inc();
        p.dsq_insert(FALLBACK_DSQ.0, SCX_SLICE_INF, enq_flags);
        return;
    }

    NR_QUEUED.fetch_add(1, Relaxed);

    if !p.is_running() {
        kick_cpu(central_cpu(), SCX_KICK_PREEMPT);
    }
});

fn dispatch_to_cpu(cpu: i32) -> bool {
    // The guard is a temporary of the condition: the queue is unlocked while
    // the task is looked at.
    while let Some(pid) = { let pid = CENTRAL_Q.lock().pop_front(); pid } {
        NR_QUEUED.fetch_sub(1, Relaxed);

        let Some(p) = TaskRef::from_pid(pid) else {
            Stat::LostPids.inc();
            continue;
        };

        // If we can't run the task at the top for whatever reason, bounce it
        // to the fallback dsq. Also check is_migration_disabled() explicitly
        // as p->cpus_ptr may not reflect the migration-disabled state yet if
        // migrate_disable_switch() hasn't run.
        if !p.cpus().test(cpu) || (p.is_migration_disabled() && p.cpu() != cpu) {
            Stat::Mismatches.inc();
            p.dsq_insert(FALLBACK_DSQ.0, SCX_SLICE_INF, 0);

            // We might run out of dispatch buffer slots if we continue
            // dispatching to the fallback DSQ, without dispatching to the
            // local DSQ of the target CPU. In such a case, break the loop now
            // as will fail the next dispatch operation.
            if dispatch_nr_slots() == 0 {
                break;
            }
            continue;
        }

        // dispatch to local and mark that @cpu doesn't need more
        p.dsq_insert(Dsq::local_on(cpu).0, SCX_SLICE_INF, 0);

        if cpu != central_cpu() {
            kick_cpu(cpu, SCX_KICK_IDLE);
        }
        return true;
    }

    false
}

fn start_central_timer() {
    if TIMER_STARTED.load(Relaxed) {
        return;
    }

    let Some(timer) = timers().get(0) else {
        scx_error!("failed to lookup central timer");
        return;
    };

    // BPF_F_TIMER_CPU_PIN is pretty new (>=6.7). If we're running in a kernel
    // which doesn't have it, bpf_timer_start() will return -EINVAL. Retry
    // without the PIN.
    let ret = timer.start(TIMER_INTERVAL_NS, BPF_F_TIMER_CPU_PIN).or_else(|e| {
        if e != EINVAL {
            return Err(e);
        }
        TIMER_PINNED.store(false, Relaxed);
        timer.start(TIMER_INTERVAL_NS, 0)
    });

    match ret {
        Ok(()) => TIMER_STARTED.store(true, Relaxed),
        Err(e) => scx_error!("bpf_timer_start failed (%d)", -e.0),
    }
}

bpf_prog!("struct_ops/central_dispatch",
fn central_dispatch(cpu: i32, _prev: Option<Task>) {
    if cpu != central_cpu() {
        if FALLBACK_DSQ.move_to_local() {
            return;
        }

        if let Some(state) = cpu_state(cpu) {
            state.gimme_task.store(true, Relaxed);
        }

        // Force dispatch on the scheduling CPU so that it finds a task to run
        // for us.
        kick_cpu(central_cpu(), SCX_KICK_PREEMPT);
        return;
    }

    start_central_timer();

    // dispatch for all other CPUs first
    Stat::Dispatches.inc();

    CPUS.get().iter().zip(0..)
        .take_while(|_| dispatch_nr_slots() != 0)
        .filter(|(state, _)| state.gimme_task.load(Relaxed))
        .for_each(|(state, cpu)| {
            if dispatch_to_cpu(cpu) {
                state.gimme_task.store(false, Relaxed);
            }
        });

    // Retry if we ran out of dispatch buffer slots as we might have skipped
    // some CPUs and also need to dispatch for self. The ext core automatically
    // retries if the local dsq is empty but we can't rely on that as we're
    // dispatching for other CPUs too. Kick self explicitly to retry.
    if dispatch_nr_slots() == 0 {
        Stat::Retries.inc();
        kick_cpu(central_cpu(), SCX_KICK_PREEMPT);
        return;
    }

    // look for a task to run on the central CPU
    if !FALLBACK_DSQ.move_to_local() {
        dispatch_to_cpu(central_cpu());
    }
});

bpf_prog!("struct_ops/central_running",
fn central_running(p: Task) {
    if let Some(state) = cpu_state(p.cpu()) {
        state.started_at.store(scx_now().max(1), Relaxed); // 0 indicates idle
    }
});

bpf_prog!("struct_ops/central_stopping",
fn central_stopping(p: Task, _runnable: bool) {
    if let Some(state) = cpu_state(p.cpu()) {
        state.started_at.store(0, Relaxed);
    }
});

extern "C" fn timerfn(_map: *mut u8, _key: *mut u32, timer: *mut bpf_timer) -> i32 {
    let now = scx_now();
    let mut nr_to_kick = NR_QUEUED.load(Relaxed);
    let pinned = TIMER_PINNED.load(Relaxed);

    let curr_cpu = this_cpu();
    if pinned && curr_cpu != central_cpu() {
        scx_error!("Central timer ran on CPU %d, not central CPU %d", curr_cpu, central_cpu());
        return 0;
    }

    let cpus = CPUS.get();
    let first = Stat::Timers.get() as usize % cpus.len().max(1);

    // Start from a different CPU every time.
    for (cpu, state) in cpus.iter().enumerate().cycle().skip(first).take(cpus.len()) {
        let cpu = cpu as i32;
        if cpu == central_cpu() {
            continue;
        }

        // kick iff the current one exhausted its slice
        let started_at = state.started_at.load(Relaxed);
        if started_at != 0 && time_before(now, started_at + SLICE_NS.load(Relaxed)) {
            continue;
        }

        // and there's something pending
        if FALLBACK_DSQ.nr_queued() == 0 && Dsq::local_on(cpu).nr_queued() == 0 {
            match nr_to_kick.checked_sub(1) {
                Some(left) => nr_to_kick = left,
                None => continue,
            }
        }

        kick_cpu(cpu, SCX_KICK_PREEMPT);
    }

    let ret = Timer::from_ptr(timer).ok_or(EINVAL)
        .and_then(|t| t.start(TIMER_INTERVAL_NS, if pinned { BPF_F_TIMER_CPU_PIN } else { 0 }));
    if let Err(e) = ret {
        scx_error!("bpf_timer_start failed (%d)", -e.0);
    }
    Stat::Timers.inc();
    0
}

bpf_prog!("struct_ops.s/central_init",
fn central_init() -> Result {
    FALLBACK_DSQ.create(-1)
        .inspect_err(|e| scx_error!("scx_bpf_create_dsq failed (%d)", -e.0))?;

    let mut cpus = Vec::new();
    cpus.resize_with(nr_cpu_ids() as usize, CpuState::default);
    *unsafe { CPUS.get_mut() } = cpus;

    CENTRAL_Q.with_irqs_off(|q| q.reserve(CENTRAL_Q_MAX));

    timers().init(0, CLOCK_MONOTONIC, timerfn)?;

    kick_cpu(central_cpu(), 0);

    Ok(())
});

bpf_prog!("struct_ops/central_exit",
fn central_exit(_ei: *const ScxExitInfo) {
    timers().cancel_all();
});

// We are offloading all scheduling decisions to the central CPU and thus being
// the last task on a given CPU doesn't mean anything special. Enqueue the last
// tasks like any other tasks.
scx_ops_define!(central_ops, name: b"central", flags: SCX_OPS_ENQ_LAST, timeout_ms: 0,
    select_cpu: central_select_cpu,
    enqueue: central_enqueue,
    dispatch: central_dispatch,
    running: central_running,
    stopping: central_stopping,
    init: central_init,
    exit: central_exit,
);

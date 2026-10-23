// SPDX-License-Identifier: GPL-2.0
//
// scx_p2dq: a pick 2 load balancing scheduler. Every LLC has its own queues.
// A task moves between "dumb queues" with different time slices depending on
// how much of its slice it uses. An LLC that runs dry picks two other LLCs at
// random and takes work from the more loaded one.
//
// Rust port of the core of scheds/rust/scx_p2dq/src/bpf/main.bpf.c.
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// - struct enqueue_promise (kind + union) -> enum Promise, with data
// - flags words and their macros          -> the flags! types
// - llc_ctxs, cpu_ctxs (array maps)       -> Vec<Llc>, Vec<BpfCell<CpuCtx>>
// - scx_task_alloc() (arena)              -> TaskMap<TaskCtx>
// - scx_atq_t (arena task queue, rbtree)  -> SpinLock<BTreeMap<(vtime, pid), ()>>
// - kptr cpumasks, task_masks             -> CpuSet, iterator chains
// - p2dq_timers[] + switch in the callback -> a table with function pointers
// - the goto found_cpu of pick_idle_cpu() -> Found, `?`-free early returns
//
// User space provides the topology (cpu_llc_ids[] ...) and the time slices of
// the queues in C. Here ops.init() puts LLC_CPUS consecutive CPUs of a NUMA
// node in an "LLC" and derives the slices from MIN_SLICE_US and DSQ_SHIFT.
//
// Dropped: PELT (load is the run time per period, the !pelt_enabled case of C),
// energy aware and thermal placement, big.LITTLE, double helix queues, LLC
// shards, the idle CPU heap (cpu_priority), wakeup preemption, debug, UEI.

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::{max, min};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use scx_common::*;

const MAX_LLCS: u32 = 64;
const MAX_DSQS_PER_LLC: usize = 8;
const LOAD_BALANCE_SLACK: u64 = 20;
const P2DQ_MIG_DSQ: u64 = 1 << 60;
const PF_FORKNOEXEC: u32 = 0x40;

// ── Configuration (const volatile equivalents) ───────────────────────

tunables! { "p2dq",
    // topo_config
    SMT_ENABLED: AtomicBool = true;
    /// CPUs per LLC.
    LLC_CPUS: AtomicU32 = 4;

    // timeline_config
    MIN_SLICE_US: AtomicU64 = 100;
    MAX_EXEC_NS: AtomicU64 = 20 * NSEC_PER_MSEC;
    AUTOSLICE: AtomicBool = true;
    DEADLINE: AtomicBool = true;

    // lb_config
    BACKOFF_NS: AtomicU64 = 5 * NSEC_PER_MSEC;
    MIN_LLC_RUNS_PICK2: AtomicU64 = 4;
    MIN_NR_QUEUED_PICK2: AtomicU64 = 10;
    SLACK_FACTOR: AtomicU64 = LOAD_BALANCE_SLACK;
    DISPATCH_LB_INTERACTIVE: AtomicBool = false;
    DISPATCH_PICK2_DISABLE: AtomicBool = false;
    MAX_DSQ_PICK2: AtomicBool = false;
    WAKEUP_LLC_MIGRATIONS: AtomicBool = false;
    SINGLE_LLC_MODE: AtomicBool = false;

    // p2dq_config
    NR_DSQS_PER_LLC: AtomicU32 = 3;
    INIT_DSQ_INDEX: AtomicU32 = 0;
    DSQ_SHIFT: AtomicU64 = 2;
    INTERACTIVE_RATIO: AtomicU64 = 10;
    SATURATED_PERCENT: AtomicU32 = 5;
    ATQ_ENABLED: AtomicBool = false;
    TASK_SLICE: AtomicBool = true;
    FREQ_CONTROL: AtomicBool = false;
    INTERACTIVE_STICKY: AtomicBool = false;
    KEEP_RUNNING_ENABLED: AtomicBool = true;
    KTHREADS_LOCAL: AtomicBool = true;
    FORK_BALANCE: AtomicBool = true;
    EXEC_BALANCE: AtomicBool = true;
}

fn nr_dsqs_per_llc() -> usize { min(NR_DSQS_PER_LLC.load(Relaxed) as usize, MAX_DSQS_PER_LLC).max(1) }
fn single_llc_mode() -> bool { SINGLE_LLC_MODE.load(Relaxed) }
fn atq_enabled() -> bool { ATQ_ENABLED.load(Relaxed) }

const LB_TIMER_INTVL_NS: u64 = 250 * NSEC_PER_MSEC;

// ── Statistics ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Stat {
    AtqEnq,
    Direct,
    DsqSame,
    DsqChange,
    Idle,
    LlcMigration,
    NodeMigration,
    Keep,
    EnqCpu,
    EnqLlc,
    EnqMig,
    SelectPick2,
    DispatchPick2,
    WakePrev,
    WakeLlc,
    WakeMig,
    ForkBalance,
    ExecBalance,
    ForkSameLlc,
    ExecSameLlc,
    NrStats,
}

static STATS: [AtomicU64; Stat::NrStats as usize] =
    [const { AtomicU64::new(0) }; Stat::NrStats as usize];

impl Stat {
    fn inc(self) { STATS[self as usize].fetch_add(1, Relaxed); }
}

// ── Flags ────────────────────────────────────────────────────────────

/// A set of named bits, with the operations of the *_set_flag(), *_clear_flag()
/// and *_test_flag() macros of C.
macro_rules! flags {
    ($name:ident { $($flag:ident = $bit:expr,)* }) => {
        #[derive(Clone, Copy, Default, PartialEq, Eq)]
        struct $name(u32);

        #[allow(dead_code)]
        impl $name {
            $(const $flag: $name = $name(1 << $bit);)*

            fn contains(self, other: $name) -> bool { self.0 & other.0 == other.0 }
            fn insert(&mut self, other: $name) { self.0 |= other.0 }
            fn remove(&mut self, other: $name) { self.0 &= !other.0 }
            fn set(&mut self, other: $name, on: bool) {
                if on { self.insert(other) } else { self.remove(other) }
            }
        }
    };
}

flags!(CpuFlags {
    INTERACTIVE = 0,
    NICE_TASK = 2,
});

flags!(TaskFlags {
    INTERACTIVE = 0,
    WAS_NICE = 1,
    ALL_CPUS = 3,
    FORKNOEXEC = 4,
});

// ── Global state (all in arena) ──────────────────────────────────────

static NR_CPUS: AtomicU32 = AtomicU32::new(0);
static LLC_LB_OFFSET: AtomicU32 = AtomicU32::new(1);
static CUR_MIN_LLC_RUNS_PICK2: AtomicU64 = AtomicU64::new(1);
static SATURATED: AtomicBool = AtomicBool::new(false);
static OVERLOADED: AtomicBool = AtomicBool::new(false);
static MIN_SLICE_NS: AtomicU64 = AtomicU64::new(500);
static ALL_CPUS: CpuSet = CpuSet::new();

/// The time slice of each of the queues of an LLC.
static DSQ_TIME_SLICES: [AtomicU64; MAX_DSQS_PER_LLC] = [const { AtomicU64::new(0) }; MAX_DSQS_PER_LLC];

fn dsq_time_slice(dsq_index: usize) -> u64 {
    match DSQ_TIME_SLICES[..nr_dsqs_per_llc()].get(dsq_index) {
        Some(slice) => slice.load(Relaxed),
        None => {
            scx_error!("Invalid DSQ index");
            0
        }
    }
}

fn max_dsq_time_slice() -> u64 { dsq_time_slice(nr_dsqs_per_llc() - 1) }
fn min_dsq_time_slice() -> u64 { dsq_time_slice(0) }
fn clamp_slice(slice_ns: u64) -> u64 { min(max(min_dsq_time_slice(), slice_ns), max_dsq_time_slice()) }
fn task_slice_ns(p: Task, slice_ns: u64) -> u64 { clamp_slice(p.scale_by_weight(slice_ns)) }

/// The first slice changed: the others follow.
fn rescale_dsq_time_slices(first: u64) {
    let shift = DSQ_SHIFT.load(Relaxed);
    DSQ_TIME_SLICES[0].store(first, Relaxed);
    for (j, slice) in DSQ_TIME_SLICES[..nr_dsqs_per_llc()].iter().enumerate().skip(1) {
        slice.store(first << j << shift, Relaxed);
    }
}

fn saturated_or_overloaded() -> bool { SATURATED.load(Relaxed) || OVERLOADED.load(Relaxed) }

// ── LLCs ─────────────────────────────────────────────────────────────

struct Llc {
    id: u32,
    node_id: i32,
    cpus: CpuSet,
    dsq: Dsq,
    mig_dsq: Dsq,
    /// Tasks that may be taken by other LLCs, when ATQs are enabled: (vtime,
    /// pid) in order.
    mig_atq: SpinLock<BTreeMap<(u64, i32), ()>>,
    /// The LLC to send wakeups to, MAX_LLCS for none.
    lb_llc_id: AtomicU32,
    last_period_ns: AtomicU64,
    vtime: AtomicU64,
    load: AtomicU64,
    affn_load: AtomicU64,
    intr_load: AtomicU64,
    dsq_load: [AtomicU64; MAX_DSQS_PER_LLC],
    saturated: AtomicBool,
}

static LLCS: BpfCell<Vec<Llc>> = BpfCell::new(Vec::new());

fn llcs() -> &'static [Llc] { LLCS.get() }

fn lookup_llc(llc_id: u32) -> Option<&'static Llc> {
    let llc = llcs().get(llc_id as usize);
    if llc.is_none() {
        scx_error!("no llc_ctx for llc %u", llc_id);
    }
    llc
}

fn rand_llc() -> Option<&'static Llc> { llcs().get(random() as usize % llcs().len().max(1)) }

impl Llc {
    fn new(id: u32, node_id: i32) -> Self {
        Llc {
            id,
            node_id,
            cpus: CpuSet::new(),
            dsq: Dsq((id | MAX_LLCS) as u64),
            mig_dsq: Dsq(id as u64 | P2DQ_MIG_DSQ),
            mig_atq: SpinLock::new(BTreeMap::new()),
            lb_llc_id: AtomicU32::new(MAX_LLCS),
            last_period_ns: AtomicU64::new(0),
            vtime: AtomicU64::new(0),
            load: AtomicU64::new(0),
            affn_load: AtomicU64::new(0),
            intr_load: AtomicU64::new(0),
            dsq_load: [const { AtomicU64::new(0) }; MAX_DSQS_PER_LLC],
            saturated: AtomicBool::new(false),
        }
    }

    fn load(&self) -> u64 { self.load.load(Relaxed) }
    fn vtime(&self) -> u64 { self.vtime.load(Relaxed) }

    fn nr_queued(&self) -> u64 {
        let migratable = match llcs().len() {
            0 | 1 => 0,
            _ if atq_enabled() => self.mig_atq.lock().len() as u64,
            _ => self.mig_dsq.nr_queued(),
        };
        self.dsq.nr_queued() + migratable
    }

    /// The first task of the ATQ, taken out of it or not.
    fn atq_first(&self, pop: bool) -> Option<TaskRef> {
        let (_, pid) = {
            let mut atq = self.mig_atq.lock();
            if pop { atq.pop_first()?.0 } else { *atq.first_key_value()?.0 }
        };
        TaskRef::from_pid(pid)
    }

    /// An idle CPU of the LLC that @p, if given, can use.
    fn pick_idle(&self, p: Option<Task>, core: bool) -> Option<i32> {
        pick_idle_cpu_in(self.cpus.iter(), p, core)
    }
}

/// __pick_idle_cpu() of C, over something that yields CPUs instead of over a
/// cpumask of the kernel.
fn pick_idle_cpu_in(cpus: impl Iterator<Item = i32>, p: Option<Task>, core: bool) -> Option<i32> {
    let cores = core.then(ScxCpumask::idle_smt);
    cpus.filter(|&cpu| p.is_none_or(|p| p.cpus().test(cpu)))
        .filter(|&cpu| cores.as_ref().is_none_or(|cores| cores.test(cpu)))
        .find(|&cpu| test_and_clear_cpu_idle(cpu))
}

// ── Per-CPU context ──────────────────────────────────────────────────

struct CpuCtx {
    id: i32,
    llc_id: u32,
    node_id: i32,
    affn_dsq: Dsq,
    slice_ns: u64,
    dsq_index: usize,
    flags: CpuFlags,
    ran_for: u64,
}

static CPU_CTXS: BpfCell<Vec<BpfCell<CpuCtx>>> = BpfCell::new(Vec::new());

fn cpu_dsq_id(cpu: i32) -> Dsq { Dsq(((MAX_DSQS_PER_LLC as u64 * MAX_LLCS as u64) << 2) + cpu as u64) }

fn lookup_cpu_ctx(cpu: i32) -> Option<&'static mut CpuCtx> {
    let cpuc = usize::try_from(cpu).ok().and_then(|cpu| CPU_CTXS.get().get(cpu));
    if cpuc.is_none() {
        scx_error!("no cpu_ctx for cpu %d", cpu);
    }
    cpuc.map(|cpuc| unsafe { cpuc.get_mut() })
}

/// A CPU and its LLC.
fn lookup_cpu_llc(cpu: i32) -> Option<(&'static mut CpuCtx, &'static Llc)> {
    let cpuc = lookup_cpu_ctx(cpu)?;
    let llc = lookup_llc(cpuc.llc_id)?;
    Some((cpuc, llc))
}

// ── Per-task context ─────────────────────────────────────────────────

struct TaskCtx {
    /// The queue the task was put on last, None before the first time.
    dsq_id: Option<Dsq>,
    slice_ns: u64,
    dsq_index: usize,
    llc_id: u32,
    node_id: i32,
    last_run_started: u64,
    last_run_at: u64,
    /// how many runs on the current LLC
    llc_runs: u64,
    enq_flags: u64,
    flags: TaskFlags,
    /// Target LLC for initial placement
    target_llc_hint: Option<u32>,
}

static TASK_CTXS: TaskMap<TaskCtx> = TaskMap::new();

fn lookup_task_ctx(p: Task) -> Option<&'static mut TaskCtx> {
    let taskc = TASK_CTXS.get(p);
    if taskc.is_none() {
        scx_error!("task_ctx lookup failed for pid %d", p.pid());
    }
    taskc
}

fn task_all_cpus(p: Task) -> bool { p.nr_cpus_allowed() as u32 == NR_CPUS.load(Relaxed) }

impl TaskCtx {
    fn all_cpus(&self) -> bool { self.flags.contains(TaskFlags::ALL_CPUS) }
    fn interactive(&self) -> bool { self.flags.contains(TaskFlags::INTERACTIVE) }

    /// Is the task in the queue with the shortest slice?
    fn is_interactive(&self) -> bool { nr_dsqs_per_llc() > 1 && self.dsq_index == 0 }

    fn refresh_llc_runs(&mut self) { self.llc_runs = CUR_MIN_LLC_RUNS_PICK2.load(Relaxed); }

    /// Returns if the task can migrate to another LLC.
    fn can_migrate(&self, llc: &Llc) -> bool {
        if single_llc_mode() || llcs().len() < 2 || !self.all_cpus() ||
           (!DISPATCH_LB_INTERACTIVE.load(Relaxed) && self.interactive()) {
            return false;
        }
        if MAX_DSQ_PICK2.load(Relaxed) && self.dsq_index != nr_dsqs_per_llc() - 1 {
            return false;
        }
        if self.llc_runs > 0 {
            return false;
        }
        saturated_or_overloaded() || llc.saturated.load(Relaxed)
    }

    /// Scale the slice by how many tasks wait per idle CPU.
    fn set_deadline_slice(&mut self, p: Task, llc: &Llc) {
        let max_ns = p.scale_by_weight(max_dsq_time_slice());
        let nr_queued = llc.nr_queued();
        let nr_idle = max(ScxCpumask::idle().weight() as u64, 1);

        self.slice_ns = clamp_slice(if nr_queued > nr_idle { max_ns * nr_idle / nr_queued } else { max_ns });
    }

    /// Updates a tasks vtime based on the newly assigned cpu_ctx and returns
    /// the updated vtime.
    fn update_vtime(&self, p: Task, cpuc: &CpuCtx, llc: &Llc) {
        // If in the same LLC we only need to clamp the vtime to ensure no task
        // accumulates too much.
        if self.llc_id != cpuc.llc_id {
            p.set_dsq_vtime(llc.vtime());
            return;
        }
        if p.dsq_vtime() >= llc.vtime() {
            return;
        }
        let vtime_floor = llc.vtime().saturating_sub(p.scale_by_weight(max_dsq_time_slice()));
        if p.dsq_vtime() < vtime_floor {
            p.set_dsq_vtime(vtime_floor);
        }
    }
}

/// Returns if a task should keep running on its CPU for another slice.
fn keep_running(cpuc: &mut CpuCtx, llc: &Llc, p: Task) -> bool {
    // Only tasks in the most interactive DSQs can keep running.
    if !KEEP_RUNNING_ENABLED.load(Relaxed) || cpuc.dsq_index == nr_dsqs_per_llc() - 1 ||
       p.is_queued() || cpuc.ran_for >= MAX_EXEC_NS.load(Relaxed) {
        return false;
    }
    if llc.nr_queued() >= llc.cpus.weight() as u64 {
        return false;
    }

    let slice_ns = task_slice_ns(p, cpuc.slice_ns);
    cpuc.ran_for += slice_ns;
    p.set_slice(slice_ns);
    Stat::Keep.inc();
    true
}

// ── Idle CPU selection ───────────────────────────────────────────────

/// A CPU for a task, and whether it was idle and has been claimed.
#[derive(Clone, Copy)]
struct Found {
    cpu: i32,
    is_idle: bool,
}

impl Found {
    fn idle(cpu: i32) -> Self { Found { cpu, is_idle: true } }
    fn busy(cpu: i32) -> Self { Found { cpu, is_idle: false } }
}

fn pick_idle_affinitized_cpu(p: Task, taskc: &TaskCtx, prev_cpu: i32) -> Found {
    // Migration-disabled tasks must stay on their current CPU.
    if p.is_migration_disabled() {
        return Found::busy(prev_cpu);
    }
    let Some(llc) = lookup_llc(taskc.llc_id) else { return Found::busy(prev_cpu) };

    // First try last CPU
    if p.cpus().test(prev_cpu) && test_and_clear_cpu_idle(prev_cpu) {
        return Found::idle(prev_cpu);
    }

    // Then an idle core in the LLC, any idle CPU there, one on the node.
    let on_node = || ALL_CPUS.iter().filter(|&cpu| cpu_node(cpu) == llc.node_id);

    SMT_ENABLED.load(Relaxed).then(|| llc.pick_idle(Some(p), true)).flatten()
        .or_else(|| llc.pick_idle(Some(p), false))
        .or_else(|| pick_idle_cpu_in(on_node(), Some(p), false))
        .map_or_else(|| Found::busy(p.cpus().any_distribute()), Found::idle)
}

/// Where a forked or exec'ing task should go: the parent's LLC or another one
/// that is picked at random, whichever has less load.
fn find_least_loaded_llc_for_fork(parent_llc_id: u32) -> u32 {
    let Some(parent) = lookup_llc(parent_llc_id) else { return parent_llc_id };

    let candidate = match llcs() {
        [a, b] => Some(if parent.id == a.id { b } else { a }),
        _ => rand_llc(),
    };

    candidate.filter(|llc| llc.load() <= parent.load()).map_or(parent_llc_id, |llc| llc.id)
}

/// The sync wakeup part of pick_idle_cpu().
fn pick_idle_cpu_sync(taskc: &TaskCtx, llc: &Llc, prev_cpu: i32) -> Found {
    let smt = SMT_ENABLED.load(Relaxed);
    let in_llc = |llc: &Llc, stat: Stat| {
        let cpu = smt.then(|| llc.pick_idle(None, true)).flatten().or_else(|| llc.pick_idle(None, false));
        cpu.inspect(|_| stat.inc()).map(Found::idle)
    };
    let prev = || {
        Stat::WakePrev.inc();
        Found::busy(prev_cpu)
    };

    // Interactive tasks aren't worth migrating across LLCs.
    if taskc.interactive() || (llcs().len() == 2 && nr_node_ids() == 2) {
        return llc.pick_idle(None, false).inspect(|_| Stat::WakeLlc.inc())
            .map_or_else(prev, Found::idle);
    }

    let waker = Task::current();
    let Some(waker_taskc) = TASK_CTXS.get(waker) else { return prev() };

    // Keep the task in its LLC if the waker is there too, or if wakeups are
    // not supposed to migrate.
    if waker_taskc.llc_id == llc.id || !WAKEUP_LLC_MIGRATIONS.load(Relaxed) {
        return in_llc(llc, Stat::WakeLlc).unwrap_or_else(prev);
    }

    // If wakeup LLC migrations are allowed then migrate to the waker's LLC.
    let Some(waker_llc) = lookup_llc(waker_taskc.llc_id) else { return prev() };
    in_llc(waker_llc, Stat::WakeMig).unwrap_or_else(|| {
        // Couldn't find an idle CPU, so use the CPU of the waker.
        Stat::WakeMig.inc();
        Found::busy(waker.cpu())
    })
}

fn pick_idle_cpu(p: Task, taskc: &TaskCtx, prev_cpu: i32, wake_flags: u64) -> Found {
    {
        let idle_cpumask = ScxCpumask::idle();

        // Fast path: the last CPU is idle.
        if idle_cpumask.test(prev_cpu) && test_and_clear_cpu_idle(prev_cpu) {
            return Found::idle(prev_cpu);
        }
        if INTERACTIVE_STICKY.load(Relaxed) && taskc.interactive() {
            return Found::busy(prev_cpu);
        }
        // Nothing idle anywhere.
        if idle_cpumask.is_empty() {
            return Found::busy(prev_cpu);
        }
    }

    let Some(mut llc) = lookup_llc(taskc.llc_id) else { return Found::busy(prev_cpu) };

    let migratable = taskc.can_migrate(llc);
    if llcs().len() > 1 && (llc.saturated.load(Relaxed) || saturated_or_overloaded()) && !migratable {
        return Found::busy(prev_cpu);
    }

    // A task that has not been queued yet starts in a random LLC.
    if taskc.dsq_id.is_none() {
        match rand_llc() {
            Some(random) => llc = random,
            None => return Found::busy(prev_cpu),
        }
    }

    if wake_flags & SCX_WAKE_SYNC != 0 {
        return pick_idle_cpu_sync(taskc, llc, prev_cpu);
    }

    // The load balancer wants this LLC to shed load.
    if taskc.llc_runs == 0 {
        if let Some(target) = llcs().get(llc.lb_llc_id.swap(MAX_LLCS, Relaxed) as usize) {
            llc = target;
            Stat::SelectPick2.inc();
        }
    }

    // Next try in the local LLC: an idle core, then any idle CPU.
    if let Some(cpu) = llc.pick_idle(None, true).or_else(|| llc.pick_idle(None, false)) {
        return Found::idle(cpu);
    }

    // Then the node, then the whole machine.
    if llcs().len() > 1 && llc.saturated.load(Relaxed) && migratable {
        let node_id = llc.node_id;
        let on_node = || ALL_CPUS.iter().filter(move |&cpu| cpu_node(cpu) == node_id);
        let anywhere = SATURATED.load(Relaxed);

        let cpu = pick_idle_cpu_in(on_node(), None, true)
            .or_else(|| pick_idle_cpu_in(on_node(), None, false))
            .or_else(|| anywhere.then(|| pick_idle_cpu_in(ALL_CPUS.iter(), None, true)).flatten())
            .or_else(|| anywhere.then(|| pick_idle_cpu_in(ALL_CPUS.iter(), None, false)).flatten());
        if let Some(cpu) = cpu {
            return Found::idle(cpu);
        }
    }

    // Couldn't find anything idle just return something in the local LLC.
    Found::busy(prev_cpu)
}

bpf_prog!("struct_ops/p2dq_select_cpu",
fn p2dq_select_cpu(p: Task, prev_cpu: i32, wake_flags: u64) -> i32 {
    let Some(taskc) = lookup_task_ctx(p) else { return prev_cpu };

    let found = if taskc.all_cpus() {
        pick_idle_cpu(p, taskc, prev_cpu, wake_flags)
    } else {
        pick_idle_affinitized_cpu(p, taskc, prev_cpu)
    };

    if found.is_idle {
        Stat::Idle.inc();
        // Only direct dispatch non-affinitized tasks, the others go through
        // the DSQ of the CPU in ops.enqueue().
        if taskc.all_cpus() {
            p.dsq_insert(SCX_DSQ_LOCAL, taskc.slice_ns, 0);
        }
    }

    found.cpu
});

// ── Enqueue ──────────────────────────────────────────────────────────

/// What remains to be done to enqueue a task. Deciding and doing are separate
/// so that another scheduler (scx_chaos) can sit in between.
enum Promise {
    Complete,
    Fifo { dsq: Dsq, slice_ns: u64, enq_flags: u64 },
    Vtime { dsq: Dsq, slice_ns: u64, vtime: u64, enq_flags: u64 },
    AtqVtime { llc: &'static Llc, vtime: u64 },
    Failed,
}

struct Enqueue {
    promise: Promise,
    /// The idle CPU to wake up afterwards.
    kick_idle: Option<i32>,
}

impl From<Promise> for Enqueue {
    fn from(promise: Promise) -> Self { Enqueue { promise, kick_idle: None } }
}

/// Pick the LLC for a task that has just forked or exec'ed.
fn balance_fork_exec(p: Task, taskc: &mut TaskCtx, cpu: i32) {
    let is_fork = p.flags() & PF_FORKNOEXEC != 0;
    let was_fork = taskc.flags.contains(TaskFlags::FORKNOEXEC);
    taskc.flags.set(TaskFlags::FORKNOEXEC, is_fork);

    if single_llc_mode() || !taskc.all_cpus() {
        return;
    }

    // The flag went away: the task has called exec. It is set and the task has
    // not run here yet: the task is new.
    let (moved, stayed) = if was_fork && !is_fork && EXEC_BALANCE.load(Relaxed) {
        (Stat::ExecBalance, Stat::ExecSameLlc)
    } else if is_fork && taskc.llc_runs == 0 && FORK_BALANCE.load(Relaxed) {
        (Stat::ForkBalance, Stat::ForkSameLlc)
    } else {
        return;
    };

    let Some(cpuc) = lookup_cpu_ctx(cpu) else { return };
    match find_least_loaded_llc_for_fork(cpuc.llc_id) {
        target if target != cpuc.llc_id => {
            taskc.target_llc_hint = Some(target);
            moved.inc();
        }
        _ => stayed.inc(),
    }
}

/// The queue of the LLC, or the one that other LLCs take tasks from.
fn queue_in_llc(p: Task, taskc: &mut TaskCtx, llc: &'static Llc, enq_flags: u64) -> Promise {
    let vtime = p.dsq_vtime();

    if taskc.can_migrate(llc) {
        taskc.dsq_id = Some(llc.mig_dsq);
        Stat::EnqMig.inc();
        if atq_enabled() {
            taskc.enq_flags = enq_flags;
            return Promise::AtqVtime { llc, vtime };
        }
    } else {
        taskc.dsq_id = Some(llc.dsq);
        Stat::EnqLlc.inc();
    }

    Promise::Vtime { dsq: taskc.dsq_id.unwrap_or(llc.dsq), slice_ns: taskc.slice_ns, vtime, enq_flags }
}

/// Tasks that cannot run everywhere wait in the DSQ of a CPU.
fn enqueue_affinitized(p: Task, taskc: &mut TaskCtx, cpu: i32, mut enq_flags: u64) -> Option<Enqueue> {
    let found = if enq_flags & SCX_ENQ_CPU_SELECTED == 0 || !p.cpus().test(cpu) {
        pick_idle_affinitized_cpu(p, taskc, cpu)
    } else {
        Found { cpu, is_idle: test_and_clear_cpu_idle(cpu) }
    };

    Stat::EnqCpu.inc();

    // The CPU may have dropped out of the cpumask in the meantime.
    let target_cpu = Some(found.cpu).filter(|&cpu| p.cpus().test(cpu))
        .or_else(|| Some(p.cpu()).filter(|&cpu| p.cpus().test(cpu)))
        .unwrap_or_else(|| p.cpus().any_distribute());
    let (cpuc, llc) = lookup_cpu_llc(target_cpu)?;

    taskc.dsq_id = Some(cpuc.affn_dsq);
    taskc.update_vtime(p, cpuc, llc);
    if DEADLINE.load(Relaxed) {
        taskc.set_deadline_slice(p, llc);
    }

    // Pinned tasks share one CPU: shorter slices when several are waiting.
    if p.nr_cpus_allowed() == 1 {
        taskc.slice_ns = clamp_slice(taskc.slice_ns / (cpuc.affn_dsq.nr_queued() + 1));
    }

    if cpuc.flags.contains(CpuFlags::NICE_TASK) {
        enq_flags |= SCX_ENQ_PREEMPT;
    }

    Some(Enqueue {
        promise: Promise::Vtime {
            dsq: cpuc.affn_dsq,
            slice_ns: taskc.slice_ns,
            vtime: p.dsq_vtime(),
            enq_flags,
        },
        kick_idle: found.is_idle.then_some(target_cpu),
    })
}

fn async_p2dq_enqueue(p: Task, mut enq_flags: u64) -> Option<Enqueue> {
    let task_cpu = p.cpu();

    // Per CPU kthreads are considered interactive and dispatched directly into
    // the local DSQ.
    if KTHREADS_LOCAL.load(Relaxed) && p.is_kthread() && p.nr_cpus_allowed() == 1 {
        Stat::Direct.inc();
        p.dsq_insert(SCX_DSQ_LOCAL, min_dsq_time_slice(), enq_flags);
        if test_and_clear_cpu_idle(task_cpu) {
            kick_cpu(task_cpu, SCX_KICK_IDLE);
        }
        return Some(Promise::Complete.into());
    }

    let taskc = lookup_task_ctx(p)?;

    balance_fork_exec(p, taskc, task_cpu);

    // Handle the placement hint of fork and exec balancing.
    if let Some(target_llc) = taskc.target_llc_hint.take().filter(|_| llcs().len() > 1).and_then(lookup_llc) {
        if let Some(target_cpu) = target_llc.pick_idle(Some(p), false) {
            let cpuc = lookup_cpu_ctx(target_cpu)?;
            taskc.llc_id = target_llc.id;
            taskc.llc_runs = 0;
            taskc.update_vtime(p, cpuc, target_llc);
            return Some(Promise::Fifo {
                dsq: Dsq::local_on(target_cpu),
                slice_ns: taskc.slice_ns,
                enq_flags,
            }.into());
        }
    }

    if !taskc.all_cpus() || !task_all_cpus(p) {
        return enqueue_affinitized(p, taskc, task_cpu, enq_flags);
    }

    // If an idle CPU hasn't been found in select_cpu find one now.
    let selected = enq_flags & SCX_ENQ_CPU_SELECTED != 0;
    let found = if selected {
        Found { cpu: task_cpu, is_idle: test_and_clear_cpu_idle(task_cpu) }
    } else {
        pick_idle_cpu(p, taskc, task_cpu, 0)
    };

    let (cpuc, llc) = lookup_cpu_llc(found.cpu)?;

    taskc.update_vtime(p, cpuc, llc);
    if DEADLINE.load(Relaxed) {
        taskc.set_deadline_slice(p, llc);
    }

    let nice = cpuc.flags.contains(CpuFlags::NICE_TASK);
    if nice {
        enq_flags |= SCX_ENQ_PREEMPT;
    }

    // Idle CPU, or one that runs a nice task: go there directly.
    if (found.is_idle || nice) && p.cpus().test(found.cpu) {
        let remote = found.cpu != task_cpu && !p.is_migration_disabled();
        return Some(Enqueue {
            promise: Promise::Fifo {
                dsq: if remote { Dsq::local_on(found.cpu) } else { Dsq(SCX_DSQ_LOCAL) },
                slice_ns: taskc.slice_ns,
                enq_flags,
            },
            kick_idle: found.is_idle.then_some(found.cpu),
        });
    }

    Some(queue_in_llc(p, taskc, llc, enq_flags).into())
}

fn complete_p2dq_enqueue(enq: Enqueue, p: Task) {
    match enq.promise {
        Promise::Complete => {}
        Promise::Fifo { dsq, slice_ns, enq_flags } => p.dsq_insert(dsq.0, slice_ns, enq_flags),
        Promise::Vtime { dsq, slice_ns, vtime, enq_flags } => {
            p.dsq_insert_vtime(dsq.0, slice_ns, vtime, enq_flags)
        }
        Promise::AtqVtime { llc, vtime } => {
            llc.mig_atq.lock().insert((vtime, p.pid()), ());
            Stat::AtqEnq.inc();
        }
        Promise::Failed => scx_error!("p2dq enqueue failed"),
    }

    if let Some(cpu) = enq.kick_idle {
        Stat::Idle.inc();
        kick_cpu(cpu, SCX_KICK_IDLE);
    }
}

bpf_prog!("struct_ops/p2dq_enqueue",
fn p2dq_enqueue(p: Task, enq_flags: u64) {
    let enq = async_p2dq_enqueue(p, enq_flags).unwrap_or(Promise::Failed.into());
    complete_p2dq_enqueue(enq, p);
});

bpf_prog!("struct_ops/p2dq_dequeue",
fn p2dq_dequeue(p: Task, _deq_flags: u64) {
    if !atq_enabled() {
        return;
    }
    // The task may be in the ATQ of the LLC it was queued in.
    if let Some(llc) = TASK_CTXS.get(p).and_then(|taskc| llcs().get(taskc.llc_id as usize)) {
        let pid = p.pid();
        llc.mig_atq.lock().retain(|&(_, queued), _| queued != pid);
    }
});

// ── Task state tracking ──────────────────────────────────────────────

bpf_prog!("struct_ops/p2dq_running",
fn p2dq_running(p: Task) {
    let task_cpu = p.cpu();
    let Some(taskc) = lookup_task_ctx(p) else { return };
    let Some((cpuc, llc)) = lookup_cpu_llc(task_cpu) else { return };

    if taskc.llc_id != cpuc.llc_id {
        taskc.refresh_llc_runs();
        Stat::LlcMigration.inc();
    } else {
        match taskc.llc_runs.checked_sub(1) {
            Some(runs) => taskc.llc_runs = runs,
            None => taskc.refresh_llc_runs(),
        }
    }
    if taskc.node_id != cpuc.node_id {
        Stat::NodeMigration.inc();
    }

    taskc.llc_id = llc.id;
    taskc.node_id = llc.node_id;

    let nice = p.weight() < 100;
    taskc.flags.set(TaskFlags::WAS_NICE, nice);
    cpuc.flags.set(CpuFlags::NICE_TASK, nice);
    cpuc.flags.set(CpuFlags::INTERACTIVE, taskc.interactive());

    cpuc.dsq_index = taskc.dsq_index;
    cpuc.slice_ns = taskc.slice_ns;
    cpuc.ran_for = 0;

    // racy, but don't care
    let (vtime, llc_vtime) = (p.dsq_vtime(), llc.vtime());
    if vtime > llc_vtime && vtime < llc_vtime + max_dsq_time_slice() {
        let _ = llc.vtime.compare_exchange(llc_vtime, vtime, Relaxed, Relaxed);
    }

    // If the task is running in the least interactive DSQ, bump the frequency.
    if FREQ_CONTROL.load(Relaxed) && taskc.dsq_index == nr_dsqs_per_llc() - 1 {
        cpuperf_set(task_cpu, SCX_CPUPERF_ONE);
    }

    let now = now();
    if taskc.last_run_started == 0 {
        taskc.last_run_started = now;
    }
    taskc.last_run_at = now;
});

/// The task went to sleep after running for @used ns in all: does it belong in
/// a queue with a longer or with a shorter slice?
fn adjust_dsq_index(p: Task, taskc: &mut TaskCtx, used: u64, slice_ns: u64) {
    // Affinitized tasks are moved less eagerly.
    let (inc_threshold, dec_threshold) = if taskc.all_cpus() {
        (9 * slice_ns / 10, slice_ns / 2)
    } else {
        (19 * slice_ns / 20, slice_ns / 4)
    };

    let index = taskc.dsq_index;
    if used >= inc_threshold && index < nr_dsqs_per_llc() - 1 && p.weight() >= 100 {
        taskc.dsq_index += 1;
    } else if used < dec_threshold && index > 0 {
        taskc.dsq_index -= 1;
    }
    if taskc.dsq_index == index { Stat::DsqSame.inc() } else { Stat::DsqChange.inc() }

    // nice tasks can't get into the longest queues
    if p.weight() < 100 {
        taskc.dsq_index = min(taskc.dsq_index, 1);
    }

    taskc.slice_ns = if !TASK_SLICE.load(Relaxed) {
        task_slice_ns(p, dsq_time_slice(taskc.dsq_index))
    } else if used >= 7 * slice_ns / 8 {
        clamp_slice(5 * taskc.slice_ns >> 2)
    } else if used < slice_ns / 2 {
        clamp_slice(7 * taskc.slice_ns >> 3)
    } else {
        taskc.slice_ns
    };
}

bpf_prog!("struct_ops/p2dq_stopping",
fn p2dq_stopping(p: Task, runnable: bool) {
    let now = now();
    let Some(taskc) = lookup_task_ctx(p) else { return };
    let Some(llc) = lookup_llc(taskc.llc_id) else { return };

    // can't happen, appease the bounds check
    let Some(dsq_load) = llc.dsq_load[..nr_dsqs_per_llc()].get(taskc.dsq_index) else {
        scx_error!("taskc invalid dsq index");
        return;
    };

    if taskc.flags.contains(TaskFlags::WAS_NICE) {
        if let Some(cpuc) = lookup_cpu_ctx(p.cpu()) {
            cpuc.flags.remove(CpuFlags::NICE_TASK);
            taskc.flags.remove(TaskFlags::WAS_NICE);
        }
    }

    let last_dsq_slice_ns = taskc.slice_ns;
    let used = now - taskc.last_run_at;

    p.set_dsq_vtime(p.dsq_vtime() + p.scale_by_weight_inverse(used));
    llc.vtime.fetch_add(used, Relaxed);

    let accounts = [
        Some(&llc.load),
        Some(dsq_load),
        taskc.interactive().then_some(&llc.intr_load),
        (!taskc.all_cpus()).then_some(&llc.affn_load),
    ];
    accounts.into_iter().flatten().for_each(|load| { load.fetch_add(used, Relaxed); });

    // On stopping determine if the task can move to a longer DSQ by comparing
    // the used time to the scaled DSQ slice.
    if !runnable {
        adjust_dsq_index(p, taskc, now - taskc.last_run_started, last_dsq_slice_ns);
        taskc.last_run_started = 0;
        let interactive = taskc.is_interactive();
        taskc.flags.set(TaskFlags::INTERACTIVE, interactive);
    }
});

// ── Dispatch ─────────────────────────────────────────────────────────

/// Put the first task of the ATQ of @from on the DSQ of the LLC of this CPU and
/// run it.
fn consume_atq(from: &Llc, llc_dsq: Dsq) -> bool {
    let Some(p) = from.atq_first(true) else { return false };
    let Some(taskc) = lookup_task_ctx(*p) else { return false };

    p.dsq_insert_vtime(llc_dsq.0, taskc.slice_ns, p.dsq_vtime(), taskc.enq_flags);
    drop(p);
    llc_dsq.move_to_local()
}

/// Take a task from another LLC.
fn consume_llc(from: &Llc, cur: &Llc) -> bool {
    if atq_enabled() && !from.mig_atq.lock().is_empty() {
        return consume_atq(from, cur.dsq);
    }
    if from.mig_dsq.move_to_local() {
        Stat::DispatchPick2.inc();
        return true;
    }
    false
}

fn dispatch_pick_two(cur: &Llc) -> Option<()> {
    let nr_llcs = llcs().len();

    // Single LLC mode, or nothing to pick from.
    if single_llc_mode() || nr_llcs < 2 || DISPATCH_PICK2_DISABLE.load(Relaxed) {
        return None;
    }
    if cur.nr_queued() < MIN_NR_QUEUED_PICK2.load(Relaxed) {
        return None;
    }
    if scx_now() - cur.last_period_ns.load(Relaxed) < BACKOFF_NS.load(Relaxed) {
        return None;
    }

    // For pick two load balancing we randomly choose two LLCs. We then first
    // try to consume from the LLC with the largest load. If we are unable to
    // consume from the first LLC then the second LLC is consumed from. This
    // yields better work conservation on machines with a large number of LLCs.
    let (left, mut right) = match llcs() {
        [a, b] => (a, b),
        _ => (rand_llc()?, rand_llc()?),
    };
    // The same one twice: derive another one from the load.
    if left.id == right.id {
        right = llcs().get(cur.load() as usize % nr_llcs)?;
    }

    let (mut first, mut second) = if right.load() > left.load() { (right, left) } else { (left, right) };

    // Handle the edge case where there are two LLCs and the current has more
    // load. Since it's already been checked start with the other LLC.
    if nr_llcs == 2 && first.id == cur.id {
        (first, second) = (second, cur);
    }

    let cur_load = cur.load() + cur.load() * SLACK_FACTOR.load(Relaxed) / 100;
    let picks = [first, second];

    if picks.iter().any(|llc| llc.load() >= cur_load && consume_llc(llc, cur)) {
        return Some(());
    }

    // If the system is saturated then be aggressive in trying to load balance.
    if SATURATED.load(Relaxed) {
        let third = (nr_llcs > 2).then(rand_llc).flatten();
        if picks.iter().copied().chain(third).any(|llc| consume_llc(llc, cur)) {
            return Some(());
        }
    }

    None
}

/// Tasks in the DSQ of @cpuc whose cpumask has changed since they were queued
/// cannot run here any more. Send them where they can.
fn clean_affn_dsq(cpuc: &CpuCtx) {
    let mut state = DsqIterState::new();
    let mut queue = state.iter(cpuc.affn_dsq, 0);

    while let Some(p) = queue.next() {
        if p.cpus().test(cpuc.id) {
            break;
        }
        if let Some(target) = lookup_cpu_ctx(p.cpus().any_distribute()) {
            queue.move_vtime_to(p, target.affn_dsq, 0);
        }
    }
}

/// Something that ops.dispatch() can take a task from.
#[derive(Clone, Copy)]
enum Source {
    Dsq(Dsq),
    Atq,
}

bpf_prog!("struct_ops/p2dq_dispatch",
fn p2dq_dispatch(cpu: i32, prev: Option<Task>) {
    let Some((cpuc, llc)) = lookup_cpu_llc(cpu) else { return };
    let many_llcs = llcs().len() > 1;

    // The vtime of the first task of a DSQ, if it can run here.
    let head = |dsq: Dsq| {
        dsq.peek().filter(|p| p.cpus().test(cpu)).map(|p| (p.dsq_vtime(), Source::Dsq(dsq)))
    };

    if cpuc.affn_dsq.peek().is_some_and(|p| !p.cpus().test(cpu)) {
        clean_affn_dsq(cpuc);
    }

    // Find the task with the lowest vtime: in the DSQ of this CPU, in those of
    // the other CPUs of the LLC, in the DSQ of the LLC and in its migration
    // queue.
    let min = {
        let _rcu = rcu_read_lock();

        let atq_head = || {
            let p = llc.atq_first(false)?;
            p.cpus().test(cpu).then(|| (p.dsq_vtime(), Source::Atq))
        };
        let migration = match (many_llcs, atq_enabled()) {
            (false, _) => None,
            (true, true) => atq_head(),
            (true, false) => head(llc.mig_dsq),
        };

        head(cpuc.affn_dsq).into_iter()
            .chain(llc.cpus.iter().filter(|&other| other != cpu).filter_map(|other| head(cpu_dsq_id(other))))
            .chain(head(llc.dsq))
            .chain(migration)
            .reduce(|min, next| if time_before(next.0, min.0) { next } else { min })
    };

    let tried = match min {
        Some((_, Source::Atq)) => {
            if consume_atq(llc, llc.dsq) {
                return;
            }
            None
        }
        Some((_, Source::Dsq(dsq))) => {
            if dsq.move_to_local() {
                return;
            }
            Some(dsq)
        }
        None => None,
    };

    // Lost a race for that task. Try the queues of the LLC.
    if tried != Some(llc.dsq) && llc.dsq.move_to_local() {
        return;
    }
    if atq_enabled() {
        if consume_atq(llc, llc.dsq) {
            return;
        }
    } else if tried != Some(llc.mig_dsq) && llc.mig_dsq.move_to_local() {
        return;
    }

    if prev.is_some_and(|prev| keep_running(cpuc, llc, prev)) {
        return;
    }

    dispatch_pick_two(llc);
});

bpf_prog!("struct_ops/p2dq_set_cpumask",
fn p2dq_set_cpumask(p: Task, _cpumask: Cpumask) {
    let Some(taskc) = lookup_task_ctx(p) else { return };

    let was_all_cpus = taskc.all_cpus();
    taskc.flags.set(TaskFlags::ALL_CPUS, task_all_cpus(p));

    // A task that has become affinitized must not stay bound for a migration
    // queue: another LLC may not be able to run it.
    if was_all_cpus && !taskc.all_cpus() && taskc.dsq_id.is_some_and(|dsq| dsq.0 & P2DQ_MIG_DSQ != 0) {
        if let Some((_, llc)) = lookup_cpu_llc(p.cpu()) {
            taskc.dsq_id = Some(llc.dsq);
            taskc.refresh_llc_runs();
        }
    }
});

bpf_prog!("struct_ops/p2dq_update_idle",
fn p2dq_update_idle(cpu: i32, idle: bool) {
    let idle_cpumask = ScxCpumask::idle();
    let percent_idle = 100 * idle_cpumask.weight() / NR_CPUS.load(Relaxed).max(1);

    let saturated = percent_idle < SATURATED_PERCENT.load(Relaxed);
    SATURATED.store(saturated, Relaxed);

    // The busier the system, the sooner tasks may migrate.
    let log2 = |v: u32| v.checked_ilog2().unwrap_or(0) as u64;
    let runs = if saturated { 2 } else { log2(percent_idle) + log2(llcs().len() as u32) };
    CUR_MIN_LLC_RUNS_PICK2.store(min(runs, MIN_LLC_RUNS_PICK2.load(Relaxed)), Relaxed);

    let Some((_, llc)) = lookup_cpu_llc(cpu) else { return };

    if percent_idle == 0 {
        OVERLOADED.store(true, Relaxed);
    }

    if idle {
        llc.saturated.store(false, Relaxed);
        OVERLOADED.store(false, Relaxed);
    } else if !llc.cpus.intersects(*idle_cpumask) {
        llc.saturated.store(true, Relaxed);
    }
});

bpf_prog!("struct_ops/p2dq_init_task",
fn p2dq_init_task(p: Task, _args: InitTaskArgs) -> Result {
    let (cpuc, llc) = lookup_cpu_llc(p.cpu()).ok_or(EINVAL)?;
    let init_dsq_index = INIT_DSQ_INDEX.load(Relaxed) as usize;

    let mut taskc = TaskCtx {
        dsq_id: None,
        slice_ns: p.scale_by_weight(dsq_time_slice(init_dsq_index)),
        // Adjust starting index based on niceness
        dsq_index: match p.weight() {
            100 => init_dsq_index,
            ..100 => 0,
            _ => nr_dsqs_per_llc() - 1,
        },
        llc_id: cpuc.llc_id,
        node_id: cpuc.node_id,
        last_run_started: 0,
        last_run_at: 0,
        llc_runs: 0,
        enq_flags: 0,
        flags: TaskFlags::default(),
        target_llc_hint: None,
    };

    taskc.flags.set(TaskFlags::ALL_CPUS, task_all_cpus(p));
    taskc.flags.set(TaskFlags::FORKNOEXEC, p.flags() & PF_FORKNOEXEC != 0);
    let interactive = taskc.is_interactive();
    taskc.flags.set(TaskFlags::INTERACTIVE, interactive);
    taskc.refresh_llc_runs();
    if !taskc.all_cpus() {
        taskc.dsq_id = Some(llc.dsq);
    }

    p.set_dsq_vtime(llc.vtime());
    TASK_CTXS.insert(p, taskc);
    Ok(())
});

bpf_prog!("struct_ops/p2dq_exit_task",
fn p2dq_exit_task(p: Task, _args: *const u8) {
    TASK_CTXS.remove(p);
});

// ── Timers ───────────────────────────────────────────────────────────

/// Compare the load of every LLC with that of another one, a different one in
/// every period, tell the more loaded one to send wakeups over, and adapt the
/// time slices to the share of interactive load.
fn load_balance_timer() -> bool {
    let llcs = llcs();
    let offset = LLC_LB_OFFSET.load(Relaxed) as usize;
    let slack = match SLACK_FACTOR.load(Relaxed) {
        0 => LOAD_BALANCE_SLACK,
        slack => slack,
    };

    for (llc, lb_llc) in llcs.iter().zip(llcs.iter().cycle().skip(offset)) {
        let (load, lb_load) = (llc.load(), lb_llc.load());
        let imbalance = if load > lb_load { 100 * (load - lb_load) / load } else { 0 };

        llc.lb_llc_id.store(if imbalance > slack { lb_llc.id } else { MAX_LLCS }, Relaxed);
    }

    if llcs.len() > 1 {
        LLC_LB_OFFSET.store((offset % (llcs.len() - 1)) as u32 + 1, Relaxed);
    }

    let (load_sum, interactive_sum) = llcs.iter()
        .fold((0, 0), |(load, intr), llc| (load + llc.load(), intr + llc.intr_load.load(Relaxed)));

    if AUTOSLICE.load(Relaxed) && load_sum != 0 && load_sum >= interactive_sum {
        let first = DSQ_TIME_SLICES[0].load(Relaxed);
        let ideal_sum = load_sum * INTERACTIVE_RATIO.load(Relaxed) / 100;

        // Too little interactive load: lengthen the slices, so that more tasks
        // count as interactive. Too much: shorten them.
        rescale_dsq_time_slices(if interactive_sum < ideal_sum || interactive_sum == 0 {
            11 * first / 10
        } else {
            max(10 * first / 11, MIN_SLICE_NS.load(Relaxed))
        });
    }

    // A new period starts.
    let now = scx_now();
    for llc in llcs {
        let loads = [&llc.load, &llc.intr_load, &llc.affn_load];
        loads.into_iter().chain(&llc.dsq_load).for_each(|load| load.store(0, Relaxed));
        llc.last_period_ns.store(now, Relaxed);
    }

    true
}

struct P2dqTimer {
    /// if set to 0 the timer will only be scheduled once
    interval_ns: u64,
    clock: u64,
    start_flags: u64,
    /// Returns whether the timer shall run again.
    run: fn() -> bool,
}

const MAX_TIMERS: usize = 1;

static P2DQ_TIMERS: [P2dqTimer; MAX_TIMERS] = [
    // EAGER_LOAD_BALANCER_TMR
    P2dqTimer { interval_ns: LB_TIMER_INTVL_NS, clock: CLOCK_BOOTTIME, start_flags: 0, run: load_balance_timer },
];

bpf_timer_map!(p2dq_timer_data, timers, MAX_TIMERS);

bpf_callback!(fn timer_cb(_map: *mut u8, key: *mut u32, timer: *mut bpf_timer) -> i32 {
    let Some(cb_timer) = P2DQ_TIMERS.get(unsafe { *key } as usize) else { return 0 };

    let resched = (cb_timer.run)();

    if resched && cb_timer.interval_ns != 0 {
        if let Some(timer) = Timer::from_ptr(timer) {
            let _ = timer.start(cb_timer.interval_ns, cb_timer.start_flags);
        }
    }
    0
});

fn start_timers() -> Result {
    P2DQ_TIMERS.iter().zip(0u32..).try_for_each(|(new_timer, timer_id)| {
        timers().init(timer_id, new_timer.clock, timer_cb)?
            .start(new_timer.interval_ns, new_timer.start_flags)
    })
}

// ── Init ─────────────────────────────────────────────────────────────

fn create_dsq(dsq: Dsq, node: i32) -> Result {
    dsq.create(node).inspect_err(|_| scx_error!("failed to create DSQ %llu", dsq.0))
}

fn init_topology() -> Result<(Vec<Llc>, Vec<BpfCell<CpuCtx>>)> {
    let nr_cpus = min(nr_cpu_ids() as usize, MAX_CPUS) as i32;
    let llc_cpus = LLC_CPUS.load(Relaxed).max(1);
    let mut llcs: Vec<Llc> = Vec::new();
    let mut cpus = Vec::with_capacity(nr_cpus as usize);

    for cpu in 0..nr_cpus {
        let node_id = cpu_node(cpu);

        if !llcs.last().is_some_and(|llc| llc.node_id == node_id && llc.cpus.weight() < llc_cpus) {
            if llcs.len() as u32 == MAX_LLCS {
                scx_error!("too many LLCs");
                return Err(EINVAL);
            }
            llcs.push(Llc::new(llcs.len() as u32, node_id));
        }
        let llc = llcs.last().ok_or(ENOMEM)?;
        if llc.cpus.is_empty() {
            create_dsq(llc.dsq, node_id)?;
            create_dsq(llc.mig_dsq, node_id)?;
        }

        llc.cpus.set(cpu);
        ALL_CPUS.set(cpu);

        let affn_dsq = cpu_dsq_id(cpu);
        create_dsq(affn_dsq, node_id)?;
        cpus.push(BpfCell::new(CpuCtx {
            id: cpu,
            llc_id: llc.id,
            node_id,
            affn_dsq,
            slice_ns: 1,
            dsq_index: 0,
            flags: CpuFlags::default(),
            ran_for: 0,
        }));
    }

    NR_CPUS.store(nr_cpus as u32, Relaxed);
    Ok((llcs, cpus))
}

bpf_prog!("struct_ops.s/p2dq_init",
fn p2dq_init() -> Result {
    if INIT_DSQ_INDEX.load(Relaxed) as usize >= nr_dsqs_per_llc() {
        scx_error!("invalid init_dsq_index");
        return Err(EINVAL);
    }

    let min_slice_ns = 1000 * MIN_SLICE_US.load(Relaxed);
    MIN_SLICE_NS.store(min_slice_ns, Relaxed);
    rescale_dsq_time_slices(min_slice_ns);

    let (llcs, cpus) = init_topology()?;
    unsafe {
        *LLCS.get_mut() = llcs;
        *CPU_CTXS.get_mut() = cpus;
    }

    start_timers()
});

bpf_prog!("struct_ops/p2dq_exit",
fn p2dq_exit(_ei: *const ScxExitInfo) {
    timers().cancel_all();
});

scx_ops_define!(p2dq_ops, name: b"p2dq",
    flags: SCX_OPS_KEEP_BUILTIN_IDLE | SCX_OPS_ALLOW_QUEUED_WAKEUP,
    timeout_ms: 25000,
    select_cpu: p2dq_select_cpu,
    enqueue: p2dq_enqueue,
    dequeue: p2dq_dequeue,
    dispatch: p2dq_dispatch,
    running: p2dq_running,
    stopping: p2dq_stopping,
    set_cpumask: p2dq_set_cpumask,
    update_idle: p2dq_update_idle,
    init_task: p2dq_init_task,
    exit_task: p2dq_exit_task,
    init: p2dq_init,
    exit: p2dq_exit,
);

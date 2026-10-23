// SPDX-License-Identifier: GPL-2.0
//
// scx_rusty: a multi-domain scheduler. The CPUs are split into domains, each
// with its own DSQ in deadline order. Tasks belong to a domain and are moved
// between domains by a load balancer.
//
// Rust port of scheds/rust/scx_rusty/src/bpf/main.bpf.c with ravg_impl.bpf.h.
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// - sdt_alloc/sdt_task (arena allocator) -> TaskMap<TaskCtx>, Box, Vec
// - struct dom_ctx + struct lb_domain    -> Domain, in a Vec
// - dom_dcycle_locks (bpf_spin_lock map) -> SpinLock<Bucket>
// - dom vtime lock                       -> AtomicU64::fetch_update()
// - task_masks, all the kptr cpumasks    -> CpuSet
// - struct ravg_data + functions         -> Ravg + methods, 128 bit arithmetic
//                                           instead of u64_x_u32_rshift()
// - the gotos of rusty_select_cpu()      -> Result<Pick>, `?` and Option chains
// - stats (per-CPU array)                -> [AtomicU64; N] indexed by an enum
//
// User space does three things for the C scheduler, which are done here:
// - Domains. C gets cpu_dom_id_map[], dom_cpumasks[] etc., one domain per LLC.
//   Here ops.init() puts DOM_CPUS consecutive CPUs of a NUMA node in a domain.
// - Load balancing. C exports the duty cycles and the recently active tasks of
//   each domain, user space computes loads and picks the tasks to move.
//   load_balance() is a small version of that, run from ops.tick(): it moves
//   tasks from the most to the least loaded domain.
// - Tuning. tune_input is exported like in C. Nobody fills it in.
//
// Dropped: mempolicy affinity, debug messages, perf mode, UEI.

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::vec::Vec;
use core::cmp::min;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering::Relaxed};
use scx_common::*;

const MAX_DOMS: usize = 64; // limited to avoid complex bitmask ops

const LB_MAX_WEIGHT: u64 = 10000;
const LB_LOAD_BUCKETS: usize = 100; // Must be a factor of LB_MAX_WEIGHT
const LB_WEIGHT_PER_BUCKET: u64 = LB_MAX_WEIGHT / LB_LOAD_BUCKETS as u64;

// Constants used for determining a task's deadline
/// roughly scales average runtime to same order of magnitude as waker and
/// blocked frequencies
const DL_RUNTIME_SCALE: u64 = 2;
const DL_MAX_LATENCY_NS: u64 = 50 * NSEC_PER_MSEC;
const DL_FREQ_FT_MAX: u64 = 100000;
const DL_MAX_LAT_PRIO: u64 = 39;

/// When the load balancer is trying to determine the tasks to push out from an
/// overloaded domain, it looks at the the following number of recently active
/// tasks of the domain.
const MAX_DOM_ACTIVE_TPTRS: usize = 1024;

// ── Configuration (const volatile equivalents) ───────────────────────

tunables! { "rusty",
    LOAD_HALF_LIFE: AtomicU32 = 1_000_000_000; // 1s
    KTHREADS_LOCAL: AtomicBool = false;
    FIFO_SCHED: AtomicBool = false;
    DIRECT_GREEDY_NUMA: AtomicBool = false;
    GREEDY_THRESHOLD: AtomicU32 = 1;
    GREEDY_THRESHOLD_X_NUMA: AtomicU32 = 0;
    /// CPUs per domain.
    DOM_CPUS: AtomicU32 = 4;
    /// Time between two rounds of load balancing.
    LB_INTERVAL_NS: AtomicU64 = 100 * NSEC_PER_MSEC;
}

fn half_life() -> u32 { LOAD_HALF_LIFE.load(Relaxed) }
fn fifo_sched() -> bool { FIFO_SCHED.load(Relaxed) }

/// Tune params: user space writes them and bumps the generation.
#[repr(C)]
struct TuneInput {
    genn: AtomicU64,
    slice_ns: AtomicU64,
    direct_greedy_cpumask: CpuSet,
    kick_greedy_cpumask: CpuSet,
}

#[export_name = "rusty_tune_input"]
static TUNE_INPUT: TuneInput = TuneInput {
    genn: AtomicU64::new(0),
    slice_ns: AtomicU64::new(0),
    direct_greedy_cpumask: CpuSet::new(),
    kick_greedy_cpumask: CpuSet::new(),
};

static TUNE_PARAMS_GEN: AtomicU64 = AtomicU64::new(0);
static SLICE_NS: AtomicU64 = AtomicU64::new(SCX_SLICE_DFL);

fn slice_ns() -> u64 { SLICE_NS.load(Relaxed) }

// ── Statistics ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Stat {
    // The following fields add up to all dispatched tasks
    WakeSync,
    SyncPrevIdle,
    PrevIdle,
    GreedyIdle,
    Pinned,
    DirectDispatch,
    DirectGreedy,
    DirectGreedyFar,
    DsqDispatch,
    GreedyLocal,
    GreedyXnuma,
    // Extra stats that don't contribute to total
    Repatriate,
    KickGreedy,
    LoadBalance,
    // Deadline related stats
    DlClamp,
    DlPreset,
    NrStats,
}

static STATS: [AtomicU64; Stat::NrStats as usize] =
    [const { AtomicU64::new(0) }; Stat::NrStats as usize];

impl Stat {
    fn inc(self) { STATS[self as usize].fetch_add(1, Relaxed); }
}

// ── Running average ──────────────────────────────────────────────────
//
// A running average of a value over time with exponential decay: what
// happened one half life ago counts half. Time is cut into periods of one half
// life. @old is the decayed sum of the finished periods, @cur the sum of the
// one in progress.

const RAVG_VAL_BITS: u32 = 44; // input values are 44bit
const RAVG_FRAC_BITS: u32 = 20; // 1048576 is 1.0

#[derive(Clone, Copy, Default)]
struct Ravg {
    val: u64,
    val_at: u64,
    old: u64,
    cur: u64,
}

/// The sum of 2^-1 + 2^-2 + ... + 2^-(idx + 1) in fixed point: what a value of
/// 1 contributes over that many full periods.
const RAVG_FULL_SUM: [u64; 20] = {
    let mut sums = [0; 20];
    let mut i = 0;
    while i < 20 {
        sums[i] = (1 << RAVG_FRAC_BITS) - (1 << (RAVG_FRAC_BITS - 1 - i as u32));
        i += 1;
    }
    sums
};

fn ravg_decay(v: u64, shift: u32) -> u64 { v.checked_shr(shift).unwrap_or(0) }

/// A duration as a fraction of the half life.
fn ravg_normalize_dur(dur: u32, half_life: u32) -> u64 {
    if dur < half_life {
        (((dur as u64) << RAVG_FRAC_BITS) + half_life as u64 - 1) / half_life as u64
    } else {
        1 << RAVG_FRAC_BITS
    }
}

impl Ravg {
    /// The value was @self.val since @self.val_at. It is @new_val from @now on.
    fn accumulate(&mut self, new_val: u64, now: u64, half_life: u32) {
        let hl = half_life as u64;
        // It may be difficult for the caller to guarantee monotonic progress.
        let now = now.max(self.val_at);
        let seq_delta = (now / hl - self.val_at / hl) as u32;

        // Decay ->old and fold ->cur into it.
        if seq_delta > 0 {
            self.old = ravg_decay(self.old, seq_delta)
                .saturating_add(ravg_decay(self.cur, seq_delta));
            self.cur = 0;
        }

        if self.val != 0 {
            if seq_delta > 0 {
                // Fold the oldest period which may be partial.
                let dur = ravg_normalize_dur((hl - self.val_at % hl) as u32, half_life);
                self.old = self.old.saturating_add(self.val * ravg_decay(dur, seq_delta));

                // Pre-computed decayed full-period values.
                if let Some(idx) = seq_delta.checked_sub(2) {
                    let full = RAVG_FULL_SUM[min(idx as usize, RAVG_FULL_SUM.len() - 1)];
                    self.old = self.old.saturating_add(self.val * full);
                }

                // Accumulate the current period duration into ->cur.
                self.cur += self.val * ravg_normalize_dur((now % hl) as u32, half_life);
            } else {
                self.cur += self.val * ravg_normalize_dur((now - self.val_at) as u32, half_life);
            }
        }

        self.val = min(new_val, (1 << RAVG_VAL_BITS) - 1);
        self.val_at = now;
    }

    /// Move the contribution of @xfer into or out of @self.
    fn transfer(&mut self, new_val: u64, xfer: &mut Ravg, xfer_new_val: u64, half_life: u32,
                dir: Xfer) {
        // Synchronize the two.
        if time_before(self.val_at, xfer.val_at) {
            self.accumulate(new_val, xfer.val_at, half_life);
        } else if time_after(self.val_at, xfer.val_at) {
            xfer.accumulate(xfer_new_val, self.val_at, half_life);
        }

        // An out-transfer can go below zero due to the rounding of the decay.
        match dir {
            Xfer::In => {
                self.old += xfer.old;
                self.cur += xfer.cur;
            }
            Xfer::Out => {
                self.old = self.old.saturating_sub(xfer.old);
                self.cur = self.cur.saturating_sub(xfer.cur);
            }
        }
    }

    /// Read the current running avg, in fixed point.
    fn read(&self, now: u64, half_life: u32) -> u64 {
        let now = now.max(self.val_at);
        let elapsed = (now % half_life as u64) as u32;

        // Accumulate the ongoing period into a temporary copy.
        let mut rd = *self;
        rd.accumulate(0, now, half_life);

        if elapsed == 0 {
            return rd.old;
        }

        // Blend ->old, which loses weight as the period progresses, with ->cur.
        let progress = ravg_normalize_dur(elapsed, half_life);
        let old_weight = (1u64 << RAVG_FRAC_BITS) - progress / 2;
        ((rd.old as u128 * old_weight as u128) >> RAVG_FRAC_BITS) as u64 + rd.cur / 2
    }
}

#[derive(Clone, Copy)]
enum Xfer {
    In,
    Out,
}

// ── Domains ──────────────────────────────────────────────────────────

/// The duty cycle of the tasks of a domain whose weight falls into one range.
#[derive(Default)]
struct Bucket {
    dcycle: u64,
    rd: Ravg,
}

struct Domain {
    id: u32,
    node: i32,
    cpus: CpuSet,
    direct_greedy: CpuSet,
    min_vruntime: AtomicU64,
    buckets: Vec<SpinLock<Bucket>>,
    /// The pids of the tasks that ran since the last round of load balancing.
    active_gen: AtomicU64,
    active_idx: AtomicU64,
    active_pids: Vec<AtomicI32>,
}

static DOMAINS: BpfCell<Vec<Domain>> = BpfCell::new(Vec::new());

fn domains() -> &'static [Domain] { DOMAINS.get() }

fn lookup_dom(dom_id: u32) -> Option<&'static Domain> {
    let dom = domains().get(dom_id as usize);
    if dom.is_none() {
        scx_error!("Failed to lookup dom[%u]", dom_id);
    }
    dom
}

/// Weight is calculated linearly, and is within range of [1, 10000]
fn weight_to_bucket_idx(weight: u32) -> usize {
    min(weight as usize * LB_LOAD_BUCKETS / LB_MAX_WEIGHT as usize, LB_LOAD_BUCKETS - 1)
}

impl Domain {
    fn new(id: u32, node: i32) -> Self {
        Domain {
            id,
            node,
            cpus: CpuSet::new(),
            direct_greedy: CpuSet::new(),
            min_vruntime: AtomicU64::new(0),
            buckets: (0..LB_LOAD_BUCKETS).map(|_| SpinLock::new(Bucket::default())).collect(),
            active_gen: AtomicU64::new(0),
            active_idx: AtomicU64::new(0),
            active_pids: (0..MAX_DOM_ACTIVE_TPTRS).map(|_| AtomicI32::new(0)).collect(),
        }
    }

    fn dsq(&self) -> Dsq { Dsq(self.id as u64) }
    fn min_vruntime(&self) -> u64 { self.min_vruntime.load(Relaxed) }

    /// A task of @weight became runnable, or stopped being runnable.
    fn dcycle_adj(&self, weight: u32, now: u64, runnable: bool) {
        let idx = weight_to_bucket_idx(weight);
        let underflow = {
            let mut bucket = self.buckets[idx].lock();
            let dcycle = if runnable { bucket.dcycle.checked_add(1) } else { bucket.dcycle.checked_sub(1) };
            bucket.dcycle = dcycle.unwrap_or(0);
            let dcycle_now = bucket.dcycle;
            bucket.rd.accumulate(dcycle_now, now, half_life());
            dcycle.is_none()
        };

        if underflow {
            scx_error!("cpu%d dom%u bucket%u load underflow", this_cpu(), self.id, idx);
        }
    }

    /// One half of the move of a task to another domain.
    fn dcycle_xfer(&self, taskc: &TaskCtx, task_rd: &mut Ravg, dir: Xfer) {
        let mut bucket = self.buckets[weight_to_bucket_idx(taskc.weight)].lock();
        if taskc.runnable {
            bucket.dcycle = match dir {
                Xfer::In => bucket.dcycle + 1,
                Xfer::Out => bucket.dcycle.saturating_sub(1),
            };
        }
        let dcycle = bucket.dcycle;
        bucket.rd.transfer(dcycle, task_rd, taskc.runnable as u64, half_life(), dir);
    }

    /// Sum of duty cycle * weight over the buckets. User space does this in C.
    fn load(&self, now: u64) -> u64 {
        self.buckets.iter().zip(1u64..)
            .map(|(bucket, nth)| {
                let dcycle = bucket.lock().rd.read(now, half_life());
                // The weight in the middle of the bucket.
                dcycle * (nth * LB_WEIGHT_PER_BUCKET - LB_WEIGHT_PER_BUCKET / 2) >> RAVG_FRAC_BITS
            })
            .sum()
    }

    fn record_active(&self, p: Task, taskc: &mut TaskCtx) {
        let gen = self.active_gen.load(Relaxed);
        if taskc.dom_active_tasks_gen == gen {
            return;
        }
        let idx = self.active_idx.fetch_add(1, Relaxed) as usize % MAX_DOM_ACTIVE_TPTRS;
        self.active_pids[idx].store(p.pid(), Relaxed);
        taskc.dom_active_tasks_gen = gen;
    }
}

// ── Per-CPU context ──────────────────────────────────────────────────

struct PcpuCtx {
    /// used when scanning other doms
    dom_rr_cur: AtomicU32,
    dom_id: AtomicU32,
}

const NO_DOM: u32 = u32::MAX;

static PCPU_CTXS: [PcpuCtx; MAX_CPUS] = [const {
    PcpuCtx { dom_rr_cur: AtomicU32::new(0), dom_id: AtomicU32::new(NO_DOM) }
}; MAX_CPUS];

fn lookup_pcpu_ctx(cpu: i32) -> Option<&'static PcpuCtx> {
    let pcpuc = usize::try_from(cpu).ok().and_then(|cpu| PCPU_CTXS.get(cpu));
    if pcpuc.is_none() {
        scx_error!("Failed to lookup pcpu ctx for %d", cpu);
    }
    pcpuc
}

/// The domain of a CPU. None for a CPU that was offline at init.
fn cpu_to_dom(cpu: i32) -> Option<&'static Domain> {
    let pcpuc = PCPU_CTXS.get(usize::try_from(cpu).ok()?)?;
    domains().get(pcpuc.dom_id.load(Relaxed) as usize)
}

static ALL_CPUS: CpuSet = CpuSet::new();
static DIRECT_GREEDY: CpuSet = CpuSet::new();
static KICK_GREEDY: CpuSet = CpuSet::new();

// ── Per-task context ─────────────────────────────────────────────────

struct TaskCtx {
    /// The domains this task can run on
    dom_mask: u64,
    /// The CPUs of its domain that the task can run on
    cpus: CpuSet,
    target_dom: u32,
    /// Where the load balancer wants the task to be
    lb_dom: AtomicU32,
    weight: u32,
    runnable: bool,
    dom_active_tasks_gen: u64,
    deadline: u64,

    sum_runtime: u64,
    avg_runtime: u64,
    last_run_at: u64,

    /// frequency with which a task is blocked (consumer)
    blocked_freq: u64,
    last_blocked_at: u64,

    /// frequency with which a task wakes other tasks (producer)
    waker_freq: u64,
    last_woke_at: u64,

    /// The task is a workqueue worker thread
    is_kworker: bool,
    /// Allowed on all CPUs and eligible for DIRECT_GREEDY optimization
    all_cpus: bool,
    /// select_cpu() telling enqueue() to queue directly on the DSQ
    dispatch_local: bool,

    dcyc_rd: Ravg,
}

static TASK_CTXS: TaskMap<TaskCtx> = TaskMap::new();

fn lookup_task_ctx(p: Task) -> Option<&'static mut TaskCtx> {
    let taskc = TASK_CTXS.get(p);
    if taskc.is_none() {
        scx_error!("task_ctx lookup failed for pid %d", p.pid());
    }
    taskc
}

fn scale_up_fair(value: u64, weight: u64) -> u64 { value * weight / 100 }
fn scale_inverse_fair(value: u64, weight: u64) -> u64 { value * 100 / weight }

impl TaskCtx {
    fn new(p: Task, now: u64) -> Self {
        TaskCtx {
            dom_mask: 0,
            cpus: CpuSet::new(),
            target_dom: 0,
            lb_dom: AtomicU32::new(0),
            weight: p.weight() as u32,
            runnable: false,
            dom_active_tasks_gen: u64::MAX,
            deadline: 0,
            sum_runtime: 0,
            avg_runtime: 0,
            last_run_at: 0,
            blocked_freq: 0,
            last_blocked_at: now,
            waker_freq: 0,
            last_woke_at: now,
            is_kworker: false,
            all_cpus: false,
            dispatch_local: false,
            dcyc_rd: Ravg::default(),
        }
    }

    fn domain(&self) -> Option<&'static Domain> { lookup_dom(self.target_dom) }

    fn load_adj(&mut self, now: u64, runnable: bool) {
        self.runnable = runnable;
        self.dcyc_rd.accumulate(runnable as u64, now, half_life());
    }

    /// @self is moving from @from to @to. Its duty cycle contribution in the
    /// relevant bucket of @from should be moved together to the corresponding
    /// bucket in @to.
    fn dcycle_xfer(&mut self, from: &Domain, to: &Domain, now: u64) {
        self.dcyc_rd.accumulate(self.runnable as u64, now, half_life());
        let mut task_rd = self.dcyc_rd;

        from.dcycle_xfer(self, &mut task_rd, Xfer::Out);
        to.dcycle_xfer(self, &mut task_rd, Xfer::In);
    }
}

fn refresh_tune_params() {
    let genn = TUNE_INPUT.genn.load(Relaxed);
    if TUNE_PARAMS_GEN.swap(genn, Relaxed) == genn {
        return;
    }

    SLICE_NS.store(TUNE_INPUT.slice_ns.load(Relaxed), Relaxed);

    let copy = |cpu: i32, from: &CpuSet, to: &CpuSet| {
        if from.test(cpu) { to.set(cpu) } else { to.clear(cpu) }
    };

    for dom in domains() {
        for cpu in dom.cpus.iter() {
            copy(cpu, &TUNE_INPUT.direct_greedy_cpumask, &DIRECT_GREEDY);
            copy(cpu, &TUNE_INPUT.direct_greedy_cpumask, &dom.direct_greedy);
            copy(cpu, &TUNE_INPUT.kick_greedy_cpumask, &KICK_GREEDY);
        }
    }
}

// ── Deadlines ────────────────────────────────────────────────────────

/// ** Taken directly from fair.c in the Linux kernel **
///
/// We use this table to inversely scale deadline according to a task's
/// calculated latency factor.
///
/// "Nice levels are multiplicative, with a gentle 10% change for every nice
/// level changed."
const SCHED_PRIO_TO_WEIGHT: [u32; DL_MAX_LAT_PRIO as usize + 1] = [
    /* -20 */ 88761, 71755, 56483, 46273, 36291,
    /* -15 */ 29154, 23254, 18705, 14949, 11916,
    /* -10 */ 9548, 7620, 6100, 4904, 3906,
    /*  -5 */ 3121, 2501, 1991, 1586, 1277,
    /*   0 */ 1024, 820, 655, 526, 423,
    /*   5 */ 335, 272, 215, 172, 137,
    /*  10 */ 110, 87, 70, 56, 45,
    /*  15 */ 36, 29, 23, 18, 15,
];

fn sched_prio_to_latency_weight(prio: u64) -> u64 {
    match SCHED_PRIO_TO_WEIGHT.iter().rev().nth(prio as usize + 1) {
        Some(&weight) => weight as u64,
        None => {
            scx_error!("Invalid prio index");
            0
        }
    }
}

fn log2_u64(v: u64) -> u64 { v.checked_ilog2().unwrap_or(0) as u64 }

/// Determine the task's deadline relative to its vruntime: tasks that wake
/// others and block often (they sit in the middle of a work chain) and that run
/// for a short time get a short one.
fn task_compute_dl(p: Task, taskc: &TaskCtx) -> u64 {
    // Determine the latency criticality of a task, and scale a task's deadline
    // accordingly. A producer is weighed more heavily than a consumer.
    let waker_freq = min(taskc.waker_freq, DL_FREQ_FT_MAX);
    let blocked_freq = min(taskc.blocked_freq, DL_FREQ_FT_MAX);
    let freq_factor = scale_up_fair(blocked_freq * waker_freq * waker_freq, p.weight());

    // The above frequencies roughly follow an exponential distribution, so use
    // log2_u64() to linearize it to a boost priority.
    let lat_prio = min(log2_u64(freq_factor + 1), DL_MAX_LAT_PRIO);

    // Next calculate a task's average runtime, and apply it to deadline
    // accordingly. A task with a large runtime is penalized from an
    // interactivity standpoint, for obvious reasons.
    let avg_run_raw = min(taskc.avg_runtime / DL_RUNTIME_SCALE, DL_MAX_LATENCY_NS);
    let avg_run = log2_u64(scale_inverse_fair(avg_run_raw, p.weight()) + 1);

    let lat_prio = lat_prio.saturating_sub(avg_run);

    // Ultimately, what we're trying to arrive at is a single value by which we
    // can scale the task's average runtime.
    let lat_scale = min(sched_prio_to_latency_weight(lat_prio), LB_MAX_WEIGHT);

    scale_inverse_fair(taskc.avg_runtime, lat_scale.max(1))
}

fn clamp_task_vtime(p: Task, taskc: &mut TaskCtx) {
    let Some(dom) = taskc.domain() else { return };

    // Allow an idling task to accumulate at most one slice worth of vtime
    // budget.
    let min_vruntime = dom.min_vruntime().wrapping_sub(slice_ns());

    if time_before(p.dsq_vtime(), min_vruntime) {
        p.set_dsq_vtime(min_vruntime);
        taskc.deadline = min_vruntime.wrapping_add(task_compute_dl(p, taskc));
        Stat::DlClamp.inc();
    } else {
        Stat::DlPreset.inc();
    }
}

/// Move @p to @new_dom, None if there is no domain that it can run in. Returns
/// whether that is where it is now.
fn task_set_domain(p: Task, taskc: &mut TaskCtx, new_dom: Option<u32>, init_dsq_vtime: bool) -> bool {
    let Some(old_dom) = lookup_dom(taskc.target_dom) else { return false };

    let Some(new_dom_id) = new_dom else {
        taskc.cpus.clear_all();
        return !p.is_queued();
    };
    let Some(new_dom) = lookup_dom(new_dom_id) else { return false };

    // set_cpumask might have happened between the load balancer choosing the
    // task and here. @p may not be able to run in @new_dom anymore. Verify.
    if new_dom.cpus.intersects(p.cpus()) {
        if !init_dsq_vtime {
            taskc.dcycle_xfer(old_dom, new_dom, scx_now());
        }

        taskc.target_dom = new_dom_id;
        taskc.lb_dom.store(new_dom_id, Relaxed);

        p.set_dsq_vtime(new_dom.min_vruntime());
        taskc.deadline = new_dom.min_vruntime()
            .wrapping_add(scale_inverse_fair(taskc.avg_runtime, taskc.weight.max(1) as u64));
        taskc.cpus.assign_and(&new_dom.cpus, p.cpus());
    }

    taskc.target_dom == new_dom_id
}

// ── CPU selection ────────────────────────────────────────────────────

/// What rusty_select_cpu() has decided.
enum Pick {
    /// The CPU is idle or as good as: ops.enqueue() shall use its local DSQ.
    Direct(i32, Stat),
    /// Queue in the DSQ of the domain.
    Queue(i32),
}

/// An idle CPU out of @cpus, a fully idle core if @cores is given.
fn pick_idle(mut cpus: impl Iterator<Item = i32>, cores: Option<Cpumask>) -> Option<i32> {
    cpus.find(|&cpu| cores.is_none_or(|cores| cores.test(cpu)) && test_and_clear_cpu_idle(cpu))
}

fn try_sync_wakeup(p: Task, taskc: &TaskCtx, prev_cpu: i32) -> Option<Pick> {
    let cpu = this_cpu();
    let dom = cpu_to_dom(cpu)?;
    let idle_cpumask = ScxCpumask::idle();

    // If the waker and the previous CPU of the wakee share a domain and the
    // latter is idle, stay there.
    if dom.cpus.test(prev_cpu) && test_and_clear_cpu_idle(prev_cpu) {
        return Some(Pick::Direct(prev_cpu, Stat::SyncPrevIdle));
    }

    // If there are idle CPUs in the domain of the waker, the wakee can take
    // over the CPU of the waker, which is about to release it.
    let has_idle = dom.cpus.intersects(*idle_cpumask);
    if has_idle && p.cpus().test(cpu) && !Task::current().is_exiting() &&
       (taskc.target_dom as usize) < MAX_DOMS && Dsq::local_on(cpu).nr_queued() == 0 {
        return Some(Pick::Direct(cpu, Stat::WakeSync));
    }

    None
}

/// The task found nothing idle at home. Look at the CPUs that accept foreign
/// tasks, near ones first.
fn pick_direct_greedy(prev_cpu: i32, cores: Option<Cpumask>) -> Option<Pick> {
    let dom = cpu_to_dom(prev_cpu);

    // Without direct_greedy_numa stay on the node.
    let node = dom.filter(|_| !DIRECT_GREEDY_NUMA.load(Relaxed)).map(|dom| dom.node);
    let far = || DIRECT_GREEDY.iter().filter(move |&cpu| node.is_none_or(|node| cpu_node(cpu) == node));
    let near = |cores| pick_idle(dom?.direct_greedy.iter(), cores);

    // Try to find an idle core in the previous and then any domain, then the
    // same for any idle CPU.
    let passes = cores.map(Some).into_iter().chain([None]);
    for cores in passes {
        if let Some(cpu) = near(cores) {
            return Some(Pick::Direct(cpu, Stat::DirectGreedy));
        }
        if let Some(cpu) = pick_idle(far(), cores) {
            return Some(Pick::Direct(cpu, Stat::DirectGreedyFar));
        }
    }
    None
}

fn pick_cpu(p: Task, taskc: &TaskCtx, prev_cpu: i32, wake_flags: u64) -> Pick {
    let idle_smtmask = ScxCpumask::idle_smt();

    if p.nr_cpus_allowed() == 1 {
        let kthread = KTHREADS_LOCAL.load(Relaxed) && p.is_kthread();
        return Pick::Direct(prev_cpu, if kthread { Stat::DirectDispatch } else { Stat::Pinned });
    }

    // If WAKE_SYNC, try to migrate the wakee to the waker's CPU.
    if wake_flags & SCX_WAKE_SYNC != 0 {
        if let Some(pick) = try_sync_wakeup(p, taskc, prev_cpu) {
            return pick;
        }
    }

    let cores = (!idle_smtmask.is_empty()).then_some(*idle_smtmask);

    // did @p get pulled out to a foreign domain by e.g. greedy execution?
    let prev_domestic = taskc.cpus.test(prev_cpu);

    // See if we want to keep @prev_cpu. We want to keep @prev_cpu if the whole
    // physical core is idle. If the sibling[s] are busy, it's likely more
    // advantageous to look for wholly idle cores first.
    if (prev_domestic || DIRECT_GREEDY.test(prev_cpu)) && idle_smtmask.test(prev_cpu) &&
       test_and_clear_cpu_idle(prev_cpu) {
        return Pick::Direct(prev_cpu, if prev_domestic { Stat::PrevIdle } else { Stat::GreedyIdle });
    }

    // @prev_cpu didn't work out. Let's see whether there's an idle CPU @p can
    // be directly dispatched to. We'll first try to find the best idle domestic
    // CPU and then move onto foreign.
    let domestic = cores
        // If there is a domestic idle core, dispatch directly
        .and_then(|cores| pick_idle(taskc.cpus.iter(), Some(cores)))
        // If @prev_cpu was domestic and is idle itself even though the core
        // isn't, picking @prev_cpu may improve L1/2 locality.
        .or_else(|| (prev_domestic && test_and_clear_cpu_idle(prev_cpu)).then_some(prev_cpu))
        // If there is any domestic idle CPU, dispatch directly
        .or_else(|| pick_idle(taskc.cpus.iter(), None));
    if let Some(cpu) = domestic {
        return Pick::Direct(cpu, Stat::DirectDispatch);
    }

    // Domestic domain is fully booked. If there are CPUs which are idle and
    // under-utilized, ignore domain boundaries (while still respecting NUMA
    // boundaries) and push the task there.
    if taskc.all_cpus && !DIRECT_GREEDY.is_empty() {
        if let Some(pick) = pick_direct_greedy(prev_cpu, cores) {
            return pick;
        }
    }

    // We're going to queue on the domestic domain's DSQ. @prev_cpu may be in a
    // different domain. Returning an out-of-domain CPU can lead to stalls as
    // all in-domain CPUs may be idle by the time @p gets enqueued.
    Pick::Queue(if prev_domestic { prev_cpu } else { taskc.cpus.any_distribute().unwrap_or(prev_cpu) })
}

bpf_prog!("struct_ops/rusty_select_cpu",
fn rusty_select_cpu(p: Task, prev_cpu: i32, wake_flags: u64) -> i32 {
    refresh_tune_params();

    let Some(taskc) = lookup_task_ctx(p) else { return -ENOENT.0 };

    match pick_cpu(p, taskc, prev_cpu, wake_flags) {
        Pick::Direct(cpu, stat) => {
            stat.inc();
            taskc.dispatch_local = true;
            cpu
        }
        Pick::Queue(cpu) => cpu,
    }
});

bpf_prog!("struct_ops/rusty_enqueue",
fn rusty_enqueue(p: Task, enq_flags: u64) {
    let Some(taskc) = lookup_task_ctx(p) else { return };

    // Migrate @p to a new domain if requested by the load balancer.
    let lb_dom = taskc.lb_dom.load(Relaxed);
    if lb_dom != taskc.target_dom && task_set_domain(p, taskc, Some(lb_dom), false) {
        Stat::LoadBalance.inc();
        taskc.dispatch_local = false;
        if let Some(cpu) = taskc.cpus.any_distribute() {
            kick_cpu(cpu, 0);
        }
    } else {
        if core::mem::take(&mut taskc.dispatch_local) {
            p.dsq_insert(SCX_DSQ_LOCAL, slice_ns(), enq_flags);
            return;
        }

        // @p is about to be queued on its domain's dsq. However, @p may be on
        // a foreign CPU due to a greedy execution and not have gone through
        // ->select_cpu() if it's being enqueued e.g. after slice exhaustion. If
        // so, @p would be queued on its domain's dsq but none of the CPUs in
        // the domain would be woken up which can induce temporary execution
        // stalls. Kick a domestic CPU if @p is on a foreign domain.
        if !taskc.cpus.test(p.cpu()) {
            if let Some(cpu) = taskc.cpus.any_distribute() {
                kick_cpu(cpu, 0);
            }
            Stat::Repatriate.inc();
        }
    }

    if fifo_sched() {
        p.dsq_insert(taskc.target_dom as u64, slice_ns(), enq_flags);
    } else {
        clamp_task_vtime(p, taskc);
        p.dsq_insert_vtime(taskc.target_dom as u64, slice_ns(), taskc.deadline, enq_flags);
    }

    // If there are CPUs which are idle and not saturated, wake them up to see
    // whether they'd be able to steal the just queued task. This path is taken
    // only if DIRECT_GREEDY didn't trigger in select_cpu().
    if taskc.all_cpus {
        let cpu = {
            let idle_cpumask = ScxCpumask::idle();
            KICK_GREEDY.iter().find(|&cpu| idle_cpumask.test(cpu))
        };
        if let Some(cpu) = cpu {
            Stat::KickGreedy.inc();
            kick_cpu(cpu, SCX_KICK_IDLE);
        }
    }
});

bpf_prog!("struct_ops/rusty_dispatch",
fn rusty_dispatch(cpu: i32, _prev: Option<Task>) {
    // In older kernels, we may receive an ops.dispatch() callback when a CPU is
    // coming online during a hotplug _before_ the hotplug callback has been
    // invoked. Just return.
    let Some(curr_dom) = cpu_to_dom(cpu) else { return };

    if curr_dom.dsq().move_to_local() {
        Stat::DsqDispatch.inc();
        return;
    }

    if GREEDY_THRESHOLD.load(Relaxed) == 0 {
        return;
    }

    let Some(pcpuc) = lookup_pcpu_ctx(cpu) else { return };
    let doms = domains();

    // The other domains, round robin, going on from where the last scan of
    // this CPU stopped.
    let scan = || {
        (1..doms.len())
            .map(|_| &doms[pcpuc.dom_rr_cur.fetch_add(1, Relaxed) as usize % doms.len()])
            .filter(|dom| dom.id != curr_dom.id)
    };

    // try to steal a task from domains on the current NUMA node
    if scan().filter(|dom| dom.node == curr_dom.node).any(|dom| dom.dsq().move_to_local()) {
        Stat::GreedyLocal.inc();
        return;
    }

    let x_numa = GREEDY_THRESHOLD_X_NUMA.load(Relaxed) as u64;
    if x_numa == 0 || nr_node_ids() == 1 {
        return;
    }

    // try to steal a task from domains on other NUMA nodes
    if scan()
        .filter(|dom| dom.node != curr_dom.node && dom.dsq().nr_queued() < x_numa)
        .any(|dom| dom.dsq().move_to_local())
    {
        Stat::GreedyXnuma.inc();
    }
});

// ── Task state tracking ──────────────────────────────────────────────

bpf_prog!("struct_ops/rusty_runnable",
fn rusty_runnable(p: Task, _enq_flags: u64) {
    let now = scx_now();
    let Some(wakee_ctx) = lookup_task_ctx(p) else { return };

    wakee_ctx.is_kworker = p.flags() & PF_WQ_WORKER != 0;

    wakee_ctx.load_adj(now, true);
    if let Some(dom) = wakee_ctx.domain() {
        dom.dcycle_adj(wakee_ctx.weight, now, true);
    }

    if fifo_sched() {
        return;
    }

    wakee_ctx.sum_runtime = 0;

    if let Some(waker_ctx) = TASK_CTXS.get(Task::current()) {
        let interval = now - waker_ctx.last_woke_at;
        waker_ctx.waker_freq = update_freq(waker_ctx.waker_freq, interval);
        waker_ctx.last_woke_at = now;
    }
});

bpf_prog!("struct_ops/rusty_running",
fn rusty_running(p: Task) {
    let Some(taskc) = lookup_task_ctx(p) else { return };
    let Some(dom) = taskc.domain() else { return };

    // Record that @p has been active in @dom. Load balancer will only consider
    // recently active tasks.
    dom.record_active(p, taskc);

    if fifo_sched() {
        return;
    }

    // Global vtime always progresses forward as tasks start executing.
    let vtime = p.dsq_vtime();
    let _ = dom.min_vruntime.fetch_update(Relaxed, Relaxed, |min_vruntime| {
        time_before(min_vruntime, vtime).then_some(vtime)
    });

    taskc.last_run_at = scx_now();
});

bpf_prog!("struct_ops/rusty_stopping",
fn rusty_stopping(p: Task, _runnable: bool) {
    if fifo_sched() {
        return;
    }
    let Some(taskc) = lookup_task_ctx(p) else { return };

    let delta = scx_now() - taskc.last_run_at;

    taskc.sum_runtime += delta;
    taskc.avg_runtime = calc_avg(taskc.avg_runtime, taskc.sum_runtime);

    // Penalize the task's vtime by the used time, and compute its deadline.
    let vtime = p.dsq_vtime().wrapping_add(scale_inverse_fair(delta, p.weight()));
    p.set_dsq_vtime(vtime);
    taskc.deadline = vtime.wrapping_add(task_compute_dl(p, taskc));
});

bpf_prog!("struct_ops/rusty_quiescent",
fn rusty_quiescent(p: Task, _deq_flags: u64) {
    let now = scx_now();
    let Some(taskc) = lookup_task_ctx(p) else { return };
    let Some(dom) = taskc.domain() else { return };

    taskc.load_adj(now, false);
    dom.dcycle_adj(taskc.weight, now, false);

    if fifo_sched() {
        return;
    }

    let interval = now - taskc.last_blocked_at;
    taskc.blocked_freq = update_freq(taskc.blocked_freq, interval);
    taskc.last_blocked_at = now;
});

bpf_prog!("struct_ops/rusty_set_weight",
fn rusty_set_weight(p: Task, weight: u32) {
    if let Some(taskc) = lookup_task_ctx(p) {
        taskc.weight = weight;
    }
});

/// Find the domains that @cpumask reaches and pick one of them, a different
/// one every time.
fn task_pick_domain(taskc: &mut TaskCtx, cpumask: Cpumask) -> Option<u32> {
    let doms = domains();
    let first = lookup_pcpu_ctx(this_cpu())?.dom_rr_cur.fetch_add(1, Relaxed) as usize + 1;

    let (dom_mask, picked) = doms.iter().cycle().skip(first % doms.len()).take(doms.len())
        .filter(|dom| dom.cpus.intersects(cpumask))
        .fold((0u64, None), |(mask, picked), dom| (mask | 1 << dom.id, picked.or(Some(dom.id))));

    taskc.dom_mask = dom_mask;
    picked
}

fn task_pick_and_set_domain(taskc: &mut TaskCtx, p: Task, cpumask: Cpumask, init_dsq_vtime: bool) {
    let dom_id = if domains().len() > 1 { task_pick_domain(taskc, cpumask) } else { Some(0) };

    if !task_set_domain(p, taskc, dom_id, init_dsq_vtime) {
        scx_error!("Failed to set dom%d for pid %d", dom_id.map_or(-1, |id| id as i32), p.pid());
    }
}

bpf_prog!("struct_ops/rusty_set_cpumask",
fn rusty_set_cpumask(p: Task, cpumask: Cpumask) {
    let Some(taskc) = lookup_task_ctx(p) else { return };

    task_pick_and_set_domain(taskc, p, cpumask, false);
    taskc.all_cpus = ALL_CPUS.is_subset_of(cpumask);
});

bpf_prog!("struct_ops/rusty_init_task",
fn rusty_init_task(p: Task, _args: InitTaskArgs) -> i32 {
    let mut taskc = TaskCtx::new(p, scx_now());

    task_pick_and_set_domain(&mut taskc, p, p.cpus(), true);
    taskc.all_cpus = ALL_CPUS.is_subset_of(p.cpus());

    TASK_CTXS.insert(p, taskc);
    0
});

bpf_prog!("struct_ops/rusty_exit_task",
fn rusty_exit_task(p: Task, _args: *const u8) {
    TASK_CTXS.remove(p);
});

// ── Load balancer ────────────────────────────────────────────────────

static LB_NEXT_AT: AtomicU64 = AtomicU64::new(0);

/// Move load from the most loaded to the least loaded domain, by telling
/// recently active tasks of the former to go to the latter. They move the next
/// time they are enqueued.
fn load_balance(now: u64) -> Option<()> {
    let mut loads: Vec<(u64, &Domain)> = domains().iter().map(|dom| (dom.load(now), dom)).collect();
    loads.sort_unstable_by_key(|&(load, _)| load);

    let (&(min_load, pull), &(max_load, push)) = (loads.first()?, loads.last()?);

    // Leave an imbalance of less than 10% of the average alone.
    let avg = loads.iter().map(|&(load, _)| load).sum::<u64>() / loads.len() as u64;
    let mut to_xfer = (max_load - min_load) / 2;
    if push.id == pull.id || to_xfer * 10 < avg {
        return None;
    }

    let nr_active = min(push.active_idx.swap(0, Relaxed) as usize, MAX_DOM_ACTIVE_TPTRS);
    push.active_gen.fetch_add(1, Relaxed);

    let mut candidates: Vec<(u64, &TaskCtx)> = push.active_pids[..nr_active].iter()
        .filter_map(|pid| TASK_CTXS.get_pid(pid.load(Relaxed)))
        .filter(|taskc| {
            taskc.target_dom == push.id && !taskc.is_kworker && taskc.dom_mask & 1 << pull.id != 0
        })
        .map(|taskc| {
            let load = taskc.dcyc_rd.read(now, half_life()) * taskc.weight as u64 >> RAVG_FRAC_BITS;
            (load, taskc)
        })
        .collect();

    // The heaviest tasks that fit first.
    candidates.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    for (load, taskc) in candidates {
        if load != 0 && load <= to_xfer {
            taskc.lb_dom.store(pull.id, Relaxed);
            to_xfer -= load;
        }
    }
    Some(())
}

bpf_prog!("struct_ops/rusty_tick",
fn rusty_tick(_p: Task) {
    let now = scx_now();
    let next_at = LB_NEXT_AT.load(Relaxed);

    // The first CPU to notice that it is time does it.
    if time_before(now, next_at) ||
       LB_NEXT_AT.compare_exchange(next_at, now + LB_INTERVAL_NS.load(Relaxed), Relaxed, Relaxed).is_err() {
        return;
    }
    load_balance(now);
});

// ── Init ─────────────────────────────────────────────────────────────

fn create_domains() -> Result<Vec<Domain>> {
    let online = ScxCpumask::online();
    let dom_cpus = DOM_CPUS.load(Relaxed).max(1);
    let mut doms: Vec<Domain> = Vec::new();

    for cpu in (0..min(nr_cpu_ids() as usize, MAX_CPUS) as i32).filter(|&cpu| online.test(cpu)) {
        let node = cpu_node(cpu);

        // Room left in the last domain?
        let dom = match doms.last() {
            Some(dom) if dom.node == node && dom.cpus.weight() < dom_cpus => dom,
            _ => {
                if doms.len() == MAX_DOMS {
                    scx_error!("Max dom ID %u exceeded", MAX_DOMS);
                    return Err(EINVAL);
                }
                doms.push(Domain::new(doms.len() as u32, node));
                let dom = doms.last().ok_or(ENOMEM)?;
                dom.dsq().create(node)
                    .inspect_err(|e| scx_error!("Failed to create dsq %u (%d)", dom.id, -e.0))?;
                dom
            }
        };

        dom.cpus.set(cpu);
        ALL_CPUS.set(cpu);

        let pcpuc = lookup_pcpu_ctx(cpu).ok_or(ENOENT)?;
        pcpuc.dom_rr_cur.store(cpu as u32, Relaxed);
        pcpuc.dom_id.store(dom.id, Relaxed);
    }

    Ok(doms)
}

bpf_prog!("struct_ops.s/rusty_init",
fn rusty_init() -> Result {
    *unsafe { DOMAINS.get_mut() } = create_domains()?;
    Ok(())
});

bpf_prog!("struct_ops/rusty_exit",
fn rusty_exit(_ei: *const ScxExitInfo) {
});

scx_ops_define!(rusty_ops, name: b"rusty", flags: 0, timeout_ms: 10000,
    select_cpu: rusty_select_cpu,
    enqueue: rusty_enqueue,
    dispatch: rusty_dispatch,
    tick: rusty_tick,
    runnable: rusty_runnable,
    running: rusty_running,
    stopping: rusty_stopping,
    quiescent: rusty_quiescent,
    set_weight: rusty_set_weight,
    set_cpumask: rusty_set_cpumask,
    init_task: rusty_init_task,
    exit_task: rusty_exit_task,
    init: rusty_init,
    exit: rusty_exit,
);

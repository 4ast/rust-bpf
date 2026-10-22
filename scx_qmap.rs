// SPDX-License-Identifier: GPL-2.0
//
// scx_qmap: a simple five-level FIFO queue scheduler.
//
// There are five FIFOs. A task gets assigned to one depending on its weight.
// Each CPU round robins through the FIFOs and dispatches more from FIFOs with
// higher indices: 1 from queue0, 2 from queue1, 4 from queue2 and so on.
//
// This scheduler demonstrates:
//
// - The cid form of the sched_ext ops: CPUs are numbered by topology, sets of
//   them are cmasks that live in the arena of the scheduler.
// - Sleepable per-task storage allocation using ops.init_task().
// - Core-sched support.
// - Moving tasks between DSQs while iterating, from ops.dispatch() and timers.
// - Sub-schedulers: cids are handed out to child schedulers by cgroup weight,
//   what does not divide evenly goes round robin.
//
// Rust port of tools/sched_ext/scx_qmap.bpf.c.
// Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
// Copyright (c) 2022 Tejun Heo <tj@kernel.org>
// Copyright (c) 2022 David Vernet <dvernet@meta.com>
//
// - struct scx_cmask + cid.bpf.h            -> Cmask, same layout: the kernel
//                                              reads and writes them
// - qmap_fifo: doubly linked list + lock    -> SpinLock<BTreeMap<seq, tid>>,
//   so that ops.dequeue() is O(1)              TaskCtx has (fifo, seq)
// - slab of task_ctx with a free list,      -> TaskMap<TaskCtx>
//   pointer in task storage
// - bpf_res_spin_lock in .data              -> SpinLock in arena
// - CID_SELF, CID_NONE, CID_SHARED, slot    -> enum Owner
// - part_try_start(), part_end()            -> PartGuard
// - three maps with a timer each            -> one map, a table of functions
// - -1 and >= nr_cids for "none"            -> Option
//
// Left out: bpf_printk() (print_msgs, print_dsqs_and_events), disallow_tgid,
// UEI. The cpu.weight of a child at attach time is 100 until
// ops.cpuctl_set_weight() says otherwise (C reads task_group->scx.weight).
// SCX_ENQ_IMMED is not passed to scx_bpf_dsq_move_to_local(): that takes the v2
// kfunc. The cid override tables come from user space in C. Here
// ops.init_cids() computes them for the modes "shuffle" and "out of range".

#![no_std]
#![no_main]
#![feature(panic_can_unwind, core_intrinsics)]
#![allow(dead_code, internal_features)]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::collections::BTreeMap;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering::Relaxed};
use btf_macros::btf;
use scx_common::*;

const ONE_SEC_IN_NS: u64 = NSEC_PER_SEC;
const LOWPRI_INTV_NS: u64 = 10 * NSEC_PER_MSEC;
const SHARED_DSQ: Dsq = Dsq(0);
const HIGHPRI_DSQ: Dsq = Dsq(1);
const LOWPRI_DSQ: Dsq = Dsq(2);
/// this is what -20 maps to
const HIGHPRI_WEIGHT: u64 = 8668;

const NR_FIFOS: usize = 5;
const MAX_SUB_SCHEDS: usize = 8;
/// participants: children + self
const MAX_PARTS: usize = MAX_SUB_SCHEDS + 1;
const SCX_QMAP_MAX_CPUS: usize = 1024;
const IDLE_PICK_RETRIES: usize = 16;

const SCX_ENQ_IMMED: u64 = 1 << 33;
const SCX_ENQ_RESCUE: u64 = 1 << 34;
const SCX_DEQ_CORE_SCHED_EXEC: u64 = 1 << 32;
const SCX_OPS_TID_TO_TASK: u64 = 1 << 8;
const SCX_TASK_REENQ_REASON_MASK: u32 = 7 << 12;
const SCX_TASK_REENQ_IMMED: u32 = 2 << 12;
const SCX_TASK_REENQ_CAP: u32 = 4 << 12;
const SCX_CAP_ENQ_IMMED: u64 = 1 << 0;
const SCX_CAP_ENQ: u64 = 1 << 1;
const SCX_CAP_PREEMPT: u64 = 1 << 2;
const SCX_CAP_PERF: u64 = 1 << 3;
const ENOSPC: Errno = Errno(28);

// ── Configuration (const volatile equivalents) ───────────────────────

tunables! { "qmap",
    SLICE_NS: AtomicU64 = SCX_SLICE_DFL;
    STALL_USER_NTH: AtomicU32 = 0;
    STALL_KERNEL_NTH: AtomicU32 = 0;
    DSP_INF_LOOP_AFTER: AtomicU64 = 0;
    DSP_BATCH: AtomicU32 = 0;
    HIGHPRI_BOOSTING: AtomicBool = true;
    SUB_CGROUP_ID: AtomicU64 = 0;
    SUPPRESS_DUMP: AtomicBool = false;
    IMMED_STRESS_NTH: AtomicU32 = 0;
    MAX_TASKS: AtomicU32 = 16384;
    ROUND_ROBIN_NS: AtomicU64 = 100 * NSEC_PER_MSEC;
    /// 0: off, 1: reversed cpu -> cid mapping, 3: invalid, a cid out of range
    CID_OVERRIDE_MODE: AtomicU32 = 0;
    /// Makes the scheduler fail after that many enqueues.
    TEST_ERROR_CNT: AtomicU32 = 0;
    /// 0: off, 1: dispatch to a cid we don't hold, 2: fail init_task for
    /// "qmfail*" comms, 4: panic in the monitor timer (not in C)
    INJECT_MODE: AtomicU32 = 0;
}

const QMAP_INJ_WRONG_CID: u32 = 1;
const QMAP_INJ_INIT_FAIL: u32 = 2;
const QMAP_INJ_TIMER_PANIC: u32 = 4;

// ── kfuncs of the cid form and of sub-schedulers ─────────────────────

extern "C" {
    fn scx_bpf_nr_cids() -> u32;
    fn scx_bpf_nr_online_cids() -> u32;
    fn scx_bpf_this_cid() -> i32;
    fn scx_bpf_task_cid(p: *const task_struct) -> i32;
    fn scx_bpf_kick_cid(cid: i32, flags: u64);
    fn scx_bpf_cidperf_cap(cid: i32) -> u32;
    fn scx_bpf_cidperf_cur(cid: i32) -> u32;
    fn scx_bpf_cidperf_set(cid: i32, perf: u32) -> i32;
    fn scx_bpf_tid_to_task(tid: u64) -> *mut task_struct;
    fn scx_bpf_dsq_reenq(dsq_id: u64, reenq_flags: u64);
    fn scx_bpf_cid_override(cpu_to_cid: *const i32, cpu_to_cid_cnt: u32, shard_start: *const i32, shard_start_cnt: u32);
    fn scx_bpf_sub_dispatch(cgroup_id: u64) -> bool;
    fn scx_bpf_sub_grant(cgroup_id: u64, caps: u64, cmask: *const Cmask, denied_out: *mut Cmask) -> i32;
    fn scx_bpf_sub_revoke(cgroup_id: u64, caps: u64, cmask: *const Cmask);
    fn scx_bpf_sub_caps(cgroup_id: u64, caps: u64, out: *mut Cmask) -> i32;
    fn scx_bpf_sub_kill_bstr(cgroup_id: u64, fmt: *mut u8, data: *const u64, data_sz: u32) -> i32;
}

fn nr_cids() -> i32 { unsafe { scx_bpf_nr_cids() as i32 } }
fn this_cid() -> i32 { unsafe { scx_bpf_this_cid() } }
fn task_cid(p: Task) -> i32 { unsafe { scx_bpf_task_cid(p.as_ptr()) } }
fn kick_cid(cid: i32, flags: u64) { unsafe { scx_bpf_kick_cid(cid, flags) } }
fn local_on(cid: i32) -> u64 { SCX_DSQ_LOCAL_ON | cid as u64 }

#[btf]
pub struct sched_ext_ops {
    sub_cgroup_id: u64,
}

/// struct scx_sub_attach_args and struct scx_sub_detach_args start the same.
#[btf]
pub struct scx_sub_attach_args {
    ops: *mut sched_ext_ops,
}

// ── cmask ────────────────────────────────────────────────────────────

const CMASK_WORDS: usize = SCX_QMAP_MAX_CPUS / 64 + 1;

/// struct scx_cmask with room for SCX_QMAP_MAX_CPUS cids: the cids
/// [base, base + nr_cids). Bit n of word w stands for cid (base / 64 + w) * 64 + n.
#[repr(C)]
pub struct Cmask {
    base: AtomicU32,
    nr_cids: AtomicU32,
    alloc_words: AtomicU32,
    bits: [AtomicU64; CMASK_WORDS],
}

impl Cmask {
    const fn new() -> Cmask {
        Cmask {
            base: AtomicU32::new(0),
            nr_cids: AtomicU32::new(0),
            alloc_words: AtomicU32::new(CMASK_WORDS as u32),
            bits: [const { AtomicU64::new(0) }; CMASK_WORDS],
        }
    }

    /// An empty mask for the cids [0, nr_cids).
    fn init(&self, nr_cids: i32) {
        self.base.store(0, Relaxed);
        self.nr_cids.store(nr_cids as u32, Relaxed);
        self.alloc_words.store(CMASK_WORDS as u32, Relaxed);
        self.bits.iter().for_each(|w| w.store(0, Relaxed));
    }

    #[inline(always)]
    fn word(&self, cid: i32) -> Option<(&AtomicU64, u64)> {
        let cid = u32::try_from(cid).ok()?;
        let base = self.base.load(Relaxed);
        if cid < base || cid - base >= self.nr_cids.load(Relaxed) {
            return None;
        }
        Some((self.bits.get((cid / 64 - base / 64) as usize)?, 1 << (cid % 64)))
    }

    fn test(&self, cid: i32) -> bool { self.word(cid).is_some_and(|(w, bit)| w.load(Relaxed) & bit != 0) }
    fn set(&self, cid: i32) {
        if let Some((w, bit)) = self.word(cid) { w.fetch_or(bit, Relaxed); }
    }
    fn clear(&self, cid: i32) {
        if let Some((w, bit)) = self.word(cid) { w.fetch_and(!bit, Relaxed); }
    }
    fn test_and_clear(&self, cid: i32) -> bool {
        self.word(cid).is_some_and(|(w, bit)| w.fetch_and(!bit, Relaxed) & bit != 0)
    }

    /// For the kfuncs that take a cmask in arena.
    fn for_kfunc(&self) -> *mut Cmask { self as *const Cmask as *mut Cmask }

    /// The words of the mask, 0 beyond the last one in use. A mask that the
    /// kernel made has no more storage than it needs: there is something else
    /// where `bits` goes on.
    fn words(&self) -> impl Iterator<Item = u64> + '_ {
        let in_use = (self.base.load(Relaxed) % 64 + self.nr_cids.load(Relaxed)).div_ceil(64) as usize;
        self.bits.iter().enumerate().map(move |(i, w)| if i < in_use { w.load(Relaxed) } else { 0 })
    }

    fn weight(&self) -> u32 { self.words().map(u64::count_ones).sum() }

    /// self = f(self, other), 64 cids at a time. All masks have base 0: ours do,
    /// and so do the ones that the kernel makes for the root scheduler.
    fn combine(&self, other: &Cmask, f: impl Fn(u64, u64) -> u64) {
        for (dst, src) in self.bits.iter().zip(other.words()) {
            dst.store(f(dst.load(Relaxed), src), Relaxed);
        }
    }
    fn copy_from(&self, other: &Cmask) { self.combine(other, |_, o| o) }
    fn and(&self, other: &Cmask) { self.combine(other, |s, o| s & o) }
    fn andnot(&self, other: &Cmask) { self.combine(other, |s, o| s & !o) }

    fn intersects(&self, other: &Cmask) -> bool {
        self.words().zip(other.words()).any(|(a, b)| a & b != 0)
    }

    /// The first cid at or after @start, wrapping around, that is in all masks.
    fn next_set_wrap(masks: &[&Cmask], start: i32) -> Option<i32> {
        let nr = nr_cids();
        let in_all = |cid: &i32| masks.iter().all(|m| m.test(*cid));
        let start = start.clamp(0, nr);
        (start..nr).find(in_all).or_else(|| (0..start).find(in_all))
    }
}

// ── Statistics ───────────────────────────────────────────────────────

macro_rules! stats {
    ($($name:ident,)*) => {
        #[allow(non_snake_case)]
        pub struct Stats { $(pub $name: AtomicU64,)* }
        #[export_name = "qmap_stats"]
        pub static STATS: Stats = Stats { $($name: AtomicU64::new(0),)* };
    };
}

stats! {
    nr_enqueued, nr_dispatched, nr_reenqueued, nr_reenqueued_cid0, nr_dequeued, nr_ddsp_from_enq,
    nr_core_sched_execed, nr_expedited_local, nr_expedited_remote, nr_expedited_lost,
    nr_expedited_from_timer, nr_highpri_queued, nr_reenq_cap, nr_reenq_immed, nr_inject_attempts,
    nr_rescue_dsp, cpuperf_min, cpuperf_avg, cpuperf_max, cpuperf_target_min, cpuperf_target_avg,
    cpuperf_target_max, nr_sub_scheds, self_alloc_ns, alloc_ts, alloc_window_ns,
}

fn inc(stat: &AtomicU64) { stat.fetch_add(1, Relaxed); }
fn dec(stat: &AtomicU64) { stat.fetch_sub(1, Relaxed); }

/// `!(++cnt % nth)` of C: true every @nth time, never if @nth is 0.
fn every_nth(cnt: &AtomicU32, nth: u32) -> bool { nth != 0 && (cnt.fetch_add(1, Relaxed) + 1) % nth == 0 }

// ── Sets of cids ─────────────────────────────────────────────────────

/// cids this node runs its own tasks on
static SELF_CIDS: Cmask = Cmask::new();
/// cids with caps in effect on the cpu
static AVAIL_CIDS: Cmask = Cmask::new();
/// self_cids & avail_cids, placeable right now
static USABLE_CIDS: Cmask = Cmask::new();
/// idle state of all cids regardless of delegation
static IDLE_CIDS: Cmask = Cmask::new();
/// the shared pool, as a mask for grant and revoke
static RR_CIDS: Cmask = Cmask::new();
static PREV_RR_CIDS: Cmask = Cmask::new();
static TO_REVOKE_CIDS: Cmask = Cmask::new();
static TO_GRANT_CIDS: Cmask = Cmask::new();
static USABLE_SCRATCH: Cmask = Cmask::new();
/// cids held exclusively (ENQ): delegatable
static HELD_EXCL: Cmask = Cmask::new();
/// cids held shared (ENQ_IMMED only): self-local
static HELD_SHARED: Cmask = Cmask::new();
/// per cid: held shared, so only SCX_ENQ_IMMED works
static CID_SHARED: Cmask = Cmask::new();

fn needs_immed(cid: i32) -> u64 { if CID_SHARED.test(cid) { SCX_ENQ_IMMED } else { 0 } }

// ── Per-cid and per-task context, the FIFOs ──────────────────────────

struct CpuCtx {
    /// dispatch index
    dsp_idx: AtomicU64,
    /// remaining count
    dsp_cnt: AtomicU64,
    avg_weight: AtomicU64,
    cpuperf_target: AtomicU32,
}

static CPU_CTXS: [CpuCtx; SCX_QMAP_MAX_CPUS] = [const {
    CpuCtx {
        dsp_idx: AtomicU64::new(0),
        dsp_cnt: AtomicU64::new(0),
        avg_weight: AtomicU64::new(0),
        cpuperf_target: AtomicU32::new(0),
    }
}; SCX_QMAP_MAX_CPUS];

fn cpu_ctx(cid: i32) -> Option<&'static CpuCtx> { CPU_CTXS.get(usize::try_from(cid).ok()?) }

/// CPUs are throttled to a quarter of their performance per level.
const fn qidx_to_cpuperf_target(idx: usize) -> u32 { (SCX_CPUPERF_ONE as usize * idx / 4) as u32 }

struct TaskCtx {
    /// Which FIFO the task is in and at which position.
    queued: Option<(usize, u64)>,
    tid: u64,
    pid: i32,
    /// Dispatch directly to local_dsq
    force_local: bool,
    highpri: bool,
    core_sched_seq: u64,
    cpus_allowed: Cmask,
}

static TASK_CTXS: TaskMap<TaskCtx> = TaskMap::new();

fn lookup_task_ctx(p: Task) -> Option<&'static mut TaskCtx> { TASK_CTXS.get(p) }

/// The tids in the order in which they were queued.
struct Fifo {
    tasks: BTreeMap<u64, (u64, i32)>,
    next_seq: u64,
}

static FIFOS: [SpinLock<Fifo>; NR_FIFOS] =
    [const { SpinLock::new(Fifo { tasks: BTreeMap::new(), next_seq: 0 }) }; NR_FIFOS];

/// Per-queue sequence numbers to implement core-sched ordering. Tail seq is
/// assigned to each queued task and incremented. Head seq tracks the sequence
/// number of the latest dispatched task.
static CORE_SCHED_HEAD_SEQS: [AtomicU64; NR_FIFOS] = [const { AtomicU64::new(0) }; NR_FIFOS];
static CORE_SCHED_TAIL_SEQS: [AtomicU64; NR_FIFOS] = [const { AtomicU64::new(0) }; NR_FIFOS];

fn next_core_sched_seq(idx: usize) -> u64 { CORE_SCHED_TAIL_SEQS.get(idx).map_or(0, |seq| seq.fetch_add(1, Relaxed)) }

fn fifo_enqueue(idx: usize, taskc: &mut TaskCtx) {
    let Some(fifo) = FIFOS.get(idx) else { return };
    let mut fifo = fifo.lock();
    let seq = fifo.next_seq;
    fifo.next_seq += 1;
    fifo.tasks.insert(seq, (taskc.tid, taskc.pid));
    taskc.queued = Some((idx, seq));
}

/// The tid and the pid of the task that waits the longest.
fn fifo_pop(idx: usize) -> Option<(u64, i32)> { Some(FIFOS.get(idx)?.lock().tasks.pop_first()?.1) }

fn fifo_remove(taskc: &mut TaskCtx) {
    if let Some((fifo, seq)) = taskc.queued.take().and_then(|(idx, seq)| Some((FIFOS.get(idx)?, seq))) {
        fifo.lock().tasks.remove(&seq);
    }
}

fn weight_to_idx(weight: u64) -> usize {
    // Coarsely map the compound weight to a FIFO.
    match weight {
        0..=25 => 0,
        26..=50 => 1,
        51..=199 => 2,
        200..=399 => 3,
        _ => 4,
    }
}

// ── Callbacks ────────────────────────────────────────────────────────

/// An idle cid that the task can be dispatched to right away. The idle bit is
/// claimed.
fn pick_direct_dispatch_cid(prev_cid: i32, taskc: &TaskCtx) -> Option<i32> {
    if USABLE_CIDS.test(prev_cid) && IDLE_CIDS.test_and_clear(prev_cid) {
        return Some(prev_cid);
    }

    // Somebody else may claim the cid between the search and the claim.
    let mut cid = prev_cid;
    for _ in 0..IDLE_PICK_RETRIES {
        cid = Cmask::next_set_wrap(&[&taskc.cpus_allowed, &IDLE_CIDS, &USABLE_CIDS], cid + 1)?;
        if IDLE_CIDS.test_and_clear(cid) {
            return Some(cid);
        }
    }
    None
}

/// Tasks with the lowest weight go through LOWPRI_DSQ.
fn is_lowpri(p: Task) -> bool { p.weight() < 2 && !p.is_kthread() }

bpf_prog!("struct_ops/qmap_select_cid",
fn qmap_select_cid(p: Task, prev_cid: i32, _wake_flags: u64) -> i32 {
    let Some(taskc) = lookup_task_ctx(p) else { return prev_cid };

    if is_lowpri(p) {
        return prev_cid;
    }

    match pick_direct_dispatch_cid(prev_cid, taskc) {
        Some(cid) => {
            taskc.force_local = true;
            cid
        }
        None => prev_cid,
    }
});

/// A cid that we hold in no way.
fn first_unavail_cid() -> Option<i32> { (0..nr_cids()).find(|&c| !HELD_EXCL.test(c) && !HELD_SHARED.test(c)) }

/// None of the cids of the task is ours: hand it to the kernel.
fn rescue_cid(taskc: &TaskCtx) -> Option<i32> {
    if taskc.cpus_allowed.intersects(&SELF_CIDS) {
        return None;
    }
    Cmask::next_set_wrap(&[&taskc.cpus_allowed], 0)
}

bpf_prog!("struct_ops/qmap_enqueue",
fn qmap_enqueue(p: Task, enq_flags: u64) {
    static USER_CNT: AtomicU32 = AtomicU32::new(0);
    static KERNEL_CNT: AtomicU32 = AtomicU32::new(0);
    static INJ_CNT: AtomicU32 = AtomicU32::new(0);
    static IMMED_STRESS_CNT: AtomicU32 = AtomicU32::new(0);

    let idx = weight_to_idx(p.weight());
    let slice_ns = SLICE_NS.load(Relaxed);
    let reenq = enq_flags & SCX_ENQ_REENQ != 0;

    if reenq {
        inc(&STATS.nr_reenqueued);
        if task_cid(p) == 0 {
            inc(&STATS.nr_reenqueued_cid0);
        }
        match p.scx_flags() & SCX_TASK_REENQ_REASON_MASK {
            SCX_TASK_REENQ_CAP => inc(&STATS.nr_reenq_cap),
            SCX_TASK_REENQ_IMMED => inc(&STATS.nr_reenq_immed),
            _ => (),
        }
    }

    // Lose a task every now and then, to see the watchdog work.
    let (cnt, nth) = if p.is_kthread() { (&KERNEL_CNT, &STALL_KERNEL_NTH) } else { (&USER_CNT, &STALL_USER_NTH) };
    if every_nth(cnt, nth.load(Relaxed)) {
        return;
    }

    if TEST_ERROR_CNT.load(Relaxed) != 0 && TEST_ERROR_CNT.fetch_sub(1, Relaxed) == 1 {
        scx_error!("test triggering error");
    }

    let Some(taskc) = lookup_task_ctx(p) else { return };

    // All enqueued tasks must have their core_sched_seq updated for correct
    // core-sched ordering. Also, take a look at the end of qmap_dispatch().
    taskc.core_sched_seq = next_core_sched_seq(idx);

    if let Some(cid) = rescue_cid(taskc) {
        taskc.force_local = false;
        inc(&STATS.nr_rescue_dsp);
        p.dsq_insert(local_on(cid), slice_ns, enq_flags | SCX_ENQ_RESCUE);
        return;
    }

    // Fault injection: dispatch to a cid that we don't hold.
    if INJECT_MODE.load(Relaxed) == QMAP_INJ_WRONG_CID && p.nr_cpus_allowed() > 1 && !reenq
        && every_nth(&INJ_CNT, 64) {
        if let Some(bad) = first_unavail_cid().filter(|&bad| taskc.cpus_allowed.test(bad)) {
            inc(&STATS.nr_inject_attempts);
            inc(&STATS.nr_rescue_dsp);
            p.dsq_insert(local_on(bad), slice_ns, enq_flags | SCX_ENQ_RESCUE);
            return;
        }
    }

    // IMMED stress testing: every nth enqueue goes to the local DSQ of a CPU
    // that is likely busy.
    if !reenq && every_nth(&IMMED_STRESS_CNT, IMMED_STRESS_NTH.load(Relaxed)) {
        taskc.force_local = false;
        p.dsq_insert(local_on(task_cid(p)), slice_ns, enq_flags);
        return;
    }

    // If qmap_select_cid() is telling us to or this is the last runnable task
    // on the CPU, enqueue locally.
    if taskc.force_local {
        taskc.force_local = false;
        p.dsq_insert(SCX_DSQ_LOCAL, slice_ns, enq_flags | needs_immed(task_cid(p)));
        return;
    }

    // The lowest priority waits until the timer reenqueues it.
    if is_lowpri(p) && !reenq {
        p.dsq_insert(LOWPRI_DSQ.0, slice_ns, enq_flags);
        return;
    }

    // If select_cid() is not called, try direct dispatch here.
    if enq_flags & SCX_ENQ_CPU_SELECTED == 0 {
        if let Some(cid) = pick_direct_dispatch_cid(task_cid(p), taskc) {
            inc(&STATS.nr_ddsp_from_enq);
            p.dsq_insert(local_on(cid), slice_ns, enq_flags | needs_immed(cid));
            return;
        }
    }

    // If the task was re-enqueued due to the CPU being preempted by a higher
    // priority scheduling class, just re-enqueue the task directly on the
    // global DSQ. As we want another CPU to pick it up, find and kick an idle
    // CPU.
    if reenq {
        p.dsq_insert(SHARED_DSQ.0, 0, enq_flags);
        if let Some(cid) = Cmask::next_set_wrap(&[&taskc.cpus_allowed, &IDLE_CIDS, &USABLE_CIDS], 0) {
            kick_cid(cid, SCX_KICK_IDLE);
        }
        return;
    }

    fifo_enqueue(idx, taskc);

    if HIGHPRI_BOOSTING.load(Relaxed) && p.weight() >= HIGHPRI_WEIGHT {
        taskc.highpri = true;
        inc(&STATS.nr_highpri_queued);
    }
    inc(&STATS.nr_enqueued);
});

bpf_prog!("struct_ops/qmap_dequeue",
fn qmap_dequeue(p: Task, deq_flags: u64) {
    inc(&STATS.nr_dequeued);
    if deq_flags & SCX_DEQ_CORE_SCHED_EXEC != 0 {
        inc(&STATS.nr_core_sched_execed);
    }

    if let Some(taskc) = lookup_task_ctx(p).filter(|taskc| taskc.queued.is_some()) {
        if taskc.highpri {
            dec(&STATS.nr_highpri_queued);
        }
        fifo_remove(taskc);
    }
});

/// Where a high priority task found in HIGHPRI_DSQ goes.
enum Expedite { To(i32), Rescue(i32), Skip }

fn expedite_target(taskc: &TaskCtx, this_cid: i32) -> Expedite {
    if taskc.cpus_allowed.test(this_cid) && USABLE_CIDS.test(this_cid) {
        return Expedite::To(this_cid);
    }
    if let Some(cid) = Cmask::next_set_wrap(&[&taskc.cpus_allowed, &USABLE_CIDS], this_cid + 1) {
        return Expedite::To(cid);
    }
    rescue_cid(taskc).map_or(Expedite::Skip, Expedite::Rescue)
}

/// To demonstrate the use of scx_bpf_dsq_move(), implement silly selective
/// priority boosting mechanism by scanning SHARED_DSQ looking for highpri tasks,
/// moving them to HIGHPRI_DSQ and then consuming them first. This makes minor
/// difference only when dsp_batch is larger than 1.
///
/// Returns whether a task was moved to the local DSQ of this CPU.
#[inline(never)]
fn scan_shared_dsq(from_timer: bool) -> bool {
    static HIGHPRI_SEQ: AtomicU64 = AtomicU64::new(0);
    let this_cid = this_cid();
    let slice_ns = SLICE_NS.load(Relaxed);

    {
        let mut state = DsqIterState::new();
        let mut it = state.iter(SHARED_DSQ, 0);
        while let Some(p) = it.next() {
            let Some(taskc) = lookup_task_ctx(p) else { return false };

            if let Some(cid) = rescue_cid(taskc) {
                inc(&STATS.nr_rescue_dsp);
                it.move_to(p, Dsq(local_on(cid)), SCX_ENQ_RESCUE);
            } else if taskc.highpri {
                // exercise the set_*() and vtime interface too
                it.set_slice(slice_ns * 2);
                it.set_vtime(HIGHPRI_SEQ.fetch_add(1, Relaxed));
                it.move_vtime_to(p, HIGHPRI_DSQ, 0);
            }
        }
    }

    // Scan HIGHPRI_DSQ and dispatch until a task that can run on this CPU is
    // found.
    let mut state = DsqIterState::new();
    let mut it = state.iter(HIGHPRI_DSQ, 0);
    while let Some(p) = it.next() {
        let Some(taskc) = lookup_task_ctx(p) else { return false };

        match expedite_target(taskc, this_cid) {
            Expedite::Skip => (),
            Expedite::Rescue(cid) => {
                inc(&STATS.nr_rescue_dsp);
                it.move_to(p, Dsq(local_on(cid)), SCX_ENQ_RESCUE);
            }
            Expedite::To(cid) => {
                if !it.move_to(p, Dsq(local_on(cid)), SCX_ENQ_PREEMPT | needs_immed(cid)) {
                    inc(&STATS.nr_expedited_lost);
                    continue;
                }
                inc(if cid == this_cid { &STATS.nr_expedited_local } else { &STATS.nr_expedited_remote });
                if from_timer {
                    inc(&STATS.nr_expedited_from_timer);
                }
                if cid == this_cid {
                    return true;
                }
            }
        }
    }
    false
}

/// Moves up to a batch of tasks from the FIFOs to SHARED_DSQ. Returns whether
/// the batch is full, i.e. whether it is time to consume.
fn fill_shared_dsq(cid: i32, cpuc: &CpuCtx) -> bool {
    let slice_ns = SLICE_NS.load(Relaxed);
    let mut batch = DSP_BATCH.load(Relaxed).max(1);

    for _ in 0..NR_FIFOS {
        // Advance the dispatch cursor and pick the fifo.
        if cpuc.dsp_cnt.load(Relaxed) == 0 {
            let idx = (cpuc.dsp_idx.load(Relaxed) + 1) % NR_FIFOS as u64;
            cpuc.dsp_idx.store(idx, Relaxed);
            cpuc.dsp_cnt.store(1 << idx, Relaxed);
        }
        let idx = cpuc.dsp_idx.load(Relaxed) as usize;

        // Dispatch or advance.
        while let Some((tid, _pid)) = fifo_pop(idx) {
            let Some(p) = Task::from_ptr(unsafe { scx_bpf_tid_to_task(tid) }) else { continue };
            let Some(taskc) = lookup_task_ctx(p) else { continue };
            taskc.queued = None;

            if taskc.highpri {
                dec(&STATS.nr_highpri_queued);
            }
            if let Some(head) = CORE_SCHED_HEAD_SEQS.get(weight_to_idx(p.weight())) {
                head.store(taskc.core_sched_seq, Relaxed);
            }
            inc(&STATS.nr_dispatched);

            p.dsq_insert(SHARED_DSQ.0, slice_ns, 0);

            // If the task cannot run here, somebody else has to take it.
            if !taskc.cpus_allowed.test(cid) {
                kick_cid(task_cid(p), 0);
            }

            batch -= 1;
            let left = cpuc.dsp_cnt.fetch_sub(1, Relaxed) - 1;
            if batch == 0 || dispatch_nr_slots() == 0 {
                return true;
            }
            if left == 0 {
                break;
            }
        }

        cpuc.dsp_cnt.store(0, Relaxed);
    }
    false
}

bpf_prog!("struct_ops/qmap_dispatch",
fn qmap_dispatch(cid: i32, prev: Option<Task>) {
    if scan_shared_dsq(false) {
        return;
    }

    // A cid that was handed to a child, for good or for this round, is the
    // child's to fill.
    match PART.owner(cid) {
        Owner::Shared => {
            if let Some(holder_cgid) = PART.rr_holder() {
                unsafe { scx_bpf_sub_dispatch(holder_cgid) };
                return;
            }
        }
        Owner::Child(slot) => {
            if let Some((ssc, cgid)) = SUB_SCHEDS.get(slot).and_then(|ssc| Some((ssc, ssc.cgid()?))) {
                if unsafe { scx_bpf_sub_dispatch(cgid) } {
                    inc(&ssc.nr_dsps);
                }
                return;
            }
        }
        Owner::Own | Owner::Nobody => (),
    }

    if STATS.nr_highpri_queued.load(Relaxed) == 0 && SHARED_DSQ.move_to_local() {
        return;
    }

    // PID 2 should be kthreadd which should mostly be idle and off the
    // scheduler. Let's keep dispatching it to force the kernel to call this
    // function over and over again.
    let inf_loop_after = DSP_INF_LOOP_AFTER.load(Relaxed);
    if inf_loop_after != 0 && STATS.nr_dispatched.load(Relaxed) > inf_loop_after {
        if let Some(p) = TaskRef::from_pid(2) {
            p.dsq_insert(SCX_DSQ_LOCAL, SLICE_NS.load(Relaxed), 0);
            return;
        }
    }

    let Some(cpuc) = cpu_ctx(this_cid()) else { return };

    let full = fill_shared_dsq(cid, cpuc);
    if scan_shared_dsq(false) || (full && SHARED_DSQ.move_to_local()) {
        return;
    }

    // No other tasks. @prev will keep running. Update its core_sched_seq as if
    // the task were enqueued and dispatched immediately.
    match prev {
        Some(prev) => {
            if let Some(taskc) = lookup_task_ctx(prev) {
                taskc.core_sched_seq = next_core_sched_seq(weight_to_idx(prev.weight()));
            }
        }
        None => IDLE_CIDS.set(cid),
    }
});

bpf_prog!("struct_ops/qmap_tick",
fn qmap_tick(p: Task) {
    let Some(cpuc) = cpu_ctx(this_cid()) else { return };

    // Use the running avg of weights to select the target cpuperf level. This
    // is a demonstration of the cpuperf feature rather than a practical
    // strategy to regulate CPU frequency.
    let avg_weight = cpuc.avg_weight.load(Relaxed) * 3 / 4 + p.weight() / 4;
    cpuc.avg_weight.store(avg_weight, Relaxed);
    let target = qidx_to_cpuperf_target(weight_to_idx(avg_weight));
    cpuc.cpuperf_target.store(target, Relaxed);

    unsafe { scx_bpf_cidperf_set(task_cid(p), target) };
});

/// The distance from the head of the queue scaled by the weight of the queue.
/// The lower the number, the older the task and the higher the priority.
fn task_qdist(p: Task, taskc: &TaskCtx) -> i64 {
    let idx = weight_to_idx(p.weight());
    let head = CORE_SCHED_HEAD_SEQS.get(idx).map_or(0, |seq| seq.load(Relaxed));
    let qdist = taskc.core_sched_seq.wrapping_sub(head) as i64;

    // As queue index increments, the priority doubles. The queue w/ index 3 is
    // dispatched twice more frequently than 2. Reflect the difference by
    // scaling qdists accordingly. Note that the shift amount needs to be
    // flipped depending on the sign to avoid flipping priority direction.
    if qdist >= 0 { qdist << (4 - idx) } else { qdist << idx }
}

/// This is called to determine the task ordering when core-sched is picking
/// tasks to execute on SMT siblings and should encode about the same ordering as
/// the regular scheduling path. Use the priority-scaled distances from the head
/// of the queues to compare the two tasks which should be consistent with the
/// dispatch path behavior.
bpf_prog!("struct_ops/qmap_core_sched_before",
fn qmap_core_sched_before(a: Task, b: Task) -> i32 {
    match (lookup_task_ctx(a), lookup_task_ctx(b)) {
        (Some(taskc_a), Some(taskc_b)) => (task_qdist(a, taskc_a) < task_qdist(b, taskc_b)) as i32,
        _ => 0,
    }
});

bpf_prog!("struct_ops.s/qmap_init_task",
fn qmap_init_task(p: Task, _args: InitTaskArgs) -> Result {
    if INJECT_MODE.load(Relaxed) == QMAP_INJ_INIT_FAIL && p.comm().starts_with(b"qmfail") {
        return Err(ENOMEM);
    }

    let max_tasks = MAX_TASKS.load(Relaxed);
    if with_irqs_off(|| TASK_CTXS.len()) >= max_tasks as usize {
        scx_error!("task_ctx slab exhausted (max_tasks=%u)", max_tasks);
        return Err(ENOMEM);
    }

    // ops.set_cmask() fills in cpus_allowed before the task is enqueued.
    let taskc = TaskCtx {
        queued: None,
        tid: p.tid(),
        pid: p.pid(),
        force_local: false,
        highpri: false,
        core_sched_seq: 0,
        cpus_allowed: Cmask::new(),
    };
    taskc.cpus_allowed.init(nr_cids());
    TASK_CTXS.insert(p, taskc);
    Ok(())
});

bpf_prog!("struct_ops/qmap_exit_task",
fn qmap_exit_task(p: Task, _args: *const u8) {
    TASK_CTXS.remove(p);
});

bpf_prog!("struct_ops/qmap_dump",
fn qmap_dump(_dctx: *const u8) {
    if SUPPRESS_DUMP.load(Relaxed) {
        return;
    }

    for (i, fifo) in FIFOS.iter().enumerate() {
        let _ = write!(ScxDump, "QMAP FIFO[{}]:", i);
        for (tid, pid) in fifo.lock().tasks.values().take(4096) {
            let _ = write!(ScxDump, " {}:{}", pid, tid);
        }
        let _ = writeln!(ScxDump);
    }

    // Not in C: what the kernel and the partition made of the cids.
    let _ = writeln!(ScxDump, "QMAP: held_excl={} held_shared={} self={} avail={} usable={} idle={}",
                     HELD_EXCL.weight(), HELD_SHARED.weight(), SELF_CIDS.weight(), AVAIL_CIDS.weight(),
                     USABLE_CIDS.weight(), IDLE_CIDS.weight());
});

bpf_prog!("struct_ops/qmap_dump_cid",
fn qmap_dump_cid(_dctx: *const u8, cid: i32, idle: bool) {
    if SUPPRESS_DUMP.load(Relaxed) || idle {
        return;
    }
    if let Some(cpuc) = cpu_ctx(cid) {
        let _ = write!(ScxDump, "QMAP: dsp_idx={} dsp_cnt={} avg_weight={} cpuperf_target={}",
                       cpuc.dsp_idx.load(Relaxed), cpuc.dsp_cnt.load(Relaxed),
                       cpuc.avg_weight.load(Relaxed), cpuc.cpuperf_target.load(Relaxed));
    }
});

bpf_prog!("struct_ops/qmap_dump_task",
fn qmap_dump_task(_dctx: *const u8, p: Task) {
    if SUPPRESS_DUMP.load(Relaxed) {
        return;
    }
    if let Some(taskc) = lookup_task_ctx(p) {
        let _ = write!(ScxDump, "QMAP: force_local={} core_sched_seq={} nr_allowed={}",
                       taskc.force_local as u32, taskc.core_sched_seq, taskc.cpus_allowed.weight());
    }
});

bpf_prog!("struct_ops/qmap_cpuctl_set_weight",
fn qmap_cpuctl_set_weight(cgrp: Cgroup, weight: u32) {
    let cgid = cgrp.id();

    if let Some(ssc) = SUB_SCHEDS.iter().find(|ssc| ssc.cgid() == Some(cgid)) {
        if ssc.weight.swap(weight, Relaxed) != weight {
            redistribute();
        }
    }
});

bpf_prog!("struct_ops/qmap_update_idle",
fn qmap_update_idle(cid: i32, idle: bool) {
    if idle { IDLE_CIDS.set(cid) } else { IDLE_CIDS.clear(cid) }
});

/// The kernel writes the mask to the arena of the scheduler and passes its
/// address.
bpf_prog!("struct_ops/qmap_set_cmask",
fn qmap_set_cmask(p: Task, cmask: *const Cmask) {
    if let Some(taskc) = lookup_task_ctx(p) {
        taskc.cpus_allowed.copy_from(unsafe { &*cmask });
    }
});

// ── Timers ───────────────────────────────────────────────────────────

/// Print out the min, avg and max performance levels of CPUs every second to
/// demonstrate the cpuperf interface.
fn monitor_cpuperf() {
    #[derive(Clone, Copy)]
    struct MinSumMax { min: u64, sum: u64, max: u64 }
    impl MinSumMax {
        fn add(self, v: u64, weighted: u64) -> Self {
            MinSumMax { min: self.min.min(v), sum: self.sum + weighted, max: self.max.max(v) }
        }
    }
    let zero = MinSumMax { min: SCX_CPUPERF_ONE, sum: 0, max: 0 };

    let nr_online = unsafe { scx_bpf_nr_online_cids() } as u64;
    let (cur, target, cap_sum) = (0..nr_online as i32).zip(&CPU_CTXS).fold((zero, zero, 0), |(cur, target, cap_sum), (cid, cpuc)| {
        let cap = unsafe { scx_bpf_cidperf_cap(cid) } as u64;
        let perf = unsafe { scx_bpf_cidperf_cur(cid) } as u64;
        let t = cpuc.cpuperf_target.load(Relaxed) as u64;

        // $cur is relative to $cap. Scale it down accordingly so that it is in
        // the same scale as other CPUs and $cur_sum/$cap_sum makes sense.
        (cur.add(perf, perf * cap / SCX_CPUPERF_ONE), target.add(t, t), cap_sum + cap)
    });

    if let (Some(cur_avg), Some(target_avg)) = ((cur.sum * SCX_CPUPERF_ONE).checked_div(cap_sum), target.sum.checked_div(nr_online)) {
        STATS.cpuperf_min.store(cur.min, Relaxed);
        STATS.cpuperf_avg.store(cur_avg, Relaxed);
        STATS.cpuperf_max.store(cur.max, Relaxed);
        STATS.cpuperf_target_min.store(target.min, Relaxed);
        STATS.cpuperf_target_avg.store(target_avg, Relaxed);
        STATS.cpuperf_target_max.store(target.max, Relaxed);
    }
}

fn monitor_timerfn() {
    if INJECT_MODE.load(Relaxed) == QMAP_INJ_TIMER_PANIC {
        panic!("injected");
    }

    {
        let _rcu = rcu_read_lock();
        scan_shared_dsq(true);
    }
    monitor_cpuperf();
}

/// Reenqueue the tasks in LOWPRI_DSQ every 10 msec.
fn lowpri_timerfn() { unsafe { scx_bpf_dsq_reenq(LOWPRI_DSQ.0, 0) } }

fn round_robin_timerfn() { rr_advance() }

struct QmapTimer {
    /// None: ROUND_ROBIN_NS
    interval_ns: Option<u64>,
    run: fn(),
}

impl QmapTimer {
    fn interval_ns(&self) -> u64 { self.interval_ns.unwrap_or_else(|| ROUND_ROBIN_NS.load(Relaxed)) }
}

const NR_TIMERS: usize = 3;

static QMAP_TIMERS: [QmapTimer; NR_TIMERS] = [
    QmapTimer { interval_ns: Some(ONE_SEC_IN_NS), run: monitor_timerfn },
    QmapTimer { interval_ns: Some(LOWPRI_INTV_NS), run: lowpri_timerfn },
    QmapTimer { interval_ns: None, run: round_robin_timerfn },
];

bpf_timer_map!(qmap_timer_data, timers, NR_TIMERS);

extern "C" fn timer_cb(_map: *mut u8, key: *mut u32, timer: *mut bpf_timer) -> i32 {
    let Some(t) = QMAP_TIMERS.get(unsafe { *key } as usize) else { return 0 };

    if !catch_panic!(t.run) {
        scx_error!("panic in a timer function");
    }

    if Timer::from_ptr(timer).is_none_or(|timer| timer.start(t.interval_ns(), 0).is_err()) {
        scx_error!("failed to re-arm timer");
    }
    0
}

// ── Sub-schedulers: who gets which cids ──────────────────────────────

/// Who runs tasks on a cid.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// this scheduler
    Own,
    /// not ours to use
    Nobody,
    /// in the pool that goes round robin
    Shared,
    /// the child in that slot
    Child(usize),
}

impl From<i32> for Owner {
    fn from(v: i32) -> Owner {
        match v {
            -1 => Owner::Own,
            -3 => Owner::Shared,
            slot if slot >= 0 && (slot as usize) < MAX_SUB_SCHEDS => Owner::Child(slot as usize),
            _ => Owner::Nobody,
        }
    }
}

impl From<Owner> for i32 {
    fn from(owner: Owner) -> i32 {
        match owner {
            Owner::Own => -1,
            Owner::Nobody => -2,
            Owner::Shared => -3,
            Owner::Child(slot) => slot as i32,
        }
    }
}

struct SubSched {
    /// 0: the slot is free
    cgroup_id: AtomicU64,
    /// cpu.weight
    weight: AtomicU32,
    nr_dsps: AtomicU64,
    /// how long it had how many cids
    alloc_ns: AtomicU64,
    /// cids granted exclusively to this child
    granted_cids: Cmask,
    /// last grant, for delta calculation
    prev_granted: Cmask,
}

impl SubSched {
    fn cgid(&self) -> Option<u64> { Some(self.cgroup_id.load(Relaxed)).filter(|&cgid| cgid != 0) }
    /// 0 for a free slot
    fn share_weight(&self) -> u64 {
        self.cgid().map_or(0, |_| match self.weight.load(Relaxed) { 0 => 100, w => w as u64 })
    }
}

static SUB_SCHEDS: [SubSched; MAX_SUB_SCHEDS] = [const {
    SubSched {
        cgroup_id: AtomicU64::new(0),
        weight: AtomicU32::new(100),
        nr_dsps: AtomicU64::new(0),
        alloc_ns: AtomicU64::new(0),
        granted_cids: Cmask::new(),
        prev_granted: Cmask::new(),
    }
}; MAX_SUB_SCHEDS];

struct Partition {
    /// number of cids held exclusively, which can be delegated
    nr_excl: AtomicU32,
    cid_owner: [AtomicI32; SCX_QMAP_MAX_CPUS],
    /// number of cids in RR_CIDS
    nr_shared: AtomicU32,
    /// rotation order: cgroup id of the holder, 0 = self
    rr_slots: [AtomicU64; MAX_PARTS],
    nr_rr: AtomicU32,
    rr_pos: AtomicU32,
}

static PART: Partition = Partition {
    nr_excl: AtomicU32::new(0),
    cid_owner: [const { AtomicI32::new(-2) }; SCX_QMAP_MAX_CPUS],
    nr_shared: AtomicU32::new(0),
    rr_slots: [const { AtomicU64::new(0) }; MAX_PARTS],
    nr_rr: AtomicU32::new(0),
    rr_pos: AtomicU32::new(0),
};

impl Partition {
    fn owner(&self, cid: i32) -> Owner {
        usize::try_from(cid).ok().and_then(|cid| self.cid_owner.get(cid)).map_or(Owner::Nobody, |o| o.load(Relaxed).into())
    }

    fn set_owner(&self, cid: i32, owner: Owner) {
        if let Some(o) = usize::try_from(cid).ok().and_then(|cid| self.cid_owner.get(cid)) {
            o.store(owner.into(), Relaxed);
        }
    }

    /// The child that has the shared pool right now. None: we have.
    fn rr_holder(&self) -> Option<u64> {
        self.rr_slots.get(self.rr_pos.load(Relaxed) as usize).map(|slot| slot.load(Relaxed)).filter(|&cgid| cgid != 0)
    }
}

const PART_REFRESH: u64 = 1 << 0;
const PART_REDISTRIBUTE: u64 = 1 << 1;

static PART_BUSY: AtomicBool = AtomicBool::new(false);
static PART_PENDING: AtomicU64 = AtomicU64::new(0);

/// Only one CPU at a time works on the partition. The others leave a note in
/// PART_PENDING.
struct PartGuard(());

impl PartGuard {
    fn try_start() -> Option<PartGuard> { (!PART_BUSY.swap(true, Relaxed)).then_some(PartGuard(())) }
}

impl Drop for PartGuard {
    fn drop(&mut self) { PART_BUSY.store(false, Relaxed) }
}

fn read_held_caps() {
    unsafe {
        scx_bpf_sub_caps(0, SCX_CAP_ENQ, HELD_EXCL.for_kfunc());
        scx_bpf_sub_caps(0, SCX_CAP_ENQ_IMMED, HELD_SHARED.for_kfunc());
    }
    HELD_SHARED.andnot(&HELD_EXCL);
}

impl PartGuard {
    /// Divides the cids that we hold exclusively among ourselves and the
    /// children in proportion to the weights. Everybody gets a contiguous range.
    /// What is left over is the shared pool.
    #[inline(never)]
    fn compute_partition(&self) {
        read_held_caps();

        PART.nr_shared.store(0, Relaxed);
        PART.nr_rr.store(0, Relaxed);
        PART.rr_pos.store(0, Relaxed);
        let nr_excl = HELD_EXCL.weight() as u64;
        PART.nr_excl.store(nr_excl as u32, Relaxed);

        let not_excl = |cid: i32| if HELD_SHARED.test(cid) { Owner::Own } else { Owner::Nobody };

        // Nothing to hand out.
        if nr_excl == 0 {
            (0..nr_cids()).for_each(|cid| PART.set_owner(cid, not_excl(cid)));
            return;
        }

        // The participants and where their ranges end.
        let weights = || core::iter::once((Owner::Own, 100))
            .chain(SUB_SCHEDS.iter().enumerate().map(|(slot, ssc)| (Owner::Child(slot), ssc.share_weight())));
        let sum_w: u64 = weights().map(|(_, w)| w).sum();
        let ranges = || weights().scan(0, |end, (owner, w)| {
            *end += nr_excl * w / sum_w.max(1);
            Some((owner, *end))
        });
        let total_excl = ranges().last().map_or(0, |(_, end)| end);

        // The rotation: we, then the children.
        let holders = core::iter::once(0).chain(SUB_SCHEDS.iter().filter_map(SubSched::cgid));
        let nr_rr = PART.rr_slots.iter().zip(holders).map(|(slot, cgid)| slot.store(cgid, Relaxed)).count();

        RR_SCRATCH.init(nr_cids());
        let mut n = 0;
        for cid in 0..nr_cids() {
            if !HELD_EXCL.test(cid) {
                PART.set_owner(cid, not_excl(cid));
                continue;
            }
            let owner = ranges().find(|&(_, end)| n < end).map(|(owner, _)| owner);
            if owner.is_none() {
                RR_SCRATCH.set(cid);
            }
            PART.set_owner(cid, owner.unwrap_or(Owner::Shared));
            n += 1;
        }

        PART.nr_shared.store((nr_excl - total_excl) as u32, Relaxed);
        PART.nr_rr.store(nr_rr as u32, Relaxed);
    }

    /// Charges the time since the last call to whoever had the cids.
    #[inline(never)]
    fn account_alloc(&self) {
        let now = now();
        let last = STATS.alloc_ts.swap(now, Relaxed);
        if last == 0 {
            return;
        }
        let delta = now - last;
        STATS.alloc_window_ns.fetch_add(delta, Relaxed);

        let rr_owner = match PART.rr_holder() {
            Some(cgid) if PART.nr_shared.load(Relaxed) != 0 && PART.nr_rr.load(Relaxed) != 0 => {
                SUB_SCHEDS.iter().position(|ssc| ssc.cgid() == Some(cgid)).map_or(Owner::Nobody, Owner::Child)
            }
            _ => Owner::Own,
        };

        for cid in 0..nr_cids() {
            match Some(PART.owner(cid)).map(|o| if o == Owner::Shared { rr_owner } else { o }) {
                Some(Owner::Child(slot)) => {
                    if let Some(ssc) = SUB_SCHEDS.get(slot) {
                        ssc.alloc_ns.fetch_add(delta, Relaxed);
                    }
                }
                Some(Owner::Own) => { STATS.self_alloc_ns.fetch_add(delta, Relaxed); }
                _ => (),
            }
        }
    }

    /// Readers must never see a mask that is half done.
    fn refresh_usable(&self) {
        USABLE_SCRATCH.copy_from(&SELF_CIDS);
        USABLE_SCRATCH.and(&AVAIL_CIDS);
        USABLE_CIDS.copy_from(&USABLE_SCRATCH);
    }

    /// Tells the kernel: revokes what a child no longer has, grants what is new.
    #[inline(never)]
    fn apply_partition(&self) {
        const EXCL_CAPS: u64 = SCX_CAP_ENQ | SCX_CAP_PREEMPT | SCX_CAP_ENQ_IMMED | SCX_CAP_PERF;
        const SHARED_CAPS: u64 = SCX_CAP_ENQ_IMMED | SCX_CAP_PERF;
        let nr_cids = nr_cids();

        if PART.nr_excl.load(Relaxed) == 0 {
            SELF_CIDS.copy_from(&HELD_SHARED);
            self.refresh_usable();
            for cgid in SUB_SCHEDS.iter().filter_map(SubSched::cgid) {
                static FMT: BpfCell<[u8; 39]> = BpfCell::new(*b"parent holds no excl cpu to distribute\0");
                let args = [0u64];
                unsafe { scx_bpf_sub_kill_bstr(cgid, FMT.0.get() as *mut u8, args.as_ptr(), 8) };
            }
            return;
        }

        PREV_RR_CIDS.copy_from(&RR_CIDS);
        RR_CIDS.copy_from(&RR_SCRATCH);
        SELF_CIDS.init(nr_cids);
        for ssc in &SUB_SCHEDS {
            ssc.prev_granted.copy_from(&ssc.granted_cids);
            ssc.granted_cids.init(nr_cids);
        }

        for cid in 0..nr_cids {
            match PART.owner(cid) {
                Owner::Child(slot) => {
                    if let Some(ssc) = SUB_SCHEDS.get(slot) {
                        ssc.granted_cids.set(cid);
                    }
                }
                Owner::Own => SELF_CIDS.set(cid),
                Owner::Shared | Owner::Nobody => (),
            }
        }
        self.refresh_usable();

        for (ssc, cgid) in SUB_SCHEDS.iter().filter_map(|ssc| Some((ssc, ssc.cgid()?))) {
            TO_REVOKE_CIDS.copy_from(&ssc.prev_granted);
            TO_REVOKE_CIDS.andnot(&ssc.granted_cids);
            TO_GRANT_CIDS.copy_from(&ssc.granted_cids);
            TO_GRANT_CIDS.andnot(&ssc.prev_granted);

            unsafe {
                scx_bpf_sub_revoke(cgid, SHARED_CAPS, PREV_RR_CIDS.for_kfunc());
                scx_bpf_sub_revoke(cgid, EXCL_CAPS, TO_REVOKE_CIDS.for_kfunc());
                scx_bpf_sub_grant(cgid, EXCL_CAPS, TO_GRANT_CIDS.for_kfunc(), core::ptr::null_mut());
            }
        }

        if PART.nr_shared.load(Relaxed) != 0 {
            if let Some(holder_cgid) = PART.rr_holder() {
                unsafe { scx_bpf_sub_grant(holder_cgid, SHARED_CAPS, RR_CIDS.for_kfunc(), core::ptr::null_mut()) };
            }
        }
    }
}

/// The shared pool that compute_partition() found.
static RR_SCRATCH: Cmask = Cmask::new();

/// Does what was asked for in PART_PENDING, including what is asked for while
/// it is at it.
fn execute_partition() {
    for _ in 0..1024 {
        let Some(part) = PartGuard::try_start() else { break };

        let pending = PART_PENDING.swap(0, Relaxed);
        if pending & PART_REDISTRIBUTE != 0 {
            part.account_alloc();
            part.compute_partition();
            part.apply_partition();
        } else if pending & PART_REFRESH != 0 {
            part.refresh_usable();
        }
        drop(part);

        if PART_PENDING.load(Relaxed) == 0 {
            break;
        }
    }
}

fn redistribute() {
    PART_PENDING.fetch_or(PART_REDISTRIBUTE, Relaxed);
    execute_partition();
}

/// In C user space writes to qa.inject_mode.
bpf_prog!("syscall",
fn qmap_set_inject_mode(mode: u32) {
    INJECT_MODE.store(mode, Relaxed);
});

/// For user space: brings the accounting up to date.
bpf_prog!("syscall",
fn qmap_flush_alloc(_ctx: *const u8) {
    if let Some(part) = PartGuard::try_start() {
        part.account_alloc();
        drop(part);
        execute_partition();
    }
});

/// The shared pool goes to the next in the rotation.
fn rr_advance() {
    const SHARED_CAPS: u64 = SCX_CAP_ENQ_IMMED | SCX_CAP_PERF;
    let Some(part) = PartGuard::try_start() else { return };

    let nr_rr = PART.nr_rr.load(Relaxed);
    if PART.nr_shared.load(Relaxed) != 0 && nr_rr >= 2 {
        part.account_alloc();

        let old_cgid = PART.rr_holder();
        PART.rr_pos.store((PART.rr_pos.load(Relaxed) + 1) % nr_rr, Relaxed);
        let new_cgid = PART.rr_holder();

        if let Some(cgid) = old_cgid {
            unsafe { scx_bpf_sub_revoke(cgid, SHARED_CAPS, RR_CIDS.for_kfunc()) };
        }
        if let Some(cgid) = new_cgid {
            unsafe { scx_bpf_sub_grant(cgid, SHARED_CAPS, RR_CIDS.for_kfunc(), core::ptr::null_mut()) };
        }
    }
    drop(part);
    execute_partition();
}

fn sub_cgroup_id(args: *const scx_sub_attach_args) -> u64 {
    let ops = *unsafe { &*args }.ops().get().unwrap();
    *unsafe { &*ops }.sub_cgroup_id().get().unwrap()
}

bpf_prog!("struct_ops/qmap_sub_attach",
fn qmap_sub_attach(args: *const scx_sub_attach_args) -> Result {
    if HELD_EXCL.weight() == 0 {
        return Err(ENOSPC);
    }

    let ssc = SUB_SCHEDS.iter().find(|ssc| ssc.cgid().is_none()).ok_or(ENOSPC)?;
    ssc.cgroup_id.store(sub_cgroup_id(args), Relaxed);
    ssc.weight.store(100, Relaxed);
    inc(&STATS.nr_sub_scheds);
    redistribute();
    Ok(())
});

bpf_prog!("struct_ops/qmap_sub_detach",
fn qmap_sub_detach(args: *const scx_sub_attach_args) {
    let cgid = sub_cgroup_id(args);

    if let Some(ssc) = SUB_SCHEDS.iter().find(|ssc| ssc.cgid() == Some(cgid)) {
        ssc.cgroup_id.store(0, Relaxed);
        ssc.weight.store(100, Relaxed);
        ssc.granted_cids.init(nr_cids());
        dec(&STATS.nr_sub_scheds);
        redistribute();
    }
});

/// What our parent lets us do has changed.
bpf_prog!("struct_ops/qmap_sub_caps_updated",
fn qmap_sub_caps_updated(_cmask: *const Cmask, _caps: u64) {
    redistribute();
});

/// What we can do on @cid right now has changed.
bpf_prog!("struct_ops/qmap_sub_ecaps_updated",
fn qmap_sub_ecaps_updated(cid: i32, _before: u64, after: u64) {
    let avail = after & SCX_CAP_ENQ_IMMED != 0;

    if avail && after & SCX_CAP_ENQ == 0 { CID_SHARED.set(cid) } else { CID_SHARED.clear(cid) }
    if avail { AVAIL_CIDS.set(cid) } else { AVAIL_CIDS.clear(cid) }

    PART_PENDING.fetch_or(PART_REFRESH, Relaxed);
    execute_partition();
});

// ── Init ─────────────────────────────────────────────────────────────

static CID_OVERRIDE_CPU_TO_CID: [AtomicI32; SCX_QMAP_MAX_CPUS] = [const { AtomicI32::new(0) }; SCX_QMAP_MAX_CPUS];
static CID_OVERRIDE_SHARD_START: [AtomicI32; 1] = [const { AtomicI32::new(0) }; 1];

bpf_prog!("struct_ops.s/qmap_init_cids",
fn qmap_init_cids() -> Result {
    let nr_cpu_ids = nr_cpu_ids();
    let mode = CID_OVERRIDE_MODE.load(Relaxed);

    if mode == 0 {
        return Ok(());
    }
    if nr_cpu_ids as usize > SCX_QMAP_MAX_CPUS {
        scx_error!("nr_cpu_ids=%u exceeds SCX_QMAP_MAX_CPUS=%d", nr_cpu_ids, SCX_QMAP_MAX_CPUS);
        return Err(EINVAL);
    }

    // Reversed. In mode 3 the first one is beyond the end.
    for (cpu, cid) in (0..nr_cpu_ids as i32).zip(&CID_OVERRIDE_CPU_TO_CID) {
        cid.store(nr_cpu_ids as i32 - 1 - cpu + (mode == 3 && cpu == 0) as i32, Relaxed);
    }
    unsafe {
        scx_bpf_cid_override(CID_OVERRIDE_CPU_TO_CID.as_ptr() as *const i32, nr_cpu_ids,
                             CID_OVERRIDE_SHARD_START.as_ptr() as *const i32, 1);
    }
    Ok(())
});

bpf_prog!("struct_ops.s/qmap_init",
fn qmap_init() -> Result {
    let nr_cids = nr_cids();

    if nr_cids as usize > SCX_QMAP_MAX_CPUS {
        scx_error!("nr_cids=%u exceeds SCX_QMAP_MAX_CPUS=%d", nr_cids, SCX_QMAP_MAX_CPUS);
        return Err(EINVAL);
    }
    if MAX_TASKS.load(Relaxed) == 0 {
        scx_error!("max_tasks must be > 0");
        return Err(EINVAL);
    }

    [
        &IDLE_CIDS, &RR_CIDS, &PREV_RR_CIDS, &RR_SCRATCH, &SELF_CIDS, &AVAIL_CIDS, &USABLE_CIDS, &TO_REVOKE_CIDS,
        &TO_GRANT_CIDS, &USABLE_SCRATCH, &HELD_EXCL, &HELD_SHARED, &CID_SHARED,
    ].into_iter()
        .chain(SUB_SCHEDS.iter().flat_map(|ssc| [&ssc.granted_cids, &ssc.prev_granted]))
        .for_each(|mask| mask.init(nr_cids));

    read_held_caps();

    // The root scheduler has everything. A sub-scheduler waits for grants.
    let is_root = SUB_CGROUP_ID.load(Relaxed) == 0;
    for cid in 0..nr_cids {
        if is_root {
            SELF_CIDS.set(cid);
            AVAIL_CIDS.set(cid);
            USABLE_CIDS.set(cid);
        }
        PART.set_owner(cid, if is_root { Owner::Own } else { Owner::Nobody });
    }

    for dsq in [SHARED_DSQ, HIGHPRI_DSQ, LOWPRI_DSQ] {
        dsq.create(-1).inspect_err(|err| scx_error!("failed to create DSQ %d (%d)", dsq.0, err.0))?;
    }

    QMAP_TIMERS.iter().zip(0u32..).try_for_each(|(t, id)| {
        timers().init(id, CLOCK_MONOTONIC, timer_cb)?.start(t.interval_ns(), 0)
    })
});

bpf_prog!("struct_ops/qmap_exit",
fn qmap_exit(_ei: *const ScxExitInfo) {
    timers().cancel_all();
});

scx_ops_cid_define!(qmap_ops, name: b"qmap",
    flags: SCX_OPS_ENQ_EXITING | SCX_OPS_TID_TO_TASK,
    timeout_ms: 5000,
    select_cid: qmap_select_cid,
    enqueue: qmap_enqueue,
    dequeue: qmap_dequeue,
    dispatch: qmap_dispatch,
    tick: qmap_tick,
    core_sched_before: qmap_core_sched_before,
    set_cmask: qmap_set_cmask,
    update_idle: qmap_update_idle,
    init_task: qmap_init_task,
    exit_task: qmap_exit_task,
    dump: qmap_dump,
    dump_cid: qmap_dump_cid,
    dump_task: qmap_dump_task,
    cpuctl_set_weight: qmap_cpuctl_set_weight,
    sub_attach: qmap_sub_attach,
    sub_detach: qmap_sub_detach,
    sub_caps_updated: qmap_sub_caps_updated,
    sub_ecaps_updated: qmap_sub_ecaps_updated,
    init_cids: qmap_init_cids,
    init: qmap_init,
    exit: qmap_exit,
);

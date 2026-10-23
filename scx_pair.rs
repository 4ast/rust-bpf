// SPDX-License-Identifier: GPL-2.0
//
// scx_pair: a demo core-scheduler which always makes every sibling CPU pair
// execute from the same CPU cgroup.
//
// Each CPU in the system is paired with exactly one other CPU. Paired CPUs
// always schedule tasks from the same cgroup, and synchronize with each other
// to guarantee that this constraint is not violated.
//
// A cgroup has a FIFO of runnable tasks. A cgroup with runnable tasks is in the
// top level FIFO. A pair picks a cgroup from there and runs its tasks for a
// batch duration. Then it drains: the CPU that gets there first waits until the
// other one has stopped too, and only then the next cgroup is picked. When a
// higher scheduling class takes one CPU of a pair, the other one is kicked out
// and waits.
//
// Rust port of tools/sched_ext/scx_pair.bpf.c.
// Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
// Copyright (c) 2022 Tejun Heo <tj@kernel.org>
// Copyright (c) 2022 David Vernet <dvernet@meta.com>
//
// - pair_cpu[], pair_id[], in_pair_idx[]     -> Vec<Cpu>
// - pair_ctx (array map, bpf_spin_lock)      -> Vec<SpinLock<PairCtx>>
// - top_q (queue map)                        -> SpinLock<VecDeque<u64>>
// - cgrp_q_arr (array of queue maps),        -> Vec<CgrpQ>
//   cgrp_q_len[], cgrp_q_idx_busy[]
// - cgrp_q_idx_hash (hash map)               -> SpinLock<BTreeMap<u64, usize>>
// - -EAGAIN, -ENOENT, goto out_maybe_kick    -> enum Outcome
//
// User space pairs the CPUs in C. Here ops.init() does: CPU i goes with CPU
// i + STRIDE, by default half the number of CPUs.

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use scx_common::*;

const MAX_QUEUED: usize = 4096;
const MAX_CGRPS: usize = 4096;
const MAX_RT_PRIO: i32 = 100;
const SCX_DSQ_GLOBAL: u64 = (1 << 63) | 1;
const SCX_KICK_WAIT: u64 = 1 << 2;

tunables! { "pair",
    /// a pair of CPUs stay on a cgroup for this duration
    PAIR_BATCH_DUR_NS: AtomicU64 = SCX_SLICE_DFL;
    /// 0: half the number of CPUs
    STRIDE: AtomicU32 = 0;
}

// ── Statistics ───────────────────────────────────────────────────────

macro_rules! stats {
    ($($name:ident,)*) => { $(
        #[export_name = concat!("pair_", stringify!($name))]
        #[allow(non_upper_case_globals)]
        static $name: AtomicU64 = AtomicU64::new(0);
    )* };
}

stats! {
    nr_total, nr_dispatched, nr_missing, nr_kicks, nr_preemptions,
    nr_exps, nr_exp_waits, nr_exp_empty,
    nr_cgrp_next, nr_cgrp_coll, nr_cgrp_empty,
}

fn inc(stat: &AtomicU64) { stat.fetch_add(1, Relaxed); }

// ── CPUs and pairs ───────────────────────────────────────────────────

struct Cpu {
    /// the other CPU of the pair
    pair_cpu: i32,
    pair_id: usize,
    /// the bit of this CPU in the masks of the pair
    in_pair_mask: u32,
}

/// The state that the two CPUs of a pair share.
#[derive(Default)]
struct PairCtx {
    /// the cgroup the pair is currently executing
    cgid: u64,
    /// the pair started executing the current cgroup at
    started_at: u64,
    /// whether the current cgroup is draining
    draining: bool,
    /// the CPUs that are currently active on the cgroup
    active_mask: u32,
    /// the CPUs that are currently preempted and running tasks in a different
    /// scheduler
    preempted_mask: u32,
}

impl PairCtx {
    /// A higher scheduling class gave the CPU back. Returns how to kick the
    /// other CPU, which may have been waiting for that.
    fn cpu_acquire(&mut self, in_pair_mask: u32) -> Option<u64> {
        self.preempted_mask &= !in_pair_mask;
        (self.preempted_mask == 0).then_some(SCX_KICK_PREEMPT)
    }

    /// A higher scheduling class took the CPU. The other CPU must stop running
    /// the cgroup before the newcomer starts.
    fn cpu_release(&mut self, in_pair_mask: u32) -> Option<u64> {
        self.preempted_mask |= in_pair_mask;
        self.active_mask &= !in_pair_mask;
        self.draining = true;
        (self.active_mask != 0).then_some(SCX_KICK_PREEMPT | SCX_KICK_WAIT)
    }
}

static CPUS: BpfCell<Vec<Cpu>> = BpfCell::new(Vec::new());
static PAIRS: BpfCell<Vec<SpinLock<PairCtx>>> = BpfCell::new(Vec::new());

fn lookup_pair(cpu: i32) -> Option<(&'static Cpu, &'static SpinLock<PairCtx>)> {
    let cpuc = CPUS.get().get(usize::try_from(cpu).ok()?)?;
    Some((cpuc, PAIRS.get().get(cpuc.pair_id)?))
}

fn kick_pair(cpuc: &Cpu, flags: u64) {
    inc(&nr_kicks);
    kick_cpu(cpuc.pair_cpu, flags);
}

// ── Queues ───────────────────────────────────────────────────────────

/// The runnable tasks of a cgroup.
struct CgrpQ {
    busy: AtomicBool,
    /// Decremented before a task is taken out: who gets to decrement it has a
    /// task coming.
    len: AtomicU64,
    pids: SpinLock<VecDeque<i32>>,
}

/// The cgroups that have runnable tasks.
static TOP_Q: SpinLock<VecDeque<u64>> = SpinLock::new(VecDeque::new());
static CGRP_QS: BpfCell<Vec<CgrpQ>> = BpfCell::new(Vec::new());
static CGRP_Q_IDX: SpinLock<BTreeMap<u64, usize>> = SpinLock::new(BTreeMap::new());
static CGRP_Q_IDX_CURSOR: AtomicU32 = AtomicU32::new(0);

fn lookup_cgrp_q(cgid: u64) -> Option<&'static CgrpQ> {
    let q_idx = *CGRP_Q_IDX.lock().get(&cgid)?;
    CGRP_QS.get().get(q_idx)
}

/// bpf_map_push_elem() on a queue map: fails when the queue is full.
fn push<T>(q: &SpinLock<VecDeque<T>>, v: T, max: usize) -> bool {
    let mut q = q.lock();
    if q.len() >= max {
        return false;
    }
    q.push_back(v);
    true
}

bpf_prog!("struct_ops/pair_enqueue",
fn pair_enqueue(p: Task, _enq_flags: u64) {
    inc(&nr_total);

    let cgid = p.cgroup().id();

    // find the cgroup's q and push @p into it
    let Some(cgq) = lookup_cgrp_q(cgid) else {
        scx_error!("failed to lookup q_idx for cgroup[%llu]", cgid);
        return;
    };
    if !push(&cgq.pids, p.pid(), MAX_QUEUED) {
        scx_error!("cgroup[%llu] queue overflow", cgid);
        return;
    }

    // bump q len, if going 0 -> 1, queue cgroup into the top_q
    if cgq.len.fetch_add(1, Relaxed) == 0 && !push(&TOP_Q, cgid, 4 * MAX_CGRPS) {
        scx_error!("top_q overflow");
    }
});

// ── Dispatch ─────────────────────────────────────────────────────────

enum Outcome {
    /// A task was dispatched, or there is nothing to do.
    Done,
    /// The same, and the other CPU has to look at the state of the pair.
    KickPair,
    /// -EAGAIN
    Again,
}

/// The next cgroup with runnable tasks. It stays in the queue.
fn pick_next_cgroup() -> Option<u64> {
    loop {
        let cgid = TOP_Q.lock().pop_front()?;

        // This is the only place where empty cgroups are taken off the top_q.
        if lookup_cgrp_q(cgid).is_some_and(|cgq| cgq.len.load(Relaxed) > 0) {
            // If it has any tasks, requeue as we may race and not execute it.
            push(&TOP_Q, cgid, 4 * MAX_CGRPS);
            return Some(cgid);
        }
    }
}

/// Reserves a task of the queue.
fn claim_task(cgq: &CgrpQ) -> bool {
    cgq.len.fetch_update(Relaxed, Relaxed, |len| len.checked_sub(1)).is_ok()
}

#[inline(never)]
fn try_dispatch(cpu: i32) -> Outcome {
    let now = scx_now();
    let mut outcome = Outcome::Done;

    let Some((cpuc, pair)) = lookup_pair(cpu) else {
        scx_error!("failed to lookup pairc and in_pair_mask for cpu[%d]", cpu);
        return Outcome::Done;
    };
    let in_pair_mask = cpuc.in_pair_mask;

    let mut pairc = pair.lock();
    pairc.active_mask &= !in_pair_mask;

    let expired = time_before(pairc.started_at + PAIR_BATCH_DUR_NS.load(Relaxed), now);
    if expired || pairc.draining {
        inc(&nr_exps);

        // We're done with the current cgid. An obvious optimization would be
        // not draining if the next cgroup is the current one. For now, be dumb
        // and always expire.
        pairc.draining = true;

        let pair_preempted = pairc.preempted_mask != 0;
        if pairc.active_mask != 0 || pair_preempted {
            // The other CPU is still active, or is no longer under our control
            // due to e.g. being preempted by a higher priority sched_class. We
            // want to wait until this cgroup expires, or until control of our
            // pair CPU has been returned to us.
            //
            // If the pair controls its CPU, and the time already expired, kick.
            // When the other CPU arrives at dispatch and clears its active
            // mask, it'll push the pair to the next cgroup and kick this CPU.
            inc(&nr_exp_waits);
            return if expired && !pair_preempted { Outcome::KickPair } else { Outcome::Done };
        }
        drop(pairc);

        // Pick the next cgroup. It'd be easier / cleaner to not drop the lock
        // but the queues have locks of their own.
        let Some(new_cgid) = pick_next_cgroup() else {
            // no active cgroup, go idle
            inc(&nr_exp_empty);
            return Outcome::Done;
        };

        pairc = pair.lock();

        // The other CPU may already have started on a new cgroup while we
        // dropped the lock. Make sure that we're still draining and start on
        // the new cgroup.
        if pairc.draining && pairc.active_mask == 0 {
            inc(&nr_cgrp_next);
            pairc.cgid = new_cgid;
            pairc.started_at = now;
            pairc.draining = false;
            outcome = Outcome::KickPair;
        } else {
            inc(&nr_cgrp_coll);
        }
    }

    let cgid = pairc.cgid;
    pairc.active_mask |= in_pair_mask;
    drop(pairc);

    // again, it'd be better to do all these with the lock held, oh well
    let Some(cgq) = lookup_cgrp_q(cgid) else {
        scx_error!("failed to lookup q_idx for cgroup[%llu]", cgid);
        return Outcome::Done;
    };

    // claim one task from cgrp_q w/ q_idx
    if !claim_task(cgq) {
        // the cgroup must be empty, expire and repeat
        inc(&nr_cgrp_empty);
        let mut pairc = pair.lock();
        pairc.draining = true;
        pairc.active_mask &= !in_pair_mask;
        return Outcome::Again;
    }

    let Some(pid) = cgq.pids.lock().pop_front() else {
        scx_error!("cgq_map is empty for cgroup[%llu]", cgid);
        return Outcome::Done;
    };

    match TaskRef::from_pid(pid) {
        Some(p) => {
            inc(&nr_dispatched);
            // Task cgroup migration can leave a task in the queue of a cgroup
            // that it is no longer in. Ignored here.
            p.dsq_insert(SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
            outcome
        }
        None => {
            // we don't handle dequeues, retry on lost tasks
            inc(&nr_missing);
            Outcome::Again
        }
    }
}

bpf_prog!("struct_ops/pair_dispatch",
fn pair_dispatch(cpu: i32, _prev: Option<Task>) {
    loop {
        match try_dispatch(cpu) {
            Outcome::Again => continue,
            Outcome::Done => break,
            Outcome::KickPair => {
                if let Some((cpuc, _)) = lookup_pair(cpu) {
                    kick_pair(cpuc, SCX_KICK_PREEMPT);
                }
                break;
            }
        }
    }
});

// ── Preemption by higher scheduling classes ──────────────────────────

fn is_highpri(p: Task) -> bool { p.prio() < MAX_RT_PRIO }

bpf_prog!("tp_btf/sched_switch",
fn pair_sched_switch(_preempt: bool, prev: Task, next: Task, _prev_state: u32) -> i32 {
    let Some((cpuc, pair)) = lookup_pair(this_cpu()) else { return 0 };
    let in_pair_mask = cpuc.in_pair_mask;

    let preempted = pair.lock().preempted_mask & in_pair_mask != 0;
    let next_highpri = next.pid() != 0 && is_highpri(next);

    let kick_flags = if next_highpri {
        // From one of ours to a higher class: the CPU is taken from us.
        if preempted || prev.pid() == 0 || is_highpri(prev) {
            return 0;
        }
        inc(&nr_preemptions);
        pair.lock().cpu_release(in_pair_mask)
    } else {
        if !preempted {
            return 0;
        }
        pair.lock().cpu_acquire(in_pair_mask)
    };

    if let Some(kick_flags) = kick_flags {
        kick_pair(cpuc, kick_flags);
    }
    0
});

// ── cgroups ──────────────────────────────────────────────────────────

bpf_prog!("struct_ops/pair_cgroup_init",
fn pair_cgroup_init(cgrp: Cgroup, _args: CgroupInitArgs) -> Result {
    let cgid = cgrp.id();
    let qs = CGRP_QS.get();

    // Find a free queue, starting after the one that was handed out last.
    let (q_idx, cgq) = (0..qs.len())
        .map(|_| CGRP_Q_IDX_CURSOR.fetch_add(1, Relaxed) as usize % qs.len().max(1))
        .filter_map(|q_idx| Some((q_idx, qs.get(q_idx)?)))
        .find(|(_, cgq)| !cgq.busy.swap(true, Relaxed))
        .ok_or(EBUSY)?;

    let _ = cgq;
    CGRP_Q_IDX.with_irqs_off(|idx| idx.insert(cgid, q_idx));
    Ok(())
});

bpf_prog!("struct_ops/pair_cgroup_exit",
fn pair_cgroup_exit(cgrp: Cgroup) {
    let cgid = cgrp.id();

    if let Some(cgq) = CGRP_Q_IDX.with_irqs_off(|idx| idx.remove(&cgid)).and_then(|q_idx| CGRP_QS.get().get(q_idx)) {
        cgq.busy.store(false, Relaxed);
    }
});

// ── Init ─────────────────────────────────────────────────────────────

/// What scx_pair.c does before it loads the scheduler.
fn pair_up(nr_cpus: usize, stride: usize) -> Result<Vec<Cpu>> {
    let mut pair_of: Vec<Option<usize>> = Vec::new();
    pair_of.resize(nr_cpus, None);

    for i in 0..nr_cpus {
        if pair_of.get(i).copied().flatten().is_some() {
            continue;
        }
        let j = (i + stride) % nr_cpus;
        if i == j {
            scx_error!("Invalid stride %d - CPU%d wants to be its own pair", stride, i);
            return Err(EINVAL);
        }
        if pair_of.get(j).copied().flatten().is_some() {
            scx_error!("Invalid stride %d - three CPUs (%d, %d, ...) want to be a pair", stride, i, j);
            return Err(EINVAL);
        }
        for (cpu, other) in [(i, j), (j, i)] {
            if let Some(slot) = pair_of.get_mut(cpu) {
                *slot = Some(other);
            }
        }
    }

    // The pairs are numbered by their first CPU.
    let firsts = || pair_of.iter().enumerate().filter(|(cpu, other)| other.is_some_and(|other| *cpu < other));
    Ok(pair_of.iter().enumerate().filter_map(|(cpu, other)| {
        let other = (*other)?;
        let first = cpu.min(other);
        Some(Cpu {
            pair_cpu: other as i32,
            pair_id: firsts().position(|(c, _)| c == first)?,
            in_pair_mask: 1 << (cpu > other) as u32,
        })
    }).collect())
}

bpf_prog!("struct_ops.s/pair_init",
fn pair_init() -> Result {
    let nr_cpus = nr_cpu_ids() as usize;
    let stride = match STRIDE.load(Relaxed) { 0 => nr_cpus / 2, stride => stride as usize };
    if nr_cpus < 2 || stride == 0 {
        scx_error!("Invalid stride %d, must be positive", stride);
        return Err(EINVAL);
    }

    let cpus = pair_up(nr_cpus, stride)?;
    let pairs = (0..nr_cpus / 2).map(|_| SpinLock::new(PairCtx::default())).collect();
    let qs = (0..MAX_CGRPS).map(|_| CgrpQ {
        busy: AtomicBool::new(false),
        len: AtomicU64::new(0),
        pids: SpinLock::new(VecDeque::new()),
    }).collect();

    unsafe {
        *CPUS.get_mut() = cpus;
        *PAIRS.get_mut() = pairs;
        *CGRP_QS.get_mut() = qs;
    }
    Ok(())
});

bpf_prog!("struct_ops/pair_exit",
fn pair_exit(_ei: *const ScxExitInfo) {
});

scx_ops_define!(pair_ops, name: b"pair",
    flags: 0,
    timeout_ms: 0,
    enqueue: pair_enqueue,
    dispatch: pair_dispatch,
    cgroup_init: pair_cgroup_init,
    cgroup_exit: pair_cgroup_exit,
    init: pair_init,
    exit: pair_exit,
);

// SPDX-License-Identifier: GPL-2.0
//
// scx_flatcg: a demo sched_ext flattened cgroup hierarchy scheduler. It
// implements hierarchical weight-based cgroup CPU control by flattening the
// cgroup hierarchy into a single layer by compounding the active weight share
// at each level. Consider the following hierarchy with weights in parentheses:
//
// R + A (100) + B (100)
//   |         \ C (100)
//   \ D (200)
//
// Ignoring the root and threaded cgroups, only B, C and D can contain tasks.
// Let's say all three have runnable tasks. The total share that each of these
// three cgroups is entitled to can be calculated by compounding its share at
// each level.
//
// For example, B is competing against C and in that competition its share is
// 100/(100+100) == 1/2. At its parent level, A is competing against D and A's
// share in that competition is 100/(200+100) == 1/3. B's eventual share in the
// system can be calculated by multiplying the two shares, 1/2 * 1/3 == 1/6. C's
// eventual shaer is the same at 1/6. D is only competing at the top level and
// its share is 200/(100+200) == 2/3.
//
// So, instead of hierarchically scheduling level-by-level, we can consider it
// as B, C and D competing each other with respective share of 1/6, 1/6 and 2/3
// and keep updating the eventual shares as the cgroups' runnable states change.
//
// Rust port of tools/sched_ext/scx_flatcg.bpf.c.
//
// - BPF_MAP_TYPE_CGRP_STORAGE       -> SpinLock<BTreeMap<u64, Arc<CgrpCtx>>>
// - bpf_cgroup_ancestor() per level -> every CgrpCtx holds an Arc of its parent.
//                                      Up the tree: iter::successors(). Down
//                                      from the root: recursion.
// - bpf_rb_root cgv_tree            -> BinaryHeap<Reverse<CgvNode>>: only the
//                                      first node is ever taken out
// - cgv_node_stash (hash of kptrs)  -> SpinLock<Option<CgvNode>> in CgrpCtx.
//                                      bpf_kptr_xchg(NULL) is take().
// - bpf_cgroup_from_id()            -> not needed, contexts are found by id
// - BPF_MAP_TYPE_TASK_STORAGE       -> TaskMap<TaskCtx>
// - UEI is dropped

#![no_std]
#![no_main]
#![feature(panic_can_unwind)]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::collections::{BTreeMap, BinaryHeap};
use alloc::sync::Arc;
use core::cmp::Reverse;
use core::iter;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering::Relaxed};
use scx_common::*;

const FALLBACK_DSQ: Dsq = Dsq(0);
const CGROUP_MAX_RETRIES: u32 = 1024;
const FCG_HWEIGHT_ONE: u64 = 1 << 16;

tunables! { "flatcg",
    CGRP_SLICE_NS: AtomicU64 = SCX_SLICE_DFL;
    FIFO_SCHED: AtomicBool = false;
}

fn cgrp_slice_ns() -> u64 { CGRP_SLICE_NS.load(Relaxed) }
fn fifo_sched() -> bool { FIFO_SCHED.load(Relaxed) }

static NR_CPUS: AtomicU32 = AtomicU32::new(0);
static CVTIME_NOW: AtomicU64 = AtomicU64::new(0);
/// gets inc'd on weight tree changes to expire the cached hweights
static HWEIGHT_GEN: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
enum Stat {
    Act,
    Deact,
    Local,
    Global,
    HwtUpdates,
    HwtCache,
    HwtSkip,
    HwtRace,
    EnqSkip,
    EnqRace,
    CnsKeep,
    CnsExpire,
    CnsEmpty,
    CnsGone,
    PncNoCgrp,
    PncNext,
    PncEmpty,
    PncGone,
    PncRace,
    PncFail,
    NrStats,
}

static STATS: [AtomicU64; Stat::NrStats as usize] =
    [const { AtomicU64::new(0) }; Stat::NrStats as usize];

impl Stat {
    fn inc(self) { STATS[self as usize].fetch_add(1, Relaxed); }
}

// ── Per-CPU and per-task context ─────────────────────────────────────

struct CpuCtx {
    cur_cgid: u64,
    cur_at: u64,
}

static CPU_CTXS: [BpfCell<CpuCtx>; MAX_CPUS] =
    [const { BpfCell::new(CpuCtx { cur_cgid: 0, cur_at: 0 }) }; MAX_CPUS];

#[derive(Default)]
struct TaskCtx {
    /// The task bypassed the regular scheduling path when it had run for this
    /// long, and should be force charged to the cgroup.
    bypassed_at: Option<u64>,
}

static TASK_CTXS: TaskMap<TaskCtx> = TaskMap::new();

fn find_task_ctx(p: Task) -> Option<&'static mut TaskCtx> {
    let taskc = TASK_CTXS.get(p);
    if taskc.is_none() {
        scx_error!("task_ctx lookup failed");
    }
    taskc
}

// ── The queue of cgroups ─────────────────────────────────────────────

/// A cgroup with tasks to run, ordered by its virtual time.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct CgvNode {
    cvtime: u64,
    cgid: u64,
}

/// Also protects nr_active, weight, hweight and child_weight_sum of all the
/// cgroups, like cgv_tree_lock of C.
static CGV_TREE: SpinLock<BinaryHeap<Reverse<CgvNode>>> = SpinLock::new(BinaryHeap::new());

// ── Per-cgroup context ───────────────────────────────────────────────

struct CgrpCtx {
    cgid: u64,
    parent: Option<Arc<CgrpCtx>>,
    nr_active: AtomicU32,
    nr_runnable: AtomicU32,
    queued: AtomicBool,
    weight: AtomicU32,
    hweight: AtomicU64,
    child_weight_sum: AtomicU64,
    hweight_gen: AtomicU64,
    cvtime_delta: AtomicI64,
    tvtime_now: AtomicU64,
    /// None if the node is on the queue
    stash: SpinLock<Option<CgvNode>>,
}

type CgrpCtxs = BTreeMap<u64, Arc<CgrpCtx>>;

static CGRP_CTXS: SpinLock<CgrpCtxs> = SpinLock::new(BTreeMap::new());

/// With the lock held.
fn lookup_cgrp_ctx(cgroups: &CgrpCtxs, cgid: u64) -> Option<&Arc<CgrpCtx>> {
    let cgc = cgroups.get(&cgid);
    if cgc.is_none() {
        scx_error!("cgrp_ctx lookup failed for cgid %llu", cgid);
    }
    cgc
}

fn try_find_cgrp_ctx(cgid: u64) -> Option<Arc<CgrpCtx>> { CGRP_CTXS.lock().get(&cgid).cloned() }

fn find_cgrp_ctx(cgid: u64) -> Option<Arc<CgrpCtx>> { lookup_cgrp_ctx(&CGRP_CTXS.lock(), cgid).cloned() }

/// The context of the cgroup of a task.
fn task_cgrp_ctx(p: Task) -> Option<Arc<CgrpCtx>> {
    let cgid = p.cgroup().id();
    find_cgrp_ctx(cgid)
}

impl CgrpCtx {
    fn dsq(&self) -> Dsq { Dsq(self.cgid) }
    fn hweight(&self) -> u64 { self.hweight.load(Relaxed).max(1) }

    /// Wall time as virtual time of this cgroup.
    fn to_cvtime(&self, delta: u64) -> u64 { delta * FCG_HWEIGHT_ONE / self.hweight() }

    /// This cgroup and its ancestors, the root last.
    fn path_to_root(&self) -> impl Iterator<Item = &CgrpCtx> {
        iter::successors(Some(self), |cgc| cgc.parent.as_deref())
    }

    /// Compound the shares from the root down to this cgroup. False if one of
    /// the cgroups on the way went inactive in the meantime.
    fn compound_hweight(&self) -> bool {
        let Some(parent) = &self.parent else {
            self.hweight.store(FCG_HWEIGHT_ONE, Relaxed);
            self.hweight_gen.store(HWEIGHT_GEN.load(Relaxed), Relaxed);
            return true;
        };

        if !parent.compound_hweight() {
            return false;
        }

        // We can be opportunistic here and not grab the cgv_tree_lock and deal
        // with the occasional races. However, hweight updates are already
        // cached and relatively low-frequency. Let's just do the
        // straightforward thing.
        let _tree = CGV_TREE.lock();
        if self.nr_active.load(Relaxed) == 0 {
            Stat::HwtRace.inc();
            return false;
        }
        self.hweight_gen.store(parent.hweight_gen.load(Relaxed), Relaxed);
        self.hweight.store(
            (parent.hweight.load(Relaxed) * self.weight.load(Relaxed) as u64)
                .div_ceil(parent.child_weight_sum.load(Relaxed)),
            Relaxed);
        true
    }

    fn refresh_hweight(&self) {
        if self.nr_active.load(Relaxed) == 0 {
            Stat::HwtSkip.inc();
        } else if self.hweight_gen.load(Relaxed) == HWEIGHT_GEN.load(Relaxed) {
            Stat::HwtCache.inc();
        } else {
            Stat::HwtUpdates.inc();
            self.compound_hweight();
        }
    }

    fn cap_budget(&self, node: &mut CgvNode) {
        // A node which is on the queue can't be pointed to from elsewhere yet
        // and thus can't be updated and repositioned. Instead, we collect the
        // vtime deltas separately and apply it asynchronously here.
        let delta = self.cvtime_delta.swap(0, Relaxed);
        let cvtime = node.cvtime.wrapping_add(delta as u64);

        // Allow a cgroup to carry the maximum budget proportional to its
        // hweight such that a full-hweight cgroup can immediately take up half
        // of the CPUs at the most while staying at the front of the queue.
        let max_budget = cgrp_slice_ns() * NR_CPUS.load(Relaxed) as u64 *
            self.hweight.load(Relaxed) / (2 * FCG_HWEIGHT_ONE);
        let floor = CVTIME_NOW.load(Relaxed).wrapping_sub(max_budget);

        node.cvtime = if time_before(cvtime, floor) { floor } else { cvtime };
    }

    /// A task was put on the DSQ of the cgroup.
    fn enqueued(&self) {
        // paired with the store in try_pick_next_cgroup()
        if self.queued.swap(true, Relaxed) {
            Stat::EnqSkip.inc();
            return;
        }

        // None if the node is already on the queue
        let Some(mut node) = self.stash.lock().take() else {
            Stat::EnqRace.inc();
            return;
        };

        let mut tree = CGV_TREE.lock();
        self.cap_budget(&mut node);
        tree.push(Reverse(node));
    }

    /// Walk the cgroup tree to update the active weight sums as tasks wake up
    /// and sleep. The weight sums are used to flatten the hierarchy.
    fn update_active_weight_sums(&self, runnable: bool) {
        // In most cases, a hot cgroup would have multiple threads going to
        // sleep and waking up while the whole cgroup stays active. In leaf
        // cgroups, ->nr_runnable which is updated with atomics tracks whether
        // the cgroup is active or not.
        if runnable {
            if self.nr_runnable.fetch_add(1, Relaxed) != 0 {
                return;
            }
            Stat::Act.inc();
        } else {
            if self.nr_runnable.fetch_sub(1, Relaxed) != 1 {
                return;
            }
            Stat::Deact.inc();
        }

        // If @self is becoming runnable, its hweight should be refreshed after
        // it's added to the weight tree so that enqueue has the up-to-date
        // value. If @self is becoming quiescent, the hweight should be
        // refreshed before it's removed from the weight tree so that the usage
        // charging which happens afterwards has access to the latest value.
        if !runnable {
            self.refresh_hweight();
        }

        // propagate upwards, as long as the active state of a level changes
        let mut updated = false;
        for cgc in self.path_to_root() {
            let Some(parent) = &cgc.parent else { break };
            let weight = cgc.weight.load(Relaxed) as u64;

            // We need the propagation protected by a lock to synchronize
            // against weight changes.
            let _tree = CGV_TREE.lock();
            if runnable {
                if cgc.nr_active.fetch_add(1, Relaxed) != 0 {
                    break;
                }
                parent.child_weight_sum.fetch_add(weight, Relaxed);
            } else {
                if cgc.nr_active.fetch_sub(1, Relaxed) != 1 {
                    break;
                }
                parent.child_weight_sum.fetch_sub(weight, Relaxed);
            }
            updated = true;
        }

        if updated {
            HWEIGHT_GEN.fetch_add(1, Relaxed);
        }

        if runnable {
            self.refresh_hweight();
        }
    }
}

// ── struct_ops callbacks ─────────────────────────────────────────────

bpf_prog!("struct_ops/flatcg_select_cpu",
fn flatcg_select_cpu(p: Task, prev_cpu: i32, wake_flags: u64) -> i32 {
    let (cpu, is_idle) = p.select_cpu_dfl(prev_cpu, wake_flags);

    let Some(taskc) = find_task_ctx(p) else { return cpu };

    // If select_cpu_dfl() is recommending local enqueue, the target CPU is
    // idle. Follow it and charge the cgroup later in flatcg_stopping() after
    // the fact.
    if is_idle {
        taskc.bypassed_at = Some(p.sum_exec_runtime());
        Stat::Local.inc();
        p.dsq_insert(SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }

    cpu
});

bpf_prog!("struct_ops/flatcg_enqueue",
fn flatcg_enqueue(p: Task, enq_flags: u64) {
    let Some(taskc) = find_task_ctx(p) else { return };

    // Use the direct dispatching and force charging to deal with tasks with
    // custom affinities so that we don't have to worry about per-cgroup dq's
    // containing tasks that can't be executed from some CPUs.
    if p.nr_cpus_allowed() as u32 != NR_CPUS.load(Relaxed) {
        taskc.bypassed_at = Some(p.sum_exec_runtime());

        // The global dq is deprioritized as we don't want to let tasks to
        // boost themselves by constraining its cpumask. The deprioritization
        // is rather severe, so let's not apply that to per-cpu kernel threads.
        if p.nr_cpus_allowed() == 1 && p.is_kthread() {
            Stat::Local.inc();
            p.dsq_insert(SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
        } else {
            Stat::Global.inc();
            p.dsq_insert(FALLBACK_DSQ.0, SCX_SLICE_DFL, enq_flags);
        }
        return;
    }

    let Some(cgc) = task_cgrp_ctx(p) else { return };

    if fifo_sched() {
        p.dsq_insert(cgc.cgid, SCX_SLICE_DFL, enq_flags);
    } else {
        // Limit the amount of budget that an idling task can accumulate to one
        // slice.
        let floor = cgc.tvtime_now.load(Relaxed).wrapping_sub(SCX_SLICE_DFL);
        let tvtime = p.dsq_vtime();
        let tvtime = if time_before(tvtime, floor) { floor } else { tvtime };

        p.dsq_insert_vtime(cgc.cgid, SCX_SLICE_DFL, tvtime, enq_flags);
    }

    cgc.enqueued();
});

bpf_prog!("struct_ops/flatcg_runnable",
fn flatcg_runnable(p: Task, _enq_flags: u64) {
    if let Some(cgc) = task_cgrp_ctx(p) {
        cgc.update_active_weight_sums(true);
    }
});

bpf_prog!("struct_ops/flatcg_running",
fn flatcg_running(p: Task) {
    if fifo_sched() {
        return;
    }

    // @cgc->tvtime_now always progresses forward as tasks start executing. The
    // test and update can be performed concurrently from multiple CPUs and thus
    // racy. Any error should be contained and temporary. Let's just live with
    // it.
    if let Some(cgc) = task_cgrp_ctx(p) {
        if time_before(cgc.tvtime_now.load(Relaxed), p.dsq_vtime()) {
            cgc.tvtime_now.store(p.dsq_vtime(), Relaxed);
        }
    }
});

bpf_prog!("struct_ops/flatcg_stopping",
fn flatcg_stopping(p: Task, _runnable: bool) {
    // Scale the execution time by the inverse of the weight and charge.
    //
    // Note that the default yield implementation yields by setting
    // @p->scx.slice to zero and the following would treat the yielding task as
    // if it has consumed all its slice.
    if !fifo_sched() {
        let delta = p.scale_by_weight_inverse(SCX_SLICE_DFL.saturating_sub(p.slice()));
        p.set_dsq_vtime(p.dsq_vtime().wrapping_add(delta));
    }

    let Some(taskc) = find_task_ctx(p) else { return };
    let Some(bypassed_at) = taskc.bypassed_at else { return };

    if let Some(cgc) = task_cgrp_ctx(p) {
        let used = cgc.to_cvtime(p.sum_exec_runtime() - bypassed_at);
        cgc.cvtime_delta.fetch_add(used as i64, Relaxed);
        taskc.bypassed_at = None;
    }
});

bpf_prog!("struct_ops/flatcg_quiescent",
fn flatcg_quiescent(p: Task, _deq_flags: u64) {
    if let Some(cgc) = task_cgrp_ctx(p) {
        cgc.update_active_weight_sums(false);
    }
});

bpf_prog!("struct_ops/flatcg_cgroup_set_weight",
fn flatcg_cgroup_set_weight(cgrp: Cgroup, weight: u32) {
    let cgid = cgrp.id();

    CGRP_CTXS.with_irqs_off(|cgroups| {
        let Some(cgc) = lookup_cgrp_ctx(cgroups, cgid) else { return };

        let _tree = CGV_TREE.lock();
        let old = cgc.weight.swap(weight, Relaxed);
        if let Some(parent) = cgc.parent.as_ref().filter(|_| cgc.nr_active.load(Relaxed) != 0) {
            parent.child_weight_sum.fetch_add((weight as u64).wrapping_sub(old as u64), Relaxed);
        }
    });

    HWEIGHT_GEN.fetch_add(1, Relaxed);
});

/// What became of an attempt to find the next cgroup to run.
enum Picked {
    /// Tasks of this cgroup were moved to the local DSQ.
    Cgroup(u64),
    /// No cgroup is waiting.
    Nothing,
    /// The first cgroup in the queue turned out to be gone or empty.
    Retry,
}

fn try_pick_next_cgroup() -> Picked {
    // pop the front cgroup and wind cvtime_now accordingly
    let Some(Reverse(mut node)) = CGV_TREE.lock().pop() else {
        Stat::PncNoCgrp.inc();
        return Picked::Nothing;
    };

    if time_before(CVTIME_NOW.load(Relaxed), node.cvtime) {
        CVTIME_NOW.store(node.cvtime, Relaxed);
    }

    // If lookup fails, the cgroup's gone. Drop the node and try the next
    // cgroup.
    let Some(cgc) = try_find_cgrp_ctx(node.cgid) else {
        Stat::PncGone.inc();
        return Picked::Retry;
    };

    if cgc.dsq().move_to_local() {
        // Successfully consumed from the cgroup. This will be our current
        // cgroup for the new slice. Refresh its hweight.
        cgc.refresh_hweight();

        // As the cgroup may have more tasks, add it back to the queue. Note
        // that here we charge the full slice upfront and then exact later
        // according to the actual consumption. This prevents lowpri thundering
        // herd from saturating the machine.
        let cgid = node.cgid;
        let mut tree = CGV_TREE.lock();
        node.cvtime = node.cvtime.wrapping_add(cgc.to_cvtime(cgrp_slice_ns()));
        cgc.cap_budget(&mut node);
        tree.push(Reverse(node));

        Stat::PncNext.inc();
        return Picked::Cgroup(cgid);
    }

    Stat::PncEmpty.inc();

    // Paired with the swap in enqueued(). If they see the following transition,
    // they'll enqueue the cgroup. If they are earlier, we'll see their task in
    // the dq below and requeue the cgroup.
    cgc.queued.store(false, Relaxed);

    if cgc.dsq().nr_queued() != 0 {
        CGV_TREE.lock().push(Reverse(node));
        Stat::PncRace.inc();
    } else if cgc.stash.lock().replace(node).is_some() {
        scx_error!("unexpected !NULL cgv_node stash");
    }

    Picked::Retry
}

bpf_prog!("struct_ops/flatcg_dispatch",
fn flatcg_dispatch(cpu: i32, _prev: Option<Task>) {
    let now = scx_now();
    let Some(cpuc) = CPU_CTXS.get(cpu as usize).map(|cpuc| unsafe { cpuc.get_mut() }) else {
        scx_error!("cpu_ctx lookup failed");
        return;
    };

    if cpuc.cur_cgid != 0 {
        if time_before(now, cpuc.cur_at + cgrp_slice_ns()) {
            if Dsq(cpuc.cur_cgid).move_to_local() {
                Stat::CnsKeep.inc();
                return;
            }
            Stat::CnsEmpty.inc();
        } else {
            Stat::CnsExpire.inc();
        }

        // The current cgroup is expiring. It was already charged a full slice.
        // Calculate the actual usage and accumulate the delta.
        match try_find_cgrp_ctx(cpuc.cur_cgid) {
            Some(cgc) => {
                // We want to update the vtime delta and then look for the next
                // cgroup to execute but the latter needs to be done in a loop
                // and we can't keep the lock held. Oh well...
                let used = now - cpuc.cur_at;
                let delta = match used.checked_sub(cgrp_slice_ns()) {
                    Some(over) => cgc.to_cvtime(over) as i64,
                    None => -(cgc.to_cvtime(cgrp_slice_ns() - used) as i64),
                };
                let _tree = CGV_TREE.lock();
                cgc.cvtime_delta.fetch_add(delta, Relaxed);
            }
            None => Stat::CnsGone.inc(),
        }
    }

    cpuc.cur_at = now;

    // This only happens with custom affinities and per-cpu kthreads.
    if FALLBACK_DSQ.move_to_local() {
        cpuc.cur_cgid = 0;
        return;
    }

    let picked = (0..CGROUP_MAX_RETRIES)
        .map(|_| try_pick_next_cgroup())
        .find(|picked| !matches!(picked, Picked::Retry));

    match picked {
        Some(Picked::Cgroup(cgid)) => cpuc.cur_cgid = cgid,
        Some(_) => cpuc.cur_cgid = 0,
        // This only happens if many cgroups go away or empty at once. The
        // kernel retries as long as tasks are runnable.
        None => Stat::PncFail.inc(),
    }
});

bpf_prog!("struct_ops/flatcg_init_task",
fn flatcg_init_task(p: Task, args: InitTaskArgs) -> Result {
    TASK_CTXS.insert(p, TaskCtx::default());

    let cgid = args.cgroup().ok_or(ENOENT)?.id();
    let tvtime_now = CGRP_CTXS
        .with_irqs_off(|cgroups| Some(lookup_cgrp_ctx(cgroups, cgid)?.tvtime_now.load(Relaxed)))
        .ok_or(ENOENT)?;

    p.set_dsq_vtime(tvtime_now);
    Ok(())
});

bpf_prog!("struct_ops/flatcg_exit_task",
fn flatcg_exit_task(p: Task, _args: *const u8) {
    TASK_CTXS.remove(p);
});

fn cgroup_init(cgrp: Cgroup, weight: u32) -> Result {
    let cgid = cgrp.id();
    let parent_cgid = match cgrp.level() {
        0 => None,
        level => Some(cgrp.ancestor(level - 1).ok_or(ENOENT)?.id()),
    };

    CGRP_CTXS.with_irqs_off(|cgroups| {
        let parent = match parent_cgid {
            Some(cgid) => Some(lookup_cgrp_ctx(cgroups, cgid).ok_or(ENOENT)?.clone()),
            None => None,
        };

        let cgc = Arc::new(CgrpCtx {
            cgid,
            parent,
            nr_active: AtomicU32::new(0),
            nr_runnable: AtomicU32::new(0),
            queued: AtomicBool::new(false),
            weight: AtomicU32::new(weight),
            hweight: AtomicU64::new(FCG_HWEIGHT_ONE),
            child_weight_sum: AtomicU64::new(0),
            hweight_gen: AtomicU64::new(0),
            cvtime_delta: AtomicI64::new(0),
            tvtime_now: AtomicU64::new(0),
            stash: SpinLock::new(Some(CgvNode { cvtime: CVTIME_NOW.load(Relaxed), cgid })),
        });

        match cgroups.insert(cgid, cgc) {
            None => Ok(()),
            Some(_) => {
                scx_error!("unexpected cgrp_ctx for cgid %llu", cgid);
                Err(EBUSY)
            }
        }
    })
}

bpf_prog!("struct_ops.s/flatcg_cgroup_init",
fn flatcg_cgroup_init(cgrp: Cgroup, args: CgroupInitArgs) -> Result {
    let dsq = Dsq(cgrp.id());

    // Technically incorrect as cgroup ID is full 64bit while dsq ID is 63bit.
    // Should not be a problem in practice and easy to spot in the unlikely case
    // that it breaks.
    dsq.create(-1).inspect_err(|e| scx_error!("scx_bpf_create_dsq failed (%d)", -e.0))?;

    cgroup_init(cgrp, args.weight()).inspect_err(|_| dsq.destroy())
});

bpf_prog!("struct_ops/flatcg_cgroup_exit",
fn flatcg_cgroup_exit(cgrp: Cgroup) {
    let cgid = cgrp.id();

    // For now, there's no way to find and remove the node if it's on the
    // queue. try_pick_next_cgroup() will notice that the context is gone.
    let cgc = CGRP_CTXS.with_irqs_off(|cgroups| cgroups.remove(&cgid));
    drop(cgc);

    Dsq(cgid).destroy();
});

bpf_prog!("struct_ops/flatcg_cgroup_move",
fn flatcg_cgroup_move(p: Task, from: Cgroup, to: Cgroup) {
    let (from, to) = (from.id(), to.id());

    // lookup_cgrp_ctx() triggers scx_ops_error() on lookup failures
    let tvtimes = CGRP_CTXS.with_irqs_off(|cgroups| {
        let tvtime_now = |cgid| Some(lookup_cgrp_ctx(cgroups, cgid)?.tvtime_now.load(Relaxed));
        Some((tvtime_now(from)?, tvtime_now(to)?))
    });

    if let Some((from, to)) = tvtimes {
        p.set_dsq_vtime(to.wrapping_add(p.dsq_vtime().wrapping_sub(from)));
    }
});

bpf_prog!("struct_ops.s/flatcg_init",
fn flatcg_init() -> Result {
    NR_CPUS.store(ScxCpumask::possible().weight(), Relaxed);

    FALLBACK_DSQ.create(-1)
        .inspect_err(|e| scx_error!("failed to create DSQ %d (%d)", FALLBACK_DSQ.0, -e.0))
});

bpf_prog!("struct_ops/flatcg_exit",
fn flatcg_exit(_ei: *const ScxExitInfo) {
});

scx_ops_define!(flatcg_ops, name: b"flatcg", flags: SCX_OPS_ENQ_EXITING, timeout_ms: 0,
    select_cpu: flatcg_select_cpu,
    enqueue: flatcg_enqueue,
    dispatch: flatcg_dispatch,
    runnable: flatcg_runnable,
    running: flatcg_running,
    stopping: flatcg_stopping,
    quiescent: flatcg_quiescent,
    init_task: flatcg_init_task,
    exit_task: flatcg_exit_task,
    cgroup_set_weight: flatcg_cgroup_set_weight,
    cgroup_init: flatcg_cgroup_init,
    cgroup_exit: flatcg_cgroup_exit,
    cgroup_move: flatcg_cgroup_move,
    init: flatcg_init,
    exit: flatcg_exit,
);

// SPDX-License-Identifier: GPL-2.0
//
// scx_mitosis: a dynamic affinity scheduler. Cgroups (and their tasks) are
// assigned to cells, and cells are assigned CPUs. A cell is divided into
// subcells that tasks are sorted into by name. Each subcell has a DSQ in vtime
// order, tasks that cannot use all the CPUs of their cell wait in the DSQ of a
// CPU.
//
// Rust port of the core of scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c.
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// - cells (array map of fixed size structs) -> Config { Vec<Cell> } with
//   Vec<Subcell>, replaced as a whole: readers clone an Arc, like arc-swap
// - cell/subcell cpumask maps (double buffered kptrs) -> CpuSet in there
// - subcell_match (kind + char[16])   -> enum Match { CommPrefix(String) }
// - OR of ANDs in nested arrays       -> Vec<Vec<Match>>, any() of all()
// - BPF_MAP_TYPE_CGRP_STORAGE         -> BTreeMap<u64, CgrpCtx> with parent ids
// - scx_bpf_dump("...")               -> write!(ScxDump, ...), core::fmt
// - __free(), guard(), scoped_guard() -> Drop
//
// User space decides which cgroup gets a cell and which CPUs a cell gets, and
// hands the result to the apply_cell_config syscall program. That program is
// here, it reads the exported mitosis_cell_config. In addition, with AUTO_CELLS
// (default), every child of the root cgroup that appears while the scheduler
// runs gets a cell, and the CPUs are split evenly between the cells.
//
// Dropped: LLC awareness and work stealing, slice shrinking, demand tracking,
// dynamic affinity CPU selection, the cpuset fentry and cgroup tracepoints (the
// cgroup ops do it), per-cell statistics per CPU, UEI. 16 cells of 4 subcells.

#![no_std]
#![no_main]
#![feature(panic_can_unwind)]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::fmt::Write;
use core::iter;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use scx_common::*;

const MAX_CELLS: usize = 16;
const MAX_SUBCELLS_PER_CELL: usize = 4;
const MAX_COMM: usize = 16;
const MAX_SUBCELL_MATCH_ORS: usize = 4;
const MAX_SUBCELL_MATCH_ANDS: usize = 4;
const ROOT_CELL_ID: u32 = 0;
const VTIME_DEBT_CAP_SLICES: u64 = 4;
/// A pinned task that has waited for this long goes first.
const PINNED_OVERDUE_NS: u64 = 10 * NSEC_PER_MSEC;

tunables! { "mitosis",
    SMT_ENABLED: AtomicBool = true;
    SLICE_NS: AtomicU64 = SCX_SLICE_DFL;
    ENABLE_BORROWING: AtomicBool = false;
    REJECT_MULTICPU_PINNING: AtomicBool = false;
    AUTO_CELLS: AtomicBool = true;
}

fn slice_ns() -> u64 { SLICE_NS.load(Relaxed) }

#[derive(Clone, Copy)]
enum Stat {
    Local,
    CpuDsq,
    CellDsq,
    AffnViol,
    Borrowed,
    NrStats,
}

static STATS: [AtomicU64; Stat::NrStats as usize] =
    [const { AtomicU64::new(0) }; Stat::NrStats as usize];

impl Stat {
    fn inc(self) { STATS[self as usize].fetch_add(1, Relaxed); }
    fn get(self) -> u64 { STATS[self as usize].load(Relaxed) }
}

// ── DSQ ids ──────────────────────────────────────────────────────────

/// dsq_id_t of C: which kind of queue an id stands for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DsqId {
    Cpu(i32),
    Subcell { cell: u32, subcell: u32 },
}

impl DsqId {
    const CPU_BIT: u64 = 1 << 32;

    fn dsq(self) -> Dsq {
        match self {
            DsqId::Cpu(cpu) => Dsq(Self::CPU_BIT | cpu as u64),
            DsqId::Subcell { cell, subcell } => {
                Dsq(1 + cell as u64 * MAX_SUBCELLS_PER_CELL as u64 + subcell as u64)
            }
        }
    }
}

// ── Cells ────────────────────────────────────────────────────────────

enum Match {
    CommPrefix(String),
}

impl Match {
    fn matches(&self, comm: &[u8]) -> bool {
        match self {
            Match::CommPrefix(prefix) => comm.starts_with(prefix.as_bytes()),
        }
    }
}

struct Subcell {
    id: u32,
    /// The task has to satisfy all the matches of one of the groups. A group
    /// without matches takes everything.
    matches: Vec<Vec<Match>>,
    cpus: CpuSet,
    vtime_now: AtomicU64,
}

impl Subcell {
    fn new(id: u32) -> Self {
        Subcell { id, matches: Vec::new(), cpus: CpuSet::new(), vtime_now: AtomicU64::new(0) }
    }

    fn task_matches(&self, comm: &[u8]) -> bool {
        self.matches.iter().any(|group| group.iter().all(|m| m.matches(comm)))
    }
}

struct Cell {
    id: u32,
    owner_cgid: u64,
    cpus: CpuSet,
    borrowable: CpuSet,
    /// The first one takes what the others do not match.
    subcells: Vec<Subcell>,
}

impl Cell {
    fn new(id: u32, owner_cgid: u64) -> Self {
        let mut subcells = Vec::new();
        subcells.push(Subcell::new(0));
        Cell { id, owner_cgid, cpus: CpuSet::new(), borrowable: CpuSet::new(), subcells }
    }

    fn pick_task_subcell(&self, p: Task) -> u32 {
        let comm = p.comm();
        let comm = CStr::from_bytes_until_nul(&comm).map_or(&comm[..], CStr::to_bytes);

        self.subcells.iter().skip(1).find(|subcell| subcell.task_matches(comm)).map_or(0, |subcell| subcell.id)
    }
}

/// Everything that user space configures. Never changed, only replaced.
struct Config {
    seq: u32,
    cells: Vec<Cell>,
}

impl Config {
    fn cell(&self, id: u32) -> Option<&Cell> {
        let cell = self.cells.get(id as usize);
        if cell.is_none() {
            scx_error!("Invalid cell %d", id);
        }
        cell
    }

    fn subcell(&self, cell: u32, subcell: u32) -> Option<&Subcell> {
        let subcell_ref = self.cell(cell)?.subcells.get(subcell as usize);
        if subcell_ref.is_none() {
            scx_error!("invalid subcell %u for cell %u", subcell, cell);
        }
        subcell_ref
    }

    /// The cell that a cgroup owns.
    fn cell_of_owner(&self, cgid: u64) -> Option<u32> {
        self.cells.iter().skip(1).find(|cell| cell.owner_cgid == cgid).map(|cell| cell.id)
    }
}

static CONFIG: SpinLock<Option<Arc<Config>>> = SpinLock::new(None);
static APPLIED_CONFIGURATION_SEQ: AtomicU32 = AtomicU32::new(0);

fn config() -> Option<Arc<Config>> {
    let cfg = CONFIG.lock().clone();
    if cfg.is_none() {
        scx_error!("no configuration");
    }
    cfg
}

/// For the ops that are called with interrupts on. They look at the
/// configuration under its lock instead of taking a reference.
fn with_config_irqs_off<R>(f: impl FnOnce(&Config) -> R) -> Option<R> {
    CONFIG.with_irqs_off(|cfg| cfg.as_deref().map(f))
}

// ── Per-CPU context ──────────────────────────────────────────────────

struct CpuCtx {
    pinned_waiting_since: AtomicU64,
    vtime_now: AtomicU64,
    cell: AtomicU32,
    subcell: AtomicU32,
}

static CPU_CTXS: [CpuCtx; MAX_CPUS] = [const {
    CpuCtx {
        pinned_waiting_since: AtomicU64::new(0),
        vtime_now: AtomicU64::new(0),
        cell: AtomicU32::new(0),
        subcell: AtomicU32::new(0),
    }
}; MAX_CPUS];

fn lookup_cpu_ctx(cpu: i32) -> Option<&'static CpuCtx> {
    let cctx = usize::try_from(cpu).ok().and_then(|cpu| CPU_CTXS.get(cpu));
    if cctx.is_none() {
        scx_error!("no cpu_ctx for cpu %d", cpu);
    }
    cctx
}

static ALL_CPUS: CpuSet = CpuSet::new();

/// Make @new the configuration. Callers have interrupts off.
fn install_config(mut new: Config) {
    new.seq = APPLIED_CONFIGURATION_SEQ.load(Relaxed) + 1;

    // Which cell and subcell does each CPU work for?
    for cell in &new.cells {
        for subcell in &cell.subcells {
            for cctx in subcell.cpus.iter().filter_map(lookup_cpu_ctx) {
                cctx.cell.store(cell.id, Relaxed);
                cctx.subcell.store(subcell.id, Relaxed);
            }
        }
    }

    let seq = new.seq;
    let old = CONFIG.lock().replace(Arc::new(new));
    // Tasks notice the new number and look up their cell again.
    APPLIED_CONFIGURATION_SEQ.store(seq, Relaxed);
    drop(old);
}

// ── Per-cgroup context ───────────────────────────────────────────────

struct CgrpCtx {
    parent: Option<u64>,
    cell: u32,
}

static CGRP_CTXS: SpinLock<BTreeMap<u64, CgrpCtx>> = SpinLock::new(BTreeMap::new());

/// A cgroup is in the cell that it or its nearest ancestor owns.
fn assign_cgroups_to_cells(cfg: &Config) {
    let mut cgroups = CGRP_CTXS.lock();

    let cells: Vec<(u64, u32)> = cgroups.keys()
        .map(|&cgid| {
            let cell = iter::successors(Some(cgid), |cgid| cgroups.get(cgid)?.parent)
                .find_map(|cgid| cfg.cell_of_owner(cgid))
                .unwrap_or(ROOT_CELL_ID);
            (cgid, cell)
        })
        .collect();

    for (cgid, cell) in cells {
        if let Some(cgc) = cgroups.get_mut(&cgid) {
            cgc.cell = cell;
        }
    }
}

/// What user space does in C, in the simplest way: a cell for every child of
/// the root cgroup in @owners, the same number of CPUs for every cell, what is
/// left over for the root cell.
fn auto_config(owners: &[u64]) -> Config {
    let mut cells: Vec<Cell> = iter::once(0).chain(owners.iter().copied().take(MAX_CELLS - 1))
        .zip(0u32..)
        .map(|(cgid, id)| Cell::new(id, cgid))
        .collect();

    let share = (ALL_CPUS.weight() as usize / cells.len()).max(1);
    let last = cells.len() - 1;

    // From the end, so that the root cell gets the first CPUs and the rest.
    for (nth, cpu) in ALL_CPUS.iter().enumerate() {
        let cell = &mut cells[last.saturating_sub((ALL_CPUS.weight() as usize - 1 - nth) / share)];
        cell.cpus.set(cpu);
        cell.subcells[0].cpus.set(cpu);
    }

    Config { seq: 0, cells }
}

fn reconfigure_auto() {
    let owners: Vec<u64> = CGRP_CTXS.lock().iter()
        .filter(|(_, cgc)| cgc.parent.is_some_and(|parent| parent == ROOT_CGID.load(Relaxed)))
        .filter(|(&cgid, _)| cgid > FIRST_NEW_CGID.load(Relaxed))
        .map(|(&cgid, _)| cgid)
        .collect();

    let cfg = auto_config(&owners);
    assign_cgroups_to_cells(&cfg);
    install_config(cfg);
}

static ROOT_CGID: AtomicU64 = AtomicU64::new(1);
/// Cgroups that were there when the scheduler started have ids up to this one.
static FIRST_NEW_CGID: AtomicU64 = AtomicU64::new(u64::MAX);

// ── Per-task context ─────────────────────────────────────────────────

struct TaskCtx {
    /// The CPUs of the subcell that the task can run on
    cpus: CpuSet,
    started_running_at: u64,
    basis_vtime: u64,
    cell: u32,
    subcell: u32,
    dsq: DsqId,
    /// Which configuration the above was derived from
    configuration_seq: u32,
    /// Is the task allowed on all the CPUs of its cell?
    all_cell_cpus_allowed: bool,
    borrowed: bool,
    cgid: u64,
}

static TASK_CTXS: TaskMap<TaskCtx> = TaskMap::new();

fn lookup_task_ctx(p: Task) -> Option<&'static mut TaskCtx> {
    let tctx = TASK_CTXS.get(p);
    if tctx.is_none() {
        scx_error!("task_ctx lookup failed for pid %d", p.pid());
    }
    tctx
}

impl TaskCtx {
    /// Helper function for picking the queue of a task from its cpumask and
    /// that of its cell.
    fn update_cpumask(&mut self, p: Task, cfg: &Config) -> Result {
        let cell = cfg.cell(self.cell).ok_or(ENOENT)?;
        let subcell = cfg.subcell(self.cell, self.subcell).ok_or(ENOENT)?;

        self.cpus.assign_and(&subcell.cpus, p.cpus());

        let all_allowed = cell.cpus.is_subset_of(p.cpus()) &&
            (!ENABLE_BORROWING.load(Relaxed) || cell.borrowable.is_subset_of(p.cpus()));

        if self.cell != ROOT_CELL_ID && REJECT_MULTICPU_PINNING.load(Relaxed) && !all_allowed &&
           p.cpus().weight() > 1 {
            scx_error!("multi-CPU pinning within cell %d not supported", self.cell);
            return Err(EINVAL);
        }

        // A task that changes queues starts from the vtime of the new one.
        let (dsq, vtime_now) = if all_allowed {
            (DsqId::Subcell { cell: self.cell, subcell: self.subcell }, &subcell.vtime_now)
        } else {
            let cpu = p.cpus().any_distribute();
            (DsqId::Cpu(cpu), &lookup_cpu_ctx(cpu).ok_or(ENOENT)?.vtime_now)
        };
        if dsq != self.dsq || all_allowed != self.all_cell_cpus_allowed {
            p.set_dsq_vtime(vtime_now.load(Relaxed));
        }

        self.dsq = dsq;
        self.all_cell_cpus_allowed = all_allowed;
        Ok(())
    }

    /// Figure out the task's cell, subcell, dsq and store the corresponding
    /// cpumask in the task_ctx.
    fn update_cell(&mut self, p: Task, cgid: u64, cfg: &Config) -> Result {
        // An exiting task may have left its cgroup already.
        let cell = match CGRP_CTXS.lock().get(&cgid) {
            Some(cgc) => cgc.cell,
            None if p.is_exiting() => ROOT_CELL_ID,
            None => {
                scx_error!("cgrp_ctx lookup failed for cgid %llu (task %d)", cgid, p.pid());
                return Err(ENOENT);
            }
        };

        self.configuration_seq = cfg.seq;
        self.cell = cell;
        self.subcell = cfg.cell(cell).ok_or(ENOENT)?.pick_task_subcell(p);
        self.cgid = cgid;
        self.update_cpumask(p, cfg)
    }

    /// Look the cell up again if the configuration or the cgroup has changed.
    fn maybe_refresh_cell(&mut self, p: Task, cfg: &Config) -> Result {
        let cgid = p.cgroup().id();
        if self.configuration_seq != cfg.seq || cgid != self.cgid {
            self.update_cell(p, cgid, cfg)?;
        }
        Ok(())
    }
}

// ── Idle CPU selection ───────────────────────────────────────────────

fn pick_idle_cpu_from(cand: &CpuSet, p: Task, prev_cpu: i32, idle_smtmask: Cpumask) -> Option<i32> {
    let prev_in_cand = cand.test(prev_cpu);
    let usable = || cand.iter().filter(|&cpu| p.cpus().test(cpu));

    // If SMT is enabled, try to find a fully idle core: the previous one first.
    if SMT_ENABLED.load(Relaxed) {
        if prev_in_cand && idle_smtmask.test(prev_cpu) && test_and_clear_cpu_idle(prev_cpu) {
            return Some(prev_cpu);
        }
        let core = usable().filter(|&cpu| idle_smtmask.test(cpu)).find(|&cpu| test_and_clear_cpu_idle(cpu));
        if core.is_some() {
            return core;
        }
    }

    if prev_in_cand && test_and_clear_cpu_idle(prev_cpu) {
        return Some(prev_cpu);
    }
    usable().find(|&cpu| test_and_clear_cpu_idle(cpu))
}

/// Find an idle CPU in the cell, or one that the cell may borrow, and send the
/// task there.
fn try_pick_idle_cpu(p: Task, prev_cpu: i32, tctx: &mut TaskCtx, cfg: &Config, kick: bool) -> Option<i32> {
    let idle_smtmask = ScxCpumask::idle_smt();

    // No overlap between cell cpus and task cpus: any CPU of the task will do.
    let home = if tctx.cpus.is_empty() {
        Stat::AffnViol.inc();
        pick_idle_cpu_from(&ALL_CPUS, p, prev_cpu, *idle_smtmask)
    } else {
        pick_idle_cpu_from(&tctx.cpus, p, prev_cpu, *idle_smtmask)
    };

    let cpu = match home {
        Some(cpu) => {
            Stat::Local.inc();
            cpu
        }
        None if ENABLE_BORROWING.load(Relaxed) => {
            let cpu = pick_idle_cpu_from(&cfg.cell(tctx.cell)?.borrowable, p, prev_cpu, *idle_smtmask)?;
            tctx.borrowed = true;
            Stat::Borrowed.inc();
            cpu
        }
        None => return None,
    };

    p.dsq_insert(Dsq::local_on(cpu).0, slice_ns(), 0);
    if kick {
        kick_cpu(cpu, SCX_KICK_IDLE);
    }
    Some(cpu)
}

// ── struct_ops callbacks ─────────────────────────────────────────────

bpf_prog!("struct_ops/mitosis_select_cpu",
fn mitosis_select_cpu(p: Task, prev_cpu: i32, _wake_flags: u64) -> i32 {
    let (Some(tctx), Some(cfg)) = (lookup_task_ctx(p), config()) else { return prev_cpu };

    if tctx.maybe_refresh_cell(p, &cfg).is_err() {
        return prev_cpu;
    }

    // Pinned path: the CPU was chosen when the queue was.
    if let DsqId::Cpu(cpu) = tctx.dsq {
        Stat::AffnViol.inc();
        if test_and_clear_cpu_idle(cpu) {
            p.dsq_insert(SCX_DSQ_LOCAL, slice_ns(), 0);
        }
        return cpu;
    }

    try_pick_idle_cpu(p, prev_cpu, tctx, &cfg, false)
        // All CPUs are busy. Stay, unless the previous CPU is not ours.
        .or_else(|| Some(prev_cpu).filter(|&cpu| tctx.cpus.test(cpu)))
        .or_else(|| tctx.cpus.any_distribute())
        .unwrap_or(prev_cpu)
});

bpf_prog!("struct_ops/mitosis_enqueue",
fn mitosis_enqueue(p: Task, enq_flags: u64) {
    let (Some(tctx), Some(cfg)) = (lookup_task_ctx(p), config()) else { return };

    if tctx.maybe_refresh_cell(p, &cfg).is_err() {
        return;
    }
    tctx.borrowed = false;

    let unselected = enq_flags & SCX_ENQ_CPU_SELECTED == 0 || enq_flags & SCX_ENQ_LAST != 0;

    // The CPU to wake up, and the vtime that the queue has got to.
    let (cpu, basis_vtime) = match tctx.dsq {
        DsqId::Cpu(cpu) => {
            let Some(cctx) = lookup_cpu_ctx(cpu) else { return };
            Stat::CpuDsq.inc();
            let _ = cctx.pinned_waiting_since.compare_exchange(0, scx_now(), Relaxed, Relaxed);
            (Some(cpu), cctx.vtime_now.load(Relaxed))
        }
        DsqId::Subcell { cell, subcell } => {
            // If we haven't selected a cpu, then we haven't looked for and
            // kicked an idle CPU. Let's do the lookup now.
            if unselected && try_pick_idle_cpu(p, p.cpu(), tctx, &cfg, true).is_some() {
                return;
            }
            let Some(subcell) = cfg.subcell(cell, subcell) else { return };
            Stat::CellDsq.inc();
            (tctx.cpus.any_distribute(), subcell.vtime_now.load(Relaxed))
        }
    };

    tctx.basis_vtime = basis_vtime;

    // Limit both how far a task can be ahead (debt) and the amount of budget
    // that an idling task can accumulate.
    let ceiling = basis_vtime.wrapping_add(VTIME_DEBT_CAP_SLICES * slice_ns());
    let floor = basis_vtime.wrapping_sub(slice_ns());
    let vtime = match p.dsq_vtime() {
        vtime if time_after(vtime, ceiling) => ceiling,
        vtime if time_before(vtime, floor) => floor,
        vtime => vtime,
    };

    p.dsq_insert_vtime(tctx.dsq.dsq().0, slice_ns(), vtime, enq_flags);

    // Kick the CPU if needed
    if let Some(cpu) = cpu.filter(|_| unselected) {
        kick_cpu(cpu, SCX_KICK_IDLE);
    }
});

bpf_prog!("struct_ops/mitosis_dispatch",
fn mitosis_dispatch(cpu: i32, prev: Option<Task>) {
    let Some(cctx) = lookup_cpu_ctx(cpu) else { return };
    let (cell, subcell) = (cctx.cell.load(Relaxed), cctx.subcell.load(Relaxed));

    let subcell_dsq = DsqId::Subcell { cell, subcell };
    let cpu_dsq = DsqId::Cpu(cpu);
    let head = |id: DsqId| id.dsq().peek().map(|p| (p.dsq_vtime(), id));

    // Peek at the first task of both queues and take the one with the lower
    // vtime, unless a pinned task has been waiting for too long.
    let pinned = head(cpu_dsq);
    if pinned.is_none() {
        cctx.pinned_waiting_since.store(0, Relaxed);
    }
    let overdue = match cctx.pinned_waiting_since.load(Relaxed) {
        0 => false,
        since => scx_now().wrapping_sub(since) > PINNED_OVERDUE_NS,
    };

    let first = match (head(subcell_dsq), pinned) {
        (Some(shared), Some(pinned)) if !overdue && !time_before(pinned.0, shared.0) => Some(shared.1),
        (_, Some(pinned)) => Some(pinned.1),
        (Some(shared), None) => Some(shared.1),
        (None, None) => None,
    };

    let Some(first) = first else {
        // Nothing is waiting. Let @prev go on if it is still where it belongs.
        let Some(prev) = prev.filter(|prev| prev.is_queued()) else { return };
        let Some(tctx) = lookup_task_ctx(prev) else { return };

        let current = tctx.configuration_seq == APPLIED_CONFIGURATION_SEQ.load(Relaxed);
        if current && (tctx.dsq == subcell_dsq || tctx.dsq == cpu_dsq) {
            prev.set_slice(slice_ns());
        }
        return;
    };

    // The move can fail if the task was taken or dequeued meanwhile: try the
    // other queue.
    let second = if first == cpu_dsq { subcell_dsq } else { cpu_dsq };
    let Some(taken) = [first, second].into_iter().find(|id| id.dsq().move_to_local()) else { return };

    if taken == cpu_dsq {
        cctx.pinned_waiting_since.store(scx_now(), Relaxed);
    }
});

bpf_prog!("struct_ops/mitosis_running",
fn mitosis_running(p: Task) {
    let (Some(tctx), Some(cfg)) = (lookup_task_ctx(p), config()) else { return };

    // Update the vtime of the queue that the task came from, if the task's
    // vtime is ahead of it.
    let vtime_now = match tctx.dsq {
        DsqId::Cpu(cpu) => lookup_cpu_ctx(cpu).map(|cctx| &cctx.vtime_now),
        DsqId::Subcell { cell, subcell } => cfg.subcell(cell, subcell).map(|subcell| &subcell.vtime_now),
    };
    if let Some(vtime_now) = vtime_now {
        let vtime = p.dsq_vtime();
        let _ = vtime_now.fetch_update(Relaxed, Relaxed, |now| time_before(now, vtime).then_some(vtime));
    }

    tctx.started_running_at = scx_now();
});

bpf_prog!("struct_ops/mitosis_stopping",
fn mitosis_stopping(p: Task, _runnable: bool) {
    let Some(tctx) = lookup_task_ctx(p) else { return };

    // scale the execution time by the inverse of the weight and charge
    let used = scx_now().wrapping_sub(tctx.started_running_at);
    p.set_dsq_vtime(p.dsq_vtime().wrapping_add(p.scale_by_weight_inverse(used)));
});

bpf_prog!("struct_ops/mitosis_set_cpumask",
fn mitosis_set_cpumask(p: Task, _cpumask: Cpumask) {
    let (Some(tctx), Some(cfg)) = (lookup_task_ctx(p), config()) else { return };
    let _ = tctx.update_cpumask(p, &cfg);
});

fn cgroup_init(cgrp: Cgroup) -> Result {
    let cgid = cgrp.id();
    let parent = match cgrp.level() {
        0 => None,
        level => Some(cgrp.ancestor(level - 1).ok_or(ENOENT)?.id()),
    };

    // Inherit the cell of the parent for now.
    CGRP_CTXS.with_irqs_off(|cgroups| {
        let cell = parent.and_then(|parent| cgroups.get(&parent)).map_or(ROOT_CELL_ID, |cgc| cgc.cell);
        cgroups.insert(cgid, CgrpCtx { parent, cell });
    });

    if parent.is_none() {
        ROOT_CGID.store(cgid, Relaxed);
    }
    if AUTO_CELLS.load(Relaxed) && parent == Some(ROOT_CGID.load(Relaxed)) &&
       cgid > FIRST_NEW_CGID.load(Relaxed) {
        with_irqs_off(reconfigure_auto);
    }
    Ok(())
}

bpf_prog!("struct_ops/mitosis_cgroup_init",
fn mitosis_cgroup_init(cgrp: Cgroup, _args: CgroupInitArgs) -> Result {
    cgroup_init(cgrp)
});

bpf_prog!("struct_ops/mitosis_cgroup_exit",
fn mitosis_cgroup_exit(cgrp: Cgroup) {
    let cgid = cgrp.id();

    CGRP_CTXS.with_irqs_off(|cgroups| cgroups.remove(&cgid));

    // Give the CPUs of its cell back.
    let owner = with_config_irqs_off(|cfg| cfg.cell_of_owner(cgid).is_some());
    if AUTO_CELLS.load(Relaxed) && owner == Some(true) {
        with_irqs_off(reconfigure_auto);
    }
});

bpf_prog!("struct_ops/mitosis_cgroup_move",
fn mitosis_cgroup_move(p: Task, _from: Cgroup, to: Cgroup) {
    let cgid = to.id();

    with_config_irqs_off(|cfg| {
        if let Some(tctx) = lookup_task_ctx(p) {
            let _ = tctx.update_cell(p, cgid, cfg);
        }
    });
});

bpf_prog!("struct_ops/mitosis_init_task",
fn mitosis_init_task(p: Task, args: InitTaskArgs) -> Result {
    let cgid = args.cgroup().ok_or(ENOENT)?.id();

    let mut tctx = TaskCtx {
        cpus: CpuSet::new(),
        started_running_at: 0,
        basis_vtime: 0,
        cell: ROOT_CELL_ID,
        subcell: 0,
        dsq: DsqId::Subcell { cell: ROOT_CELL_ID, subcell: 0 },
        configuration_seq: 0,
        all_cell_cpus_allowed: true,
        borrowed: false,
        cgid,
    };

    with_config_irqs_off(|cfg| tctx.update_cell(p, cgid, cfg)).ok_or(ENOENT)??;

    TASK_CTXS.insert(p, tctx);
    Ok(())
});

bpf_prog!("struct_ops/mitosis_exit_task",
fn mitosis_exit_task(p: Task, _args: *const u8) {
    TASK_CTXS.remove(p);
});

// ── Dump ─────────────────────────────────────────────────────────────

/// A CpuSet as ranges: 0-3,8,10-11
struct Ranges<'a>(&'a CpuSet);

impl core::fmt::Display for Ranges<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut cpus = self.0.iter().peekable();
        let mut sep = "";

        while let Some(first) = cpus.next() {
            let mut last = first;
            while let Some(next) = cpus.next_if_eq(&(last + 1)) {
                last = next;
            }
            if first == last {
                write!(f, "{sep}{first}")?;
            } else {
                write!(f, "{sep}{first}-{last}")?;
            }
            sep = ",";
        }
        Ok(())
    }
}

fn dump(cfg: &Config) -> core::fmt::Result {
    let out = &mut ScxDump;

    writeln!(out, "configuration {}, {} cells, {} tasks", cfg.seq, cfg.cells.len(), TASK_CTXS.len())?;
    writeln!(out, "local {} cpu_dsq {} cell_dsq {} affn_viol {} borrowed {}", Stat::Local.get(),
             Stat::CpuDsq.get(), Stat::CellDsq.get(), Stat::AffnViol.get(), Stat::Borrowed.get())?;

    for cell in &cfg.cells {
        writeln!(out, "CELL[{}] owner={} CPUS={}", cell.id, cell.owner_cgid, Ranges(&cell.cpus))?;
        for subcell in &cell.subcells {
            let id = DsqId::Subcell { cell: cell.id, subcell: subcell.id };
            writeln!(out, "  SUBCELL[{}] CPUS={} vtime={} nr_queued={}", subcell.id, Ranges(&subcell.cpus),
                     subcell.vtime_now.load(Relaxed), id.dsq().nr_queued())?;
            for Match::CommPrefix(prefix) in subcell.matches.iter().flatten() {
                writeln!(out, "    comm={prefix}*")?;
            }
        }
    }
    Ok(())
}

bpf_prog!("struct_ops/mitosis_dump",
fn mitosis_dump(_dctx: *const u8) {
    if let Some(cfg) = config() {
        let _ = dump(&cfg);
    }
});

bpf_prog!("struct_ops/mitosis_dump_task",
fn mitosis_dump_task(_dctx: *const u8, p: Task) {
    let Some(tctx) = lookup_task_ctx(p) else { return };

    let _ = writeln!(ScxDump, "Task[{}] vtime={} basis_vtime={} cell={} subcell={} all_cell_cpus_allowed={} CPUS={}",
                     p.pid(), p.dsq_vtime(), tctx.basis_vtime, tctx.cell, tctx.subcell,
                     tctx.all_cell_cpus_allowed, Ranges(&tctx.cpus));
});

// ── Configuration from user space ────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct SubcellMatch {
    /// 0: none, 1: prefix of the comm
    kind: u32,
    value: [u8; MAX_COMM],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SubcellMatchAndGroup {
    nr_matches: u32,
    matches: [SubcellMatch; MAX_SUBCELL_MATCH_ANDS],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SubcellConfig {
    in_use: u32,
    nr_match_ors: u32,
    matches: [SubcellMatchAndGroup; MAX_SUBCELL_MATCH_ORS],
    primary: [u8; MAX_CPUS / 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CellAssignment {
    cgid: u64,
    cell_id: u32,
}

#[repr(C)]
struct CellConfig {
    num_cell_assignments: u32,
    num_cells: u32,
    assignments: [CellAssignment; MAX_CELLS],
    cpumasks: [[u8; MAX_CPUS / 8]; MAX_CELLS],
    borrowable_cpumasks: [[u8; MAX_CPUS / 8]; MAX_CELLS],
    subcells: [[SubcellConfig; MAX_SUBCELLS_PER_CELL]; MAX_CELLS],
}

#[export_name = "mitosis_cell_config"]
static CELL_CONFIG: BpfCell<CellConfig> = BpfCell::new(unsafe { core::mem::zeroed() });

fn fill_cpuset(set: &CpuSet, mask: &[u8]) {
    mask.iter().enumerate()
        .flat_map(|(i, &byte)| (0..8).filter(move |bit| byte & 1 << bit != 0).map(move |bit| (i * 8 + bit) as i32))
        .for_each(|cpu| set.set(cpu));
}

impl TryFrom<&SubcellMatch> for Match {
    type Error = Errno;

    fn try_from(m: &SubcellMatch) -> Result<Match> {
        match m.kind {
            1 => {
                let prefix = CStr::from_bytes_until_nul(&m.value).map_err(|_| EINVAL)?;
                Ok(Match::CommPrefix(String::from(prefix.to_str().map_err(|_| EINVAL)?)))
            }
            _ => Err(EINVAL),
        }
    }
}

fn parse_subcell(id: u32, input: &SubcellConfig) -> Result<Subcell> {
    let mut subcell = Subcell::new(id);

    fill_cpuset(&subcell.cpus, &input.primary);
    subcell.matches = input.matches.get(..input.nr_match_ors as usize).ok_or(EINVAL)?.iter()
        .map(|group| {
            group.matches.get(..group.nr_matches as usize).ok_or(EINVAL)?.iter().map(Match::try_from).collect()
        })
        .collect::<Result<_>>()?;
    Ok(subcell)
}

fn parse_cell_config(input: &CellConfig) -> Result<Config> {
    let nr_cells = input.num_cells as usize;
    if nr_cells == 0 || nr_cells > MAX_CELLS {
        return Err(EINVAL);
    }
    let assignments = input.assignments.get(..input.num_cell_assignments as usize).ok_or(EINVAL)?;

    let cells = (0..nr_cells).map(|id| {
        let owner = assignments.iter().find(|a| a.cell_id as usize == id).map_or(0, |a| a.cgid);
        let mut cell = Cell::new(id as u32, owner);

        fill_cpuset(&cell.cpus, &input.cpumasks[id]);
        fill_cpuset(&cell.borrowable, &input.borrowable_cpumasks[id]);

        // Subcell 0 always exists. Without a mask of its own it has all the
        // CPUs of the cell.
        cell.subcells = input.subcells[id].iter().zip(0u32..)
            .filter(|(subcell, id)| *id == 0 || subcell.in_use != 0)
            .map(|(subcell, id)| parse_subcell(id, subcell))
            .collect::<Result<_>>()?;
        if cell.subcells[0].cpus.is_empty() {
            fill_cpuset(&cell.subcells[0].cpus, &input.cpumasks[id]);
        }
        // Ids are positions.
        if cell.subcells.iter().zip(0u32..).any(|(subcell, pos)| subcell.id != pos) {
            return Err(EINVAL);
        }
        Ok(cell)
    }).collect::<Result<Vec<Cell>>>()?;

    // Every CPU has to be in exactly one cell.
    let covered: u32 = cells.iter().map(|cell| cell.cpus.weight()).sum();
    if covered != ALL_CPUS.weight() || !ALL_CPUS.iter().all(|cpu| cells.iter().any(|cell| cell.cpus.test(cpu))) {
        scx_error!("cells cover %u CPUs of %u", covered, ALL_CPUS.weight());
        return Err(EINVAL);
    }

    Ok(Config { seq: 0, cells })
}

/// Apply the configuration that user space has put into mitosis_cell_config.
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn mitosis_apply_cell_config(_ctx: *const u8) -> i32 {
    let apply = || -> Result {
        let cfg = parse_cell_config(CELL_CONFIG.get())?;

        with_irqs_off(|| {
            assign_cgroups_to_cells(&cfg);
            install_config(cfg);
        });
        Ok(())
    };
    apply().ret()
}

// ── Init ─────────────────────────────────────────────────────────────

bpf_prog!("struct_ops.s/mitosis_init",
fn mitosis_init() -> Result {
    let nr_cpus = nr_cpu_ids().min(MAX_CPUS as u32) as i32;
    {
        let possible = ScxCpumask::possible();
        (0..nr_cpus).filter(|&cpu| possible.test(cpu)).for_each(|cpu| ALL_CPUS.set(cpu));
    }

    // The queues of all the CPUs, cells and subcells that there can be.
    let cpu_dsqs = ALL_CPUS.iter().map(DsqId::Cpu);
    let subcell_dsqs = (0..MAX_CELLS as u32)
        .flat_map(|cell| (0..MAX_SUBCELLS_PER_CELL as u32).map(move |subcell| DsqId::Subcell { cell, subcell }));

    cpu_dsqs.chain(subcell_dsqs).try_for_each(|id| {
        id.dsq().create(-1).inspect_err(|e| scx_error!("failed to create DSQ %llu: %d", id.dsq().0, -e.0))
    })?;

    // One cell with everything in it to begin with. The kernel calls
    // ops.cgroup_init() for the existing cgroups after this.
    with_irqs_off(|| install_config(auto_config(&[])));
    Ok(())
});

// The first task to be enabled: the existing cgroups are known by now, the ones
// that come later are new.
bpf_prog!("struct_ops/mitosis_enable",
fn mitosis_enable(_p: Task) {
    if FIRST_NEW_CGID.load(Relaxed) == u64::MAX {
        let last = CGRP_CTXS.lock().last_key_value().map_or(0, |(&cgid, _)| cgid);
        let _ = FIRST_NEW_CGID.compare_exchange(u64::MAX, last, Relaxed, Relaxed);
    }
});

bpf_prog!("struct_ops/mitosis_exit",
fn mitosis_exit(_ei: *const ScxExitInfo) {
});

scx_ops_define!(mitosis_ops, name: b"mitosis", flags: SCX_OPS_ENQ_LAST | SCX_OPS_ALLOW_QUEUED_WAKEUP, timeout_ms: 0,
    select_cpu: mitosis_select_cpu,
    enqueue: mitosis_enqueue,
    dispatch: mitosis_dispatch,
    running: mitosis_running,
    stopping: mitosis_stopping,
    set_cpumask: mitosis_set_cpumask,
    enable: mitosis_enable,
    init_task: mitosis_init_task,
    exit_task: mitosis_exit_task,
    cgroup_init: mitosis_cgroup_init,
    cgroup_exit: mitosis_cgroup_exit,
    cgroup_move: mitosis_cgroup_move,
    dump: mitosis_dump,
    dump_task: mitosis_dump_task,
    init: mitosis_init,
    exit: mitosis_exit,
);

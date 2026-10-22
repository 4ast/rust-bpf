// SPDX-License-Identifier: GPL-2.0
//
// lavd.bpf.h and intf.h: constants, the contexts of tasks, CPUs and compute
// domains, the statistics of the system.
// Copyright (c) 2023, 2024 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

use crate::*;

pub const LAVD_SHIFT: u32 = 10;
pub const LAVD_SCALE: u64 = 1 << LAVD_SHIFT;
/// percent to scale
pub const fn p2s(percent: u64) -> u64 { (percent << LAVD_SHIFT) / 100 }

pub const LAVD_CPDOM_MAX_NR: usize = 128;
pub const LAVD_COMP_TIME_INF: u64 = u64::MAX >> 2;
pub const MAX_RT_PRIO: i32 = 100;

pub const LAVD_TIME_ONE_SEC: u64 = NSEC_PER_SEC;
pub const LAVD_MAX_RETRY: usize = 3;

pub const LAVD_TARGETED_LATENCY_NS: u64 = 10 * NSEC_PER_MSEC;
pub const LAVD_SLICE_MIN_NS_DFL: u64 = 500 * NSEC_PER_USEC;
pub const LAVD_SLICE_MAX_NS_DFL: u64 = 5 * NSEC_PER_MSEC;
pub const LAVD_SLICE_BOOST_BONUS: u64 = LAVD_SLICE_MIN_NS_DFL;
pub const LAVD_SLICE_BOOST_MAX: u64 = 500 * NSEC_PER_MSEC;
pub const LAVD_SLICE_BOOST_UTIL_WALL: u64 = p2s(95);
pub const LAVD_ACC_RUNTIME_MAX: u64 = LAVD_SLICE_MAX_NS_DFL;
pub const LAVD_TASK_LAG_MAX: u64 = 500 * NSEC_PER_MSEC;
/// assuming task's latency criticality is around 1000
pub const LAVD_DL_COMPETE_WINDOW: u64 = (300 * NSEC_PER_MSEC) >> 16;

/// shortest interval: 10usec
pub const LAVD_LC_FREQ_MAX: u64 = 100_000;
pub const LAVD_LC_RUNTIME_MAX: u64 = LAVD_TIME_ONE_SEC;
pub const LAVD_LC_WEIGHT_BOOST_REGULAR: u64 = 128;
pub const LAVD_LC_WEIGHT_BOOST_MEDIUM: u64 = 2 * LAVD_LC_WEIGHT_BOOST_REGULAR;
pub const LAVD_LC_WEIGHT_BOOST_HIGH: u64 = 2 * LAVD_LC_WEIGHT_BOOST_MEDIUM;
pub const LAVD_LC_WEIGHT_BOOST_HIGHEST: u64 = 2 * LAVD_LC_WEIGHT_BOOST_HIGH;
pub const LAVD_LC_GREEDY_SHIFT: u32 = 1;
pub const LAVD_LC_WAKE_INTERVAL_MIN: u64 = LAVD_SLICE_MIN_NS_DFL;
/// 25.0% of receiver's latency criticality
pub const LAVD_LC_INH_RECEIVER_SHIFT: u32 = 2;
/// 12.5% of giver's latency criticality
pub const LAVD_LC_INH_GIVER_SHIFT: u32 = 3;
/// top 12.5% most latency-critical tasks
pub const LAVD_LC_LATENCY_SENSITIVE_THRESH: u64 = LAVD_SCALE - (LAVD_SCALE >> 3);

pub const LAVD_VULN_THRESH_STEP_SIZE: u64 = 64;
pub const LAVD_VULN_THRESH_UTIL_STEPS: u64 = LAVD_SCALE / LAVD_VULN_THRESH_STEP_SIZE;
pub const LAVD_VULN_THRESH_MAX: u64 = LAVD_VULN_THRESH_UTIL_STEPS * LAVD_VULN_THRESH_UTIL_STEPS;
pub const LAVD_VULN_THRESH_INIT: u64 = 32;

pub const LAVD_RAVG_HALFLIFE_NS: u64 = 128 * NSEC_PER_MSEC;

pub const LAVD_SYS_STAT_INTERVAL_NS: u64 = 10 * NSEC_PER_MSEC;
pub const LAVD_SYS_STAT_DECAY_TIMES: u64 = (2 * LAVD_TIME_ONE_SEC) / LAVD_SYS_STAT_INTERVAL_NS;

pub const LAVD_CPU_UTIL_MAX_FOR_CPUPERF: u64 = p2s(85);
pub const LAVD_CPU_UTIL_THR_FOR_MAX_FREQ: u64 = p2s(80);
pub const LAVD_CPUPERF_UP_SHIFT: u32 = 6;
pub const LAVD_CPUPERF_DOWN_SHIFT: u32 = 5;

pub const LAVD_CC_REQ_CAPACITY_HEADROOM: u64 = p2s(25);
pub const LAVD_CC_PER_CPU_UTIL: u64 = p2s(50);
pub const LAVD_CC_UTIL_SPIKE: u64 = p2s(90);
pub const LAVD_CC_CPU_PIN_INTERVAL: u64 = 250 * NSEC_PER_MSEC;
pub const LAVD_CC_CPU_PIN_INTERVAL_DIV: u64 = LAVD_CC_CPU_PIN_INTERVAL / LAVD_SYS_STAT_INTERVAL_NS;
pub const LAVD_AP_HIGH_UTIL_DFL_SMT_RT: u64 = p2s(25);
pub const LAVD_AP_HIGH_UTIL_DFL_NO_SMT_RT: u64 = p2s(50);

/// when under-loaded: 1/2**2 = [-25.0%, +25.0%]
pub const LAVD_CPDOM_MIG_SHIFT_UL: u32 = 2;
/// when mildly loaded: 1/2**3 = [-12.5%, +12.5%]
pub const LAVD_CPDOM_MIG_SHIFT: u32 = 3;
/// when over-loaded: 1/2**4 = [-6.25%, +6.25%]
pub const LAVD_CPDOM_MIG_SHIFT_OL: u32 = 4;
/// roughly twice per interval
pub const LAVD_CPDOM_MIG_PROB_FT: u64 = LAVD_SYS_STAT_INTERVAL_NS / LAVD_SLICE_MAX_NS_DFL;
pub const LAVD_CPU_CONGESTED_THRES: u64 = 1;

/// residence to full heat
pub const LAVD_CPU_WARM_SAT_NS: u64 = 500 * NSEC_PER_USEC;
/// linear decay to 0 once away
pub const LAVD_CPU_WARM_LIFETIME_NS: u64 = 5 * NSEC_PER_MSEC;

// ── READ_ONCE(), WRITE_ONCE(), __sync_*() ────────────────────────────

/// A number that other CPUs read and write while we do.
pub trait Shared {
    type V;
    fn get(&self) -> Self::V;
    fn set(&self, v: Self::V);
    /// `+=` where there is one writer, or where a lost update does no harm.
    fn bump(&self, v: Self::V);
    fn add(&self, v: Self::V);
    fn sub(&self, v: Self::V);
    /// Reads the number and sets it to 0.
    fn take(&self) -> Self::V;
    fn cas(&self, old: Self::V, new: Self::V) -> bool;
    fn raise_to(&self, v: Self::V);
    fn lower_to(&self, v: Self::V);
}

macro_rules! shared {
    ($($atomic:ty: $v:ty,)*) => { $(
        impl Shared for $atomic {
            type V = $v;
            #[inline(always)] fn get(&self) -> $v { self.load(Relaxed) }
            #[inline(always)] fn set(&self, v: $v) { self.store(v, Relaxed) }
            #[inline(always)] fn bump(&self, v: $v) { self.set(self.get().wrapping_add(v)) }
            #[inline(always)] fn add(&self, v: $v) { self.fetch_add(v, Relaxed); }
            #[inline(always)] fn sub(&self, v: $v) { self.fetch_sub(v, Relaxed); }
            #[inline(always)] fn take(&self) -> $v { let v = self.get(); self.set(0); v }
            #[inline(always)] fn cas(&self, old: $v, new: $v) -> bool {
                self.compare_exchange(old, new, Relaxed, Relaxed).is_ok()
            }
            #[inline(always)] fn raise_to(&self, v: $v) { if self.get() < v { self.set(v) } }
            #[inline(always)] fn lower_to(&self, v: $v) { if self.get() > v { self.set(v) } }
        }
    )* };
}

shared! { AtomicU64: u64, AtomicU32: u32, AtomicI64: i64, }

pub trait Switch {
    fn on(&self) -> bool;
    fn turn(&self, on: bool);
}

impl Switch for AtomicBool {
    #[inline(always)] fn on(&self) -> bool { self.load(Relaxed) }
    #[inline(always)] fn turn(&self, on: bool) { self.store(on, Relaxed) }
}

// ── DSQ ids ──────────────────────────────────────────────────────────

const LAVD_DSQ_TYPE_SHFT: u32 = 12;
const LAVD_DSQ_ID_MASK: u64 = 0xfff;

/// The three kinds of queues and how they are numbered.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LavdDsq {
    /// of a physical core, named after its primary CPU
    Cpu(i32),
    /// of a compute domain, for the tasks that a preemption would hurt
    Cpdom(u32),
    /// of a compute domain, for the rest: CPUs with interrupts take these first
    CpdomTurb(u32),
}

impl LavdDsq {
    pub fn dsq(self) -> Dsq {
        Dsq(match self {
            LavdDsq::Cpu(cpu) => cpu as u64 & LAVD_DSQ_ID_MASK,
            LavdDsq::Cpdom(id) => id as u64 | 1 << LAVD_DSQ_TYPE_SHFT,
            LavdDsq::CpdomTurb(id) => id as u64 | 2 << LAVD_DSQ_TYPE_SHFT,
        })
    }
    pub fn nr_queued(self) -> u64 { self.dsq().nr_queued() }
    /// vtime of the task at the head
    pub fn peek_vtime(self) -> Option<u64> { self.dsq().peek().map(Task::dsq_vtime) }
}

// ── Flags of a task ──────────────────────────────────────────────────

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct TaskFlags(pub u64);

macro_rules! task_flags {
    ($($(#[$meta:meta])* $flag:ident = $bit:expr,)*) => {
        #[allow(dead_code)]
        impl TaskFlags { $($(#[$meta])* pub const $flag: TaskFlags = TaskFlags(1 << $bit);)* }
    };
}

task_flags! {
    /// futex acquired or not
    FUTEX_BOOST = 0,
    /// need to boost lock for deadline calculation
    NEED_LOCK_BOOST = 1,
    /// task's overscheduling ratio compared to its nice priority
    IS_GREEDY = 2,
    /// is this task pinned to a subset of all CPUs?
    IS_AFFINITIZED = 3,
    IS_WAKEUP = 4,
    IS_SYNC_WAKEUP = 5,
    /// can a task run on a big core?
    ON_BIG = 6,
    /// can a task run on a little core?
    ON_LITTLE = 7,
    /// task's time slice is boosted
    SLICE_BOOST = 8,
    /// an idle CPU is picked at ops.select_cpu()
    IDLE_CPU_PICKED = 9,
    KSOFTIRQD = 10,
    WOKEN_BY_RT_DL = 11,
    WOKEN_BY_HARDIRQ = 12,
    WOKEN_BY_SOFTIRQ = 13,
    /// immediate task migration is necessary
    MIGRATION_AGGRESSIVE = 14,
    /// task's cpumask is confined to a single compute domain
    DOMAIN_PINNED = 15,
    /// effective cpumask weight is 1
    IS_EFFECTIVELY_PINNED = 16,
    /// wait on the previous CPU: enqueue on its per-CPU DSQ
    WARM_CPU = 17,
}

impl TaskFlags {
    pub fn contains(self, other: TaskFlags) -> bool { self.0 & other.0 == other.0 }
    pub fn insert(&mut self, other: TaskFlags) { self.0 |= other.0 }
    pub fn remove(&mut self, other: TaskFlags) { self.0 &= !other.0 }
    pub fn set(&mut self, other: TaskFlags, on: bool) {
        if on { self.insert(other) } else { self.remove(other) }
    }
    /// Tests the flag and clears it.
    pub fn take(&mut self, other: TaskFlags) -> bool {
        let was = self.contains(other);
        self.remove(other);
        was
    }
}

impl core::ops::BitOr for TaskFlags {
    type Output = TaskFlags;
    fn bitor(self, other: TaskFlags) -> TaskFlags { TaskFlags(self.0 | other.0) }
}

// ── Task context ─────────────────────────────────────────────────────

/// What a queued task added to the counters of a domain or CPU, so that the
/// same amount is taken off again.
#[derive(Clone, Copy)]
pub struct QueuedLoad {
    pub id: u32,
    pub load: u64,
    pub svc: u64,
}

#[derive(Clone)]
pub struct TaskCtx {
    pub flags: TaskFlags,
    /// time slice (wall clock time)
    pub slice_wall: u64,
    /// last time when running time was measured
    pub last_measured_wall_clk: u64,
    /// p->se.sum_exec_runtime at last measurement
    pub last_measured_exec: u64,
    /// run time since the task became runnable
    pub acc_runtime_wall: u64,
    /// the same, capacity and frequency invariant
    pub acc_runtime_invr: u64,
    /// total service time, invariant, divided by the weight
    pub svc_time_iwgt: u64,

    /// final context-aware latency criticality
    pub lat_cri: u64,
    /// lat_cri normalized to [0, 1024]
    pub normalized_lat_cri: u64,
    pub lat_cri_waker: u64,
    pub lat_cri_wakee: u64,
    /// performance criticality
    pub perf_cri: u64,

    /// chosen compute domain at ops.enqueue()
    pub cpdom_id: u32,
    /// suggested CPU at ops.enqueue() and ops.select_cpu()
    pub suggested_cpu_id: i32,
    /// where a pinned task waits, None if not pinned or not runnable
    pub pinned_cpu_id: Option<i32>,

    pub last_running_clk: u64,
    /// scheduling frequency in a second
    pub run_freq: u64,
    /// waiting frequency in a second
    pub wait_freq: u64,
    /// waking-up frequency in a second
    pub wake_freq: u64,
    pub avg_runtime_invr: u64,
    pub avg_runtime_wall: u64,
    pub last_runnable_clk: u64,
    pub last_quiescent_clk: u64,
    pub cgrp_id: u64,
    pub last_slice_used_wall: u64,

    /// where a task is running now
    pub cpu_id: i32,
    /// where a task ran last time
    pub prev_cpu_id: i32,
    pub queued_in_cpdom: Option<QueuedLoad>,
    pub queued_on_cpu: Option<QueuedLoad>,
    pub waker_pid: i32,

    pub util_est: u64,
    pub avg_util_ravg: Ravg,
    /// when cpu_heat was last integrated (task stopped)
    pub last_stopping_clk: u64,
    /// residence-integrated heat for cpu_id [0, LAVD_SCALE]
    pub cpu_heat: u64,
}

pub static TASK_CTXS: TaskMap<TaskCtx> = TaskMap::new();

/// The context of a task that is known to have one.
pub fn get_task_ctx(p: Task) -> Option<&'static mut TaskCtx> {
    let taskc = TASK_CTXS.get(p);
    if taskc.is_none() {
        scx_error!("Failed to lookup task_ctx for task %d", p.pid());
    }
    taskc
}

/// The context of a task that may not be ours.
pub fn find_task_ctx(p: Task) -> Option<&'static mut TaskCtx> { TASK_CTXS.get(p) }

// ── Compute domain context ───────────────────────────────────────────

pub struct Cpdom {
    pub id: u32,
    /// the closest compute domain of the other type (big, little)
    pub alt_id: u32,
    pub numa_id: i32,
    pub llc_id: u32,
    pub is_big: bool,
    /// all CPUs of the domain
    pub all_cpus: CpuSet,
    /// the ones that are online
    pub cpus: CpuSet,
    /// the other domains, by distance and in circular order
    pub neighbors: Vec<Vec<u32>>,

    /// this domain should steal tasks from others
    pub is_stealer: AtomicBool,
    /// stealer domains should steal tasks from this domain
    pub is_stealee: AtomicBool,
    pub nr_active_cpus: AtomicU32,
    pub nr_acpus_temp: AtomicU32,
    /// sum of task_load_metric() of all queued tasks
    pub qload_invr: AtomicU64,
    /// sum of avg_runtime_invr of all queued tasks
    pub qload_svc_invr: AtomicU64,
    /// load for balancing: avg_util_invr_sum + qload_invr
    pub load_invr: AtomicU64,
    pub nr_queued_task: AtomicU64,
    pub cur_util_wall_sum: AtomicU64,
    pub avg_util_wall_sum: AtomicU64,
    pub cur_util_invr_sum: AtomicU64,
    pub avg_util_invr_sum: AtomicU64,
    pub avg_steal_util_invr_sum: AtomicU64,
    pub avg_dom_pinned_util_invr_sum: AtomicU64,
    pub cap_sum_active_cpus: AtomicU64,
    pub cap_sum_temp: AtomicU64,
    pub nr_overflow_cpus: AtomicU64,
    pub cap_sum_overflow_cpus: AtomicU64,
    /// unified lat/util threshold step [0, LAVD_VULN_THRESH_MAX]
    pub vuln_thresh: AtomicU64,
    pub util_sum_steady: AtomicU64,
    pub util_sum_turb: AtomicU64,
    pub cap_sum_steady: AtomicU64,
    pub cap_sum_turb: AtomicU64,
    pub nr_steady_cpus: AtomicU32,
    pub nr_turb_cpus: AtomicU32,
    /// how much load can leave this domain per round
    pub stealee_budget_invr: AtomicI64,
    /// how much additional load this stealer can accept
    pub stealer_budget_invr: AtomicI64,
}

impl Cpdom {
    pub fn new(id: u32, numa_id: i32, is_big: bool) -> Cpdom {
        Cpdom {
            id, alt_id: id, numa_id, llc_id: id, is_big,
            all_cpus: CpuSet::new(),
            cpus: CpuSet::new(),
            neighbors: Vec::new(),
            is_stealer: AtomicBool::new(false),
            is_stealee: AtomicBool::new(false),
            nr_active_cpus: AtomicU32::new(0),
            nr_acpus_temp: AtomicU32::new(0),
            qload_invr: AtomicU64::new(0),
            qload_svc_invr: AtomicU64::new(0),
            load_invr: AtomicU64::new(0),
            nr_queued_task: AtomicU64::new(0),
            cur_util_wall_sum: AtomicU64::new(0),
            avg_util_wall_sum: AtomicU64::new(0),
            cur_util_invr_sum: AtomicU64::new(0),
            avg_util_invr_sum: AtomicU64::new(0),
            avg_steal_util_invr_sum: AtomicU64::new(0),
            avg_dom_pinned_util_invr_sum: AtomicU64::new(0),
            cap_sum_active_cpus: AtomicU64::new(0),
            cap_sum_temp: AtomicU64::new(0),
            nr_overflow_cpus: AtomicU64::new(0),
            cap_sum_overflow_cpus: AtomicU64::new(0),
            vuln_thresh: AtomicU64::new(LAVD_VULN_THRESH_INIT),
            util_sum_steady: AtomicU64::new(0),
            util_sum_turb: AtomicU64::new(0),
            cap_sum_steady: AtomicU64::new(0),
            cap_sum_turb: AtomicU64::new(0),
            nr_steady_cpus: AtomicU32::new(0),
            nr_turb_cpus: AtomicU32::new(0),
            stealee_budget_invr: AtomicI64::new(0),
            stealer_budget_invr: AtomicI64::new(0),
        }
    }

    pub fn dsq(&self) -> LavdDsq { LavdDsq::Cpdom(self.id) }
    pub fn turb_dsq(&self) -> LavdDsq { LavdDsq::CpdomTurb(self.id) }

    /// The other domains, the closest first.
    pub fn neighbors(&self) -> impl Iterator<Item = &'static Cpdom> + '_ {
        self.neighbors.iter().flatten().filter_map(|&id| cpdoms().get(id as usize))
    }

    pub fn decrement_stealee_budget(&self, amount: u64) {
        self.stealee_budget_invr.sub(amount as i64);
        if self.stealee_budget_invr.get() <= 0 {
            self.is_stealee.turn(false);
        }
    }

    pub fn decrement_stealer_budget(&self, amount: u64) {
        self.stealer_budget_invr.sub(amount as i64);
        if self.stealer_budget_invr.get() <= 0 {
            self.is_stealer.turn(false);
        }
    }

    pub fn set_role(&self, stealer: Option<u64>, stealee: Option<u64>) {
        self.stealer_budget_invr.set(stealer.unwrap_or(0) as i64);
        self.stealee_budget_invr.set(stealee.unwrap_or(0) as i64);
        self.is_stealer.turn(stealer.is_some());
        self.is_stealee.turn(stealee.is_some());
    }
}

pub static CPDOMS: BpfCell<Vec<Cpdom>> = BpfCell::new(Vec::new());

pub fn cpdoms() -> &'static [Cpdom] { CPDOMS.get() }
pub fn nr_cpdoms() -> usize { cpdoms().len() }

pub fn get_cpdom(id: u32) -> Option<&'static Cpdom> {
    let cpdomc = cpdoms().get(id as usize);
    if cpdomc.is_none() {
        scx_error!("Failed to lookup cpdom_ctx for %u", id);
    }
    cpdomc
}

// ── CPU context ──────────────────────────────────────────────────────

#[derive(Default)]
pub struct CpuCtx {
    /// cached copy of the flags of the running task
    pub flags: AtomicU64,
    /// estimated stopping time
    pub est_stopping_clk: AtomicU64,
    /// when a task starts running
    pub running_clk: AtomicU64,
    pub lat_cri: AtomicU64,
    /// the capacity that the CPU has right now
    pub effective_capacity: AtomicU64,
    pub cpu_id: i32,
    pub max_capacity: u64,
    pub sum_lat_cri: AtomicU64,
    pub max_lat_cri: AtomicU64,
    /// the number of pinned tasks waiting for running on this CPU
    pub nr_pinned_tasks: AtomicU32,
    pub cpdom_id: u32,
    pub big_core: bool,
    pub turbo_core: bool,
    pub is_online: AtomicBool,
    /// effective_capacity counted in the overflow set
    pub ovrflw_cap: AtomicU64,
    /// the op of the futex(2) that is under way
    pub futex_op: AtomicU32,

    pub tot_task_time_wall: AtomicU64,
    pub tot_task_time_iwgt: AtomicU64,
    pub tot_task_time_invr: AtomicU64,
    pub tot_dom_pinned_task_time_invr: AtomicU64,
    pub sum_perf_cri: AtomicU64,
    pub min_perf_cri: AtomicU64,
    pub max_perf_cri: AtomicU64,
    pub nr_sched: AtomicU64,
    pub nr_preempt: AtomicU64,
    pub nr_x_migration: AtomicU64,
    pub nr_perf_cri: AtomicU64,
    pub nr_lat_cri: AtomicU64,

    pub avg_util_wall: AtomicU64,
    pub cur_util_wall: AtomicU64,
    pub avg_util_invr: AtomicU64,
    pub cur_util_invr: AtomicU64,
    /// what interrupts and higher scheduling classes leave of this CPU
    pub lat_headroom: AtomicU64,
    /// computed at the last sys_stat interval, committed at ops.running()
    pub cpuperf_target: AtomicU64,
    pub cpuperf_cur: AtomicU64,
    pub cur_steal_util_wall: AtomicU64,
    pub avg_steal_util_wall: AtomicU64,
    pub cur_steal_util_invr: AtomicU64,
    pub avg_steal_util_invr: AtomicU64,
    pub avg_dom_pinned_util_invr: AtomicU64,
    pub idle_total_wall: AtomicU64,
    pub idle_start_clk: AtomicU64,
    /// maximum frequency observed within an interval, scaled to 1024
    pub max_freq_observed: AtomicU64,
    /// the same averaged across intervals
    pub max_freq: AtomicU64,

    pub avg_irq_steal_ravg: RavgCell,
    pub avg_util_ravg: RavgCell,
    pub util_est: AtomicU64,
    pub qload_invr: AtomicU64,
    pub qload_svc_invr: AtomicU64,
}

impl CpuCtx {
    pub fn task_flags(&self) -> TaskFlags { TaskFlags(self.flags.get()) }
    pub fn test_flag(&self, flag: TaskFlags) -> bool { self.task_flags().contains(flag) }
    pub fn reset_flag(&self, flag: TaskFlags) { self.flags.set(self.flags.get() & !flag.0) }
    pub fn is_lock_holder_running(&self) -> bool { self.test_flag(TaskFlags::FUTEX_BOOST) }
    pub fn cpdom(&self) -> Option<&'static Cpdom> { get_cpdom(self.cpdom_id) }
    pub fn local_dsq(&self) -> Dsq { Dsq::local_on(self.cpu_id) }

    pub fn is_turbulent(&self) -> bool { self.lat_headroom.get() < LAVD_LC_LATENCY_SENSITIVE_THRESH }

    /// From wall clock time on this CPU to time that does not depend on the
    /// capacity of the CPU and its frequency.
    pub fn wall_to_invr(&self, wall: u64) -> u64 {
        let freq = cpuperf_cur(self.cpu_id) as u64;
        self.max_freq_observed.raise_to(freq);
        (wall * self.max_capacity * freq) >> (2 * LAVD_SHIFT)
    }

    pub fn reset_preemption_info(&self) {
        self.flags.set(0);
        self.lat_cri.set(0);
        self.est_stopping_clk.set(SCX_SLICE_INF);
    }
}

pub static CPU_CTXS: BpfCell<Vec<CpuCtx>> = BpfCell::new(Vec::new());

pub fn cpu_ctxs() -> &'static [CpuCtx] { CPU_CTXS.get() }

pub fn get_cpu_ctx_id(cpu: i32) -> Option<&'static CpuCtx> {
    let cpuc = usize::try_from(cpu).ok().and_then(|cpu| cpu_ctxs().get(cpu));
    if cpuc.is_none() {
        scx_error!("Failed to lookup cpu_ctx %d", cpu);
    }
    cpuc
}

pub fn get_cpu_ctx() -> Option<&'static CpuCtx> { get_cpu_ctx_id(this_cpu()) }
pub fn get_cpu_ctx_task(p: Task) -> Option<&'static CpuCtx> { get_cpu_ctx_id(p.cpu()) }

// ── System-wide statistics ───────────────────────────────────────────

pub struct SysStat {
    pub last_update_clk: AtomicU64,
    /// average of the CPU utilization (wall clock time)
    pub avg_util_wall: AtomicU64,
    /// the same, capacity and frequency invariant
    pub avg_util_invr: AtomicU64,
    /// average service time per task
    pub avg_svc_time_iwgt: AtomicU64,
    pub nr_queued_task: AtomicU64,
    /// base time slice
    pub slice_wall: AtomicU64,

    pub avg_lat_cri: AtomicU64,
    pub max_lat_cri: AtomicU64,
    /// latency criticality threshold for kicking
    pub thr_lat_cri: AtomicU64,

    pub min_perf_cri: AtomicU64,
    pub avg_perf_cri: AtomicU64,
    pub max_perf_cri: AtomicU64,
    pub thr_perf_cri: AtomicU64,

    /// number of compute domains to be migrated
    pub nr_stealee: AtomicU64,
    pub nr_active: AtomicU64,
    pub nr_active_cpdoms: AtomicU64,

    pub nr_sched: AtomicU64,
    pub nr_preempt: AtomicU64,
    pub nr_perf_cri: AtomicU64,
    pub nr_lat_cri: AtomicU64,
    pub nr_x_migration: AtomicU64,
    pub nr_big: AtomicU64,
    pub nr_pc_on_big: AtomicU64,
    pub nr_lc_on_big: AtomicU64,
}

const ZERO: AtomicU64 = AtomicU64::new(0);

#[export_name = "lavd_sys_stat"]
pub static SYS_STAT: SysStat = SysStat {
    last_update_clk: ZERO, avg_util_wall: ZERO, avg_util_invr: ZERO, avg_svc_time_iwgt: ZERO,
    nr_queued_task: ZERO, slice_wall: ZERO, avg_lat_cri: ZERO, max_lat_cri: ZERO, thr_lat_cri: ZERO,
    min_perf_cri: ZERO, avg_perf_cri: ZERO, max_perf_cri: ZERO, thr_perf_cri: ZERO, nr_stealee: ZERO,
    nr_active: ZERO, nr_active_cpdoms: ZERO, nr_sched: ZERO, nr_preempt: ZERO, nr_perf_cri: ZERO,
    nr_lat_cri: ZERO, nr_x_migration: ZERO, nr_big: ZERO, nr_pc_on_big: ZERO, nr_lc_on_big: ZERO,
};

// ── Sets of CPUs and other global state ──────────────────────────────

pub static TURBO_CPUS: CpuSet = CpuSet::new();
pub static BIG_CPUS: CpuSet = CpuSet::new();
/// where tasks are placed
pub static ACTIVE_CPUS: CpuSet = CpuSet::new();
/// where they go when the active CPUs don't do
pub static OVRFLW_CPUS: CpuSet = CpuSet::new();
/// the CPUs that interrupts leave alone
pub static STEADY_CPUS: CpuSet = CpuSet::new();
pub static ONLINE_CPUS: CpuSet = CpuSet::new();

pub static NR_CPU_IDS: AtomicU32 = AtomicU32::new(0);
pub static NR_CPUS_ONLN: AtomicU64 = AtomicU64::new(0);
pub static HAVE_TURBO_CORE: AtomicBool = AtomicBool::new(false);
pub static HAVE_LITTLE_CORE: AtomicBool = AtomicBool::new(false);
/// overflow CPUs are also counted as active
pub static OVRFLW_COUNTED_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static REINIT_CPUMASK_FOR_PERFORMANCE: AtomicBool = AtomicBool::new(false);

/// Logical current clock
pub static CUR_LOGICAL_CLK: AtomicU64 = AtomicU64::new(LAVD_DL_COMPETE_WINDOW);
/// Current service time
pub static CUR_SVC_TIME_IWGT: AtomicU64 = AtomicU64::new(0);

pub fn nr_cpus() -> i32 { NR_CPU_IDS.get() as i32 }

pub fn use_per_cpu_dsq() -> bool { PER_CPU_DSQ.on() || PINNED_SLICE_NS.get() != 0 || WARM_CPU_NS.get() != 0 }
pub fn is_per_cpu_dsq_migratable() -> bool { PER_CPU_DSQ.on() }
pub fn use_cpdom_dsq() -> bool { !PER_CPU_DSQ.on() }

/// Adds a CPU to the overflow set. Returns whether it was in there already.
pub fn ovrflw_test_and_set(cpu: i32) -> bool {
    if OVRFLW_CPUS.test_and_set(cpu) {
        return true;
    }
    if let Some((cpuc, cpdc)) = get_cpu_ctx_id(cpu).and_then(|cpuc| Some((cpuc, cpuc.cpdom()?))) {
        cpdc.nr_overflow_cpus.add(1);
        cpuc.ovrflw_cap.set(cpuc.effective_capacity.get());
        cpdc.cap_sum_overflow_cpus.add(cpuc.ovrflw_cap.get());
    }
    false
}

/// Takes a CPU out of the overflow set. Returns whether it was in there.
pub fn ovrflw_test_and_clear(cpu: i32) -> bool {
    if !OVRFLW_CPUS.test_and_clear(cpu) {
        return false;
    }
    if let Some((cpuc, cpdc)) = get_cpu_ctx_id(cpu).and_then(|cpuc| Some((cpuc, cpuc.cpdom()?))) {
        cpdc.nr_overflow_cpus.sub(1);
        cpdc.cap_sum_overflow_cpus.sub(cpuc.ovrflw_cap.get());
    }
    true
}

/// How much a preemption hurts a task: latency critical tasks first, then the
/// ones that use a lot of CPU.
pub fn preemption_vulnerability(normalized_lat_cri: u64, util_est: u64) -> u64 {
    let lat_step = normalized_lat_cri / LAVD_VULN_THRESH_STEP_SIZE;
    let util_step = util_est / LAVD_VULN_THRESH_STEP_SIZE;
    lat_step * LAVD_VULN_THRESH_UTIL_STEPS + util_step
}

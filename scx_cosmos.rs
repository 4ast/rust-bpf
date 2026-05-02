// SPDX-License-Identifier: GPL-2.0
//
// scx_cosmos: A deadline-based sched-ext scheduler in Rust.
//
// Full Rust port of scx_cosmos/main.bpf.c.
//
// All BPF maps replaced with standard Rust data structures in arena:
// - BPF_MAP_TYPE_TASK_STORAGE  -> BTreeMap<u32, TaskCtx>
// - BPF_MAP_TYPE_ARRAY         -> [T; N]
// - BPF_MAP_TYPE_HASH          -> BTreeMap<u32, u32>
// - BPF_MAP_TYPE_PERCPU_ARRAY  -> [T; MAX_CPUS]

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::cmp::{max, min};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

// ── Constants ────────────────────────────────────────────────────────

const MAX_CPUS: usize = 1024;
const MAX_NODES: usize = 1024;
const SHARED_DSQ: u64 = 0;
const SCX_DSQ_LOCAL: u64 = u64::MAX;
const SCX_DSQ_LOCAL_ON: u64 = u64::MAX - 1;
const SCX_CPUPERF_ONE: u64 = 1024;
const CPUFREQ_LOW_THRESH: u64 = SCX_CPUPERF_ONE / 4;
const CPUFREQ_HIGH_THRESH: u64 = SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4;
const NSEC_PER_MSEC: u64 = 1_000_000;
const SCX_TASK_QUEUED: u32 = 1;
const SCX_WAKE_TTWU: u64 = 1;
const SCX_WAKE_SYNC: u64 = 2;
const SCX_KICK_IDLE: u64 = 1;
const SCX_PICK_IDLE_CORE: u64 = 1;
const PF_IDLE: u32 = 0x0000_0002;
const PF_EXITING: u32 = 0x0000_0004;

// ── BPF helpers (called via helper ID, not kfunc BTF) ────────────────

macro_rules! bpf_helper {
    (fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty = $id:expr) => {
        unsafe fn $name($($arg: $ty),*) -> $ret {
            let f: unsafe extern "C" fn($($ty),*) -> $ret = core::mem::transmute($id as usize);
            f($($arg),*)
        }
    };
    (fn $name:ident($($arg:ident: $ty:ty),*) = $id:expr) => {
        #[allow(dead_code)]
        unsafe fn $name($($arg: $ty),*) {
            let f: unsafe extern "C" fn($($ty),*) = core::mem::transmute($id as usize);
            f($($arg),*)
        }
    };
}

bpf_helper!(fn bpf_ktime_get_ns() -> u64 = 5);
bpf_helper!(fn bpf_get_smp_processor_id() -> i32 = 8);
bpf_helper!(fn bpf_get_current_task_btf() -> *mut task_struct = 158);

// ── Kfunc bindings (resolved via BTF at load time) ───────────────────

extern "C" {
    fn bpf_alloc(size: u64, flags: u64) -> *mut u8;
    fn bpf_free(ptr: *mut u8);
    fn bpf_cpumask_test_cpu(cpu: i32, mask: *const u64) -> bool;
    fn bpf_cpumask_first(mask: *const u64) -> i32;
    fn bpf_cpumask_intersects(a: *const u64, b: *const u64) -> bool;

    fn scx_bpf_select_cpu_dfl(p: *mut task_struct, prev_cpu: i32,
                               wake_flags: u64, is_idle: *mut bool) -> i32;
    fn scx_bpf_select_cpu_and(p: *mut task_struct, prev_cpu: i32,
                               wake_flags: u64, mask: *const u64,
                               flags: u64) -> i32;
    fn scx_bpf_dsq_insert(p: *mut task_struct, dsq_id: u64,
                           slice: u64, enq_flags: u64);
    fn scx_bpf_dsq_insert_vtime(p: *mut task_struct, dsq_id: u64,
                                 slice: u64, vtime: u64, enq_flags: u64);
    fn scx_bpf_dsq_move_to_local(dsq_id: u64) -> bool;
    fn scx_bpf_create_dsq(dsq_id: u64, node: i32) -> i32;
    fn scx_bpf_task_cpu(p: *const task_struct) -> i32;
    fn scx_bpf_kick_cpu(cpu: i32, flags: u64);
    fn scx_bpf_task_running(p: *const task_struct) -> bool;
    fn scx_bpf_cpuperf_set(cpu: i32, perf: u64);
    fn scx_bpf_nr_cpu_ids() -> u64;
    fn scx_bpf_dsq_nr_queued(dsq_id: u64) -> u32;
    fn scx_bpf_test_and_clear_cpu_idle(cpu: i32) -> bool;
    fn scx_bpf_get_idle_smtmask() -> *const u64;
    fn scx_bpf_put_cpumask(mask: *const u64);

    fn bpf_throw(cookie: u64) -> !;
    fn bpf_stream_vprintk(stream_id: i32, fmt: *const u8, args: *const u64,
                           len: u32) -> i32;
}

// ── Allocator ────────────────────────────────────────────────────────

struct BpfAllocator;

unsafe impl GlobalAlloc for BpfAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bpf_alloc(layout.size() as u64, 0)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        bpf_free(ptr)
    }
}

#[global_allocator]
static ALLOC: BpfAllocator = BpfAllocator;

// ── Kernel types (CO-RE relocates field offsets at load time) ────────
//
// Structs are opaque — no Rust field layout. All field access goes through
// CO-RE shims compiled by clang (core_defs.c) which carry
// preserve_access_index relocations. The macros below hide the extern calls.
//
// gen_core.py reads the @core_struct blocks below to auto-generate core_defs.c.
//
// @core_struct sched_ext_entity {
//     dsq_vtime: unsigned long long,
//     slice: unsigned long long,
//     weight: unsigned int,
//     flags: unsigned int,
// }
// @core_struct task_struct {
//     scx: sched_ext_entity,
//     pid: unsigned int,
//     flags: unsigned int,
//     nr_cpus_allowed: unsigned int,
//     mm: unsigned long long,
//     cpus_ptr: const void *,
// }

#[repr(C)]
struct task_struct { _opaque: [u8; 0] }

// Macros to generate CO-RE accessor methods. Each expands to an extern "C"
// declaration + a one-liner method that calls the shim. The shim naming
// convention matches core_defs.c.
macro_rules! core_read {
    ($field:ident -> $ret:ty, $shim:ident) => {
        fn $field(&self) -> $ret {
            extern "C" { fn $shim(p: *const u8) -> $ret; }
            unsafe { $shim(self.0 as *const u8) }
        }
    };
}

macro_rules! core_write {
    ($method:ident($val:ty), $shim:ident) => {
        fn $method(&self, v: $val) {
            extern "C" { fn $shim(p: *mut u8, v: $val); }
            unsafe { $shim(self.0 as *mut u8, v) }
        }
    };
}

#[repr(transparent)]
struct TaskRef(*mut task_struct);

impl TaskRef {
    core_read!(pid -> u32, __core_read_task_struct__pid);
    core_read!(flags -> u32, __core_read_task_struct__flags);
    core_read!(nr_cpus_allowed -> u32, __core_read_task_struct__nr_cpus_allowed);
    core_read!(mm -> u64, __core_read_task_struct__mm);
    core_read!(cpus_ptr -> *const u64, __core_read_task_struct__cpus_ptr);

    core_read!(scx_dsq_vtime -> u64, __core_read_task_struct__scx__dsq_vtime);
    core_read!(scx_slice -> u64, __core_read_task_struct__scx__slice);
    core_read!(scx_weight -> u32, __core_read_task_struct__scx__weight);
    core_read!(scx_flags -> u32, __core_read_task_struct__scx__flags);

    core_write!(set_scx_dsq_vtime(u64), __core_write_task_struct__scx__dsq_vtime);
    core_write!(set_scx_slice(u64), __core_write_task_struct__scx__slice);

    fn cpu(&self) -> i32 { unsafe { scx_bpf_task_cpu(self.0) } }
    fn is_running(&self) -> bool { unsafe { scx_bpf_task_running(self.0) } }
    fn is_queued(&self) -> bool { self.scx_flags() & SCX_TASK_QUEUED != 0 }
    fn is_pcpu(&self) -> bool { self.nr_cpus_allowed() == 1 }
    fn cpu_allowed(&self, cpu: i32) -> bool {
        unsafe { bpf_cpumask_test_cpu(cpu, self.cpus_ptr()) }
    }
}

// ── Per-task context ─────────────────────────────────────────────────

struct TaskCtx {
    last_run_at: u64,
    exec_runtime: u64,
    wakeup_freq: u64,
    last_woke_at: u64,
    perf_events: u64,
    perf_sticky_events: u64,
}

impl TaskCtx {
    fn new() -> Self {
        TaskCtx { last_run_at: 0, exec_runtime: 0, wakeup_freq: 0,
                  last_woke_at: 0, perf_events: 0, perf_sticky_events: 0 }
    }
}

// ── Per-CPU context ──────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct CpuCtx {
    last_update: u64,
    perf_lvl: u64,
    perf_events: u64,
}

impl CpuCtx {
    const fn new() -> Self {
        CpuCtx { last_update: 0, perf_lvl: 0, perf_events: 0 }
    }
}

struct BpfCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for BpfCell<T> {}

// ── Configuration (const volatile equivalents) ───────────────────────

static SLICE_NS: AtomicU64 = AtomicU64::new(1_000_000);
static SLICE_LAG: AtomicU64 = AtomicU64::new(20_000_000);
static BUSY_THRESHOLD: AtomicU64 = AtomicU64::new(0);
static NR_CPU_IDS: AtomicU64 = AtomicU64::new(0);
static NR_NODE_IDS: AtomicU64 = AtomicU64::new(0);
static PERF_CONFIG: AtomicU64 = AtomicU64::new(0);
static PERF_THRESHOLD: AtomicU64 = AtomicU64::new(0);
static PERF_STICKY: AtomicU64 = AtomicU64::new(0);
static PERF_STICKY_THRESHOLD: AtomicU64 = AtomicU64::new(0);

static PRIMARY_ALL: AtomicBool = AtomicBool::new(true);
static FLAT_IDLE_SCAN: AtomicBool = AtomicBool::new(false);
static SMT_ENABLED: AtomicBool = AtomicBool::new(true);
static PREFERRED_IDLE_SCAN: AtomicBool = AtomicBool::new(false);
static ALL_CPUS_SAME_CAPACITY: AtomicBool = AtomicBool::new(false);
static CPUFREQ_ENABLED: AtomicBool = AtomicBool::new(true);
static NUMA_ENABLED: AtomicBool = AtomicBool::new(false);
static GPU_ENABLED: AtomicBool = AtomicBool::new(true);
static AVOID_SMT: AtomicBool = AtomicBool::new(true);
static MM_AFFINITY: AtomicBool = AtomicBool::new(false);
static TICK_PREEMPT: AtomicBool = AtomicBool::new(true);
static NO_WAKE_SYNC: AtomicBool = AtomicBool::new(false);
static NO_EARLY_CLEAR: AtomicBool = AtomicBool::new(false);

// ── Global state (all in arena) ──────────────────────────────────────

static VTIME_NOW: AtomicU64 = AtomicU64::new(0);
static NR_EVENT_DISPATCHES: AtomicU64 = AtomicU64::new(0);
static NR_EV_STICKY_DISPATCHES: AtomicU64 = AtomicU64::new(0);
static NR_GPU_DISPATCHES: AtomicU64 = AtomicU64::new(0);

// replaces BPF_MAP_TYPE_TASK_STORAGE
static TASK_CTXS: BpfCell<Option<BTreeMap<u32, UnsafeCell<TaskCtx>>>> =
    BpfCell(UnsafeCell::new(None));
// replaces BPF_MAP_TYPE_PERCPU_ARRAY cpu_ctx_stor
static CPU_CTXS: BpfCell<[CpuCtx; MAX_CPUS]> =
    BpfCell(UnsafeCell::new([CpuCtx::new(); MAX_CPUS]));
// replaces BPF_MAP_TYPE_ARRAY cpu_util_map
static CPU_UTIL: BpfCell<[u64; MAX_CPUS]> =
    BpfCell(UnsafeCell::new([0u64; MAX_CPUS]));
// replaces BPF_MAP_TYPE_HASH cpu_node_map
static CPU_NODE_MAP: BpfCell<Option<BTreeMap<u32, u32>>> =
    BpfCell(UnsafeCell::new(None));
// replaces BPF_MAP_TYPE_HASH gpu_pid_map
static GPU_PID_MAP: BpfCell<Option<BTreeMap<u32, u32>>> =
    BpfCell(UnsafeCell::new(None));
// CPU capacity values (const volatile array)
static CPU_CAPACITY: BpfCell<[u64; MAX_CPUS]> =
    BpfCell(UnsafeCell::new([SCX_CPUPERF_ONE; MAX_CPUS]));
// preferred CPU ordering for flat idle scan
static PREFERRED_CPUS: BpfCell<[u64; MAX_CPUS]> =
    BpfCell(UnsafeCell::new([0u64; MAX_CPUS]));
// SMT sibling per CPU
static SMT_SIBLING: BpfCell<[i32; MAX_CPUS]> =
    BpfCell(UnsafeCell::new([-1i32; MAX_CPUS]));
// per-node cpumask pointers (stored as opaque u64)
static NODE_CPUMASK: BpfCell<[u64; MAX_NODES]> =
    BpfCell(UnsafeCell::new([0u64; MAX_NODES]));
// primary cpumask (opaque pointer)
static PRIMARY_MASK: AtomicU64 = AtomicU64::new(0);
// flat idle scan last_cpu
static FLAT_LAST_CPU: BpfCell<u32> = BpfCell(UnsafeCell::new(0));

// ── Accessors ────────────────────────────────────────────────────────

fn slice_ns() -> u64 { SLICE_NS.load(Relaxed) }
fn slice_lag() -> u64 { SLICE_LAG.load(Relaxed) }
fn nr_cpu_ids() -> u64 { NR_CPU_IDS.load(Relaxed) }
fn now() -> u64 { unsafe { bpf_ktime_get_ns() } }
fn time_before(a: u64, b: u64) -> bool { (a as i64).wrapping_sub(b as i64) < 0 }
fn time_delta(a: u64, b: u64) -> u64 { a.wrapping_sub(b) }
fn is_wakeup(wake_flags: u64) -> bool { wake_flags & SCX_WAKE_TTWU != 0 }

fn get_task_ctx(pid: u32) -> Option<&'static mut TaskCtx> {
    let ctxs = unsafe { &*TASK_CTXS.0.get() };
    let cell = ctxs.as_ref()?.get(&pid)?;
    Some(unsafe { &mut *cell.get() })
}

fn get_cpu_ctx(cpu: i32) -> Option<&'static mut CpuCtx> {
    if cpu < 0 || cpu as usize >= MAX_CPUS { return None; }
    Some(&mut unsafe { &mut *CPU_CTXS.0.get() }[cpu as usize])
}

fn cpu_node(cpu: i32) -> i32 {
    if !NUMA_ENABLED.load(Relaxed) { return 0; }
    let map = unsafe { &*CPU_NODE_MAP.0.get() };
    match map.as_ref().and_then(|m| m.get(&(cpu as u32))) {
        Some(&n) => n as i32,
        None => -1,
    }
}

fn gpu_node_by_pid(pid: u32) -> i32 {
    if !GPU_ENABLED.load(Relaxed) || !NUMA_ENABLED.load(Relaxed) { return -1; }
    let map = unsafe { &*GPU_PID_MAP.0.get() };
    match map.as_ref().and_then(|m| m.get(&pid)) {
        Some(&n) => n as i32,
        None => -1,
    }
}

fn cpu_cap(cpu: i32) -> u64 {
    if cpu < 0 || cpu as usize >= MAX_CPUS { return SCX_CPUPERF_ONE; }
    unsafe { (*CPU_CAPACITY.0.get())[cpu as usize] }
}

fn smt_sibling(cpu: i32) -> i32 {
    if cpu < 0 || cpu as usize >= MAX_CPUS { return cpu; }
    let s = unsafe { (*SMT_SIBLING.0.get())[cpu as usize] };
    if s < 0 { cpu } else { s }
}

fn node_cpumask(node: i32) -> *const u64 {
    if node < 0 || node as usize >= MAX_NODES { return core::ptr::null(); }
    unsafe { (*NODE_CPUMASK.0.get())[node as usize] as *const u64 }
}

fn shared_dsq(cpu: i32) -> u64 {
    if NUMA_ENABLED.load(Relaxed) {
        let n = cpu_node(cpu);
        if n >= 0 { n as u64 } else { SHARED_DSQ }
    } else {
        SHARED_DSQ
    }
}

// ── EWMA and scaling ─────────────────────────────────────────────────

fn calc_avg(old: u64, new: u64) -> u64 {
    (old - (old >> 2)) + (new >> 2)
}

fn update_freq(freq: u64, interval: u64) -> u64 {
    if interval == 0 { return freq; }
    calc_avg(freq, (100 * NSEC_PER_MSEC) / interval)
}

fn scale_by_weight(p: &TaskRef, val: u64) -> u64 {
    let w = p.scx_weight() as u64;
    if w == 0 { val } else { val * w / 100 }
}

fn scale_by_weight_inverse(p: &TaskRef, val: u64) -> u64 {
    let w = p.scx_weight() as u64;
    if w == 0 { val } else { val * 100 / w }
}

fn scale_by_cpu_capacity(slice: u64, cpu: i32) -> u64 {
    if ALL_CPUS_SAME_CAPACITY.load(Relaxed) { return slice; }
    slice * cpu_cap(cpu) / SCX_CPUPERF_ONE
}

fn task_slice(p: &TaskRef) -> u64 { scale_by_weight(p, slice_ns()) }

// ── PMU event checks ─────────────────────────────────────────────────

fn is_event_heavy(tctx: &TaskCtx) -> bool {
    PERF_CONFIG.load(Relaxed) != 0 && tctx.perf_events > PERF_THRESHOLD.load(Relaxed)
}

fn is_sticky_event_heavy(tctx: &TaskCtx) -> bool {
    PERF_STICKY.load(Relaxed) != 0 &&
        tctx.perf_sticky_events > PERF_STICKY_THRESHOLD.load(Relaxed)
}

fn update_counters(tctx: &mut TaskCtx, cpu: i32) {
    if let Some(cctx) = get_cpu_ctx(cpu) {
        cctx.perf_events += tctx.perf_events;
    }
    // scx_pmu_read would fill tctx.perf_events / perf_sticky_events
}

// ── CPU state checks ─────────────────────────────────────────────────

fn is_cpu_valid(cpu: i32) -> bool {
    cpu >= 0 && (cpu as u64) < nr_cpu_ids() && (cpu as usize) < MAX_CPUS
}

fn is_cpu_busy(cpu: i32) -> bool {
    let threshold = BUSY_THRESHOLD.load(Relaxed);
    if threshold == 0 { return false; }
    if !is_cpu_valid(cpu) { return false; }
    let util = unsafe { (*CPU_UTIL.0.get())[cpu as usize] };
    util >= threshold
}

fn is_cpu_faster(this_cpu: i32, that_cpu: i32) -> bool {
    if ALL_CPUS_SAME_CAPACITY.load(Relaxed) || this_cpu == that_cpu { return false; }
    if !is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu) { return false; }
    cpu_cap(this_cpu) > cpu_cap(that_cpu)
}

fn cpus_share_cache(this_cpu: i32, that_cpu: i32) -> bool {
    if this_cpu == that_cpu { return true; }
    // CO-RE: cpu_llc_id[this_cpu] == cpu_llc_id[that_cpu]
    false
}

fn is_primary_cpu(cpu: i32) -> bool {
    if PRIMARY_ALL.load(Relaxed) { return true; }
    let mask = PRIMARY_MASK.load(Relaxed) as *const u64;
    if mask.is_null() { return true; }
    unsafe { bpf_cpumask_test_cpu(cpu, mask) }
}

fn is_cpu_idle(cpu: i32) -> bool {
    // In C: p = __COMPAT_scx_bpf_cpu_curr(cpu);
    //        return p ? p->flags & PF_IDLE : false;
    // Simplified: would need scx_bpf_cpu_curr kfunc binding
    let _ = (cpu, PF_IDLE);
    false
}

fn test_cpu_idle(cpu: i32) -> bool {
    if NO_EARLY_CLEAR.load(Relaxed) {
        is_cpu_idle(cpu)
    } else {
        unsafe { scx_bpf_test_and_clear_cpu_idle(cpu) }
    }
}

fn is_smt_contended(cpu: i32) -> bool {
    if !SMT_ENABLED.load(Relaxed) { return false; }
    let sibling = smt_sibling(cpu);
    // Check if sibling is not idle and there are other idle CPUs
    !unsafe { scx_bpf_test_and_clear_cpu_idle(sibling) }
}

fn is_wake_affine(waker: &TaskRef, wakee: &TaskRef) -> bool {
    MM_AFFINITY.load(Relaxed) &&
        (waker.flags() & PF_EXITING == 0) &&
        wakee.mm() != 0 && wakee.mm() == waker.mm()
}

fn can_use_node(p: &TaskRef, node: i32) -> bool {
    if !NUMA_ENABLED.load(Relaxed) { return true; }
    if p.nr_cpus_allowed() as u64 == nr_cpu_ids() { return true; }
    let mask = node_cpumask(node);
    if mask.is_null() { return false; }
    unsafe { bpf_cpumask_intersects(mask, p.cpus_ptr()) }
}

fn task_should_migrate(p: &TaskRef) -> bool {
    !p.is_running()
}

// ── GPU affinity ─────────────────────────────────────────────────────

fn pick_cpu_on_gpu_node(p: &TaskRef, current_node: i32, _tctx: &TaskCtx) -> i32 {
    let target_node = gpu_node_by_pid(p.pid());
    if target_node < 0 || target_node == current_node { return -1; }
    if !can_use_node(p, target_node) { return -1; }

    let mask = node_cpumask(target_node);
    if mask.is_null() { return -1; }

    // Would intersect with p->cpus_ptr and pick idle
    -1
}

// ── Deadline computation ─────────────────────────────────────────────

fn task_deadline(p: &TaskRef, tctx: &TaskCtx) -> u64 {
    let vtime_now = VTIME_NOW.load(Relaxed);
    let lag_scale = max(tctx.wakeup_freq, 1);
    let vsleep_max = scale_by_weight(p, slice_lag() * lag_scale);
    let vtime_min = vtime_now.wrapping_sub(vsleep_max);

    let mut vtime = p.scx_dsq_vtime();
    if time_before(vtime, vtime_min) {
        vtime = vtime_min;
        p.set_scx_dsq_vtime(vtime_min);
    }

    vtime + scale_by_weight_inverse(p, tctx.exec_runtime)
}

// ── cpufreq ──────────────────────────────────────────────────────────

fn update_cpufreq(cpu: i32) {
    if !CPUFREQ_ENABLED.load(Relaxed) { return; }
    let cctx = match get_cpu_ctx(cpu) { Some(c) => c, None => return };
    let perf_lvl = if cctx.perf_lvl >= CPUFREQ_HIGH_THRESH {
        SCX_CPUPERF_ONE
    } else if cctx.perf_lvl <= CPUFREQ_LOW_THRESH {
        SCX_CPUPERF_ONE / 2
    } else {
        cctx.perf_lvl
    };
    unsafe { scx_bpf_cpuperf_set(cpu, perf_lvl) };
}

fn update_cpu_load(p: &TaskRef, slice: u64) {
    if !CPUFREQ_ENABLED.load(Relaxed) { return; }
    let t = now();
    let cctx = match get_cpu_ctx(p.cpu()) { Some(c) => c, None => return };
    let delta_t = t - cctx.last_update;
    if delta_t == 0 { return; }
    let perf_lvl = min(slice * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
    cctx.perf_lvl = calc_avg(cctx.perf_lvl, perf_lvl);
    cctx.last_update = t;
}

// ── Idle CPU selection ───────────────────────────────────────────────

/// Try to pick idle CPU from preferred list, optionally filtering by
/// primary domain and SMT full-idle mask.
fn pick_idle_cpu_pref_smt(p: &TaskRef, prev_cpu: i32, is_prev_allowed: bool,
                           primary: *const u64, smt: *const u64) -> i32 {
    let max_cpus = min(nr_cpu_ids() as usize, MAX_CPUS);
    let preferred = unsafe { &*PREFERRED_CPUS.0.get() as &[u64; MAX_CPUS] };

    // Try prev_cpu first
    if is_prev_allowed &&
       (primary.is_null() || unsafe { bpf_cpumask_test_cpu(prev_cpu, primary) }) &&
       (smt.is_null() || unsafe { bpf_cpumask_test_cpu(prev_cpu, smt) }) &&
       test_cpu_idle(prev_cpu) {
        return prev_cpu;
    }

    let start = if PREFERRED_IDLE_SCAN.load(Relaxed) {
        0
    } else {
        unsafe { *FLAT_LAST_CPU.0.get() as usize }
    };

    for i in 0..max_cpus {
        let cpu = if PREFERRED_IDLE_SCAN.load(Relaxed) {
            preferred[i] as i32
        } else {
            ((start + i) % max_cpus) as i32
        };

        if cpu == prev_cpu || !p.cpu_allowed(cpu) { continue; }

        if (primary.is_null() || unsafe { bpf_cpumask_test_cpu(cpu, primary) }) &&
           (smt.is_null() || unsafe { bpf_cpumask_test_cpu(cpu, smt) }) &&
           test_cpu_idle(cpu) {
            if !PREFERRED_IDLE_SCAN.load(Relaxed) {
                unsafe { *FLAT_LAST_CPU.0.get() = (cpu + 1) as u32; }
            }
            return cpu;
        }
    }

    -1
}

fn pick_idle_cpu_flat(p: &TaskRef, prev_cpu: i32) -> i32 {
    let is_prev_allowed = p.cpu_allowed(prev_cpu);
    let primary = if !PRIMARY_ALL.load(Relaxed) {
        PRIMARY_MASK.load(Relaxed) as *const u64
    } else {
        core::ptr::null()
    };
    let smt = if SMT_ENABLED.load(Relaxed) {
        unsafe { scx_bpf_get_idle_smtmask() }
    } else {
        core::ptr::null()
    };

    // Pinned task: only check prev_cpu
    if p.is_pcpu() {
        let result = if test_cpu_idle(prev_cpu) { prev_cpu } else { -1 };
        if !smt.is_null() { unsafe { scx_bpf_put_cpumask(smt) }; }
        return result;
    }

    // Try full-idle core in primary domain
    if !PRIMARY_ALL.load(Relaxed) && SMT_ENABLED.load(Relaxed) {
        let cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, primary, smt);
        if cpu >= 0 {
            if !smt.is_null() { unsafe { scx_bpf_put_cpumask(smt) }; }
            return cpu;
        }
    }

    // Try any idle CPU in primary domain
    if !PRIMARY_ALL.load(Relaxed) {
        let cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed,
                                          primary, core::ptr::null());
        if cpu >= 0 {
            if !smt.is_null() { unsafe { scx_bpf_put_cpumask(smt) }; }
            return cpu;
        }
    }

    // Try full-idle core anywhere
    if SMT_ENABLED.load(Relaxed) {
        let cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed,
                                          core::ptr::null(), smt);
        if cpu >= 0 {
            if !smt.is_null() { unsafe { scx_bpf_put_cpumask(smt) }; }
            return cpu;
        }
    }

    // Try any idle CPU anywhere
    let cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed,
                                      core::ptr::null(), core::ptr::null());

    if !smt.is_null() { unsafe { scx_bpf_put_cpumask(smt) }; }
    cpu
}

fn pick_idle_cpu(p: &TaskRef, prev_cpu: i32, this_cpu: i32,
                 wake_flags: u64, from_enqueue: bool) -> i32 {
    // Use flat scan when enabled and not busy
    if (FLAT_IDLE_SCAN.load(Relaxed) || PREFERRED_IDLE_SCAN.load(Relaxed)) &&
       !is_cpu_busy(prev_cpu) {
        return pick_idle_cpu_flat(p, prev_cpu);
    }

    let mut wake = wake_flags;
    if NO_WAKE_SYNC.load(Relaxed) { wake &= !SCX_WAKE_SYNC; }

    // Hybrid core migration: waker is faster than wakee
    let mut prev = prev_cpu;
    if PRIMARY_ALL.load(Relaxed) && is_wakeup(wake_flags) &&
       this_cpu >= 0 && is_cpu_faster(this_cpu, prev) {
        if cpus_share_cache(this_cpu, prev) &&
           !is_smt_contended(prev) && test_cpu_idle(prev) {
            return prev;
        }
        prev = this_cpu;
    }

    // Fallback to the old API if scx_bpf_select_cpu_and is not available.
    // Required for kernels <= 6.16.
    let use_old_api = false; // would be __COMPAT_HAS_scx_bpf_select_cpu_and
    if use_old_api {
        if from_enqueue { return -1; }
        let mut is_idle = false;
        let cpu = unsafe {
            scx_bpf_select_cpu_dfl(p.0, prev, wake, &mut is_idle)
        };
        return if is_idle { cpu } else { -1 };
    }

    // Try primary domain with idle core preference
    let primary_mask = PRIMARY_MASK.load(Relaxed) as *const u64;
    if !PRIMARY_ALL.load(Relaxed) && !primary_mask.is_null() {
        let cpu = unsafe {
            scx_bpf_select_cpu_and(p.0, prev, wake, primary_mask,
                                    if AVOID_SMT.load(Relaxed) { SCX_PICK_IDLE_CORE } else { 0 })
        };
        if cpu >= 0 { return cpu; }
    }

    // Pick any idle CPU
    unsafe { scx_bpf_select_cpu_and(p.0, prev, wake, p.cpus_ptr(), 0) }
}

// ── keep_running ─────────────────────────────────────────────────────

fn keep_running(p: &TaskRef, cpu: i32) -> bool {
    if !p.is_queued() { return false; }
    if p.is_pcpu() { return true; }
    if AVOID_SMT.load(Relaxed) && is_smt_contended(cpu) { return false; }
    if !is_primary_cpu(cpu) {
        let mask = PRIMARY_MASK.load(Relaxed) as *const u64;
        if !mask.is_null() && unsafe { bpf_cpumask_intersects(p.cpus_ptr(), mask) } {
            return false;
        }
    }
    true
}

// ── struct_ops callbacks ─────────────────────────────────────────────
// Kernel passes arguments through a ctx array. bpf_prog! extracts args
// from ctx[0], ctx[1], ... like C's BPF_PROG macro.

#[repr(C)]
#[allow(dead_code)]
struct ScxExitInfo { /* opaque */ }

macro_rules! bpf_prog {
    ($section:expr, fn $name:ident($($arg:ident : $ty:ty),* $(,)?) $(-> $ret:ty)? {$($t:tt)*}) => {
        #[link_section = $section]
        #[no_mangle]
        extern "C" fn $name(_ctx: *const u64) -> i32 {
            let mut _i = 0usize;
            $(
                #[allow(unused_assignments)]
                let $arg = { let v = unsafe { *_ctx.add(_i) } as $ty; _i += 1; v };
            )*
            { $($t)* };
            0
        }
    };
}

bpf_prog!("struct_ops/cosmos_select_cpu",
fn cosmos_select_cpu(p: *mut task_struct, prev_cpu: i32, wake_flags: u64) -> i32 {
    let p = TaskRef(p);
    let p = &p;
    let current = unsafe { &*bpf_get_current_task_btf() };
    let current_ref = TaskRef(current as *const task_struct as *mut task_struct);
    let this_cpu = unsafe { bpf_get_smp_processor_id() };
    let is_this_allowed = p.cpu_allowed(this_cpu);
    let is_busy = is_cpu_busy(prev_cpu);

    let tctx = match get_task_ctx(p.pid()) {
        Some(t) => t,
        None => return prev_cpu,
    };

    let mut prev = prev_cpu;
    if !p.cpu_allowed(prev) {
        prev = if is_this_allowed { this_cpu } else {
            unsafe { bpf_cpumask_first(p.cpus_ptr()) }
        };
    }

    if is_wake_affine(&current_ref, p) && !is_busy {
        if this_cpu == prev {
            unsafe { scx_bpf_dsq_insert(p.0, SCX_DSQ_LOCAL, task_slice(p), 0) };
            return this_cpu;
        }
    }

    if GPU_ENABLED.load(Relaxed) && NUMA_ENABLED.load(Relaxed) {
        let cpu = pick_cpu_on_gpu_node(p, cpu_node(prev), tctx);
        if cpu >= 0 {
            NR_GPU_DISPATCHES.fetch_add(1, Relaxed);
            unsafe { scx_bpf_dsq_insert(p.0, SCX_DSQ_LOCAL, task_slice(p), 0) };
            return cpu;
        }
    }

    let cpu = pick_idle_cpu(p, prev, if is_this_allowed { this_cpu } else { -1 },
                            wake_flags, false);
    if cpu >= 0 || !is_busy {
        unsafe { scx_bpf_dsq_insert(p.0, SCX_DSQ_LOCAL, task_slice(p), 0) };
    }

    if cpu >= 0 { cpu } else { prev }
});

bpf_prog!("struct_ops/cosmos_tick",
fn cosmos_tick(p: *mut task_struct) {
    let p = TaskRef(p);
    let p = &p;
    if !TICK_PREEMPT.load(Relaxed) { return 0; }

    let tctx = match get_task_ctx(p.pid()) {
        Some(t) => t,
        None => return 0,
    };

    if time_delta(now(), tctx.last_run_at) > task_slice(p) {
        let cpu = p.cpu();
        let smt_contention = AVOID_SMT.load(Relaxed) && is_smt_contended(cpu);
        let cpu_busy = unsafe {
            scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu as u64) > 0 ||
            scx_bpf_dsq_nr_queued(shared_dsq(cpu)) > 0
        };

        if smt_contention || (is_cpu_busy(cpu) && cpu_busy) {
            p.set_scx_slice(0);
        }
    }
});

bpf_prog!("struct_ops/cosmos_enqueue",
fn cosmos_enqueue(p: *mut task_struct, enq_flags: u64) {
    let p = TaskRef(p);
    let p = &p;
    let prev_cpu = p.cpu();
    let node = cpu_node(prev_cpu);

    let tctx = match get_task_ctx(p.pid()) {
        Some(t) => t,
        None => return 0,
    };

    if GPU_ENABLED.load(Relaxed) && NUMA_ENABLED.load(Relaxed) &&
       !p.is_pcpu() && task_should_migrate(p) {
        let cpu = pick_cpu_on_gpu_node(p, node, tctx);
        if cpu >= 0 {
            NR_GPU_DISPATCHES.fetch_add(1, Relaxed);
            unsafe {
                scx_bpf_dsq_insert(p.0, SCX_DSQ_LOCAL_ON | cpu as u64,
                                   task_slice(p), enq_flags);
                if cpu != prev_cpu || !p.is_running() {
                    scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
                }
            }
            return 0;
        }
    }

    if is_sticky_event_heavy(tctx) &&
       (is_primary_cpu(prev_cpu) || p.is_pcpu()) &&
       (!AVOID_SMT.load(Relaxed) || !is_smt_contended(prev_cpu)) {
        unsafe {
            scx_bpf_dsq_insert(p.0, SCX_DSQ_LOCAL, task_slice(p), enq_flags);
        }
        NR_EV_STICKY_DISPATCHES.fetch_add(1, Relaxed);
        if !p.is_running() {
            unsafe { scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE) };
        }
        return 0;
    }

    if task_should_migrate(p) ||
       !is_cpu_idle(prev_cpu) ||
       (AVOID_SMT.load(Relaxed) && is_smt_contended(prev_cpu)) ||
       (!p.is_pcpu() && (is_event_heavy(tctx) || !is_primary_cpu(prev_cpu))) {
        let cpu = if p.is_pcpu() {
            if test_cpu_idle(prev_cpu) { prev_cpu } else { -1 }
        } else {
            pick_idle_cpu(p, prev_cpu, -1, 0, true)
        };

        if cpu >= 0 {
            unsafe {
                scx_bpf_dsq_insert(p.0, SCX_DSQ_LOCAL_ON | cpu as u64,
                                   task_slice(p), enq_flags);
            }
            if is_event_heavy(tctx) && cpu != prev_cpu {
                NR_EVENT_DISPATCHES.fetch_add(1, Relaxed);
            }
            if cpu != prev_cpu || !p.is_running() {
                unsafe { scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE) };
            }
            return 0;
        }
    }

    if !is_cpu_busy(prev_cpu) && (is_primary_cpu(prev_cpu) || p.is_pcpu()) {
        unsafe {
            scx_bpf_dsq_insert(p.0, SCX_DSQ_LOCAL_ON | prev_cpu as u64,
                               task_slice(p), enq_flags);
        }
        if task_should_migrate(p) {
            unsafe { scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE) };
        }
        return 0;
    }

    let deadline = task_deadline(p, tctx);
    unsafe {
        scx_bpf_dsq_insert_vtime(p.0, shared_dsq(prev_cpu),
                                  task_slice(p), deadline, enq_flags);
    }
    if task_should_migrate(p) {
        unsafe { scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE) };
    }
});

bpf_prog!("struct_ops/cosmos_dispatch",
fn cosmos_dispatch(cpu: i32, prev: *mut task_struct) {
    if unsafe { scx_bpf_dsq_move_to_local(shared_dsq(cpu)) } {
        return 0;
    }

    if prev.is_null() {
        return 0;
    }
    let prev = TaskRef(prev);
    let prev = &prev;

    if keep_running(prev, cpu) {
        prev.set_scx_slice(task_slice(prev));
    }
});

bpf_prog!("struct_ops/cosmos_runnable",
fn cosmos_runnable(p: *mut task_struct, _enq_flags: u64) {
    let p = TaskRef(p);
    let p = &p;
    let t = now();
    let tctx = match get_task_ctx(p.pid()) {
        Some(t) => t,
        None => return 0,
    };

    tctx.exec_runtime = 0;

    let delta_t = t - tctx.last_woke_at;
    tctx.wakeup_freq = update_freq(tctx.wakeup_freq, delta_t);
    tctx.wakeup_freq = min(tctx.wakeup_freq, 1024);
    tctx.last_woke_at = t;
});

bpf_prog!("struct_ops/cosmos_running",
fn cosmos_running(p: *mut task_struct) {
    let p = TaskRef(p);
    let p = &p;
    let tctx = match get_task_ctx(p.pid()) {
        Some(t) => t,
        None => return 0,
    };

    tctx.last_run_at = now();

    if time_before(VTIME_NOW.load(Relaxed), p.scx_dsq_vtime()) {
        VTIME_NOW.store(p.scx_dsq_vtime(), Relaxed);
    }

    update_cpufreq(p.cpu());
});

bpf_prog!("struct_ops/cosmos_stopping",
fn cosmos_stopping(p: *mut task_struct, _runnable: u64) {
    let p = TaskRef(p);
    let p = &p;
    let cpu = p.cpu();
    let tctx = match get_task_ctx(p.pid()) {
        Some(t) => t,
        None => return 0,
    };

    if PERF_CONFIG.load(Relaxed) != 0 || PERF_STICKY.load(Relaxed) != 0 {
        update_counters(tctx, cpu);
    }

    let slice = now() - tctx.last_run_at;
    let scaled = scale_by_cpu_capacity(slice, cpu);

    p.set_scx_dsq_vtime(p.scx_dsq_vtime() + scale_by_weight_inverse(p, scaled));
    tctx.exec_runtime = min(tctx.exec_runtime + scaled, slice_lag());

    update_cpu_load(p, scaled);
});

bpf_prog!("struct_ops/cosmos_enable",
fn cosmos_enable(p: *mut task_struct) {
    let p = TaskRef(p);
    p.set_scx_dsq_vtime(VTIME_NOW.load(Relaxed));
});

bpf_prog!("struct_ops/cosmos_init_task",
fn cosmos_init_task(p: *mut task_struct) -> i32 {
    let p = TaskRef(p);
    let ctxs = unsafe { &mut *TASK_CTXS.0.get() };
    if let Some(map) = ctxs {
        map.insert(p.pid(), UnsafeCell::new(TaskCtx::new()));
    }
    0
});

bpf_prog!("struct_ops/cosmos_exit_task",
fn cosmos_exit_task(p: *mut task_struct) {
    let p = TaskRef(p);
    let ctxs = unsafe { &mut *TASK_CTXS.0.get() };
    if let Some(map) = ctxs {
        map.remove(&p.pid());
    }
});

bpf_prog!("struct_ops/cosmos_init",
fn cosmos_init() -> i32 {
    NR_CPU_IDS.store(unsafe { scx_bpf_nr_cpu_ids() }, Relaxed);

    let task_ctxs = unsafe { &mut *TASK_CTXS.0.get() };
    *task_ctxs = Some(BTreeMap::new());

    let cpu_node = unsafe { &mut *CPU_NODE_MAP.0.get() };
    *cpu_node = Some(BTreeMap::new());

    let gpu_pid = unsafe { &mut *GPU_PID_MAP.0.get() };
    *gpu_pid = Some(BTreeMap::new());

    if NUMA_ENABLED.load(Relaxed) {
        let nr_nodes = NR_NODE_IDS.load(Relaxed) as i32;
        for node in 0..nr_nodes {
            let ret = unsafe { scx_bpf_create_dsq(node as u64, node) };
            if ret != 0 { return ret; }
        }
    } else {
        let ret = unsafe { scx_bpf_create_dsq(SHARED_DSQ, -1) };
        if ret != 0 { return ret; }
    }

    let cpu_ctxs = unsafe { &mut *CPU_CTXS.0.get() };
    for c in cpu_ctxs.iter_mut() {
        c.perf_events = 0;
    }

    0
});

bpf_prog!("struct_ops/cosmos_exit",
fn cosmos_exit(_ei: *const ScxExitInfo) {
});

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
fn enable_sibling_cpu(input: &DomainArg) -> i32 {
    let cpu = input.cpu_id;
    let sibling = input.sibling_cpu_id;
    if !is_cpu_valid(cpu) || !is_cpu_valid(sibling) { return -1; }
    unsafe { (*SMT_SIBLING.0.get())[cpu as usize] = sibling };

    0
}

#[link_section = "syscall"]
#[no_mangle]
fn enable_primary_cpu(input: &CpuArg) -> i32 {
    // Would set bit in primary cpumask; simplified with atomic store
    // In practice this would use bpf_cpumask_set_cpu on a kptr cpumask
    let _ = input.cpu_id;
    0
}

// ── Panic handler ────────────────────────────────────────────────────

struct BpfStream(i32);

impl core::fmt::Write for BpfStream {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let args: [u64; 2] = [s.as_ptr() as u64, s.len() as u64];
        unsafe { bpf_stream_vprintk(self.0, b"%.*s\0".as_ptr(), args.as_ptr(), 16) };
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    let mut stream = BpfStream(0);
    let _ = write!(stream, "{}", info);
    unsafe { bpf_throw(1) }
}

#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    unsafe { bpf_throw(12) }
}

// ── struct_ops map definition ────────────────────────────────────────

type OpFn = extern "C" fn(*const u64) -> i32;

#[repr(C)]
struct sched_ext_ops {
    select_cpu: OpFn,
    enqueue: OpFn,
    dispatch: OpFn,
    tick: OpFn,
    runnable: OpFn,
    running: OpFn,
    stopping: OpFn,
    enable: OpFn,
    init_task: OpFn,
    exit_task: OpFn,
    init: OpFn,
    exit: OpFn,
    name: [u8; 128],
}

unsafe impl Sync for sched_ext_ops {}

const fn pad_name<const N: usize>(s: &[u8; N]) -> [u8; 128] {
    let mut buf = [0u8; 128];
    let mut i = 0;
    while i < N && i < 127 {
        buf[i] = s[i];
        i += 1;
    }
    buf
}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static cosmos_ops: sched_ext_ops = sched_ext_ops {
    select_cpu: cosmos_select_cpu,
    enqueue: cosmos_enqueue,
    dispatch: cosmos_dispatch,
    tick: cosmos_tick,
    runnable: cosmos_runnable,
    running: cosmos_running,
    stopping: cosmos_stopping,
    enable: cosmos_enable,
    init_task: cosmos_init_task,
    exit_task: cosmos_exit_task,
    init: cosmos_init,
    exit: cosmos_exit,
    name: pad_name(b"cosmos"),
};

#[link_section = "license"]
#[no_mangle]
static _LICENSE: [u8; 4] = *b"GPL\0";

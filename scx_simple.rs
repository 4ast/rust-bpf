#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

// -- kfunc bindings (safe: the BPF verifier proves safety) --

extern "C" {
    fn bpf_alloc(size: u64, flags: u64) -> *mut u8;
    fn bpf_free(ptr: *mut u8);
}

fn scx_bpf_select_cpu_dfl(p: &TaskRef, prev_cpu: i32, wake_flags: u64,
                           is_idle: &mut bool) -> i32 {
    extern "C" { fn scx_bpf_select_cpu_dfl(p: *mut task_struct, prev_cpu: i32,
                   wake_flags: u64, is_idle: *mut bool) -> i32; }
    unsafe { scx_bpf_select_cpu_dfl(p.0, prev_cpu, wake_flags, is_idle) }
}

fn scx_bpf_dsq_insert(p: &TaskRef, dsq_id: u64, slice: u64, enq_flags: u64) {
    extern "C" { fn scx_bpf_dsq_insert(p: *mut task_struct, dsq_id: u64,
                   slice: u64, enq_flags: u64); }
    unsafe { scx_bpf_dsq_insert(p.0, dsq_id, slice, enq_flags) }
}

fn scx_bpf_dsq_insert_vtime(p: &TaskRef, dsq_id: u64, slice: u64,
                             vtime: u64, enq_flags: u64) {
    extern "C" { fn scx_bpf_dsq_insert_vtime(p: *mut task_struct, dsq_id: u64,
                   slice: u64, vtime: u64, enq_flags: u64); }
    unsafe { scx_bpf_dsq_insert_vtime(p.0, dsq_id, slice, vtime, enq_flags) }
}

fn scx_bpf_dsq_move_to_local(dsq_id: u64) {
    extern "C" { fn scx_bpf_dsq_move_to_local(dsq_id: u64); }
    unsafe { scx_bpf_dsq_move_to_local(dsq_id) }
}

fn scx_bpf_create_dsq(dsq_id: u64, node: i32) -> i32 {
    extern "C" { fn scx_bpf_create_dsq(dsq_id: u64, node: i32) -> i32; }
    unsafe { scx_bpf_create_dsq(dsq_id, node) }
}

// -- allocator --

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

// -- task_struct with BTF-described layout (CO-RE relocates field offsets) --

#[repr(C)]
struct task_struct {
    // ... other fields omitted, CO-RE relocates accesses ...
    scx: sched_ext_entity,
}

#[repr(C)]
struct sched_ext_entity {
    dsq_vtime: u64,
    slice: u64,
    weight: u32,
    // ... other fields ...
}

#[repr(transparent)]
struct TaskRef(*mut task_struct);

impl TaskRef {
    fn scx(&self) -> &sched_ext_entity { unsafe { &(*self.0).scx } }
    fn scx_mut(&self) -> &mut sched_ext_entity { unsafe { &mut (*self.0).scx } }
}

const SHARED_DSQ: u64 = 0;
const SCX_DSQ_LOCAL: u64 = u64::MAX;
const SCX_SLICE_DFL: u64 = 20_000_000; // 20ms in ns

static FIFO_SCHED: AtomicBool = AtomicBool::new(false);
static VTIME_NOW: AtomicU64 = AtomicU64::new(0);

// BPF runs single-threaded per-CPU, so UnsafeCell is safe here.
struct BpfCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for BpfCell<T> {}

static STATS: BpfCell<Option<BTreeMap<&str, u64>>> = BpfCell(UnsafeCell::new(None));

// -- scheduling policy as a trait --

trait SchedPolicy {
    fn enqueue(&self, p: &TaskRef, vtime: u64, enq_flags: u64);
}

struct FifoPolicy;
struct VtimePolicy;

impl SchedPolicy for FifoPolicy {
    fn enqueue(&self, p: &TaskRef, _vtime: u64, enq_flags: u64) {
        scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
    }
}

impl SchedPolicy for VtimePolicy {
    fn enqueue(&self, p: &TaskRef, vtime: u64, enq_flags: u64) {
        // Limit the amount of budget that an idling task can accumulate
        let vtime = if vtime < VTIME_NOW.load(Relaxed).wrapping_sub(SCX_SLICE_DFL) {
            VTIME_NOW.load(Relaxed).wrapping_sub(SCX_SLICE_DFL)
        } else {
            vtime
        };
        scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL,
                                  vtime, enq_flags);
    }
}

fn stat_inc(key: &'static str) {
    let stats = unsafe { &mut *STATS.0.get() };
    if let Some(map) = stats {
        *map.entry(key).or_insert(0) += 1;
    }
}

// -- struct_ops callbacks --

#[link_section = "struct_ops/simple_select_cpu"]
#[no_mangle]
fn simple_select_cpu(p: &TaskRef, prev_cpu: i32, wake_flags: u64) -> i32 {
    let mut is_idle = false;
    let cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &mut is_idle);
    if is_idle {
        stat_inc("local");
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }
    cpu
}

#[link_section = "struct_ops/simple_enqueue"]
#[no_mangle]
fn simple_enqueue(p: &TaskRef, enq_flags: u64) {
    stat_inc("global");
    let vtime = p.scx().dsq_vtime;

    // dyn Trait dispatch -- PTR_TO_FUNC via vtable
    let policy: &dyn SchedPolicy = if FIFO_SCHED.load(Relaxed) {
        &FifoPolicy
    } else {
        &VtimePolicy
    };
    policy.enqueue(p, vtime, enq_flags);
}

#[link_section = "struct_ops/simple_dispatch"]
#[no_mangle]
fn simple_dispatch(_cpu: i32, _prev: &TaskRef) {
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

#[link_section = "struct_ops/simple_running"]
#[no_mangle]
fn simple_running(p: &TaskRef) {
    if FIFO_SCHED.load(Relaxed) {
        return;
    }
    // Global vtime always progresses forward as tasks start executing.
    // The test and update can be racy across CPUs. Any error should be
    // contained and temporary.
    let vtime = p.scx().dsq_vtime;
    if VTIME_NOW.load(Relaxed) < vtime {
        VTIME_NOW.store(vtime, Relaxed);
    }
}

#[link_section = "struct_ops/simple_stopping"]
#[no_mangle]
fn simple_stopping(p: &TaskRef, _runnable: bool) {
    if FIFO_SCHED.load(Relaxed) {
        return;
    }
    // Charge vtime: scale execution time by inverse of weight
    let scx = p.scx_mut();
    let delta = (SCX_SLICE_DFL - scx.slice) * 100 / scx.weight as u64;
    scx.dsq_vtime += delta;
}

#[link_section = "struct_ops/simple_enable"]
#[no_mangle]
fn simple_enable(p: &TaskRef) {
    p.scx_mut().dsq_vtime = VTIME_NOW.load(Relaxed);
}

#[link_section = "struct_ops/simple_init"]
#[no_mangle]
fn simple_init() -> i32 {
    // Heap-allocated BTreeMap -- backed by bpf_alloc
    let stats = unsafe { &mut *STATS.0.get() };
    *stats = Some(BTreeMap::new());

    scx_bpf_create_dsq(SHARED_DSQ, -1)
}

#[repr(C)]
struct ScxExitInfo { /* opaque */ }

#[link_section = "struct_ops/simple_exit"]
#[no_mangle]
fn simple_exit(_ei: &ScxExitInfo) {}

extern "C" {
    fn bpf_throw(cookie: u64) -> !;
    fn bpf_stream_vprintk(stream_id: i32, fmt: *const u8, args: *const u64,
                           len: u32) -> i32;
}

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
    extern "C" { fn bpf_throw(cookie: u64) -> !; }
    unsafe { bpf_throw(12) } // ENOMEM
}

// -- struct_ops map definition --
// libbpf matches fields by name via BTF, not by type.
// Use Option<fn()> as an opaque function pointer — the actual
// signatures live on the callbacks themselves.

#[repr(C)]
struct sched_ext_ops {
    select_cpu: *const (),
    enqueue: *const (),
    dispatch: *const (),
    running: *const (),
    stopping: *const (),
    enable: *const (),
    init: *const (),
    exit: *const (),
    name: [u8; 7],
}

unsafe impl Sync for sched_ext_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static simple_ops: sched_ext_ops = sched_ext_ops {
    select_cpu: simple_select_cpu as *const (),
    enqueue: simple_enqueue as *const (),
    dispatch: simple_dispatch as *const (),
    running: simple_running as *const (),
    stopping: simple_stopping as *const (),
    enable: simple_enable as *const (),
    init: simple_init as *const (),
    exit: simple_exit as *const (),
    name: *b"simple\0",
};

#[link_section = "license"]
#[no_mangle]
static _LICENSE: [u8; 4] = *b"GPL\0";

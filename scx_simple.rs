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

// -- kernel types (CO-RE relocates field offsets at load time) --
//
// gen_core.py reads these @core_struct blocks to auto-generate core_defs.c.
//
// @core_struct sched_ext_entity {
//     dsq_vtime: unsigned long long,
//     slice: unsigned long long,
//     weight: unsigned int,
// }
// @core_struct task_struct {
//     scx: sched_ext_entity,
// }

#[repr(C)]
struct task_struct { _opaque: [u8; 0] }

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
    core_read!(scx_dsq_vtime -> u64, __core_read_task_struct__scx__dsq_vtime);
    core_read!(scx_slice -> u64, __core_read_task_struct__scx__slice);
    core_read!(scx_weight -> u32, __core_read_task_struct__scx__weight);

    core_write!(set_scx_dsq_vtime(u64), __core_write_task_struct__scx__dsq_vtime);
    core_write!(set_scx_slice(u64), __core_write_task_struct__scx__slice);
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
// The kernel passes struct_ops arguments through a ctx array.
// bpf_prog! extracts args from ctx[0], ctx[1], etc. like C's BPF_PROG macro.

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

bpf_prog!("struct_ops/simple_select_cpu",
fn simple_select_cpu(p: *mut task_struct, prev_cpu: i32, wake_flags: u64) -> i32 {
    let p = TaskRef(p);
    let mut is_idle = false;
    let cpu = scx_bpf_select_cpu_dfl(&p, prev_cpu, wake_flags, &mut is_idle);
    if is_idle {
        stat_inc("local");
        scx_bpf_dsq_insert(&p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }
    cpu
});

bpf_prog!("struct_ops/simple_enqueue",
fn simple_enqueue(p: *mut task_struct, enq_flags: u64) {
    let p = TaskRef(p);
    stat_inc("global");
    let vtime = p.scx_dsq_vtime();

    let policy: &dyn SchedPolicy = if FIFO_SCHED.load(Relaxed) {
        &FifoPolicy
    } else {
        &VtimePolicy
    };
    policy.enqueue(&p, vtime, enq_flags);
});

bpf_prog!("struct_ops/simple_dispatch",
fn simple_dispatch(_cpu: i32, _prev: *mut task_struct) {
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
});

bpf_prog!("struct_ops/simple_running",
fn simple_running(p: *mut task_struct) {
    let p = TaskRef(p);
    if FIFO_SCHED.load(Relaxed) {
        return 0;
    }
    let vtime = p.scx_dsq_vtime();
    if VTIME_NOW.load(Relaxed) < vtime {
        VTIME_NOW.store(vtime, Relaxed);
    }
});

bpf_prog!("struct_ops/simple_stopping",
fn simple_stopping(p: *mut task_struct, _runnable: u64) {
    let p = TaskRef(p);
    if FIFO_SCHED.load(Relaxed) {
        return 0;
    }
    let delta = (SCX_SLICE_DFL - p.scx_slice()) * 100 / p.scx_weight() as u64;
    p.set_scx_dsq_vtime(p.scx_dsq_vtime() + delta);
});

bpf_prog!("struct_ops/simple_enable",
fn simple_enable(p: *mut task_struct) {
    let p = TaskRef(p);
    p.set_scx_dsq_vtime(VTIME_NOW.load(Relaxed));
});

bpf_prog!("struct_ops.s/simple_init",
fn simple_init() -> i32 {
    let stats = unsafe { &mut *STATS.0.get() };
    *stats = Some(BTreeMap::new());
    scx_bpf_create_dsq(SHARED_DSQ, -1)
});

bpf_prog!("struct_ops/simple_exit",
fn simple_exit(_ei: *const ScxExitInfo) {
});

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

type OpFn = extern "C" fn(*const u64) -> i32;

#[repr(C)]
struct sched_ext_ops {
    select_cpu: OpFn,
    enqueue: OpFn,
    dispatch: OpFn,
    running: OpFn,
    stopping: OpFn,
    enable: OpFn,
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
static simple_ops: sched_ext_ops = sched_ext_ops {
    select_cpu: simple_select_cpu,
    enqueue: simple_enqueue,
    dispatch: simple_dispatch,
    running: simple_running,
    stopping: simple_stopping,
    enable: simple_enable,
    init: simple_init,
    exit: simple_exit,
    name: pad_name(b"simple"),
};

#[link_section = "license"]
#[no_mangle]
static _LICENSE: [u8; 4] = *b"GPL\0";

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

use btf_macros::btf;

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
// #[btf] declares the kernel fields this program inspects. bpf-linker
// matches each declared path against the target-kernel BTF and emits
// standard .BTF.ext CO-RE relocation records.

#[btf]
struct sched_ext_entity {
    dsq_vtime: u64,
    slice: u64,
    weight: u32,
}

#[btf]
struct task_struct {
    scx: sched_ext_entity,
}

#[repr(transparent)]
struct TaskRef(*mut task_struct);

impl TaskRef {
    fn view(&self) -> &task_struct { unsafe { &*self.0 } }

    fn scx_dsq_vtime(&self) -> u64 { *self.view().scx().dsq_vtime().get().unwrap() }
    fn scx_slice(&self) -> u64 { *self.view().scx().slice().get().unwrap() }
    fn scx_weight(&self) -> u32 { *self.view().scx().weight().get().unwrap() }

    fn set_scx_dsq_vtime(&self, v: u64) {
        unsafe { *self.view().scx().dsq_vtime().as_mut_ptr() = v; }
    }
    fn set_scx_slice(&self, v: u64) {
        unsafe { *self.view().scx().slice().as_mut_ptr() = v; }
    }
}

const SHARED_DSQ: u64 = 0;
const SCX_DSQ_LOCAL: u64 = (1 << 63) | 2;
const SCX_SLICE_DFL: u64 = 20_000_000; // 20ms in ns

// User space sets it before it loads the scheduler. Exported: nothing in the
// program writes to it, and LLVM replaces a variable that nobody outside can see
// and nobody inside writes with its initial value. FifoPolicy would be gone.
#[export_name = "simple_FIFO_SCHED"]
static FIFO_SCHED: AtomicBool = AtomicBool::new(false);
static VTIME_NOW: AtomicU64 = AtomicU64::new(0);

struct BpfCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for BpfCell<T> {}

static STATS: BpfCell<Option<BTreeMap<&str, AtomicU64>>> = BpfCell(UnsafeCell::new(None));

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
    let stats = unsafe { &*STATS.0.get() };
    stats.as_ref().unwrap().get(key).unwrap().fetch_add(1, Relaxed);
}

// -- struct_ops callbacks --
// The kernel passes struct_ops arguments through a ctx array.
// bpf_prog! extracts args from ctx[0], ctx[1], etc. like C's BPF_PROG macro.

#[repr(C)]
#[allow(dead_code)]
struct ScxExitInfo { /* opaque */ }

/// An unwind that gets to the top of a program is a panic that nobody caught, or
/// the kernel ended a loop or a recursion that went on for too long. Either way
/// something is half done. scx_bpf_error() makes the kernel disable the
/// scheduler and hand the tasks back to the fair class. The program returns 0.
/// Why it happened is in its stderr.
struct Unwound;

impl Drop for Unwound {
    fn drop(&mut self) {
        // The kfunc takes a `char *`, so the format has to be writable.
        static FMT: BpfCell<[u8; 22]> = BpfCell(UnsafeCell::new(*b"a program was unwound\0"));
        let args = [0u64];
        unsafe { scx_bpf_error_bstr(FMT.0.get() as *mut u8, args.as_ptr(), 8) };
    }
}

/// What an op returns to the kernel. One without a value returns 0.
trait OpRet { fn ret(self) -> i32; }
impl OpRet for () { #[inline(always)] fn ret(self) -> i32 { 0 } }
impl OpRet for i32 { #[inline(always)] fn ret(self) -> i32 { self } }

macro_rules! bpf_prog {
    ($section:expr, fn $name:ident($($arg:ident : $ty:ty),* $(,)?) $(-> $ret:ty)? $body:block) => {
        #[link_section = $section]
        #[no_mangle]
        extern "C-unwind" fn $name(_ctx: *const u64) -> i32 {
            // Not inlined: when the kernel ends a loop it leaves the function
            // that the loop is in. The landing pads of the callers run.
            #[inline(never)]
            fn op($($arg: $ty),*) $(-> $ret)? $body
            let mut _i = 0usize;
            $(
                #[allow(unused_assignments)]
                let $arg = { let v = unsafe { *_ctx.add(_i) } as $ty; _i += 1; v };
            )*
            let unwound = Unwound;
            let ret = OpRet::ret(op($($arg),*));
            core::mem::forget(unwound);
            ret
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
        return;
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
        return;
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
    let mut map = BTreeMap::new();
    map.insert("local", AtomicU64::new(0));
    map.insert("global", AtomicU64::new(0));
    *stats = Some(map);
    scx_bpf_create_dsq(SHARED_DSQ, -1)
});

bpf_prog!("struct_ops/simple_exit",
fn simple_exit(_ei: *const ScxExitInfo) {
});

extern "C" {
    fn bpf_stream_vprintk(stream_id: i32, fmt: *const u8, args: *const u64,
                           len: u32) -> i32;
    fn bpf_stream_print_stack(stream_id: i32) -> i32;
    fn scx_bpf_error_bstr(fmt: *mut u8, data: *const u64, data_sz: u32);
}

extern "C-unwind" {
    /// Starts the unwind: landing pads only carry one on. It is the Itanium ABI's
    /// name for that, the one std's panic runtime calls. Not a kfunc: LLVM lowers
    /// the call. By its prototype it comes back when it fails. On BPF it cannot.
    fn _Unwind_RaiseException(exception: *mut u8) -> i32;
}

const BPF_STDERR: i32 = 2;

struct BpfStream(i32);

impl core::fmt::Write for BpfStream {
    /// The printf of the kernel has no %.*s, and its %s wants a string that ends
    /// with 0 in memory of the kernel. A &str is bytes in arena.
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let (chunks, rest) = s.as_bytes().as_chunks::<8>();
        for chunk in chunks {
            let args = chunk.map(u64::from);
            unsafe { bpf_stream_vprintk(self.0, b"%c%c%c%c%c%c%c%c\0".as_ptr(), args.as_ptr(), 64) };
        }
        for &byte in rest {
            let args = [byte as u64];
            unsafe { bpf_stream_vprintk(self.0, b"%c\0".as_ptr(), args.as_ptr(), 8) };
        }
        Ok(())
    }
}

/// A panic unwinds, so that every frame on the way out runs its Drop impls. So
/// does one that must not, e.g. because it got to the end of an extern "C"
/// function, and so does an abort: see add_ksyms.py. There is no other way to
/// end a program that holds a lock, a reference or interrupt flags.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    let _ = writeln!(BpfStream(BPF_STDERR), "{}", info);
    unsafe {
        bpf_stream_print_stack(BPF_STDERR);
        _Unwind_RaiseException(core::ptr::null_mut());
        core::hint::unreachable_unchecked()
    }
}

#[alloc_error_handler]
fn oom(layout: Layout) -> ! {
    panic!("memory allocation of {} bytes failed", layout.size())
}

// -- struct_ops map definition --

type OpFn = extern "C-unwind" fn(*const u64) -> i32;

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

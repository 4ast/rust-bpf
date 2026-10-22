// SPDX-License-Identifier: GPL-2.0
//
// What the schedulers ported from C share: the counterpart of
// scx/common.bpf.h. A scheduler pulls it in with
//
//     #[macro_use]
//     mod scx_common;
//
// - allocator, panic and OOM handlers (same as in scx_simple.rs)
// - helper and kfunc bindings, wrapped in types that own what they acquire:
//   a reference taken from the kernel is released by Drop, on every path
//   out of a function, a panic included
// - kernel types through #[btf]
// - what replaces BPF maps: TaskMap (task storage), SpinLock, CpuSet (kptr
//   cpumasks). All of it lives in arena.
// - bpf_prog! and scx_ops_define!, the BPF_STRUCT_OPS and SCX_OPS_DEFINE of C

#![allow(dead_code, non_camel_case_types, improper_ctypes)]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::{Acquire, Relaxed, Release}};

use btf_macros::btf;

// ── Constants ────────────────────────────────────────────────────────

pub const MAX_CPUS: usize = 1024;

pub const NSEC_PER_USEC: u64 = 1_000;
pub const NSEC_PER_MSEC: u64 = 1_000_000;
pub const NSEC_PER_SEC: u64 = 1_000_000_000;

pub const SCX_DSQ_LOCAL: u64 = (1 << 63) | 2;
pub const SCX_DSQ_LOCAL_ON: u64 = (1 << 63) | (1 << 62);
pub const SCX_SLICE_DFL: u64 = 20 * NSEC_PER_MSEC;
pub const SCX_SLICE_INF: u64 = u64::MAX;
pub const SCX_CPUPERF_ONE: u64 = 1024;

pub const SCX_TASK_QUEUED: u32 = 1 << 0;

pub const SCX_WAKE_FORK: u64 = 0x04;
pub const SCX_WAKE_TTWU: u64 = 0x08;
pub const SCX_WAKE_SYNC: u64 = 0x10;

pub const SCX_ENQ_WAKEUP: u64 = 0x1;
pub const SCX_ENQ_HEAD: u64 = 0x10000;
pub const SCX_ENQ_CPU_SELECTED: u64 = 0x100000;
pub const SCX_ENQ_PREEMPT: u64 = 1 << 32;
pub const SCX_ENQ_REENQ: u64 = 1 << 40;
pub const SCX_ENQ_LAST: u64 = 1 << 41;

pub const SCX_DEQ_SLEEP: u64 = 0x1;

pub const SCX_KICK_IDLE: u64 = 1 << 0;
pub const SCX_KICK_PREEMPT: u64 = 1 << 1;

pub const SCX_PICK_IDLE_CORE: u64 = 1 << 0;
pub const SCX_PICK_IDLE_IN_NODE: u64 = 1 << 1;

pub const SCX_OPS_KEEP_BUILTIN_IDLE: u64 = 1 << 0;
pub const SCX_OPS_ENQ_LAST: u64 = 1 << 1;
pub const SCX_OPS_ENQ_EXITING: u64 = 1 << 2;
pub const SCX_OPS_SWITCH_PARTIAL: u64 = 1 << 3;
pub const SCX_OPS_ENQ_MIGRATION_DISABLED: u64 = 1 << 4;
pub const SCX_OPS_ALLOW_QUEUED_WAKEUP: u64 = 1 << 5;
pub const SCX_OPS_BUILTIN_IDLE_PER_NODE: u64 = 1 << 6;
pub const SCX_OPS_ALWAYS_ENQ_IMMED: u64 = 1 << 7;

pub const PF_IDLE: u32 = 0x0000_0002;
pub const PF_EXITING: u32 = 0x0000_0004;
pub const PF_WQ_WORKER: u32 = 0x0000_0020;
pub const PF_KTHREAD: u32 = 0x0020_0000;

pub const CLOCK_MONOTONIC: u64 = 1;
pub const CLOCK_BOOTTIME: u64 = 7;
pub const BPF_F_TIMER_CPU_PIN: u64 = 1 << 1;

// ── Errors ───────────────────────────────────────────────────────────

/// An errno. Ops that return s32 in C return Result<_, Errno> here.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

pub const ENOENT: Errno = Errno(2);
pub const ESRCH: Errno = Errno(3);
pub const ENOMEM: Errno = Errno(12);
pub const EBUSY: Errno = Errno(16);
pub const EINVAL: Errno = Errno(22);

pub type Result<T = ()> = core::result::Result<T, Errno>;

impl Errno {
    /// 0 or -errno, the convention of helpers and kfuncs.
    #[inline(always)]
    pub fn check(ret: i32) -> Result {
        if ret < 0 { Err(Errno(-ret)) } else { Ok(()) }
    }
}

// ── BPF helpers (called via helper ID, not kfunc BTF) ────────────────

macro_rules! bpf_helper {
    (fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty = $id:expr) => {
        #[inline(always)]
        pub unsafe fn $name($($arg: $ty),*) -> $ret {
            let f: unsafe extern "C" fn($($ty),*) -> $ret = core::mem::transmute($id as usize);
            f($($arg),*)
        }
    };
}

bpf_helper!(fn bpf_map_lookup_elem(map: *const u8, key: *const u8) -> *mut u8 = 1);
bpf_helper!(fn bpf_ktime_get_ns() -> u64 = 5);
bpf_helper!(fn bpf_get_prandom_u32() -> u32 = 7);
bpf_helper!(fn bpf_get_smp_processor_id() -> i32 = 8);
bpf_helper!(fn bpf_get_current_task_btf() -> *mut task_struct = 158);
bpf_helper!(fn bpf_ringbuf_reserve(ringbuf: *const u8, size: u64, flags: u64) -> *mut u8 = 131);
bpf_helper!(fn bpf_ringbuf_submit(data: *mut u8, flags: u64) -> () = 132);
bpf_helper!(fn bpf_ringbuf_discard(data: *mut u8, flags: u64) -> () = 133);
bpf_helper!(fn bpf_timer_init(timer: *mut bpf_timer, map: *const u8, flags: u64) -> i64 = 169);
bpf_helper!(fn bpf_timer_set_callback(timer: *mut bpf_timer, cb: TimerFn) -> i64 = 170);
bpf_helper!(fn bpf_timer_start(timer: *mut bpf_timer, nsecs: u64, flags: u64) -> i64 = 171);
bpf_helper!(fn bpf_timer_cancel(timer: *mut bpf_timer) -> i64 = 172);

pub fn now() -> u64 { unsafe { bpf_ktime_get_ns() } }
pub fn this_cpu() -> i32 { unsafe { bpf_get_smp_processor_id() } }
pub fn random() -> u32 { unsafe { bpf_get_prandom_u32() } }

pub fn time_before(a: u64, b: u64) -> bool { (a.wrapping_sub(b) as i64) < 0 }
pub fn time_after(a: u64, b: u64) -> bool { time_before(b, a) }

// ── Kfunc bindings (resolved via BTF at load time) ───────────────────

#[repr(C)]
pub struct cpumask { _opaque: [u8; 0] }

#[repr(C, align(8))]
pub struct bpf_iter_scx_dsq { __opaque: [u64; 6] }

#[repr(C, align(8))]
pub struct bpf_timer { __opaque: [u64; 2] }

extern "C" {
    fn bpf_alloc(size: u64, flags: u64) -> *mut u8;
    fn bpf_free(ptr: *mut u8);
    fn bpf_throw(cookie: u64) -> !;
    fn bpf_stream_vprintk(stream_id: i32, fmt: *const u8, args: *const u64,
                           len: u32) -> i32;
    fn bpf_stream_print_stack(stream_id: i32) -> i32;

    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_local_irq_save(flags: *mut u64);
    fn bpf_local_irq_restore(flags: *mut u64);

    fn bpf_task_from_pid(pid: i32) -> *mut task_struct;
    fn bpf_task_release(p: *mut task_struct);

    fn bpf_cgroup_ancestor(cgrp: *mut cgroup, level: i32) -> *mut cgroup;
    fn bpf_cgroup_release(cgrp: *mut cgroup);
    fn scx_bpf_task_cgroup(p: *mut task_struct) -> *mut cgroup;

    fn bpf_cpumask_test_cpu(cpu: u32, mask: *const cpumask) -> bool;
    fn bpf_cpumask_first(mask: *const cpumask) -> u32;
    fn bpf_cpumask_weight(mask: *const cpumask) -> u32;
    fn bpf_cpumask_empty(mask: *const cpumask) -> bool;
    fn bpf_cpumask_intersects(a: *const cpumask, b: *const cpumask) -> bool;
    fn bpf_cpumask_subset(a: *const cpumask, b: *const cpumask) -> bool;
    fn bpf_cpumask_any_distribute(mask: *const cpumask) -> u32;

    fn scx_bpf_select_cpu_dfl(p: *mut task_struct, prev_cpu: i32,
                               wake_flags: u64, is_idle: *mut bool) -> i32;
    fn scx_bpf_select_cpu_and(p: *mut task_struct, prev_cpu: i32,
                               wake_flags: u64, mask: *const cpumask,
                               flags: u64) -> i32;
    fn scx_bpf_pick_idle_cpu(mask: *const cpumask, flags: u64) -> i32;
    fn scx_bpf_pick_any_cpu(mask: *const cpumask, flags: u64) -> i32;
    fn scx_bpf_test_and_clear_cpu_idle(cpu: i32) -> bool;
    fn scx_bpf_get_idle_cpumask() -> *const cpumask;
    fn scx_bpf_get_idle_cpumask_node(node: i32) -> *const cpumask;
    fn scx_bpf_get_idle_smtmask() -> *const cpumask;
    fn scx_bpf_get_idle_smtmask_node(node: i32) -> *const cpumask;
    fn scx_bpf_get_online_cpumask() -> *const cpumask;
    fn scx_bpf_get_possible_cpumask() -> *const cpumask;
    fn scx_bpf_put_cpumask(mask: *const cpumask);

    fn scx_bpf_dsq_insert(p: *mut task_struct, dsq_id: u64,
                           slice: u64, enq_flags: u64);
    fn scx_bpf_dsq_insert_vtime(p: *mut task_struct, dsq_id: u64,
                                 slice: u64, vtime: u64, enq_flags: u64);
    fn scx_bpf_dsq_move_to_local(dsq_id: u64) -> bool;
    fn scx_bpf_dsq_nr_queued(dsq_id: u64) -> i32;
    fn scx_bpf_dsq_peek(dsq_id: u64) -> *mut task_struct;
    fn scx_bpf_create_dsq(dsq_id: u64, node: i32) -> i32;
    fn scx_bpf_destroy_dsq(dsq_id: u64);
    fn scx_bpf_dispatch_nr_slots() -> u32;
    fn scx_bpf_reenqueue_local() -> u32;

    fn bpf_iter_scx_dsq_new(it: *mut bpf_iter_scx_dsq, dsq_id: u64, flags: u64) -> i32;
    fn bpf_iter_scx_dsq_next(it: *mut bpf_iter_scx_dsq) -> *mut task_struct;
    fn bpf_iter_scx_dsq_destroy(it: *mut bpf_iter_scx_dsq);
    fn scx_bpf_dsq_move(it: *mut bpf_iter_scx_dsq, p: *mut task_struct,
                         dsq_id: u64, enq_flags: u64) -> bool;
    fn scx_bpf_dsq_move_vtime(it: *mut bpf_iter_scx_dsq, p: *mut task_struct,
                               dsq_id: u64, enq_flags: u64) -> bool;
    fn scx_bpf_dsq_move_set_slice(it: *mut bpf_iter_scx_dsq, slice: u64);
    fn scx_bpf_dsq_move_set_vtime(it: *mut bpf_iter_scx_dsq, vtime: u64);

    fn scx_bpf_task_cpu(p: *const task_struct) -> i32;
    fn scx_bpf_task_running(p: *const task_struct) -> bool;
    fn scx_bpf_task_set_slice(p: *mut task_struct, slice: u64) -> bool;
    fn scx_bpf_task_set_dsq_vtime(p: *mut task_struct, vtime: u64) -> bool;
    fn scx_bpf_cpu_curr(cpu: i32) -> *mut task_struct;

    fn scx_bpf_kick_cpu(cpu: i32, flags: u64);
    fn scx_bpf_cpuperf_cap(cpu: i32) -> u32;
    fn scx_bpf_cpuperf_cur(cpu: i32) -> u32;
    fn scx_bpf_cpuperf_set(cpu: i32, perf: u32);
    fn scx_bpf_cpu_node(cpu: i32) -> i32;
    fn scx_bpf_nr_cpu_ids() -> u32;
    fn scx_bpf_nr_node_ids() -> u32;
    fn scx_bpf_now() -> u64;
    fn scx_bpf_error_bstr(fmt: *mut u8, data: *const u64, data_sz: u32);
    fn scx_bpf_dump_bstr(fmt: *mut u8, data: *const u64, data_sz: u32);
}

pub fn nr_cpu_ids() -> u32 { unsafe { scx_bpf_nr_cpu_ids() } }
pub fn nr_node_ids() -> u32 { unsafe { scx_bpf_nr_node_ids() } }
pub fn scx_now() -> u64 { unsafe { scx_bpf_now() } }
pub fn cpu_node(cpu: i32) -> i32 { unsafe { scx_bpf_cpu_node(cpu) } }
pub fn kick_cpu(cpu: i32, flags: u64) { unsafe { scx_bpf_kick_cpu(cpu, flags) } }
pub fn cpuperf_cap(cpu: i32) -> u32 { unsafe { scx_bpf_cpuperf_cap(cpu) } }
pub fn cpuperf_cur(cpu: i32) -> u32 { unsafe { scx_bpf_cpuperf_cur(cpu) } }
pub fn cpuperf_set(cpu: i32, perf: u64) { unsafe { scx_bpf_cpuperf_set(cpu, perf as u32) } }
pub fn test_and_clear_cpu_idle(cpu: i32) -> bool {
    unsafe { scx_bpf_test_and_clear_cpu_idle(cpu) }
}
pub fn dispatch_nr_slots() -> u32 { unsafe { scx_bpf_dispatch_nr_slots() } }
pub fn reenqueue_local() -> u32 { unsafe { scx_bpf_reenqueue_local() } }

/// A negative CPU number means "none" to the kernel. Option says it in Rust.
#[inline(always)]
fn cpu_or_none(cpu: i32) -> Option<i32> {
    if cpu >= 0 { Some(cpu) } else { None }
}

#[doc(hidden)]
#[inline(always)]
pub fn __scx_error(fmt: *mut u8, args: &[u64]) {
    unsafe { scx_bpf_error_bstr(fmt, args.as_ptr(), (args.len() * 8) as u32) }
}

#[doc(hidden)]
pub const fn __fmt_array<const N: usize>(s: &str) -> [u8; N] {
    let mut buf = [0u8; N];
    let mut i = 0;
    while i < s.len() {
        buf[i] = s.as_bytes()[i];
        i += 1;
    }
    buf
}

/// scx_bpf_error() of C: printf-style format, aborts the scheduler. The kfunc
/// takes a `char *`, so the format has to be writable, like the
/// `static char ___fmt[]` of the C macro.
#[macro_export]
macro_rules! scx_error {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        static FMT: $crate::scx_common::BpfCell<[u8; $fmt.len() + 1]> =
            $crate::scx_common::BpfCell::new($crate::scx_common::__fmt_array($fmt));
        let args = [$($arg as u64,)* 0u64];
        $crate::scx_common::__scx_error(FMT.0.get() as *mut u8, &args)
    }};
}

/// Where ops.dump() and friends write to: scx_bpf_dump() of C, as a target for
/// write!(). The text is in arena, where the %s of the kernel cannot read it,
/// so the characters are passed by value.
pub struct ScxDump;

impl core::fmt::Write for ScxDump {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        static FMT: BpfCell<[u8; 3]> = BpfCell::new(*b"%c\0");
        for byte in s.bytes() {
            let args = [byte as u64];
            unsafe { scx_bpf_dump_bstr(FMT.0.get() as *mut u8, args.as_ptr(), 8) };
        }
        Ok(())
    }
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

#[btf]
pub struct sched_ext_entity {
    dsq_vtime: u64,
    slice: u64,
    weight: u32,
    flags: u32,
    tid: u64,
}

#[btf]
pub struct sched_entity {
    sum_exec_runtime: u64,
}

#[btf]
pub struct task_struct {
    scx: sched_ext_entity,
    se: sched_entity,
    pid: i32,
    tgid: i32,
    flags: u32,
    nr_cpus_allowed: i32,
    migration_disabled: u16,
    static_prio: i32,
    prio: i32,
    real_parent: *mut task_struct,
    utime: u64,
    stime: u64,
    comm: [u8; 16],
    mm: *const u8,
    cpus_ptr: *const u64,
}

#[btf]
pub struct kernfs_node {
    id: u64,
}

#[btf]
pub struct cgroup {
    kn: *const kernfs_node,
    level: i32,
}

#[btf]
pub struct scx_init_task_args {
    fork: bool,
    cgroup: *mut cgroup,
}

#[btf]
pub struct scx_cgroup_init_args {
    weight: u32,
}

/// A cgroup the kernel handed to the program.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Cgroup(NonNull<cgroup>);

impl Cgroup {
    #[inline(always)]
    pub fn from_ptr(p: *mut cgroup) -> Option<Cgroup> { NonNull::new(p).map(Cgroup) }
    #[inline(always)]
    pub fn as_ptr(self) -> *mut cgroup { self.0.as_ptr() }
    #[inline(always)]
    fn view(self) -> &'static cgroup { unsafe { &*self.0.as_ptr() } }

    /// What replaces the cgroup as the key of BPF_MAP_TYPE_CGRP_STORAGE.
    pub fn id(self) -> u64 {
        let kn = *self.view().kn().get().unwrap();
        *unsafe { &*kn }.id().get().unwrap()
    }
    pub fn level(self) -> i32 { *self.view().level().get().unwrap() }

    pub fn ancestor(self, level: i32) -> Option<CgroupRef> {
        Cgroup::from_ptr(unsafe { bpf_cgroup_ancestor(self.as_ptr(), level) }).map(CgroupRef)
    }
}

/// A cgroup reference, from scx_bpf_task_cgroup() or bpf_cgroup_ancestor().
pub struct CgroupRef(Cgroup);

impl Deref for CgroupRef {
    type Target = Cgroup;
    #[inline(always)]
    fn deref(&self) -> &Cgroup { &self.0 }
}

impl Drop for CgroupRef {
    #[inline(always)]
    fn drop(&mut self) { unsafe { bpf_cgroup_release(self.0.as_ptr()) } }
}

/// The second argument of ops.init_task().
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct InitTaskArgs(NonNull<scx_init_task_args>);

impl InitTaskArgs {
    #[inline(always)]
    fn view(self) -> &'static scx_init_task_args { unsafe { &*self.0.as_ptr() } }
    pub fn fork(self) -> bool { *self.view().fork().get().unwrap() }
    pub fn cgroup(self) -> Option<Cgroup> { Cgroup::from_ptr(*self.view().cgroup().get().unwrap()) }
}

/// The second argument of ops.cgroup_init().
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct CgroupInitArgs(NonNull<scx_cgroup_init_args>);

impl CgroupInitArgs {
    pub fn weight(self) -> u32 { *unsafe { &*self.0.as_ptr() }.weight().get().unwrap() }
}

/// A task the kernel handed to the program. Only good for the duration of the
/// call, which the verifier checks, so it is a plain copyable pointer.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Task(NonNull<task_struct>);

impl Task {
    #[inline(always)]
    pub fn from_ptr(p: *mut task_struct) -> Option<Task> { NonNull::new(p).map(Task) }
    #[inline(always)]
    pub fn as_ptr(self) -> *mut task_struct { self.0.as_ptr() }
    #[inline(always)]
    fn view(self) -> &'static task_struct { unsafe { &*self.0.as_ptr() } }

    pub fn current() -> Task {
        Task(unsafe { NonNull::new_unchecked(bpf_get_current_task_btf()) })
    }

    pub fn pid(self) -> i32 { *self.view().pid().get().unwrap() }
    pub fn tgid(self) -> i32 { *self.view().tgid().get().unwrap() }
    pub fn flags(self) -> u32 { *self.view().flags().get().unwrap() }
    pub fn nr_cpus_allowed(self) -> i32 { *self.view().nr_cpus_allowed().get().unwrap() }
    pub fn static_prio(self) -> i32 { *self.view().static_prio().get().unwrap() }
    pub fn prio(self) -> i32 { *self.view().prio().get().unwrap() }
    /// Good for comparing and for reading, not for kfuncs.
    pub fn real_parent(self) -> Option<Task> { Task::from_ptr(*self.view().real_parent().get().unwrap()) }
    /// The name of the task, NUL terminated.
    ///
    /// Read in two halves: a copy of the array would be a memcpy, which becomes
    /// bpf_arena_memcpy(), and that one cannot read kernel memory.
    pub fn comm(self) -> [u8; 16] {
        let comm = self.view().comm().as_ptr() as *const u64;
        let halves = unsafe { [comm.read_unaligned(), comm.add(1).read_unaligned()] };
        unsafe { core::mem::transmute(halves) }
    }
    pub fn sum_exec_runtime(self) -> u64 { *self.view().se().sum_exec_runtime().get().unwrap() }
    /// The cgroup of the task in the cpu controller.
    pub fn cgroup(self) -> CgroupRef {
        CgroupRef(Cgroup(unsafe { NonNull::new_unchecked(scx_bpf_task_cgroup(self.as_ptr())) }))
    }
    /// User and system time, in ns.
    pub fn cputime(self) -> u64 {
        *self.view().utime().get().unwrap() + *self.view().stime().get().unwrap()
    }
    pub fn mm(self) -> u64 { *self.view().mm().get().unwrap() as u64 }
    pub fn cpus(self) -> Cpumask {
        Cpumask(*self.view().cpus_ptr().get().unwrap() as *const cpumask)
    }

    pub fn dsq_vtime(self) -> u64 { *self.view().scx().dsq_vtime().get().unwrap() }
    pub fn slice(self) -> u64 { *self.view().scx().slice().get().unwrap() }
    pub fn weight(self) -> u64 { *self.view().scx().weight().get().unwrap() as u64 }
    pub fn scx_flags(self) -> u32 { *self.view().scx().flags().get().unwrap() }
    /// With SCX_OPS_TID_TO_TASK: what scx_bpf_tid_to_task() finds the task by.
    pub fn tid(self) -> u64 { *self.view().scx().tid().get().unwrap() }

    pub fn set_dsq_vtime(self, v: u64) { unsafe { scx_bpf_task_set_dsq_vtime(self.as_ptr(), v); } }
    pub fn set_slice(self, v: u64) { unsafe { scx_bpf_task_set_slice(self.as_ptr(), v); } }

    pub fn cpu(self) -> i32 { unsafe { scx_bpf_task_cpu(self.as_ptr()) } }
    pub fn is_running(self) -> bool { unsafe { scx_bpf_task_running(self.as_ptr()) } }
    pub fn is_queued(self) -> bool { self.scx_flags() & SCX_TASK_QUEUED != 0 }
    pub fn is_kthread(self) -> bool { self.flags() & PF_KTHREAD != 0 }
    pub fn is_idle_task(self) -> bool { self.flags() & PF_IDLE != 0 }
    pub fn is_exiting(self) -> bool { self.flags() & PF_EXITING != 0 }

    /// The BPF program itself runs with migration disabled: one level does
    /// not count when @self is the current task.
    pub fn is_migration_disabled(self) -> bool {
        match *self.view().migration_disabled().get().unwrap() {
            0 => false,
            1 => Task::current() != self,
            _ => true,
        }
    }

    /// Can only run on a single CPU.
    pub fn is_pcpu(self) -> bool {
        self.nr_cpus_allowed() == 1 || self.is_migration_disabled()
    }

    pub fn scale_by_weight(self, v: u64) -> u64 { v * self.weight() / 100 }
    pub fn scale_by_weight_inverse(self, v: u64) -> u64 { v * 100 / self.weight() }

    pub fn dsq_insert(self, dsq_id: u64, slice: u64, enq_flags: u64) {
        unsafe { scx_bpf_dsq_insert(self.as_ptr(), dsq_id, slice, enq_flags) }
    }
    pub fn dsq_insert_vtime(self, dsq_id: u64, slice: u64, vtime: u64, enq_flags: u64) {
        unsafe { scx_bpf_dsq_insert_vtime(self.as_ptr(), dsq_id, slice, vtime, enq_flags) }
    }

    /// The built-in idle CPU selection. The bool says whether the CPU is idle.
    pub fn select_cpu_dfl(self, prev_cpu: i32, wake_flags: u64) -> (i32, bool) {
        let mut is_idle = false;
        let cpu = unsafe {
            scx_bpf_select_cpu_dfl(self.as_ptr(), prev_cpu, wake_flags, &mut is_idle)
        };
        (cpu, is_idle)
    }
    /// An idle CPU out of @allowed, as close to @prev_cpu as possible.
    pub fn select_cpu_and(self, prev_cpu: i32, wake_flags: u64, allowed: Cpumask,
                          flags: u64) -> Option<i32> {
        cpu_or_none(unsafe {
            scx_bpf_select_cpu_and(self.as_ptr(), prev_cpu, wake_flags, allowed.0, flags)
        })
    }
}

/// A task reference from bpf_task_from_pid().
pub struct TaskRef(Task);

impl TaskRef {
    pub fn from_pid(pid: i32) -> Option<TaskRef> {
        Task::from_ptr(unsafe { bpf_task_from_pid(pid) }).map(TaskRef)
    }
}

impl Deref for TaskRef {
    type Target = Task;
    #[inline(always)]
    fn deref(&self) -> &Task { &self.0 }
}

impl Drop for TaskRef {
    #[inline(always)]
    fn drop(&mut self) { unsafe { bpf_task_release(self.0.as_ptr()) } }
}

// ── RCU and interrupts ───────────────────────────────────────────────

pub struct RcuGuard(());

pub fn rcu_read_lock() -> RcuGuard {
    unsafe { bpf_rcu_read_lock() };
    RcuGuard(())
}

impl RcuGuard {
    /// The task running on @cpu. Stays valid as long as the guard does.
    pub fn cpu_curr(&self, cpu: i32) -> Option<Task> {
        Task::from_ptr(unsafe { scx_bpf_cpu_curr(cpu) })
    }
}

impl Drop for RcuGuard {
    #[inline(always)]
    fn drop(&mut self) { unsafe { bpf_rcu_read_unlock() } }
}

/// The task running on @cpu, for programs that cannot sleep: those run inside
/// an RCU section from start to end.
pub fn cpu_curr(cpu: i32) -> Option<Task> {
    Task::from_ptr(unsafe { scx_bpf_cpu_curr(cpu) })
}

/// Where bpf_local_irq_save() keeps the flags. The verifier tracks that stack
/// slot, so it must not move: the guard borrows it instead of owning it.
pub struct IrqFlags(u64);

pub struct IrqGuard<'a>(&'a mut IrqFlags);

impl IrqFlags {
    #[inline(always)]
    pub fn new() -> Self { IrqFlags(0) }
    #[inline(always)]
    pub fn save(&mut self) -> IrqGuard<'_> {
        unsafe { bpf_local_irq_save(&mut self.0) };
        IrqGuard(self)
    }
}

impl Drop for IrqGuard<'_> {
    #[inline(always)]
    fn drop(&mut self) { unsafe { bpf_local_irq_restore(&mut self.0.0) } }
}

// ── cpumasks of the kernel ───────────────────────────────────────────

/// A cpumask that belongs to the kernel, e.g. p->cpus_ptr.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Cpumask(*const cpumask);

impl Cpumask {
    pub fn test(self, cpu: i32) -> bool { unsafe { bpf_cpumask_test_cpu(cpu as u32, self.0) } }
    pub fn first(self) -> i32 { unsafe { bpf_cpumask_first(self.0) as i32 } }
    pub fn weight(self) -> u32 { unsafe { bpf_cpumask_weight(self.0) } }
    pub fn is_empty(self) -> bool { unsafe { bpf_cpumask_empty(self.0) } }
    pub fn intersects(self, other: Cpumask) -> bool {
        unsafe { bpf_cpumask_intersects(self.0, other.0) }
    }
    pub fn is_subset(self, other: Cpumask) -> bool {
        unsafe { bpf_cpumask_subset(self.0, other.0) }
    }
    pub fn any_distribute(self) -> i32 { unsafe { bpf_cpumask_any_distribute(self.0) as i32 } }
    pub fn pick_idle(self, flags: u64) -> Option<i32> {
        cpu_or_none(unsafe { scx_bpf_pick_idle_cpu(self.0, flags) })
    }
    pub fn pick_any(self, flags: u64) -> Option<i32> {
        cpu_or_none(unsafe { scx_bpf_pick_any_cpu(self.0, flags) })
    }
}

/// A cpumask acquired with one of scx_bpf_get_*_cpumask().
pub struct ScxCpumask(Cpumask);

impl ScxCpumask {
    pub fn idle() -> Self { ScxCpumask(Cpumask(unsafe { scx_bpf_get_idle_cpumask() })) }
    pub fn idle_node(node: i32) -> Self {
        ScxCpumask(Cpumask(unsafe { scx_bpf_get_idle_cpumask_node(node) }))
    }
    pub fn idle_smt() -> Self { ScxCpumask(Cpumask(unsafe { scx_bpf_get_idle_smtmask() })) }
    pub fn idle_smt_node(node: i32) -> Self {
        ScxCpumask(Cpumask(unsafe { scx_bpf_get_idle_smtmask_node(node) }))
    }
    pub fn online() -> Self { ScxCpumask(Cpumask(unsafe { scx_bpf_get_online_cpumask() })) }
    pub fn possible() -> Self { ScxCpumask(Cpumask(unsafe { scx_bpf_get_possible_cpumask() })) }
}

impl Deref for ScxCpumask {
    type Target = Cpumask;
    #[inline(always)]
    fn deref(&self) -> &Cpumask { &self.0 }
}

impl Drop for ScxCpumask {
    #[inline(always)]
    fn drop(&mut self) { unsafe { scx_bpf_put_cpumask(self.0.0) } }
}

// ── DSQs ─────────────────────────────────────────────────────────────

/// A dispatch queue, by id.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Dsq(pub u64);

impl Dsq {
    pub fn create(self, node: i32) -> Result { Errno::check(unsafe { scx_bpf_create_dsq(self.0, node) }) }
    pub fn destroy(self) { unsafe { scx_bpf_destroy_dsq(self.0) } }
    pub fn nr_queued(self) -> u64 {
        let nr = unsafe { scx_bpf_dsq_nr_queued(self.0) };
        if nr > 0 { nr as u64 } else { 0 }
    }
    pub fn move_to_local(self) -> bool { unsafe { scx_bpf_dsq_move_to_local(self.0) } }
    /// The first task, without taking it off the queue.
    pub fn peek(self) -> Option<Task> { Task::from_ptr(unsafe { scx_bpf_dsq_peek(self.0) }) }
    pub fn local_on(cpu: i32) -> Dsq { Dsq(SCX_DSQ_LOCAL_ON | cpu as u64) }
}

/// Room for the state of a walk over a DSQ: bpf_for_each(scx_dsq, ...) of C.
/// Like IrqFlags it is a stack slot that the verifier tracks, so the iterator
/// borrows it.
///
///     let mut it = DsqIterState::new();
///     let mut tasks = it.iter(dsq, 0);
///     while let Some(p) = tasks.next() { ... tasks.move_to(p, ...) ... }
pub struct DsqIterState(core::mem::MaybeUninit<bpf_iter_scx_dsq>);

pub struct DsqIter<'a>(&'a mut DsqIterState);

impl DsqIterState {
    #[inline(always)]
    pub fn new() -> Self { DsqIterState(core::mem::MaybeUninit::uninit()) }
    #[inline(always)]
    pub fn iter(&mut self, dsq: Dsq, flags: u64) -> DsqIter<'_> {
        unsafe { bpf_iter_scx_dsq_new(self.0.as_mut_ptr(), dsq.0, flags) };
        DsqIter(self)
    }
}

impl DsqIter<'_> {
    #[inline(always)]
    pub fn move_to(&mut self, p: Task, dsq: Dsq, enq_flags: u64) -> bool {
        unsafe { scx_bpf_dsq_move(self.0.0.as_mut_ptr(), p.as_ptr(), dsq.0, enq_flags) }
    }
    #[inline(always)]
    pub fn move_vtime_to(&mut self, p: Task, dsq: Dsq, enq_flags: u64) -> bool {
        unsafe { scx_bpf_dsq_move_vtime(self.0.0.as_mut_ptr(), p.as_ptr(), dsq.0, enq_flags) }
    }
    #[inline(always)]
    pub fn set_slice(&mut self, slice: u64) {
        unsafe { scx_bpf_dsq_move_set_slice(self.0.0.as_mut_ptr(), slice) }
    }
    #[inline(always)]
    pub fn set_vtime(&mut self, vtime: u64) {
        unsafe { scx_bpf_dsq_move_set_vtime(self.0.0.as_mut_ptr(), vtime) }
    }
}

impl Iterator for DsqIter<'_> {
    type Item = Task;
    #[inline(always)]
    fn next(&mut self) -> Option<Task> {
        Task::from_ptr(unsafe { bpf_iter_scx_dsq_next(self.0.0.as_mut_ptr()) })
    }
}

impl Drop for DsqIter<'_> {
    #[inline(always)]
    fn drop(&mut self) { unsafe { bpf_iter_scx_dsq_destroy(self.0.0.as_mut_ptr()) } }
}

// ── Timers ───────────────────────────────────────────────────────────
//
// struct bpf_timer is the one thing that cannot live in arena: the kernel has
// to find it, so it stays in the value of a BPF array map. The map is declared
// the way libbpf expects a BTF-defined map: the numbers are array sizes.
//
//     bpf_timer_map!(foo_timers, timers, 1);
//
// defines the map foo_timers with one timer and the function timers() to get
// at it. `static mut` makes the section writable, like the .maps section of a
// C program and the one that LLVM makes for the arena map. With other flags it
// would be a second section of that name, which libbpf cannot deal with.
//
// The kernel cancels and frees the timers of a map when the last reference of
// user space to the map goes away. The loader of a C scheduler stays around and
// holds one. `bpftool struct_ops register` exits, and 10 ms later the timers are
// gone. So libbpf is told to pin the map, as /sys/fs/bpf/foo_timers. The pin
// outlives the scheduler: ops.exit() has to cancel the timers, and whoever
// unregisters the scheduler removes the pin.

pub type TimerFn = extern "C" fn(map: *mut u8, key: *mut u32, timer: *mut bpf_timer) -> i32;

/// The kernel looks for a member of type struct bpf_timer in the value.
#[repr(C)]
pub struct timer_val { timer: bpf_timer }

#[repr(C)]
pub struct timer_map_def<const N: usize> {
    r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY
    max_entries: *const [i32; N],
    key: *const u32,
    value: *const timer_val,
    pinning: *const [i32; 1], // LIBBPF_PIN_BY_NAME
}

unsafe impl<const N: usize> Sync for timer_map_def<N> {}

impl<const N: usize> timer_map_def<N> {
    pub const fn new() -> Self {
        timer_map_def {
            r#type: core::ptr::null(),
            max_entries: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
            pinning: core::ptr::null(),
        }
    }

    #[inline(always)]
    fn as_ptr(&'static self) -> *const u8 { self as *const Self as *const u8 }

    /// The timer number @idx.
    #[inline(always)]
    pub fn get(&'static self, idx: u32) -> Option<Timer> {
        let t = unsafe {
            bpf_map_lookup_elem(self.as_ptr(), &idx as *const u32 as *const u8)
        };
        NonNull::new(t as *mut bpf_timer).map(Timer)
    }

    #[inline(always)]
    pub fn init(&'static self, idx: u32, clock: u64, cb: TimerFn) -> Result<Timer> {
        let t = self.get(idx).ok_or(ESRCH)?;
        // EBUSY: left behind in the pinned map by an earlier run.
        Errno::check(unsafe { bpf_timer_init(t.0.as_ptr(), self.as_ptr(), clock) } as i32)
            .or_else(|e| if e == EBUSY { Ok(()) } else { Err(e) })?;
        Errno::check(unsafe { bpf_timer_set_callback(t.0.as_ptr(), cb) } as i32)?;
        Ok(t)
    }
}

impl<const N: usize> timer_map_def<N> {
    /// For ops.exit().
    pub fn cancel_all(&'static self) {
        (0..N as u32).filter_map(|idx| self.get(idx)).for_each(Timer::cancel);
    }
}

#[macro_export]
macro_rules! bpf_timer_map {
    ($map:ident, $get:ident, $n:expr) => {
        #[link_section = ".maps"]
        #[no_mangle]
        #[allow(non_upper_case_globals)]
        static mut $map: $crate::scx_common::timer_map_def<$n> =
            $crate::scx_common::timer_map_def::new();

        #[inline(always)]
        fn $get() -> &'static $crate::scx_common::timer_map_def<$n> {
            unsafe { &*&raw const $map }
        }
    };
}

// ── Ring buffer to user space ────────────────────────────────────────

#[repr(C)]
pub struct ringbuf_map_def<const SIZE: usize> {
    r#type: *const [i32; 27], // BPF_MAP_TYPE_RINGBUF
    max_entries: *const [i32; SIZE],
}

unsafe impl<const SIZE: usize> Sync for ringbuf_map_def<SIZE> {}

impl<const SIZE: usize> ringbuf_map_def<SIZE> {
    pub const fn new() -> Self { ringbuf_map_def { r#type: core::ptr::null(), max_entries: core::ptr::null() } }

    /// Room for a T, or None if the buffer is full. What is in there is not
    /// initialized: T should be made of numbers.
    #[inline(always)]
    pub fn reserve<T>(&'static self) -> Option<RingbufRecord<T>> {
        let rec = unsafe { bpf_ringbuf_reserve(self as *const Self as *const u8, core::mem::size_of::<T>() as u64, 0) };
        NonNull::new(rec as *mut T).map(RingbufRecord)
    }
}

/// A record that was reserved. It is discarded unless it is submitted.
pub struct RingbufRecord<T>(NonNull<T>);

impl<T> RingbufRecord<T> {
    #[inline(always)]
    pub fn as_mut(&mut self) -> &mut T { unsafe { self.0.as_mut() } }

    #[inline(always)]
    pub fn submit(self) {
        unsafe { bpf_ringbuf_submit(self.0.as_ptr() as *mut u8, 0) };
        core::mem::forget(self);
    }
}

impl<T> Drop for RingbufRecord<T> {
    #[inline(always)]
    fn drop(&mut self) { unsafe { bpf_ringbuf_discard(self.0.as_ptr() as *mut u8, 0) } }
}

#[macro_export]
macro_rules! bpf_ringbuf_map {
    ($map:ident, $get:ident, $size:expr) => {
        #[link_section = ".maps"]
        #[no_mangle]
        #[allow(non_upper_case_globals)]
        static mut $map: $crate::scx_common::ringbuf_map_def<{ $size }> =
            $crate::scx_common::ringbuf_map_def::new();

        #[inline(always)]
        fn $get() -> &'static $crate::scx_common::ringbuf_map_def<{ $size }> {
            unsafe { &*&raw const $map }
        }
    };
}

/// std::panic::catch_unwind() for a plain function. Tells whether it came back
/// without a panic.
///
/// A panic must not leave an `extern "C"` function like the callback of a timer:
/// rustc makes that an abort, which is bpf_throw(), which the verifier does not
/// allow in a callback. It is enough that the compiler cannot rule a panic out,
/// as with a call through a pointer.
///
/// A macro, so that only the schedulers that use it need
/// `#![feature(core_intrinsics)]`.
#[macro_export]
macro_rules! catch_panic {
    ($f:expr) => {{
        fn do_call(f: *mut u8) { (unsafe { core::mem::transmute::<*mut u8, fn()>(f) })() }
        fn do_catch(_f: *mut u8, _payload: *mut u8) {}

        let f: fn() = $f;
        unsafe { core::intrinsics::catch_unwind(do_call, f as *mut u8, do_catch) == 0 }
    }};
}

#[derive(Clone, Copy)]
pub struct Timer(NonNull<bpf_timer>);

impl Timer {
    /// What a callback gets as its third argument.
    #[inline(always)]
    pub fn from_ptr(t: *mut bpf_timer) -> Option<Timer> { NonNull::new(t).map(Timer) }
    #[inline(always)]
    pub fn start(self, nsecs: u64, flags: u64) -> Result {
        Errno::check(unsafe { bpf_timer_start(self.0.as_ptr(), nsecs, flags) } as i32)
    }
    #[inline(always)]
    pub fn cancel(self) { unsafe { bpf_timer_cancel(self.0.as_ptr()); } }
}

// ── Shared state ─────────────────────────────────────────────────────

/// The `const volatile` variables of C, which user space sets before it loads
/// the scheduler.
///
///     tunables! { "foo",
///         /// Default time slice.
///         SLICE_NS: AtomicU64 = NSEC_PER_MSEC;
///     }
///
/// defines the atomic SLICE_NS and exports it as foo_SLICE_NS. Exported it has
/// to be: nothing in the program writes to it, and LLVM replaces a variable
/// that nobody outside can see and nobody inside writes with its initial value.
/// All the code for the other values would be gone from the object.
#[macro_export]
macro_rules! tunables {
    ($prefix:literal, $($(#[$meta:meta])* $name:ident: $ty:ty = $val:expr;)*) => {
        $(
            $(#[$meta])*
            #[export_name = concat!($prefix, "_", stringify!($name))]
            static $name: $ty = <$ty>::new($val);
        )*
    };
}

pub struct BpfCell<T>(pub UnsafeCell<T>);
unsafe impl<T> Sync for BpfCell<T> {}

impl<T> BpfCell<T> {
    pub const fn new(v: T) -> Self { BpfCell(UnsafeCell::new(v)) }
    #[inline(always)]
    pub fn get(&self) -> &T { unsafe { &*self.0.get() } }
    /// For data that the caller knows it has to itself, e.g. the context of
    /// the CPU whose rq lock is held.
    #[inline(always)]
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut(&self) -> &mut T { &mut *self.0.get() }
}

/// Test-and-set lock in arena. Most ops run with interrupts off and the rq
/// lock held. The ones that do not (init_task, init, syscall programs) have to
/// turn interrupts off first, see IrqFlags: a wakeup from an interrupt would
/// spin on the lock of the context that it interrupted.
pub struct SpinLock<T> {
    locked: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}

pub struct SpinGuard<'a, T>(&'a SpinLock<T>);

impl<T> SpinLock<T> {
    pub const fn new(v: T) -> Self {
        SpinLock { locked: AtomicU32::new(0), data: UnsafeCell::new(v) }
    }

    pub fn lock(&self) -> SpinGuard<'_, T> {
        while self.locked.compare_exchange(0, 1, Acquire, Relaxed).is_err() {
            while self.locked.load(Relaxed) != 0 {
                core::hint::spin_loop();
            }
        }
        SpinGuard(self)
    }
}

/// Run @f with interrupts off: for the ops that are called with interrupts on
/// and take a SpinLock.
///
/// @f is not inlined. alloc aborts in a few places, e.g. when the closure of
/// btree::mem::replace() panics or a reference count overflows, and an abort can
/// only be turned into something that gets past the guard here, an unwind, when
/// it is not in the same function as the guard. See TRAP_TO_UNWIND in
/// add_ksyms.py.
pub fn with_irqs_off<R>(f: impl FnOnce() -> R) -> R {
    #[inline(never)]
    fn outlined<R>(f: impl FnOnce() -> R) -> R { f() }

    let mut flags = IrqFlags::new();
    let _irq = flags.save();
    outlined(f)
}

impl<T> SpinLock<T> {
    /// Run @f on the data with interrupts off and the lock held. Not inlined
    /// either, for the same reason.
    pub fn with_irqs_off<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        #[inline(never)]
        fn outlined<T, R>(f: impl FnOnce(&mut T) -> R, data: &mut T) -> R { f(data) }

        let mut flags = IrqFlags::new();
        let _irq = flags.save();
        let mut data = self.lock();
        outlined(f, &mut data)
    }
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T { unsafe { &*self.0.data.get() } }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T { unsafe { &mut *self.0.data.get() } }
}

impl<T> Drop for SpinGuard<'_, T> {
    #[inline(always)]
    fn drop(&mut self) { self.0.locked.store(0, Release) }
}

/// Replaces BPF_MAP_TYPE_TASK_STORAGE. The lock protects the tree. A context
/// is boxed, so it stays where it is while the tree changes around it, and it
/// is used without the lock: the kernel serializes the ops of one task.
pub struct TaskMap<T>(SpinLock<BTreeMap<i32, Box<UnsafeCell<T>>>>);

unsafe impl<T> Sync for TaskMap<T> {}

impl<T> TaskMap<T> {
    pub const fn new() -> Self { TaskMap(SpinLock::new(BTreeMap::new())) }

    /// From ops.init_task(), which runs with interrupts on.
    pub fn insert(&self, p: Task, ctx: T) {
        let ctx = Box::new(UnsafeCell::new(ctx));
        self.0.with_irqs_off(|tasks| tasks.insert(p.pid(), ctx));
    }

    pub fn remove(&self, p: Task) {
        let old = self.0.lock().remove(&p.pid());
        drop(old);
    }

    #[allow(clippy::mut_from_ref)]
    pub fn get(&self, p: Task) -> Option<&mut T> {
        let ctx = self.0.lock().get(&p.pid())?.get();
        Some(unsafe { &mut *ctx })
    }

    /// The same where interrupts are on: in tracing programs, in ops that can
    /// sleep. An op that interrupts the holder of the lock on its CPU would wait
    /// for the lock for ever.
    #[allow(clippy::mut_from_ref)]
    pub fn get_irqs_on(&self, p: Task) -> Option<&mut T> {
        let ctx = self.0.with_irqs_off(|tasks| tasks.get(&p.pid()).map(|ctx| ctx.get()))?;
        Some(unsafe { &mut *ctx })
    }

    /// The context of some other task. It may be in use on another CPU.
    pub fn get_pid(&self, pid: i32) -> Option<&T> {
        let ctx = self.0.lock().get(&pid)?.get();
        Some(unsafe { &*ctx })
    }

    pub fn len(&self) -> usize { self.0.lock().len() }
}

// ── CPU sets ─────────────────────────────────────────────────────────

/// Replaces `struct bpf_cpumask __kptr *`: a set of CPUs that the scheduler
/// maintains itself. A kptr cannot be stored in arena, a bitmap can.
pub struct CpuSet([AtomicU64; MAX_CPUS / 64]);

impl CpuSet {
    pub const fn new() -> Self { CpuSet([const { AtomicU64::new(0) }; MAX_CPUS / 64]) }

    #[inline(always)]
    fn word(&self, cpu: i32) -> Option<(&AtomicU64, u64)> {
        let cpu = usize::try_from(cpu).ok()?;
        Some((self.0.get(cpu / 64)?, 1 << (cpu % 64)))
    }

    pub fn set(&self, cpu: i32) {
        if let Some((w, bit)) = self.word(cpu) { w.fetch_or(bit, Relaxed); }
    }
    pub fn clear(&self, cpu: i32) {
        if let Some((w, bit)) = self.word(cpu) { w.fetch_and(!bit, Relaxed); }
    }
    /// Returns whether the CPU was in the set.
    pub fn test_and_set(&self, cpu: i32) -> bool {
        self.word(cpu).is_some_and(|(w, bit)| w.fetch_or(bit, Relaxed) & bit != 0)
    }
    pub fn test_and_clear(&self, cpu: i32) -> bool {
        self.word(cpu).is_some_and(|(w, bit)| w.fetch_and(!bit, Relaxed) & bit != 0)
    }
    pub fn clear_all(&self) { self.0.iter().for_each(|w| w.store(0, Relaxed)) }
    pub fn test(&self, cpu: i32) -> bool {
        self.word(cpu).is_some_and(|(w, bit)| w.load(Relaxed) & bit != 0)
    }
    pub fn is_empty(&self) -> bool { self.0.iter().all(|w| w.load(Relaxed) == 0) }
    pub fn weight(&self) -> u32 { self.0.iter().map(|w| w.load(Relaxed).count_ones()).sum() }
    pub fn first(&self) -> Option<i32> { self.iter().next() }

    /// The CPUs of the set in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = i32> + '_ {
        self.0.iter().enumerate().flat_map(|(i, w)| Bits(w.load(Relaxed)).map(move |b| (i * 64) as i32 + b))
    }

    /// The same, starting from @start and wrapping around.
    pub fn iter_from(&self, start: i32) -> impl Iterator<Item = i32> + '_ {
        self.iter().filter(move |&c| c >= start).chain(self.iter().filter(move |&c| c < start))
    }

    pub fn intersects(&self, mask: Cpumask) -> bool { self.iter().any(|c| mask.test(c)) }
    pub fn is_subset_of(&self, mask: Cpumask) -> bool { self.iter().all(|c| mask.test(c)) }

    /// The CPUs that are in both sets.
    pub fn iter_and<'a>(&'a self, other: &'a CpuSet) -> impl Iterator<Item = i32> + 'a {
        self.0.iter().zip(&other.0).enumerate().flat_map(|(i, (a, b))| {
            Bits(a.load(Relaxed) & b.load(Relaxed)).map(move |bit| (i * 64) as i32 + bit)
        })
    }

    pub fn intersects_set(&self, other: &CpuSet) -> bool {
        self.0.iter().zip(&other.0).any(|(a, b)| a.load(Relaxed) & b.load(Relaxed) != 0)
    }

    /// bpf_cpumask_and(), _or(), _xor(), _copy(): @f combines the sets 64 CPUs
    /// at a time. @self may be one of them.
    pub fn assign_with(&self, a: &CpuSet, b: &CpuSet, f: impl Fn(u64, u64) -> u64) {
        for ((dst, a), b) in self.0.iter().zip(&a.0).zip(&b.0) {
            dst.store(f(a.load(Relaxed), b.load(Relaxed)), Relaxed);
        }
    }

    /// Make this the set of the CPUs of @other that are in @mask.
    pub fn assign_and(&self, other: &CpuSet, mask: Cpumask) {
        for (i, (dst, src)) in self.0.iter().zip(&other.0).enumerate() {
            let word = Bits(src.load(Relaxed))
                .filter(|bit| mask.test((i * 64) as i32 + bit))
                .fold(0, |word, bit| word | 1 << bit);
            dst.store(word, Relaxed);
        }
    }

    /// Some CPU of the set, not the same one every time.
    pub fn any_distribute(&self) -> Option<i32> {
        match self.weight() {
            0 => None,
            nr => self.iter().nth((random() % nr) as usize),
        }
    }
}

/// The positions of the bits set in a word.
struct Bits(u64);

impl Iterator for Bits {
    type Item = i32;
    #[inline(always)]
    fn next(&mut self) -> Option<i32> {
        if self.0 == 0 { return None; }
        let bit = self.0.trailing_zeros();
        self.0 &= self.0 - 1;
        Some(bit as i32)
    }
}

// ── EWMA ─────────────────────────────────────────────────────────────

/// new_avg := (old_avg * .75) + (new_val * .25)
pub fn calc_avg(old: u64, new: u64) -> u64 { (old - (old >> 2)) + (new >> 2) }

/// Average frequency of an event, from the interval since the last one.
pub fn update_freq(freq: u64, interval: u64) -> u64 {
    calc_avg(freq, (100 * NSEC_PER_MSEC) / interval.max(1))
}

// ── struct_ops callbacks ─────────────────────────────────────────────
// The kernel passes struct_ops arguments through a ctx array. bpf_prog!
// extracts them like C's BPF_PROG macro. FromCtx says how an argument is made
// out of a ctx slot, OpRet how a return value becomes the s32 of the op.

pub trait FromCtx { fn from_ctx(v: u64) -> Self; }

impl FromCtx for u64 { #[inline(always)] fn from_ctx(v: u64) -> u64 { v } }
impl FromCtx for i32 { #[inline(always)] fn from_ctx(v: u64) -> i32 { v as i32 } }
impl FromCtx for u32 { #[inline(always)] fn from_ctx(v: u64) -> u32 { v as u32 } }
impl FromCtx for bool { #[inline(always)] fn from_ctx(v: u64) -> bool { v != 0 } }
impl<T> FromCtx for *const T { #[inline(always)] fn from_ctx(v: u64) -> *const T { v as *const T } }
impl<T> FromCtx for *mut T { #[inline(always)] fn from_ctx(v: u64) -> *mut T { v as *mut T } }
impl FromCtx for Task {
    #[inline(always)]
    fn from_ctx(v: u64) -> Task { Task(unsafe { NonNull::new_unchecked(v as *mut task_struct) }) }
}
impl FromCtx for Cpumask {
    #[inline(always)]
    fn from_ctx(v: u64) -> Cpumask { Cpumask(v as *const cpumask) }
}
impl FromCtx for Cgroup {
    #[inline(always)]
    fn from_ctx(v: u64) -> Cgroup { Cgroup(unsafe { NonNull::new_unchecked(v as *mut cgroup) }) }
}
impl FromCtx for InitTaskArgs {
    #[inline(always)]
    fn from_ctx(v: u64) -> Self { InitTaskArgs(unsafe { NonNull::new_unchecked(v as *mut _) }) }
}
impl FromCtx for CgroupInitArgs {
    #[inline(always)]
    fn from_ctx(v: u64) -> Self { CgroupInitArgs(unsafe { NonNull::new_unchecked(v as *mut _) }) }
}
impl FromCtx for Option<Task> {
    #[inline(always)]
    fn from_ctx(v: u64) -> Option<Task> { Task::from_ptr(v as *mut task_struct) }
}

pub trait OpRet { fn ret(self) -> i32; }

impl OpRet for () { #[inline(always)] fn ret(self) -> i32 { 0 } }
impl OpRet for i32 { #[inline(always)] fn ret(self) -> i32 { self } }
impl OpRet for Result {
    #[inline(always)]
    fn ret(self) -> i32 { match self { Ok(()) => 0, Err(e) => -e.0 } }
}

#[repr(C)]
pub struct ScxExitInfo { /* opaque */ }

#[repr(C)]
pub struct ScxInitTaskArgs { /* opaque */ }

#[macro_export]
macro_rules! bpf_prog {
    ($section:expr, fn $name:ident($($arg:ident : $ty:ty),* $(,)?) $(-> $ret:ty)? $body:block) => {
        #[link_section = $section]
        #[no_mangle]
        extern "C" fn $name(_ctx: *const u64) -> i32 {
            #[inline(always)]
            fn op($($arg: $ty),*) $(-> $ret)? $body
            let mut _i = 0usize;
            $(
                #[allow(unused_assignments)]
                let $arg = {
                    let v = unsafe { *_ctx.add(_i) };
                    _i += 1;
                    <$ty as $crate::scx_common::FromCtx>::from_ctx(v)
                };
            )*
            $crate::scx_common::OpRet::ret(op($($arg),*))
        }
    };
}

pub type OpFn = extern "C" fn(*const u64) -> i32;

pub const fn pad_name<const N: usize>(s: &[u8; N]) -> [u8; 128] {
    let mut buf = [0u8; 128];
    let mut i = 0;
    while i < N && i < 127 {
        buf[i] = s[i];
        i += 1;
    }
    buf
}

/// SCX_OPS_DEFINE of C. libbpf matches the members with the kernel's struct
/// sched_ext_ops by name, so only the ones in use are declared.
#[macro_export]
macro_rules! scx_ops_define {
    ($var:ident, $($rest:tt)*) => { scx_ops_define!(@sched_ext_ops $var, $($rest)*); };
    (@$ops:ident $var:ident, name: $name:literal, flags: $flags:expr, timeout_ms: $timeout:expr,
     $($op:ident: $f:ident),* $(,)?) => {
        #[repr(C)]
        #[allow(non_camel_case_types)]
        struct $ops {
            $($op: $crate::scx_common::OpFn,)*
            flags: u64,
            timeout_ms: u32,
            name: [u8; 128],
        }

        unsafe impl Sync for $ops {}

        #[link_section = ".struct_ops.link"]
        #[no_mangle]
        #[allow(non_upper_case_globals)]
        static $var: $ops = $ops {
            $($op: $f,)*
            flags: $flags,
            timeout_ms: $timeout,
            name: $crate::scx_common::pad_name($name),
        };

        #[link_section = "license"]
        #[no_mangle]
        static _LICENSE: [u8; 4] = *b"GPL\0";
    };
}

/// SCX_OPS_CID_DEFINE of C: the form of the ops that speaks of cids and cmasks
/// instead of CPUs and cpumasks.
#[macro_export]
macro_rules! scx_ops_cid_define {
    ($var:ident, $($rest:tt)*) => { scx_ops_define!(@sched_ext_ops_cid $var, $($rest)*); };
}

// ── Panic handler ────────────────────────────────────────────────────

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

/// See scx_simple.rs.
#[panic_handler]
#[inline(always)]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    let mut stream = BpfStream(BPF_STDERR);
    if !cfg!(bpf_unwind) {
        let _ = write!(stream, "{}", info);
    } else if info.can_unwind() {
        let _ = writeln!(stream, "{}", info);
        unsafe { bpf_stream_print_stack(BPF_STDERR) };
        unsafe { _Unwind_RaiseException(core::ptr::null_mut()) };
    } else if let Some(msg) = info.message().as_str() {
        let _ = stream.write_str(msg);
    }
    unsafe { bpf_throw(1) }
}

/// A failed allocation panics: it unwinds, so that interrupts are restored,
/// locks and references released on the way out. bpf_throw() would leave all
/// that behind, and the verifier refuses it where something is held.
#[alloc_error_handler]
fn oom(layout: Layout) -> ! {
    panic!("memory allocation of {} bytes failed", layout.size())
}

// SPDX-License-Identifier: GPL-2.0
//! Run time of the corpus: allocator, panic handler and the test harness.
//!
//! Nothing here knows about arena. The heap is a static array, pointers are
//! plain pointers; where they live is decided by the LLVM backend.
//!
//! The tests are compiled for the host too (make host), as a control: there
//! panics are those of std, the rest is the same.
#![no_std]
#![cfg_attr(target_arch = "bpf", feature(lang_items))]
#![cfg_attr(target_arch = "bpf", feature(alloc_error_handler))]
#![cfg_attr(target_arch = "bpf", feature(core_intrinsics))]
#![allow(internal_features)]
#![allow(static_mut_refs)]

extern crate alloc;
#[cfg(not(target_arch = "bpf"))]
extern crate std;

use core::alloc::{GlobalAlloc, Layout};

pub use core::hint::black_box as bb;

// ---- allocator: power of two size classes, a free list per class

const HEAP_SIZE: usize = 8 << 20;
const MIN_SHIFT: u32 = 4;
const NR_CLASSES: usize = 24;

#[repr(C, align(4096))]
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static mut HEAP_OFF: usize = 0;
static mut FREE: [*mut u8; NR_CLASSES] = [core::ptr::null_mut(); NR_CLASSES];
static mut LIVE: i64 = 0;
static mut ALLOCS: u64 = 0;

#[inline(always)]
fn class_of(layout: &Layout) -> usize {
    let sz = layout.size().max(layout.align()).max(1 << MIN_SHIFT);
    (sz.next_power_of_two().trailing_zeros() - MIN_SHIFT) as usize
}

struct BpfAllocator;

unsafe impl GlobalAlloc for BpfAllocator {
    #[inline(never)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let c = class_of(&layout);
        if c >= NR_CLASSES {
            return core::ptr::null_mut();
        }
        unsafe {
            let p = FREE[c];
            if !p.is_null() {
                FREE[c] = *(p as *mut *mut u8);
                LIVE += 1;
                ALLOCS += 1;
                return p;
            }
            // A block is aligned to its size, a page at most.
            let sz = 1usize << (c as u32 + MIN_SHIFT);
            let al = sz.min(4096).max(layout.align());
            let off = (HEAP_OFF + al - 1) & !(al - 1);
            if off + sz > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            HEAP_OFF = off + sz;
            LIVE += 1;
            ALLOCS += 1;
            (&raw mut HEAP.0 as *mut u8).add(off)
        }
    }

    #[inline(never)]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let c = class_of(&layout);
        // An allocator must not unwind: no bounds check that can fail.
        if c >= NR_CLASSES {
            return;
        }
        unsafe {
            *(ptr as *mut *mut u8) = FREE[c];
            FREE[c] = ptr;
            LIVE -= 1;
        }
    }
}

#[global_allocator]
static ALLOC: BpfAllocator = BpfAllocator;

/// Number of allocations that are not freed yet.
pub fn live() -> i64 {
    unsafe { core::ptr::read_volatile(&raw const LIVE) }
}

/// Number of allocations made so far.
pub fn allocs() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const ALLOCS) }
}

// ---- panics

static mut PANIC_LINE: u32 = 0;
static mut PANICS: u32 = 0;

/// Number of panics so far.
pub fn panics() -> u32 {
    unsafe { core::ptr::read_volatile(&raw const PANICS) }
}

#[cfg(target_arch = "bpf")]
mod imp {
    use super::{PANIC_LINE, PANICS};
    use core::alloc::Layout;
    use core::mem::ManuallyDrop;
    use core::panic::PanicInfo;

    unsafe extern "C-unwind" {
        fn _Unwind_RaiseException(exception: *mut u8) -> i32;
    }

    #[panic_handler]
    fn panic(info: &PanicInfo) -> ! {
        unsafe {
            PANICS += 1;
            PANIC_LINE = match info.location() {
                Some(l) => l.line(),
                None => 0,
            };
        }
        // Also when it must not unwind: see ../add_ksyms.py.
        unsafe {
            _Unwind_RaiseException(core::ptr::null_mut());
            core::hint::unreachable_unchecked()
        }
    }

    #[alloc_error_handler]
    fn alloc_error(_layout: Layout) -> ! {
        // unwinds: what the program holds is released by Drop
        panic!("out of memory")
    }

    #[lang = "eh_personality"]
    extern "C" fn rust_eh_personality() {}

    union Try<F, R> {
        f: ManuallyDrop<F>,
        r: ManuallyDrop<R>,
    }

    fn do_call<F: FnOnce() -> R, R>(data: *mut u8) {
        unsafe {
            let data = &mut *(data as *mut Try<F, R>);
            let f = ManuallyDrop::take(&mut data.f);
            data.r = ManuallyDrop::new(f());
        }
    }

    fn do_catch(_data: *mut u8, _payload: *mut u8) {}

    pub fn catch<F: FnOnce() -> R, R>(f: F) -> Result<R, u32> {
        let mut data = Try { f: ManuallyDrop::new(f) };
        let p = &raw mut data as *mut u8;
        unsafe {
            if core::intrinsics::catch_unwind(do_call::<F, R>, p, do_catch) == 0 {
                Ok(ManuallyDrop::into_inner(data.r))
            } else {
                Err(core::ptr::read_volatile(&raw const PANIC_LINE))
            }
        }
    }
}

#[cfg(not(target_arch = "bpf"))]
mod imp {
    use super::{PANIC_LINE, PANICS};
    use std::boxed::Box;

    static HOOK: std::sync::Once = std::sync::Once::new();

    pub fn catch<F: FnOnce() -> R, R>(f: F) -> Result<R, u32> {
        HOOK.call_once(|| {
            std::panic::set_hook(Box::new(|info| unsafe {
                PANICS += 1;
                PANIC_LINE = match info.location() {
                    Some(l) => l.line(),
                    None => 0,
                };
            }))
        });
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| unsafe { PANIC_LINE })
    }
}

/// std::panic::catch_unwind() without std. Err is the line of the panic.
pub fn catch<F: FnOnce() -> R, R>(f: F) -> Result<R, u32> {
    imp::catch(f)
}

// ---- harness

pub const PANICKED: i32 = 100000;
pub const LEAKED: i32 = 200000;

/// What a test program returns:
///   0                the test passed
///   N < 100000       the check in line N failed
///   100000 + N       a panic in line N (of whatever file) was not expected
///   200000 + N       N allocations were not freed
#[inline(always)]
pub fn run<F: FnOnce() -> i32>(leaks: bool, f: F) -> i32 {
    #[cfg(not(target_arch = "bpf"))]
    let _ = catch(|| ()); // the hook is an allocation
    let before = live();
    match catch(f) {
        Err(line) => PANICKED + line as i32,
        Ok(0) if !leaks && live() != before => LEAKED + (live() - before) as i32,
        Ok(r) => r,
    }
}

/// test!(name, { body }): a program "name". The body uses check!().
#[macro_export]
macro_rules! test {
    ($name:ident, $body:block) => {
        $crate::test!(@ false, $name, $body);
    };
    (leaks $name:ident, $body:block) => {
        $crate::test!(@ true, $name, $body);
    };
    (@ $leaks:expr, $name:ident, $body:block) => {
        #[cfg_attr(target_arch = "bpf", unsafe(link_section = "syscall"))]
        #[unsafe(no_mangle)]
        pub extern "C-unwind" fn $name(_ctx: *mut u8) -> i32 {
            $crate::run($leaks, || -> i32 {
                $body;
                0
            })
        }
    };
}

/// The test fails with the number of this line unless the condition holds.
#[macro_export]
macro_rules! check {
    ($cond:expr) => {
        if !($cond) {
            return line!() as i32;
        }
    };
}

#[macro_export]
macro_rules! check_eq {
    ($a:expr, $b:expr) => {
        if $a != $b {
            return line!() as i32;
        }
    };
}

#[cfg(target_arch = "bpf")]
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
pub static _LICENSE: [u8; 4] = *b"GPL\0";

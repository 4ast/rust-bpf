// SPDX-License-Identifier: GPL-2.0
//! Multi-frame BPF unwinding, written in Rust.
//!
//! The compiler side of the feature is LLVM's "[BPF] Lower unwinding to a flag
//! in r3 and a branch": a function that can unwind says in r3 how it returns,
//! and its caller looks at r3 after the call.
//!
//!   ret                           r3 = 0; exit
//!   invoke f() unwind pad         call f; if r3 != 0 goto pad
//!   resume                        r0 = 0; r3 = 1; exit
//!   call _Unwind_RaiseException   r0 = 0; r3 = 1; exit
//!   invoke _Unwind_RaiseException r0 = 0; goto pad
//!
//! Landing pads are ordinary blocks reached by ordinary branches.  There are no
//! tables, and nothing for libbpf or the kernel to dispatch.  The functions that
//! follow the convention carry BTF decl_tag "unwind".  Rust Drop glue is what
//! produces the pads, which is what this program is.
//!
//! Call chain:
//!
//!   entry -> foo1 -> foo2 -> foo3
//!
//! foo3 and foo2 both hold resources acquired with kfuncs and both can panic.
//! Each of them therefore gets an `invoke` + `landingpad cleanup` that runs the
//! Drop impls (i.e. the "undo" kfunc calls) and then `resume`s.  The panic
//! handler starts the unwind with _Unwind_RaiseException(), and every frame
//! hands it to its caller:
//!
//!   frame foo3: re-enable preemption   (bpf_preempt_enable)
//!   frame foo2: leave the RCU section  (bpf_rcu_read_unlock), drop tracker
//!   frame foo1: nothing to clean up -> LLVM adds a pad that only resumes
//!   frame entry: likewise, so the program returns 0, with r3 = 1
//!
//! Neither _Unwind_RaiseException nor _Unwind_Resume reaches the object file.
//!
//! Two things are required to get this out of rustc:
//!
//!  1. panic=unwind, from -C panic=unwind plus panic-strategy=unwind in
//!     bpfel-unknown-none-v4.json.  Under panic=abort every landing pad is
//!     optimized away.  It also puts uwtable on every function, and LLVM only
//!     applies the convention to functions that have it.
//!  2. the "C-unwind" ABI on foo1/foo2/foo3/entry.  Plain extern "C" is
//!     nounwind in Rust: the foo2 -> foo3 call would get no unwind edge, and
//!     a panic would end in the abort-on-unwind shim
//!     (core::panicking::panic_cannot_unwind) instead of the pads.
//!
//! The guards deliberately use kfunc pairs that the verifier tracks itself,
//! bpf_rcu_read_lock/bpf_rcu_read_unlock and
//! bpf_preempt_disable/bpf_preempt_enable.  A way out of foo2 or foo3 that
//! misses the landing pad leaves the region unbalanced and the program does not
//! load at all.  On top of that each Drop sets its own bit in PADS_RAN, so the
//! value left in .bss names exactly the pads that ran.  Unwinding zeroes r0, so
//! a side effect like this is the only way to see a pad from user space.
//!
//! Every kfunc used here takes either no arguments or integers, because the
//! BTF prototypes in .ksyms are synthesised from the LLVM declaration and
//! libbpf checks them against the kernel's: a struct pointer argument would
//! need the real kernel type reconstructed to stay compatible.

#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(panic_can_unwind)]
#![allow(internal_features)]

use core::hint::black_box;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

// -- kfunc bindings --

unsafe extern "C-unwind" {
    /// Starts the unwind: landing pads only carry one on.  It is the Itanium
    /// ABI's name for that, the one std's panic runtime calls.  Not a kfunc: LLVM
    /// lowers the call.  By its prototype it comes back when it fails.  On BPF it
    /// cannot.
    fn _Unwind_RaiseException(exception: *mut u8) -> i32;
}

unsafe extern "C" {
    /// Aborts the program: no landing pad runs.
    fn bpf_throw(cookie: u64) -> !;
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_preempt_disable();
    fn bpf_preempt_enable();
}

/// Must match prog_tests/rust_exceptions.c.
pub const RAN_FOO3_PREEMPT: u64 = 0x1;
pub const RAN_FOO2_RCU: u64 = 0x2;
pub const RAN_FOO2_TRACKER: u64 = 0x4;

/// One bit per landing pad that ran, read back from .bss by the test.
#[unsafe(no_mangle)]
pub static mut PADS_RAN: u64 = 0;

/// The accesses are volatile because nothing in the program ever reads
/// PADS_RAN: a plain store to a variable that is written and never read is
/// dead, and the optimizer would drop the only evidence the pad left behind.
#[inline(always)]
fn pad_ran(bit: u64) {
    unsafe {
        let p = &raw mut PADS_RAN;
        write_volatile(p, read_volatile(p) | bit);
    }
}

// -- RAII guards --
//
// Every Drop here is the "undo" work that has to run while the panic unwinds
// through the frame that owns the guard.

/// Non-preemptible section; the verifier insists it is closed on every path.
struct PreemptGuard;

impl PreemptGuard {
    #[inline(never)]
    fn disable() -> PreemptGuard {
        unsafe { bpf_preempt_disable() };
        PreemptGuard
    }
}

impl Drop for PreemptGuard {
    fn drop(&mut self) {
        unsafe { bpf_preempt_enable() };
        pad_ran(RAN_FOO3_PREEMPT);
    }
}

/// RCU read-side critical section; likewise balanced by the verifier.
struct RcuGuard;

impl RcuGuard {
    #[inline(never)]
    fn lock() -> RcuGuard {
        unsafe { bpf_rcu_read_lock() };
        RcuGuard
    }
}

impl Drop for RcuGuard {
    fn drop(&mut self) {
        unsafe { bpf_rcu_read_unlock() };
        pad_ran(RAN_FOO2_RCU);
    }
}

/// A second thing for foo2 to own, so its landing pad has more than one Drop
/// to run.
struct Tracker;

impl Drop for Tracker {
    fn drop(&mut self) {
        pad_ran(RAN_FOO2_TRACKER);
    }
}

// -- level 3: innermost frame, disables preemption, panics while holding it --

/// Cleanup on the unwind path: bpf_preempt_enable().
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn foo3(val: u64) -> u64 {
    let _preempt = PreemptGuard::disable();

    // `_preempt` is live across this call, so rustc emits
    //     invoke @core::panicking::panic  to normal unwind %cleanup
    // and %cleanup runs PreemptGuard::drop before `resume`.
    if val > 100 {
        panic!("foo3: value out of range");
    }

    black_box(val) ^ 1
}

// -- level 2: holds two resources, unwinds both from foo3 and by itself --

/// Cleanup on the unwind path: bpf_rcu_read_unlock() plus Tracker's Drop.
/// This frame gets two invokes, both pointing at the same landing pad.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn foo2(val: u64) -> u64 {
    let _tracker = Tracker;
    let _rcu = RcuGuard::lock();

    // Invoke #1: the panic raised inside foo3 unwinds through here, so r3 is
    // looked at after the call.  The landing pad drops _rcu
    // (bpf_rcu_read_unlock) and _tracker, then resumes into foo1's frame.
    let r = foo3(val);

    // Invoke #2: foo2 panics by itself, still holding both resources -> same
    // cleanup work.  panic!() does not return, so this is a plain jump to the
    // pad with no look at r3.
    if r & 1 == 1 {
        panic!("foo2: odd result from foo3");
    }

    black_box(r).wrapping_add(1)
}

// -- level 1: no resources, no cleanup --
//
// rustc emits a plain call here.  It may unwind, so LLVM gives it a landing pad
// that only resumes.

#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn foo1(val: u64) -> u64 {
    foo2(val)
}

#[unsafe(link_section = "syscall")]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn entry(_ctx: *mut u8) -> i32 {
    foo1(black_box(101)) as i32
}

// -- unwinding runtime bits --

/// A Rust panic turns into a BPF unwind here.  One that cannot unwind aborts the
/// program instead.  Nothing in this program panics like that, so bpf_throw()
/// does not reach the object; scx_simple.rs has more on this.
#[panic_handler]
#[inline(always)]
fn panic(info: &PanicInfo) -> ! {
    if info.can_unwind() {
        unsafe { _Unwind_RaiseException(core::ptr::null_mut()) };
    }
    unsafe { bpf_throw(1) }
}

/// Referenced by every function with a landing pad; never actually called on
/// BPF, because the pads are reached with plain branches.  Stripped from the
/// final object by llvm-objcopy.
#[lang = "eh_personality"]
extern "C" fn rust_eh_personality() {}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static _LICENSE: [u8; 4] = *b"GPL\0";

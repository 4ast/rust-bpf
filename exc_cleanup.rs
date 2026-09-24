// SPDX-License-Identifier: GPL-2.0
//! Multi-frame BPF exception handling, written in Rust.
//!
//! The compiler side of the feature is the .bpf_cleanup section added in LLVM
//! 23 by 9d51c891b719 ("[BPF] Add exception handling support with
//! .bpf_cleanup section"): a flat array of (begin, end, landing_pad) triples,
//! one per `invoke` region, saying that a frame unwinding out of a call in
//! [begin, end) has to run landing_pad before it is popped.  Rust Drop glue is
//! what produces those regions today, which is what this program is: the C
//! counterpart, progs/exceptions_cleanup.c, has to spell the same thing out in
//! __naked assembly because C has no unwinding.
//!
//! Call chain:
//!
//!   entry -> foo1 -> foo2 -> foo3
//!
//! foo3 and foo2 both hold resources acquired with kfuncs and both can throw.
//! Each of them therefore gets an `invoke` + `landingpad cleanup` that runs the
//! Drop impls (i.e. the "undo" kfunc calls) and then `resume`s, which lowers to
//! `call _Unwind_Resume` - the kernel's bpf_unwind_resume kfunc, which libbpf
//! maps that name onto.  bpf_throw() walks the frames and dispatches each one's
//! pad:
//!
//!   frame foo3: re-enable preemption   (bpf_preempt_enable)
//!   frame foo2: leave the RCU section  (bpf_rcu_read_unlock), drop tracker
//!   frame foo1: no cleanup entry -> the frame is just popped
//!   frame entry: the exception boundary; the cookie becomes the retval
//!
//! Two things are required to get this out of rustc:
//!
//!  1. panic=unwind, from -C panic=unwind plus panic-strategy=unwind in
//!     bpfel-unknown-none-v4.json.  Under panic=abort every landing pad is
//!     optimized away.
//!  2. the "C-unwind" ABI on foo1/foo2/foo3/entry.  Plain extern "C" is
//!     nounwind in Rust: the foo2 -> foo3 call would get no unwind edge, and
//!     the abort-on-unwind shim (core::panicking::panic_cannot_unwind) emits
//!     a `landingpad filter`, which the BPF backend rejects with
//!     "BPF does not support exception filters yet".
//!
//! The guards deliberately use kfunc pairs that the verifier tracks itself,
//! bpf_rcu_read_lock/bpf_rcu_read_unlock and
//! bpf_preempt_disable/bpf_preempt_enable.  A landing pad that never ran, or
//! that the kernel failed to make reachable, leaves the region unbalanced and
//! the program does not load at all.  On top of that each Drop sets its own bit
//! in PADS_RAN, so the value left in .bss names exactly the pads that ran.  A
//! pad runs as a subroutine of bpf_throw() and the cookie it carries is
//! untouched, so a side effect like this is the only way to see a pad from user
//! space.
//!
//! Every kfunc used here takes either no arguments or integers, because the
//! BTF prototypes in .ksyms are synthesised from the LLVM declaration and
//! libbpf checks them against the kernel's: a struct pointer argument would
//! need the real kernel type reconstructed to stay compatible.

#![no_std]
#![no_main]
#![feature(lang_items)]
#![allow(internal_features)]

use core::hint::black_box;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

// -- kfunc bindings --

unsafe extern "C-unwind" {
    /// Raises a BPF exception carrying @cookie.  Every frame with a matching
    /// .bpf_cleanup entry runs its landing pad on the way out, and @cookie is
    /// what the program returns at the exception boundary.
    fn bpf_throw(cookie: u64) -> !;
}

unsafe extern "C" {
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_preempt_disable();
    fn bpf_preempt_enable();
}

/// Cookie the panic handler throws with.  Must match
/// prog_tests/rust_exceptions.c, and so must the bits below.
pub const THROW_COOKIE: u64 = 0x100;
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
// Every Drop here is the "undo" work that has to run while the exception
// unwinds through the frame that owns the guard.

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

// -- level 3: innermost frame, disables preemption, throws while holding it --

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

// -- level 2: holds two resources, throws both through foo3 and by itself --

/// Cleanup on the unwind path: bpf_rcu_read_unlock() plus Tracker's Drop.
/// This frame gets two invoke regions, both pointing at the same landing pad.
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C-unwind" fn foo2(val: u64) -> u64 {
    let _tracker = Tracker;
    let _rcu = RcuGuard::lock();

    // Region #1: the exception raised inside foo3 unwinds through here.
    // The landing pad drops _rcu (bpf_rcu_read_unlock) and _tracker, then
    // resumes into foo1's frame.
    let r = foo3(val);

    // Region #2: foo2 raises its own exception, still holding both
    // resources -> same cleanup work, second .bpf_cleanup entry.
    if r & 1 == 1 {
        panic!("foo2: odd result from foo3");
    }

    black_box(r).wrapping_add(1)
}

// -- level 1: no resources, no cleanup --
//
// No .bpf_cleanup entry is emitted for this frame, so the kernel just pops
// it and keeps unwinding.

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

/// A Rust panic turns into a BPF exception here.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { bpf_throw(THROW_COOKIE) }
}

/// Referenced by every function with a landing pad; never actually called on
/// BPF, because the kernel dispatches to the pads itself.  Stripped from the
/// final object by llvm-objcopy.
#[lang = "eh_personality"]
extern "C" fn rust_eh_personality() {}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static _LICENSE: [u8; 4] = *b"GPL\0";

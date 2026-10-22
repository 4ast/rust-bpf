// SPDX-License-Identifier: GPL-2.0
//! core::sync::atomic of every width.
#![no_std]
#![no_main]
use core::sync::atomic::Ordering::*;
use core::sync::atomic::*;
use rt::{bb, check, check_eq, test};

macro_rules! width {
    ($atomic:ident, $t:ty) => {{
            let a = $atomic::new(bb(5));
            check_eq!(a.load(Relaxed), 5);
            a.store(7, Release);
            check_eq!(a.load(Acquire), 7);
            check_eq!(a.swap(9, AcqRel), 7);
            check_eq!(a.fetch_add(3, SeqCst), 9);
            check_eq!(a.fetch_sub(2, Relaxed), 12);
            check_eq!(a.fetch_and(0b0110, SeqCst), 10);
            check_eq!(a.fetch_or(0b1001, SeqCst), 2);
            check_eq!(a.fetch_xor(0b0011, SeqCst), 11);
            check_eq!(a.load(SeqCst), 8);
            check_eq!(a.compare_exchange(8, 20, SeqCst, Relaxed), Ok(8));
            check_eq!(a.compare_exchange(8, 30, AcqRel, Acquire), Err(20));
            check_eq!(a.fetch_max(25, SeqCst), 20);
            check_eq!(a.fetch_min(3, SeqCst), 25);
            check_eq!(a.fetch_nand(1, SeqCst), 3);
            check_eq!(a.load(SeqCst), !1);
            a.store(<$t>::MAX, SeqCst);
            check_eq!(a.fetch_add(1, SeqCst), <$t>::MAX);
            check_eq!(a.load(SeqCst), <$t>::MIN);
            check_eq!(a.fetch_update(SeqCst, SeqCst, |v| Some(v.wrapping_add(4))), Ok(<$t>::MIN));
            check_eq!(a.into_inner(), <$t>::MIN.wrapping_add(4));
    }};
}

test!(atomic_u8, {
    width!(AtomicU8, u8);
});

test!(atomic_i8, {
    width!(AtomicI8, i8);
});

test!(atomic_u16, {
    width!(AtomicU16, u16);
});

test!(atomic_i16, {
    width!(AtomicI16, i16);
});

test!(atomic_u32, {
    width!(AtomicU32, u32);
});

test!(atomic_i32, {
    width!(AtomicI32, i32);
});

test!(atomic_u64, {
    width!(AtomicU64, u64);
});

test!(atomic_i64, {
    width!(AtomicI64, i64);
});

test!(atomic_usize, {
    width!(AtomicUsize, usize);
});


test!(atomic_neighbours, {
    // an operation on a byte leaves the bytes around it alone
    let a = [AtomicU8::new(bb(1)), AtomicU8::new(2), AtomicU8::new(3), AtomicU8::new(4), AtomicU8::new(5)];
    a[1].fetch_add(0xff, SeqCst);
    a[2].swap(0x80, SeqCst);
    check_eq!(a[3].compare_exchange(4, 0xff, SeqCst, SeqCst), Ok(4));
    let v: [u8; 5] = core::array::from_fn(|i| a[i].load(Relaxed));
    check_eq!(v, [1, 1, 0x80, 0xff, 5]);
    let h = [AtomicU16::new(bb(1)), AtomicU16::new(2), AtomicU16::new(3)];
    h[1].fetch_sub(3, SeqCst);
    check!(h[0].load(Relaxed) == 1 && h[1].load(Relaxed) == 0xffff && h[2].load(Relaxed) == 3);
});

test!(atomic_bool, {
    let b = AtomicBool::new(bb(false));
    check_eq!(b.swap(true, SeqCst), false);
    check_eq!(b.fetch_and(false, SeqCst), true);
    check_eq!(b.fetch_or(true, SeqCst), false);
    check_eq!(b.fetch_xor(true, SeqCst), true);
    check_eq!(b.fetch_nand(false, SeqCst), false);
    check_eq!(b.fetch_not(SeqCst), true);
    check_eq!(b.compare_exchange(false, true, SeqCst, SeqCst), Ok(false));
    check_eq!(b.compare_exchange_weak(false, true, SeqCst, SeqCst), Err(true));
    check!(b.load(SeqCst));
});

test!(atomic_ptr, {
    let mut x = bb([1u32, 2, 3]);
    let base = x.as_mut_ptr();
    let p = AtomicPtr::new(base);
    check_eq!(unsafe { *p.load(SeqCst) }, 1);
    let old = p.swap(unsafe { base.add(2) }, SeqCst);
    check!(old == base);
    check_eq!(unsafe { *p.load(SeqCst) }, 3);
    check!(p.compare_exchange(base, base, SeqCst, SeqCst).is_err());
    check!(p.compare_exchange(unsafe { base.add(2) }, unsafe { base.add(1) }, SeqCst, SeqCst).is_ok());
    check_eq!(unsafe { *p.load(SeqCst) }, 2);
    let n: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    check!(n.load(Relaxed).is_null());
});

static COUNTER: AtomicU64 = AtomicU64::new(100);
static FLAG: AtomicBool = AtomicBool::new(false);

test!(atomic_static_fence, {
    let before = COUNTER.fetch_add(bb(1), SeqCst);
    fence(SeqCst);
    compiler_fence(AcqRel);
    fence(Acquire);
    fence(Release);
    check_eq!(COUNTER.load(SeqCst), before + 1);
    FLAG.store(true, Release);
    check!(FLAG.load(Acquire));
    FLAG.store(false, Relaxed);
    core::hint::spin_loop();
});

test!(atomic_spin_lock, {
    let lock = AtomicBool::new(false);
    let mut data = bb(0u32);
    for _ in 0..bb(10) {
        while lock.compare_exchange_weak(false, true, Acquire, Relaxed).is_err() {
            core::hint::spin_loop();
        }
        data += 1;
        lock.store(false, Release);
    }
    check_eq!(data, 10);
});

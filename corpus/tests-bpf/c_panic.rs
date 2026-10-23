// SPDX-License-Identifier: GPL-2.0
//! Panics: where they come from, what they unwind through, who catches them.
#![no_std]
#![no_main]
use core::cell::RefCell;
use rt::{bb, catch, check, check_eq, test};

static mut LOG: [u8; 16] = [0; 16];
static mut LOG_N: usize = 0;

fn log(c: u8) {
    unsafe {
        if LOG_N < 16 {
            LOG[LOG_N] = c;
            LOG_N += 1;
        }
    }
}
fn log_reset() {
    unsafe { LOG_N = 0 };
}
#[allow(static_mut_refs)]
fn log_is(want: &[u8]) -> bool {
    unsafe { &LOG[..core::ptr::read_volatile(&raw const LOG_N)] == want }
}

struct D(u8);
impl Drop for D {
    #[inline(never)]
    fn drop(&mut self) {
        log(self.0);
    }
}

test!(panic_explicit, {
    check!(catch(|| if bb(true) { panic!() }).is_err());
    check!(catch(|| if bb(true) { panic!("with a message {}", bb(5)) }).is_err());
    check!(catch(|| if bb(false) { panic!() }).is_ok());
    check!(catch(|| if bb(true) { unreachable!() }).is_err());
    check!(catch(|| if bb(true) { todo!() }).is_err());
    check!(catch(|| if bb(true) { unimplemented!("x") }).is_err());
});

test!(panic_assert, {
    check!(catch(|| assert!(bb(1) == 2)).is_err());
    check!(catch(|| assert!(bb(1) == 1)).is_ok());
    check!(catch(|| assert_eq!(bb(1), 2)).is_err());
    check!(catch(|| assert_eq!(bb(1), 2, "text {}", 3)).is_err());
    check!(catch(|| assert_ne!(bb(1), 1)).is_err());
    check!(catch(|| assert_ne!(bb(1), 2)).is_ok());
});

test!(panic_unwrap_expect, {
    check!(catch(|| bb(None::<u8>).unwrap()).is_err());
    check!(catch(|| bb(None::<u8>).expect("nothing")).is_err());
    check!(catch(|| bb(Err::<u8, u8>(1)).unwrap()).is_err());
    check!(catch(|| bb(Err::<u8, &str>("e")).expect("failed")).is_err());
    check!(catch(|| bb(Ok::<u8, u8>(1)).unwrap_err()).is_err());
    check_eq!(catch(|| bb(Some(3u8)).unwrap()), Ok(3));
});

test!(panic_bounds, {
    let a = bb([1u8, 2, 3]);
    check!(catch(|| a[bb(3usize)]).is_err());
    check_eq!(catch(|| a[bb(2usize)]), Ok(3));
    check!(catch(|| a[bb(2usize)..bb(4usize)].len()).is_err());
    check!(catch(|| a[bb(2usize)..bb(1usize)].len()).is_err());
    check!(catch(|| a[bb(4usize)..].len()).is_err());
    check!(catch(|| a.split_at(bb(4)).0.len()).is_err());
    check!(catch(|| bb("héllo")[bb(2usize)..].len()).is_err());
    check!(catch(|| bb("abc")[..bb(4usize)].len()).is_err());
    let mut m = bb([0u8; 4]);
    check!(catch(|| m.copy_from_slice(bb(&[1u8, 2][..]))).is_err());
    check!(catch(|| a.chunks(bb(0)).count()).is_err());
});

test!(panic_arithmetic, {
    check!(catch(|| bb(1u32) / bb(0)).is_err());
    check!(catch(|| bb(1u64) % bb(0)).is_err());
    check!(catch(|| bb(i32::MIN) / bb(-1)).is_err());
    check!(catch(|| bb(i64::MIN) % bb(-1)).is_err());
    check!(catch(|| bb(1u128) / bb(0)).is_err());
    check!(catch(|| bb(0u32).ilog2()).is_err());
    check!(catch(|| bb(5u8).strict_add(bb(251))).is_err());
    check!(catch(|| bb(1i32).div_euclid(bb(0))).is_err());
    check_eq!(catch(|| bb(7u32) / bb(2)), Ok(3));
});

test!(panic_refcell, {
    let r = RefCell::new(bb(1));
    let b = r.borrow();
    check!(catch(|| *r.borrow_mut() = 2).is_err());
    drop(b);
    let m = r.borrow_mut();
    check!(catch(|| *r.borrow()).is_err());
    drop(m);
    check_eq!(catch(|| *r.borrow()), Ok(1));
});

#[inline(never)]
fn level3(p: bool) -> u32 {
    let _d = D(b'3');
    if p {
        panic!();
    }
    3
}
#[inline(never)]
fn level2(p: bool) -> u32 {
    let _a = D(b'a');
    let _b = D(b'b');
    level3(p) + 2
}
#[inline(never)]
fn level1(p: bool) -> u32 {
    let _d = D(b'1');
    let r = level2(p);
    log(b'+');
    r + 1
}

test!(panic_drop_order, {
    log_reset();
    check_eq!(catch(|| level1(bb(false))), Ok(6));
    check!(log_is(b"3ba+1"));
    log_reset();
    check!(catch(|| level1(bb(true))).is_err());
    check!(log_is(b"3ba1"));
});

test!(panic_nested_catch, {
    log_reset();
    let r = catch(|| {
        let _o = D(b'o');
        let inner = catch(|| {
            let _i = D(b'i');
            level3(bb(true))
        });
        log(if inner.is_err() { b'E' } else { b'K' });
        if bb(true) {
            panic!();
        }
        1
    });
    check!(r.is_err());
    check!(log_is(b"3iEo"));
});

test!(panic_repeated, {
    let n = rt::panics();
    let mut caught = 0;
    for i in 0..bb(8u32) {
        if catch(|| if i % 2 == 0 { panic!() }).is_err() {
            caught += 1;
        }
    }
    check_eq!(caught, 4);
    check_eq!(rt::panics(), n + 4);
});

test!(panic_line, {
    let e = catch(|| if bb(true) { panic!() }).unwrap_err();
    check_eq!(e, line!() - 1);
});

test!(panic_in_closure_and_iter, {
    let d = bb([1u32, 2, 0, 4]);
    check!(catch(|| d.iter().map(|x| 8 / x).sum::<u32>()).is_err());
    check_eq!(catch(|| d.iter().filter(|x| **x != 0).map(|x| 8 / x).sum::<u32>()), Ok(14));
    log_reset();
    let r = catch(|| {
        for (i, x) in d.iter().enumerate() {
            let _g = D(b'0' + i as u8);
            let _ = 8 / x;
        }
    });
    check!(r.is_err());
    check!(log_is(b"012"));
});

trait Risky {
    fn go(&self, v: u32) -> u32;
}
struct Div;
impl Risky for Div {
    fn go(&self, v: u32) -> u32 {
        let _d = D(b'd');
        100 / v
    }
}

test!(panic_through_dyn, {
    log_reset();
    let r: &dyn Risky = bb(&Div);
    check_eq!(catch(|| r.go(bb(5))), Ok(20));
    check!(catch(|| r.go(bb(0))).is_err());
    check!(log_is(b"dd"));
});

test!(panic_moved_values, {
    log_reset();
    let r = catch(|| {
        let a = D(b'a');
        let b = D(b'b');
        drop(a);
        let c = b;
        if bb(true) {
            panic!();
        }
        drop(c);
    });
    check!(r.is_err());
    check!(log_is(b"ab"));
});

test!(panic_partial_array, {
    log_reset();
    let r = catch(|| {
        let arr: [D; 4] = core::array::from_fn(|i| {
            if i == bb(2) {
                panic!();
            }
            D(b'0' + i as u8)
        });
        arr.len()
    });
    check!(r.is_err());
    check!(log_is(b"01"));
});

// Not caught by the test: the harness reports it.
test!(panic_uncaught, {
    let _d = D(b'x');
    check!(bb([1u8])[bb(1usize)] == 0);
});

// The heap has 8 Mbyte. Running out of memory is a panic that unwinds. With std it aborts the process.
test!(panic_out_of_memory, {
    extern crate alloc;
    use alloc::vec::Vec;
    let mut v: Vec<u8> = Vec::new();
    check!(v.try_reserve(bb(64 << 20)).is_err());
    #[cfg(target_arch = "bpf")]
    {
        log_reset();
        let r = catch(|| {
            let _d = D(b'm');
            bb(Vec::<u8>::with_capacity(bb(64 << 20))).capacity()
        });
        check!(r.is_err());
        check!(log_is(b"m"));
    }
});

// What follows aborts the process with std. A BPF program cannot just stop: what
// it holds has to be released. So an abort unwinds, and it can be caught. The
// frames that have a landing pad for the call run their Drop impls.

// A Drop that runs in a landing pad panics.
#[cfg(target_arch = "bpf")]
struct PanicsInDrop;
#[cfg(target_arch = "bpf")]
impl Drop for PanicsInDrop {
    fn drop(&mut self) {
        if bb(true) {
            panic!("in drop");
        }
    }
}

#[cfg(target_arch = "bpf")]
#[inline(never)]
fn panics_twice() {
    let _p = PanicsInDrop;
    if bb(true) {
        panic!("first");
    }
}

test!(abort_panic_in_cleanup, {
    #[cfg(target_arch = "bpf")]
    {
        log_reset();
        let before = rt::panics();
        let r = catch(|| {
            let _d = D(b'o');
            panics_twice();
        });
        check!(r.is_err());
        check_eq!(rt::panics() - before, 2);
        check!(log_is(b"o"));
    }
});

// abort() in functions that have nothing else in them that unwinds.
#[cfg(target_arch = "bpf")]
#[inline(never)]
fn aborts_at_7(x: u32) -> u32 {
    if bb(x) == 7 {
        rt::abort();
    }
    x + 1
}

#[cfg(target_arch = "bpf")]
#[inline(never)]
fn calls_it_twice(x: u32) -> u32 {
    aborts_at_7(x) + aborts_at_7(x + 1)
}

test!(abort_in_a_leaf, {
    #[cfg(target_arch = "bpf")]
    {
        check!(catch(|| calls_it_twice(bb(1))) == Ok(5));
        check!(catch(|| calls_it_twice(bb(6))).is_err());
        check!(catch(|| calls_it_twice(bb(7))).is_err());
        check!(catch(|| calls_it_twice(bb(8))) == Ok(19));
    }
});

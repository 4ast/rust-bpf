// SPDX-License-Identifier: GPL-2.0
//! The harness itself: what a pass, a failed check, a panic and a leak look like.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use rt::{bb, check, check_eq, test};

test!(smoke_pass, {
    let v: Vec<u64> = (0..bb(10u64)).collect();
    check_eq!(v.iter().sum::<u64>(), 45);
});

// Fails.
test!(smoke_fail, {
    check!(bb(1) == 2);
});

// Panics.
test!(smoke_panic, {
    let v: Vec<u64> = (0..bb(10u64)).collect();
    check!(v[bb(10usize)] == 0);
});

// Leaks.
test!(smoke_leak, {
    core::mem::forget(bb(Box::new(1u64)));
});

test!(leaks smoke_leak_allowed, {
    core::mem::forget(bb(Box::new(1u64)));
});

test!(smoke_catch, {
    let n = rt::panics();
    let r = rt::catch(|| {
        let b = Box::new(bb(5u64));
        if *b == 5 {
            panic!();
        }
        *b
    });
    check!(r.is_err());
    check_eq!(rt::panics(), n + 1);
    check_eq!(rt::catch(|| bb(7)), Ok(7));
});

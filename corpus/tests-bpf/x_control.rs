// SPDX-License-Identifier: GPL-2.0
//! Negative controls: what the other tests compute, compared with a value that
//! is off by a bit. Every program has to fail in its last check. One that passes
//! means that checks of that kind don't check anything.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};
use rt::{bb, check, check_eq, test};
use sha2::Digest;

test!(ctl_u128_div, {
    check_eq!(bb(10u128.pow(30)) / bb(10u128.pow(15)), 10u128.pow(15));
    check_eq!(bb(10u128.pow(30)) / bb(10u128.pow(15)), 10u128.pow(15) + 1);
});

test!(ctl_iter, {
    check_eq!((1..=bb(100u64)).sum::<u64>(), 5050);
    check_eq!((1..=bb(100u64)).sum::<u64>(), 5051);
});

test!(ctl_str, {
    check_eq!(bb("the quick brown fox").find("brown"), Some(10));
    check_eq!(bb("the quick brown fox").find("brown"), Some(11));
});

test!(ctl_fmt, {
    check_eq!(format!("{:>5}|{:#x}", bb(42), bb(255)), "   42|0xff");
    check_eq!(format!("{:>5}|{:#x}", bb(42), bb(255)), "   42|0xfe");
});

test!(ctl_atomic, {
    let a = AtomicU8::new(bb(250));
    check_eq!(a.fetch_add(10, Ordering::SeqCst), 250);
    check_eq!(a.load(Ordering::SeqCst), 5);
});

test!(ctl_float, {
    check_eq!(bb(0.1f64) + bb(0.2), 0.30000000000000004);
    check_eq!(bb(0.1f64) + bb(0.2), 0.3);
});

test!(ctl_vec, {
    let v: Vec<u64> = (0..bb(100u64)).map(|i| i * i).collect();
    check_eq!(v.iter().sum::<u64>(), 328350);
    check_eq!(v.iter().sum::<u64>(), 328351);
});

test!(ctl_btree, {
    let mut m = BTreeMap::new();
    for i in 0..bb(50u32) {
        m.insert(i * 7 % 53, i);
    }
    check_eq!(m.range(10..20).count(), 10);
    check_eq!(m.range(10..20).count(), 9);
});

test!(ctl_drop, {
    let live = rt::live();
    let v = bb(alloc::vec![1u8, 2, 3]);
    check_eq!(rt::live(), live + 1);
    drop(v);
    check_eq!(rt::live(), live + 1);
});

test!(ctl_catch, {
    check!(rt::catch(|| bb([1u8, 2])[bb(2usize)]).is_err());
    check!(rt::catch(|| bb([1u8, 2])[bb(2usize)]).is_ok());
});

test!(ctl_sha256, {
    let d = sha2::Sha256::digest(bb(b"abc"));
    check_eq!(d[0], 0xba);
    check_eq!(d[31], 0xac);
});

test!(ctl_hashmap, {
    let mut m = hashbrown::HashMap::with_hasher(fnv::FnvBuildHasher::default());
    for i in 0..bb(20u32) {
        m.insert(i, i * 2);
    }
    check_eq!(m.get(&7), Some(&14));
    check_eq!(m.get(&7), Some(&15));
});

test!(ctl_serde, {
    check_eq!(postcard::to_allocvec(&bb(300u32)).unwrap(), [0xac, 0x02]);
    check_eq!(postcard::to_allocvec(&bb(300u32)).unwrap(), [0xac, 0x03]);
});

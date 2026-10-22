// SPDX-License-Identifier: GPL-2.0
//! crates: spin, once_cell, scopeguard, static_assertions
#![no_std]
#![no_main]
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use rt::{bb, check, check_eq, test};

static COUNTER: spin::Mutex<u64> = spin::Mutex::new(0);
static TABLE: spin::Lazy<[u32; 8]> = spin::Lazy::new(|| core::array::from_fn(|i| (i * i) as u32));
static INIT: spin::Once<u32> = spin::Once::new();

test!(spin_mutex, {
    let m = spin::Mutex::new(bb(5));
    {
        let mut g = m.lock();
        *g += 1;
        check!(m.try_lock().is_none());
        check!(m.is_locked());
    }
    check!(!m.is_locked());
    check_eq!(*m.lock(), 6);
    check_eq!(m.try_lock().map(|g| *g), Some(6));
    check_eq!(m.into_inner(), 6);
    let before = *COUNTER.lock();
    for _ in 0..bb(10) {
        *COUNTER.lock() += 1;
    }
    check_eq!(*COUNTER.lock(), before + 10);
    let shared = Arc::new(spin::Mutex::new(Vec::new()));
    let other = Arc::clone(&shared);
    shared.lock().push(bb(1));
    other.lock().push(2);
    check_eq!(*shared.lock(), [1, 2]);
});

test!(spin_mutex_unlocks_on_panic, {
    let m = spin::Mutex::new(bb(0));
    let r = rt::catch(|| {
        let mut g = m.lock();
        *g = 1;
        if bb(true) {
            panic!();
        }
    });
    check!(r.is_err());
    check_eq!(m.try_lock().map(|g| *g), Some(1));
});

test!(spin_rwlock, {
    let l = spin::RwLock::new(bb(1));
    {
        let a = l.read();
        let b = l.read();
        check_eq!(*a + *b, 2);
        check_eq!(l.reader_count(), 2);
        check!(l.try_write().is_none());
    }
    {
        let mut w = l.write();
        *w = 10;
        check!(l.try_read().is_none());
        let r = w.downgrade();
        check_eq!(*r, 10);
        check!(l.try_read().is_some());
    }
    {
        let u = l.upgradeable_read();
        check!(l.try_upgradeable_read().is_none());
        let mut w = u.upgrade();
        *w += 1;
    }
    check_eq!(l.into_inner(), 11);
});

test!(spin_once_lazy, {
    check_eq!(TABLE[bb(7)], 49);
    check_eq!(TABLE.iter().sum::<u32>(), 140);
    let a = *INIT.call_once(|| bb(5));
    let b = *INIT.call_once(|| 6);
    check!(a == 5 && b == 5);
    check_eq!(INIT.get(), Some(&5));
    check!(INIT.is_completed());
    let calls = Cell::new(0);
    let l = spin::Lazy::new(|| {
        calls.set(calls.get() + 1);
        bb(3)
    });
    check_eq!(calls.get(), 0);
    check_eq!(*l + *l, 6);
    check_eq!(calls.get(), 1);
    let o: spin::Once<String> = spin::Once::new();
    check!(o.get().is_none());
    check_eq!(o.call_once(|| String::from("x")).len(), 1);
});

test!(once_cell_unsync, {
    use once_cell::unsync::{Lazy, OnceCell};
    let c: OnceCell<String> = OnceCell::new();
    check!(c.get().is_none());
    check_eq!(c.get_or_init(|| String::from(bb("first"))), "first");
    check_eq!(c.get_or_init(|| String::from("second")), "first");
    check!(c.set(String::from("third")).is_err());
    check_eq!(c.into_inner().as_deref(), Some("first"));
    let e: OnceCell<u32> = OnceCell::new();
    check_eq!(e.get_or_try_init(|| Err::<u32, u8>(bb(1))), Err(1));
    check_eq!(e.get_or_try_init(|| Ok::<u32, u8>(2)), Ok(&2));
    let n = Cell::new(0);
    let l = Lazy::new(|| {
        n.set(n.get() + 1);
        alloc::vec![bb(1), 2, 3]
    });
    check_eq!(l.len() + l.len(), 6);
    check_eq!(n.get(), 1);
});

test!(once_cell_race, {
    use core::num::NonZeroUsize;
    use once_cell::race::{OnceBool, OnceBox, OnceNonZeroUsize};
    let b: OnceBox<String> = OnceBox::new();
    check!(b.get().is_none());
    check_eq!(b.get_or_init(|| Box::new(String::from(bb("boxed")))), "boxed");
    check!(b.set(Box::new(String::from("again"))).is_err());
    let n = OnceNonZeroUsize::new();
    check_eq!(n.get_or_init(|| NonZeroUsize::new(bb(7)).unwrap()).get(), 7);
    check!(n.set(NonZeroUsize::new(8).unwrap()).is_err());
    let f = OnceBool::new();
    check_eq!(f.get(), None);
    check_eq!(f.get_or_init(|| bb(true)), true);
    check_eq!(f.get_or_init(|| false), true);
});

test!(scopeguard_defer, {
    let log = Cell::new(0u32);
    {
        scopeguard::defer! { log.set(log.get() * 10 + 1); }
        scopeguard::defer! { log.set(log.get() * 10 + 2); }
        log.set(log.get() * 10 + 3);
    }
    check_eq!(log.get(), 321);
    let mut v = scopeguard::guard(alloc::vec![bb(1)], |v| log.set(v.len() as u32));
    v.push(2);
    v.push(3);
    drop(v);
    check_eq!(log.get(), 3);
    let g = scopeguard::guard(bb(5), |_| log.set(99));
    check_eq!(scopeguard::ScopeGuard::into_inner(g), 5);
    check_eq!(log.get(), 3);
});

test!(scopeguard_on_unwind, {
    let log = Cell::new(0u32);
    let r = rt::catch(|| {
        let _a = scopeguard::guard((), |_| log.set(log.get() + 1));
        if bb(true) {
            panic!();
        }
    });
    check!(r.is_err());
    check_eq!(log.get(), 1);
});

static_assertions::const_assert!(core::mem::size_of::<u64>() == 8);
static_assertions::const_assert_eq!(1 << 4, 16);
static_assertions::assert_eq_size!(u32, [u8; 4]);
static_assertions::assert_eq_align!(u64, usize);
static_assertions::assert_impl_all!(u32: Copy, Send, Sync);
static_assertions::assert_not_impl_any!(Cell<u8>: Sync);
static_assertions::assert_type_eq_all!(usize, usize);
static_assertions::assert_obj_safe!(core::fmt::Debug);

test!(static_assertions_compile, {
    static_assertions::const_assert!(usize::BITS == 64);
    check_eq!(bb(1), 1);
});

// SPDX-License-Identifier: GPL-2.0
//! async/await: futures are state machines that the compiler makes. The executor is here.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::{Pin, pin};
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use rt::{bb, check, check_eq, test};

fn block_on<F: Future>(f: F) -> (F::Output, u32) {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    let mut polls = 0;
    loop {
        polls += 1;
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return (v, polls);
        }
    }
}

/// Pending that many times
struct Yield(u32);
impl Future for Yield {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 == 0 {
            return Poll::Ready(());
        }
        self.0 -= 1;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

async fn add(a: u32, b: u32) -> u32 {
    a + b
}
async fn slow_add(a: u32, b: u32) -> u32 {
    Yield(2).await;
    a + b
}
async fn chain(n: u32) -> u32 {
    let x = add(n, 1).await;
    let y = slow_add(x, 10).await;
    let z = slow_add(y, 100).await;
    x + y + z
}

test!(async_basic, {
    check_eq!(block_on(add(bb(1), 2)), (3, 1));
    check_eq!(block_on(slow_add(bb(1), 2)), (3, 3));
    check_eq!(block_on(chain(bb(0))), (1 + 11 + 111, 5));
    check_eq!(block_on(async { bb(7) }).0, 7);
    check_eq!(block_on(core::future::ready(bb(8))).0, 8);
});

async fn sum_loop(n: u32) -> u32 {
    let mut s = 0;
    for i in 0..n {
        if i % 3 == 0 {
            Yield(1).await;
        }
        s += add(i, 0).await;
    }
    s
}
async fn borrows(v: &mut [u32]) -> u32 {
    for x in v.iter_mut() {
        Yield(1).await;
        *x *= 2;
    }
    v.iter().sum()
}

test!(async_state_across_await, {
    check_eq!(block_on(sum_loop(bb(10))), (45, 5));
    let mut v = bb([1, 2, 3]);
    check_eq!(block_on(borrows(&mut v)), (12, 4));
    check_eq!(v, [2, 4, 6]);
});

static mut DROPS: u32 = 0;
struct D;
impl Drop for D {
    fn drop(&mut self) {
        unsafe { DROPS += 1 };
    }
}
fn drops() -> u32 {
    unsafe { core::ptr::read_volatile(&raw const DROPS) }
}
async fn holds() -> u32 {
    let _d = D;
    Yield(5).await;
    1
}

test!(async_drop_cancelled, {
    let d = drops();
    {
        let mut f = pin!(holds());
        let mut cx = Context::from_waker(Waker::noop());
        check!(f.as_mut().poll(&mut cx).is_pending());
        check_eq!(drops(), d);
    }
    check_eq!(drops(), d + 1);
    drop(holds());
    check_eq!(drops(), d + 1);
    check_eq!(block_on(holds()).0, 1);
    check_eq!(drops(), d + 2);
});

fn boxed(n: u32) -> Pin<Box<dyn Future<Output = u32>>> {
    Box::pin(async move { if n == 0 { 0 } else { n + boxed(n - 1).await } })
}

test!(async_boxed_recursion, {
    check_eq!(block_on(boxed(bb(6))).0, 21);
    let fs: Vec<Pin<Box<dyn Future<Output = u32>>>> = alloc::vec![Box::pin(add(bb(1), 1)), Box::pin(slow_add(2, 2)), Box::pin(async { 6 })];
    let mut s = 0;
    for f in fs {
        s += block_on(f).0;
    }
    check_eq!(s, 12);
});

struct Counter(AtomicU32);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

test!(async_arc_waker, {
    let c = Arc::new(Counter(AtomicU32::new(0)));
    let w = Waker::from(Arc::clone(&c));
    let mut cx = Context::from_waker(&w);
    let mut f = pin!(slow_add(bb(1), 2));
    check!(f.as_mut().poll(&mut cx).is_pending());
    check!(f.as_mut().poll(&mut cx).is_pending());
    check_eq!(f.as_mut().poll(&mut cx), Poll::Ready(3));
    check_eq!(c.0.load(Ordering::SeqCst), 2);
    let w2 = w.clone();
    check!(w.will_wake(&w2));
    w2.wake();
    check_eq!(c.0.load(Ordering::SeqCst), 3);
    check_eq!(Arc::strong_count(&c), 2);
});

static WOKEN: AtomicU32 = AtomicU32::new(0);
fn raw() -> RawWaker {
    fn clone(_: *const ()) -> RawWaker {
        raw()
    }
    fn wake(_: *const ()) {
        WOKEN.fetch_add(1, Ordering::SeqCst);
    }
    fn noop(_: *const ()) {}
    static VT: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, noop);
    RawWaker::new(core::ptr::null(), &VT)
}

test!(async_raw_waker, {
    let before = WOKEN.load(Ordering::SeqCst);
    let w = unsafe { Waker::from_raw(raw()) };
    let mut cx = Context::from_waker(&w);
    let mut f = pin!(Yield(bb(3)));
    let mut n = 0;
    while f.as_mut().poll(&mut cx).is_pending() {
        n += 1;
    }
    check_eq!(n, 3);
    check_eq!(WOKEN.load(Ordering::SeqCst), before + 3);
});

type Task = Pin<Box<dyn Future<Output = ()>>>;

test!(async_round_robin_executor, {
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut q: VecDeque<Task> = VecDeque::new();
    for id in 0..bb(3u32) {
        let log = Rc::clone(&log);
        q.push_back(Box::pin(async move {
            for step in 0..=id {
                log.borrow_mut().push(id * 10 + step);
                Yield(1).await;
            }
        }));
    }
    let mut cx = Context::from_waker(Waker::noop());
    while let Some(mut t) = q.pop_front() {
        if t.as_mut().poll(&mut cx).is_pending() {
            q.push_back(t);
        }
    }
    check_eq!(*log.borrow(), [0, 10, 20, 11, 21, 22]);
});

struct Chan<T>(RefCell<VecDeque<T>>);
impl<T> Chan<T> {
    fn send(&self, v: T) {
        self.0.borrow_mut().push_back(v);
    }
    fn recv(&self) -> impl Future<Output = T> + '_ {
        core::future::poll_fn(move |_| match self.0.borrow_mut().pop_front() {
            Some(v) => Poll::Ready(v),
            None => Poll::Pending,
        })
    }
}

test!(async_channel_join, {
    let ch = Chan(RefCell::new(VecDeque::new()));
    let got = Cell::new(0u32);
    let mut producer = pin!(async {
        for i in 1..=bb(4u32) {
            Yield(1).await;
            ch.send(i);
        }
    });
    let mut consumer = pin!(async {
        for _ in 0..4 {
            got.set(got.get() * 10 + ch.recv().await);
        }
    });
    let mut cx = Context::from_waker(Waker::noop());
    let (mut p, mut c) = (false, false);
    while !(p && c) {
        p = p || producer.as_mut().poll(&mut cx).is_ready();
        c = c || consumer.as_mut().poll(&mut cx).is_ready();
    }
    check_eq!(got.get(), 1234);
});

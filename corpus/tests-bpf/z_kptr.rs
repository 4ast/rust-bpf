// SPDX-License-Identifier: GPL-2.0
//! Pointers of the kernel that go through memory.
//!
//! A pointer that the kernel gave to the program is a pointer for the verifier
//! while it is in a register or in the stack of the program. In arena it is
//! a number. use_task() passes it to a kfunc that takes nothing but a task.
#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
extern crate alloc;
use alloc::boxed::Box;
use rt::{bb, check, check_eq, test};

#[repr(C)]
pub struct task_struct {
    _p: [u8; 0],
}
#[derive(Clone, Copy)]
pub struct Task(*mut task_struct);

#[cfg(target_arch = "bpf")]
mod k {
    use super::task_struct;
    unsafe extern "C" {
        pub fn bpf_task_acquire(p: *mut task_struct) -> *mut task_struct;
        pub fn bpf_task_release(p: *mut task_struct);
    }
    pub fn current() -> *mut task_struct {
        let f: extern "C" fn() -> *mut task_struct = unsafe { core::mem::transmute(158usize) };
        f()
    }
}
#[cfg(not(target_arch = "bpf"))]
mod k {
    use super::task_struct;
    pub unsafe fn bpf_task_acquire(p: *mut task_struct) -> *mut task_struct {
        p
    }
    pub unsafe fn bpf_task_release(_p: *mut task_struct) {}
    pub fn current() -> *mut task_struct {
        8 as *mut task_struct
    }
}

impl Task {
    fn current() -> Task {
        Task(k::current())
    }
    /// 1 if the kernel takes it for a task
    #[inline(always)]
    fn use_task(self) -> u32 {
        unsafe {
            let a = k::bpf_task_acquire(self.0);
            if a.is_null() {
                return 0;
            }
            k::bpf_task_release(a);
        }
        1
    }
}

// In registers all the way: works.
#[inline(never)]
fn by_value(t: Task, n: u32) -> u32 {
    t.use_task() + n
}
test!(kptr_by_value, {
    check_eq!(by_value(Task::current(), bb(1)), 2);
});

// Three and more fields in use: LLVM doesn't turn the reference into arguments.
struct Ctx {
    n: u32,
    x: u32,
    task: Task,
    m: u64,
}

// A: a struct by reference, direct call
#[inline(never)]
fn by_ref(c: &Ctx) -> u32 {
    c.task.use_task() + c.n + c.x + c.m as u32
}
test!(kptr_struct_by_ref, {
    let c = Ctx { n: bb(1), x: bb(0), task: Task::current(), m: bb(2) };
    check_eq!(by_ref(&c), 4);
});

// B: a closure that captures by reference, run by a function that is not inlined
#[inline(never)]
fn run<F: FnOnce(u32) -> u32>(f: F) -> u32 {
    f(bb(10))
}
test!(kptr_closure_by_ref, {
    let t = Task::current();
    let mut calls = bb(0u32);
    let (a, b) = (bb(1u32), bb(2u64));
    let r = run(|x| {
        calls += 1;
        t.use_task() + x + a + b as u32
    });
    check_eq!(r, 14);
    check_eq!(calls, 1);
});

// C: the same through a trait object: an indirect call
#[inline(never)]
fn run_dyn(f: &dyn Fn(u32) -> u32) -> u32 {
    f(bb(10))
}
test!(kptr_closure_dyn, {
    let t = Task::current();
    let (a, b) = (bb(1u32), bb(2u64));
    let with_task = |x: u32| t.use_task() + x + a + b as u32;
    let other = |x: u32| x + a;
    check_eq!(run_dyn(&with_task), 14);
    check_eq!(run_dyn(&other), 11);
});

// D: one function, a struct in the stack and a struct in the heap
#[inline(never)]
fn count(c: &Ctx) -> u32 {
    c.n + c.x + c.m as u32
}
test!(kptr_same_callee_stack_and_heap, {
    let c = Ctx { n: bb(1), x: bb(0), task: Task::current(), m: bb(2) };
    let h = Box::new(Ctx { n: bb(10), x: bb(0), task: Task(core::ptr::null_mut()), m: bb(20) });
    check_eq!(count(&c) + count(&h), 33);
    check_eq!(by_ref(&c), 4);
});

// E: returned through a hidden pointer
#[inline(never)]
fn make(n: u32) -> Ctx {
    Ctx { n, x: 0, task: Task::current(), m: n as u64 * 2 }
}
test!(kptr_returned_in_struct, {
    let c = make(bb(1));
    check_eq!(by_ref(&c), 4);
});

// F: an array with an index that is not a constant
#[inline(never)]
fn pick(ts: &[Task; 4], i: usize) -> u32 {
    ts[i & 3].use_task()
}
test!(kptr_array_variable_index, {
    let ts = [Task::current(); 4];
    check_eq!(pick(&ts, bb(2)), 1);
});

// G: Option in a local, by mutable reference
#[inline(never)]
fn fill(slot: &mut Option<Task>) {
    *slot = Some(Task::current());
}
test!(kptr_option_out_param, {
    let mut s = None;
    fill(&mut s);
    check!(s.is_some_and(|t| t.use_task() == 1));
});

// I: a method that is called through a vtable, for an object in the stack and for one in the heap
trait Named {
    fn score(&self) -> u32;
}
impl Named for Ctx {
    fn score(&self) -> u32 {
        (if self.task.0.is_null() { 0 } else { self.task.use_task() }) + self.n + self.x + self.m as u32
    }
}
struct Other(u32);
impl Named for Other {
    fn score(&self) -> u32 {
        self.0
    }
}
#[inline(never)]
fn score_of(n: &dyn Named) -> u32 {
    n.score()
}
test!(kptr_dyn_method_stack_and_heap, {
    let c = Ctx { n: bb(1), x: bb(0), task: Task::current(), m: bb(2) };
    let h: Box<dyn Named> = Box::new(Ctx { n: bb(10), x: bb(0), task: Task(core::ptr::null_mut()), m: bb(20) });
    let o = Other(bb(5));
    check_eq!(score_of(&c) + score_of(&*h) + score_of(&o), 4 + 30 + 5);
});

// H: in the heap. Arena cannot hold it.
test!(kptr_in_box, {
    let b = bb(Box::new(Ctx { n: 1, x: 0, task: Task::current(), m: 2 }));
    check_eq!(b.task.use_task(), 1);
});

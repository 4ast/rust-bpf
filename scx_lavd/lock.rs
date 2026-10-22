// SPDX-License-Identifier: GPL-2.0
//
// lock.bpf.c: a task that holds a futex is not preempted and goes on when its
// slice is over, so that the ones that wait for the lock get it soon.
// Copyright (c) 2024 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>
//
// The kernel does not know who holds a futex: that is decided in user space.
// What can be seen is who comes back from waiting for one (it has the lock now)
// and who wakes up others (it has let go). There are two ways to see it, user
// space picks one: fexit programs on the functions of the kernel, or, where
// these cannot be traced, the tracepoints of the system calls.

use crate::*;

bpf_helper!(fn bpf_get_func_ret(ctx: *const u64, value: *mut u64) -> i64 = 184);

/// The current task and its CPU, unless the task is none of ours.
fn current_ctx() -> Option<(&'static mut TaskCtx, &'static CpuCtx)> {
    let p = Task::current();
    if p.is_rt_or_dl() {
        return None;
    }
    Some((TASK_CTXS.get_irqs_on(p)?, get_cpu_ctx()?))
}

fn inc_futex_boost() {
    if let Some((taskc, cpuc)) = current_ctx() {
        taskc.flags.insert(TaskFlags::FUTEX_BOOST);
        cpuc.flags.set(taskc.flags.0);
    }
}

fn dec_futex_boost() {
    if let Some((taskc, cpuc)) = current_ctx().filter(|(taskc, _)| taskc.is_lock_holder()) {
        taskc.flags.remove(TaskFlags::FUTEX_BOOST);
        cpuc.flags.set(taskc.flags.0);
    }
}

impl TaskCtx {
    pub fn is_lock_holder(&self) -> bool { self.flags.contains(TaskFlags::FUTEX_BOOST) }

    /// The boost is good for one time slice. It leaves a bonus for the next
    /// deadline behind.
    pub fn reset_lock_futex_boost(&mut self, cpuc: &CpuCtx) {
        if self.is_lock_holder() {
            self.flags.insert(TaskFlags::NEED_LOCK_BOOST);
        }
        self.flags.remove(TaskFlags::FUTEX_BOOST);
        cpuc.flags.set(self.flags.0);
    }
}

// ── fexit ────────────────────────────────────────────────────────────

/// `name: "function of the kernel", what its return value has to be => what
/// that means`
macro_rules! futex_fexit {
    ($($name:ident: $func:literal, $ok:expr => $action:ident;)*) => { $(
        #[link_section = concat!("?fexit/", $func)]
        #[no_mangle]
        extern "C" fn $name(ctx: *const u64) -> i32 {
            let mut retval = 0u64;
            unsafe { bpf_get_func_ret(ctx, &mut retval) };
            let ok: fn(i32) -> bool = $ok;
            if ok(retval as i32) {
                $action();
            }
            0
        }
    )* };
}

futex_fexit! {
    lavd_fexit___futex_wait: "__futex_wait", |ret| ret == 0 => inc_futex_boost;
    lavd_fexit_futex_wait_multiple: "futex_wait_multiple", |ret| ret == 0 => inc_futex_boost;
    lavd_fexit_futex_wait_requeue_pi: "futex_wait_requeue_pi", |ret| ret == 0 => inc_futex_boost;
    lavd_fexit_futex_wake: "futex_wake", |ret| ret >= 0 => dec_futex_boost;
    lavd_fexit_futex_wake_op: "futex_wake_op", |ret| ret >= 0 => dec_futex_boost;
    lavd_fexit_futex_lock_pi: "futex_lock_pi", |ret| ret == 0 => inc_futex_boost;
    lavd_fexit_futex_unlock_pi: "futex_unlock_pi", |ret| ret == 0 => dec_futex_boost;
}

// ── Tracepoints ──────────────────────────────────────────────────────

const FUTEX_PRIVATE_FLAG: u32 = 128;
const FUTEX_CLOCK_REALTIME: u32 = 256;
const FUTEX_CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

/// The commands of futex(2) that say something about who has the lock.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FutexCmd { Wait, Wake, LockPi, UnlockPi, Other }

impl From<u32> for FutexCmd {
    fn from(op: u32) -> FutexCmd {
        match op & FUTEX_CMD_MASK {
            // FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAIT_REQUEUE_PI
            0 | 9 | 11 => FutexCmd::Wait,
            // FUTEX_WAKE, FUTEX_WAKE_BITSET, FUTEX_WAKE_OP
            1 | 10 | 5 => FutexCmd::Wake,
            // FUTEX_LOCK_PI, FUTEX_LOCK_PI2, FUTEX_TRYLOCK_PI
            6 | 13 | 8 => FutexCmd::LockPi,
            7 => FutexCmd::UnlockPi,
            _ => FutexCmd::Other,
        }
    }
}

// What a tracepoint of a system call gets: struct trace_entry, the number of the
// call, then the arguments or the result, 8 bytes each, except that `op` and
// `val` of futex(2) are ints and share a slot.

bpf_prog!("?tracepoint/syscalls/sys_enter_futex",
fn lavd_tp_sys_enter_futex(_ent: u64, _nr: u64, _uaddr: u64, op_val: u64) {
    if let Some(cpuc) = get_cpu_ctx() {
        cpuc.futex_op.set(op_val as u32);
    }
});

bpf_prog!("?tracepoint/syscalls/sys_exit_futex",
fn lavd_tp_sys_exit_futex(_ent: u64, _nr: u64, ret: u64) {
    let ret = ret as i64;
    let Some(cpuc) = get_cpu_ctx() else { return };

    match (FutexCmd::from(cpuc.futex_op.get()), ret) {
        (FutexCmd::Wait | FutexCmd::LockPi, 0) => inc_futex_boost(),
        (FutexCmd::Wake, 1..) | (FutexCmd::UnlockPi, 0) => dec_futex_boost(),
        _ => (),
    }
});

bpf_prog!("?tracepoint/syscalls/sys_exit_futex_wait",
fn lavd_tp_sys_exit_futex_wait(_ent: u64, _nr: u64, ret: u64) {
    if ret as i64 == 0 {
        inc_futex_boost();
    }
});

bpf_prog!("?tracepoint/syscalls/sys_exit_futex_waitv",
fn lavd_tp_sys_exit_futex_waitv(_ent: u64, _nr: u64, ret: u64) {
    if ret as i64 >= 0 {
        inc_futex_boost();
    }
});

bpf_prog!("?tracepoint/syscalls/sys_exit_futex_wake",
fn lavd_tp_sys_exit_futex_wake(_ent: u64, _nr: u64, ret: u64) {
    if ret as i64 > 0 {
        dec_futex_boost();
    }
});

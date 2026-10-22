// SPDX-License-Identifier: GPL-2.0
//
// scx_cpu0: a CPU0 scheduler.
//
// Rust port of tools/sched_ext/scx_cpu0.bpf.c.
// Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
// Copyright (c) 2025 Tejun Heo <tj@kernel.org>
//
// This scheduler queues all tasks to a shared DSQ and only dispatches them on
// CPU0 in FIFO order. This is useful for testing bypass behavior when many
// tasks are concentrated on a single CPU.
//
// - BPF_MAP_TYPE_PERCPU_ARRAY stats -> [AtomicU64; 2] indexed by an enum
// - UEI (exit info for user space) is dropped

#![no_std]
#![no_main]
#![feature(panic_can_unwind)]

extern crate alloc;

#[macro_use]
mod scx_common;

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use scx_common::*;

/// We create a custom DSQ with ID 0 that we dispatch to and consume from on
/// CPU0.
const DSQ_CPU0: Dsq = Dsq(0);

#[derive(Clone, Copy)]
enum Stat {
    Local,
    Cpu0,
}

static STATS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

impl Stat {
    fn inc(self) { STATS[self as usize].fetch_add(1, Relaxed); }
}

bpf_prog!("struct_ops/cpu0_select_cpu",
fn cpu0_select_cpu(_p: Task, _prev_cpu: i32, _wake_flags: u64) -> i32 {
    0
});

bpf_prog!("struct_ops/cpu0_enqueue",
fn cpu0_enqueue(p: Task, enq_flags: u64) {
    // select_cpu() always picks CPU0. If @p is not on CPU0, it can't run on
    // CPU 0. Queue on whichever CPU it's currently only.
    if p.cpu() != 0 {
        Stat::Local.inc();
        p.dsq_insert(SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
        return;
    }

    Stat::Cpu0.inc();
    p.dsq_insert(DSQ_CPU0.0, SCX_SLICE_DFL, enq_flags);
});

bpf_prog!("struct_ops/cpu0_dispatch",
fn cpu0_dispatch(cpu: i32, _prev: Option<Task>) {
    if cpu == 0 {
        DSQ_CPU0.move_to_local();
    }
});

bpf_prog!("struct_ops.s/cpu0_init",
fn cpu0_init() -> Result {
    DSQ_CPU0.create(-1).inspect_err(|e| {
        scx_error!("failed to create DSQ %d (%d)", DSQ_CPU0.0, -e.0);
    })
});

bpf_prog!("struct_ops/cpu0_exit",
fn cpu0_exit(_ei: *const ScxExitInfo) {
});

scx_ops_define!(cpu0_ops, name: b"cpu0", flags: 0, timeout_ms: 0,
    select_cpu: cpu0_select_cpu,
    enqueue: cpu0_enqueue,
    dispatch: cpu0_dispatch,
    init: cpu0_init,
    exit: cpu0_exit,
);

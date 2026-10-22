// SPDX-License-Identifier: GPL-2.0
//
// introspec.bpf.c: on request, a record about each of the next N tasks that get
// scheduled goes to user space through a ring buffer.
// Copyright (c) 2023, 2024 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

use crate::*;

/// What user space asks for. It writes here, the scheduler counts `arg` down.
pub struct Introspec {
    pub cmd: AtomicU32,
    pub arg: AtomicU64,
}

pub const LAVD_CMD_NOP: u32 = 0;
/// report the next `arg` scheduled tasks
pub const LAVD_CMD_SCHED_N: u32 = 1;
const LAVD_MSG_TASKC: u32 = 0x1;

#[export_name = "lavd_intrspc"]
pub static INTRSPC: Introspec = Introspec { cmd: AtomicU32::new(LAVD_CMD_NOP), arg: AtomicU64::new(0) };

/// struct msg_task_ctx of C, less what this port does not keep track of.
#[repr(C)]
pub struct MsgTaskCtx {
    pub kind: u32,
    pub pid: i32,
    pub comm: [u64; 2],
    /// Latency critical or Regular, High or lIttle performance, Big or liTtle
    /// core, Greedy or Eligible
    pub stat: [u8; 8],
    pub cpu_id: i32,
    pub prev_cpu_id: i32,
    pub suggested_cpu_id: i32,
    pub waker_pid: i32,
    pub slice_wall: u64,
    pub lat_cri: u64,
    pub avg_lat_cri: u64,
    pub static_prio: u64,
    pub rerunnable_interval_wall: u64,
    pub run_freq: u64,
    pub avg_runtime_wall: u64,
    pub wait_freq: u64,
    pub wake_freq: u64,
    pub perf_cri: u64,
    pub thr_perf_cri: u64,
    pub cpuperf_cur: u64,
    pub cpu_util_wall: u64,
    pub cpu_util_invr: u64,
    pub steal_util_wall: u64,
    pub steal_util_invr: u64,
    pub nr_active: u64,
    pub dsq_id: u64,
    pub last_slice_used_wall: u64,
    pub lat_headroom: u64,
    pub vuln_thresh: u64,
    pub task_util_est: u64,
    pub norm_lat_cri: u64,
    pub cpu_heat: u64,
}

bpf_ringbuf_map!(lavd_introspec_msg, introspec_msg, 16 * 1024);

/// scale to percent
fn s2p(scale: u64) -> u64 { (scale * 100) >> LAVD_SHIFT }

fn submit_task_ctx(p: Task, taskc: &TaskCtx, cpuc: &CpuCtx) -> Option<()> {
    let cpdomc = cpuc.cpdom()?;
    let pick = |cond: bool, yes: u8, no: u8| if cond { yes } else { no };
    let comm = p.comm();
    let word = |i: usize| comm.chunks_exact(8).nth(i).map_or(0, |b| b.iter().rev().fold(0u64, |w, &b| w << 8 | b as u64));

    // The record is in the memory of the kernel: it is filled in member by
    // member. A struct expression would be built in arena and copied.
    let mut rec = introspec_msg().reserve::<MsgTaskCtx>()?;
    let m = rec.as_mut();
    m.kind = LAVD_MSG_TASKC;
    m.pid = p.pid();
    m.comm = [word(0), word(1)];
    m.stat = [
        pick(taskc.is_lat_cri(), b'L', b'R'),
        pick(is_perf_cri(taskc), b'H', b'I'),
        pick(cpuc.big_core, b'B', b'T'),
        pick(taskc.flags.contains(TaskFlags::IS_GREEDY), b'G', b'E'),
        0, 0, 0, 0,
    ];
    m.cpu_id = taskc.cpu_id;
    m.prev_cpu_id = taskc.prev_cpu_id;
    m.suggested_cpu_id = taskc.suggested_cpu_id;
    m.waker_pid = taskc.waker_pid;
    m.slice_wall = taskc.slice_wall;
    m.lat_cri = taskc.lat_cri;
    m.avg_lat_cri = SYS_STAT.avg_lat_cri.get();
    m.static_prio = (p.static_prio() - MAX_RT_PRIO) as u64;
    m.rerunnable_interval_wall = time_delta(taskc.last_quiescent_clk, taskc.last_runnable_clk);
    m.run_freq = taskc.run_freq;
    m.avg_runtime_wall = taskc.avg_runtime_wall;
    m.wait_freq = taskc.wait_freq;
    m.wake_freq = taskc.wake_freq;
    m.perf_cri = taskc.perf_cri;
    m.thr_perf_cri = SYS_STAT.thr_perf_cri.get();
    m.cpuperf_cur = cpuc.cpuperf_cur.get();
    m.cpu_util_wall = s2p(cpuc.avg_util_wall.get());
    m.cpu_util_invr = s2p(cpuc.avg_util_invr.get());
    m.steal_util_wall = s2p(cpuc.avg_steal_util_wall.get());
    m.steal_util_invr = s2p(cpuc.avg_steal_util_invr.get());
    m.nr_active = SYS_STAT.nr_active.get();
    m.dsq_id = cpdomc.id as u64;
    m.last_slice_used_wall = taskc.last_slice_used_wall;
    m.lat_headroom = cpuc.lat_headroom.get();
    m.vuln_thresh = cpdomc.vuln_thresh.get();
    m.task_util_est = taskc.util_est;
    m.norm_lat_cri = taskc.normalized_lat_cri;
    m.cpu_heat = taskc.cpu_heat;
    rec.submit();
    Some(())
}

/// From ops.running().
pub fn try_proc_introspec_cmd(p: Task, taskc: &TaskCtx, cpuc: &CpuCtx) {
    match INTRSPC.cmd.get() {
        LAVD_CMD_NOP => (),
        LAVD_CMD_SCHED_N => {
            // Who gets to count down reports.
            if INTRSPC.arg.fetch_update(Relaxed, Relaxed, |nr| nr.checked_sub(1)).is_ok() {
                submit_task_ctx(p, taskc, cpuc);
            }
        }
        cmd => scx_error!("Unknown introspec command: %d", cmd),
    }
}

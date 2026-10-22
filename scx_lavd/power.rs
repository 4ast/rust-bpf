// SPDX-License-Identifier: GPL-2.0
//
// power.bpf.c: core compaction (run on as few CPUs as the load needs), big and
// little cores, CPU frequency, power profiles and the autopilot.
// Copyright (c) 2023, 2024 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>
//
// Without an energy model: the no_use_em case of C, where there are two orders
// in which CPUs get activated, little cores first or big cores first.

use crate::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PowerMode { Performance, Balanced, Powersave }

impl TryFrom<u32> for PowerMode {
    type Error = Errno;
    fn try_from(v: u32) -> Result<PowerMode> {
        match v {
            0 => Ok(PowerMode::Performance),
            1 => Ok(PowerMode::Balanced),
            2 => Ok(PowerMode::Powersave),
            _ => Err(EINVAL),
        }
    }
}

static POWER_MODE: AtomicU32 = AtomicU32::new(PowerMode::Balanced as u32);
static LAST_POWER_MODE_CLK: AtomicU64 = AtomicU64::new(0);
static IS_POWERSAVE_MODE: AtomicBool = AtomicBool::new(false);
/// Time spent in each mode, indexed by PowerMode.
#[export_name = "lavd_power_mode_ns"]
pub static POWER_MODE_NS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// pco_table[]: the CPUs in the order of activation, [0] to save power, [1] to
/// perform.
pub static CPU_ORDER: BpfCell<[Vec<u16>; 2]> = BpfCell::new([Vec::new(), Vec::new()]);
static PCO_IDX: AtomicU32 = AtomicU32::new(1);

pub static TOTAL_MAX_CAPACITY: AtomicU64 = AtomicU64::new(0);
pub static ONE_LITTLE_MAX_CAPACITY: AtomicU64 = AtomicU64::new(LAVD_SCALE);
pub static CUR_BIG_CORE_SCALE: AtomicU64 = AtomicU64::new(0);
pub static DEFAULT_BIG_CORE_SCALE: AtomicU64 = AtomicU64::new(0);
static AP_LOW_CAP: AtomicU64 = AtomicU64::new(0);
static AP_HIGH_CAP: AtomicU64 = AtomicU64::new(0);

pub fn get_cpu_order() -> &'static [u16] {
    CPU_ORDER.get().get(PCO_IDX.get() as usize).map_or(&[], |order| order.as_slice())
}

impl CpuCtx {
    /// What the CPU can do right now: its capacity at the highest frequency
    /// that it was seen to reach lately. (C also asks cpufreq and hw_pressure.)
    pub fn update_effective_capacity(&self) {
        let mfo = self.max_freq_observed.take();
        if mfo > 0 && (self.max_freq.get() < mfo || self.cur_util_wall.get() >= LAVD_CPU_UTIL_THR_FOR_MAX_FREQ) {
            self.max_freq.set(avg(self.max_freq.get(), mfo));
        }
        let capacity_observed = (self.max_capacity * self.max_freq.get()) >> LAVD_SHIFT;
        self.effective_capacity.set(min(self.max_capacity, capacity_observed));
    }

    /// From the timer: the frequency for the utilization by our tasks.
    pub fn calc_cpuperf_target(&self) {
        let scx_only = |total: &AtomicU64, steal: &AtomicU64| total.get().saturating_sub(steal.get());
        let cap = cpuperf_cap(self.cpu_id) as u64;

        let max_util_wall = max(scx_only(&self.avg_util_wall, &self.avg_steal_util_wall),
                                scx_only(&self.cur_util_wall, &self.cur_steal_util_wall));
        let target = if NO_FREQ_SCALING.on() || max_util_wall >= LAVD_CPU_UTIL_MAX_FOR_CPUPERF {
            cap
        } else {
            min(cap, max(scx_only(&self.avg_util_invr, &self.avg_steal_util_invr),
                         scx_only(&self.cur_util_invr, &self.cur_steal_util_invr)))
        };

        // Up in steps, down only past a dead band.
        let step = max(cap >> LAVD_CPUPERF_UP_SHIFT, 1);
        let target = min(target.next_multiple_of(step), cap);
        let cur = self.cpuperf_target.get();
        if target >= cur || cur - target >= cap >> LAVD_CPUPERF_DOWN_SHIFT {
            self.cpuperf_target.set(target);
        }
    }

    /// From ops.running(), on the CPU itself.
    pub fn update_cpuperf_target(&self) {
        let target = self.cpuperf_target.get();
        if self.cpuperf_cur.get() != target {
            cpuperf_set(self.cpu_id, target);
            self.cpuperf_cur.set(target);
        }
    }
}

/// Does the task belong on a big core?
pub fn is_perf_cri(taskc: &TaskCtx) -> bool {
    if !HAVE_LITTLE_CORE.on() {
        return true;
    }
    if taskc.flags.contains(TaskFlags::ON_BIG | TaskFlags::ON_LITTLE) {
        return taskc.perf_cri > SYS_STAT.thr_perf_cri.get();
    }
    taskc.flags.contains(TaskFlags::ON_BIG)
}

fn calc_required_capacity() -> u64 { NR_CPUS_ONLN.get() * SYS_STAT.avg_util_invr.get() }

/// How many CPUs, in the order of activation, have the capacity for the load
/// when none of them is to be more than half busy.
fn calc_nr_active_cpus() -> usize {
    let req_cap = calc_required_capacity();
    let req_cap = req_cap + ((req_cap * LAVD_CC_REQ_CAPACITY_HEADROOM) >> LAVD_SHIFT);

    PCO_IDX.set(if IS_POWERSAVE_MODE.on() { 0 } else { 1 });

    get_cpu_order().iter()
        .map(|&cpu| cpu_ctxs().get(cpu as usize).filter(|cpuc| cpuc.is_online.on())
            .map_or(0, |cpuc| (cpuc.effective_capacity.get() * LAVD_CC_PER_CPU_UTIL) >> LAVD_SHIFT))
        .scan(0, |sum_eff_cap, eff_cap| { *sum_eff_cap += eff_cap; Some(*sum_eff_cap) })
        .position(|sum_eff_cap| sum_eff_cap >= req_cap)
        .map_or(nr_cpus() as usize, |i| i + 1)
}

/// Publishes what the passes below counted per domain.
fn commit_active_cpus() {
    let nr_active_cpdoms = cpdoms().iter().filter(|cpdomc| {
        cpdomc.nr_active_cpus.set(cpdomc.nr_acpus_temp.take());
        cpdomc.cap_sum_active_cpus.set(cpdomc.cap_sum_temp.take());
        cpdomc.nr_active_cpus.get() > 0
    }).count();
    SYS_STAT.nr_active_cpdoms.set(nr_active_cpdoms as u64);
}

fn count_active(cpuc: &CpuCtx) {
    if let Some(cpdomc) = cpdoms().get(cpuc.cpdom_id as usize) {
        cpdomc.cap_sum_temp.bump(cpuc.effective_capacity.get());
        cpdomc.nr_acpus_temp.bump(1);
    }
}

/// From the timer: which CPUs are active from here on.
#[inline(never)]
pub fn do_core_compaction() {
    let nr_active = calc_nr_active_cpus();
    let mut sum_capacity = 0;
    let mut big_capacity = 0;

    for (i, &cpu) in get_cpu_order().iter().enumerate() {
        let cpu = cpu as i32;
        let Some(cpuc) = cpu_ctxs().get(cpu as usize).filter(|cpuc| cpuc.is_online.on()) else {
            ACTIVE_CPUS.clear(cpu);
            ovrflw_test_and_clear(cpu);
            continue;
        };

        if i < nr_active {
            ACTIVE_CPUS.set(cpu);
            ovrflw_test_and_clear(cpu);
            count_active(cpuc);
        } else {
            ACTIVE_CPUS.clear(cpu);

            if cpuc.nr_pinned_tasks.get() > 0 || cpuc.local_dsq().nr_queued() > 0
                || (use_per_cpu_dsq() && cpu_to_dsq(cpu).nr_queued() > 0) {
                // Something waits that can only run here.
                ovrflw_test_and_set(cpu);
            } else {
                if !OVRFLW_CPUS.test(cpu) {
                    continue;
                }
                // An overflow CPU is let go after a while, not at once.
                if random() as u64 % LAVD_CC_CPU_PIN_INTERVAL_DIV != 0 {
                    ovrflw_test_and_clear(cpu);
                    continue;
                }
            }
        }

        // Make the CPU notice.
        kick_cpu(cpu, SCX_KICK_IDLE);
        sum_capacity += cpuc.effective_capacity.get();
        if cpuc.big_core {
            big_capacity += cpuc.effective_capacity.get();
        }
    }

    CUR_BIG_CORE_SCALE.set((big_capacity << LAVD_SHIFT) / max(sum_capacity, 1));
    SYS_STAT.nr_active.set(nr_active as u64);
    commit_active_cpus();
    OVRFLW_COUNTED_ACTIVE.turn(false);
}

pub fn update_power_mode_time() {
    let now = scx_now();
    let last = match LAST_POWER_MODE_CLK.get() { 0 => now, last => last };
    LAST_POWER_MODE_CLK.set(now);

    if let Some(mode_ns) = POWER_MODE_NS.get(POWER_MODE.get() as usize) {
        mode_ns.add(time_delta(now, last));
    }
}

pub fn do_set_power_profile(pm: PowerMode) {
    if POWER_MODE.get() == pm as u32 {
        return;
    }
    update_power_mode_time();
    POWER_MODE.set(pm as u32);

    NO_CORE_COMPACTION.turn(pm == PowerMode::Performance);
    IS_POWERSAVE_MODE.turn(pm == PowerMode::Powersave);
    REINIT_CPUMASK_FOR_PERFORMANCE.turn(pm == PowerMode::Performance);
}

/// Picks the power profile from the load.
pub fn do_autopilot() {
    do_set_power_profile(match calc_required_capacity() {
        req_cap if req_cap <= AP_LOW_CAP.get() => PowerMode::Powersave,
        req_cap if req_cap <= AP_HIGH_CAP.get() => PowerMode::Balanced,
        _ => PowerMode::Performance,
    });
}

/// Above which performance criticality a task goes to a big core: so that the
/// share of such tasks matches the share of the big cores in the capacity.
pub fn update_thr_perf_cri() {
    if NO_CORE_COMPACTION.on() || !HAVE_LITTLE_CORE.on() {
        CUR_BIG_CORE_SCALE.set(DEFAULT_BIG_CORE_SCALE.get());
    }
    let (min_pc, avg_pc, max_pc) =
        (SYS_STAT.min_perf_cri.get(), SYS_STAT.avg_perf_cri.get(), SYS_STAT.max_perf_cri.get());
    const HALF: u64 = LAVD_SCALE >> 1;

    SYS_STAT.thr_perf_cri.set(match LAVD_SCALE.saturating_sub(CUR_BIG_CORE_SCALE.get()) {
        // only little cores, only big cores
        LAVD_SCALE => max_pc,
        0 => 0,
        little if little < p2s(50) => min_pc + (avg_pc.saturating_sub(min_pc) * little) / HALF,
        little => avg_pc + (max_pc.saturating_sub(avg_pc) * (little - p2s(50))) / HALF,
    });
}

/// Performance mode: all big cores are active, little ones are for overflow.
#[inline(never)]
pub fn reinit_active_cpumask_for_performance() {
    let have_little_core = HAVE_LITTLE_CORE.on();
    if have_little_core {
        OVRFLW_COUNTED_ACTIVE.turn(true);
    }

    for cpuc in cpu_ctxs() {
        let cpu = cpuc.cpu_id;
        if !cpuc.is_online.on() {
            ACTIVE_CPUS.clear(cpu);
            ovrflw_test_and_clear(cpu);
            continue;
        }
        if cpuc.big_core || !have_little_core {
            ACTIVE_CPUS.set(cpu);
            ovrflw_test_and_clear(cpu);
        } else {
            ovrflw_test_and_set(cpu);
            ACTIVE_CPUS.clear(cpu);
        }
        kick_cpu(cpu, SCX_KICK_IDLE);
        count_active(cpuc);
    }

    commit_active_cpus();
    SYS_STAT.nr_active.set(NR_CPUS_ONLN.get());
    PCO_IDX.set(1);
}

pub fn update_autopilot_high_cap() {
    let rt = if SMT_ACTIVE.on() { LAVD_AP_HIGH_UTIL_DFL_SMT_RT } else { LAVD_AP_HIGH_UTIL_DFL_NO_SMT_RT };
    AP_HIGH_CAP.set((TOTAL_MAX_CAPACITY.get() * rt) >> LAVD_SHIFT);
}

pub fn init_autopilot_caps() {
    AP_LOW_CAP.set(ONE_LITTLE_MAX_CAPACITY.get() / 2);
    update_autopilot_high_cap();
}

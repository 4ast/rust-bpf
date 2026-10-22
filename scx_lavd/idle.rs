// SPDX-License-Identifier: GPL-2.0
//
// idle.bpf.c: where to put a task that becomes runnable.
// Copyright (c) 2023-2025 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>
//
// The scratch cpumasks that every CPU has in C (kptrs in cpu_ctx) are members
// of PickCtx, which lives on the stack of the caller. The idle masks of the
// kernel and the cpumask of an affinitized task are copied once per pick: a
// pointer to kernel memory cannot be kept in PickCtx, nor in a closure that the
// compiler may decide not to inline, because these are in arena. The gotos to
// unlock_out are `return`s of try_pick(), whose None is the -ENOENT of C.

use crate::*;

/// The result of pick_idle_cpu().
#[derive(Clone, Copy)]
pub struct Picked {
    pub cpu: i32,
    /// The CPU was idle and is reserved for the task now.
    pub is_idle: bool,
}

impl Picked {
    fn idle(cpu: i32) -> Option<Picked> { Some(Picked { cpu, is_idle: true }) }
    fn busy(cpu: i32) -> Option<Picked> { Some(Picked { cpu, is_idle: false }) }
    /// Whatever state the CPU is in.
    fn claim(cpu: i32) -> Option<Picked> { Some(Picked { cpu, is_idle: test_and_clear_cpu_idle(cpu) }) }
}

/// Where a mask of a task comes from. A task that can run everywhere uses the
/// masks of the system.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Src { Empty, Global, Own }

pub struct PickCtx<'a> {
    pub taskc: &'a mut TaskCtx,
    pub wake_flags: u64,
    pub prev_cpu: i32,
    pub cpuc_cur: &'static CpuCtx,
    sync_waker_cpu: Option<i32>,
    is_task_big: bool,
    a_src: Src,
    o_src: Src,
    /// where an affinitized task may run
    allowed: CpuSet,
    /// task & active, or the steady CPUs for a task that preemption hurts
    a_own: CpuSet,
    /// task & overflow, or the turbulent CPUs
    o_own: CpuSet,
    /// task & idle
    i_mask: CpuSet,
    /// fully idle cores
    i_smt: CpuSet,
    /// idle & active
    ia_mask: CpuSet,
    /// idle & overflow
    io_mask: CpuSet,
    /// idle & active & turbo
    iat_mask: CpuSet,
}

/// The CPU and the domain that a task would like to stay on.
struct Sticky {
    cpu: Option<i32>,
    cpdom: u32,
}

impl<'a> PickCtx<'a> {
    pub fn new(taskc: &'a mut TaskCtx, cpuc_cur: &'static CpuCtx, prev_cpu: i32, wake_flags: u64) -> Self {
        PickCtx {
            taskc, wake_flags, prev_cpu, cpuc_cur,
            sync_waker_cpu: None,
            is_task_big: false,
            a_src: Src::Empty,
            o_src: Src::Empty,
            allowed: CpuSet::new(),
            a_own: CpuSet::new(),
            o_own: CpuSet::new(),
            i_mask: CpuSet::new(),
            i_smt: CpuSet::new(),
            ia_mask: CpuSet::new(),
            io_mask: CpuSet::new(),
            iat_mask: CpuSet::new(),
        }
    }

    fn a_mask(&self) -> Option<&CpuSet> {
        match self.a_src {
            Src::Empty => None,
            Src::Global => Some(&ACTIVE_CPUS),
            Src::Own => Some(&self.a_own),
        }
    }

    fn o_mask(&self) -> Option<&CpuSet> {
        match self.o_src {
            Src::Empty => None,
            Src::Global => Some(&OVRFLW_CPUS),
            Src::Own => Some(&self.o_own),
        }
    }

    fn use_own_masks(&mut self) {
        self.a_src = if self.a_own.is_empty() { Src::Empty } else { Src::Own };
        self.o_src = if self.o_own.is_empty() { Src::Empty } else { Src::Own };
    }

    fn allows(&self, cpu: i32) -> bool { !self.taskc.is_affinitized() || self.allowed.test(cpu) }

    /// The active and overflow CPUs that the task can run on.
    fn init_ao_masks(&mut self, p: Task) {
        if !self.taskc.is_affinitized() {
            self.a_src = Src::Global;
            self.o_src = Src::Global;
            return;
        }
        self.allowed.assign_and(&ONLINE_CPUS, p.cpus());
        self.a_own.assign_with(&ACTIVE_CPUS, &self.allowed, |a, t| a & t);
        self.o_own.assign_with(&OVRFLW_CPUS, &self.allowed, |o, t| o & t);
        self.use_own_masks();
    }

    fn is_preemption_vulnerable(&self) -> bool {
        self.cpuc_cur.cpdom().is_some_and(|cpdc| {
            preemption_vulnerability(self.taskc.normalized_lat_cri, self.taskc.util_est) >= cpdc.vuln_thresh.get()
        })
    }

    /// For a task that preemption hurts the first choice are the CPUs that
    /// interrupts leave alone, active or not, and the second choice the rest.
    fn repartition_masks_for_latency(&mut self) {
        let (steady_set, turb_set) = (&self.a_own, &self.o_own);

        turb_set.assign_with(&ACTIVE_CPUS, &OVRFLW_CPUS, |a, o| a | o);
        if self.taskc.is_affinitized() {
            turb_set.assign_with(turb_set, &self.allowed, |all, t| all & t);
        }
        steady_set.assign_with(turb_set, &STEADY_CPUS, |all, steady| all & steady);
        turb_set.assign_with(turb_set, steady_set, |all, steady| all ^ steady);
        self.use_own_masks();
    }

    /// Which of the CPUs in @fully (or of the idle CPUs of the task) are
    /// active, overflow, turbo.
    fn init_idle_ato_masks(&self, fully_idle_cores: bool) {
        let idle = if fully_idle_cores { &self.i_smt } else { &self.i_mask };

        match self.a_mask() {
            Some(a_mask) => self.ia_mask.assign_with(idle, a_mask, |i, a| i & a),
            None => self.ia_mask.clear_all(),
        }
        match self.o_mask() {
            Some(o_mask) => self.io_mask.assign_with(idle, o_mask, |i, o| i & o),
            None => self.io_mask.clear_all(),
        }
        if HAVE_TURBO_CORE.on() {
            self.iat_mask.assign_with(&self.ia_mask, &TURBO_CPUS, |ia, t| ia & t);
        } else {
            self.iat_mask.clear_all();
        }
    }

    fn no_idle_ao(&self) -> bool { self.ia_mask.is_empty() && self.io_mask.is_empty() }

    /// An inactive CPU in the LLC of the previous CPU, to grow the overflow set.
    fn find_cpu_for_ovrflw_extend(&self) -> Option<i32> {
        if NO_OVRFLW_EXTEND.on() || use_full_cpus() {
            return None;
        }
        let prev_llc = get_cpu_ctx_id(self.prev_cpu)?.cpdom()?.llc_id;

        inactive_cpus_in_order()
            .filter(|&cpu| ONLINE_CPUS.test(cpu) && !OVRFLW_CPUS.test(cpu) && self.allows(cpu))
            .find(|&cpu| {
                cpu_ctxs().get(cpu as usize).and_then(|cpuc| cpdoms().get(cpuc.cpdom_id as usize))
                    .is_some_and(|cpdc| cpdc.llc_id == prev_llc)
            })
    }

    /// Reserves an idle CPU of a domain: turbo first, then active, then overflow.
    #[inline(never)]
    fn pick_idle_cpu_at_cpdom(&self, cpdom: u32, core: bool) -> Option<i32> {
        let cpdc = cpdoms().get(cpdom as usize)?;
        let has_active = cpdc.nr_active_cpus.get() > 0;
        let core = core && SMT_ACTIVE.on();

        [
            (has_active && cpdc.is_big, &self.iat_mask),
            (has_active, &self.ia_mask),
            (true, &self.io_mask),
        ].into_iter()
            .filter(|(usable, _)| *usable)
            .flat_map(|(_, mask)| cpdc.cpus.iter_and(mask))
            .filter(|&cpu| !core || self.i_smt.test(cpu))
            .find(|&cpu| test_and_clear_cpu_idle(cpu))
    }

    fn cpumask_any_distribute(&self) -> Option<i32> {
        self.a_mask().and_then(CpuSet::any_distribute)
            .or_else(|| self.o_mask().and_then(CpuSet::any_distribute))
    }

    /// The less utilized of two random CPUs.
    #[inline(never)]
    fn pick_random_cpu(&self) -> i32 {
        let cpuc = |cpu: Option<i32>| cpu.and_then(|cpu| cpu_ctxs().get(cpu as usize));

        match (cpuc(self.cpumask_any_distribute()), cpuc(self.cpumask_any_distribute())) {
            (Some(c0), Some(c1)) => {
                if c0.cur_util_invr.get() < c1.cur_util_invr.get() { c0.cpu_id } else { c1.cpu_id }
            }
            _ => self.prev_cpu,
        }
    }

    /// The sticky CPU, or else any CPU of the sticky domain.
    fn find_sticky_cpu_at_cpdom(&self, sticky_cpu: Option<i32>, sticky_cpdom: u32) -> Option<i32> {
        if sticky_cpu.is_some() {
            return sticky_cpu;
        }
        let cpd_mask = &cpdoms().get(sticky_cpdom as usize)?.cpus;
        let any_and = |mask: &CpuSet| {
            let nr = cpd_mask.iter_and(mask).count();
            if nr == 0 { None } else { cpd_mask.iter_and(mask).nth(random() as usize % nr) }
        };

        self.a_mask().and_then(any_and).or_else(|| self.o_mask().and_then(any_and))
    }

    fn can_run_on_cpu(&self, cpu: i32) -> bool {
        if !self.taskc.is_affinitized() {
            return true;
        }
        self.allowed.test(cpu)
            && (self.a_mask().is_some_and(|m| m.test(cpu)) || self.o_mask().is_some_and(|m| m.test(cpu)))
    }

    fn can_run_on_domain(&self, cpdom: u32) -> bool {
        if !self.taskc.is_affinitized() {
            return true;
        }
        let Some(cpdc) = cpdoms().get(cpdom as usize) else { return false };

        (cpdc.nr_active_cpus.get() > 0 && self.a_mask().is_some_and(|m| m.intersects_set(&cpdc.cpus)))
            || self.o_mask().is_some_and(|m| m.intersects_set(&cpdc.cpus))
    }

    fn is_sync_wakeup(&self) -> bool {
        self.wake_flags & SCX_WAKE_SYNC != 0 && !Task::current().is_exiting()
    }

    /// The previous CPU and, for a synchronous wake up, the CPU of the waker
    /// are where the caches are warm. Prefer the one whose core type fits the
    /// task, then the one in the less loaded domain.
    #[inline(never)]
    fn find_sticky_cpu_and_cpdom(&mut self) -> Option<Sticky> {
        if self.is_sync_wakeup() {
            self.sync_waker_cpu = Some(this_cpu()).filter(|&cpu| cpu != self.prev_cpu);
        }

        let candidates = || [Some(self.prev_cpu), self.sync_waker_cpu].into_iter().flatten()
            .filter(|&cpu| self.can_run_on_cpu(cpu))
            .filter_map(|cpu| cpu_ctxs().get(cpu as usize));
        let load = |cpuc: &CpuCtx| cpdoms().get(cpuc.cpdom_id as usize).map_or(0, |d| d.load_invr.get());
        let in_domain = |cpuc: &CpuCtx| Some(Sticky { cpu: None, cpdom: cpuc.cpdom_id });

        // CPUs of the type that the task wants.
        let mut matching = candidates().filter(|cpuc| cpuc.big_core == self.is_task_big);
        match (matching.next(), matching.next()) {
            (Some(p0), Some(p1)) if load(p0) > load(p1) => return in_domain(p1),
            (Some(p0), _) => return Some(Sticky { cpu: Some(p0.cpu_id), cpdom: p0.cpdom_id }),
            _ => (),
        }

        // CPUs of the other type: stay in the domain at least.
        let mut other = candidates().filter(|cpuc| self.can_run_on_domain(cpuc.cpdom_id));
        match (other.next(), other.next()) {
            (Some(p0), Some(p1)) => return in_domain(if load(p0) > load(p1) { p1 } else { p0 }),
            (Some(p0), None) => return in_domain(p0),
            _ => (),
        }

        // The task cannot run on these CPUs, but maybe next to them.
        [Some(self.prev_cpu), self.sync_waker_cpu].into_iter().flatten()
            .filter_map(|cpu| cpu_ctxs().get(cpu as usize))
            .find(|cpuc| self.can_run_on_domain(cpuc.cpdom_id))
            .and_then(in_domain)
    }

    /// The waker is about to sleep and nothing else waits for its CPU.
    fn sync_waker_cpu_if_idle(&self) -> Option<i32> {
        let waker_cpu = self.sync_waker_cpu.filter(|&cpu| self.can_run_on_cpu(cpu))?;
        let cpuc_waker = get_cpu_ctx_id(waker_cpu).filter(|cpuc| !cpuc.queued_on_cpu())?;

        if nr_cpdoms() > 1 && get_cpu_ctx_id(self.prev_cpu)?.cpdom_id != cpuc_waker.cpdom_id {
            return None;
        }
        Some(waker_cpu)
    }

    /// The domain of the task has too much to do: look at the neighbours that
    /// have too little, or where the task would be done earlier.
    #[inline(never)]
    fn migrate_to_neighbor(&self, cpdc: &Cpdom, core: bool) -> Option<Picked> {
        let svc_invr = self.taskc.avg_runtime_invr;
        let min_gain = XMIG_MIN_GAIN_NS.get();
        let ct_s = (min_gain > 0).then(|| calc_comp_time_on_cpdom(svc_invr, cpdc));

        let (mig_cpdc, picked) = cpdc.neighbors()
            .filter(|mig_cpdc| match ct_s {
                // Completion time only compares within an LLC.
                Some(ct_s) => mig_cpdc.llc_id == cpdc.llc_id
                    && ct_s.saturating_sub(calc_comp_time_on_cpdom(svc_invr, mig_cpdc)) > min_gain,
                None => mig_cpdc.is_stealer.on(),
            })
            .find_map(|mig_cpdc| {
                let idle = self.pick_idle_cpu_at_cpdom(mig_cpdc.id, core).and_then(Picked::idle);
                let queue = || ct_s.and(self.find_sticky_cpu_at_cpdom(None, mig_cpdc.id)).and_then(Picked::busy);
                idle.or_else(queue).map(|picked| (mig_cpdc, picked))
            })?;

        // One migration per round when balancing the slow way.
        if NO_FAST_LB.on() {
            mig_cpdc.is_stealer.turn(false);
            cpdc.is_stealee.turn(false);
        }
        Some(picked)
    }

    fn try_pick(&mut self, p: Task, extend_ovrflw: bool) -> Option<Picked> {
        let prev_cpu = self.prev_cpu;

        // A task that cannot move: no choice. Its CPU has to be usable.
        if self.taskc.is_effectively_pinned() || p.is_migration_disabled() {
            if !ACTIVE_CPUS.test(prev_cpu) && p.is_permanently_pinned() {
                ovrflw_test_and_set(prev_cpu);
            }
            return Picked::claim(prev_cpu);
        }

        // The previous CPU while the caches are warm, even if that means waiting.
        if WARM_CPU_NS.get() != 0 && ACTIVE_CPUS.test(prev_cpu) && p.cpus().test(prev_cpu) {
            if test_and_clear_cpu_idle(prev_cpu) {
                return Picked::idle(prev_cpu);
            }
            if self.taskc.lat_cri < SYS_STAT.thr_lat_cri.get() && self.taskc.warm_cpu_wait_ok(prev_cpu, scx_now()) {
                self.taskc.flags.insert(TaskFlags::WARM_CPU);
                return Picked::busy(prev_cpu);
            }
        }

        self.init_ao_masks(p);

        // The task can run on neither active nor overflow CPUs: extend the
        // overflow set.
        if self.a_src == Src::Empty && self.o_src == Src::Empty {
            let cpu = find_cpu_in(p.cpus())?;
            ovrflw_test_and_set(cpu);
            return Picked::claim(cpu);
        }

        if self.is_preemption_vulnerable() {
            self.repartition_masks_for_latency();
        }

        self.sync_waker_cpu = None;
        self.is_task_big = is_perf_cri(self.taskc);
        let sticky = self.find_sticky_cpu_and_cpdom()?;
        let stay = |ctx: &Self| ctx.find_sticky_cpu_at_cpdom(sticky.cpu, sticky.cpdom).and_then(Picked::busy);

        // Nothing idle: stay where the caches are warm.
        {
            let idle = ScxCpumask::idle();
            self.i_mask.assign_and(&ONLINE_CPUS, *idle);
        }
        if self.taskc.is_affinitized() {
            self.i_mask.assign_with(&self.i_mask, &self.allowed, |i, t| i & t);
        }
        if self.i_mask.is_empty() {
            return stay(self);
        }

        if SMT_ACTIVE.on() {
            let idle_smt = ScxCpumask::idle_smt();
            self.i_smt.assign_and(&ONLINE_CPUS, *idle_smt);
        } else {
            self.i_smt.assign_with(&self.i_mask, &self.i_mask, |i, _| i);
        }
        let i_smt_empty = self.i_smt.is_empty();

        // A fully idle core: the sticky CPU, or one in the sticky domain.
        if let Some(cpu) = sticky.cpu.filter(|&cpu| self.i_smt.test(cpu) && test_and_clear_cpu_idle(cpu)) {
            return Picked::idle(cpu);
        }
        if !i_smt_empty {
            self.init_idle_ato_masks(true);
            if let Some(cpu) = self.pick_idle_cpu_at_cpdom(sticky.cpdom, true) {
                return Picked::idle(cpu);
            }
        }

        // A partially idle core.
        if let Some(cpu) = sticky.cpu.filter(|&cpu| test_and_clear_cpu_idle(cpu)) {
            return Picked::idle(cpu);
        }

        if !NO_WAKE_SYNC.on() {
            if let Some(cpu) = self.sync_waker_cpu_if_idle() {
                return Picked::busy(cpu);
            }
        }

        self.init_idle_ato_masks(false);
        if self.no_idle_ao() {
            // All active and overflow CPUs are busy, others are idle.
            if let Some(cpu) = extend_ovrflw.then(|| self.find_cpu_for_ovrflw_extend()).flatten()
                .filter(|&cpu| test_and_clear_cpu_idle(cpu)) {
                ovrflw_test_and_set(cpu);
                return Picked::idle(cpu);
            }
            return stay(self);
        }

        let stealee = (nr_cpdoms() > 1).then(|| cpdoms().get(sticky.cpdom as usize)).flatten()
            .filter(|cpdc| cpdc.is_stealee.on());

        if let Some(cpdc) = stealee.filter(|_| !i_smt_empty || XMIG_MIN_GAIN_NS.get() > 0) {
            if let Some(picked) = self.migrate_to_neighbor(cpdc, true) {
                return Some(picked);
            }
        }

        if let Some(cpu) = self.pick_idle_cpu_at_cpdom(sticky.cpdom, false) {
            return Picked::idle(cpu);
        }

        if let Some(cpdc) = stealee.filter(|_| self.taskc.flags.contains(TaskFlags::MIGRATION_AGGRESSIVE)) {
            if let Some(picked) = self.migrate_to_neighbor(cpdc, false) {
                return Some(picked);
            }
        }

        if self.can_run_on_cpu(prev_cpu) { Picked::busy(prev_cpu) } else { None }
    }
}

/// The CPUs beyond the active ones, in the order in which they get activated.
fn inactive_cpus_in_order() -> impl Iterator<Item = i32> {
    get_cpu_order().iter().skip(SYS_STAT.nr_active.get() as usize).map(|&cpu| cpu as i32)
}

/// The next CPU to activate that is in @src_mask.
#[inline(never)]
pub fn find_cpu_in(src_mask: Cpumask) -> Option<i32> {
    inactive_cpus_in_order().find(|&cpu| ONLINE_CPUS.test(cpu) && src_mask.test(cpu))
}

#[inline(never)]
pub fn pick_idle_cpu(p: Task, ctx: &mut PickCtx, extend_ovrflw: bool) -> Picked {
    match ctx.try_pick(p, extend_ovrflw) {
        Some(picked) => picked,
        None => Picked { cpu: ctx.pick_random_cpu(), is_idle: false },
    }
}

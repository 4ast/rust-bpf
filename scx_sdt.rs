// SPDX-License-Identifier: GPL-2.0
//
// scx_sdt: a scheduler that keeps per-task statistics in memory from an
// allocator of its own.
//
// The scheduler is as simple as it gets: an idle CPU if there is one, else one
// shared queue. The point is the allocator. It hands out slots that are
// numbered, so that a slot can be named by a 64 bit id (index and generation)
// instead of a pointer. The slots are the leaves of a radix tree with three
// levels and 512 entries per node. Every node has a bitmap that says which of
// its entries are full, so that a free slot is found by going down three times.
// Memory for data is never given back: a slot that is freed keeps it for its
// next user.
//
// Rust port of tools/sched_ext/scx_sdt.bpf.c.
// Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
// Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
// Copyright (c) 2024-2025 Tejun Heo <tj@kernel.org>
//
// - struct sdt_desc + struct sdt_chunk, whose  -> struct Node<T> with
//   union is descs[] or data[] by the level       enum Entries<T>
// - loops over the levels with lv_desc[] and   -> recursion: what has to be done
//   lv_pos[] to walk back up                      on the way up is done when
//                                                 the call returns
// - void *, elem_size, payload[]               -> generics, T: Default
// - sdt_pool (bump allocation from pages)      -> Box
// - scx_task_map (task storage)                -> TaskMap<Handle>
// - ffs() by hand                              -> trailing_ones()
// - bpf_spin_lock alloc_lock                   -> SpinLock<Allocator<T>>

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod scx_common;

use alloc::boxed::Box;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use scx_common::*;

const SHARED_DSQ: Dsq = Dsq(0);

// ── The allocator ────────────────────────────────────────────────────

const SDT_TASK_ENTS_PER_PAGE_SHIFT: u32 = 9;
const SDT_TASK_LEVELS: u32 = 3;
const SDT_TASK_ENTS_PER_CHUNK: usize = 1 << SDT_TASK_ENTS_PER_PAGE_SHIFT;
const SDT_TASK_CHUNK_BITMAP_U64S: usize = SDT_TASK_ENTS_PER_CHUNK.div_ceil(64);

/// Names a slot and tells its users apart.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct SdtId {
    /// index in the radix tree
    idx: u32,
    /// ++'d on recycle so that it forms unique'ish 64bit ID
    genn: u32,
}

#[derive(Default)]
struct SdtData<T> {
    tid: SdtId,
    payload: T,
}

/// What the entries of a node are depends on its level.
enum Entries<T> {
    Nodes(Box<[Option<Box<Node<T>>>; SDT_TASK_ENTS_PER_CHUNK]>),
    Data(Box<[Option<Box<SdtData<T>>>; SDT_TASK_ENTS_PER_CHUNK]>),
}

struct Node<T> {
    /// An inner node: the subtree is full. A leaf: the slot is in use.
    allocated: [u64; SDT_TASK_CHUNK_BITMAP_U64S],
    nr_free: usize,
    entries: Entries<T>,
}

#[derive(Default)]
struct AllocStats {
    chunk_allocs: u64,
    data_allocs: u64,
    alloc_ops: u64,
    free_ops: u64,
    active_allocs: u64,
}

impl<T: Default> Node<T> {
    /// @level counts from the root, which is 0.
    fn new(level: u32, stats: &mut AllocStats) -> Box<Node<T>> {
        stats.chunk_allocs += 1;
        Box::new(Node {
            allocated: [0; SDT_TASK_CHUNK_BITMAP_U64S],
            nr_free: SDT_TASK_ENTS_PER_CHUNK,
            entries: if level == SDT_TASK_LEVELS - 1 {
                Entries::Data(Box::new([const { None }; SDT_TASK_ENTS_PER_CHUNK]))
            } else {
                Entries::Nodes(Box::new([const { None }; SDT_TASK_ENTS_PER_CHUNK]))
            },
        })
    }

    /// The first entry that has room.
    fn find_empty(&self) -> Option<usize> {
        self.allocated.iter().enumerate()
            .find(|(_, word)| **word != u64::MAX)
            .map(|(i, word)| i * 64 + word.trailing_ones() as usize)
    }

    fn set_idx_state(&mut self, pos: usize, state: bool) {
        if let Some(word) = self.allocated.get_mut(pos / 64) {
            let bit = 1 << (pos % 64);
            if state { *word |= bit } else { *word &= !bit }
        }
    }

    /// Takes a free slot in this subtree. @idx is the path to this node.
    /// Returns the data of the slot.
    fn alloc(&mut self, level: u32, idx: u32, stats: &mut AllocStats) -> Option<NonNull<SdtData<T>>> {
        let pos = self.find_empty()?;
        let idx = idx << SDT_TASK_ENTS_PER_PAGE_SHIFT | pos as u32;

        let (data, full) = match &mut self.entries {
            Entries::Nodes(nodes) => {
                let child = nodes.get_mut(pos)?.get_or_insert_with(|| Node::new(level + 1, stats));
                (child.alloc(level + 1, idx, stats)?, child.nr_free == 0)
            }
            Entries::Data(slots) => {
                let data = slots.get_mut(pos)?.get_or_insert_with(|| {
                    stats.data_allocs += 1;
                    Box::default()
                });
                data.tid.idx = idx;
                (NonNull::from(&mut **data), true)
            }
        };

        // On the way up: an entry that has become full is marked.
        if full {
            self.set_idx_state(pos, true);
            self.nr_free -= 1;
        }
        Some(data)
    }

    /// Gives the slot @idx back. Returns whether there was such a slot.
    fn free(&mut self, level: u32, idx: u32) -> bool {
        let shift = (SDT_TASK_LEVELS - 1 - level) * SDT_TASK_ENTS_PER_PAGE_SHIFT;
        let pos = (idx >> shift) as usize & (SDT_TASK_ENTS_PER_CHUNK - 1);

        // Did the entry have no room before?
        let was_full = match &mut self.entries {
            Entries::Nodes(nodes) => {
                let Some(child) = nodes.get_mut(pos).and_then(Option::as_mut) else { return false };
                let was_full = child.nr_free == 0;
                if !child.free(level + 1, idx) {
                    return false;
                }
                was_full
            }
            Entries::Data(slots) => {
                // The memory stays with the slot. The next user finds it zeroed
                // and with another generation.
                if let Some(data) = slots.get_mut(pos).and_then(Option::as_mut) {
                    **data = SdtData { tid: SdtId { idx: 0, genn: data.tid.genn.wrapping_add(1) }, payload: T::default() };
                }
                true
            }
        };

        if was_full {
            self.set_idx_state(pos, false);
            self.nr_free += 1;
        }
        true
    }
}

struct Allocator<T> {
    root: Option<Box<Node<T>>>,
    stats: AllocStats,
}

impl<T: Default> Allocator<T> {
    const fn new() -> Self {
        Allocator {
            root: None,
            stats: AllocStats { chunk_allocs: 0, data_allocs: 0, alloc_ops: 0, free_ops: 0, active_allocs: 0 },
        }
    }

    fn init(&mut self) { self.root = Some(Node::new(0, &mut self.stats)); }

    fn alloc(&mut self) -> Option<NonNull<SdtData<T>>> {
        let data = self.root.as_mut()?.alloc(0, 0, &mut self.stats)?;
        self.stats.alloc_ops += 1;
        self.stats.active_allocs += 1;
        Some(data)
    }

    fn free_idx(&mut self, idx: u32) -> bool {
        let freed = self.root.as_mut().is_some_and(|root| root.free(0, idx));
        if freed {
            self.stats.active_allocs -= 1;
            self.stats.free_ops += 1;
        }
        freed
    }
}

// ── Per-task data ────────────────────────────────────────────────────

#[derive(Default)]
struct ScxStats {
    pid: i32,
    enqueue: u64,
    exit: u64,
    init: u64,
    select_busy_cpu: u64,
    select_idle_cpu: u64,
}

/// What a task remembers of its slot.
struct Handle {
    tid: SdtId,
    data: NonNull<SdtData<ScxStats>>,
}

static SCX_TASK_ALLOCATOR: SpinLock<Allocator<ScxStats>> = SpinLock::new(Allocator::new());
static SCX_TASK_MAP: TaskMap<Handle> = TaskMap::new();

/// From ops.init_task(), which runs with interrupts on.
fn scx_task_alloc(p: Task) -> Option<&'static mut ScxStats> {
    let mut data = SCX_TASK_ALLOCATOR.with_irqs_off(|alloc| alloc.alloc())?;
    let data_ref = unsafe { data.as_mut() };

    SCX_TASK_MAP.insert(p, Handle { tid: data_ref.tid, data });
    Some(&mut data_ref.payload)
}

fn scx_task_data(p: Task) -> Option<&'static mut ScxStats> {
    let stats = SCX_TASK_MAP.get(p).map(|handle| unsafe { &mut handle.data.as_mut().payload });
    if stats.is_none() {
        scx_error!("no stats for pid %d", p.pid());
    }
    stats
}

fn scx_task_free(p: Task) {
    if let Some(handle) = SCX_TASK_MAP.get(p) {
        SCX_TASK_ALLOCATOR.lock().free_idx(handle.tid.idx);
        SCX_TASK_MAP.remove(p);
    }
}

// ── Statistics of the tasks that are gone ────────────────────────────

macro_rules! global_stats {
    ($($stat:ident: $metric:ident,)*) => {
        $(
            #[export_name = concat!("sdt_stat_", stringify!($metric))]
            static $stat: AtomicU64 = AtomicU64::new(0);
        )*

        fn scx_stat_global_update(stats: &ScxStats) {
            $($stat.fetch_add(stats.$metric, Relaxed);)*
        }
    };
}

global_stats! {
    STAT_ENQUEUE: enqueue,
    STAT_INIT: init,
    STAT_EXIT: exit,
    STAT_SELECT_IDLE_CPU: select_idle_cpu,
    STAT_SELECT_BUSY_CPU: select_busy_cpu,
}

// ── The scheduler ────────────────────────────────────────────────────

bpf_prog!("struct_ops/sdt_select_cpu",
fn sdt_select_cpu(p: Task, prev_cpu: i32, wake_flags: u64) -> i32 {
    let Some(stats) = scx_task_data(p) else { return 0 };

    let (cpu, is_idle) = p.select_cpu_dfl(prev_cpu, wake_flags);
    if is_idle {
        stats.select_idle_cpu += 1;
        p.dsq_insert(SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    } else {
        stats.select_busy_cpu += 1;
    }
    cpu
});

bpf_prog!("struct_ops/sdt_enqueue",
fn sdt_enqueue(p: Task, enq_flags: u64) {
    let Some(stats) = scx_task_data(p) else { return };

    stats.enqueue += 1;
    p.dsq_insert(SHARED_DSQ.0, SCX_SLICE_DFL, enq_flags);
});

bpf_prog!("struct_ops/sdt_dispatch",
fn sdt_dispatch(_cpu: i32, _prev: Option<Task>) {
    SHARED_DSQ.move_to_local();
});

bpf_prog!("struct_ops.s/sdt_init_task",
fn sdt_init_task(p: Task, _args: InitTaskArgs) -> Result {
    let Some(stats) = scx_task_alloc(p) else {
        scx_error!("arena allocator out of memory");
        return Err(ENOMEM);
    };

    stats.pid = p.pid();
    stats.init += 1;
    Ok(())
});

bpf_prog!("struct_ops/sdt_exit_task",
fn sdt_exit_task(p: Task, _args: *const u8) {
    let Some(stats) = scx_task_data(p) else { return };

    stats.exit += 1;
    scx_stat_global_update(stats);
    scx_task_free(p);
});

/// The state of the allocator, for SysRq-D. Not in C, where user space reads
/// alloc_stats.
bpf_prog!("struct_ops/sdt_dump",
fn sdt_dump(_dctx: *const u8) {
    use core::fmt::Write;
    let alloc = SCX_TASK_ALLOCATOR.lock();
    let s = &alloc.stats;

    let _ = writeln!(ScxDump, "SDT: chunk_allocs={} data_allocs={} alloc_ops={} free_ops={} active_allocs={}",
                     s.chunk_allocs, s.data_allocs, s.alloc_ops, s.free_ops, s.active_allocs);
    let _ = writeln!(ScxDump, "SDT: gone: init={} exit={} enqueue={} idle={} busy={}",
                     STAT_INIT.load(Relaxed), STAT_EXIT.load(Relaxed), STAT_ENQUEUE.load(Relaxed),
                     STAT_SELECT_IDLE_CPU.load(Relaxed), STAT_SELECT_BUSY_CPU.load(Relaxed));
});

bpf_prog!("struct_ops.s/sdt_init",
fn sdt_init() -> Result {
    SCX_TASK_ALLOCATOR.with_irqs_off(|alloc| alloc.init());

    SHARED_DSQ.create(-1).inspect_err(|err| scx_error!("failed to create DSQ %d (%d)", SHARED_DSQ.0, err.0))
});

bpf_prog!("struct_ops/sdt_exit",
fn sdt_exit(_ei: *const ScxExitInfo) {
});

scx_ops_define!(sdt_ops, name: b"sdt",
    flags: 0,
    timeout_ms: 0,
    select_cpu: sdt_select_cpu,
    enqueue: sdt_enqueue,
    dispatch: sdt_dispatch,
    init_task: sdt_init_task,
    exit_task: sdt_exit_task,
    dump: sdt_dump,
    init: sdt_init,
    exit: sdt_exit,
);

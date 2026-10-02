//! BTF_KIND_TYPE_TAG from Rust.
//!
//! A type tag annotates a *pointer type* rather than the declaration using it,
//! which is how the kernel's BTF carries `__kptr`, `__rcu`, `__percpu` and
//! `__user`. In C:
//!
//!     struct task_struct __attribute__((btf_type_tag("kptr"))) *task;
//!
//! rustc has no equivalent, so `#[btf_tag(type_tag = "...")]` records the
//! request in the `.btf_tags` manifest and `btf_tags.py` clones the field's
//! pointer DIDerivedType with an `annotations:` operand attached. Cloning
//! matters: rustc uniques one `!DIDerivedType(DW_TAG_pointer_type, ...)` per
//! pointee type and shares it across the whole module, so annotating in place
//! would tag every other `*mut task_struct` too. The clone gets a
//! distinguishing name, which is harmless because BTFDebug drops the names of
//! PTR types.
//!
//! Expected BTF:
//!
//!     [n] TYPE_TAG 'kptr' type_id=<task_struct>
//!     [m] PTR '(anon)' type_id=n
//!     STRUCT 'task_slot' ... 'task' type_id=m
//!
//! Verify with: bpftool btf dump file bld/type_tag_test.o

#![no_std]
#![no_main]

use btf_macros::btf_tag;

// Stand-ins for the kernel types the tagged pointers refer to. Only their BTF
// identity matters here.

#[repr(C)]
pub struct task_struct {
    pub pid: i32,
    pub tgid: i32,
}

#[repr(C)]
pub struct cpu_stats {
    pub nr_runs: u64,
    pub nr_migrations: u64,
}

/// One entry of the program's task table.
///
/// Each pointer carries the tag the verifier would need to treat it as
/// something other than plain scalar memory.
#[btf_tag]
#[repr(C)]
pub struct task_slot {
    /// A kernel object reference owned by the map: `BTF_KIND_TYPE_TAG "kptr"`
    /// is what makes `bpf_kptr_xchg()` legal against this field.
    #[btf_tag(type_tag = "kptr")]
    pub task: *mut task_struct,

    /// A per-CPU base pointer, the input to `bpf_per_cpu_ptr()`.
    #[btf_tag(type_tag = "percpu")]
    pub stats: *mut cpu_stats,

    /// Tags chain in source order, exactly as `struct x __rcu __user *p` does
    /// in C: BTFDebug emits PTR -> user -> rcu -> task_slot.
    #[btf_tag(type_tag = "rcu", type_tag = "user")]
    pub peer: *mut task_slot,

    /// Untagged, to show the tag really is per-field and not per-struct.
    pub plain: *mut task_struct,

    pub generation: u64,
}

const EMPTY_SLOT: task_slot = task_slot {
    task: core::ptr::null_mut(),
    stats: core::ptr::null_mut(),
    peer: core::ptr::null_mut(),
    plain: core::ptr::null_mut(),
    generation: 0,
};

/// The table has to reach BTF for its member types to be emitted at all, which
/// means being the type of a live global.
#[used]
#[unsafe(no_mangle)]
pub static mut TASK_TABLE: [task_slot; 8] = [EMPTY_SLOT; 8];

const TABLE_MASK: usize = 7;

/// Keeps every tagged member live so none of them is dropped from debug info.
#[unsafe(link_section = "tp_btf/sched_switch")]
#[unsafe(no_mangle)]
pub extern "C" fn type_tag_entry(ctx: *mut u8) -> i32 {
    // Masking rather than bounds-checking keeps the panic path out of the
    // program: the verifier has no use for an `unreachable`.
    let index = (ctx as usize) & TABLE_MASK;

    unsafe {
        let table = core::ptr::addr_of_mut!(TASK_TABLE).cast::<task_slot>();
        let slot = &mut *table.add(index);

        slot.generation = slot.generation.wrapping_add(1);
        slot.task = ctx.cast::<task_struct>();
        slot.stats = ctx.cast::<cpu_stats>();
        slot.peer = table.add((index + 1) & TABLE_MASK);
        slot.plain = ctx.cast::<task_struct>();

        (*slot.task).pid
    }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static _LICENSE: [u8; 4] = *b"GPL\0";

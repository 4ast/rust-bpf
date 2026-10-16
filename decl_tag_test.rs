//! BTF_KIND_DECL_TAG from Rust.
//!
//! A decl tag annotates a *declaration* -- a struct, one of its members, a
//! global variable, a function, or one function parameter -- rather than a
//! type. It is how a BPF program tells the verifier things like "this global
//! subprog's first argument really is the context pointer" (`arg:ctx`) or
//! "this kfunc does not clobber caller-saved registers" (`bpf_fastcall`).
//!
//! In C these come from `__attribute__((btf_decl_tag("...")))`. rustc has no
//! equivalent, so `#[btf_tag(decl_tag = "...")]` records the request in the
//! `.btf_tags` manifest and `btf_tags.py` attaches the `annotations:` operand
//! to the matching debug-info node just before codegen.
//!
//! For a parameter, BTFDebug reads the position from the DILocalVariable's
//! `arg` field and stores `arg - 1` as the DECL_TAG `component_idx`, so the
//! tag only survives if the parameter still has debug info -- hence
//! `#[inline(never)]` and an exported name on `tagged_subprog`.
//!
//! Expected BTF:
//!
//!     DECL_TAG 'task_table_entry'  type_id=<STRUCT task_slot> component_idx=-1
//!     DECL_TAG 'trusted_ref'       type_id=<STRUCT task_slot> component_idx=0
//!     DECL_TAG 'shared_with_user'  type_id=<VAR SLOT>         component_idx=-1
//!     DECL_TAG 'arg:ctx'           type_id=<FUNC tagged_subprog> component_idx=0
//!     DECL_TAG 'bpf_fastcall'      type_id=<FUNC bpf_get_smp_processor_id>
//!
//! Verify with: bpftool btf dump file bld/decl_tag_test.o

#![no_std]
#![no_main]

use btf_macros::btf_tag;

#[repr(C)]
pub struct task_struct {
    pub pid: i32,
    pub tgid: i32,
}

// A decl tag on the `extern` declaration of a kfunc.
//
// This one is different from all the others: rustc emits no debug info at all
// for a foreign function, so there is nothing to annotate until add_ksyms.py
// synthesises the `.ksyms` DISubprogram. btf_tags.py therefore runs after it.
#[btf_tag]
unsafe extern "C" {
    /// `bpf_fastcall` is the C `__bpf_fastcall`: it lets the verifier skip the
    /// caller-saved spill/fill around this call.
    #[btf_tag(decl_tag = "bpf_fastcall")]
    fn bpf_get_smp_processor_id() -> i32;

    #[btf_tag(decl_tag = "bpf_fastcall")]
    fn bpf_ktime_get_ns() -> u64;
}

/// A tag on the struct itself, and one on a single member.
#[btf_tag(decl_tag = "task_table_entry")]
#[repr(C)]
pub struct task_slot {
    /// `component_idx` 0.
    #[btf_tag(decl_tag = "trusted_ref")]
    pub task: *mut task_struct,

    /// `component_idx` 1. Two tags on one member produce two DECL_TAG records
    /// sharing a `component_idx`.
    #[btf_tag(decl_tag = "monotonic", decl_tag = "reset_on_exec")]
    pub generation: u64,

    pub cpu: i32,
    pub _pad: i32,
}

/// A tag on a global variable.
#[btf_tag(decl_tag = "shared_with_user")]
#[used]
#[unsafe(no_mangle)]
pub static mut SLOT: task_slot = task_slot {
    task: core::ptr::null_mut(),
    generation: 0,
    cpu: -1,
    _pad: 0,
};

/// A tag on a function, plus tags on two of its parameters.
///
/// `arg:ctx` and `arg:nonnull` are the real spellings the verifier looks for
/// on a *global* (non-static) subprog: they are what lets it verify the
/// subprog once against a declared contract instead of re-verifying it at
/// every call site.
#[btf_tag(decl_tag = "a_subprog_tag")]
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn tagged_subprog(
    #[btf_tag(decl_tag = "arg:ctx")] ctx: *mut u8,
    #[btf_tag(decl_tag = "arg:nonnull")] slot: *mut task_slot,
    delta: u64,
) -> i32 {
    unsafe {
        (*slot).generation = (*slot).generation.wrapping_add(delta);
        (*slot).cpu = bpf_get_smp_processor_id();
        (*slot).task = ctx.cast::<task_struct>();
        (*slot).cpu
    }
}

#[unsafe(link_section = "tp_btf/sched_switch")]
#[unsafe(no_mangle)]
pub extern "C" fn decl_tag_entry(ctx: *mut u8) -> i32 {
    let delta = unsafe { bpf_ktime_get_ns() } | 1;
    tagged_subprog(ctx, core::ptr::addr_of_mut!(SLOT), delta)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static _LICENSE: [u8; 4] = *b"GPL\0";

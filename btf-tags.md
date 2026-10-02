# btf_type_tag and btf_decl_tag in rust-bpf

Implemented. Two demo programs — `type_tag_test.rs` and `decl_tag_test.rs` — build
through the normal pipeline and produce real `BTF_KIND_TYPE_TAG` /
`BTF_KIND_DECL_TAG` records.

```
make
bpftool btf dump file bld/type_tag_test.o
bpftool btf dump file bld/decl_tag_test.o
```

## The constraint that decides everything

Both features are debug-info features that rustc has no syntax for and will
never emit:

| feature | what LLVM needs | rustc can emit it? |
|---|---|---|
| `btf_decl_tag` | `annotations: !{!{!"btf_decl_tag", !"x"}}` on `DIGlobalVariable` / `DISubprogram` / `DILocalVariable` (arg) / member `DIDerivedType` / `DICompositeType` | no |
| `btf_type_tag` | `annotations: !{!{!"btf_type_tag", !"x"}}` on the *pointer* `DIDerivedType` | no |

So the approach is the same shape as the existing CO-RE work: **encode the
intent in Rust, decode it in a post-pass.**

## Pieces added

| file | role |
|---|---|
| `btf-macros/src/tags.rs` | `#[btf_tag(...)]`: records tag requests as a manifest |
| `btf_tags.py` | consumes the manifest, writes `annotations:` into the IR, deletes the manifest |
| `Makefile` | `TAG_PROGS`, keep-symbol list, `btf_tags.py` in the ksyms step |

## Source surface

One attribute, `#[btf_tag]`, on a struct, a static, a function, or an `extern`
block. `decl_tag` works everywhere; `type_tag` is fields-only, because a type
tag annotates a pointer type rather than a declaration.

```rust
#[btf_tag(decl_tag = "task_table_entry")]
#[repr(C)]
pub struct task_slot {
    #[btf_tag(type_tag = "kptr")]     task: *mut task_struct,
    #[btf_tag(type_tag = "percpu")]   stats: *mut cpu_stats,
    #[btf_tag(type_tag = "rcu", type_tag = "user")] peer: *mut task_slot,
    #[btf_tag(decl_tag = "monotonic")] generation: u64,
}

#[btf_tag(decl_tag = "a_subprog_tag")]
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn tagged_subprog(
    #[btf_tag(decl_tag = "arg:ctx")] ctx: *mut u8,
    #[btf_tag(decl_tag = "arg:nonnull")] slot: *mut task_slot,
) -> i32 { ... }

#[btf_tag]
unsafe extern "C" {
    #[btf_tag(decl_tag = "bpf_fastcall")] fn bpf_ktime_get_ns() -> u64;
}
```

Repeated `type_tag`s chain in source order, matching C's `int __tag1 __tag2 *p`
(BTFDebug builds `PTR -> tag2 -> tag1 -> base`). `bld/type_tag_test.o` shows the
`__rcu __user` case coming out as `PTR -> TYPE_TAG 'user' -> TYPE_TAG 'rcu'`.

## Manifest protocol

`#[btf_tag]` does not produce annotations. It emits one `#[used]` static per
tag in section `.btf_tags`, holding a NUL-terminated directive:

```text
m|<struct>|<field>|t|<tag>    btf_type_tag on a member's pointer type
m|<struct>|<field>|d|<tag>    btf_decl_tag on a struct member
s|<struct>||d|<tag>           btf_decl_tag on the struct
g|<static>||d|<tag>           btf_decl_tag on a global variable
f|<func>||d|<tag>             btf_decl_tag on a function
a|<func>|<arg index>|d|<tag>  btf_decl_tag on a function parameter
```

Names are debug-info names — a Rust item's plain identifier, not its mangled
symbol — because that is what BTF sees.

## Why the consumer is Python and not bpf-postproc

Two reasons, and they are worth recording because the obvious choice is the
other one:

- **`DISubprogram` drops trailing null operands.** `annotations` is operand 11,
  but rustc sets nothing past `retainedNodes` (operand 7), so a typical
  `DISubprogram` has 8 operands and slot 11 does not exist. `MDNode` operand
  counts are fixed at construction and the LLVM C API cannot grow one, so
  function and parameter tags are unreachable from `bpf-postproc`.
  (`DIDerivedType` and `DICompositeType` are fine — fixed 8 and 16 operands,
  annotations at 7 and 15.)
- **A kfunc has no debug info at all** until `add_ksyms.py` synthesises its
  `.ksyms` `DISubprogram`. `bpf_fastcall` has nothing to attach to before that.

So `btf_tags.py` runs last in the `-ksyms.bc` rule, after both `add_ksyms.py`
passes and immediately before the final `llvm-as`. Since llc derives BTF from
debug info, that is the only point the annotations actually have to exist.

## Type tags need a cloned pointer node

rustc uniques one `!DIDerivedType(DW_TAG_pointer_type, ...)` per pointee type
and shares it across the whole module, so annotating in place would tag every
other `*mut task_struct` too. `btf_tags.py` clones the node under a
distinguishing name and repoints the member at the clone. That is safe because
`BTFTypeDerived::completeType` deliberately drops the names of
PTR/CONST/VOLATILE/RESTRICT types ("naming reference types doesn't bring any
value"), so the synthetic name never reaches BTF. `bld/type_tag_test.o` has a tagged
and an untagged `*mut task_struct` in the same struct to prove it.

## Failure mode

`btf_tags.py` errors out rather than silently emitting nothing, e.g.

```
btf_tags.py: no debug info for function `tagged_subprog`
             (inlined away? mark it #[inline(never)] #[no_mangle])
```

A tagged parameter in particular only survives if the parameter still has a
`DILocalVariable` at codegen time, since BTFDebug takes `component_idx` from
its `arg` field.

## What is left

1. **Loading.** None of this is load-tested — the Makefile stops at `.o`.
2. **`arg:arena`**, the one decl tag with no use here yet. The manifest already
   supports it; there is nothing to point it at until arena globals exist.

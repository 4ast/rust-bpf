# rust-bpf

BPF programs written in plain Rust: `core`, `alloc`, crates from crates.io, no
BPF specific framework. The compiler keeps the data and the stack of a program
in a BPF arena, so that references, `Box`, `Vec`, `BTreeMap`, trait objects,
closures, recursion and unwinding work the way they do everywhere else.

| what | where |
|---|---|
| sched_ext schedulers | `scx_*.rs`. `scx_simple.rs` and `scx_cosmos.rs` stand alone, the others are ports of C schedulers on top of `scx_common.rs`, the counterpart of `scx/common.bpf.h`. The comment at the top of each says what it was ported from, how maps and kptrs were replaced and what was left out |
| tests of `core`, `alloc` and no_std crates | `corpus/tests-bpf/*.rs`, a "syscall" program per test. The same tests are compiled for the host as a control |
| demos | `exc_cleanup.rs` (unwinding), `type_tag_test.rs`, `decl_tag_test.rs` (BTF tags, see `btf-tags.md`) |
| loader | `scxload.c`: attaches everything a scheduler has, not only the struct_ops map, runs its "syscall" programs, reads its ring buffer |
| from bitcode to object | `Makefile`, `corpus/Makefile`, `toolchain.mk`, `add_ksyms.py`, `btf_tags.py`, `bpf-postproc/`, `corpus/bc2obj.sh` |

The schedulers and where they come from:

| | ported from | |
|---|---|---|
| simple, cosmos | | stand alone |
| cpu0, central, flatcg, qmap, pair, sdt | `tools/sched_ext` of the kernel | qmap uses the cid form of the ops |
| bpfland, tickless, beerland, flash, rusty | `scheds/rust` of sched-ext/scx | |
| p2dq, mitosis | the same | the core |
| lavd | the same | a file in `scx_lavd/` per C file |

## What is needed

- LLVM with register r12, the function table for indirect calls and the arena
  passes (`bpf-func-table`, `bpf-arena-data`, `bpf-arena-stack`, features
  `+arena-stack,+arena-data`). Not upstream yet. `llc`, `opt`, `llvm-link`,
  `llvm-as`, `llvm-dis`, `llvm-nm`, `llvm-extract`, `llvm-objcopy`, `llvm-config`
  and the libraries of the components core, bitreader, bitwriter are enough.
- A kernel with the arena stack (r12), casts of any pointer, the verifier pass
  without the limits on instructions, jumps and recursion, and the kfuncs
  `bpf_alloc`, `bpf_free`, `bpf_arena_memcpy`, `bpf_arena_memcmp`. Not upstream
  yet. Its `vmlinux` BTF, `bpftool` and `libbpf` are used at build time.
- A nightly rustc with the `rust-src` component. Tested with nightly-2026-02-27.
- clang (any that knows `may_goto`) for `corpus/shim.c`, python3, a C compiler.

`toolchain.mk` is the one place where tools and flags are named. What differs
from machine to machine goes to `config.mk` next to it, which is not tracked:

    LLVM_PREFIX := /path/to/llvm/build
    CLANG := /path/to/clang
    KSYM_BTF_FILES := /path/to/kernel/build/vmlinux.btf
    BPFTOOL := /path/to/bpftool/of/that/kernel
    LIBBPF := /path/to/dir/with/include/and/libbpf.a
    RUSTC_THREADS := 8
    VM_BIN := /path/to/dir/with/vm-up/vm-ssh/vm-down
    VM_RUN := /path/to/dir/with/PORT/console.log
    VERISTAT := /path/to/veristat/in/the/vm

## Build

    make -j8

builds `bld/*.o` (schedulers and demos), `corpus/bld/one/*.o` (an object per
test), `corpus/bld/*.o` (an object per file of tests), the controls for the host
and the loader `corpus/bld/run`. The crates are copied to `corpus/vendor/` the
first time, from the cache of cargo or from the net. `make progs` and
`make corpus` build one half. The schedulers are rebuilt when `KSYM_BTF_FILES`
names another kernel.

## Run

    ./run-tests.sh KIT PORT        # OUT=dir, default test-out.PORT

boots the kernel in a VM, loads every program of every scheduler, registers each
scheduler that loads completely with `bpftool struct_ops register`, runs a load
on it (24 busy loops, 1500 forks, pinned tasks, a pipe), unregisters it, then
loads and runs the corpus, prints a table and stops the VM. A test that the
kernel ends because it ran for too long returns 77 and counts as failed. It builds nothing and
writes to `OUT` only. The head of the script lists the files and the variables.

By hand: `bpftool struct_ops register bld/scx_flash.o /sys/fs/bpf/scx`, and
`rm -r /sys/fs/bpf/scx /sys/fs/bpf/*_timer*` to get rid of it. The maps with
timers are pinned: the kernel frees the timers of a map that user space has no
reference to, and bpftool exits.

Or `bld/scxload bld/scx_flash.o`, which stays until it is killed. It is needed
for programs that are not struct_ops:

    bld/scxload -e lavd_fexit -e lavd_sched_switch -e lavd_tp_sys_enter_exec \
                -r lavd_introspec_msg -c lavd_introspec_sched_n=100 bld/scx_lavd.o

## Known not to work

- An abort (`abort()`, a panic in a `Drop` during unwinding, a panic in a
  function that cannot unwind) ends in `bpf_throw()`, which the verifier refuses
  while interrupt flags, an RCU section or a reference are held. `add_ksyms.py`
  turns aborts into unwinds where the function may unwind (`TRAP_TO_UNWIND=1`,
  schedulers only). That gets past guards in callers only, hence
  `with_irqs_off()` in `scx_common.rs`, which does not inline its closure.
- A pointer of the kernel (task, cpumask, cgroup) that has been in arena is a
  number to the verifier. The compiler keeps a local that holds one on the BPF
  stack, also when it is what a closure captured and the closure is not inlined.
  Not covered: such a pointer in a `Box`, `Vec` or `BTreeMap`, in an array with a
  variable index, and behind a reference that is itself stored in arena, like a
  parameter that a closure in an iterator captures by reference
  (`PickCtx::allowed` in `scx_lavd/idle.rs` is there for that).
- `memcpy` out of kernel memory: it becomes `bpf_arena_memcpy()`. Read scalars.
- CO-RE accesses (`#[btf]`) are calls that differ in their debug location only.
  LLVM merges them when they sit in two branches or in a closure that is
  instantiated twice (`chain()`), and `bpf-postproc` stops the build.
- A callback (timer) is an `extern "C"` function. A panic that gets to its end
  is an abort, and `bpf_throw()` is not allowed in a callback at all. It is
  enough that the compiler cannot rule a panic out, as with a call through a
  pointer: catch it with `catch_panic!()` of `scx_common.rs`.
- A spin lock in arena does not turn interrupts off. Most ops run with interrupts
  off. Where they are on (ops that can sleep, cgroup ops, fexit programs,
  tracepoints) use `with_irqs_off()`, `TaskMap::get_irqs_on()`: an op that
  interrupts the holder of the lock on its CPU waits for ever.
- Recursion is limited at run time, the arena stack to 32 Kbyte per call chain.
- The failures of the corpus are listed by `run-tests.sh`, grouped by message.

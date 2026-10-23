# Status, October 2026

How much Rust compiles to BPF and runs in the kernel today.

| | |
|---|---|
| sched_ext schedulers | 16, with 225 BPF programs. 16,700 lines of Rust, 387,000 BPF insns. All 225 load. All 16 schedule an 8 CPU VM under load. |
| tests | 437 programs, 909,000 BPF insns. 433 load. 430 return what the same test returns on x86-64. |
| crates | 92 from crates.io, 177 with their dependencies. Not patched. 91 have a test that passes. |
| rustc | nightly from rustup. Not patched. `core` and `alloc` are built from `rust-src`. Not patched. |
| BPF specific source | None in the tests, but for the 10 that call kfuncs and the 2 that abort: the same files are compiled for the host as a control. |

It needs an LLVM and a kernel that are [not upstream yet](#where-the-pieces-are).
How to build and run: [README.md](README.md).

## What it looks like

These are BPF programs that load and run in the kernel.

JSON, `corpus/tests-bpf/k2_text.rs`:

```rust
test!(json_value, {
    let v: serde_json::Value = serde_json::from_str(bb(r#"{"a": [1, {"b": "x"}, null], "n": -3, "t": true}"#)).unwrap();
    check_eq!(v["a"][0].as_u64(), Some(1));
    check_eq!(v["a"][1]["b"].as_str(), Some("x"));
    check!(v["a"][2].is_null() && v["missing"].is_null());
    check_eq!(v["n"].as_i64(), Some(-3));
    check_eq!(v["a"].as_array().map(|a| a.len()), Some(3));
    check_eq!(v.pointer("/a/1/b").and_then(|x| x.as_str()), Some("x"));
    let j = serde_json::json!({"x": bb(1), "y": [true, null]});
    check_eq!(j.to_string(), r#"{"x":1,"y":[true,null]}"#);
});
```

Elliptic curve Diffie-Hellman with the vectors of RFC 7748,
`corpus/tests-bpf/k3_crypto.rs`:

```rust
test!(x25519_rfc7748, {
    use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
    let a = bb(hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    let b = bb(hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    let pa = x25519(a, X25519_BASEPOINT_BYTES);
    let pb = x25519(b, X25519_BASEPOINT_BYTES);
    check_eq!(pa, hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    check_eq!(pb, hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    let k = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    check_eq!(x25519(a, pb), k);
    check_eq!(x25519(b, pa), k);
});
```

The state of a CPU scheduler, `scx_flatcg.rs`, abridged. The original in
`tools/sched_ext` keeps it in what BPF had to offer: a cgroup storage map,
a `bpf_rb_root`, a hash map of kptrs, and `bpf_cgroup_ancestor()` per level:

```rust
static CGV_TREE: SpinLock<BinaryHeap<Reverse<CgvNode>>> = SpinLock::new(BinaryHeap::new());
static CGRP_CTXS: SpinLock<BTreeMap<u64, Arc<CgrpCtx>>> = SpinLock::new(BTreeMap::new());

struct CgrpCtx {
    cgid: u64,
    parent: Option<Arc<CgrpCtx>>,
    weight: AtomicU32,
    hweight: AtomicU64,
    stash: SpinLock<Option<CgvNode>>,
    ...
}

impl CgrpCtx {
    /// This cgroup and its ancestors, the root last.
    fn path_to_root(&self) -> impl Iterator<Item = &CgrpCtx> {
        iter::successors(Some(self), |cgc| cgc.parent.as_deref())
    }
}
```

## Before and after

What a BPF program could do before this work, and what it can do now. The
limits on the left are those of the insn set, the LLVM backend and the verifier.
They hold for every language that is compiled to BPF, Rust included. What lifts
them is [in LLVM and in the kernel](#what-it-took), not in rustc. Rust is what
it is measured with.

| | before | after |
|---|---|---|
| state | in maps: hash, array, per-CPU array, task and cgroup storage, queue, rbtree, kptr | in global data and on the heap: `static`, `BTreeMap`, `Vec`, `VecDeque`, `BinaryHeap`, `Arc`, `Box`. Maps are left for what the kernel has to find: timers and ring buffers. |
| pointers | a pointer to arena is in a different address space, and the source has to say so: `__arena` | one kind of pointer. The compiler inserts the casts. |
| stack | 512 bytes, 2 Kbyte in bpf-next | locals whose address is taken go to a stack in arena, 32 Kbyte per call chain |
| loops | bounded in a way that the verifier can see, or written with `bpf_for`, `bpf_loop()`, `can_loop` | any loop that has an exit |
| recursion | rejected | allowed, limited at run time |
| calls | direct. `callx` is new in bpf-next. | function pointers, `&dyn Trait`, `Box<dyn Fn>`, vtables in static data |
| arguments | 5, 12 in bpf-next | 24. The helpers of `derive(Debug)` take up to 23 registers worth. |
| cleanup | the source has an error path for every acquire, or the verifier complains. Unwinding is new in bpf-next. | `Drop` releases references, RCU sections and interrupt flags on every path, a panic included. |
| bounds | the program has to convince the verifier that an index is in bounds | the bounds check is in the code. When it fails it panics. `panic!`, `unwrap()` and overflow checks unwind through landing pads, and a panic can be caught. |
| size | 1 million insns and 8192 pending jumps per program for the verifier | no such limits. The largest program has 98,169 insns and 620 functions. |
| arithmetic | no floats, no 128 bit division | soft float, `u128`/`i128`, libm, from `compiler_builtins` |

## The language, core and alloc

253 tests (`corpus/tests-bpf/c_*.rs`, `a_*.rs`).

| | what is tested | tests |
|---|---|---|
| integers | every width up to 128 bit: checked, wrapping, saturating, overflowing, division, shifts, bits, `parse` | 15 |
| the language | `Option`, `Result` and `?`, enums, `match`, generics, const generics, traits, `dyn`, closures, operators | 11 |
| iterators, slices, `str`, `char` | adaptors, `try_fold`, `sort_unstable`, `select_nth_unstable`, binary search, `chunks`, `windows`, `rotate`, UTF-8, Unicode tables, `split`, `parse` | 37 |
| `core::fmt` | `Display`, `Debug`, `derive(Debug)`, `{:#?}`, radix, width, precision, 128 bit, `dyn` | 12 |
| memory | `mem`, `ptr`, `Cell`, `RefCell`, `MaybeUninit`, unions, packed structs, `Pin`, `Any`, big locals | 16 |
| atomics | `u8` to `u64`, `bool`, pointers, fences, a spin lock | 14 |
| floats | `f32`, `f64`, conversions, `Display`, `FromStr`, libm | 10 |
| panics | where they come from, what they unwind through, `Drop` order, nested `catch`, out of memory, aborts | 18 |
| recursion | factorial, Fibonacci, Ackermann, Hanoi, mutual, through `dyn`, trees, quicksort, a recursive descent parser, unwinding through 100 frames | 33 |
| `async`/`await` | state across `await`, cancelled futures, boxed recursion, `Arc` and raw wakers, a round robin executor, a channel | 8 |
| calling conventions | 16 arguments, `u128` arguments, structs by value, hidden result pointers, `extern "C"`, `dyn` | 13 |
| `core::hash`, `Duration`, `Error`, conversions, statics | | 13 |
| `Vec`, `String`, `format!`, `Cow` | | 22 |
| `BTreeMap`, `BTreeSet`, `VecDeque`, `BinaryHeap`, `LinkedList` | | 19 |
| `Box`, `Rc`, `Weak`, `Arc`, trait objects and closures on the heap | | 12 |

## Crates

142 tests (`k_*.rs`, `k2_*.rs`, `k3_*.rs`). Versions are in
`corpus/Cargo.lock`. Expected values of hashes and ciphers come from RFCs, FIPS
documents and python's hashlib.

| | crates |
|---|---|
| maps and sets | hashbrown, indexmap, lru, rpds (persistent), slotmap, slab, priority-queue |
| small and fixed size collections | smallvec, arrayvec, tinyvec, heapless, smol_str |
| pointers and arenas | intrusive-collections, typed-arena, bumpalo, bytes, bytemuck, zerocopy |
| bits and bytes | bitflags, fixedbitset, bitvec, byteorder, memchr |
| iterators | itertools, either |
| hashes and checksums | fnv, ahash, rustc-hash, hash32, siphasher, xxhash-rust, crc, crc32fast, adler2 |
| cryptography | sha1, sha2, sha3, md-5, blake2, hmac, aes, chacha20, chacha20poly1305, x25519-dalek |
| random numbers | rand, rand_core, rand_chacha, rand_pcg, rand_xoshiro |
| numbers | num-traits, num-integer, num-bigint, num-rational, fixed, libm, glam, nalgebra |
| numbers and text | itoa, ryu, lexical-core, hex, base64 |
| parsers | nom, winnow, logos, aho-corasick, regex-automata |
| serialization | serde (derive), serde_json, postcard, minicbor |
| text | unicode-segmentation, unicode-normalization, uuid, semver, chrono |
| compression | lz4_flex, miniz_oxide (inflate) |
| networking | etherparse, smoltcp |
| graphs | petgraph: Dijkstra, DFS, BFS, topological sort, strongly connected components |
| synchronization | spin, once_cell, crossbeam-queue, scopeguard |
| async | futures-util |
| errors and macros | thiserror, anyhow, derive_more, strum, num_enum, static_assertions |

13 small programs without crates (`p_algo.rs`): sieve, matrix multiplication,
edit distance, KMP, N queens, Dijkstra, flood fill, union-find, factorial of
a big number, word count, an RPN calculator, run length and base64 coding, an LRU
cache.

13 negative controls (`x_control.rs`) compute what other tests compute and
compare with a value that is off by a bit. All 13 fail in the line they are
supposed to fail in.

The largest programs:

| test | BPF insns | insns the verifier processed |
|---|---|---|
| regex_automata | 98,169 | 289,661 |
| aho_corasick | 39,674 | 110,028 |
| num_bigint_rational | 25,418 | 109,852 |
| json_deserialize | 17,557 | 48,471 |
| chrono_dates | 13,769 | 48,849 |
| uuid_semver | 12,543 | 31,413 |
| fmt_debug_std_types | 12,080 | 31,616 |

## Schedulers

`scx_simple.rs` and `scx_cosmos.rs` stand alone. The other 14 are ports of C
schedulers on top of `scx_common.rs` (1,389 lines), the counterpart of
`scx/common.bpf.h`. The head of each file lists what became what and what was
left out.

| | from | Rust lines | programs | BPF insns | verifier, ms | what it uses |
|---|---|---|---|---|---|---|
| simple | | 375 | 8 | 6,186 | 42 | `BTreeMap` |
| cosmos | sched-ext/scx | 1,213 | 14 | 8,841 | 61 | `BTreeMap`, arrays, 28 tunables and tables for user space |
| cpu0 | tools/sched_ext | 86 | 5 | 135 | 1 | |
| central | tools/sched_ext | 366 | 7 | 3,712 | 48 | `SpinLock<VecDeque>`, `Vec` sized in `ops.init()` |
| flatcg | tools/sched_ext | 713 | 15 | 18,809 | 277 | `BTreeMap<u64, Arc<CgrpCtx>>`, `BinaryHeap`, recursion down the cgroup tree |
| pair | tools/sched_ext | 475 | 7 | 9,857 | 169 | `Vec<SpinLock<PairCtx>>`, `enum Outcome` |
| sdt | tools/sched_ext | 368 | 8 | 10,648 | 283 | a generic radix tree allocator: `Node<T>`, `enum Entries<T>`, recursion |
| qmap | tools/sched_ext | 1,482 | 23 | 84,008 | 730 | cid form of the ops, sub-schedulers, `BTreeMap` FIFOs, a table of timer functions |
| bpfland | sched-ext/scx | 827 | 13 | 17,786 | 182 | `TaskMap`, `CpuSet`, `Option<Box<CpuSet>>` |
| tickless | sched-ext/scx | 488 | 14 | 12,596 | 166 | `DsqIter` as an `Iterator`, `Vec` sorted by capacity |
| beerland | sched-ext/scx | 655 | 14 | 15,895 | 147 | `Vtime` whose `Ord` wraps |
| flash | sched-ext/scx | 765 | 17 | 34,094 | 261 | `trait Policy`, used through `&dyn Policy` |
| rusty | sched-ext/scx | 1,121 | 14 | 30,166 | 321 | `Vec<Domain>`, 128 bit running averages, `Result` and `?` |
| p2dq | sched-ext/scx, the core | 1,392 | 12 | 22,186 | 225 | `enum Promise` with data, `BTreeMap<(vtime, pid), ()>`, function pointers |
| mitosis | sched-ext/scx, the core | 969 | 17 | 45,401 | 670 | `Arc<Config>` swapped as a whole, `Vec<Vec<Match>>`, `String`, `core::fmt` in `ops.dump()` |
| lavd | sched-ext/scx | 3,990 | 37 | 66,733 | 847 | a Rust module per C file, fexit and tracepoint programs, a ring buffer |

All 225 programs are verified in 4.4 seconds together.

There is no user space part. What the loader of the original provides
(topology, domains, tunables) is probed or computed in `ops.init()`.
`scxload -s` sets a tunable.

Each scheduler is registered with `bpftool struct_ops register`, gets a load of
24 busy loops, 1,500 forks, pinned tasks and a pipe, and is unregistered. All
16 stay enabled, no invocation of a program is missed, the console stays clean.

A check that a scheduler does what it is for: scx_pair with 2 cgroups of 6 busy
loops each. In 300 samples of what all CPUs run, the two CPUs of a pair were
seen in different cgroups 0 times. Without the scheduler 287 times.

A scheduler ends when one of its programs is unwound. The entry of every program
holds a guard whose `Drop` calls `scx_bpf_error()`: the kernel disables the
scheduler and hands the tasks back to the fair class. Injected into scx_qmap
under load:

| | without the guard | with it |
|---|---|---|
| `panic!` in `ops.enqueue()` | "runnable task stall" after 5 s | "qmap_enqueue was unwound" at once |
| a loop in `ops.enqueue()` that does not end | "runnable task stall" after 5 s | "qmap_enqueue was unwound" after 250 ms |
| `panic!` in the callback of a timer | stays enabled with a dead timer | "timer_cb was unwound" at once |

## How a test runs

```
tests-bpf/*.rs ── cargo + rustc ──> bitcode of the test, the crates, core, alloc
   llvm-link        one module, only what the test needs
   opt -O2          internalize, inline, remove what is dead. No function is nounwind.
   link-builtins.sh soft float, 128 bit division, libm, as far as llc asks for them
   opt              bpf-func-table, bpf-arena-data, bpf-arena-stack
   add_ksyms.py     kfuncs get prototypes from the BTF of the kernel, aborts unwind
   fix-protos.py    BTF prototypes of functions from their IR signature
   llc              -mcpu=v4 -mattr=+arena-stack,+arena-data
   corpus/run       libbpf loads the program, BPF_PROG_TEST_RUN runs it
```

A test is a "syscall" program. It returns 0, the line of the check that
failed, 100000 + the line of a panic, or 200000 + the number of allocations that
were not freed. So every test is a leak test too.

The same file is compiled for x86-64 and run there. A test counts when it
returns what is expected on both. A test that the kernel cuts short counts as
failed whatever it returns: the kernel marks the program.

`./run-tests.sh` boots a VM, does all of the above for the 16 schedulers and
the 437 tests in about 6 minutes and prints the tables that the numbers here
are from.

## What it took

### Compiler

LLVM BPF backend, on top of LLVM 24.

- **r12, a stack in arena.** A local whose address is taken cannot stay on the
  BPF stack: the stack is small, and a pointer to it that is stored in arena
  comes back as a number. `bpf-arena-stack` moves such locals to
  a second stack. The prologue is `r12 += N`, a local is `*(u64 *)(r12 - 8)`.
- **Global data in arena.** `bpf-arena-data` puts `static`s, string literals and
  vtables there. Pointers between them are relocated by libbpf.
- **One kind of pointer.** Rust has no address spaces. The backend inserts
  `addr_space_cast` where a pointer is dereferenced.
- **A table of functions.** Vtables and closures are in arena, and what is loaded
  from arena is a number. With `bpf-func-table` a pointer to a function is the
  index of the function in a read-only table. An indirect call is `callx`
  through the table, with the index clamped to the functions of the type of the
  call.
- **Unwinding.** Two insns. `call f; unwind_goto pad` goes to the landing pad
  when f left with `unwind_exit` and falls through when it left with `exit`. No
  register says which one it was, and the normal path costs nothing.
  `_Unwind_RaiseException` starts an unwind, like on other architectures.
  A landing pad is ordinary code for the verifier: one that forgets to drop
  a lock is a leak on that path.
- **Arguments.** r1-r5, then slots of r11.
- **Pointers of the kernel.** A task or a cpumask is a pointer for the verifier
  while it is in a register or on the BPF stack. In arena it is a number.
  `bpf-arena-kptr` keeps the locals that hold one on the BPF stack, closure
  environments included. 7 of the 10 tests in `z_kptr.rs` pass.
- 7 fixes that are not about Rust: jump tables in position independent code,
  a switch with an unreachable default, atomic operations that have no insn,
  and others.

### Kernel

- **The arena stack.** Every CPU has a stack in the arena of the program.
  A program claims it at entry with one CPU-local `fetch_add` and releases
  it with a store: 0.7 ns per invocation. A program that interrupts or
  preempts another one takes a spare stack.
- **Casts of any pointer.** Generic code is compiled once and gets pointers
  to arena, to the context, to map values and to the stack. `addr_space_cast` of
  what is not a pointer to arena is a move. NULL stays NULL.
- **A new main pass of the verifier.** The current one walks every path and
  prunes. It loads 7 of the 20 programs of scx_simple and scx_cosmos. 12 stop at
  the first loop over a `BTreeMap`: "The sequence of 8193 jumps is too complex".
  The new pass is a fixpoint over the control flow graph. States that meet are
  joined.
  - No limit on insns and jumps.
  - A static function is verified for the states at its entry, not for every
    chain of calls that leads to it.
  - Loops: scalar evolution counts them. What it cannot count is walked for
    a while. The rest gets a `may_goto` that the verifier inserts.
    Termination is not proved. A loop without an exit is rejected.
  - Recursion is allowed. The verifier inserts a check of the stack that is
    left: 4 Kbyte for recursive frames.
  - 1024 functions per program, 32 call frames, 24 arguments of a static function.
  - C programs gain too. Of the 3,597 programs of the kernel selftests that the
    current verifier loads it loses 1. It loads 19 more, and processes 2.2
    million insns instead of 5.2 million.
- **A program that runs out of budget is unwound.** It cannot just stop: what it
  holds has to be released. The function with the loop or the recursion leaves
  with `unwind_exit`, the landing pads of the callers run, and the program
  returns 0. No return value is right for every kind of program, so the kernel
  marks the program as unwound in `struct bpf_prog_info` and user space has to
  act. Its stderr stream says why, with Rust source lines:

  ```
  ERROR: No room in the stack for a call of a recursive function
  bpf_prog_a81793565f7e0c47_sum_to+0x57/0x166
    fn sum_to(n: u64) -> u64 { @ c_deep.rs:14
  bpf_prog_a81793565f7e0c47_sum_to+0xd8/0x166
    bb(sum_to(bb(n - 1))) + n @ c_deep.rs:18
  ```

  There is no landing pad for a loop in a function that holds a reference,
  an RCU section or interrupt flags itself. Such a loop is left. Of the 3,414
  `may_goto` that the verifier added to the 225 programs of the schedulers 71 are
  of that kind.
- `bpf_alloc()`, `bpf_free()`: the heap. `bpf_arena_memcpy()`,
  `bpf_arena_memcmp()`.

### This repository

- `core` and `alloc` from `rust-src` for the target `bpfel-unknown-none-v4`.
  cargo for the crates: features, build scripts and proc macros work as usual.
- The real `compiler_builtins`, with wrappers for the one place where the
  `extern "C"` of rustc and the calls that LLVM makes disagree: 128 bit values.
- `#[btf]` and `bpf-postproc`: CO-RE relocations for fields of kernel structs.
- `add_ksyms.py`: kfunc prototypes from kernel BTF, names that are too long for
  BTF, aborts that unwind.
- No function is `nounwind`. The kernel can unwind a function when `unwind_goto`
  follows every call of it, so LLVM must not conclude that a function without
  a panic in it cannot unwind: the callers would lose their landing pads. It
  costs 1.0% more insns in the schedulers and 0.5% in the tests.
- No `bpf_throw()`. It is refused while something is held, and the compiler
  cannot see where that is.
- BTF prototypes from the IR signature. Debug info describes the source, the code
  follows the Rust ABI: hidden result pointers, pairs in two registers, no
  register for a zero sized argument.

## What does not work yet

7 of the 437 tests:

- 3 run out of the 4 Kbyte for recursive frames at run time: `sum_to(128)`,
  `sum_to(1000)`, regex-automata.
- 3 keep a pointer of the kernel where the verifier loses it: `[Task; 4]` with
  a variable index, one method behind a vtable called on an object on the stack
  and on one on the heap, `Box<Task>`.
- `miniz_oxide::deflate` does not compile: 65 Kbyte of locals in one function.

And:

- An abort (`abort()`, a panic in a function that must not unwind) unwinds. The
  frames that have no landing pad for the call are skipped: their `Drop` impls
  do not run. A frame that holds something that the kernel knows about has to
  have one, or the verifier rejects the program.
- CO-RE covers offsets of fields. kfuncs are declared by hand and are not weak,
  `SCX_*` constants are written down, not read from BTF.
- The schedulers are ports of the BPF side. p2dq and mitosis are the core only.
  None was compared with its C original for performance.
- x86-64 only. The arm64 JIT changes compile and were not run.
- `std` is out of scope: no files, threads or sockets in a BPF program.

The list with details: [README.md](README.md#known-not-to-work).

## Where the pieces are

| | |
|---|---|
| `callx`, 12 arguments, 16 call frames, unwinding, scalar evolution | in bpf-next |
| arena stack (r12), casts of any pointer, data in arena, libbpf side | patches, not upstream yet |
| the new verifier pass, recursion, 24 arguments, 32 call frames, programs that are unwound and marked, `bpf_alloc()` | experimental, not upstream yet |
| LLVM: r12, the arena passes, the function table, 7 fixes | patches, not upstream yet |
| everything else | here |

## The commits behind this file

| commits | |
|---|---|
| 1-7 | fixes: `bpf-postproc` builds with LLVM 24, `toolchain.mk`, long names in BTF, `unreachable` blocks, aborts that unwind, `memset` and `__multi3` |
| 8-9 | all memory of a scheduler goes to arena |
| 10-11 | `scx_common.rs`, `scxload` |
| 12-17 | cpu0, central, flatcg, pair, sdt, qmap from `tools/sched_ext` |
| 18-25 | bpfland, tickless, beerland, flash, rusty, p2dq, mitosis, lavd from sched-ext/scx |
| 26 | the harness of the corpus |
| 27-34 | the language, core, floats, panics, recursion, async, calling conventions, alloc, small programs |
| 35-37 | 38 + 38 + 16 crates |
| 38-39 | negative controls, pointers of the kernel that go through memory |
| 40-41 | `run-tests.sh`, `README.md` |
| later | programs return what their body returns, tunables are exported, panics print to stderr, aborts unwind, no `bpf_throw()`, no `nounwind`, a scheduler ends when one of its programs is unwound |

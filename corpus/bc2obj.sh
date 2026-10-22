#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# bc2obj.sh LINKED.bc OUT.o PROG...
#
# From the bitcode of a test file with its libraries to an object with the
# programs that are named. The steps are those of ../Makefile plus the arena
# passes and compiler_builtins.
#
# env: LLVM_PREFIX, BLDDIR (builtins.bc, shim.bc), TOP (add_ksyms.py),
#      LLC_ATTR, ARENA_PASSES, OPT_ARGS (for the opt that runs them), O2_ARGS (for the opt that optimizes),
#      KEEP_TMP=1 to keep the intermediate files,
#      NO_FIX_PROTOS=1 to leave the prototypes in BTF as rustc describes them
set -e
in=$1; out=$2; shift 2
: ${LLVM_PREFIX:?} ${BLDDIR:?} ${TOP:?}
B=$LLVM_PREFIX/bin
t=${out%.o}
here=$(cd $(dirname $0) && pwd)
LLC_ATTR=${LLC_ATTR-+arena-stack,+arena-data}
ARENA_PASSES=${ARENA_PASSES-bpf-func-table,bpf-arena-data,function(bpf-arena-stack)}
# A copy of a small function per vtable that it is called with: the calls through the vtable are direct then.
O2_ARGS=${O2_ARGS--funcspec-on-address -funcspec-min-function-size=1}
export TRAP_TO_BPF_THROW=1

keep=--internalize-public-api-list=_LICENSE
for p in "$@"; do keep="$keep --internalize-public-api-list=$p"; done

# keep the programs and the license, optimize
$B/opt $keep --force-remove-attribute=cold $O2_ARGS \
	-passes='forceattrs,internalize,globaldce,default<O2>' $in -o $t-opt.bc

# what llc is going to call
LLVM_PREFIX=$LLVM_PREFIX $here/link-builtins.sh $t-opt.bc $BLDDIR/builtins.bc $t-full.bc

# memcpy and co, locals and data to arena.
# shim.bc after O2: nothing refers to bpf_arena_memcpy until add_ksyms.py.
# internalize after the last link: llvm-link drops a static function that
# nothing refers to, and nothing refers to __udivti3 until llc.
$B/llvm-link $t-full.bc $BLDDIR/shim.bc -o $t-shim.bc
$B/opt -mtriple=bpfel $keep $OPT_ARGS -passes="internalize,$ARENA_PASSES" $t-shim.bc -o $t-arena.bc

$B/llvm-dis $t-arena.bc -o $t.ll
python3 $TOP/add_ksyms.py $t.ll $t.ll
$here/fix-dbgloc.py $t.ll $t.ll
$B/opt -passes=simplifycfg -S $t.ll -o $t.2.ll
python3 $TOP/add_ksyms.py $t.2.ll $t.2.ll
$here/fix-dbgloc.py $t.2.ll $t.2.ll
[ -n "$NO_FIX_PROTOS" ] || $here/fix-protos.py $t.2.ll $t.2.ll
$B/llvm-as $t.2.ll -o $t-ksyms.bc

# Locals are in arena, registers are spilled to the BPF stack: the verifier
# has to know what is in them. 2048 is what the kernel takes with JIT.
$B/llc -march=bpfel -mcpu=v4 ${LLC_ATTR:+-mattr=$LLC_ATTR} -bpf-allows-libcalls -bpf-stack-size=2048 -filetype=obj -o $t.tmp.o $t-ksyms.bc
$B/llvm-objcopy --remove-section=.eh_frame --remove-section=.rel.eh_frame \
	--remove-section=.gcc_except_table --strip-symbol=rust_eh_personality $t.tmp.o $out
rm -f $t.tmp.o $t.ll $t.2.ll $t-shim.bc
[ -n "$KEEP_TMP" ] || rm -f $t-opt.bc $t-full.bc $t-arena.bc $t-ksyms.bc

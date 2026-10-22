#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# link-builtins.sh IN.bc BUILTINS.bc OUT.bc
#
# Calls to __udivti3, __adddf3 and the like don't exist in the IR: llc makes
# them. So compile, look at what is undefined, take that from compiler_builtins
# and repeat, since the functions that were added have needs of their own.
# memcpy and co are left alone: see shim.c.
set -e
in=$1; builtins=$2; out=$3
tmp=$out.tmp
: ${LLVM_PREFIX:?}
B=$LLVM_PREFIX/bin

$B/llvm-nm --defined-only $builtins | awk '{print $3}' |
	grep -vxE 'memcpy|memmove|memset|memcmp|bcmp' | sort -u > $tmp.have
cp $in $tmp.bc
for i in 1 2 3 4 5 6; do
	# locals are on the BPF stack here
	$B/llc -march=bpfel -mcpu=v4 -bpf-allows-libcalls -bpf-stack-size=1000000000 -filetype=obj -o $tmp.o $tmp.bc
	need=$($B/llvm-nm -u $tmp.o | awk '{print $2}' | sort -u | comm -12 - $tmp.have)
	[ -z "$need" ] && break
	{
		$B/llvm-dis $tmp.bc -o - | grep -m2 -E '^target (datalayout|triple)'
		# a declaration that nobody uses doesn't survive the link
		for n in $need; do echo "declare void @$n()"; done
		echo "define void @__need() {"
		for n in $need; do echo "  call void @$n()"; done
		echo "  ret void"
		echo "}"
	} > $tmp.ll
	$B/llvm-link $tmp.bc $tmp.ll -o $tmp.2.bc
	$B/llvm-link --only-needed $tmp.2.bc $builtins -o $tmp.3.bc
	$B/llvm-extract --delete --func=__need $tmp.3.bc -o $tmp.bc
done
mv $tmp.bc $out
rm -f $tmp.*

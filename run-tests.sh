#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# run-tests.sh KIT PORT
#
# Boots the kernel in KIT in a VM on PORT, then
# - loads every program of every scheduler (veristat), registers each scheduler
#   that loads completely with `bpftool struct_ops register`, puts load on the
#   machine, unregisters it and looks at what the kernel said,
# - loads and runs every test of corpus/,
# prints a summary and stops the VM.
#
# It runs what `make` has built and builds nothing. Everything it writes goes to
# the directory OUT (default: test-out.PORT), so two runs with different ports
# and directories don't get in each other's way.
#
#   OUT/summary.txt         what is printed at the end
#   OUT/sched.tsv           a line per program: verdict, insns, time, message
#   OUT/sched/NAME.run      the run of a scheduler
#   OUT/sched/NAME.PROG.log end of the verifier's log of a rejected program
#   OUT/corpus.tsv          a line per test, columns below
#
# env: OUT, ONLY=sched|corpus, SCHEDS="scx_a scx_b", TESTS="c_int k_map" (files of
#      corpus/tests-bpf), TMO (seconds per test, 60)
# VM_BIN, VM_RUN, VERISTAT and BPFTOOL are those of toolchain.mk and config.mk.
TOP=$(cd "$(dirname "$0")" && pwd)
KIT=${1:?usage: run-tests.sh KIT PORT}; PORT=${2:?usage: run-tests.sh KIT PORT}
OUT=${OUT:-$TOP/test-out.$PORT}
var() { make -s --no-print-directory -C "$TOP" -f toolchain.mk -f - print <<< "print: ; @echo \$($1)"; }
VM_BIN=$(var VM_BIN); VM_RUN=$(var VM_RUN); VERISTAT=$(var VERISTAT); BPFTOOL=$(var BPFTOOL)
[ -x "$VM_BIN/vm-up" ] || { echo "VM_BIN is not set, see toolchain.mk" >&2; exit 1; }
C=$TOP/corpus
ssh() { "$VM_BIN/vm-ssh" "$PORT" "$@"; }
# push DIR FILE... : to /tmp/t in the VM
push() { local d=$1; shift; tar -C "$d" -cf - "$@" | ssh 'mkdir -p /tmp/t && tar -C /tmp/t -xf -'; }
bad_lines() { local n=$(sudo -n grep -c 'WARNING:\|Oops\|BUG:\|panic -\|RCU.*stall\|lockup' "$VM_RUN/$PORT/console.log" 2>/dev/null); echo ${n:-?}; }

rm -rf "$OUT"; mkdir -p "$OUT/sched" "$OUT/corpus" || exit 1
SUM=$OUT/summary.txt

# The prototypes of the kfuncs in the programs are copies from a BTF file.
if [ -f "$KIT/bld_x64/vmlinux.btf" ] &&
   [ "$(cksum < "$KIT/bld_x64/vmlinux.btf")" != "$(cut -d' ' -f1,2 "$TOP/bld/.ksyms-btf")" ]; then
	echo "The programs were not built for the kernel in $KIT (or it was rebuilt since):" >&2
	echo "make KSYM_BTF_FILES=$KIT/bld_x64/vmlinux.btf" >&2
	exit 1
fi

"$VM_BIN/vm-down" "$PORT" > /dev/null 2>&1
trap '"$VM_BIN/vm-down" "$PORT" > /dev/null 2>&1' EXIT
"$VM_BIN/vm-up" "$KIT" "$PORT" 8 16384 > "$OUT/vm-up.log" 2>&1 || { cat "$OUT/vm-up.log" >&2; exit 1; }
echo "kit $KIT, uname $(ssh uname -r), sources $(git -C "$TOP" log --oneline -1 | cut -c1-7)$(git -C "$TOP" diff --quiet || echo +), $(date -u '+%F %H:%M')" | tee "$SUM"
BAD0=$(bad_lines)

# ── schedulers ───────────────────────────────────────────────────────

cat > "$OUT/sched/load.sh" <<'EOF'
# load.sh NAME: register /tmp/t/NAME.o, load the machine, unregister
s=$1; BT=/tmp/t/bpftool
echo 1 > /proc/sys/kernel/bpf_stats_enabled
dmesg -C
rm -rf /sys/fs/bpf/scx /sys/fs/bpf/*_timer*; mkdir -p /sys/fs/bpf/scx
if ! $BT struct_ops register /tmp/t/$s.o /sys/fs/bpf/scx > /tmp/reg.out 2>&1; then tail -3 /tmp/reg.out; echo "RESULT register failed"; exit; fi
sleep 1
a=$(cat /sys/kernel/sched_ext/state)
for i in $(seq 24); do (timeout 12 sh -c 'while :; do :; done' &) ; done
w=$(timeout 40 sh -c 'n=0; while [ $n -lt 1500 ]; do /bin/true; n=$((n+1)); done; dd if=/dev/zero of=/dev/null bs=1M count=8000 2>/dev/null; for i in 0 1 2 3 4 5 6 7; do taskset -c $i /bin/true; done; seq 200000 | sort -n | tail -1')
sleep 3
b=$(cat /sys/kernel/sched_ext/state); ops=$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null)
$BT -j prog show 2>/dev/null | python3 -c '
import json,sys
ps=[p for p in json.load(sys.stdin) if p.get("type")=="struct_ops"]
print("STATS runs %d misses %d" % (sum(p.get("run_cnt",0) for p in ps), sum(p.get("recursion_misses",0) for p in ps)))
for p in sorted(ps,key=lambda p:-p.get("run_cnt",0)):
    if p.get("run_cnt"): print("  %-28s %9d runs %7.0f ns each" % (p["name"],p["run_cnt"],p["run_time_ns"]/p["run_cnt"]))'
rm -rf /sys/fs/bpf/scx; sleep 1
c=$(cat /sys/kernel/sched_ext/state)
rm -f /sys/fs/bpf/*_timer*
pkill -x timeout; sleep 1
dmesg | grep -v audit | grep -i 'sched_ext\|BUG\|WARN\|Oops\|stall\|lockup' | cut -c1-160 | head -12
r=ok
[ "$a" = enabled ] && [ "$b" = enabled ] && [ "$c" = disabled ] && [ "$w" = 200000 ] || r="state $a/$b/$c work=$w"
dmesg | grep -q 'disabled (unregistered from user space)' || r="$r, not unregistered from user space"
[ "$(cat /sys/kernel/sched_ext/nr_rejected)" = 0 ] || r="$r, nr_rejected"
echo "RESULT $r"
EOF

if [ "$ONLY" != corpus ]; then
	[ -n "$SCHEDS" ] || SCHEDS=$(cd "$TOP/bld" && ls scx_*.o | sed 's/\.o$//')
	cp "$BPFTOOL" "$OUT/sched/bpftool"
	push "$OUT/sched" bpftool load.sh
	push "$TOP/bld" $(for s in $SCHEDS; do echo $s.o; done)
	printf '%-14s %5s %6s %12s %9s  %-28s %9s %7s  %s\n' scheduler progs loaded insns_walked verif_ms worst_program runs misses under_load | tee -a "$SUM"
	: > "$OUT/sched.tsv"
	for s in $SCHEDS; do
		ssh "rm -f /sys/fs/bpf/*_timer*; $VERISTAT -o csv -e file,prog,verdict,duration,insns,states,prog_size /tmp/t/$s.o 2>/dev/null; rm -f /sys/fs/bpf/*_timer*" |
			awk -F, -v OFS='\t' 'NR>1 && NF>=7 {sub(/\.o$/,"",$1); print $1,$2,$3,$4,$5,$6,$7}' > "$OUT/sched/$s.tsv"
		while IFS=$'\t' read -r f p v rest; do
			msg=
			if [ "$v" != success ]; then
				ssh "$VERISTAT -v -l1 -f $p /tmp/t/$s.o 2>&1 | grep -v '^subprog\|^processed\|^verification time\|^stack depth\|^\$\|^File\|^---\|^Done\|^$s' | tail -60; rm -f /sys/fs/bpf/*_timer*" < /dev/null > "$OUT/sched/$s.$p.log"
				msg=$(grep -B3 '^Verification failed' "$OUT/sched/$s.$p.log" | grep -v '^$\|^Verification\|^;' | tail -1)
				[ -n "$msg" ] || msg=$(tail -1 "$OUT/sched/$s.$p.log")
			fi
			printf '%s\t%s\t%s\t%s\t%s\n' "$f" "$p" "$v" "$rest" "${msg:0:160}"
		done < "$OUT/sched/$s.tsv" >> "$OUT/sched.tsv"
		n=$(wc -l < "$OUT/sched/$s.tsv"); ok=$(awk -F'\t' '$3=="success"' "$OUT/sched/$s.tsv" | wc -l)
		runs=-; misses=-; res="not tried"
		if [ "$n" -gt 0 ] && [ "$n" = "$ok" ]; then
			ssh "sh /tmp/t/load.sh $s" < /dev/null > "$OUT/sched/$s.run" 2>&1
			runs=$(awk '/^STATS/{print $3}' "$OUT/sched/$s.run"); misses=$(awk '/^STATS/{print $5}' "$OUT/sched/$s.run")
			res=$(sed -n 's/^RESULT //p' "$OUT/sched/$s.run")
		fi
		printf '%-14s %5d %6d %12d %9d  %-28s %9s %7s  %s\n' "${s#scx_}" "$n" "$ok" \
			$(awk -F'\t' '{i+=$5; t+=$4; if ($5>=m) {m=$5; w=$2}} END {printf "%d %d %s", i, t/1000, w}' "$OUT/sched/$s.tsv") \
			"${runs:--}" "${misses:--}" "${res:-no result}" | tee -a "$SUM"
	done
	awk -F'\t' '{n++; if ($3=="success") ok++; i+=$5; t+=$4} END {printf "schedulers: %d of %d programs load, %d insns walked, %.1f s of verification\n", ok, n, i, t/1e6}' "$OUT/sched.tsv" | tee -a "$SUM"
	awk -F'\t' '$3!="success" {printf "  %s %s: %s\n", $1, $2, $8}' "$OUT/sched.tsv" | tee -a "$SUM"
fi

# ── corpus ───────────────────────────────────────────────────────────
#
# corpus.tsv: file, test, host, compile, load, result, insns, insns walked by the
# verifier, usec, first message.
#   host     what the same test returns on x86-64: the control for the test
#   compile  ok | fail
#   load     ok | libbpf | verifier | open
#   result   ok | check:LINE | panic:LINE | leak:N | unwound | run:ERROR. "=" in
#            front: that is what the test is there to return (corpus/EXPECT).
#            unwound: the kernel ended a loop or a recursion that went on for
#            too long. Such a program may well return 0.

names() { sed -n 's/^test!(\(leaks \)\{0,1\}\([a-z_0-9]*\),.*/\2/p' "$C/tests-bpf/$1.rs"; }

if [ "$ONLY" != sched ]; then
	[ -n "$TESTS" ] || TESTS=$(ls "$C/tests-bpf" | sed 's/\.rs$//')
	push "$C/bld" run $(for f in $TESTS; do for n in $(names $f); do [ -f "$C/bld/one/$n.o" ] && echo one/$n.o; done; done)
	: > "$OUT/corpus.tsv"
	for f in $TESTS; do
		N=$(names $f | tr '\n' ' ')
		ssh "cd /tmp/t; for n in $N; do [ -f one/\$n.o ] || continue; timeout ${TMO:-60} ./run one/\$n.o || printf '%s\ttimeout\n' \$n; done" < /dev/null > "$OUT/corpus/$f.tsv"
		[ -f "$C/bld/host/lib$f.so" ] && "$C/bld/host/run" "$C/bld/host/lib$f.so" $N > "$OUT/corpus/$f.host" 2>/dev/null
		for n in $N; do
			host=$(awk -F'\t' -v n=$n '$1==n{print $2}' "$OUT/corpus/$f.host" 2>/dev/null); host=${host:-nobuild}
			if [ ! -f "$C/bld/one/$n.o" ]; then
				printf '%s\t%s\t%s\tfail\t-\t-\t-\t-\t-\tdoes not compile\n' $f $n $host
				continue
			fi
			awk -F'\t' -v f=$f -v n=$n -v h=$host -v e="$(awk -v n=$n '$1==n{print $2}' "$C/EXPECT")" \
				'BEGIN{OFS="\t"} $1==n{r=$3; if (e!="" && index(r,e)==1) r="="r; print f,$1,h,"ok",$2,r,$4,$5,$6,$7}' "$OUT/corpus/$f.tsv"
		done >> "$OUT/corpus.tsv"
	done
	{
		echo "corpus: $(wc -l < "$OUT/corpus.tsv") tests, as expected: $(awk -F'\t' '$6=="ok"||$6~/^=/' "$OUT/corpus.tsv" | wc -l), host control not as expected: $(awk -F'\t' 'NR==FNR{if ($0 !~ /^#/) {split($0,a," "); e[a[1]]=a[2]}; next} {w=($2 in e)?e[$2]:"ok"; if (index($3,w)!=1) print}' "$C/EXPECT" "$OUT/corpus.tsv" | wc -l), $(awk -F'\t' '{i+=$8} END {print i+0}' "$OUT/corpus.tsv") insns walked"
		awk -F'\t' '$6!="ok" && $6!~/^=/{k=($4!="ok")?"compile: "$10:(($5=="ok")?"run: "$6" "$10:$5": "$10); gsub(/[0-9]+ iterations/,"N iterations",k); gsub(/insn [0-9]+/,"insn N",k); gsub(/R[0-9] !read/,"Rx !read",k); gsub(/off -[0-9]+\+0/,"off N",k); c[k]++; l[k]=l[k]" "$2} END{for(k in c) print "  "c[k]"\t"k"\t"l[k]}' "$OUT/corpus.tsv" | sort -k1,1rn | cut -c1-230
		echo "  most expensive to verify: $(sort -t$'\t' -k8,8rn "$OUT/corpus.tsv" | head -3 | awk -F'\t' '{printf "%s %d insns; ", $2, $8}')"
	} | tee -a "$SUM"
fi

echo "console: WARNING/BUG/Oops/stall lines $BAD0 at the start, $(bad_lines) at the end" | tee -a "$SUM"

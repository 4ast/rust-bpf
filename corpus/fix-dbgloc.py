#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""fix-dbgloc.py IN.ll OUT.ll

add_ksyms.py turns llvm.memcpy and co into calls of bpf_arena_memcpy(). An
intrinsic doesn't need a debug location. A call of a function that has debug
info, which those of shim.c have, does when the caller has debug info too.
LLVM drops the debug info of the whole module otherwise, and there is no BTF
without it. Give such calls line 0 of the function that they are in.
"""
import re
import sys

lines = open(sys.argv[1]).read().split('\n')
next_md = max([int(m.group(1)) for l in lines for m in [re.match(r'^!(\d+) = ', l)] if m] + [0]) + 1
md = {}
scope = None
for i, l in enumerate(lines):
    if l.startswith('define '):
        m = re.search(r'!dbg (!\d+)', l)
        scope = m.group(1) if m else None
    elif l == '}':
        scope = None
    elif scope and '!dbg' not in l and re.search(r'\b(call|invoke) .*@(bpf_arena_mem\w+|memset)\(', l):
        if scope not in md:
            md[scope] = next_md
            next_md += 1
        lines[i] = l + ', !dbg !%d' % md[scope]
for scope, n in md.items():
    lines.append('!%d = !DILocation(line: 0, scope: %s)' % (n, scope))
open(sys.argv[2], 'w').write('\n'.join(lines) + '\n')

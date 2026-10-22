#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""arena_kfunc_args.py VMLINUX_BTF...

Prints kfunc:argument (counted from 0), comma separated, for every parameter of
a function in the BTF whose name ends in __arena. That is what opt takes as
-bpf-arena-kfunc-args=LIST: what is passed to a kfunc is kept out of the arena as
a rule, and these parameters are the exception.

env: BPFTOOL
"""
import os
import re
import subprocess
import sys

out = set()
for f in sys.argv[1:]:
    t = subprocess.run([os.environ.get('BPFTOOL', 'bpftool'), 'btf', 'dump', 'file', f, 'format', 'raw'],
                       capture_output=True, text=True, check=True).stdout
    protos, cur = {}, None
    for l in t.split('\n'):
        m = re.match(r"\[(\d+)\] (\w+) '([^']*)'(.*)", l)
        if m:
            cur = None
            if m.group(2) == 'FUNC_PROTO':
                cur = protos[m.group(1)] = []
            continue
        m = re.match(r"\s+'([^']*)' type_id=", l)
        if m and cur is not None:
            cur.append(m.group(1))
    for m in re.finditer(r"^\[\d+\] FUNC '([^']+)' type_id=(\d+)", t, re.M):
        for i, p in enumerate(protos.get(m.group(2), [])):
            if p.endswith('__arena'):
                out.add('%s:%d' % (m.group(1), i))
print(','.join(sorted(out)))

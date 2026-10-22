#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""builtins-abi.py IN.ll OUT.ll

extern "C" of rustc for BPF passes and returns what is wider than 64 bits in
memory. LLVM calls __multi3() and co with 128 bit values in pairs of registers
and expects the result in r0 and r2. Rename the functions of compiler_builtins
that are affected and add functions with the signature that LLVM expects, which
call them.
"""
import re
import sys

T = 'i128'
# name: (result, arguments)
FUNCS = {
    '__multi3': (T, [T, T]),
    '__udivti3': (T, [T, T]),
    '__umodti3': (T, [T, T]),
    '__divti3': (T, [T, T]),
    '__modti3': (T, [T, T]),
    '__ashlti3': (T, [T, 'i32']),
    '__ashrti3': (T, [T, 'i32']),
    '__lshrti3': (T, [T, 'i32']),
    '__muloti4': (T, [T, T, 'ptr']),
    '__udivmodti4': (T, [T, T, 'ptr']),
    '__divmodti4': (T, [T, T, 'ptr']),
    '__fixdfti': (T, ['double']),
    '__fixunsdfti': (T, ['double']),
    '__fixsfti': (T, ['float']),
    '__fixunssfti': (T, ['float']),
    '__floattidf': ('double', [T]),
    '__floatuntidf': ('double', [T]),
    '__floattisf': ('float', [T]),
    '__floatuntisf': ('float', [T]),
    '__clzti2': ('i64', [T]),
    '__ctzti2': ('i64', [T]),
}

text = open(sys.argv[1]).read()
names = '|'.join(FUNCS)
text = re.sub(r'@(%s)\b' % names, r'@rs.\1', text)

# BTF is made of debug info, and it is BTF that tells the verifier that a
# function returns in r0 and r2.
next_md = max(int(x) for x in re.findall(r'^!(\d+) = ', text, re.M)) + 1
md = []


def node(body):
    global next_md
    md.append('!%d = %s' % (next_md, body))
    next_md += 1
    return '!%d' % (next_md - 1)


cu = re.search(r'^(!\d+) = distinct !DICompileUnit\(.*?file: (!\d+)', text, re.M)
unit, file = cu.group(1), cu.group(2)
DI = {
    T: node('!DIBasicType(name: "__int128", size: 128, encoding: DW_ATE_signed)'),
    'i64': node('!DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)'),
    'i32': node('!DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)'),
    'double': node('!DIBasicType(name: "double", size: 64, encoding: DW_ATE_float)'),
    'float': node('!DIBasicType(name: "float", size: 32, encoding: DW_ATE_float)'),
}
DI['ptr'] = node('!DIDerivedType(tag: DW_TAG_pointer_type, baseType: %s, size: 64)' % DI[T])

out = []
for name, (ret, args) in FUNCS.items():
    if not re.search(r'^define .*@rs\.%s\(' % name, text, re.M):
        continue
    types = node('!{%s}' % ', '.join(DI[t] for t in [ret] + args))
    fn_type = node('!DISubroutineType(types: %s)' % types)
    sp = '!%d' % (next_md + len(args) + 1)
    params = [node('!DILocalVariable(name: "a%d", arg: %d, scope: %s, file: %s, line: 1, type: %s)' %
                   (i, i + 1, sp, file, DI[t])) for i, t in enumerate(args)]
    retained = node('!{%s}' % ', '.join(params))
    assert sp == node('distinct !DISubprogram(name: "%s", scope: %s, file: %s, line: 1, type: %s, scopeLine: 1, '
                      'flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: %s, '
                      'retainedNodes: %s)' % (name, file, file, fn_type, unit, retained))
    loc = node('!DILocation(line: 1, scope: %s)' % sp)
    params = ', '.join('%s %%a%d' % (t, i) for i, t in enumerate(args))
    out.append('define weak hidden %s @%s(%s) !dbg %s {' % (ret, name, params, sp))
    call = []
    if ret == T:
        out.append('  %r = alloca i128, align 16')
        call.append('ptr sret([16 x i8]) align 16 %r')
    for i, t in enumerate(args):
        if t == T:
            out.append('  %%p%d = alloca i128, align 16' % i)
            out.append('  store i128 %%a%d, ptr %%p%d, align 16' % (i, i))
            call.append('ptr align 16 %%p%d' % i)
        else:
            call.append('%s %%a%d' % (t, i))
    if ret == T:
        out.append('  call void @rs.%s(%s) alwaysinline, !dbg %s' % (name, ', '.join(call), loc))
        out.append('  %v = load i128, ptr %r, align 16')
    else:
        out.append('  %%v = call %s @rs.%s(%s) alwaysinline, !dbg %s' % (ret, name, ', '.join(call), loc))
    out.append('  ret %s %%v, !dbg %s' % (ret, loc))
    out.append('}')
    out.append('')

# definitions go before the metadata
m = re.search(r'^(attributes #0|!llvm\.|!0 = )', text, re.M)
pos = m.start() if m else len(text)
open(sys.argv[2], 'w').write(text[:pos] + '\n'.join(out) + '\n' + text[pos:] + '\n'.join(md) + '\n')

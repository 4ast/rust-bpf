#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""fix-protos.py IN.ll OUT.ll

The verifier takes the number of argument slots of a function and the size of
what it returns from BTF, and BTF is made of debug info. Debug info describes
the source. The code follows the Rust ABI: a result that is returned through
a hidden pointer, a slice or an Option in two registers, no register for
a zero sized argument, and LLVM removes and promotes arguments on top of that.

Replace the prototype in the debug info of every static function with one that
is made of its IR signature: u64 per register. The types are lost. For a static
function the verifier doesn't look at them.

The kernel refuses BTF as a whole when a name in it is longer than 511 bytes.
Names of generic functions can be. Cut them and add a hash.
"""
import hashlib
import re
import sys

MAX_NAME = 200


def split_top(s):
    """split at the commas that are not inside of brackets"""
    out, depth, cur = [], 0, ''
    for c in s:
        if c in '([{<':
            depth += 1
        elif c in ')]}>':
            depth -= 1
        if c == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def slots(t):
    """registers that a value of the type takes"""
    t = t.strip()
    if t == 'void':
        return 0
    if t.startswith('{'):
        return sum(slots(x) for x in split_top(t[1:-1]))
    m = re.match(r'\[(\d+) x (.*)\]$', t)
    if m:
        return int(m.group(1)) * slots(m.group(2))
    m = re.match(r'i(\d+)$', t)
    if m:
        return (int(m.group(1)) + 63) // 64
    if t == 'fp128':
        return 2
    return 1


def first_type(s):
    """the type that a parameter starts with"""
    s = s.strip()
    if s[0] in '{[<':
        close = {'{': '}', '[': ']', '<': '>'}[s[0]]
        depth = 0
        for i, c in enumerate(s):
            if c == s[0]:
                depth += 1
            elif c == close:
                depth -= 1
                if depth == 0:
                    return s[:i + 1]
    return s.split()[0]


def last_type(s):
    """the type that the text in front of the name of a function ends with"""
    s = s.strip()
    if s[-1] in '}]>':
        opn = {'}': '{', ']': '[', '>': '<'}[s[-1]]
        depth = 0
        for i in range(len(s) - 1, -1, -1):
            if s[i] == s[-1]:
                depth += 1
            elif s[i] == opn:
                depth -= 1
                if depth == 0:
                    return s[i:]
    return s.split()[-1]


text = open(sys.argv[1]).read()
next_md = max(int(x) for x in re.findall(r'^!(\d+) = ', text, re.M)) + 1
md = []


def node(body):
    global next_md
    md.append('!%d = %s' % (next_md, body))
    next_md += 1
    return '!%d' % (next_md - 1)


U64 = node('!DIBasicType(name: "u64", size: 64, encoding: DW_ATE_unsigned)')
U128 = node('!DIBasicType(name: "u128", size: 128, encoding: DW_ATE_unsigned)')

protos = {}
for m in re.finditer(r'^define (internal|private) ([^@\n]*)@("[^"]+"|[\w.$]+)\(', text, re.M):
    # to the bracket that closes the list of parameters
    i, depth = m.end(), 1
    while depth:
        if text[i] in '([{<':
            depth += 1
        elif text[i] in ')]}>':
            depth -= 1
        i += 1
    rest = text[i:text.index('\n', i)]
    dbg = re.search(r'!dbg (!\d+)', rest)
    if not dbg or ' section "' in rest:
        continue
    nargs = sum(slots(first_type(p)) for p in split_top(text[m.end():i - 1]) if p != '...')
    nret = slots(last_type(m.group(2)))
    # LLVM returns what doesn't fit into r0 and r2 through a hidden pointer
    if nret > 2:
        nret, nargs = 0, nargs + 1
    # The rest is in the frame of the caller in arena. The kernel doesn't see it.
    protos[dbg.group(1)] = (nret, nargs)


def fix(m):
    sp, body = m.group(1), m.group(2)
    if sp not in protos:
        return m.group(0)
    nret, nargs = protos[sp]
    ret = ['null', U64, U128][nret]
    ty = node('!DISubroutineType(types: %s)' % node('!{%s}' % ', '.join([ret] + [U64] * nargs)))
    args = node('!{%s}' % ', '.join(
        node('!DILocalVariable(name: "a%d", arg: %d, scope: %s, type: %s)' % (i, i + 1, sp, U64))
        for i in range(nargs)))
    body = re.sub(r'\btype: !\d+', 'type: ' + ty, body, count=1)
    if 'retainedNodes: ' in body:
        body = re.sub(r'retainedNodes: !\d+', 'retainedNodes: ' + args, body)
    else:
        body += ', retainedNodes: ' + args
    return '%s = distinct !DISubprogram(%s)' % (sp, body)


text = re.sub(r'^(!\d+) = distinct !DISubprogram\((.*)\)$', fix, text, flags=re.M)


def shorten(m):
    name = m.group(2)
    if len(name) <= MAX_NAME:
        return m.group(0)
    return '%s%s..%s"' % (m.group(1), name[:MAX_NAME], hashlib.sha1(name.encode()).hexdigest()[:8])


text = re.sub(r'(!DISubprogram\(name: ")([^"]*)"', shorten, text)

# The parameters of the source are still referred to. They are variables now.
def unarg(m):
    scope = re.search(r'scope: (!\d+)', m.group(0))
    if not scope or scope.group(1) not in protos:
        return m.group(0)
    return re.sub(r'\barg: \d+, ', '', m.group(0))


text = re.sub(r'^!\d+ = !DILocalVariable\(.*\barg: \d+, .*$', unarg, text, flags=re.M)
open(sys.argv[2], 'w').write(text + '\n'.join(md) + '\n')

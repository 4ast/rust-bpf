#!/usr/bin/env python3
# Add section ".ksyms" and BTF-enabling debug metadata to extern function
# declarations in LLVM IR so that LLC generates proper BTF FUNC entries.
# Usage: add_ksyms.py input.ll output.ll

import re, sys

text = open(sys.argv[1]).read()

# Find the highest existing metadata ID so we can append new ones.
max_id = max((int(m[1:]) for m in re.findall(r'!\d+', text)), default=0)

# Find the DIFile used by existing DISubprograms (reuse it for kfuncs).
di_file_match = re.search(r'(!\d+) = !DIFile\(', text)
di_file = di_file_match.group(1) if di_file_match else None

# Collect non-intrinsic declare lines and add section + debug metadata.
new_metadata = []
next_id = max_id + 1

def add_ksyms(m):
    global next_id
    line = m.group(0)

    # Extract function name.
    name_match = re.search(r'@(\w+)\(', line)
    name = name_match.group(1) if name_match else "unknown"

    # Allocate metadata IDs: one for DISubprogram, one for DISubroutineType.
    dbg_id = next_id
    subrt_id = next_id + 1
    next_id += 2

    file_ref = di_file if di_file else '!0'
    new_metadata.append(
        f'!{dbg_id} = !DISubprogram(name: "{name}", scope: {file_ref}, '
        f'file: {file_ref}, type: !{subrt_id}, '
        f'flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)')
    new_metadata.append(
        f'!{subrt_id} = !DISubroutineType(types: !{{null}})')

    # Insert !dbg right after 'declare' and append section at the end.
    # declare !dbg !N <rest> #M section ".ksyms"
    line = line.replace('declare ', f'declare !dbg !{dbg_id} ', 1)
    return f'{line} section ".ksyms"'

# Skip LLVM intrinsics (@llvm.*) and rust_eh_personality.
text = re.sub(
    r'^declare\s(?!.*@llvm\.)(?!.*@rust_eh_personality\b).*#\d+\s*$',
    add_ksyms,
    text,
    flags=re.MULTILINE,
)

# LLC lowers llvm.memcpy/memmove/memset intrinsics to libc calls, but
# those won't have BTF/.ksyms info. Replace intrinsic calls with direct
# calls to declared @memcpy/@memmove/@memset with .ksyms section.
#
# llvm.memcpy.p0.p0.i64(dst, src, len, isvolatile) -> memcpy(dst, src, len)
# llvm.memmove.p0.p0.i64(dst, src, len, isvolatile) -> memmove(dst, src, len)
mem_intrinsics = {
    'memcpy':  (r'call void @llvm\.memcpy\.p0\.p0\.i64\('
                r'(ptr[^,]*),\s*(ptr[^,]*),\s*(i64[^,]*),\s*i1[^)]*\)'),
    'memmove': (r'call void @llvm\.memmove\.p0\.p0\.i64\('
                r'(ptr[^,]*),\s*(ptr[^,]*),\s*(i64[^,]*),\s*i1[^)]*\)'),
}

# Find an attribute group number used by other extern decls.
attr_match = re.search(r'^declare\s.*#(\d+)\s+section', text, re.MULTILINE)
attr_num = attr_match.group(1) if attr_match else '1'

extra_decls = []
for name, pattern in mem_intrinsics.items():
    if re.search(pattern, text):
        # Replace intrinsic calls with direct calls (void — discard result).
        text = re.sub(
            pattern,
            rf'call void @{name}(\1, \2, \3)',
            text,
        )
        # Add declaration.
        dbg_id = next_id
        subrt_id = next_id + 1
        next_id += 2
        file_ref = di_file if di_file else '!0'
        new_metadata.append(
            f'!{dbg_id} = !DISubprogram(name: "{name}", scope: {file_ref}, '
            f'file: {file_ref}, type: !{subrt_id}, '
            f'flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)')
        new_metadata.append(
            f'!{subrt_id} = !DISubroutineType(types: !{{null}})')
        extra_decls.append(
            f'declare !dbg !{dbg_id} void @{name}(ptr, ptr, i64) '
            f'#{attr_num} section ".ksyms"')

# LLC lowers 'resume' instructions to calls to _Unwind_Resume.
# Replace resume with a direct call so BTF/.ksyms picks it up.
if re.search(r'^\s+resume\s', text, re.MULTILINE):
    # resume { ptr, i32 } %val -> extract ptr, call _Unwind_Resume, unreachable
    def replace_resume(m):
        indent = m.group(1)
        val = m.group(2)
        meta = m.group(3) or ''
        # Use a unique tmp name based on position to avoid SSA conflicts.
        tmp = f'%_unwind_ptr.{m.start()}'
        return (f'{indent}{tmp} = extractvalue {{ ptr, i32 }} {val}, 0{meta}\n'
                f'{indent}call void @_Unwind_Resume(ptr {tmp}){meta}\n'
                f'{indent}unreachable')
    text = re.sub(
        r'^(\s+)resume \{ ptr, i32 \} (\S+)(,\s*!dbg\s+!\d+)?$',
        replace_resume,
        text,
        flags=re.MULTILINE,
    )
    dbg_id = next_id
    subrt_id = next_id + 1
    next_id += 2
    file_ref = di_file if di_file else '!0'
    new_metadata.append(
        f'!{dbg_id} = !DISubprogram(name: "_Unwind_Resume", scope: {file_ref}, '
        f'file: {file_ref}, type: !{subrt_id}, '
        f'flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)')
    new_metadata.append(
        f'!{subrt_id} = !DISubroutineType(types: !{{null}})')
    extra_decls.append(
        f'declare !dbg !{dbg_id} void @_Unwind_Resume(ptr) '
        f'#{attr_num} section ".ksyms"')

# Insert extra declares before the first 'attributes' line.
if extra_decls:
    text = re.sub(
        r'^(attributes\s)',
        '\n'.join(extra_decls) + '\n\n\\1',
        text,
        count=1,
        flags=re.MULTILINE,
    )

# Append new metadata at the end.
if new_metadata:
    text = text.rstrip() + '\n' + '\n'.join(new_metadata) + '\n'

open(sys.argv[2], 'w').write(text)

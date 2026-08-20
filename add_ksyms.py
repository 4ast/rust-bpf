#!/usr/bin/env python3
# Add section ".ksyms" and BTF-enabling debug metadata to extern function
# declarations in LLVM IR so that LLC generates proper BTF FUNC entries.
#
# The BTF FUNC_PROTO must be COMPATIBLE with the kernel's own prototype:
# libbpf resolves func ksyms with bpf_core_types_are_compat(), which
# demands equal arg counts and matching BTF *kinds* at every level (INT
# sizes are lax; PTR recurses into the pointee; struct names are never
# compared). A hardcoded void() proto therefore fails for every kfunc
# with args, and a guessed void* fails for struct-pointer args (pointee
# kind UNKN != STRUCT).
#
# So, when KSYM_BTF_FILES + BPFTOOL are set (first file = vmlinux, rest =
# module .ko files sharing its base BTF), each tagged extern is looked up
# in the kernel BTF and its proto is MIRRORED kind-by-kind into debug
# metadata: empty named structs for struct pointees, basic ints for
# scalars, recursively for nested pointers/protos — compatible by
# construction. Externs not found in any BTF (or when the env is unset)
# fall back to a proto derived from the IR signature (iN -> int,
# ptr -> void*), which is correct for scalar-only kfuncs.
#
# Usage: add_ksyms.py input.ll output.ll

import os, re, subprocess, sys

text = open(sys.argv[1]).read()

# Find the highest existing metadata ID so we can append new ones.
max_id = max((int(m[1:]) for m in re.findall(r'!\d+', text)), default=0)

# Find the DIFile used by existing DISubprograms (reuse it for kfuncs).
di_file_match = re.search(r'(!\d+) = !DIFile\(', text)
di_file = di_file_match.group(1) if di_file_match else None

# Collect non-intrinsic declare lines and add section + debug metadata.
new_metadata = []
next_id = max_id + 1


def alloc_id():
    global next_id
    i = next_id
    next_id += 1
    return i


# ---- kernel BTF proto mirror ------------------------------------------

class KernelBtf:
    """Lazily-loaded index over `bpftool btf dump` text of vmlinux +
    module BTFs; resolves a kfunc name to its FUNC_PROTO node tree."""

    MODS = {"TYPEDEF", "CONST", "VOLATILE", "RESTRICT", "TYPE_TAG"}

    def __init__(self):
        self.loaded = False
        self.maps = []     # per BTF file: id -> (kind, name, rest, [params])
        self.funcs = {}    # name -> (map index, proto type id)
        self.cur_map = None

    def _load_one(self, bpftool, path, base):
        # Module BTF is split BTF: type ids reference the vmlinux base, so
        # the base MUST be supplied or ids are re-numbered/unresolvable.
        # Every file gets its OWN id map — ids are only unique per file.
        attempts = ([[bpftool, "-B", base, "btf", "dump", "file", path],
                     [bpftool, "btf", "dump", "file", path]]
                    if base else
                    [[bpftool, "btf", "dump", "file", path]])
        r = None
        for cmd in attempts:
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                break
        if r is None or r.returncode != 0:
            print(f"[add_ksyms] warning: cannot dump BTF of {path}",
                  file=sys.stderr)
            return
        types = {}
        midx = len(self.maps)
        self.maps.append(types)
        cur = None
        for line in r.stdout.splitlines():
            m = re.match(r"\[(\d+)\] (\w+) '([^']*)'(.*)", line)
            if m:
                tid, kind, name, rest = int(m[1]), m[2], m[3], m[4]
                types[tid] = (kind, name, rest, [])
                cur = types[tid] if kind == "FUNC_PROTO" else None
                if kind == "FUNC":
                    tm = re.search(r"type_id=(\d+)", rest)
                    if tm and name not in self.funcs:
                        self.funcs[name] = (midx, int(tm[1]))
            elif cur is not None and line.startswith("\t"):
                pm = re.search(r"type_id=(\d+)", line)
                if pm:
                    cur[3].append(int(pm[1]))

    def load(self):
        if self.loaded:
            return
        self.loaded = True
        files = os.environ.get("KSYM_BTF_FILES", "").split()
        bpftool = os.environ.get("BPFTOOL", "")
        if not files or not bpftool or not os.path.exists(bpftool):
            return
        base = files[0]
        for i, f in enumerate(files):
            if os.path.exists(f):
                self._load_one(bpftool, f, base if i > 0 else None)

    def node(self, tid):
        """Look up a type id in the current file's map; module split
        BTF references base (vmlinux) ids, which live in maps[0]."""
        if self.cur_map is None:
            return None
        n = self.cur_map.get(tid)
        if n is None and self.maps and self.cur_map is not self.maps[0]:
            n = self.maps[0].get(tid)
        return n

    def resolve(self, tid):
        """Follow modifier/typedef chains to the base node id."""
        seen = 0
        n = self.node(tid)
        while n is not None and n[0] in self.MODS:
            m = re.search(r"type_id=(\d+)", n[2])
            if not m or seen > 32:
                return tid
            tid = int(m[1])
            n = self.node(tid)
            seen += 1
        return tid

    def proto_of(self, name):
        self.load()
        ent = self.funcs.get(name)
        if ent is None:
            return None
        midx, pid = ent
        self.cur_map = self.maps[midx]
        pid = self.resolve(pid)
        node = self.node(pid)
        return pid if node and node[0] == "FUNC_PROTO" else None


KBTF = KernelBtf()

BASIC_INT = {
    (1, True): ("signed char", "DW_ATE_signed", 8),
    (2, True): ("short", "DW_ATE_signed", 16),
    (4, True): ("int", "DW_ATE_signed", 32),
    (8, True): ("long long", "DW_ATE_signed", 64),
    (16, True): ("__int128", "DW_ATE_signed", 128),
    (1, False): ("unsigned char", "DW_ATE_unsigned", 8),
    (2, False): ("unsigned short", "DW_ATE_unsigned", 16),
    (4, False): ("unsigned int", "DW_ATE_unsigned", 32),
    (8, False): ("unsigned long long", "DW_ATE_unsigned", 64),
    (16, False): ("unsigned __int128", "DW_ATE_unsigned", 128),
}


def di_basic_int(size, signed):
    name, enc, bits = BASIC_INT.get((size, signed), BASIC_INT[(8, False)])
    i = alloc_id()
    new_metadata.append(
        f'!{i} = !DIBasicType(name: "{name}", size: {bits}, encoding: {enc})')
    return f'!{i}'


def di_from_kernel(tid, depth=0):
    """Mirror a kernel BTF node (by id) into DI; returns a metadata ref
    or None for void. Only KINDS matter for libbpf compat."""
    if depth > 8:
        return None
    if tid == 0:
        return None
    tid = KBTF.resolve(tid)
    node = KBTF.node(tid)
    if node is None:
        return None
    kind, name, rest, params = node
    file_ref = di_file if di_file else '!0'
    if kind == "INT":
        sm = re.search(r"size=(\d+)", rest)
        size = int(sm[1]) if sm else 8
        signed = "SIGNED" in rest
        return di_basic_int(size, signed)
    if kind == "FLOAT":
        sm = re.search(r"size=(\d+)", rest)
        bits = (int(sm[1]) if sm else 8) * 8
        i = alloc_id()
        nm = "double" if bits == 64 else "float"
        new_metadata.append(
            f'!{i} = !DIBasicType(name: "{nm}", size: {bits}, '
            f'encoding: DW_ATE_float)')
        return f'!{i}'
    if kind == "PTR":
        m = re.search(r"type_id=(\d+)", rest)
        inner = di_from_kernel(int(m[1]), depth + 1) if m else None
        i = alloc_id()
        base = f', baseType: {inner}' if inner else ', baseType: null'
        new_metadata.append(
            f'!{i} = !DIDerivedType(tag: DW_TAG_pointer_type{base}, size: 64)')
        return f'!{i}'
    if kind in ("STRUCT", "UNION"):
        tag = ("DW_TAG_structure_type" if kind == "STRUCT"
               else "DW_TAG_union_type")
        i = alloc_id()
        nm = f'name: "{name}", ' if name and name != "(anon)" else ''
        # empty definition (NOT FwdDecl): must reach BTF as kind
        # STRUCT/UNION — a fwd decl would be kind FWD and fail compat.
        new_metadata.append(
            f'!{i} = !DICompositeType(tag: {tag}, {nm}file: {file_ref}, '
            f'size: 0, elements: !{{}})')
        return f'!{i}'
    if kind in ("ENUM", "ENUM64"):
        bits = 64 if kind == "ENUM64" else 32
        i = alloc_id()
        nm = f'name: "{name}", ' if name and name != "(anon)" else ''
        new_metadata.append(
            f'!{i} = !DICompositeType(tag: DW_TAG_enumeration_type, '
            f'{nm}file: {file_ref}, size: {bits}, elements: !{{}})')
        return f'!{i}'
    if kind == "FUNC_PROTO":
        rm = re.search(r"ret_type_id=(\d+)", rest)
        ret = di_from_kernel(int(rm[1]), depth + 1) if rm else None
        args = [di_from_kernel(p, depth + 1) for p in params]
        i = alloc_id()
        types = ", ".join([ret or "null"] + [a or "null" for a in args])
        new_metadata.append(
            f'!{i} = !DISubroutineType(types: !{{{types}}})')
        return f'!{i}'
    if kind == "FWD":
        i = alloc_id()
        new_metadata.append(
            f'!{i} = !DICompositeType(tag: DW_TAG_structure_type, '
            f'name: "{name}", file: {file_ref}, flags: DIFlagFwdDecl)')
        return f'!{i}'
    if kind == "ARRAY":
        m = re.search(r"type_id=(\d+)", rest)
        nm = re.search(r"nr_elems=(\d+)", rest)
        inner = di_from_kernel(int(m[1]), depth + 1) if m else None
        sub = alloc_id()
        new_metadata.append(
            f'!{sub} = !DISubrange(count: {int(nm[1]) if nm else 0})')
        i = alloc_id()
        base = f'baseType: {inner}, ' if inner else ''
        new_metadata.append(
            f'!{i} = !DICompositeType(tag: DW_TAG_array_type, {base}'
            f'elements: !{{!{sub}}})')
        return f'!{i}'
    # unknown kind: safest is void
    return None


IR_INT_BITS = {"i1": 1, "i8": 1, "i16": 2, "i32": 4, "i64": 8, "i128": 16}


def di_from_ir_sig(line):
    """Fallback: derive the proto from the IR declare signature.
    ptr -> void* (only correct for void*/scalar kernel params)."""
    m = re.search(r'declare\s+(?:!dbg\s+!\d+\s+)?'
                  r'(?:(?:noundef|zeroext|signext|noalias|nonnull)\s+)*'
                  r'([\w.]+|ptr)\s+@[\w.]+\((.*?)\)\s*(?:unnamed_addr\s*)?#',
                  line)
    if not m:
        return None
    ret_ir, args_ir = m[1], m[2]

    def one(ir_ty):
        ir_ty = ir_ty.strip().split()[0] if ir_ty.strip() else ""
        if ir_ty in IR_INT_BITS:
            return di_basic_int(IR_INT_BITS[ir_ty], True)
        if ir_ty == "ptr":
            i = alloc_id()
            new_metadata.append(
                f'!{i} = !DIDerivedType(tag: DW_TAG_pointer_type, '
                f'baseType: null, size: 64)')
            return f'!{i}'
        if ir_ty in ("float", "double"):
            bits = 32 if ir_ty == "float" else 64
            i = alloc_id()
            new_metadata.append(
                f'!{i} = !DIBasicType(name: "{ir_ty}", size: {bits}, '
                f'encoding: DW_ATE_float)')
            return f'!{i}'
        return None

    ret = None if ret_ir == "void" else one(ret_ir)
    args = []
    if args_ir.strip() and args_ir.strip() != "...":
        for a in args_ir.split(","):
            if a.strip() == "...":
                continue
            args.append(one(a))
    i = alloc_id()
    types = ", ".join([ret or "null"] + [a or "null" for a in args])
    new_metadata.append(f'!{i} = !DISubroutineType(types: !{{{types}}})')
    return f'!{i}'


def make_proto(name, line):
    """Best proto for extern `name`: kernel-BTF mirror, else IR-derived,
    else void()."""
    pid = KBTF.proto_of(name)
    if pid is not None:
        ref = di_from_kernel(pid)
        if ref:
            return ref
    ref = di_from_ir_sig(line) if line else None
    if ref:
        if os.environ.get("KSYM_BTF_FILES"):
            print(f"[add_ksyms] note: '{name}' not in kernel BTF; "
                  f"using IR-derived proto", file=sys.stderr)
        return ref
    i = alloc_id()
    new_metadata.append(f'!{i} = !DISubroutineType(types: !{{null}})')
    return f'!{i}'


def add_ksyms(m):
    line = m.group(0)

    # Extract function name.
    name_match = re.search(r'@(\w+)\(', line)
    name = name_match.group(1) if name_match else "unknown"

    subrt = make_proto(name, line)
    dbg_id = alloc_id()

    file_ref = di_file if di_file else '!0'
    new_metadata.append(
        f'!{dbg_id} = !DISubprogram(name: "{name}", scope: {file_ref}, '
        f'file: {file_ref}, type: {subrt}, '
        f'flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)')

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

# LLC lowers llvm.memcpy/memmove/memset intrinsics and the memcmp libcall
# to plain extern symbols (@memcpy, @memcmp, ...). The kernel doesn't expose
# those names as kfuncs, so rename them to the arena-aware bpf_arena_* kfuncs:
#
#   llvm.memcpy.p0.p0.i64(dst, src, len, isvolatile) -> bpf_arena_memcpy(dst, src, len)
#   llvm.memmove.p0.p0.i64(dst, src, len, isvolatile) -> bpf_arena_memcpy(dst, src, len)
#   (both overlapping and non-overlapping copies go through bpf_arena_memcpy
#    for now; memmove semantics can be added as a separate kfunc later)
#   call ... @memcmp(...) -> call ... @bpf_arena_memcmp(...)
#   call ... @memcpy(...) -> call ... @bpf_arena_memcpy(...)
mem_intrinsics = {
    'bpf_arena_memcpy': (r'call void @llvm\.(?:memcpy|memmove)\.p0\.p0\.i64\('
                         r'(ptr[^,]*),\s*(ptr[^,]*),\s*(i64[^,]*),\s*i1[^)]*\)'),
}
# llvm.memset is NOT rewritten here: llc expands constant-length memsets
# inline, and turning them into a bpf_arena_memset kfunc call makes the
# object fail to load ("extern (func ksym) 'bpf_arena_memset': not found in
# kernel or module BTFs"). Pipelines that genuinely need a memset helper
# (rust-selftests/collections, where liballoc emits variable-length ones)
# lower it themselves BEFORE inlining, against a helper the object defines.

# A module may DEFINE the arena mem helpers itself (as static BPF subprogs,
# so the verifier checks them per call site with real pointer provenance —
# see rust-selftests/collections). Never emit or keep external declares for
# names the module defines; the rewritten calls bind to the local defs.
defined_syms = set(re.findall(r'^define\s[^\n]*?@([A-Za-z0-9_.$]+)\(',
                              text, re.MULTILINE))

# Find an attribute group number used by other extern decls.
attr_match = re.search(r'^declare\s.*#(\d+)\s+section', text, re.MULTILINE)
attr_num = attr_match.group(1) if attr_match else '1'

extra_decls = []
for name, pattern in mem_intrinsics.items():
    if re.search(pattern, text):
        text = re.sub(
            pattern,
            rf'call void @{name}(\1, \2, \3)',
            text,
        )
        if name in defined_syms:
            continue
        decl_line = f'declare void @{name}(ptr, ptr, i64) #{attr_num}'
        subrt = make_proto(name, decl_line)
        dbg_id = alloc_id()
        file_ref = di_file if di_file else '!0'
        new_metadata.append(
            f'!{dbg_id} = !DISubprogram(name: "{name}", scope: {file_ref}, '
            f'file: {file_ref}, type: {subrt}, '
            f'flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)')
        extra_decls.append(
            f'declare !dbg !{dbg_id} void @{name}(ptr, ptr, i64) '
            f'#{attr_num} section ".ksyms"')

# Rename memcmp/memcpy libcalls (produced by LLVM's lowering of slice
# comparisons / copies) to the arena-aware bpf_arena_* kfuncs. This covers
# both the `declare` lines add_ksyms() already tagged and every call site.
# We also rename the matching DISubprogram debug-info name, because LLC
# derives the BTF FUNC name from that rather than from the LLVM symbol —
# if we only renamed the symbol, libbpf would see `bpf_arena_memcmp` in the
# ELF symbol table but `memcmp` in BTF and fail the kfunc resolve.
libcall_renames = {
    'memcmp': 'bpf_arena_memcmp',
    'memcpy': 'bpf_arena_memcpy',
}
for old, new in libcall_renames.items():
    text = re.sub(r'(?<![A-Za-z0-9_.])@' + re.escape(old) + r'\b',
                  '@' + new, text)
    text = re.sub(r'(!DISubprogram\(name:\s*")' + re.escape(old) + r'"',
                  r'\g<1>' + new + '"', text)

# The renames above can leave a clashing external `declare` for a name the
# module defines; drop it — the calls bind to the module-local definition.
def drop_defined_declares(m):
    name_m = re.search(r'@([A-Za-z0-9_.$]+)\(', m.group(0))
    if name_m and name_m.group(1) in defined_syms:
        return ''
    return m.group(0)
# a declare may carry its section tag on a continuation line
text = re.sub(r'^declare\s[^\n]*\n(?:[ \t]+section[^\n]*\n)?',
              drop_defined_declares, text, flags=re.MULTILINE)

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
    decl_line = f'declare void @_Unwind_Resume(ptr) #{attr_num}'
    subrt = make_proto('_Unwind_Resume', decl_line)
    dbg_id = alloc_id()
    file_ref = di_file if di_file else '!0'
    new_metadata.append(
        f'!{dbg_id} = !DISubprogram(name: "_Unwind_Resume", scope: {file_ref}, '
        f'file: {file_ref}, type: {subrt}, '
        f'flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)')
    extra_decls.append(
        f'declare !dbg !{dbg_id} void @_Unwind_Resume(ptr) '
        f'#{attr_num} section ".ksyms"')

# Fix BTF linkage: Rust emits DISPFlagDefinition | DISPFlagOptimized for all
# functions, even internal ones. Without DISPFlagLocalToUnit, LLC generates
# BTF FUNC with linkage=global. The verifier then treats internal subprogs as
# global, validating caller args against the BTF signature independently.
# This fails when the optimizer drops dead args (e.g. #[track_caller]'s
# implicit &Location). Add DISPFlagLocalToUnit to every DISubprogram attached
# to a `define internal` function so LLC emits linkage=static in BTF.
internal_dbg_ids = set()
for m in re.finditer(r'^define\s+internal\s.*!dbg\s+(!\d+)', text, re.MULTILINE):
    internal_dbg_ids.add(m.group(1))

for dbg_id in internal_dbg_ids:
    text = re.sub(
        r'(' + re.escape(dbg_id) + r'\s*=\s*distinct\s+!DISubprogram\([^)]*'
        r'spFlags:\s*)(DISPFlagDefinition)',
        r'\1DISPFlagLocalToUnit | DISPFlagDefinition',
        text,
    )

# Strip 'noreturn' so LLVM doesn't DCE code after noreturn calls.
text = re.sub(r'\bnoreturn\b', '', text)
text = re.sub(r'^attributes (#\d+) = \{\s*\}$',
              r'attributes \1 = { noinline }', text, flags=re.MULTILINE)

# Convert 'invoke' to 'call' + 'br', dropping the unwind path.
# BPF has no exception handling.
def lower_invoke(m):
    indent = m.group(1)
    ret_assign = m.group(2) or ''
    tail = m.group(3)
    normal = m.group(4)
    meta = m.group(5) or ''
    call_meta = re.sub(r',\s*!noalias\s+!\d+', '', meta)
    return (f'{indent}{ret_assign}call {tail.rstrip()}{call_meta}\n'
            f'{indent}br label %{normal}{call_meta}')

text = re.sub(
    r'^(\s+)((?:%\S+\s*=\s*)?)'
    r'invoke\s+'
    r'(.*?)'
    r'\s+to\s+label\s+%(\S+)'
    r'\s+unwind\s+label\s+%\S+'
    r'((?:,\s*!\w+\s+!\d+)*)$',
    lower_invoke,
    text,
    flags=re.MULTILINE,
)

# Replace 'unreachable' with 'ret'. 'ret' compiles to a BPF exit insn.
# BPF verifier requires every subprogram to end with exit or jmp.
def fix_unreachable(text):
    lines = text.split('\n')
    out = []
    ret_type = 'void'
    for line in lines:
        m = re.match(r'define\s.*?\s+(@\S+)\(', line)
        if m:
            rt = re.search(r'define\s+(?:internal\s+)?(?:fastcc\s+)?(?:noundef\s+)?(?:zeroext\s+)?(\S+)\s+@', line)
            if rt:
                ret_type = rt.group(1)
        if re.match(r'  +unreachable', line):
            indent = re.match(r'(  +)', line).group(1)
            meta = ''
            mm = re.search(r'(,\s*!dbg\s+!\d+)', line)
            if mm:
                meta = mm.group(1)
            if ret_type == 'void':
                out.append(f'{indent}ret void{meta}')
            elif ret_type in ('i1', 'i8', 'i16', 'i32', 'i64'):
                out.append(f'{indent}ret {ret_type} 0{meta}')
            else:
                out.append(f'{indent}ret {ret_type} zeroinitializer{meta}')
            continue
        out.append(line)
    return '\n'.join(out)

text = fix_unreachable(text)

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

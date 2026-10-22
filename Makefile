# SPDX-License-Identifier: GPL-2.0
#
# Build standalone Rust BPF programs (no kernel crate dependency)
#
# Usage: make

include $(dir $(lastword $(MAKEFILE_LIST)))toolchain.mk

BLDDIR := $(CURDIR)/bld
LLC := $(LLVM_PREFIX)/bin/llc
OPT := $(LLVM_PREFIX)/bin/opt
LLVM_LINK := $(LLVM_PREFIX)/bin/llvm-link
LLVM_AS := $(LLVM_PREFIX)/bin/llvm-as
LLVM_DIS := $(LLVM_PREFIX)/bin/llvm-dis
LLVM_OBJCOPY := $(LLVM_PREFIX)/bin/llvm-objcopy
LLVM_CONFIG := $(LLVM_PREFIX)/bin/llvm-config
# "23.1.0" -> 23; trailing junk in development versions ("24.0.0git") is
# harmless, only the first field is used. Selects the matching optional
# llvm-sys dep in bpf-postproc/Cargo.toml, so the crate follows LLVM_PREFIX
# instead of being pinned in Cargo.toml.
LLVM_MAJOR := $(word 1,$(subst ., ,$(shell $(LLVM_CONFIG) --version 2>/dev/null)))
POSTPROC_FEATURE := llvm-$(LLVM_MAJOR)
# There is no llvm-sys crate for LLVM 24 yet: bpf-postproc/llvm24 has a manifest
# for the same sources with bindings of its own.
POSTPROC_DIR := $(CURDIR)/bpf-postproc$(if $(filter 24,$(LLVM_MAJOR)),/llvm24)
TARGET := $(CURDIR)/bpfel-unknown-none-v4.json
# Persistent across `rm -rf bld` — libcore/liballoc rebuilds dominate clean
# builds (~22s), and these only depend on rustc/RUST_SRC, not on user code.
DEPDIR := $(CURDIR)/bld_deps

RUSTFLAGS_ENV := RUSTC_BOOTSTRAP=1
RUSTC_COMMON := --target $(TARGET) -C opt-level=3 -C panic=unwind -C debuginfo=2 -Z unstable-options -Z threads=$(RUSTC_THREADS)

# Programs demonstrating btf_type_tag / btf_decl_tag. They use the same
# pipeline as the scx_* programs: btf_tags.py turns the `.btf_tags` manifest
# emitted by #[btf_tag] into debug-info annotations.
TAG_PROGS := type_tag_test decl_tag_test

# Schedulers ported from C on top of scx_common.rs, the counterpart of
# scx/common.bpf.h. Every symbol that has to survive internalize starts with
# the name of the scheduler: its ops, its syscall programs, its maps.
SCX_PORTS := cpu0

PROGS := scx_simple scx_cosmos $(addprefix scx_,$(SCX_PORTS)) $(TAG_PROGS)

# Programs that let a panic unwind through Rust Drop impls. These need a
# backend that lowers unwinding to a flag in r3 and a branch ("[BPF] Lower
# unwinding to a flag in r3 and a branch"), so they are only built when
# LLVM_PREFIX is new enough. An older backend would silently produce an object
# that calls _Unwind_RaiseException as a kfunc and never reaches a pad, so
# `make` skips them and says why rather than building something that cannot
# load.
#
# The other programs are built either way. With such a backend their panic
# handlers unwind (--cfg bpf_unwind) and add_ksyms.py keeps the landing pads
# (KEEP_INVOKE=1). Without it the handlers call bpf_throw() and the pads are
# dropped.
#
# Some of the pads abort instead of cleaning up, e.g. the PanicGuard in
# liballoc's btree::mem::replace(). That is llvm.trap, which llc emits as
# __bpf_trap, and the verifier rejects a program that can reach it. It is one
# more panic that cannot unwind, so it ends like the others
# (TRAP_TO_BPF_THROW=1, the cookie the panic handlers use). Except where the
# function may unwind: there it unwinds (TRAP_TO_UNWIND=1), because bpf_throw is
# refused while a caller holds interrupt flags, an RCU section or a reference.
EH_PROGS := exc_cleanup
ifeq ($(shell test "$(LLVM_MAJOR)" -ge 24 2>/dev/null && echo yes),yes)
EH_BUILD := $(EH_PROGS)
UNWIND_CFG := --cfg bpf_unwind
KSYMS_ENV := KEEP_INVOKE=1 TRAP_TO_UNWIND=1 TRAP_TO_BPF_THROW=1
else
EH_BUILD :=
UNWIND_CFG :=
KSYMS_ENV :=
ifeq ($(filter clean distclean,$(MAKECMDGOALS)),)
$(warning skipping $(EH_PROGS): unwinding via r3 needs LLVM >= 24, LLVM_PREFIX is LLVM $(LLVM_MAJOR))
endif
endif

all: progs
progs: $(addprefix $(BLDDIR)/,$(addsuffix .o,$(PROGS) $(EH_BUILD))) $(BLDDIR)/scxload

# Loads a scheduler and attaches all of its programs.
$(BLDDIR)/scxload: scxload.c
	@mkdir -p $(BLDDIR)
	$(CC) -O2 -Wall $(if $(LIBBPF),-I$(LIBBPF)/include) -o $@ $< $(if $(LIBBPF),$(LIBBPF)/libbpf.a,-lbpf) -lelf -lz

# --- core ---
$(DEPDIR)/libcore.rlib: $(RUST_SRC)/core/src/lib.rs
	@mkdir -p $(DEPDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null \
		--cfg 'no_fp_fmt_parse' \
		--crate-name core \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/libcore.rmeta \
		$<

# --- compiler_builtins (stub) ---
$(DEPDIR)/libcompiler_builtins.rlib: $(DEPDIR)/libcore.rlib
	@mkdir -p $(DEPDIR)
	echo '#![no_std]' '#![feature(compiler_builtins,rustc_attrs)]' '#![compiler_builtins]' '#![allow(internal_features)]' '#[rustc_std_internal_symbol] fn __rust_no_alloc_shim_is_unstable_v2() {}' | \
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--crate-name compiler_builtins \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/libcompiler_builtins.rmeta \
		-

# --- alloc ---
$(DEPDIR)/liballoc.rlib: $(RUST_SRC)/alloc/src/lib.rs $(DEPDIR)/libcompiler_builtins.rlib
	@mkdir -p $(DEPDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--crate-name alloc \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/liballoc.rmeta \
		$<

# --- functions that llc calls on its own: __multi3, memset ---
$(DEPDIR)/multi3.bc $(DEPDIR)/memset.bc: $(DEPDIR)/%.bc: $(CURDIR)/%.ll
	@mkdir -p $(DEPDIR)
	$(LLVM_AS) $< -o $@

# --- btf runtime crate (no_std, BPF target) ---
$(DEPDIR)/libbtf.rlib: $(CURDIR)/btf/src/lib.rs $(DEPDIR)/libcompiler_builtins.rlib
	@mkdir -p $(DEPDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--crate-name btf \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/libbtf.rmeta \
		$<

# --- btf-macros proc-macro crate (host) ---
# Built via cargo because it depends on syn/quote/proc-macro2. Proc-macro
# crates are always host-targeted; rustc loads the resulting .so when
# expanding `#[btf]` in BPF-target builds.
$(BLDDIR)/libbtf_macros.so: $(wildcard $(CURDIR)/btf-macros/src/*.rs) $(CURDIR)/btf-macros/Cargo.toml
	cd $(CURDIR)/btf-macros && PATH="$(RUST_TOOLCHAIN)/bin:$$PATH" RUSTC=$(RUSTC) $(CARGO) build --release
	@mkdir -p $(BLDDIR)
	cp $(CURDIR)/btf-macros/target/release/libbtf_macros.so $@

# --- bpf-postproc tool (host) ---
# Lowers __btf_field_byte_offset / __btf_field_exists polyfills into
# llvm.preserve.struct.access.index chains + llvm.bpf.preserve.field.info
# calls so the BPF backend emits CO-RE relocations.
# llvm-sys locates LLVM via llvm-config on PATH (unless a version-specific
# LLVM_SYS_<ver>_PREFIX env var overrides it), so putting the pinned install
# first points it at LLVM_PREFIX. Each llvm-sys accepts only its own LLVM
# major, so --features picks the crate for that major, and
# --no-default-features keeps the other one from being built alongside it.
$(BLDDIR)/bpf-postproc: $(wildcard $(CURDIR)/bpf-postproc/src/*.rs) $(CURDIR)/bpf-postproc/Cargo.toml
	cd $(POSTPROC_DIR) && \
		PATH="$(LLVM_PREFIX)/bin:$(RUST_TOOLCHAIN)/bin:$$PATH" LLVM_CONFIG=$(LLVM_CONFIG) \
		$(CARGO) build --release --no-default-features --features $(POSTPROC_FEATURE)
	@mkdir -p $(BLDDIR)
	cp $(POSTPROC_DIR)/target/release/bpf-postproc $@

# --- Build BPF program bitcode ---
$(BLDDIR)/%.bc: %.rs $(DEPDIR)/liballoc.rlib $(DEPDIR)/libbtf.rlib $(BLDDIR)/libbtf_macros.so
	@mkdir -p $(BLDDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--extern btf=$(DEPDIR)/libbtf.rlib \
		--extern btf_macros=$(BLDDIR)/libbtf_macros.so \
		-Zcrate-attr='feature(alloc_error_handler)' \
		--check-cfg 'cfg(bpf_unwind)' $(UNWIND_CFG) \
		--crate-name $(basename $(notdir $<)) \
		--emit=llvm-bc -o $@ $<

$(foreach p,$(SCX_PORTS),$(BLDDIR)/scx_$(p).bc): scx_common.rs

# --- Extract .rlib contents for linking ---
$(DEPDIR)/extracted: $(DEPDIR)/libcore.rlib $(DEPDIR)/libcompiler_builtins.rlib $(DEPDIR)/liballoc.rlib
	@mkdir -p $(DEPDIR)/extracted
	@for lib in $^; do \
		name=$$(basename $$lib .rlib | sed 's/^lib//'); \
		mkdir -p $(DEPDIR)/extracted/$$name; \
		cd $(DEPDIR)/extracted/$$name && ar x $$lib; \
	done
	@touch $@

# --- Link all bitcode ---
$(BLDDIR)/%-linked.bc: $(BLDDIR)/%.bc $(DEPDIR)/extracted $(DEPDIR)/multi3.bc $(DEPDIR)/memset.bc
	@cp $< $@
	@for i in 1 2 3 4 5; do \
		$(LLVM_LINK) --only-needed $@ \
			$$(find $(DEPDIR)/extracted -name '*.rcgu.o') \
			-o $@.tmp && mv $@.tmp $@; \
	done
	@$(LLVM_LINK) $@ $(DEPDIR)/multi3.bc $(DEPDIR)/memset.bc -o $@.tmp && mv $@.tmp $@

# --- Lower btf polyfills to CO-RE relocations ---
$(BLDDIR)/%-reloc.bc: $(BLDDIR)/%-linked.bc $(BLDDIR)/bpf-postproc
	$(BLDDIR)/bpf-postproc $< $@

# --- Optimize after linking (inlines trivial functions, DCE) ---
# Internalize everything except struct_ops entry points and license,
# then optimize. This lets opt remove dead global symbols.
# __multi3 and memset look dead until llc. Only there a multiplication that
# checks for overflow, like the one for the size of a Vec, turns into a call to
# the first, and an llvm.memset that is too long to expand into a call to the
# second.
KEEP_SYMS := simple_ops \
             simple_select_cpu simple_enqueue simple_dispatch \
             simple_running simple_stopping simple_enable \
             simple_init simple_exit \
             cosmos_ops \
             cosmos_select_cpu cosmos_tick cosmos_enqueue cosmos_dispatch \
             cosmos_runnable cosmos_running cosmos_stopping \
             cosmos_enable cosmos_init_task cosmos_exit_task \
             cosmos_init cosmos_exit \
             type_tag_entry TASK_TABLE \
             decl_tag_entry tagged_subprog SLOT \
             $(addsuffix _*,$(SCX_PORTS)) \
             __multi3 memset \
             _LICENSE
INTERNALIZE := $(foreach s,$(KEEP_SYMS),--internalize-public-api-list='$(s)')
$(BLDDIR)/%-opt.bc: $(BLDDIR)/%-reloc.bc
	$(OPT) $(INTERNALIZE) --force-remove-attribute=cold \
		-passes='forceattrs,internalize,globaldce,default<O2>' $< -o $@

# --- Add .ksyms, lower invoke→call, unreachable→ret for BPF ---
# Without KEEP_INVOKE=1 add_ksyms.py converts invoke→call, making landing pad
# blocks dead. simplifycfg removes those dead blocks. add_ksyms.py then fixes
# any remaining unreachable (e.g. switch defaults).
#
# btf_tags.py runs last, for two reasons. It has to see the .ksyms
# DISubprograms add_ksyms.py synthesises, because that is the only debug info a
# kfunc declaration has and therefore the only place a `bpf_fastcall`-style
# decl tag can attach. And BTF is generated from debug info by llc, so the
# annotations only have to exist at this point.
$(BLDDIR)/%-ksyms.bc: $(BLDDIR)/%-opt.bc $(CURDIR)/add_ksyms.py $(CURDIR)/btf_tags.py
	$(LLVM_DIS) $< -o $@.ll
	$(KSYMS_ENV) python3 $(CURDIR)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@.tmp.bc
	$(OPT) -passes=simplifycfg $@.tmp.bc -o $@.tmp2.bc
	$(LLVM_DIS) $@.tmp2.bc -o $@.ll
	$(KSYMS_ENV) python3 $(CURDIR)/add_ksyms.py $@.ll $@.ll
	python3 $(CURDIR)/btf_tags.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@
	@rm -f $@.ll $@.tmp.bc $@.tmp2.bc

# --- The same for the schedulers, whose memory is all in arena ---
# LLVM picks the locals and the global data that go there before add_ksyms.py
# turns memcpy and memcmp into kfuncs: what is passed to a kfunc is left where
# the kernel can see it. The prototypes of the kfuncs are copied from the BTF of
# the kernel. The stamp changes when another kernel is asked for.
KSYMS_BTF_ENV := KSYM_BTF_FILES='$(KSYM_BTF_FILES)' BPFTOOL='$(BPFTOOL)'
KSYMS_STAMP := $(BLDDIR)/.ksyms-btf
KSYMS_STAMP_TEXT := $(shell cksum $(KSYM_BTF_FILES) 2>/dev/null)

$(KSYMS_STAMP): FORCE
	@mkdir -p $(BLDDIR)
	@echo '$(KSYMS_STAMP_TEXT)' | cmp -s - $@ || echo '$(KSYMS_STAMP_TEXT)' > $@

# The parameters of kfuncs that do want memory in arena.
$(BLDDIR)/arena-kfunc-args: $(CURDIR)/arena_kfunc_args.py $(KSYMS_STAMP)
	BPFTOOL='$(BPFTOOL)' python3 $< $(KSYM_BTF_FILES) > $@

$(BLDDIR)/scx_%-ksyms.bc: $(BLDDIR)/scx_%-opt.bc $(CURDIR)/add_ksyms.py $(CURDIR)/btf_tags.py $(KSYMS_STAMP) $(BLDDIR)/arena-kfunc-args
	$(OPT) -mtriple=bpfel -passes='$(ARENA_PASSES)' -bpf-arena-kfunc-args=$$(cat $(BLDDIR)/arena-kfunc-args) $< -o $@.arena.bc
	$(LLVM_DIS) $@.arena.bc -o $@.ll
	$(KSYMS_ENV) $(KSYMS_BTF_ENV) python3 $(CURDIR)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@.tmp.bc
	$(OPT) -passes=simplifycfg $@.tmp.bc -o $@.tmp2.bc
	$(LLVM_DIS) $@.tmp2.bc -o $@.ll
	$(KSYMS_ENV) $(KSYMS_BTF_ENV) python3 $(CURDIR)/add_ksyms.py $@.ll $@.ll
	python3 $(CURDIR)/btf_tags.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@
	@rm -f $@.ll $@.tmp.bc $@.tmp2.bc $@.arena.bc

$(BLDDIR)/scx_%.o: $(BLDDIR)/scx_%-ksyms.bc
	$(LLC) -march=bpfel -mcpu=v4 -mattr=$(LLC_ATTR) -filetype=obj -o $@.tmp $<
	$(LLVM_OBJCOPY) \
		--remove-section=.eh_frame --remove-section=.rel.eh_frame \
		--remove-section=.gcc_except_table \
		--strip-symbol=rust_eh_personality $@.tmp $@
	@rm -f $@.tmp

# --- Final BPF object ---
$(BLDDIR)/%.o: $(BLDDIR)/%-ksyms.bc
	$(LLC) -march=bpfel -mcpu=v4 -filetype=obj -o $@.tmp $<
	$(LLVM_OBJCOPY) \
		--remove-section=.eh_frame --remove-section=.rel.eh_frame \
		--remove-section=.gcc_except_table \
		--strip-symbol=rust_eh_personality $@.tmp $@
	@rm -f $@.tmp

# --- BPF exception-handling programs ---
#
# Same tools and the same bc -> linked -> opt -> ksyms -> o shape as the
# pipeline above, with three differences:
#
#  * bpf-postproc is skipped, so -linked.bc feeds -opt.bc directly. All it
#    does is lower #[btf] CO-RE polyfills, and these programs are built
#    without --extern btf, so there is nothing for it to do.
#  * add_ksyms.py always runs with KEEP_INVOKE=1, so invoke, landingpad, resume
#    and noreturn survive into codegen and the backend can lower them to r3
#    and branches. The rest of what the script does is still needed, in
#    particular the .ksyms tagging that puts the cleanup kfuncs into BTF.
#  * add_ksyms.py runs with KERNEL_BTF=1, which reduces Rust type names to C
#    identifiers; the kernel rejects the whole .BTF section otherwise.
#
# The rules are generated per program because the ksyms step needs KERNEL_BTF=1
# and the pattern rule above does not set it.
EH_KEEP_SYMS := entry _LICENSE
EH_INTERNALIZE := $(foreach s,$(EH_KEEP_SYMS),--internalize-public-api-list=$(s))

define EH_PROG_RULES
$$(BLDDIR)/$(1).bc: $(1).rs $$(DEPDIR)/liballoc.rlib
	@mkdir -p $$(BLDDIR)
	$$(RUSTFLAGS_ENV) $$(RUSTC) --edition 2024 --crate-type rlib $$(RUSTC_COMMON) \
		--sysroot=/dev/null -L$$(DEPDIR) \
		--crate-name $(1) \
		--emit=llvm-bc -o $$@ $$<

$$(BLDDIR)/$(1)-opt.bc: $$(BLDDIR)/$(1)-linked.bc
	$$(OPT) $$(EH_INTERNALIZE) --force-remove-attribute=cold \
		-passes='forceattrs,internalize,globaldce,default<O2>' $$< -o $$@

$$(BLDDIR)/$(1)-ksyms.bc: $$(BLDDIR)/$(1)-opt.bc
	$$(LLVM_DIS) $$< -o $$@.ll
	KEEP_INVOKE=1 KERNEL_BTF=1 python3 $$(CURDIR)/add_ksyms.py $$@.ll $$@.ll
	$$(LLVM_AS) $$@.ll -o $$@.tmp.bc
	$$(OPT) -passes=simplifycfg $$@.tmp.bc -o $$@.tmp2.bc
	$$(LLVM_DIS) $$@.tmp2.bc -o $$@.ll
	KEEP_INVOKE=1 KERNEL_BTF=1 python3 $$(CURDIR)/add_ksyms.py $$@.ll $$@.ll
	$$(LLVM_AS) $$@.ll -o $$@
	@rm -f $$@.ll $$@.tmp.bc $$@.tmp2.bc

.PRECIOUS: $$(BLDDIR)/$(1).bc $$(BLDDIR)/$(1)-linked.bc \
           $$(BLDDIR)/$(1)-opt.bc $$(BLDDIR)/$(1)-ksyms.bc
endef

$(foreach p,$(EH_PROGS),$(eval $(call EH_PROG_RULES,$(p))))

clean:
	rm -rf $(BLDDIR)

distclean: clean
	rm -rf $(DEPDIR)

.PRECIOUS: $(BLDDIR)/%.bc $(BLDDIR)/%-linked.bc $(BLDDIR)/%-reloc.bc $(BLDDIR)/%-opt.bc $(BLDDIR)/%-ksyms.bc

.PHONY: all progs clean distclean FORCE

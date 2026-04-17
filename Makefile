# SPDX-License-Identifier: GPL-2.0
#
# Build standalone Rust BPF programs (no kernel crate dependency)
#
# Usage: make

BLDDIR := $(CURDIR)/bld
LLC := /w/llvm/llvm/bld/install/bin/llc
OPT := /w/llvm/llvm/bld/install/bin/opt
LLVM_LINK := /w/llvm/llvm/bld/install/bin/llvm-link
LLVM_AS := /w/llvm/llvm/bld/install/bin/llvm-as
LLVM_DIS := /w/llvm/llvm/bld/install/bin/llvm-dis
TARGET := $(CURDIR)/bpfel-unknown-none-v4.json
DEPDIR := $(BLDDIR)/deps
RUST_SRC := /usr/lib/rustlib/src/rust/library

RUSTFLAGS_ENV := RUSTC_BOOTSTRAP=1
RUSTC := rustc
RUSTC_COMMON := --target $(TARGET) -C opt-level=3 -C panic=unwind -C debuginfo=2 -Z unstable-options

PROGS := scx_simple scx_cosmos

all: $(addprefix $(BLDDIR)/,$(addsuffix .o,$(PROGS)))

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

# --- multi3 intrinsic ---
$(DEPDIR)/multi3.bc: $(CURDIR)/multi3.ll
	@mkdir -p $(DEPDIR)
	$(LLVM_AS) $< -o $@

# --- Build BPF program bitcode ---
$(BLDDIR)/%.bc: %.rs $(DEPDIR)/liballoc.rlib
	@mkdir -p $(BLDDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		-Zcrate-attr='feature(alloc_error_handler)' \
		--crate-name $(basename $(notdir $<)) \
		--emit=llvm-bc -o $@ $<

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
$(BLDDIR)/%-linked.bc: $(BLDDIR)/%.bc $(DEPDIR)/extracted $(DEPDIR)/multi3.bc
	@cp $< $@
	@for i in 1 2 3 4 5; do \
		$(LLVM_LINK) --only-needed $@ \
			$$(find $(DEPDIR)/extracted -name '*.rcgu.o') \
			-o $@.tmp && mv $@.tmp $@; \
	done
	@$(LLVM_LINK) $@ $(DEPDIR)/multi3.bc -o $@.tmp && mv $@.tmp $@

# --- Optimize after linking (inlines trivial functions, DCE) ---
# Internalize everything except struct_ops entry points and license,
# then optimize. This lets opt remove dead global symbols.
KEEP_SYMS := simple_ops \
             simple_select_cpu simple_enqueue simple_dispatch \
             simple_running simple_stopping simple_enable \
             simple_init simple_exit \
             cosmos_select_cpu cosmos_tick cosmos_enqueue cosmos_dispatch \
             cosmos_runnable cosmos_running cosmos_stopping \
             cosmos_enable cosmos_init_task cosmos_exit_task \
             cosmos_init cosmos_exit \
             _LICENSE
INTERNALIZE := $(foreach s,$(KEEP_SYMS),--internalize-public-api-list=$(s))
$(BLDDIR)/%-opt.bc: $(BLDDIR)/%-linked.bc
	$(OPT) $(INTERNALIZE) --force-remove-attribute=cold \
		-passes='forceattrs,internalize,globaldce,default<O2>' $< -o $@

# --- Add .ksyms, lower invoke→call, unreachable→ret for BPF ---
# add_ksyms.py converts invoke→call, making landing pad blocks dead.
# simplifycfg removes those dead blocks. add_ksyms.py then fixes any
# remaining unreachable (e.g. switch defaults).
$(BLDDIR)/%-ksyms.bc: $(BLDDIR)/%-opt.bc
	$(LLVM_DIS) $< -o $@.ll
	python3 $(CURDIR)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@.tmp.bc
	$(OPT) -passes=simplifycfg $@.tmp.bc -o $@.tmp2.bc
	$(LLVM_DIS) $@.tmp2.bc -o $@.ll
	python3 $(CURDIR)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@
	@rm -f $@.ll $@.tmp.bc $@.tmp2.bc

# --- Final BPF object ---
$(BLDDIR)/%.o: $(BLDDIR)/%-ksyms.bc
	$(LLC) -march=bpfel -mcpu=v4 -filetype=obj -o $@.tmp $<
	/w/llvm/llvm/bld/install/bin/llvm-objcopy \
		--remove-section=.eh_frame --remove-section=.rel.eh_frame \
		--remove-section=.gcc_except_table \
		--strip-symbol=rust_eh_personality $@.tmp $@
	@rm -f $@.tmp

clean:
	rm -rf $(BLDDIR)

.PRECIOUS: $(BLDDIR)/%.bc $(BLDDIR)/%-linked.bc $(BLDDIR)/%-opt.bc $(BLDDIR)/%-ksyms.bc

.PHONY: all clean

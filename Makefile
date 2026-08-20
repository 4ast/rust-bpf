# SPDX-License-Identifier: GPL-2.0
#
# Build standalone Rust BPF programs (no kernel crate dependency)
#
# Usage: make

BLDDIR := $(CURDIR)/bld
LLVM_PREFIX ?= /w/llvm/llvm/bld/install
CLANG := $(LLVM_PREFIX)/bin/clang
LLC := $(LLVM_PREFIX)/bin/llc
OPT := $(LLVM_PREFIX)/bin/opt
LLVM_LINK := $(LLVM_PREFIX)/bin/llvm-link
LLVM_AS := $(LLVM_PREFIX)/bin/llvm-as
LLVM_DIS := $(LLVM_PREFIX)/bin/llvm-dis
LLVM_OBJCOPY := $(LLVM_PREFIX)/bin/llvm-objcopy
TARGET := $(CURDIR)/bpfel-unknown-none-v4.json
# Persistent across `rm -rf bld` — libcore/liballoc rebuilds dominate clean
# builds (~22s), and these only depend on rustc/RUST_SRC, not on user code.
DEPDIR := $(CURDIR)/bld_deps
# System rustc + /usr/lib/rustlib/src can be mismatched (RHEL packaging splits
# the compiler and source versions). Default to the locally-built toolchain
# under /w/rust, overridable via env or `make RUSTC=... RUST_SRC=...`.
RUSTC ?= /w/rust/build/x86_64-unknown-linux-gnu/stage1/bin/rustc
RUST_SRC ?= /w/rust/library
CARGO ?= cargo

RUSTFLAGS_ENV := RUSTC_BOOTSTRAP=1
RUSTC_COMMON := --target $(TARGET) -C opt-level=3 -C panic=unwind -C debuginfo=2 -Z unstable-options -Z threads=64

# Host triple for proc-macro and bpf-postproc builds (default to current).
HOST_TRIPLE ?= x86_64-unknown-linux-gnu

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

# --- btf runtime crate (no_std, BPF target) ---
$(DEPDIR)/libbtf.rlib: $(CURDIR)/btf/src/lib.rs $(DEPDIR)/libcore.rlib
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
	cd $(CURDIR)/btf-macros && RUSTC=$(RUSTC) $(CARGO) build --release
	@mkdir -p $(BLDDIR)
	cp $(CURDIR)/btf-macros/target/release/libbtf_macros.so $@

# --- bpf-postproc tool (host) ---
# Lowers __btf_field_byte_offset / __btf_field_exists polyfills into
# llvm.preserve.struct.access.index chains + llvm.bpf.preserve.field.info
# calls so the BPF backend emits CO-RE relocations.
# llvm-sys locates LLVM via llvm-config on PATH (unless a version-specific
# LLVM_SYS_<ver>_PREFIX env var overrides it), so putting the pinned install
# first keeps this rule agnostic of the llvm-sys version in Cargo.toml.
$(BLDDIR)/bpf-postproc: $(wildcard $(CURDIR)/bpf-postproc/src/*.rs) $(CURDIR)/bpf-postproc/Cargo.toml
	cd $(CURDIR)/bpf-postproc && \
		PATH="$(LLVM_PREFIX)/bin:$$PATH" \
		$(CARGO) build --release
	@mkdir -p $(BLDDIR)
	cp $(CURDIR)/bpf-postproc/target/release/bpf-postproc $@

# --- Build BPF program bitcode ---
$(BLDDIR)/%.bc: %.rs $(DEPDIR)/liballoc.rlib $(DEPDIR)/libbtf.rlib $(BLDDIR)/libbtf_macros.so
	@mkdir -p $(BLDDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--extern btf=$(DEPDIR)/libbtf.rlib \
		--extern btf_macros=$(BLDDIR)/libbtf_macros.so \
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

# --- Lower btf polyfills to CO-RE relocations ---
$(BLDDIR)/%-reloc.bc: $(BLDDIR)/%-linked.bc $(BLDDIR)/bpf-postproc
	$(BLDDIR)/bpf-postproc $< $@

# --- Optimize after linking (inlines trivial functions, DCE) ---
# Internalize everything except struct_ops entry points and license,
# then optimize. This lets opt remove dead global symbols.
KEEP_SYMS := simple_ops \
             simple_select_cpu simple_enqueue simple_dispatch \
             simple_running simple_stopping simple_enable \
             simple_init simple_exit \
             cosmos_ops \
             cosmos_select_cpu cosmos_tick cosmos_enqueue cosmos_dispatch \
             cosmos_runnable cosmos_running cosmos_stopping \
             cosmos_enable cosmos_init_task cosmos_exit_task \
             cosmos_init cosmos_exit \
             _LICENSE
INTERNALIZE := $(foreach s,$(KEEP_SYMS),--internalize-public-api-list=$(s))
$(BLDDIR)/%-opt.bc: $(BLDDIR)/%-reloc.bc
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
	$(LLVM_OBJCOPY) \
		--remove-section=.eh_frame --remove-section=.rel.eh_frame \
		--remove-section=.gcc_except_table \
		--strip-symbol=rust_eh_personality $@.tmp $@
	@rm -f $@.tmp

clean:
	rm -rf $(BLDDIR)

distclean: clean
	rm -rf $(DEPDIR)

.PRECIOUS: $(BLDDIR)/%.bc $(BLDDIR)/%-linked.bc $(BLDDIR)/%-reloc.bc $(BLDDIR)/%-opt.bc $(BLDDIR)/%-ksyms.bc

.PHONY: all clean distclean

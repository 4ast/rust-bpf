# SPDX-License-Identifier: GPL-2.0
#
# Corpus of Rust BPF programs made of core, alloc and no_std crates.
#
# Usage: make [-j8], or make in the directory above. Tools: ../toolchain.mk
#
# cargo compiles the crates (features, build scripts and proc macros are its
# job) against core and alloc that ../Makefile builds. The target emits bitcode
# instead of objects, so what follows is the pipeline of ../Makefile: link the
# bitcode, optimize, add_ksyms.py, llc.

include ../toolchain.mk

BLDDIR := $(CURDIR)/bld
DEPDIR := $(BLDDIR)/deps
OPT := $(LLVM_PREFIX)/bin/opt
LLVM_LINK := $(LLVM_PREFIX)/bin/llvm-link
# The crates: what Cargo.lock says is copied to vendor/ once, from the cache of
# cargo if it is all there, else it is downloaded. The rest is offline.
CARGO_SRC := --offline --config 'source.crates-io.replace-with="vendored-sources"' \
	--config 'source.vendored-sources.directory="$(CURDIR)/vendor"'
TARGET_NAME := bpfel-unknown-none-v4
TARGET := $(TOP)/$(TARGET_NAME).json
SYSROOT := $(BLDDIR)/sysroot
SYSLIB := $(SYSROOT)/lib/rustlib/$(TARGET_NAME)/lib
CARGO_OUT := $(BLDDIR)/target/$(TARGET_NAME)/release

TESTS := $(basename $(notdir $(wildcard tests-bpf/*.rs)))

all: files one
files: $(addprefix $(BLDDIR)/,$(addsuffix .o,$(TESTS)))

vendor: vendor/.stamp
vendor/.stamp: Cargo.lock
	PATH="$(RUST_TOOLCHAIN)/bin:$$PATH" $(CARGO) vendor --locked --offline vendor > /dev/null 2>&1 || \
	PATH="$(RUST_TOOLCHAIN)/bin:$$PATH" $(CARGO) vendor --locked vendor > /dev/null
	@touch $@

# --- core with Display and FromStr for floats, alloc, the stub of compiler_builtins ---
$(DEPDIR)/liballoc.rlib:
	$(MAKE) -C $(TOP) DEPDIR=$(DEPDIR) CORE_CFG= $@
$(DEPDIR)/libcore.rlib $(DEPDIR)/libcompiler_builtins.rlib: $(DEPDIR)/liballoc.rlib
	@:

# --- where rustc looks for them ---
$(SYSLIB)/.stamp: $(DEPDIR)/libcore.rlib $(DEPDIR)/liballoc.rlib $(DEPDIR)/libcompiler_builtins.rlib
	@mkdir -p $(SYSLIB)
	ln -sf $^ $(SYSLIB)/
	@touch $@

# --- every crate and every test, as rlibs with bitcode inside ---
# artifacts.txt: the rlibs of this build. The directories of cargo keep the
# results of earlier builds too.
$(BLDDIR)/artifacts.txt: $(SYSLIB)/.stamp vendor/.stamp Cargo.toml src/lib.rs $(wildcard tests-bpf/*.rs)
	PATH="$(RUST_TOOLCHAIN)/bin:$$PATH" RUSTC_BOOTSTRAP=1 CARGO_TARGET_DIR=$(BLDDIR)/target \
	RUSTFLAGS="--sysroot=$(SYSROOT) -Z unstable-options" \
	$(CARGO) build -Zjson-target-spec $(CARGO_SRC) --release --keep-going --examples --target $(TARGET) -j8 \
		--message-format=json-render-diagnostics > $(BLDDIR)/cargo.json; \
	python3 -c 'import json,sys; [print(f) for l in open(sys.argv[1]) for m in [json.loads(l)] if m.get("reason") == "compiler-artifact" for f in m["filenames"] if f.endswith(".rlib") and "/$(TARGET_NAME)/" in f]' \
		$(BLDDIR)/cargo.json > $@

# --- all libraries in one module: one pass of --only-needed takes what a test needs ---
$(BLDDIR)/world.bc: $(BLDDIR)/artifacts.txt
	@rm -rf $(BLDDIR)/x && mkdir -p $(BLDDIR)/x
	@for lib in $$(grep -v /examples/ $<) $(DEPDIR)/libcore.rlib $(DEPDIR)/liballoc.rlib $(DEPDIR)/libcompiler_builtins.rlib; do \
		d=$(BLDDIR)/x/$$(basename $$lib .rlib); mkdir -p $$d; (cd $$d && ar x $$lib); \
	done
	$(LLVM_LINK) $$(find $(BLDDIR)/x -name '*.o' ! -path '*/librt-*') -o $@
	$(LLVM_LINK) $$(find $(BLDDIR)/x -name '*.o' -path '*/librt-*') -o $(BLDDIR)/rt.bc

# --- the real compiler_builtins: 128 bit division, soft float, libm ---
# The one in ../bld_deps is a stub. The manifest wants core as a path
# dependency, which is for the build of std.
$(BLDDIR)/builtins.bc: $(SYSLIB)/.stamp builtins-abi.py
	@rm -rf $(BLDDIR)/cb && mkdir -p $(BLDDIR)/cb/x
	cp -r $(RUST_SRC)/compiler-builtins/compiler-builtins $(RUST_SRC)/compiler-builtins/libm $(BLDDIR)/cb/
	cd $(BLDDIR)/cb/compiler-builtins && \
	sed -i '/^core = { path/d; s/^rustc-dep-of-std = .*/rustc-dep-of-std = ["compiler-builtins"]/' Cargo.toml && \
	echo '[workspace]' >> Cargo.toml && \
	PATH="$(RUST_TOOLCHAIN)/bin:$$PATH" RUSTC_BOOTSTRAP=1 CARGO_TARGET_DIR=$(BLDDIR)/cb/target \
	RUSTFLAGS="--sysroot=$(SYSROOT) -Z unstable-options -C debuginfo=2" \
	$(CARGO) build -q -Zjson-target-spec --offline --release --target $(TARGET) -j8
	cd $(BLDDIR)/cb/x && ar x $(BLDDIR)/cb/target/$(TARGET_NAME)/release/libcompiler_builtins.rlib
	$(LLVM_LINK) $(BLDDIR)/cb/x/*.o -o $@.tmp
	$(LLVM_PREFIX)/bin/llvm-extract --delete $(foreach f,memcpy memmove memset memcmp bcmp,--func=$(f)) $@.tmp -S -o $@.ll
	./builtins-abi.py $@.ll $@.ll
	$(OPT) -passes='default<O2>' $@.ll -o $@
	@rm -f $@.tmp $@.ll

$(BLDDIR)/shim.bc: shim.c
	$(CLANG) -g -O2 -target bpf -mcpu=v4 -emit-llvm -c $< -o $@

# --- the test, the run time as a whole (nothing refers to the license), the rest as needed ---
$(BLDDIR)/%-linked.bc: $(BLDDIR)/world.bc
	@rm -rf $(BLDDIR)/t/$* && mkdir -p $(BLDDIR)/t/$*
	@test -f $(CARGO_OUT)/examples/lib$*.rlib && grep -q "/examples/lib$*\.rlib" $(BLDDIR)/artifacts.txt
	cd $(BLDDIR)/t/$* && ar x $(CARGO_OUT)/examples/lib$*.rlib
	$(LLVM_LINK) $(BLDDIR)/t/$*/*.o $(BLDDIR)/rt.bc -o $@.tmp
	$(LLVM_LINK) --only-needed $@.tmp $(BLDDIR)/world.bc -o $@
	@rm -f $@.tmp

# --- an object per file, with all its programs ---
# A test that does not compile is a result like any other: run-tests.sh lists
# it. So the error is shown and make goes on.
NAMES = $$(sed -n 's/^test!(\(leaks \)\{0,1\}\([a-z_0-9]*\),.*/\2/p' tests-bpf/$(1).rs)
BC2OBJ := LLVM_PREFIX=$(LLVM_PREFIX) BLDDIR=$(BLDDIR) TOP=$(TOP) LLC_ATTR='$(LLC_ATTR)' \
	ARENA_PASSES='$(ARENA_PASSES)' KEEP_TMP=$(KEEP_TMP) \
	KSYM_BTF_FILES='$(KSYM_BTF_FILES)' BPFTOOL='$(BPFTOOL)' ./bc2obj.sh

# The prototypes of the kfuncs are copied from the BTF of the kernel. The stamp
# changes when another kernel is asked for.
KSYMS_STAMP := $(BLDDIR)/.ksyms-btf
KSYMS_STAMP_TEXT := $(shell cksum $(KSYM_BTF_FILES) 2>/dev/null)

$(KSYMS_STAMP): FORCE
	@mkdir -p $(BLDDIR)
	@echo '$(KSYMS_STAMP_TEXT)' | cmp -s - $@ || echo '$(KSYMS_STAMP_TEXT)' > $@

BC2OBJ_DEPS := $(KSYMS_STAMP) $(BLDDIR)/builtins.bc $(BLDDIR)/shim.bc bc2obj.sh link-builtins.sh fix-protos.py fix-dbgloc.py $(TOP)/add_ksyms.py

$(BLDDIR)/%.o: $(BLDDIR)/%-linked.bc $(BC2OBJ_DEPS)
	-$(BC2OBJ) $< $@ $(call NAMES,$*)

# --- an object per program: what is wrong with one doesn't hide the others ---
# tests.mk: $(BLDDIR)/one/PROG.o: $(BLDDIR)/FILE-linked.bc
$(BLDDIR)/tests.mk: $(wildcard tests-bpf/*.rs)
	@mkdir -p $(BLDDIR)/one
	@for f in $(TESTS); do \
		for p in $(call NAMES,$$f); do \
			echo "ONE += \$$(BLDDIR)/one/$$p.o"; \
			echo "\$$(BLDDIR)/one/$$p.o: \$$(BLDDIR)/$$f-linked.bc"; \
		done; \
	done > $@

-include $(BLDDIR)/tests.mk

$(BLDDIR)/one/%.o: $(BC2OBJ_DEPS)
	-$(BC2OBJ) $(filter %-linked.bc,$^) $@ $*

one: $(ONE)

# --- control: the same tests on the host ---
host: $(addprefix $(BLDDIR)/host/lib,$(addsuffix .so,$(TESTS))) $(BLDDIR)/host/run

$(BLDDIR)/host/lib%.so: tests-bpf/%.rs src/lib.rs Cargo.toml vendor/.stamp
	@mkdir -p $(BLDDIR)/host
	PATH="$(RUST_TOOLCHAIN)/bin:$$PATH" CARGO_TARGET_DIR=$(BLDDIR)/host-target \
	$(CARGO) rustc $(CARGO_SRC) --release --example $* --crate-type cdylib -j8
	cp $(BLDDIR)/host-target/release/examples/lib$*.so $@

$(BLDDIR)/host/run: hostrun.c
	@mkdir -p $(BLDDIR)/host
	$(CC) -O2 -Wall -o $@ $< -ldl

# --- loads and runs the tests ---
run: $(BLDDIR)/run
$(BLDDIR)/run: run.c
	@mkdir -p $(BLDDIR)
	$(CC) -O2 -Wall $(if $(LIBBPF),-I$(LIBBPF)/include) -o $@ $< $(if $(LIBBPF),$(LIBBPF)/libbpf.a,-lbpf) -lelf -lz

clean:
	rm -rf $(BLDDIR)

.PRECIOUS: $(BLDDIR)/%-linked.bc
.PHONY: all files one host run vendor clean FORCE

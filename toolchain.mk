# SPDX-License-Identifier: GPL-2.0
#
# The tools and flags that Makefile and corpus/Makefile share. Settings of the
# machine go to config.mk next to this file (not tracked, see README.md) or on
# the command line.

TOP := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
-include $(TOP)/config.mk

LLVM_PREFIX ?= /w/llvm/llvm/bld/install

# RUSTC and RUST_SRC must come from the SAME rustc: libcore/liballoc use lang
# items and built-in macros that only the exactly-matching compiler knows
# about, so a released toolchain paired with an unrelated rust checkout fails
# outright (hundreds of errors in core). The nightly rustup toolchain plus its
# own rust-src component is a matched pair by construction:
#   rustup toolchain install nightly && rustup component add rust-src --toolchain nightly
# To build against a rust git checkout instead, bootstrap it there
# (`./configure && ./x.py build --stage 1 library`) and override both:
#   make RUSTC=<tree>/build/<triple>/stage1/bin/rustc RUST_SRC=<tree>/library
HOST_TRIPLE ?= x86_64-unknown-linux-gnu
RUST_TOOLCHAIN ?= $(lastword $(sort $(wildcard $(HOME)/.rustup/toolchains/nightly*-$(HOST_TRIPLE))))
RUSTC ?= $(RUST_TOOLCHAIN)/bin/rustc
RUST_SRC ?= $(RUST_TOOLCHAIN)/lib/rustlib/src/rust/library
CARGO ?= $(RUST_TOOLCHAIN)/bin/cargo
RUSTC_THREADS ?= 64

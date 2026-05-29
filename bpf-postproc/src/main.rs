// Tool: bpf-postproc <input.bc> <output.bc>
//
// Runs the in-tree `FieldRelocPass` against a linked bitcode module,
// turning `__btf_field_byte_offset` / `__btf_field_exists` polyfill
// calls (emitted by the `btf` runtime crate) into preserve-access
// chains terminated by `llvm.bpf.preserve.field.info`. The result is
// ordinary LLVM IR that the BPF backend lowers into `.BTF.ext` CO-RE
// relocation records.

// Bring the feature-gated rename in as the generic `llvm_sys` name so
// `field_reloc.rs` (vendored verbatim) and `llvm.rs` can import paths
// like `llvm_sys::core::*` without per-version qualification.
#[cfg(feature = "llvm-22")]
extern crate llvm_sys_22 as llvm_sys;

use std::ffi::CString;
use std::process::ExitCode;

use llvm_sys::bit_reader::LLVMParseBitcodeInContext2;
use llvm_sys::bit_writer::LLVMWriteBitcodeToFile;
use llvm_sys::core::{
    LLVMContextCreate, LLVMContextDispose, LLVMCreateMemoryBufferWithContentsOfFile,
    LLVMDisposeMemoryBuffer, LLVMDisposeMessage, LLVMDisposeModule,
};
use llvm_sys::prelude::{LLVMMemoryBufferRef, LLVMModuleRef};

mod field_reloc;
mod llvm;

use crate::field_reloc::FieldRelocPass;
use crate::llvm::{LLVMContext, LLVMModule};

fn main() -> ExitCode {
    let mut args = std::env::args();
    let _prog = args.next();
    let input = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: bpf-postproc <input.bc> <output.bc>");
            return ExitCode::from(2);
        }
    };
    let output = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: bpf-postproc <input.bc> <output.bc>");
            return ExitCode::from(2);
        }
    };

    let ctx_raw = unsafe { LLVMContextCreate() };
    let context = LLVMContext::from_raw(ctx_raw);

    let input_c = match CString::new(input.clone()) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("bpf-postproc: input path contains NUL");
            return ExitCode::from(1);
        }
    };
    let mut buf: LLVMMemoryBufferRef = std::ptr::null_mut();
    let mut err_msg: *mut std::ffi::c_char = std::ptr::null_mut();
    if unsafe {
        LLVMCreateMemoryBufferWithContentsOfFile(input_c.as_ptr(), &mut buf, &mut err_msg)
    } != 0
    {
        eprintln!(
            "bpf-postproc: read {input}: {}",
            unsafe { take_msg(err_msg) }
        );
        unsafe { LLVMContextDispose(ctx_raw) };
        return ExitCode::from(1);
    }

    let mut module_raw: LLVMModuleRef = std::ptr::null_mut();
    if unsafe { LLVMParseBitcodeInContext2(ctx_raw, buf, &mut module_raw) } != 0 {
        eprintln!("bpf-postproc: parse {input}: invalid bitcode");
        unsafe { LLVMDisposeMemoryBuffer(buf) };
        unsafe { LLVMContextDispose(ctx_raw) };
        return ExitCode::from(1);
    }
    unsafe { LLVMDisposeMemoryBuffer(buf) };

    let mut module = LLVMModule::from_raw(module_raw);

    {
        let mut pass = FieldRelocPass::new(&context, &mut module);
        if let Err(e) = pass.run() {
            eprintln!("bpf-postproc: {e}");
            unsafe { LLVMDisposeModule(module_raw) };
            unsafe { LLVMContextDispose(ctx_raw) };
            return ExitCode::from(1);
        }
    }

    let output_c = match CString::new(output.clone()) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("bpf-postproc: output path contains NUL");
            unsafe { LLVMDisposeModule(module_raw) };
            unsafe { LLVMContextDispose(ctx_raw) };
            return ExitCode::from(1);
        }
    };
    if unsafe { LLVMWriteBitcodeToFile(module_raw, output_c.as_ptr()) } != 0 {
        eprintln!("bpf-postproc: write {output}: failed");
        unsafe { LLVMDisposeModule(module_raw) };
        unsafe { LLVMContextDispose(ctx_raw) };
        return ExitCode::from(1);
    }

    unsafe { LLVMDisposeModule(module_raw) };
    unsafe { LLVMContextDispose(ctx_raw) };
    ExitCode::SUCCESS
}

unsafe fn take_msg(msg: *mut std::ffi::c_char) -> String {
    if msg.is_null() {
        return String::new();
    }
    let s = unsafe { std::ffi::CStr::from_ptr(msg) }
        .to_string_lossy()
        .into_owned();
    unsafe { LLVMDisposeMessage(msg) };
    s
}

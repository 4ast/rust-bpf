//! The subset of the LLVM C API that bpf-postproc uses, laid out like llvm-sys.
//! Prototypes and enum values are from llvm/include/llvm-c of LLVM 24.
#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

pub enum LLVMOpaque {}

pub mod prelude {
    use super::LLVMOpaque;
    pub type LLVMBool = ::core::ffi::c_int;
    pub type LLVMMemoryBufferRef = *mut LLVMOpaque;
    pub type LLVMContextRef = *mut LLVMOpaque;
    pub type LLVMModuleRef = *mut LLVMOpaque;
    pub type LLVMTypeRef = *mut LLVMOpaque;
    pub type LLVMValueRef = *mut LLVMOpaque;
    pub type LLVMBasicBlockRef = *mut LLVMOpaque;
    pub type LLVMMetadataRef = *mut LLVMOpaque;
    pub type LLVMBuilderRef = *mut LLVMOpaque;
    pub type LLVMAttributeRef = *mut LLVMOpaque;
}

pub type LLVMAttributeIndex = ::core::ffi::c_uint;

/// A C enum of which only some values are named here, so not a Rust enum.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LLVMOpcode(pub ::core::ffi::c_uint);
impl LLVMOpcode {
    pub const LLVMCall: Self = Self(45);
}

pub mod core {
    use super::prelude::*;
    use super::{LLVMAttributeIndex, LLVMOpcode};
    use ::core::ffi::{c_char, c_int, c_uint, c_ulonglong};

    unsafe extern "C" {
        pub fn LLVMContextCreate() -> LLVMContextRef;
        pub fn LLVMContextDispose(C: LLVMContextRef);
        pub fn LLVMDisposeMessage(Message: *mut c_char);
        pub fn LLVMDisposeModule(M: LLVMModuleRef);
        pub fn LLVMCreateMemoryBufferWithContentsOfFile(
            Path: *const c_char,
            OutMemBuf: *mut LLVMMemoryBufferRef,
            OutMessage: *mut *mut c_char,
        ) -> LLVMBool;
        pub fn LLVMDisposeMemoryBuffer(MemBuf: LLVMMemoryBufferRef);

        pub fn LLVMGetFirstFunction(M: LLVMModuleRef) -> LLVMValueRef;
        pub fn LLVMGetNextFunction(Fn: LLVMValueRef) -> LLVMValueRef;
        pub fn LLVMGetFirstBasicBlock(Fn: LLVMValueRef) -> LLVMBasicBlockRef;
        pub fn LLVMGetNextBasicBlock(BB: LLVMBasicBlockRef) -> LLVMBasicBlockRef;
        pub fn LLVMGetFirstInstruction(BB: LLVMBasicBlockRef) -> LLVMValueRef;
        pub fn LLVMGetNextInstruction(Inst: LLVMValueRef) -> LLVMValueRef;
        pub fn LLVMGetInstructionOpcode(Inst: LLVMValueRef) -> LLVMOpcode;
        pub fn LLVMInstructionEraseFromParent(Inst: LLVMValueRef);

        pub fn LLVMGetNumOperands(Val: LLVMValueRef) -> c_int;
        pub fn LLVMGetOperand(Val: LLVMValueRef, Index: c_uint) -> LLVMValueRef;
        pub fn LLVMGetValueName2(Val: LLVMValueRef, Length: *mut usize) -> *const c_char;
        pub fn LLVMTypeOf(Val: LLVMValueRef) -> LLVMTypeRef;
        pub fn LLVMGlobalGetValueType(Global: LLVMValueRef) -> LLVMTypeRef;
        pub fn LLVMReplaceAllUsesWith(OldVal: LLVMValueRef, NewVal: LLVMValueRef);

        pub fn LLVMGetCalledValue(Instr: LLVMValueRef) -> LLVMValueRef;
        pub fn LLVMGetNumArgOperands(Instr: LLVMValueRef) -> c_uint;
        pub fn LLVMGetArgOperand(Funclet: LLVMValueRef, i: c_uint) -> LLVMValueRef;
        pub fn LLVMAddCallSiteAttribute(
            C: LLVMValueRef,
            Idx: LLVMAttributeIndex,
            A: LLVMAttributeRef,
        );
        pub fn LLVMGetEnumAttributeKindForName(Name: *const c_char, SLen: usize) -> c_uint;
        pub fn LLVMCreateTypeAttribute(
            C: LLVMContextRef,
            KindID: c_uint,
            type_ref: LLVMTypeRef,
        ) -> LLVMAttributeRef;

        pub fn LLVMLookupIntrinsicID(Name: *const c_char, NameLen: usize) -> c_uint;
        pub fn LLVMGetIntrinsicDeclaration(
            Mod: LLVMModuleRef,
            ID: c_uint,
            OverloadTypes: *mut LLVMTypeRef,
            OverloadCount: usize,
        ) -> LLVMValueRef;

        pub fn LLVMInt8TypeInContext(C: LLVMContextRef) -> LLVMTypeRef;
        pub fn LLVMInt32TypeInContext(C: LLVMContextRef) -> LLVMTypeRef;
        pub fn LLVMInt64TypeInContext(C: LLVMContextRef) -> LLVMTypeRef;
        pub fn LLVMStructTypeInContext(
            C: LLVMContextRef,
            ElementTypes: *mut LLVMTypeRef,
            ElementCount: c_uint,
            Packed: LLVMBool,
        ) -> LLVMTypeRef;
        pub fn LLVMConstInt(IntTy: LLVMTypeRef, N: c_ulonglong, SignExtend: LLVMBool)
            -> LLVMValueRef;

        pub fn LLVMCreateBuilderInContext(C: LLVMContextRef) -> LLVMBuilderRef;
        pub fn LLVMDisposeBuilder(Builder: LLVMBuilderRef);
        pub fn LLVMPositionBuilderBefore(Builder: LLVMBuilderRef, Instr: LLVMValueRef);
        pub fn LLVMBuildCall2(
            B: LLVMBuilderRef,
            Ty: LLVMTypeRef,
            Fn: LLVMValueRef,
            Args: *mut LLVMValueRef,
            NumArgs: c_uint,
            Name: *const c_char,
        ) -> LLVMValueRef;

        pub fn LLVMGetMDKindIDInContext(
            C: LLVMContextRef,
            Name: *const c_char,
            SLen: c_uint,
        ) -> c_uint;
        pub fn LLVMSetMetadata(Val: LLVMValueRef, KindID: c_uint, Node: LLVMValueRef);
        pub fn LLVMMDStringInContext2(
            C: LLVMContextRef,
            Str: *const c_char,
            SLen: usize,
        ) -> LLVMMetadataRef;
        pub fn LLVMMetadataAsValue(C: LLVMContextRef, MD: LLVMMetadataRef) -> LLVMValueRef;
        pub fn LLVMValueAsMetadata(Val: LLVMValueRef) -> LLVMMetadataRef;
        pub fn LLVMReplaceMDNodeOperandWith(
            V: LLVMValueRef,
            Index: c_uint,
            Replacement: LLVMMetadataRef,
        );
    }
}

pub mod debuginfo {
    use super::prelude::*;
    use ::core::ffi::{c_char, c_uint};

    /// `typedef unsigned LLVMMetadataKind` over an anonymous enum.
    #[repr(transparent)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct LLVMMetadataKind(pub c_uint);
    impl LLVMMetadataKind {
        pub const LLVMDIDerivedTypeMetadataKind: Self = Self(12);
        pub const LLVMDICompositeTypeMetadataKind: Self = Self(13);
        pub const LLVMDISubprogramMetadataKind: Self = Self(17);
        pub const LLVMDILexicalBlockMetadataKind: Self = Self(18);
        pub const LLVMDILexicalBlockFileMetadataKind: Self = Self(19);
    }

    unsafe extern "C" {
        pub fn LLVMGetMetadataKind(Metadata: LLVMMetadataRef) -> LLVMMetadataKind;
        pub fn LLVMGetDINodeTag(MD: LLVMMetadataRef) -> u16;
        pub fn LLVMDITypeGetName(DType: LLVMMetadataRef, Length: *mut usize) -> *const c_char;
        pub fn LLVMDILocationGetScope(Location: LLVMMetadataRef) -> LLVMMetadataRef;
        pub fn LLVMInstructionGetDebugLoc(Inst: LLVMValueRef) -> LLVMMetadataRef;
    }
}

pub mod bit_reader {
    use super::prelude::*;
    unsafe extern "C" {
        pub fn LLVMParseBitcodeInContext2(
            ContextRef: LLVMContextRef,
            MemBuf: LLVMMemoryBufferRef,
            OutModule: *mut LLVMModuleRef,
        ) -> LLVMBool;
    }
}

pub mod bit_writer {
    use super::prelude::*;
    unsafe extern "C" {
        pub fn LLVMWriteBitcodeToFile(
            M: LLVMModuleRef,
            Path: *const ::core::ffi::c_char,
        ) -> ::core::ffi::c_int;
    }
}

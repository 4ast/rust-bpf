// Thin wrappers around llvm-sys to satisfy field_reloc.rs's imports.
// The shapes match what `bpf-linker`'s `crate::llvm` module exposes, but
// only the slice actually used by `FieldRelocPass` is implemented here.

#![allow(non_snake_case)]

use std::marker::PhantomData;
use std::slice;

use llvm_sys::core::{
    LLVMGetFirstBasicBlock, LLVMGetFirstFunction, LLVMGetFirstInstruction, LLVMGetNextBasicBlock,
    LLVMGetNextFunction, LLVMGetNextInstruction, LLVMGetNumOperands, LLVMGetOperand,
    LLVMGetValueName2, LLVMMDStringInContext2, LLVMMetadataAsValue, LLVMReplaceMDNodeOperandWith,
    LLVMValueAsMetadata,
};
use llvm_sys::debuginfo::{
    LLVMDITypeGetName, LLVMGetDINodeTag, LLVMGetMetadataKind, LLVMMetadataKind,
};
use llvm_sys::prelude::{
    LLVMBasicBlockRef, LLVMContextRef, LLVMMetadataRef, LLVMModuleRef, LLVMValueRef,
};

// ── Context ──────────────────────────────────────────────────────────

/// Owning wrapper around an `LLVMContextRef`.
pub struct LLVMContext {
    context: LLVMContextRef,
}

impl LLVMContext {
    /// Borrow an externally-owned context. The caller keeps ownership;
    /// this wrapper does not dispose it on drop.
    pub fn from_raw(context: LLVMContextRef) -> Self {
        Self { context }
    }

    pub fn as_mut_ptr(&self) -> LLVMContextRef {
        self.context
    }
}

// ── Module ───────────────────────────────────────────────────────────

/// Borrowed view of an `LLVMModuleRef` tied to an `LLVMContext`.
pub struct LLVMModule<'ctx> {
    module: LLVMModuleRef,
    _phantom: PhantomData<&'ctx LLVMContext>,
}

impl<'ctx> LLVMModule<'ctx> {
    pub fn from_raw(module: LLVMModuleRef) -> Self {
        Self {
            module,
            _phantom: PhantomData,
        }
    }

    pub fn as_mut_ptr(&self) -> LLVMModuleRef {
        self.module
    }

    /// Iterate every function defined in the module.
    pub fn functions(&self) -> impl Iterator<Item = LLVMValueRef> {
        let mut cursor = unsafe { LLVMGetFirstFunction(self.module) };
        std::iter::from_fn(move || {
            if cursor.is_null() {
                return None;
            }
            let current = cursor;
            cursor = unsafe { LLVMGetNextFunction(current) };
            Some(current)
        })
    }
}

// ── Iteration traits ─────────────────────────────────────────────────

pub mod iter {
    use super::*;

    pub trait IterBasicBlocks {
        fn basic_blocks_iter(self) -> Box<dyn Iterator<Item = LLVMBasicBlockRef>>;
    }

    impl IterBasicBlocks for LLVMValueRef {
        fn basic_blocks_iter(self) -> Box<dyn Iterator<Item = LLVMBasicBlockRef>> {
            let mut cursor = unsafe { LLVMGetFirstBasicBlock(self) };
            Box::new(std::iter::from_fn(move || {
                if cursor.is_null() {
                    return None;
                }
                let current = cursor;
                cursor = unsafe { LLVMGetNextBasicBlock(current) };
                Some(current)
            }))
        }
    }

    pub trait IterInstructions {
        fn instructions_iter(self) -> Box<dyn Iterator<Item = LLVMValueRef>>;
    }

    impl IterInstructions for LLVMBasicBlockRef {
        fn instructions_iter(self) -> Box<dyn Iterator<Item = LLVMValueRef>> {
            let mut cursor = unsafe { LLVMGetFirstInstruction(self) };
            Box::new(std::iter::from_fn(move || {
                if cursor.is_null() {
                    return None;
                }
                let current = cursor;
                cursor = unsafe { LLVMGetNextInstruction(current) };
                Some(current)
            }))
        }
    }
}

// ── Symbol name ──────────────────────────────────────────────────────

/// Get the name of an LLVM value (function, global, etc.) as a byte
/// slice. Returns an empty slice if the value has no name.
///
/// The returned slice borrows from the LLVM value; do not retain it
/// across mutations that may free or rename the value.
pub fn symbol_name<'v>(value: LLVMValueRef) -> &'v [u8] {
    let mut len: usize = 0;
    let ptr = unsafe { LLVMGetValueName2(value, &mut len) };
    if ptr.is_null() || len == 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(ptr as *const u8, len) }
}

// ── Debug-info metadata ──────────────────────────────────────────────

pub mod types {
    pub mod ir {
        use super::super::*;

        /// Tagged view over the LLVM DI metadata kinds `FieldRelocPass`
        /// inspects. Anything else falls into `Other`.
        pub enum Metadata {
            DICompositeType(DICompositeType),
            DIDerivedType(DIDerivedType),
            DISubprogram(DISubprogram),
            Other(LLVMValueRef),
        }

        impl Metadata {
            /// Construct from the value form of a metadata node.
            ///
            /// # Safety
            /// `value` must be a `LLVMValueAsMetadata` result (or
            /// equivalent value-wrapping of a metadata node).
            pub unsafe fn from_value_ref(value: LLVMValueRef) -> Self {
                let metadata = unsafe { LLVMValueAsMetadata(value) };
                let kind = unsafe { LLVMGetMetadataKind(metadata) };
                match kind {
                    LLVMMetadataKind::LLVMDICompositeTypeMetadataKind => {
                        Metadata::DICompositeType(DICompositeType { value, metadata })
                    }
                    LLVMMetadataKind::LLVMDIDerivedTypeMetadataKind => {
                        Metadata::DIDerivedType(DIDerivedType { value, metadata })
                    }
                    LLVMMetadataKind::LLVMDISubprogramMetadataKind => {
                        Metadata::DISubprogram(DISubprogram { value, metadata })
                    }
                    _ => Metadata::Other(value),
                }
            }
        }

        /// Common DI type operations. Operand layout for `DIType` nodes
        /// in LLVM IR places the `name` MDString at operand 2 across DI
        /// type kinds we care about (composite, derived).
        fn di_type_name<'v>(value: LLVMValueRef) -> Option<&'v [u8]> {
            // LLVMDITypeGetName returns the name string and length.
            let mut len: usize = 0;
            let ptr = unsafe { LLVMDITypeGetName(LLVMValueAsMetadata(value), &mut len) };
            if ptr.is_null() || len == 0 {
                return None;
            }
            Some(unsafe { slice::from_raw_parts(ptr as *const u8, len) })
        }

        // ── DICompositeType ────────────────────────────────────────

        pub struct DICompositeType {
            value: LLVMValueRef,
            metadata: LLVMMetadataRef,
        }

        impl DICompositeType {
            pub fn name<'v>(&self) -> Option<&'v [u8]> {
                di_type_name(self.value)
            }

            pub fn value_ref(&self) -> LLVMValueRef {
                self.value
            }

            /// Iterate the composite's element MDNodes (struct members,
            /// enum entries, etc.) as `Metadata`.
            pub fn elements(&self) -> impl Iterator<Item = Metadata> {
                // Operand 6 on LLVM 21+ (was 4 on LLVM 20).
                let elements_tuple = unsafe { LLVMGetOperand(self.value, 6) };
                if elements_tuple.is_null() {
                    return ElementsIter {
                        tuple: std::ptr::null_mut(),
                        index: 0,
                        count: 0,
                    };
                }
                let count = (unsafe { LLVMGetNumOperands(elements_tuple) }) as u32;
                ElementsIter {
                    tuple: elements_tuple,
                    index: 0,
                    count,
                }
            }

            /// Replace the composite's name. Used by `FieldRelocPass` to
            /// strip the `__BtfCarrierFor` prefix off generated carriers
            /// so emitted local BTF carries the declared schema name.
            pub fn replace_name(&mut self, ctx: &LLVMContext, name: &[u8]) {
                let new_md = unsafe {
                    LLVMMDStringInContext2(
                        ctx.as_mut_ptr(),
                        name.as_ptr() as *const _,
                        name.len(),
                    )
                };
                // Operand 2 of a DI composite is its `name`.
                unsafe { LLVMReplaceMDNodeOperandWith(self.value, 2, new_md) };
            }
        }

        struct ElementsIter {
            tuple: LLVMValueRef,
            index: u32,
            count: u32,
        }

        impl Iterator for ElementsIter {
            type Item = Metadata;

            fn next(&mut self) -> Option<Self::Item> {
                if self.index >= self.count {
                    return None;
                }
                let operand = unsafe { LLVMGetOperand(self.tuple, self.index) };
                self.index += 1;
                if operand.is_null() {
                    return Some(Metadata::Other(operand));
                }
                Some(unsafe { Metadata::from_value_ref(operand) })
            }
        }

        // ── DIDerivedType ──────────────────────────────────────────

        pub struct DIDerivedType {
            value: LLVMValueRef,
            metadata: LLVMMetadataRef,
        }

        impl DIDerivedType {
            pub fn name<'v>(&self) -> Option<&'v [u8]> {
                di_type_name(self.value)
            }

            /// DWARF tag (e.g., `DW_TAG_member`, `DW_TAG_pointer_type`).
            pub fn tag(&self) -> gimli::DwTag {
                gimli::DwTag(unsafe { LLVMGetDINodeTag(self.metadata) })
            }

            /// The pointed-to / referenced / member-element type.
            pub fn base_type(&self) -> Metadata {
                // Operand 5 on LLVM 21+ (was 3 on LLVM 20).
                let base = unsafe { LLVMGetOperand(self.value, 5) };
                if base.is_null() {
                    return Metadata::Other(base);
                }
                unsafe { Metadata::from_value_ref(base) }
            }
        }

        // ── DISubprogram ───────────────────────────────────────────

        pub struct DISubprogram {
            value: LLVMValueRef,
            metadata: LLVMMetadataRef,
        }

        impl DISubprogram {
            /// Iterate the subprogram's parameter types as `Metadata`
            /// values. The return type slot (operand 0 of the types
            /// array) is skipped so the first yielded item is the
            /// carrier parameter.
            pub fn parameter_types(
                &self,
                ctx: LLVMContextRef,
            ) -> impl Iterator<Item = Option<Metadata>> {
                // DISubprogram operand 4 is the DISubroutineType. Operand
                // 5 of a DISubroutineType is the `types:` array — return
                // type at index 0, parameters from index 1.
                let ty_val = unsafe { LLVMGetOperand(self.value, 4) };
                let type_list = if ty_val.is_null() {
                    std::ptr::null_mut()
                } else {
                    let ty_md = unsafe { LLVMValueAsMetadata(ty_val) };
                    let subroutine_value = unsafe { LLVMMetadataAsValue(ctx, ty_md) };
                    if subroutine_value.is_null() {
                        std::ptr::null_mut()
                    } else {
                        unsafe { LLVMGetOperand(subroutine_value, 5) }
                    }
                };
                let count = if type_list.is_null() {
                    0
                } else {
                    (unsafe { LLVMGetNumOperands(type_list) }) as u32
                };
                ParamTypesIter {
                    type_list,
                    index: 1,
                    count,
                }
            }
        }

        struct ParamTypesIter {
            type_list: LLVMValueRef,
            index: u32,
            count: u32,
        }

        impl Iterator for ParamTypesIter {
            type Item = Option<Metadata>;

            fn next(&mut self) -> Option<Self::Item> {
                if self.index >= self.count {
                    return None;
                }
                let operand = unsafe { LLVMGetOperand(self.type_list, self.index) };
                self.index += 1;
                if operand.is_null() {
                    return Some(None);
                }
                Some(Some(unsafe { Metadata::from_value_ref(operand) }))
            }
        }
    }
}

use std::ffi::CStr;

use gimli::DW_TAG_pointer_type;
use llvm_sys::{
    LLVMOpcode,
    core::{
        LLVMAddCallSiteAttribute, LLVMBuildCall2, LLVMConstInt, LLVMCreateBuilderInContext,
        LLVMCreateTypeAttribute, LLVMDisposeBuilder, LLVMGetArgOperand, LLVMGetCalledValue,
        LLVMGetEnumAttributeKindForName, LLVMGetInstructionOpcode, LLVMGetIntrinsicDeclaration,
        LLVMGetMDKindIDInContext, LLVMGetNumArgOperands, LLVMGetOperand, LLVMGlobalGetValueType,
        LLVMInstructionEraseFromParent, LLVMInt8TypeInContext, LLVMInt32TypeInContext,
        LLVMInt64TypeInContext, LLVMLookupIntrinsicID, LLVMMetadataAsValue,
        LLVMPositionBuilderBefore, LLVMReplaceAllUsesWith, LLVMSetMetadata,
        LLVMStructTypeInContext, LLVMTypeOf, LLVMValueAsMetadata,
    },
    debuginfo::{
        LLVMDILocationGetScope, LLVMGetMetadataKind, LLVMInstructionGetDebugLoc, LLVMMetadataKind,
    },
    prelude::{LLVMBuilderRef, LLVMTypeRef, LLVMValueRef},
};
use thiserror::Error;

use crate::llvm::{
    LLVMContext, LLVMModule,
    iter::{IterBasicBlocks as _, IterInstructions as _},
    symbol_name,
    types::ir::Metadata,
};

// Rust does not provide BTF field-info intrinsics yet. `btf` calls these
// undefined polyfills with a carrier pointer and a root-relative path type.
// This pass reads that path from debug info, builds LLVM's preserve-access
// chain, and leaves one final `llvm.bpf.preserve.field.info` call for the BPF
// backend to turn into a `.BTF.ext` CO-RE relocation record.
const FIELD_BYTE_OFFSET_POLYFILL: &[u8] = b"__btf_field_byte_offset";
const FIELD_EXISTS_POLYFILL: &[u8] = b"__btf_field_exists";
const CARRIER_NAME_PREFIX: &[u8] = b"__BtfCarrierFor";
const ELEMENTTYPE: &CStr = c"elementtype";
const PRESERVE_ACCESS_MD_NAME: &CStr = c"llvm.preserve.access.index";
const PRESERVE_STRUCT_ACCESS_INTRINSIC_NAME: &CStr = c"llvm.preserve.struct.access.index";
const PRESERVE_FIELD_INFO_INTRINSIC_NAME: &CStr = c"llvm.bpf.preserve.field.info";

#[derive(Debug, Error)]
pub(crate) enum FieldRelocError {
    #[error("field-info polyfill `{0}` must take a carrier pointer and field path")]
    InvalidPolyfillArity(String),
    #[error("field-info polyfill `{0}` has an invalid field path: {1}")]
    InvalidPath(String, &'static str),
    #[error("field-info polyfill `{0}` names missing local field `{1}`")]
    MissingLocalField(String, String),
    #[error("field-info polyfill `{0}` is not based on debuggable carrier data: {1}")]
    UnresolvedPolyfillCall(String, &'static str),
}

pub(crate) struct FieldRelocPass<'ctx, 'module> {
    context: &'ctx LLVMContext,
    module: &'module mut LLVMModule<'ctx>,
    builder: LLVMBuilderRef,
    preserve_access_md_kind: u32,
    elementtype_attr_kind: u32,
}

impl<'ctx, 'module> FieldRelocPass<'ctx, 'module> {
    pub(crate) fn new(context: &'ctx LLVMContext, module: &'module mut LLVMModule<'ctx>) -> Self {
        Self {
            context,
            module,
            builder: unsafe { LLVMCreateBuilderInContext(context.as_mut_ptr()) },
            preserve_access_md_kind: unsafe {
                LLVMGetMDKindIDInContext(
                    context.as_mut_ptr(),
                    PRESERVE_ACCESS_MD_NAME.as_ptr(),
                    PRESERVE_ACCESS_MD_NAME.to_bytes().len().try_into().unwrap(),
                )
            },
            elementtype_attr_kind: unsafe {
                LLVMGetEnumAttributeKindForName(ELEMENTTYPE.as_ptr(), ELEMENTTYPE.to_bytes().len())
            },
        }
    }

    pub(crate) fn run(&mut self) -> Result<(), FieldRelocError> {
        let functions = self.module.functions().collect::<Vec<_>>();
        for function in functions {
            // Lowering erases polyfill call instructions, so find all of them
            // before changing any basic block.
            let mut polyfill_calls = Vec::new();
            for block in function.basic_blocks_iter() {
                for instruction in block.instructions_iter() {
                    if unsafe { LLVMGetInstructionOpcode(instruction) } != LLVMOpcode::LLVMCall {
                        continue;
                    }

                    let callee = unsafe { LLVMGetCalledValue(instruction) };
                    if !callee.is_null() && field_info_kind(symbol_name(callee)).is_some() {
                        polyfill_calls.push(instruction);
                    }
                }
            }

            for polyfill_call in polyfill_calls {
                self.lower_polyfill(polyfill_call)?;
            }
        }

        Ok(())
    }

    fn lower_polyfill(&mut self, call: LLVMValueRef) -> Result<(), FieldRelocError> {
        let callee = unsafe { LLVMGetCalledValue(call) };
        let polyfill = symbol_name(callee);
        let symbol = display(polyfill);
        let info_kind = field_info_kind(polyfill).unwrap();

        if unsafe { LLVMGetNumArgOperands(call) } != 2 {
            return Err(FieldRelocError::InvalidPolyfillArity(symbol));
        }

        let base = unsafe { LLVMGetArgOperand(call, 0) };

        // The call is generated inside an always-inlined polyfill helper whose
        // first parameter is the carrier pointer and whose second parameter is
        // a pointer to the path type. Opaque LLVM pointers erase both source
        // types at the call site; the helper's debug signature retains them.
        let mut scope = unsafe {
            let location = LLVMInstructionGetDebugLoc(call);
            (!location.is_null()).then(|| LLVMDILocationGetScope(location))
        }
        .filter(|scope| !scope.is_null());
        let subprogram = loop {
            let Some(current_scope) = scope else {
                return Err(FieldRelocError::UnresolvedPolyfillCall(
                    symbol,
                    "missing polyfill helper debug scope",
                ));
            };
            let value = unsafe { LLVMMetadataAsValue(self.context.as_mut_ptr(), current_scope) };
            match unsafe { LLVMGetMetadataKind(current_scope) } {
                LLVMMetadataKind::LLVMDISubprogramMetadataKind => {
                    let Metadata::DISubprogram(subprogram) =
                        (unsafe { Metadata::from_value_ref(value) })
                    else {
                        return Err(FieldRelocError::UnresolvedPolyfillCall(
                            symbol,
                            "polyfill helper scope is not subprogram metadata",
                        ));
                    };
                    break subprogram;
                }
                LLVMMetadataKind::LLVMDILexicalBlockMetadataKind
                | LLVMMetadataKind::LLVMDILexicalBlockFileMetadataKind => {
                    // A location in the generated helper body usually names
                    // its innermost lexical block. Operand one is that
                    // block's parent scope; walking those scopes reaches the
                    // polyfill helper's `DISubprogram`.
                    scope = unsafe {
                        let parent = LLVMGetOperand(value, 1);
                        (!parent.is_null()).then(|| LLVMValueAsMetadata(parent))
                    };
                }
                _ => {
                    return Err(FieldRelocError::UnresolvedPolyfillCall(
                        symbol,
                        "polyfill helper debug scope is not lexical",
                    ));
                }
            }
        };
        let mut parameter_types = subprogram.parameter_types(self.context.as_mut_ptr());
        let Some(base_metadata) = parameter_types.next().flatten() else {
            return Err(FieldRelocError::UnresolvedPolyfillCall(
                symbol,
                "polyfill helper has no carrier parameter type",
            ));
        };
        let Some(path_metadata) = parameter_types.next().flatten() else {
            return Err(FieldRelocError::UnresolvedPolyfillCall(
                symbol,
                "polyfill helper has no path parameter type",
            ));
        };
        // Rust records both `*const Foo` and `&Foo` as derived pointer types
        // in DI. The preserve-access metadata wants the `Foo` composite
        // underneath.
        let Metadata::DIDerivedType(pointer_type) = base_metadata else {
            return Err(FieldRelocError::UnresolvedPolyfillCall(
                symbol,
                "carrier base type is not derived",
            ));
        };
        if pointer_type.tag() != DW_TAG_pointer_type {
            return Err(FieldRelocError::UnresolvedPolyfillCall(
                symbol,
                "carrier base type is not a pointer",
            ));
        }
        let Metadata::DICompositeType(mut composite_type) = pointer_type.base_type() else {
            return Err(FieldRelocError::UnresolvedPolyfillCall(
                symbol,
                "carrier base does not point to a composite",
            ));
        };

        let Metadata::DIDerivedType(path_pointer_type) = path_metadata else {
            return Err(FieldRelocError::InvalidPath(
                symbol,
                "path parameter type is not derived",
            ));
        };
        if path_pointer_type.tag() != DW_TAG_pointer_type {
            return Err(FieldRelocError::InvalidPath(
                symbol,
                "path parameter type is not a pointer",
            ));
        }

        // `btf::FieldPath<Parent, Marker>` has real `parent` and `field`
        // fields solely so Rust writes the nested field path to DI. Each
        // generated marker's only member is named after the BTF field.
        let mut field_names = Vec::new();
        let mut path_type = path_pointer_type.base_type();
        loop {
            let path_composite = loop {
                match path_type {
                    Metadata::DICompositeType(composite) => break composite,
                    Metadata::DIDerivedType(derived) => path_type = derived.base_type(),
                    _ => {
                        return Err(FieldRelocError::InvalidPath(
                            symbol,
                            "path node is not a composite",
                        ));
                    }
                }
            };

            let mut parent_type = None;
            let mut field_marker_type = None;
            for member in path_composite.elements() {
                let Metadata::DIDerivedType(member) = member else {
                    continue;
                };
                match member.name() {
                    Some(b"parent") => parent_type = Some(member.base_type()),
                    Some(b"field") => field_marker_type = Some(member.base_type()),
                    _ => {}
                }
            }
            let (Some(parent_type), Some(mut field_marker_type)) = (parent_type, field_marker_type)
            else {
                break;
            };

            let field_marker = loop {
                match field_marker_type {
                    Metadata::DICompositeType(composite) => break composite,
                    Metadata::DIDerivedType(derived) => field_marker_type = derived.base_type(),
                    _ => {
                        return Err(FieldRelocError::InvalidPath(
                            symbol,
                            "field marker is not a composite",
                        ));
                    }
                }
            };
            let field_name = field_marker.elements().find_map(|member| {
                let Metadata::DIDerivedType(member) = member else {
                    return None;
                };
                member.name()
            });
            let Some(field_name) = field_name else {
                return Err(FieldRelocError::InvalidPath(
                    symbol,
                    "field marker has no named member",
                ));
            };
            field_names.push(field_name);
            path_type = parent_type;
        }
        if field_names.is_empty() {
            return Err(FieldRelocError::InvalidPath(symbol, "field path is empty"));
        }
        field_names.reverse();

        let mut field_ptr = base;
        let field_count = field_names.len();
        for (step, field_name) in field_names.into_iter().enumerate() {
            let mut field_index = None;
            let mut field_type = None;
            for (index, member) in composite_type.elements().enumerate() {
                let Metadata::DIDerivedType(member) = member else {
                    continue;
                };
                if member.name() == Some(field_name) {
                    field_index = Some(index.try_into().unwrap());
                    field_type = Some(member.base_type());
                    break;
                }
            }
            let Some(field_index) = field_index else {
                return Err(FieldRelocError::MissingLocalField(
                    symbol,
                    display(field_name),
                ));
            };

            // Carrier Rust identifiers are local scaffolding. Restore the
            // declared BTF type name before LLVM emits each local BTF node in
            // a preserve-access path.
            let btf_name = composite_type
                .name()
                .and_then(|name| name.strip_prefix(CARRIER_NAME_PREFIX))
                .map(<[u8]>::to_vec);
            if let Some(btf_name) = btf_name {
                composite_type.replace_name(self.context, &btf_name);
            }
            field_ptr = self.build_preserve_access(
                call,
                field_ptr,
                composite_type.value_ref(),
                field_index,
            );

            if step + 1 == field_count {
                continue;
            }
            let Some(mut field_type) = field_type else {
                unreachable!("found field has a field type");
            };
            composite_type = loop {
                match field_type {
                    Metadata::DICompositeType(composite) => break composite,
                    Metadata::DIDerivedType(derived) => field_type = derived.base_type(),
                    _ => {
                        return Err(FieldRelocError::InvalidPath(
                            symbol,
                            "non-terminal path field is not a composite",
                        ));
                    }
                }
            };
        }

        // The final field-info intrinsic asks about the whole preserved path,
        // for example whether it exists or its target-kernel byte offset.
        let field_info = self.build_field_info(call, field_ptr, info_kind);

        unsafe {
            LLVMReplaceAllUsesWith(call, field_info);
            LLVMInstructionEraseFromParent(call);
        }

        Ok(())
    }

    fn build_preserve_access(
        &self,
        before: LLVMValueRef,
        base: LLVMValueRef,
        composite_type: LLVMValueRef,
        member_index: u32,
    ) -> LLVMValueRef {
        let field_index = unsafe {
            LLVMConstInt(
                LLVMInt32TypeInContext(self.context.as_mut_ptr()),
                member_index.into(),
                0,
            )
        };

        let callee = self.preserve_struct_access_function(base);
        let mut args = [base, field_index, field_index];
        let call = self.build_call(before, callee, &mut args);
        // The preserve intrinsic needs LLVM element type shape for the field
        // index and DI metadata for the BTF type. The element type below is
        // only scaffolding; `composite_type` carries the real local type and
        // member names into the CO-RE relocation.
        let attr = unsafe {
            LLVMCreateTypeAttribute(
                self.context.as_mut_ptr(),
                self.elementtype_attr_kind,
                self.synthetic_struct_type(member_index),
            )
        };
        unsafe { LLVMAddCallSiteAttribute(call, 1, attr) };

        unsafe { LLVMSetMetadata(call, self.preserve_access_md_kind, composite_type) };
        call
    }

    fn synthetic_struct_type(&self, member_index: u32) -> LLVMTypeRef {
        // Rust has erased the original LLVM struct type by this point. The BPF
        // backend only needs an aggregate with a slot at `member_index`; the
        // `llvm.preserve.access.index` metadata attached above provides the
        // actual local BTF type.
        let element_type = unsafe { LLVMInt8TypeInContext(self.context.as_mut_ptr()) };
        let mut element_types = vec![element_type; member_index as usize + 1];
        unsafe {
            LLVMStructTypeInContext(
                self.context.as_mut_ptr(),
                element_types.as_mut_ptr(),
                element_types.len().try_into().unwrap(),
                0,
            )
        }
    }

    fn build_field_info(
        &self,
        before: LLVMValueRef,
        field_ptr: LLVMValueRef,
        info_kind: u64,
    ) -> LLVMValueRef {
        let ptr_ty = unsafe { LLVMTypeOf(field_ptr) };
        let mut overloaded_tys = [ptr_ty];
        let callee = self.intrinsic(PRESERVE_FIELD_INFO_INTRINSIC_NAME, &mut overloaded_tys);
        let info_kind = unsafe {
            LLVMConstInt(
                LLVMInt64TypeInContext(self.context.as_mut_ptr()),
                info_kind,
                0,
            )
        };
        let mut args = [field_ptr, info_kind];
        self.build_call(before, callee, &mut args)
    }

    fn preserve_struct_access_function(&self, base: LLVMValueRef) -> LLVMValueRef {
        let ptr_ty = unsafe { LLVMTypeOf(base) };
        let mut overloaded_tys = [ptr_ty, ptr_ty];
        self.intrinsic(PRESERVE_STRUCT_ACCESS_INTRINSIC_NAME, &mut overloaded_tys)
    }

    fn intrinsic(&self, name: &CStr, overloaded_tys: &mut [LLVMTypeRef]) -> LLVMValueRef {
        let intrinsic_id = unsafe { LLVMLookupIntrinsicID(name.as_ptr(), name.to_bytes().len()) };
        unsafe {
            LLVMGetIntrinsicDeclaration(
                self.module.as_mut_ptr(),
                intrinsic_id,
                overloaded_tys.as_mut_ptr(),
                overloaded_tys.len(),
            )
        }
    }

    fn build_call(
        &self,
        before: LLVMValueRef,
        callee: LLVMValueRef,
        args: &mut [LLVMValueRef],
    ) -> LLVMValueRef {
        unsafe {
            LLVMPositionBuilderBefore(self.builder, before);
            LLVMBuildCall2(
                self.builder,
                LLVMGlobalGetValueType(callee),
                callee,
                args.as_mut_ptr(),
                args.len().try_into().unwrap(),
                c"".as_ptr(),
            )
        }
    }
}

impl Drop for FieldRelocPass<'_, '_> {
    fn drop(&mut self) {
        unsafe { LLVMDisposeBuilder(self.builder) };
    }
}

fn field_info_kind(polyfill: &[u8]) -> Option<u64> {
    match polyfill {
        FIELD_BYTE_OFFSET_POLYFILL => Some(0),
        FIELD_EXISTS_POLYFILL => Some(2),
        _ => None,
    }
}

fn display(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

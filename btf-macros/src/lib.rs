use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::{format_ident, quote};
use syn::{
    Fields, GenericParam, ItemStruct, Path, Token, Visibility, braced,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
};

struct BtfArgs {
    flavor: Option<Ident>,
}

impl Parse for BtfArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(Self { flavor: None });
        }

        let option = input.parse::<Ident>()?;
        if option != "flavor" {
            return Err(syn::Error::new_spanned(
                option,
                "`#[btf]` only accepts `flavor = name`",
            ));
        }
        let _equals = input.parse::<Token![=]>()?;
        let flavor = input.parse()?;
        if input.peek(Token![,]) {
            let _comma = input.parse::<Token![,]>()?;
        }
        if !input.is_empty() {
            return Err(input.error("unexpected `#[btf]` option"));
        }

        Ok(Self {
            flavor: Some(flavor),
        })
    }
}

#[proc_macro_attribute]
pub fn btf(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as BtfArgs);
    let item = parse_macro_input!(item as ItemStruct);
    expand_btf(item, args.flavor)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

struct FieldProbe {
    root: Path,
    fields: Vec<Ident>,
}

impl Parse for FieldProbe {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let root = input.call(Path::parse_mod_style)?;
        let mut fields = Vec::new();
        while input.peek(Token![.]) {
            let _dot = input.parse::<Token![.]>()?;
            fields.push(input.parse()?);
        }
        if fields.is_empty() {
            return Err(syn::Error::new_spanned(
                root,
                "a profile discriminator must name a field path",
            ));
        }

        Ok(Self { root, fields })
    }
}

struct ProfileDecl {
    vis: Visibility,
    name: Ident,
    probes: Vec<FieldProbe>,
}

impl Parse for ProfileDecl {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let vis = input.parse()?;
        let _struct_token = input.parse::<Token![struct]>()?;
        let name = input.parse()?;
        let content;
        braced!(content in input);

        let detect_keyword = content.parse::<Ident>()?;
        if detect_keyword != "detect" {
            return Err(syn::Error::new_spanned(
                detect_keyword,
                "expected `detect { ... }`",
            ));
        }
        let detect_content;
        braced!(detect_content in content);
        let probes = Punctuated::<FieldProbe, Token![,]>::parse_terminated(&detect_content)?
            .into_iter()
            .collect::<Vec<_>>();
        if probes.is_empty() {
            return Err(detect_content.error("a profile must have at least one discriminator"));
        }
        if !content.is_empty() {
            return Err(content.error("unexpected profile declaration content"));
        }

        Ok(Self { vis, name, probes })
    }
}

/// Selects the enclosing versioned bindings module after detection succeeds.
///
/// Invoke this macro inside a module whose generated bindings use
/// `#[btf(flavor = ...)]`. The `detect` paths are target-BTF presence checks;
/// when they all hold, every flavored schema in the same module may use
/// non-optional terminal operations.
#[proc_macro]
pub fn btf_profile(input: TokenStream) -> TokenStream {
    expand_profile(parse_macro_input!(input as ProfileDecl)).into()
}

fn expand_profile(ProfileDecl { vis, name, probes }: ProfileDecl) -> proc_macro2::TokenStream {
    let probe_expressions = probes.iter().map(|probe| {
        let root = &probe.root;
        let mut expression = quote!(<#root>::__btf_probe());
        for field in &probe.fields {
            expression = quote!(#expression.#field());
        }
        quote!(#expression.exists())
    });

    quote! {
        // This declaration is intended to sit in the wrapper module around
        // an included generated `vmlinux.rs`. All flavored `#[btf]` schemas
        // emitted into that lexical module implement `InModule` for this
        // marker, so the witness selects the bindings module as a unit.
        #[doc(hidden)]
        pub struct __BtfModule;

        #[derive(Clone, Copy)]
        #vis struct #name {
            _private: ::btf::ProfileToken,
        }

        impl ::btf::Profile for #name {
            type Module = __BtfModule;
        }

        impl #name {
            #[inline(always)]
            #vis fn detect() -> ::core::option::Option<Self> {
                if true #(&& #probe_expressions)* {
                    ::core::option::Option::Some(Self {
                        _private: unsafe { ::btf::__btf_profile_token() },
                    })
                } else {
                    ::core::option::Option::None
                }
            }
        }
    }
}

fn expand_btf(item: ItemStruct, flavor: Option<Ident>) -> syn::Result<proc_macro2::TokenStream> {
    if let Some(generic) = item.generics.params.first() {
        let generic = match generic {
            GenericParam::Lifetime(param) => &param.lifetime.ident,
            GenericParam::Type(param) => &param.ident,
            GenericParam::Const(param) => &param.ident,
        };
        return Err(syn::Error::new_spanned(
            generic,
            "`#[btf]` does not support generic structs yet",
        ));
    }

    let struct_name = &item.ident;
    let Fields::Named(fields) = &item.fields else {
        return Err(syn::Error::new_spanned(
            &item.ident,
            "`#[btf]` only supports structs with named fields",
        ));
    };

    // The source declaration is the minimal local BTF struct the program
    // wants to describe. The public Rust type below is only an address view:
    // its terminal field views use CO-RE byte offsets, so it should not claim
    // that Rust's own field layout matches the running kernel.
    // A flavored carrier becomes (for example) `task_struct___modern` in
    // local BTF. Existing CO-RE loaders match that against `task_struct` while
    // keeping multiple incompatible local schemas distinct in one object.
    let (carrier_name, module_impl) = match flavor {
        Some(flavor) => (
            format_ident!("__BtfCarrierFor{}___{}", struct_name, flavor),
            quote! {
                // The generator places this schema next to the module's
                // `btf_profile!` declaration, whose hidden marker brands all
                // generated schemas without a hand-maintained type list.
                unsafe impl ::btf::InModule<__BtfModule> for #struct_name {}
            },
        ),
        None => (format_ident!("__BtfCarrierFor{}", struct_name), quote! {}),
    };
    let attrs = &item.attrs;
    let vis = &item.vis;
    let view_name = format_ident!("__BtfViewFor{}", struct_name);
    let mut carrier_fields = Vec::new();
    let mut field_markers = Vec::new();
    let mut root_accessors = Vec::new();
    let mut view_accessors = Vec::new();
    for (field_index, field) in fields.named.iter().enumerate() {
        let field_name = field.ident.as_ref().expect("named fields have identifiers");
        let field_ty = &field.ty;
        let field_attrs = &field.attrs;
        let field_vis = &field.vis;
        let field_marker = format_ident!(
            "__BtfFieldFor{}_{}",
            struct_name,
            field_index,
            span = field_name.span()
        );

        // The public type can be a ZST because local BTF shape lives in the
        // carrier. Replacing each declared field with its carrier type keeps
        // that hidden graph intact for embedded `#[btf]` structs.
        carrier_fields.push(quote! {
            #(#field_attrs)*
            #field_vis #field_name: <#field_ty as ::btf::BtfType>::Carrier
        });

        // bpf-linker reads this single member name from path type DI. That
        // keeps the macro/linker boundary name based even though LLVM's final
        // CO-RE access string is made of local BTF field indices.
        field_markers.push(quote! {
            #[doc(hidden)]
            #[allow(non_camel_case_types)]
            #[repr(C)]
            pub struct #field_marker {
                #field_name: u8
            }
        });

        root_accessors.push(quote! {
            #[inline(always)]
            pub fn #field_name<'__btf>(
                &'__btf self,
            ) -> <#field_ty as ::btf::BtfType>::View<
                '__btf,
                Self,
                ::btf::FieldPath<::btf::RootPath, #field_marker>,
                ::btf::Optional,
            > {
                let root = ::btf::Field::__btf_root(self);
                let field = root.__btf_field::<#field_ty, #field_marker>();
                <#field_ty as ::btf::BtfType>::__btf_view(field)
            }
        });

        view_accessors.push(quote! {
            #[inline(always)]
            pub fn #field_name(
                &self,
            ) -> <#field_ty as ::btf::BtfType>::View<
                '__btf,
                __BtfRoot,
                ::btf::FieldPath<__BtfPath, #field_marker>,
                __BtfMode,
            > {
                let field = self.field.__btf_field::<#field_ty, #field_marker>();
                <#field_ty as ::btf::BtfType>::__btf_view(field)
            }
        });
    }

    Ok(quote! {
        #(#attrs)*
        #[allow(non_camel_case_types)]
        #vis struct #struct_name;

        // This carrier is hidden Rust scaffolding. bpf-linker renames its
        // debug type to `#struct_name` before LLVM emits the local BTF type
        // used by the field relocations.
        #[doc(hidden)]
        #[allow(non_camel_case_types)]
        #[repr(C)]
        pub struct #carrier_name {
            #(#carrier_fields,)*
        }

        #(#field_markers)*

        #[doc(hidden)]
        #[allow(non_camel_case_types)]
        pub struct #view_name<'__btf, __BtfRoot, __BtfPath, __BtfMode>
        where
            __BtfRoot: ::btf::BtfType,
        {
            field: ::btf::Field<
                '__btf,
                __BtfRoot,
                #struct_name,
                __BtfPath,
                __BtfMode,
            >,
        }

        impl ::btf::BtfType for #struct_name {
            type Carrier = #carrier_name;

            type View<'__btf, __BtfRoot, __BtfPath, __BtfMode>
                = #view_name<'__btf, __BtfRoot, __BtfPath, __BtfMode>
            where
                Self: '__btf,
                __BtfRoot: ::btf::BtfType + '__btf;

            #[inline(always)]
            fn __btf_view<'__btf, __BtfRoot, __BtfPath, __BtfMode>(
                field: ::btf::Field<
                    '__btf,
                    __BtfRoot,
                    Self,
                    __BtfPath,
                    __BtfMode,
                >,
            ) -> Self::View<'__btf, __BtfRoot, __BtfPath, __BtfMode>
            where
                Self: '__btf,
                __BtfRoot: ::btf::BtfType + '__btf,
            {
                #view_name { field }
            }
        }

        #module_impl

        impl<'__btf, __BtfRoot, __BtfPath, __BtfMode>
            #view_name<'__btf, __BtfRoot, __BtfPath, __BtfMode>
        where
            __BtfRoot: ::btf::BtfType + '__btf,
        {
            // Aggregate views can be extended or queried for presence. They
            // are ZST schemas, not target-kernel values to return by address.
            #[inline(always)]
            pub fn exists(&self) -> bool {
                self.field.exists()
            }

            #(#view_accessors)*
        }

        impl #struct_name {
            #(#root_accessors)*

            /// Starts a query-only root used by `btf_profile!` discriminators.
            #[doc(hidden)]
            #[inline(always)]
            pub fn __btf_probe() -> #view_name<
                'static,
                Self,
                ::btf::RootPath,
                ::btf::Probe,
            > {
                let root = ::btf::Field::<
                    Self,
                    Self,
                    ::btf::RootPath,
                    ::btf::Probe,
                >::__btf_probe();
                <Self as ::btf::BtfType>::__btf_view(root)
            }
        }
    })
}


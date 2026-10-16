//! `#[btf_tag]`: BTF_KIND_DECL_TAG / BTF_KIND_TYPE_TAG from Rust source.
//!
//! Neither tag is expressible in rustc: both are debug-info features
//! (`annotations:` on a DI node) that clang emits from
//! `__attribute__((btf_decl_tag(...)))` / `__attribute__((btf_type_tag(...)))`
//! and that rustc has no syntax for.
//!
//! This macro therefore does not try to produce the annotations itself. It
//! records what was asked for in a *manifest*: one NUL-terminated directive
//! string per tag, emitted as a `#[used]` static in the `.btf_tags` section.
//! `btf_tags.py` reads those directives out of the final LLVM IR, attaches the
//! matching `annotations:` metadata, and deletes the manifest globals again so
//! nothing of them reaches BTF.
//!
//! Directive grammar (`|`-separated, so tag text may not contain `|`):
//!
//! ```text
//!   m|<struct>|<field>|t|<tag>    btf_type_tag on a member's pointer type
//!   m|<struct>|<field>|d|<tag>    btf_decl_tag on a struct member
//!   s|<struct>||d|<tag>           btf_decl_tag on the struct itself
//!   g|<static>||d|<tag>           btf_decl_tag on a global variable
//!   f|<func>||d|<tag>             btf_decl_tag on a function
//!   a|<func>|<arg index>|d|<tag>  btf_decl_tag on a function parameter
//! ```
//!
//! The names are the ones BTF sees, which are the *debug info* names: a Rust
//! item's plain identifier, not its mangled symbol.

use std::sync::atomic::{AtomicUsize, Ordering};

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    Attribute, Fields, ForeignItem, Ident, Item, ItemFn, ItemForeignMod, ItemStatic, ItemStruct,
    LitByteStr, LitStr, Pat, Token,
    parse::{Parse, ParseStream},
};

/// Distinguishes the two tag kinds a `#[btf_tag(...)]` list can request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `btf_decl_tag`: attaches to the *declaration* (member, var, func, arg).
    Decl,
    /// `btf_type_tag`: attaches to the pointer *type* the declaration uses.
    Type,
}

impl Kind {
    fn directive(self) -> &'static str {
        match self {
            Kind::Decl => "d",
            Kind::Type => "t",
        }
    }
}

/// One parsed `#[btf_tag(...)]` list.
///
/// Repeats are meaningful and order matters: `btf_type_tag` chains in source
/// order, exactly like `int __tag1 __tag2 *p` in C.
struct TagList {
    tags: Vec<(Kind, String)>,
}

impl Parse for TagList {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut tags = Vec::new();
        if input.is_empty() {
            return Ok(Self { tags });
        }

        loop {
            let key = input.parse::<Ident>()?;
            let kind = if key == "decl_tag" {
                Kind::Decl
            } else if key == "type_tag" {
                Kind::Type
            } else {
                return Err(syn::Error::new_spanned(
                    key,
                    "`#[btf_tag]` accepts `decl_tag = \"...\"` and `type_tag = \"...\"`",
                ));
            };
            let _equals = input.parse::<Token![=]>()?;
            let value = input.parse::<LitStr>()?;
            let tag = value.value();
            if tag.is_empty() || tag.contains('|') {
                return Err(syn::Error::new_spanned(
                    value,
                    "a BTF tag must be non-empty and must not contain `|`",
                ));
            }
            tags.push((kind, tag));

            if input.is_empty() {
                break;
            }
            let _comma = input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
        }

        Ok(Self { tags })
    }
}

/// Splits `#[btf_tag(...)]` off an attribute list, leaving the rest in place.
///
/// Field, parameter and foreign-item tags ride on inner `#[btf_tag(...)]`
/// attributes. They have to be removed before the item is emitted again,
/// because there is no `#[btf_tag]` attribute macro in those positions.
fn take_tags(attrs: &mut Vec<Attribute>) -> syn::Result<Vec<(Kind, String)>> {
    let mut tags = Vec::new();
    let mut error = None;
    attrs.retain(|attr| {
        if !attr.path().is_ident("btf_tag") {
            return true;
        }
        match attr.parse_args::<TagList>() {
            Ok(list) => tags.extend(list.tags),
            Err(e) => error = Some(e),
        }
        false
    });
    match error {
        Some(e) => Err(e),
        None => Ok(tags),
    }
}

/// Emits the `.btf_tags` manifest statics for a set of directives.
fn manifest(directives: Vec<String>) -> TokenStream {
    // One counter per proc-macro process is enough: a crate is expanded by a
    // single load of this dylib, and the names only have to be unique within
    // the crate being compiled.
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    let statics = directives.into_iter().map(|directive| {
        let mut bytes = directive.into_bytes();
        bytes.push(0);
        let len = bytes.len();
        let literal = LitByteStr::new(&bytes, Span::call_site());
        let name = Ident::new(
            &format!("__BTF_TAG_{}", NEXT.fetch_add(1, Ordering::Relaxed)),
            Span::call_site(),
        );

        // `#[used]` is what keeps these alive through `internalize` and
        // `globaldce`; the section is what `btf_tags.py` recognises them by.
        quote! {
            #[allow(non_upper_case_globals, dead_code)]
            #[used]
            #[link_section = ".btf_tags"]
            static #name: [u8; #len] = *#literal;
        }
    });

    quote!(#(#statics)*)
}

pub(crate) fn expand(attr: TokenStream, item: Item) -> syn::Result<TokenStream> {
    let outer = syn::parse2::<TagList>(attr)?.tags;

    match item {
        Item::Struct(item) => expand_struct(item, outer),
        Item::Static(item) => expand_static(item, outer),
        Item::Fn(item) => expand_fn(item, outer),
        Item::ForeignMod(item) => expand_foreign_mod(item, outer),
        other => Err(syn::Error::new_spanned(
            other,
            "`#[btf_tag]` applies to a struct, static, function, or `extern` block",
        )),
    }
}

fn expand_struct(mut item: ItemStruct, outer: Vec<(Kind, String)>) -> syn::Result<TokenStream> {
    let struct_name = item.ident.to_string();
    let mut directives = Vec::new();

    for (kind, tag) in outer {
        if kind == Kind::Type {
            return Err(syn::Error::new_spanned(
                &item.ident,
                "`type_tag` describes a pointer type; put it on a field, not on the struct",
            ));
        }
        directives.push(format!("s|{struct_name}||d|{tag}"));
    }

    let Fields::Named(fields) = &mut item.fields else {
        return Err(syn::Error::new_spanned(
            &item.ident,
            "`#[btf_tag]` only supports structs with named fields",
        ));
    };

    for field in &mut fields.named {
        let tags = take_tags(&mut field.attrs)?;
        if tags.is_empty() {
            continue;
        }
        let field_name = field
            .ident
            .as_ref()
            .expect("named fields have identifiers")
            .to_string();
        for (kind, tag) in tags {
            let kind = kind.directive();
            directives.push(format!("m|{struct_name}|{field_name}|{kind}|{tag}"));
        }
    }

    let manifest = manifest(directives);
    Ok(quote! {
        #item
        #manifest
    })
}

fn expand_static(item: ItemStatic, outer: Vec<(Kind, String)>) -> syn::Result<TokenStream> {
    let name = item.ident.to_string();
    let mut directives = Vec::new();
    for (kind, tag) in outer {
        if kind == Kind::Type {
            return Err(syn::Error::new_spanned(
                &item.ident,
                "`type_tag` on a global variable is not supported yet",
            ));
        }
        directives.push(format!("g|{name}||d|{tag}"));
    }

    let manifest = manifest(directives);
    Ok(quote! {
        #item
        #manifest
    })
}

fn expand_fn(mut item: ItemFn, outer: Vec<(Kind, String)>) -> syn::Result<TokenStream> {
    let name = item.sig.ident.to_string();
    let mut directives = Vec::new();

    for (kind, tag) in outer {
        if kind == Kind::Type {
            return Err(syn::Error::new_spanned(
                &item.sig.ident,
                "`type_tag` on a function is not supported yet",
            ));
        }
        directives.push(format!("f|{name}||d|{tag}"));
    }

    // BTFDebug takes the parameter position from the DILocalVariable's `arg`
    // field and stores `arg - 1` as the DECL_TAG component_idx, so the index
    // recorded here is the ordinary zero-based parameter index.
    for (index, argument) in item.sig.inputs.iter_mut().enumerate() {
        let attrs = match argument {
            syn::FnArg::Typed(typed) => &mut typed.attrs,
            syn::FnArg::Receiver(receiver) => &mut receiver.attrs,
        };
        let tags = take_tags(attrs)?;
        for (kind, tag) in tags {
            if kind == Kind::Type {
                return Err(syn::Error::new_spanned(
                    &item.sig.ident,
                    "`type_tag` on a parameter is not supported yet",
                ));
            }
            directives.push(format!("a|{name}|{index}|d|{tag}"));
        }
    }

    // A parameter tag is only reachable if the parameter still has a
    // DILocalVariable at codegen time, which means the function has to survive
    // as a real function.
    if directives.iter().any(|d| d.starts_with("a|")) {
        for argument in &item.sig.inputs {
            if let syn::FnArg::Typed(typed) = argument {
                if matches!(&*typed.pat, Pat::Wild(_)) {
                    return Err(syn::Error::new_spanned(
                        &typed.pat,
                        "a tagged parameter needs a name; `_` produces no debug info",
                    ));
                }
            }
        }
    }

    let manifest = manifest(directives);
    Ok(quote! {
        #item
        #manifest
    })
}

fn expand_foreign_mod(
    mut item: ItemForeignMod,
    outer: Vec<(Kind, String)>,
) -> syn::Result<TokenStream> {
    if let Some((_, tag)) = outer.first() {
        return Err(syn::Error::new_spanned(
            LitStr::new(tag, Span::call_site()),
            "tag the individual declarations inside the `extern` block, not the block",
        ));
    }

    let mut directives = Vec::new();
    for foreign in &mut item.items {
        let ForeignItem::Fn(foreign) = foreign else {
            continue;
        };
        let tags = take_tags(&mut foreign.attrs)?;
        if tags.is_empty() {
            continue;
        }
        // An extern declaration keeps its source name, and `add_ksyms.py`
        // names the synthesised `.ksyms` DISubprogram after that symbol.
        let name = foreign.sig.ident.to_string();
        for (kind, tag) in tags {
            if kind == Kind::Type {
                return Err(syn::Error::new_spanned(
                    &foreign.sig.ident,
                    "`type_tag` on a kfunc declaration is not supported yet",
                ));
            }
            directives.push(format!("f|{name}||d|{tag}"));
        }
    }

    let manifest = manifest(directives);
    Ok(quote! {
        #item
        #manifest
    })
}

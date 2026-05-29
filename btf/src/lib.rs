#![no_std]

//! Runtime-facing building blocks for `#[btf]`-generated field views.
//!
//! This crate does not carry BTF field paths as runtime data. Generated
//! accessors accumulate a path in Rust types, and terminal queries make the
//! typed marker call which `bpf-linker` rewrites into LLVM CO-RE intrinsics.

use core::marker::PhantomData;

/// A type which can appear in a local BTF type graph.
///
/// `#[btf]` implementations use hidden carrier structs so their public types
/// can stay layout-free views of kernel memory. Primitive implementations use
/// their ordinary Rust layout as their BTF carrier.
pub trait BtfType: Sized {
    /// The type whose debug information describes this value to BTF.
    ///
    /// For a macro-generated aggregate, `Self` is an address-view ZST and
    /// `Carrier` is the hidden struct containing the declared kernel fields.
    /// Carrier values are never used to read kernel memory.
    #[doc(hidden)]
    type Carrier;

    /// The deferred field view used when a path currently names this type.
    ///
    /// Leaf values use `Field` itself because there is no further named field
    /// to append. A macro-generated aggregate substitutes a generated view
    /// type with methods for extending the same pending path.
    #[doc(hidden)]
    type View<'a, Root, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a;

    /// Converts an untyped pending field into this type's chosen view.
    ///
    /// Generated accessors use this after appending a field marker so nested
    /// aggregate fields remain chainable while scalar fields become terminal.
    #[doc(hidden)]
    fn __btf_view<'a, Root, Path, Mode>(
        field: Field<'a, Root, Self, Path, Mode>,
    ) -> Self::View<'a, Root, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a;
}

/// A field path whose terminal operation checks for target-kernel presence.
///
/// This is the default mode for ordinary `#[btf]` views: the local schema can
/// be partial and no higher-level kernel profile has promised that the field
/// exists.
#[derive(Clone, Copy)]
pub struct Optional;

/// A field path that can be queried for existence but cannot form an address.
///
/// Generated profile detectors start from a null base pointer because CO-RE
/// existence queries inspect target BTF rather than memory. Giving that root
/// its own mode prevents the detector from accidentally materializing a
/// reference from the null pointer.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct Probe;

/// A field path whose presence is justified by a selected bindings module.
///
/// `P` is carried only at the type level. A view in this mode emits the normal
/// byte-offset relocation without an additional `field_exists` relocation.
pub struct Required<P>(PhantomData<P>);

/// The unforgeable payload stored in a generated profile witness.
///
/// `btf_profile!` can construct this value after emitting its discriminator
/// checks. User code can only manufacture a false witness by entering an
/// unsafe block, which is the operation that would violate required-view
/// assumptions.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ProfileToken {
    _private: (),
}

/// Constructs the payload for a generated profile witness.
///
/// # Safety
///
/// The caller must be generated detection code whose preceding BPF control
/// flow establishes that the profile's bindings module was selected.
#[doc(hidden)]
#[inline(always)]
pub unsafe fn __btf_profile_token() -> ProfileToken {
    ProfileToken { _private: () }
}

/// A detected kernel profile capable of selecting one bindings module.
///
/// The `btf_profile!` macro implements this trait for its generated witness
/// type. `view()` does not perform a new query: it brands `root` with the
/// module selected by that witness's `detect()` guard.
pub trait Profile: Sized {
    /// The hidden identity of the versioned bindings module selected by this
    /// profile.
    #[doc(hidden)]
    type Module;

    #[inline(always)]
    fn view<'a, Root>(&self, root: &'a Root) -> Root::View<'a, Root, RootPath, Required<Self>>
    where
        Root: BtfType + 'a,
        Root: InModule<Self::Module>,
    {
        Root::__btf_view(Field::<Root, Root, RootPath, Required<Self>>::__btf_root(
            root,
        ))
    }
}

/// Marks a schema as belonging to one versioned bindings module.
///
/// # Safety
///
/// Every schema implementing this trait for the same `Module` must describe
/// the same target-kernel layout selection. `#[btf(flavor = ...)]` emits this
/// implementation using the hidden marker declared by `btf_profile!` in its
/// enclosing bindings module.
pub unsafe trait InModule<Module>: BtfType {}

/// Selects the terminal return shape for a deferred field path.
///
/// `Probe` deliberately does not implement this trait, so a generated
/// discriminator can extend and test a path but cannot read from its null
/// address base.
#[doc(hidden)]
pub trait AccessMode<Root: BtfType>: Sized {
    type Result<T>;

    #[doc(hidden)]
    fn __btf_get<'a, Value, Path>(
        field: &Field<'a, Root, Value, Path, Self>,
    ) -> Self::Result<&'a Value>;
}

// A leaf field cannot extend a named BTF path, so its view exposes only the
// terminal `Field` operations. Its ordinary layout is already suitable for
// describing the leaf member in its enclosing carrier.
macro_rules! impl_leaf_btf_type {
    ($($ty:ty),* $(,)?) => {
        $(
            impl BtfType for $ty {
                type Carrier = Self;

                type View<'a, Root, Path, Mode>
                    = Field<'a, Root, Self, Path, Mode>
                where
                    Self: 'a,
                    Root: BtfType + 'a;

                fn __btf_view<'a, Root, Path, Mode>(
                    field: Field<'a, Root, Self, Path, Mode>,
                ) -> Self::View<'a, Root, Path, Mode>
                where
                    Self: 'a,
                    Root: BtfType + 'a,
                {
                    field
                }
            }
        )*
    };
}

impl_leaf_btf_type!(
    (),
    bool,
    char,
    f32,
    f64,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
);

// Pointer fields must point at carriers: pointing at a macro-generated public
// ZST would sever the local BTF type graph at the pointee. Dereferencing the
// pointer is separate from appending a named field path in this API.
impl<T> BtfType for *const T
where
    T: BtfType,
{
    type Carrier = *const T::Carrier;

    type View<'a, Root, Path, Mode>
        = Field<'a, Root, Self, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a;

    fn __btf_view<'a, Root, Path, Mode>(
        field: Field<'a, Root, Self, Path, Mode>,
    ) -> Self::View<'a, Root, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a,
    {
        field
    }
}

impl<T> BtfType for *mut T
where
    T: BtfType,
{
    type Carrier = *mut T::Carrier;

    type View<'a, Root, Path, Mode>
        = Field<'a, Root, Self, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a;

    fn __btf_view<'a, Root, Path, Mode>(
        field: Field<'a, Root, Self, Path, Mode>,
    ) -> Self::View<'a, Root, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a,
    {
        field
    }
}

// An array field similarly retains its element's carrier in local BTF. This
// prototype treats an array as a terminal value; indexed CO-RE paths would
// require a corresponding path component.
impl<T, const N: usize> BtfType for [T; N]
where
    T: BtfType,
{
    type Carrier = [T::Carrier; N];

    type View<'a, Root, Path, Mode>
        = Field<'a, Root, Self, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a;

    fn __btf_view<'a, Root, Path, Mode>(
        field: Field<'a, Root, Self, Path, Mode>,
    ) -> Self::View<'a, Root, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a,
    {
        field
    }
}

/// The start of a root-relative BTF field path.
///
/// The private member makes the terminator visible as a concrete composite in
/// debug information. Its name is not decoded as a field-path step.
#[doc(hidden)]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RootPath {
    _private: u8,
}

/// One field appended to a root-relative BTF field path.
///
/// These fields exist for debug information. bpf-linker reads the nested path
/// type at the field-info polyfill call and replaces that call with ordinary
/// LLVM CO-RE preserve-access intrinsics.
#[doc(hidden)]
#[repr(C)]
pub struct FieldPath<Parent, Field> {
    /// The preceding path node; the member name is part of the DI protocol.
    pub parent: Parent,
    /// A marker whose member name identifies the next local BTF field.
    pub field: Field,
}

/// A deferred view of one BTF field path.
///
/// Accessors generated by `#[btf]` extend the path. Terminal methods below ask
/// bpf-linker for one full-path CO-RE query and only then materialize the
/// relocated address.
///
/// `Root` describes the base object, `Value` describes the terminal field, and
/// `Path` is a type-only encoding of the root-relative member sequence.
pub struct Field<'a, Root, Value, Path, Mode = Optional> {
    // Always retain the root pointer. Adjusting it in each accessor would turn
    // a nested expression into separate relocations rather than one full path.
    base: *const Root,
    // No path value is stored in the BPF program. These parameters exist for
    // lifetime tracking, result typing, and monomorphized debug information.
    _marker: PhantomData<(&'a Root, Value, Path, Mode)>,
}

impl<'a, Root, Mode> Field<'a, Root, Root, RootPath, Mode>
where
    Root: BtfType,
{
    /// Starts a deferred query at a kernel object's root address.
    ///
    /// Generated root accessors immediately append their first field marker;
    /// this method performs no BTF query or memory access itself.
    #[doc(hidden)]
    #[inline(always)]
    pub fn __btf_root(base: &'a Root) -> Self {
        Self {
            base: core::ptr::from_ref(base),
            _marker: PhantomData,
        }
    }

    /// Starts a query-only path with no backing kernel address.
    ///
    /// Only generated profile detection uses this: `Probe` exposes
    /// `exists()` but has no terminal address-producing operations.
    #[doc(hidden)]
    #[inline(always)]
    pub fn __btf_probe() -> Field<'static, Root, Root, RootPath, Probe>
    where
        Root: 'static,
    {
        Field {
            base: core::ptr::null(),
            _marker: PhantomData,
        }
    }
}

impl<'a, Root, Value, Path, Mode> Field<'a, Root, Value, Path, Mode> {
    /// Appends one macro-generated field marker to the pending path.
    ///
    /// `Marker` conveys its member name through debug information. The base
    /// pointer is deliberately unchanged until a terminal query is made.
    #[doc(hidden)]
    #[inline(always)]
    pub fn __btf_field<Next, Marker>(
        &self,
    ) -> Field<'a, Root, Next, FieldPath<Path, Marker>, Mode> {
        Field {
            base: self.base,
            _marker: PhantomData,
        }
    }
}

impl<'a, Root, Value, Path, Mode> Field<'a, Root, Value, Path, Mode>
where
    Root: BtfType,
{
    /// Queries whether this complete field path exists in the target BTF type.
    ///
    /// This is a terminal operation: it produces one `field_exists` CO-RE
    /// relocation for the whole accumulated path.
    #[inline(always)]
    pub fn exists(&self) -> bool {
        let base = self.base.cast::<Root::Carrier>();
        btf_field_exists(base, core::ptr::null::<Path>()) != 0
    }

    /// Returns this field's relocated address in the shape selected by its
    /// access mode.
    ///
    /// Ordinary views return `Option<&Value>` after an existence query.
    /// Profile-backed required views return `&Value` and rely on the
    /// discriminator branch that constructed the profile witness.
    #[inline(always)]
    pub fn get(&self) -> Mode::Result<&'a Value>
    where
        Mode: AccessMode<Root>,
    {
        Mode::__btf_get(self)
    }

    #[inline(always)]
    fn __btf_get_required(&self) -> &'a Value {
        let base = self.base.cast::<Root::Carrier>();
        let offset = btf_field_byte_offset(base, core::ptr::null::<Path>()) as usize;
        let field = unsafe { self.base.cast::<u8>().add(offset).cast::<Value>() };
        unsafe { &*field }
    }

    /// Returns a raw pointer to the field at its relocated address.
    ///
    /// Emits one `byte_offset` CO-RE relocation; no `exists()` query. The
    /// caller must independently guarantee the field exists (either via a
    /// prior `exists()` true branch or a profile-backed code path).
    #[inline(always)]
    pub fn as_ptr(&self) -> *const Value {
        let base = self.base.cast::<Root::Carrier>();
        let offset = btf_field_byte_offset(base, core::ptr::null::<Path>()) as usize;
        unsafe { self.base.cast::<u8>().add(offset).cast::<Value>() }
    }

    /// Returns a writable raw pointer to the field at its relocated address.
    ///
    /// Same constraints as [`Self::as_ptr`], plus the underlying object must
    /// have been originally mutable (e.g., the kernel handed out a `*mut`,
    /// not a `*const`).
    #[inline(always)]
    pub fn as_mut_ptr(&self) -> *mut Value {
        self.as_ptr() as *mut Value
    }
}

impl<Root> AccessMode<Root> for Optional
where
    Root: BtfType,
{
    type Result<T> = Option<T>;

    #[inline(always)]
    fn __btf_get<'a, Value, Path>(
        field: &Field<'a, Root, Value, Path, Self>,
    ) -> Self::Result<&'a Value> {
        // Skip the `field_exists` CO-RE relocation: if the field is missing
        // on the target kernel, the `byte_offset` relocation below will fail
        // at libbpf load time rather than producing a runtime `None`. Callers
        // that need real defensive behavior should use a profile witness.
        Some(field.__btf_get_required())
    }
}

impl<Root, P> AccessMode<Root> for Required<P>
where
    Root: BtfType + InModule<P::Module>,
    P: Profile,
{
    type Result<T> = T;

    #[inline(always)]
    fn __btf_get<'a, Value, Path>(
        field: &Field<'a, Root, Value, Path, Self>,
    ) -> Self::Result<&'a Value> {
        field.__btf_get_required()
    }
}

// These extern calls are linker markers, not runtime imports. The symbol says
// which field-info query to emit. The generic `Carrier` and `Path` types say
// which root and member chain it applies to: after inlining, their debug
// signature is what `FieldRelocPass` reads before deleting the call.
#[inline(always)]
fn btf_field_byte_offset<Carrier, Path>(base: *const Carrier, path: *const Path) -> u32 {
    unsafe extern "C" {
        #[link_name = "__btf_field_byte_offset"]
        fn field_byte_offset(base: *const (), path: *const ()) -> u32;
    }

    unsafe { field_byte_offset(base.cast(), path.cast()) }
}

#[inline(always)]
fn btf_field_exists<Carrier, Path>(base: *const Carrier, path: *const Path) -> u32 {
    unsafe extern "C" {
        #[link_name = "__btf_field_exists"]
        fn field_exists(base: *const (), path: *const ()) -> u32;
    }

    unsafe { field_exists(base.cast(), path.cast()) }
}

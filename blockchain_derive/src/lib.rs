//! Derive macro for automatic binary serialization with zero-allocation hashing.
//!
//! This crate provides `#[derive(BinaryCodec)]` which generates `BorshSerialize`
//! and `BorshDeserialize` implementations, enabling the `BinaryCodecHash` trait
//! via blanket implementation in the main crate.
//!
//! # Why a Custom Derive?
//!
//! Instead of requiring users to write `#[derive(BorshSerialize, BorshDeserialize)]`
//! on every type, this macro provides a single `#[derive(BinaryCodec)]` that:
//! - Generates deterministic binary serialization (little-endian, field-order)
//! - Enables zero-allocation hashing via `BinaryCodecHash::hash()`
//! - Keeps the public API clean (users don't need to know about borsh)
//!
//! # Supported Types
//!
//! - **Named structs**: `struct Foo { a: u32, b: u64 }`
//! - **Tuple structs**: `struct Bar(u32, u64)`
//! - **Unit structs**: `struct Baz`
//! - **Enums**: `enum Status { Active, Pending { id: u32 }, Error(String) }`
//!
//! Unions are not supported.
//!
//! # Binary Format
//!
//! Fields are serialized in declaration order using borsh encoding:
//! - Integers: little-endian, fixed-width
//! - Arrays: elements serialized sequentially
//! - Vec/String: 4-byte length prefix (little-endian u32) followed by data
//!
//! This format is deterministic, making it suitable for cryptographic hashing.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DataEnum, DeriveInput, Fields};

/// Derives `BorshSerialize` and `BorshDeserialize` for a struct.
///
/// This enables the `BinaryCodecHash` trait automatically via blanket implementation,
/// providing zero-allocation hashing support.
///
/// # Example
///
/// ```ignore
/// use blockchain_derive::BinaryCodec;
///
/// #[derive(BinaryCodec)]
/// pub struct Header {
///     pub version: u32,
///     pub height: u32,
/// }
/// ```
///
/// # Generated Code
///
/// ```ignore
/// impl borsh::BorshSerialize for Point {
///     fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
///         borsh::BorshSerialize::serialize(&self.x, writer)?;
///         borsh::BorshSerialize::serialize(&self.y, writer)?;
///         Ok(())
///     }
/// }
///
/// impl borsh::BorshDeserialize for Point {
///     fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
///         Ok(Self {
///             x: borsh::BorshDeserialize::deserialize_reader(reader)?,
///             y: borsh::BorshDeserialize::deserialize_reader(reader)?,
///         })
///     }
/// }
/// ```
#[proc_macro_derive(BinaryCodec)]
pub fn derive_binary_codec(input: TokenStream) -> TokenStream {
    // Parse the input token stream into a syntax tree.
    // `DeriveInput` represents a struct, enum, or union definition.
    let input = parse_macro_input!(input as DeriveInput);

    // Extract the type name (e.g., "Header", "Block").
    let name = &input.ident;

    // Extract generic parameters if any (e.g., `<T>`, `<'a, T: Clone>`).
    let generics = &input.generics;

    // Split generics into components needed for impl blocks:
    // - impl_generics: `<T: Clone>` (for `impl<T: Clone>`)
    // - ty_generics: `<T>` (for `MyStruct<T>`)
    // - where_clause: `where T: Debug` (optional constraints)
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Generate different code based on the data type (struct, enum, union).
    let expanded = match &input.data {
        // Handle struct types.
        Data::Struct(data_struct) => match &data_struct.fields {
            // Named fields: `struct Foo { a: u32, b: u64 }`
            Fields::Named(fields) => {
                generate_named_struct_impl(name, &impl_generics, &ty_generics, where_clause, fields)
            }
            // Tuple fields: `struct Foo(u32, u64)`
            Fields::Unnamed(fields) => {
                generate_tuple_struct_impl(name, &impl_generics, &ty_generics, where_clause, fields)
            }
            // Unit struct: `struct Foo`
            Fields::Unit => {
                generate_unit_struct_impl(name, &impl_generics, &ty_generics, where_clause)
            }
        },
        // Handle enum types.
        Data::Enum(data_enum) => {
            generate_enum_impl(name, &impl_generics, &ty_generics, where_clause, data_enum)
        }
        // Unions are not supported - emit a compile error.
        Data::Union(_) => {
            syn::Error::new_spanned(&input, "BinaryCodec derive does not support unions")
                .to_compile_error()
        }
    };

    TokenStream::from(expanded)
}

/// Generates `BorshSerialize` and `BorshDeserialize` for named-field structs.
///
/// Named structs have fields accessed by name: `self.field_name`.
/// Serialization writes each field in declaration order.
/// Deserialization reads fields in the same order and constructs the struct.
fn generate_named_struct_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
    fields: &syn::FieldsNamed,
) -> proc_macro2::TokenStream {
    // Collect field names (e.g., [version, height, timestamp]).
    let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();

    // Generate serialization code for each field.
    // Each field calls `BorshSerialize::serialize` in order.
    let serialize_fields = field_names.iter().map(|name| {
        quote! {
            ::borsh::BorshSerialize::serialize(&self.#name, writer)?;
        }
    });

    // Generate deserialization code for each field.
    // Each field calls `BorshDeserialize::deserialize_reader` in order.
    let deserialize_fields = field_names.iter().map(|name| {
        quote! {
            #name: ::borsh::BorshDeserialize::deserialize_reader(reader)?,
        }
    });

    // Combine into full trait implementations.
    quote! {
        impl #impl_generics ::borsh::BorshSerialize for #name #ty_generics #where_clause {
            fn serialize<W: ::std::io::Write>(&self, writer: &mut W) -> ::std::io::Result<()> {
                #(#serialize_fields)*
                Ok(())
            }
        }

        impl #impl_generics ::borsh::BorshDeserialize for #name #ty_generics #where_clause {
            fn deserialize_reader<R: ::std::io::Read>(reader: &mut R) -> ::std::io::Result<Self> {
                Ok(Self {
                    #(#deserialize_fields)*
                })
            }
        }
    }
}

/// Generates `BorshSerialize` and `BorshDeserialize` for tuple structs.
///
/// Tuple structs have fields accessed by index: `self.0`, `self.1`.
/// Common for newtype wrappers like `struct Hash(pub [u8; 32])`.
fn generate_tuple_struct_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
    fields: &syn::FieldsUnnamed,
) -> proc_macro2::TokenStream {
    // Generate indices for each field (0, 1, 2, ...).
    // `syn::Index` produces tokens that work with tuple field access.
    let field_indices: Vec<_> = (0..fields.unnamed.len()).map(syn::Index::from).collect();

    // Generate serialization code for each field by index.
    let serialize_fields = field_indices.iter().map(|idx| {
        quote! {
            ::borsh::BorshSerialize::serialize(&self.#idx, writer)?;
        }
    });

    // Generate deserialization code for each field.
    // Results are collected into a tuple constructor: `Self(field0, field1, ...)`.
    let deserialize_fields = field_indices.iter().map(|_| {
        quote! {
            ::borsh::BorshDeserialize::deserialize_reader(reader)?,
        }
    });

    quote! {
        impl #impl_generics ::borsh::BorshSerialize for #name #ty_generics #where_clause {
            fn serialize<W: ::std::io::Write>(&self, writer: &mut W) -> ::std::io::Result<()> {
                #(#serialize_fields)*
                Ok(())
            }
        }

        impl #impl_generics ::borsh::BorshDeserialize for #name #ty_generics #where_clause {
            fn deserialize_reader<R: ::std::io::Read>(reader: &mut R) -> ::std::io::Result<Self> {
                Ok(Self(
                    #(#deserialize_fields)*
                ))
            }
        }
    }
}

/// Generates `BorshSerialize` and `BorshDeserialize` for unit structs.
///
/// Unit structs have no fields: `struct Marker`.
/// Serialization writes nothing; deserialization just returns `Self`.
fn generate_unit_struct_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
) -> proc_macro2::TokenStream {
    quote! {
        impl #impl_generics ::borsh::BorshSerialize for #name #ty_generics #where_clause {
            fn serialize<W: ::std::io::Write>(&self, _writer: &mut W) -> ::std::io::Result<()> {
                Ok(())
            }
        }

        impl #impl_generics ::borsh::BorshDeserialize for #name #ty_generics #where_clause {
            fn deserialize_reader<R: ::std::io::Read>(_reader: &mut R) -> ::std::io::Result<Self> {
                Ok(Self)
            }
        }
    }
}

/// Generates `BorshSerialize` and `BorshDeserialize` for enums.
///
/// Enums are serialized with a u8 discriminant followed by variant fields.
/// Supports unit variants, tuple variants, and struct variants.
///
/// # Binary Format
///
/// - Discriminant: u8 variant index (0, 1, 2, ...)
/// - Fields: serialized in declaration order (if any)
fn generate_enum_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
    data_enum: &DataEnum,
) -> proc_macro2::TokenStream {
    // Generate serialize match arms for each variant.
    let serialize_arms = data_enum.variants.iter().enumerate().map(|(idx, variant)| {
        let variant_name = &variant.ident;
        let idx = idx as u8;

        match &variant.fields {
            // Unit variant: `Variant`
            Fields::Unit => {
                quote! {
                    Self::#variant_name => {
                        ::borsh::BorshSerialize::serialize(&#idx, writer)?;
                    }
                }
            }
            // Tuple variant: `Variant(T1, T2, ...)`
            Fields::Unnamed(fields) => {
                let field_names: Vec<_> = (0..fields.unnamed.len())
                    .map(|i| quote::format_ident!("f{}", i))
                    .collect();
                let serialize_fields = field_names.iter().map(|f| {
                    quote! { ::borsh::BorshSerialize::serialize(#f, writer)?; }
                });
                quote! {
                    Self::#variant_name(#(#field_names),*) => {
                        ::borsh::BorshSerialize::serialize(&#idx, writer)?;
                        #(#serialize_fields)*
                    }
                }
            }
            // Struct variant: `Variant { a: T1, b: T2, ... }`
            Fields::Named(fields) => {
                let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();
                let serialize_fields = field_names.iter().map(|f| {
                    quote! { ::borsh::BorshSerialize::serialize(#f, writer)?; }
                });
                quote! {
                    Self::#variant_name { #(#field_names),* } => {
                        ::borsh::BorshSerialize::serialize(&#idx, writer)?;
                        #(#serialize_fields)*
                    }
                }
            }
        }
    });

    // Generate deserialize match arms for each variant.
    let deserialize_arms = data_enum.variants.iter().enumerate().map(|(idx, variant)| {
        let variant_name = &variant.ident;
        let idx = idx as u8;

        match &variant.fields {
            // Unit variant: `Variant`
            Fields::Unit => {
                quote! {
                    #idx => Ok(Self::#variant_name),
                }
            }
            // Tuple variant: `Variant(T1, T2, ...)`
            Fields::Unnamed(fields) => {
                let deserialize_fields = (0..fields.unnamed.len()).map(|_| {
                    quote! { ::borsh::BorshDeserialize::deserialize_reader(reader)?, }
                });
                quote! {
                    #idx => Ok(Self::#variant_name(#(#deserialize_fields)*)),
                }
            }
            // Struct variant: `Variant { a: T1, b: T2, ... }`
            Fields::Named(fields) => {
                let deserialize_fields = fields.named.iter().map(|f| {
                    let field_name = &f.ident;
                    quote! { #field_name: ::borsh::BorshDeserialize::deserialize_reader(reader)?, }
                });
                quote! {
                    #idx => Ok(Self::#variant_name { #(#deserialize_fields)* }),
                }
            }
        }
    });

    // Generate the full name as a string for error messages.
    let name_str = name.to_string();

    quote! {
        impl #impl_generics ::borsh::BorshSerialize for #name #ty_generics #where_clause {
            fn serialize<W: ::std::io::Write>(&self, writer: &mut W) -> ::std::io::Result<()> {
                match self {
                    #(#serialize_arms)*
                }
                Ok(())
            }
        }

        impl #impl_generics ::borsh::BorshDeserialize for #name #ty_generics #where_clause {
            fn deserialize_reader<R: ::std::io::Read>(reader: &mut R) -> ::std::io::Result<Self> {
                let variant_idx: u8 = ::borsh::BorshDeserialize::deserialize_reader(reader)?;
                match variant_idx {
                    #(#deserialize_arms)*
                    _ => Err(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidData,
                        format!("Invalid {} variant index: {}", #name_str, variant_idx),
                    )),
                }
            }
        }
    }
}

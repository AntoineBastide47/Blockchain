//! Derive macro for automatic binary serialization.
//!
//! Generates `Encode` and `Decode` implementations for structs and enums.
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
//! Fields are serialized in declaration order:
//! - Integers: little-endian, fixed-width
//! - Arrays: elements serialized sequentially
//! - Vec/String: 8-byte length prefix (little-endian u64) followed by data
//!
//! This format is deterministic, making it suitable for cryptographic hashing.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DataEnum, DeriveInput, Fields};

/// Derives `Encode` and `Decode` for a type.
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
/// impl Encode for Header {
///     fn encode<S: EncodeSink>(&self, out: &mut S) {
///         self.version.encode(out);
///         self.height.encode(out);
///     }
/// }
///
/// impl Decode for Header {
///     fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
///         Ok(Self {
///             version: u32::decode(input)?,
///             height: u32::decode(input)?,
///         })
///     }
/// }
/// ```
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

/// Generates `Encode` and `Decode` for named-field structs.
///
/// Named structs have fields accessed by name: `self.field_name`.
/// Encoding writes each field in declaration order.
/// Decoding reads fields in the same order and constructs the struct.
fn generate_named_struct_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
    fields: &syn::FieldsNamed,
) -> proc_macro2::TokenStream {
    // Collect field names (e.g., [version, height, timestamp]).
    let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();

    // Generate encoding code for each field.
    let encode_fields = field_names.iter().map(|name| {
        quote! {
            crate::types::encoding::Encode::encode(&self.#name, out);
        }
    });

    // Generate decoding code for each field.
    let decode_fields = field_names.iter().map(|name| {
        quote! {
            #name: crate::types::encoding::Decode::decode(input)?,
        }
    });

    // Combine into full trait implementations.
    quote! {
        impl #impl_generics crate::types::encoding::Encode for #name #ty_generics #where_clause {
            fn encode<S: crate::types::encoding::EncodeSink>(&self, out: &mut S) {
                #(#encode_fields)*
            }
        }

        impl #impl_generics crate::types::encoding::Decode for #name #ty_generics #where_clause {
            fn decode(input: &mut &[u8]) -> ::std::result::Result<Self, crate::types::encoding::DecodeError> {
                Ok(Self {
                    #(#decode_fields)*
                })
            }
        }
    }
}

/// Generates `Encode` and `Decode` for tuple structs.
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
    let field_indices: Vec<_> = (0..fields.unnamed.len()).map(syn::Index::from).collect();

    // Generate encoding code for each field by index.
    let encode_fields = field_indices.iter().map(|idx| {
        quote! {
            crate::types::encoding::Encode::encode(&self.#idx, out);
        }
    });

    // Generate decoding code for each field.
    let decode_fields = field_indices.iter().map(|_| {
        quote! {
            crate::types::encoding::Decode::decode(input)?,
        }
    });

    quote! {
        impl #impl_generics crate::types::encoding::Encode for #name #ty_generics #where_clause {
            fn encode<S: crate::types::encoding::EncodeSink>(&self, out: &mut S) {
                #(#encode_fields)*
            }
        }

        impl #impl_generics crate::types::encoding::Decode for #name #ty_generics #where_clause {
            fn decode(input: &mut &[u8]) -> ::std::result::Result<Self, crate::types::encoding::DecodeError> {
                Ok(Self(
                    #(#decode_fields)*
                ))
            }
        }
    }
}

/// Generates `Encode` and `Decode` for unit structs.
///
/// Unit structs have no fields: `struct Marker`.
/// Encoding writes nothing; decoding just returns `Self`.
fn generate_unit_struct_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
) -> proc_macro2::TokenStream {
    quote! {
        impl #impl_generics crate::types::encoding::Encode for #name #ty_generics #where_clause {
            fn encode<S: crate::types::encoding::EncodeSink>(&self, _out: &mut S) {}
        }

        impl #impl_generics crate::types::encoding::Decode for #name #ty_generics #where_clause {
            fn decode(_input: &mut &[u8]) -> ::std::result::Result<Self, crate::types::encoding::DecodeError> {
                Ok(Self)
            }
        }
    }
}

/// Generates `Encode` and `Decode` for enums.
///
/// Enums are encoded with a u8 discriminant followed by variant fields.
/// Supports unit variants, tuple variants, and struct variants.
/// Respects explicit discriminant values (e.g., `Variant = 5`).
///
/// # Binary Format
///
/// - Discriminant: u8 (explicit value or auto-incremented from previous)
/// - Fields: encoded in declaration order (if any)
fn generate_enum_impl(
    name: &syn::Ident,
    impl_generics: &syn::ImplGenerics,
    ty_generics: &syn::TypeGenerics,
    where_clause: Option<&syn::WhereClause>,
    data_enum: &DataEnum,
) -> proc_macro2::TokenStream {
    // Compute discriminant values respecting explicit assignments.
    let discriminants: Vec<u8> = compute_discriminants(data_enum);

    // Generate encode match arms for each variant.
    let encode_arms = data_enum.variants.iter().zip(discriminants.iter()).map(|(variant, &idx)| {
        let variant_name = &variant.ident;

        match &variant.fields {
            // Unit variant: `Variant`
            Fields::Unit => {
                quote! {
                    Self::#variant_name => {
                        crate::types::encoding::Encode::encode(&#idx, out);
                    }
                }
            }
            // Tuple variant: `Variant(T1, T2, ...)`
            Fields::Unnamed(fields) => {
                let field_names: Vec<_> = (0..fields.unnamed.len())
                    .map(|i| quote::format_ident!("f{}", i))
                    .collect();
                let encode_fields = field_names.iter().map(|f| {
                    quote! { crate::types::encoding::Encode::encode(#f, out); }
                });
                quote! {
                    Self::#variant_name(#(#field_names),*) => {
                        crate::types::encoding::Encode::encode(&#idx, out);
                        #(#encode_fields)*
                    }
                }
            }
            // Struct variant: `Variant { a: T1, b: T2, ... }`
            Fields::Named(fields) => {
                let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();
                let encode_fields = field_names.iter().map(|f| {
                    quote! { crate::types::encoding::Encode::encode(#f, out); }
                });
                quote! {
                    Self::#variant_name { #(#field_names),* } => {
                        crate::types::encoding::Encode::encode(&#idx, out);
                        #(#encode_fields)*
                    }
                }
            }
        }
    });

    // Generate decode match arms for each variant.
    let decode_arms = data_enum.variants.iter().zip(discriminants.iter()).map(|(variant, &idx)| {
        let variant_name = &variant.ident;

        match &variant.fields {
            // Unit variant: `Variant`
            Fields::Unit => {
                quote! {
                    #idx => Ok(Self::#variant_name),
                }
            }
            // Tuple variant: `Variant(T1, T2, ...)`
            Fields::Unnamed(fields) => {
                let decode_fields = (0..fields.unnamed.len()).map(|_| {
                    quote! { crate::types::encoding::Decode::decode(input)?, }
                });
                quote! {
                    #idx => Ok(Self::#variant_name(#(#decode_fields)*)),
                }
            }
            // Struct variant: `Variant { a: T1, b: T2, ... }`
            Fields::Named(fields) => {
                let decode_fields = fields.named.iter().map(|f| {
                    let field_name = &f.ident;
                    quote! { #field_name: crate::types::encoding::Decode::decode(input)?, }
                });
                quote! {
                    #idx => Ok(Self::#variant_name { #(#decode_fields)* }),
                }
            }
        }
    });

    quote! {
        impl #impl_generics crate::types::encoding::Encode for #name #ty_generics #where_clause {
            fn encode<S: crate::types::encoding::EncodeSink>(&self, out: &mut S) {
                match self {
                    #(#encode_arms)*
                }
            }
        }

        impl #impl_generics crate::types::encoding::Decode for #name #ty_generics #where_clause {
            fn decode(input: &mut &[u8]) -> ::std::result::Result<Self, crate::types::encoding::DecodeError> {
                let variant_idx: u8 = crate::types::encoding::Decode::decode(input)?;
                match variant_idx {
                    #(#decode_arms)*
                    _ => Err(crate::types::encoding::DecodeError::InvalidValue),
                }
            }
        }
    }
}

/// Computes discriminant values for each enum variant.
///
/// Follows Rust's discriminant rules:
/// - If explicit value provided (e.g., `Variant = 5`), use it
/// - Otherwise, increment from the previous variant's discriminant
/// - First variant defaults to 0 if no explicit value
fn compute_discriminants(data_enum: &DataEnum) -> Vec<u8> {
    let mut discriminants = Vec::with_capacity(data_enum.variants.len());
    let mut next_discriminant: u8 = 0;

    for variant in &data_enum.variants {
        let discriminant = if let Some((_, expr)) = &variant.discriminant {
            // Parse the explicit discriminant value.
            parse_discriminant_expr(expr)
        } else {
            next_discriminant
        };

        discriminants.push(discriminant);
        next_discriminant = discriminant.checked_add(1).unwrap_or_else(||{
            0
        });
    }

    discriminants
}

/// Parses a discriminant expression to extract its u8 value.
///
/// Supports integer literals. Panics on unsupported expressions.
fn parse_discriminant_expr(expr: &syn::Expr) -> u8 {
    match expr {
        syn::Expr::Lit(expr_lit) => match &expr_lit.lit {
            syn::Lit::Int(lit_int) => lit_int
                .base10_parse::<u8>()
                .expect("Discriminant must be a valid u8"),
            _ => panic!("Discriminant must be an integer literal"),
        },
        _ => panic!("Discriminant must be a simple integer literal"),
    }
}

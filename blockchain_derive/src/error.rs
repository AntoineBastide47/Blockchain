//! Derive macro for error types.
//!
//! Generates `std::fmt::Display` and `std::error::Error` implementations.
//! Replacement for `thiserror` crate.
//!
//! # Usage
//!
//! ```ignore
//! use blockchain_derive::Error;
//!
//! #[derive(Debug, Error)]
//! pub enum MyError {
//!     #[error("not found: {0}")]
//!     NotFound(String),
//!
//!     #[error("invalid value: expected {expected}, got {actual}")]
//!     InvalidValue { expected: u32, actual: u32 },
//!
//!     #[error("unknown error")]
//!     Unknown,
//! }
//! ```
//!
//! # Supported Features
//!
//! - Unit variants: `#[error("message")]`
//! - Tuple variants with positional args: `#[error("error: {0}")]`
//! - Struct variants with named args: `#[error("expected {expected}")]`

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Lit, Meta};

/// Derives `Display` and `Error` for an enum.
///
/// Each variant must have an `#[error("...")]` attribute specifying
/// the display message. Supports field interpolation using `{0}`, `{1}`
/// for tuple fields or `{field_name}` for struct fields.
pub fn derive_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = match &input.data {
        Data::Enum(data_enum) => {
            let display_arms = data_enum.variants.iter().map(|variant| {
                let variant_name = &variant.ident;
                let error_msg = extract_error_message(variant);

                match &variant.fields {
                    Fields::Unit => {
                        quote! {
                            Self::#variant_name => write!(f, #error_msg),
                        }
                    }
                    Fields::Unnamed(fields) => {
                        let field_names: Vec<_> = (0..fields.unnamed.len())
                            .map(|i| quote::format_ident!("f{}", i))
                            .collect();
                        let format_str = convert_positional_to_named(&error_msg, fields.unnamed.len());
                        quote! {
                            Self::#variant_name(#(#field_names),*) => write!(f, #format_str, #(#field_names = #field_names),*),
                        }
                    }
                    Fields::Named(fields) => {
                        let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();
                        quote! {
                            Self::#variant_name { #(#field_names),* } => write!(f, #error_msg, #(#field_names = #field_names),*),
                        }
                    }
                }
            });

            quote! {
                impl #impl_generics ::std::fmt::Display for #name #ty_generics #where_clause {
                    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                        match self {
                            #(#display_arms)*
                        }
                    }
                }

                impl #impl_generics ::std::error::Error for #name #ty_generics #where_clause {}
            }
        }
        Data::Struct(data_struct) => {
            let error_msg = extract_error_message_from_attrs(&input.attrs);

            let display_body = match &data_struct.fields {
                Fields::Unit => {
                    quote! {
                        write!(f, #error_msg)
                    }
                }
                Fields::Named(fields) => {
                    let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();
                    quote! {
                        write!(f, #error_msg, #(#field_names = self.#field_names),*)
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_idents: Vec<_> = (0..fields.unnamed.len())
                        .map(|i| quote::format_ident!("f{}", i))
                        .collect();
                    let field_indices: Vec<_> = (0..fields.unnamed.len())
                        .map(syn::Index::from)
                        .collect();
                    let format_str = convert_positional_to_named(&error_msg, fields.unnamed.len());
                    quote! {
                        write!(f, #format_str, #(#field_idents = self.#field_indices),*)
                    }
                }
            };

            quote! {
                impl #impl_generics ::std::fmt::Display for #name #ty_generics #where_clause {
                    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                        #display_body
                    }
                }

                impl #impl_generics ::std::error::Error for #name #ty_generics #where_clause {}
            }
        }
        Data::Union(_) => {
            syn::Error::new_spanned(&input, "Error derive does not support unions")
                .to_compile_error()
        }
    };

    TokenStream::from(expanded)
}

/// Extracts the error message from a variant's `#[error("...")]` attribute.
fn extract_error_message(variant: &syn::Variant) -> String {
    extract_error_message_from_attrs(&variant.attrs)
}

/// Extracts the error message from attributes.
fn extract_error_message_from_attrs(attrs: &[syn::Attribute]) -> String {
    for attr in attrs {
        if attr.path().is_ident("error") {
            if let Meta::List(meta_list) = &attr.meta {
                let tokens = meta_list.tokens.clone();
                if let Ok(lit) = syn::parse2::<Lit>(tokens) {
                    if let Lit::Str(lit_str) = lit {
                        return lit_str.value();
                    }
                }
            }
        }
    }
    panic!("Missing #[error(\"...\")] attribute");
}

/// Converts positional format args `{0}`, `{1}` to named args `{f0}`, `{f1}`.
fn convert_positional_to_named(format_str: &str, field_count: usize) -> String {
    let mut result = format_str.to_string();
    for i in (0..field_count).rev() {
        let positional = format!("{{{}}}", i);
        let named = format!("{{f{}}}", i);
        result = result.replace(&positional, &named);
    }
    result
}

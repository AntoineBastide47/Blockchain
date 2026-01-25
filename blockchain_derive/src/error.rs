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
use proc_macro2::Span;
use quote::{quote, ToTokens};
use std::collections::HashSet;
use syn::{parse_macro_input, Data, DeriveInput, Expr, Fields, Lit, Meta};

/// Derives `Display` and `Error` for an enum or struct.
///
/// Each variant must have an `#[error("...")]` attribute specifying
/// the display message. Supports field interpolation using `{0}`, `{1}`
/// for tuple fields or `{field_name}` for struct fields.
pub fn derive_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match expand_error_derive(&input) {
        Ok(tokens) => TokenStream::from(tokens),
        Err(err) => err.to_compile_error().into(),
    }
}

fn expand_error_derive(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = match &input.data {
        Data::Enum(data_enum) => {
            let display_arms = data_enum
                .variants
                .iter()
                .map(|variant| {
                    let variant_name = &variant.ident;
                    let error_msg = extract_error_message(variant)?;

                    let arm = match &variant.fields {
                        Fields::Unit => {
                            quote! {
                                Self::#variant_name => write!(f, #error_msg),
                            }
                        }
                        Fields::Unnamed(fields) => {
                            let field_names: Vec<_> = (0..fields.unnamed.len())
                                .map(|i| quote::format_ident!("f{}", i))
                                .collect();
                            let positional_names: Vec<String> =
                                field_names.iter().map(|f| f.to_string()).collect();
                            let rewritten =
                                rewrite_format_string(&error_msg, Some(&positional_names))?;
                            let expr_lets = rewritten
                                .expr_bindings
                                .iter()
                                .map(|(ident, expr)| quote! { let #ident = #expr; });
                            let used_args = select_used_args(
                                &rewritten.placeholder_names,
                                &field_names,
                                &rewritten.expr_bindings,
                            );
                            let format_str = rewritten.format_str;
                            quote! {
                                #[allow(unused_variables)]
                                Self::#variant_name(#(#field_names),*) => {
                                    #(#expr_lets)*
                                    write!(f, #format_str, #(#used_args = #used_args),*)
                                },
                            }
                        }
                        Fields::Named(fields) => {
                            let field_names: Vec<_> = fields
                                .named
                                .iter()
                                .map(|f| f.ident.clone().unwrap())
                                .collect();
                            let rewritten = rewrite_format_string(&error_msg, None)?;
                            let expr_lets = rewritten
                                .expr_bindings
                                .iter()
                                .map(|(ident, expr)| quote! { let #ident = #expr; });
                            let used_args = select_used_args(
                                &rewritten.placeholder_names,
                                &field_names,
                                &rewritten.expr_bindings,
                            );
                            let format_str = rewritten.format_str;
                            quote! {
                                #[allow(unused_variables)]
                                Self::#variant_name { #(#field_names),* } => {
                                    #(#expr_lets)*
                                    write!(f, #format_str, #(#used_args = #used_args),*)
                                },
                            }
                        }
                    };

                    Ok(arm)
                })
                .collect::<syn::Result<Vec<_>>>()?;

            Ok(quote! {
                impl #impl_generics ::std::fmt::Display for #name #ty_generics #where_clause {
                    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                        match self {
                            #(#display_arms)*
                        }
                    }
                }

                impl #impl_generics ::std::error::Error for #name #ty_generics #where_clause {}
            })
        }
        Data::Struct(data_struct) => {
            let error_msg = extract_error_message_from_attrs(
                &input.attrs,
                &input.ident,
                &format!("type `{}`", input.ident),
            )?;

            let display_body = match &data_struct.fields {
                Fields::Unit => {
                    quote! {
                        write!(f, #error_msg)
                    }
                }
                Fields::Named(fields) => {
                    let field_names: Vec<_> = fields
                        .named
                        .iter()
                        .map(|f| f.ident.clone().unwrap())
                        .collect();
                    let rewritten = rewrite_format_string(&error_msg, None)?;
                    let expr_lets = rewritten
                        .expr_bindings
                        .iter()
                        .map(|(ident, expr)| quote! { let #ident = #expr; });
                    let used_args = select_used_args(
                        &rewritten.placeholder_names,
                        &field_names,
                        &rewritten.expr_bindings,
                    );
                    let format_str = rewritten.format_str;
                    quote! {
                        #[allow(unused_variables)]
                        let Self { #(#field_names),* } = self;
                        #(#expr_lets)*
                        write!(f, #format_str, #(#used_args = #used_args),*)
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_names: Vec<_> = (0..fields.unnamed.len())
                        .map(|i| quote::format_ident!("f{}", i))
                        .collect();
                    let positional_names: Vec<String> =
                        field_names.iter().map(|f| f.to_string()).collect();
                    let rewritten = rewrite_format_string(&error_msg, Some(&positional_names))?;
                    let expr_lets = rewritten
                        .expr_bindings
                        .iter()
                        .map(|(ident, expr)| quote! { let #ident = #expr; });
                    let used_args = select_used_args(
                        &rewritten.placeholder_names,
                        &field_names,
                        &rewritten.expr_bindings,
                    );
                    let format_str = rewritten.format_str;
                    quote! {
                        #[allow(unused_variables)]
                        let Self(#(#field_names),*) = self;
                        #(#expr_lets)*
                        write!(f, #format_str, #(#used_args = #used_args),*)
                    }
                }
            };

            Ok(quote! {
                impl #impl_generics ::std::fmt::Display for #name #ty_generics #where_clause {
                    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                        #display_body
                    }
                }

                impl #impl_generics ::std::error::Error for #name #ty_generics #where_clause {}
            })
        }
        Data::Union(_) => Err(syn::Error::new_spanned(
            input,
            "Error derive does not support unions",
        )),
    }?;

    Ok(expanded)
}

/// Extracts the error message from a variant's `#[error("...")]` attribute.
fn extract_error_message(variant: &syn::Variant) -> syn::Result<String> {
    let variant_name = variant.ident.to_string();
    extract_error_message_from_attrs(
        &variant.attrs,
        &variant.ident,
        &format!("variant `{}`", variant_name),
    )
}

/// Extracts the error message from attributes.
fn extract_error_message_from_attrs<T: ToTokens>(
    attrs: &[syn::Attribute],
    target: &T,
    target_desc: &str,
) -> syn::Result<String> {
    for attr in attrs {
        if attr.path().is_ident("error") {
            if let Meta::List(meta_list) = &attr.meta {
                let tokens = meta_list.tokens.clone();
                let lit = syn::parse2::<Lit>(tokens).map_err(|_| {
                    syn::Error::new_spanned(
                        &attr.meta,
                        "failed to parse #[error] attribute; expected a string literal like #[error(\"network error: {0}\")]",
                    )
                })?;

                if let Lit::Str(lit_str) = lit {
                    return Ok(lit_str.value());
                }

                return Err(syn::Error::new_spanned(
                    &attr.meta,
                    "invalid #[error] attribute: message must be a string literal, e.g. #[error(\"invalid opcode: {0}\")]",
                ));
            }

            return Err(syn::Error::new_spanned(
                &attr.meta,
                "invalid #[error] attribute; use #[error(\"message\")] to describe the error",
            ));
        }
    }

    Err(syn::Error::new_spanned(
        target,
        format!(
            "missing #[error(\"...\")] attribute on {}; every error variant must declare a display message",
            target_desc
        ),
    ))
}

struct RewrittenFormat {
    format_str: String,
    expr_bindings: Vec<(syn::Ident, Expr)>,
    placeholder_names: Vec<String>,
}

fn rewrite_format_string(
    format_str: &str,
    positional_map: Option<&[String]>,
) -> syn::Result<RewrittenFormat> {
    let mut output = String::with_capacity(format_str.len());
    let mut expr_bindings = Vec::new();
    let mut placeholder_names = Vec::new();
    let mut expr_count = 0;

    let mut chars = format_str.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                if chars.peek() == Some(&'{') {
                    output.push('{');
                    output.push('{');
                    chars.next();
                    continue;
                }

                let mut content = String::new();
                let mut closed = false;
                while let Some(next) = chars.next() {
                    if next == '}' {
                        closed = true;
                        break;
                    }
                    content.push(next);
                }

                if !closed {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        "unterminated format placeholder in #[error] attribute",
                    ));
                }

                let (arg, spec) = split_arg_and_spec(&content);
                let arg_trim = arg.trim();
                if arg_trim.is_empty() {
                    output.push('{');
                    output.push_str(&content);
                    output.push('}');
                    continue;
                }

                let mut replaced = None;
                if let Ok(index) = arg_trim.parse::<usize>() {
                    if let Some(map) = positional_map {
                        if let Some(name) = map.get(index) {
                            replaced = Some(name.clone());
                        }
                    }
                }

                let name = if let Some(name) = replaced {
                    name
                } else if is_simple_ident(arg_trim) {
                    arg_trim.to_string()
                } else {
                    let expr: Expr = syn::parse_str(arg_trim).map_err(|_| {
                        syn::Error::new(
                            Span::call_site(),
                            format!(
                                "unsupported format expression `{}` in #[error] attribute",
                                arg_trim
                            ),
                        )
                    })?;
                    let ident = quote::format_ident!("__expr{}", expr_count as u64);
                    expr_count += 1;
                    expr_bindings.push((ident.clone(), expr));
                    ident.to_string()
                };

                output.push('{');
                output.push_str(&name);
                output.push_str(spec);
                output.push('}');
                placeholder_names.push(name);
            }
            '}' => {
                if chars.peek() == Some(&'}') {
                    output.push('}');
                    output.push('}');
                    chars.next();
                } else {
                    output.push('}');
                }
            }
            _ => output.push(ch),
        }
    }

    Ok(RewrittenFormat {
        format_str: output,
        expr_bindings,
        placeholder_names,
    })
}

fn split_arg_and_spec(content: &str) -> (&str, &str) {
    if let Some(idx) = content.find(':') {
        (&content[..idx], &content[idx..])
    } else {
        (content, "")
    }
}

fn select_used_args(
    placeholders: &[String],
    field_names: &[syn::Ident],
    expr_bindings: &[(syn::Ident, Expr)],
) -> Vec<syn::Ident> {
    let mut used = Vec::new();
    let mut seen = HashSet::new();
    let field_set: HashSet<String> = field_names.iter().map(|f| f.to_string()).collect();
    let expr_set: HashSet<String> = expr_bindings.iter().map(|(f, _)| f.to_string()).collect();

    for name in placeholders {
        if !field_set.contains(name) && !expr_set.contains(name) {
            continue;
        }
        if seen.insert(name.clone()) {
            used.push(quote::format_ident!("{}", name));
        }
    }

    used
}

fn is_simple_ident(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !is_ident_start(first) {
        return false;
    }
    chars.all(is_ident_continue)
}

fn is_ident_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_ident_continue(ch: char) -> bool {
    is_ident_start(ch) || ch.is_ascii_digit()
}

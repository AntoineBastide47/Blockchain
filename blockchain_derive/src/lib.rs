//! Derive macros for the blockchain crate.
//!
//! Provides:
//! - `#[derive(BinaryCodec)]` - automatic binary serialization
//! - `#[derive(Error)]` - error type boilerplate (thiserror replacement)

mod binary_codec;
mod error;

use proc_macro::TokenStream;

/// Automatically implements `Encode` and `Decode` traits for binary serialization.
#[proc_macro_derive(BinaryCodec, attributes(binary_codec))]
pub fn derive_binary_codec(input: TokenStream) -> TokenStream {
    binary_codec::derive_binary_codec(input)
}

/// Automatically implements `Display` and `Error` traits for error types.
#[proc_macro_derive(Error, attributes(error))]
pub fn derive_error(input: TokenStream) -> TokenStream {
    error::derive_error(input)
}

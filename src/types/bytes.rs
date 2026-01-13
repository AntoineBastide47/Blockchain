//! Reference-counted byte buffer with copy-on-write semantics.

use crate::types::encoding::{Decode, DecodeError, Encode, EncodeSink};
use std::ops::Deref;
use std::sync::Arc;

/// A reference-counted, immutable byte buffer.
///
/// Wraps `Arc<Vec<u8>>` to provide cheap cloning and shared ownership.
/// Mutations trigger copy-on-write via `Arc::make_mut`.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Bytes(Arc<Vec<u8>>);

impl Bytes {
    /// Creates a new buffer from any type convertible to `Vec<u8>`.
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self(Arc::new(data.into()))
    }

    /// Creates a new buffer from an existing `Vec<u8>`.
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self(Arc::new(v))
    }

    /// Creates an empty buffer with the specified capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self(Arc::new(Vec::with_capacity(cap)))
    }

    /// Returns the number of bytes in the buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the buffer contents as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Copies the buffer contents into a new `Vec<u8>`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    /// Returns a mutable reference to the underlying vector.
    ///
    /// Clones the data if other references exist (copy-on-write).
    pub fn make_mut(&mut self) -> &mut Vec<u8> {
        Arc::make_mut(&mut self.0)
    }

    /// Appends bytes to the buffer, cloning if necessary.
    pub fn extend_from_slice(&mut self, s: &[u8]) {
        self.make_mut().extend_from_slice(s);
    }
}

impl Clone for Bytes {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Encode for Bytes {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        self.0.len().encode(out);
        for item in self.clone().0.iter() {
            item.encode(out);
        }
    }
}

impl Decode for Bytes {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let len = usize::decode(input)?;

        let mut vec = Vec::<u8>::with_capacity(len);
        for _ in 0..len {
            vec.push(u8::decode(input)?);
        }
        Ok(Bytes::from_vec(vec))
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl From<&[u8]> for Bytes {
    fn from(s: &[u8]) -> Self {
        Self::new(s)
    }
}

impl From<&str> for Bytes {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for Bytes {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<Box<[u8]>> for Bytes {
    fn from(b: Box<[u8]>) -> Self {
        Self::new(b)
    }
}

impl<const N: usize> From<[u8; N]> for Bytes {
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

impl<const N: usize> From<&[u8; N]> for Bytes {
    fn from(arr: &[u8; N]) -> Self {
        Self::new(arr.as_slice())
    }
}

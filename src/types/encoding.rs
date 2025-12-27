//! Binary encoding and decoding traits for deterministic serialization.
//!
//! This module provides the core serialization infrastructure for the blockchain.
//! All encoded data uses little-endian byte order for cross-platform consistency.
//!
//! # Binary Format
//!
//! - Integers: little-endian, fixed-width
//! - `usize`: encoded as `u64` for portability
//! - `bool`: single byte (0 = false, 1 = true)
//! - `Vec<T>`/`String`: 8-byte length prefix followed by elements
//! - `Option<T>`: 1-byte tag (0 = None, 1 = Some) followed by value if present
//! - Arrays `[T; N]`: elements serialized sequentially without length prefix
//!
//! # Example
//!
//! ```ignore
//! use crate::types::encoding::{Encode, Decode};
//!
//! let value: u32 = 42;
//! let bytes = value.to_bytes();
//! let decoded = u32::from_bytes(&bytes).unwrap();
//! assert_eq!(value, decoded);
//! ```

use crate::types::bytes::Bytes;

/// Sink for writing encoded bytes.
///
/// Implemented by byte buffers and hashers to allow zero-copy encoding
/// directly into the target without intermediate allocations.
pub trait EncodeSink {
    /// Writes the given bytes to the sink.
    fn write(&mut self, bytes: &[u8]);
}

/// Counter for computing encoded size without allocating memory.
///
/// Used by `Encode::to_bytes` to pre-allocate exact capacity before encoding.
pub struct SizeCounter {
    len: usize,
}

impl SizeCounter {
    /// Creates a new counter initialized to zero.
    pub fn new() -> Self {
        Self { len: 0 }
    }

    /// Returns the total number of bytes counted.
    pub fn len(&self) -> usize {
        self.len
    }
}

impl EncodeSink for SizeCounter {
    fn write(&mut self, bytes: &[u8]) {
        self.len += bytes.len();
    }
}

impl EncodeSink for Bytes {
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

impl EncodeSink for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// Trait for types that can be serialized to binary format.
pub trait Encode {
    /// Writes the binary representation to the given sink.
    fn encode<S: EncodeSink>(&self, out: &mut S);

    /// Serializes to a new byte buffer with exact capacity.
    ///
    /// Performs two passes: first to count bytes, then to encode.
    fn to_bytes(&self) -> Bytes {
        // First pass: count
        let mut counter = SizeCounter::new();
        self.encode(&mut counter);

        // Second pass: encode once, with exact capacity
        let mut out = Bytes::with_capacity(counter.len());
        self.encode(&mut out);
        out
    }
}

/// Errors that can occur during decoding.
#[derive(Debug)]
pub enum DecodeError {
    /// Input ended before expected data was read.
    UnexpectedEof,
    /// Data does not represent a valid value for the target type.
    InvalidValue,
    /// Length prefix exceeds maximum allowed size.
    LengthOverflow,
}

/// Trait for types that can be deserialized from binary format.
pub trait Decode: Sized {
    /// Reads and decodes a value from the input buffer.
    ///
    /// Advances the input slice past the consumed bytes.
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError>;

    /// Decodes a value from a byte slice, requiring all bytes to be consumed.
    ///
    /// Returns `InvalidValue` if trailing bytes remain after decoding.
    fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut input = data;
        let value = Self::decode(&mut input)?;

        if !input.is_empty() {
            return Err(DecodeError::InvalidValue);
        }

        Ok(value)
    }
}

/// Reads exactly `n` bytes from the input, advancing the slice.
fn read_bytes<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], DecodeError> {
    if input.len() < n {
        return Err(DecodeError::UnexpectedEof);
    }
    let (bytes, rest) = input.split_at(n);
    *input = rest;
    Ok(bytes)
}

// u8
impl Encode for u8 {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        out.write(&[*self]);
    }
}

impl Decode for u8 {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let bytes = read_bytes(input, 1)?;
        Ok(bytes[0])
    }
}

// i8
impl Encode for i8 {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        out.write(&[*self as u8]);
    }
}

impl Decode for i8 {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let bytes = read_bytes(input, 1)?;
        Ok(bytes[0] as i8)
    }
}

// Macro for fixed-size integer types
macro_rules! impl_int {
    ($($t:ty),*) => {
        $(
            impl Encode for $t {
                fn encode<S: EncodeSink>(&self, out: &mut S) {
                    out.write(&self.to_le_bytes());
                }
            }

            impl Decode for $t {
                fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
                    let bytes = read_bytes(input, std::mem::size_of::<$t>())?;
                    Ok(<$t>::from_le_bytes(bytes.try_into().unwrap()))
                }
            }
        )*
    };
}

impl_int!(u16, u32, u64, u128, i16, i32, i64, i128);

// usize as u64
impl Encode for usize {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        (*self as u64).encode(out);
    }
}

impl Decode for usize {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let v = u64::decode(input)?;
        usize::try_from(v).map_err(|_| DecodeError::LengthOverflow)
    }
}

// bool
impl Encode for bool {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        out.write(&[*self as u8]);
    }
}

impl Decode for bool {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let b = u8::decode(input)?;
        match b {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::InvalidValue),
        }
    }
}

// Vec<T>
impl<T: Encode> Encode for Vec<T> {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        self.len().encode(out);
        for item in self {
            item.encode(out);
        }
    }
}

/// Maximum allowed length for decoded vectors to prevent memory exhaustion.
const MAX_VEC_LEN: usize = 1_000_000;

impl<T: Decode> Decode for Vec<T> {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let len = usize::decode(input)?;
        if len > MAX_VEC_LEN {
            return Err(DecodeError::LengthOverflow);
        }

        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::decode(input)?);
        }
        Ok(vec)
    }
}

// Box<[T]>
impl<T: Encode> Encode for Box<[T]> {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        self.len().encode(out);
        for item in self.iter() {
            item.encode(out);
        }
    }
}

impl<T: Decode> Decode for Box<[T]> {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let vec = Vec::<T>::decode(input)?;
        Ok(vec.into_boxed_slice())
    }
}

// String
impl Encode for String {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        self.len().encode(out);
        out.write(self.as_bytes());
    }
}

impl Decode for String {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let bytes = Vec::<u8>::decode(input)?;
        String::from_utf8(bytes).map_err(|_| DecodeError::InvalidValue)
    }
}

// &str (encode only)
impl Encode for &str {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        let bytes = self.as_bytes();
        bytes.len().encode(out);
        out.write(bytes);
    }
}

// Option<T>
impl<T: Encode> Encode for Option<T> {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        match self {
            None => 0u8.encode(out),
            Some(v) => {
                1u8.encode(out);
                v.encode(out);
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let tag = u8::decode(input)?;
        match tag {
            0 => Ok(None),
            1 => Ok(Some(T::decode(input)?)),
            _ => Err(DecodeError::InvalidValue),
        }
    }
}

// Fixed-size arrays [T; N]
impl<T: Encode, const N: usize> Encode for [T; N] {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        for item in self {
            item.encode(out);
        }
    }
}

impl<T: Decode, const N: usize> Decode for [T; N] {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let mut vec = Vec::with_capacity(N);
        for _ in 0..N {
            vec.push(T::decode(input)?);
        }
        vec.try_into().map_err(|_| DecodeError::InvalidValue)
    }
}

// Tuples
impl<A: Encode, B: Encode> Encode for (A, B) {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        self.0.encode(out);
        self.1.encode(out);
    }
}

impl<A: Decode, B: Decode> Decode for (A, B) {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok((A::decode(input)?, B::decode(input)?))
    }
}

impl<A: Encode, B: Encode, C: Encode> Encode for (A, B, C) {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        self.0.encode(out);
        self.1.encode(out);
        self.2.encode(out);
    }
}

impl<A: Decode, B: Decode, C: Decode> Decode for (A, B, C) {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok((A::decode(input)?, B::decode(input)?, C::decode(input)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== SizeCounter Tests ==========

    #[test]
    fn size_counter_accumulates() {
        let mut counter = SizeCounter::new();
        assert_eq!(counter.len(), 0);

        counter.write(&[1, 2, 3]);
        assert_eq!(counter.len(), 3);

        counter.write(&[4, 5]);
        assert_eq!(counter.len(), 5);
    }

    #[test]
    fn to_bytes_preallocates_exact_capacity() {
        let data: Vec<u8> = vec![1, 2, 3, 4, 5];
        let bytes = data.to_bytes();
        // Vec encodes as: 8-byte length + elements
        assert_eq!(bytes.len(), 8 + 5);
        assert_eq!(bytes.capacity(), bytes.len());
    }

    // ========== Integer Tests ==========

    #[test]
    fn u8_roundtrip() {
        for val in [0u8, 1, 127, 255] {
            let bytes = val.to_bytes();
            assert_eq!(bytes.len(), 1);
            assert_eq!(u8::from_bytes(&bytes).unwrap(), val);
        }
    }

    #[test]
    fn i8_roundtrip() {
        for val in [i8::MIN, -1, 0, 1, i8::MAX] {
            let bytes = val.to_bytes();
            assert_eq!(bytes.len(), 1);
            assert_eq!(i8::from_bytes(&bytes).unwrap(), val);
        }
    }

    #[test]
    fn u32_little_endian() {
        let val: u32 = 0x12345678;
        let bytes = val.to_bytes();
        assert_eq!(bytes.as_ref(), &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(u32::from_bytes(&bytes).unwrap(), val);
    }

    #[test]
    fn u64_roundtrip() {
        for val in [0u64, 1, u64::MAX / 2, u64::MAX] {
            let bytes = val.to_bytes();
            assert_eq!(bytes.len(), 8);
            assert_eq!(u64::from_bytes(&bytes).unwrap(), val);
        }
    }

    #[test]
    fn i64_negative_values() {
        let val: i64 = -1;
        let bytes = val.to_bytes();
        // -1 in two's complement is all 0xFF bytes
        assert_eq!(bytes.as_ref(), &[0xFF; 8]);
        assert_eq!(i64::from_bytes(&bytes).unwrap(), val);
    }

    #[test]
    fn u128_roundtrip() {
        let val: u128 = 0x0123456789ABCDEF_FEDCBA9876543210;
        let bytes = val.to_bytes();
        assert_eq!(bytes.len(), 16);
        assert_eq!(u128::from_bytes(&bytes).unwrap(), val);
    }

    // ========== usize Tests ==========

    #[test]
    fn usize_encoded_as_u64() {
        let val: usize = 42;
        let bytes = val.to_bytes();
        assert_eq!(bytes.len(), 8); // Always 8 bytes (u64)
        assert_eq!(usize::from_bytes(&bytes).unwrap(), val);
    }

    // ========== bool Tests ==========

    #[test]
    fn bool_encoding() {
        assert_eq!(false.to_bytes().as_ref(), &[0u8]);
        assert_eq!(true.to_bytes().as_ref(), &[1u8]);
    }

    #[test]
    fn bool_roundtrip() {
        assert!(!bool::from_bytes(&[0]).unwrap());
        assert!(bool::from_bytes(&[1]).unwrap());
    }

    #[test]
    fn bool_invalid_value() {
        for invalid in [2u8, 128, 255] {
            let result = bool::from_bytes(&[invalid]);
            assert!(matches!(result, Err(DecodeError::InvalidValue)));
        }
    }

    // ========== Vec<T> Tests ==========

    #[test]
    fn vec_encoding_format() {
        let vec: Vec<u8> = vec![0xAA, 0xBB, 0xCC];
        let bytes = vec.to_bytes();

        // 8-byte length prefix (little-endian) + elements
        assert_eq!(&bytes[0..8], &3u64.to_le_bytes());
        assert_eq!(&bytes[8..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn vec_roundtrip() {
        let original: Vec<u32> = vec![1, 2, 3, 4, 5];
        let bytes = original.to_bytes();
        let decoded = Vec::<u32>::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn vec_empty() {
        let empty: Vec<u8> = vec![];
        let bytes = empty.to_bytes();
        assert_eq!(bytes.len(), 8); // Just the length prefix
        assert_eq!(Vec::<u8>::from_bytes(&bytes).unwrap(), empty);
    }

    #[test]
    fn vec_length_overflow() {
        // Encode a length greater than MAX_VEC_LEN
        let huge_len: u64 = (MAX_VEC_LEN as u64) + 1;
        let bytes = huge_len.to_bytes();
        let result = Vec::<u8>::from_bytes(&bytes);
        assert!(matches!(result, Err(DecodeError::LengthOverflow)));
    }

    // ========== Box<[T]> Tests ==========

    #[test]
    fn boxed_slice_roundtrip() {
        let original: Box<[u16]> = vec![100, 200, 300].into_boxed_slice();
        let bytes = original.to_bytes();
        let decoded = Box::<[u16]>::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    // ========== String Tests ==========

    #[test]
    fn string_roundtrip() {
        let original = "hello world".to_string();
        let bytes = original.to_bytes();
        let decoded = String::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn string_unicode() {
        let original = "Hello, \u{4e16}\u{754c}!".to_string(); // "Hello, 世界!"
        let bytes = original.to_bytes();
        let decoded = String::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn string_invalid_utf8() {
        // Manually construct bytes with invalid UTF-8
        let mut bytes = Vec::new();
        3u64.encode(&mut bytes); // length = 3
        bytes.extend_from_slice(&[0xFF, 0xFE, 0x00]); // invalid UTF-8 sequence

        let result = String::from_bytes(&bytes);
        assert!(matches!(result, Err(DecodeError::InvalidValue)));
    }

    // ========== &str Tests ==========

    #[test]
    fn str_encodes_same_as_string() {
        let s = "test string";
        let str_bytes = s.to_bytes();
        let string_bytes = s.to_string().to_bytes();
        assert_eq!(str_bytes.as_ref(), string_bytes.as_ref());
    }

    // ========== Option<T> Tests ==========

    #[test]
    fn option_none_encoding() {
        let none: Option<u32> = None;
        assert_eq!(none.to_bytes().as_ref(), &[0u8]);
    }

    #[test]
    fn option_some_encoding() {
        let some: Option<u32> = Some(0x12345678);
        let bytes = some.to_bytes();
        assert_eq!(bytes[0], 1); // Some tag
        assert_eq!(&bytes[1..5], &0x12345678u32.to_le_bytes());
    }

    #[test]
    fn option_roundtrip() {
        let none: Option<u64> = None;
        assert_eq!(Option::<u64>::from_bytes(&none.to_bytes()).unwrap(), none);

        let some: Option<u64> = Some(42);
        assert_eq!(Option::<u64>::from_bytes(&some.to_bytes()).unwrap(), some);
    }

    #[test]
    fn option_invalid_tag() {
        let invalid = &[2u8, 0, 0, 0, 0]; // tag 2 is invalid
        let result = Option::<u32>::from_bytes(invalid);
        assert!(matches!(result, Err(DecodeError::InvalidValue)));
    }

    // ========== Fixed-Size Array Tests ==========

    #[test]
    fn array_no_length_prefix() {
        let arr: [u8; 4] = [1, 2, 3, 4];
        let bytes = arr.to_bytes();
        // No length prefix, just raw elements
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes.as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn array_roundtrip() {
        let original: [u32; 3] = [0xAABBCCDD, 0x11223344, 0x55667788];
        let bytes = original.to_bytes();
        let decoded = <[u32; 3]>::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn array_empty() {
        let empty: [u8; 0] = [];
        let bytes = empty.to_bytes();
        assert!(bytes.is_empty());
        assert_eq!(<[u8; 0]>::from_bytes(&bytes).unwrap(), empty);
    }

    // ========== Tuple Tests ==========

    #[test]
    fn tuple2_roundtrip() {
        let original: (u8, u32) = (0xAB, 0x12345678);
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 1 + 4);
        let decoded = <(u8, u32)>::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn tuple3_roundtrip() {
        let original: (bool, u16, String) = (true, 1000, "test".to_string());
        let bytes = original.to_bytes();
        let decoded = <(bool, u16, String)>::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    // ========== Error Handling Tests ==========

    #[test]
    fn unexpected_eof_empty_input() {
        let result = u32::from_bytes(&[]);
        assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
    }

    #[test]
    fn unexpected_eof_partial_input() {
        // u32 needs 4 bytes, only provide 2
        let result = u32::from_bytes(&[0x12, 0x34]);
        assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
    }

    #[test]
    fn trailing_bytes_error() {
        // Encode a u8 but add extra bytes
        let bytes = &[42u8, 0xFF, 0xFF];
        let result = u8::from_bytes(bytes);
        assert!(matches!(result, Err(DecodeError::InvalidValue)));
    }

    #[test]
    fn decode_advances_input() {
        let mut input: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05];

        let first = u8::decode(&mut input).unwrap();
        assert_eq!(first, 0x01);
        assert_eq!(input.len(), 4);

        let second = u16::decode(&mut input).unwrap();
        assert_eq!(second, 0x0302); // little-endian
        assert_eq!(input.len(), 2);
    }

    // ========== Nested Types Tests ==========

    #[test]
    fn nested_vec_option() {
        let original: Vec<Option<u32>> = vec![Some(1), None, Some(3)];
        let bytes = original.to_bytes();
        let decoded = Vec::<Option<u32>>::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn option_vec() {
        let original: Option<Vec<u8>> = Some(vec![1, 2, 3]);
        let bytes = original.to_bytes();
        let decoded = Option::<Vec<u8>>::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }
}

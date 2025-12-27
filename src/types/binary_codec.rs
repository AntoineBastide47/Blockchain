//! Binary serialization trait with hashing support.
//!
//! Use `#[derive(BinaryCodec)]` to automatically implement `Encode` and `Decode`.

use crate::types::encoding::EncodeSink;
pub use crate::types::encoding::{Decode, Encode};
use crate::types::hash::Hash;
pub use blockchain_derive::BinaryCodec;
use sha3::{Digest, Sha3_256};

impl EncodeSink for Sha3_256 {
    fn write(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

/// Trait for types that can be serialized to/from binary format and hashed.
///
/// Automatically implemented for all types that implement `Encode + Decode`.
pub trait BinaryCodecHash: Encode + Decode {
    /// Computes SHA3-256 hash of the encoded representation.
    fn hash(&self) -> Hash {
        let mut hasher = Sha3_256::new();
        self.encode(&mut hasher);
        Hash(hasher.finalize().into())
    }
}

impl<T: Encode + Decode> BinaryCodecHash for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::encoding::DecodeError;

    // ========== Named Struct Tests ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    struct NamedStruct {
        a: u32,
        b: u64,
        c: bool,
    }

    #[test]
    fn named_struct_roundtrip() {
        let original = NamedStruct {
            a: 42,
            b: 0xDEADBEEF,
            c: true,
        };
        let bytes = original.to_bytes();
        let decoded = NamedStruct::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn named_struct_encoding_order() {
        let s = NamedStruct {
            a: 1,
            b: 2,
            c: false,
        };
        let bytes = s.to_bytes();
        // a: u32 (4 bytes) + b: u64 (8 bytes) + c: bool (1 byte) = 13 bytes
        assert_eq!(bytes.len(), 13);
        // Verify field order: a comes first
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
        assert_eq!(&bytes[4..12], &2u64.to_le_bytes());
        assert_eq!(bytes[12], 0);
    }

    // ========== Tuple Struct Tests ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    struct TupleStruct(u16, u8);

    #[test]
    fn tuple_struct_roundtrip() {
        let original = TupleStruct(0xABCD, 0xFF);
        let bytes = original.to_bytes();
        let decoded = TupleStruct::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn tuple_struct_encoding_order() {
        let s = TupleStruct(0x1234, 0x56);
        let bytes = s.to_bytes();
        assert_eq!(bytes.len(), 3);
        assert_eq!(&bytes[0..2], &0x1234u16.to_le_bytes());
        assert_eq!(bytes[2], 0x56);
    }

    // ========== Unit Struct Tests ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    struct UnitStruct;

    #[test]
    fn unit_struct_roundtrip() {
        let original = UnitStruct;
        let bytes = original.to_bytes();
        assert!(bytes.is_empty());
        let decoded = UnitStruct::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    // ========== Enum Tests: Default Discriminants ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    enum DefaultDiscriminant {
        Zero,
        One,
        Two,
    }

    #[test]
    fn enum_default_discriminants() {
        // Variants should encode as 0, 1, 2
        assert_eq!(DefaultDiscriminant::Zero.to_bytes().as_ref(), &[0u8]);
        assert_eq!(DefaultDiscriminant::One.to_bytes().as_ref(), &[1u8]);
        assert_eq!(DefaultDiscriminant::Two.to_bytes().as_ref(), &[2u8]);
    }

    #[test]
    fn enum_default_discriminant_roundtrip() {
        for variant in [
            DefaultDiscriminant::Zero,
            DefaultDiscriminant::One,
            DefaultDiscriminant::Two,
        ] {
            let bytes = variant.to_bytes();
            let decoded = DefaultDiscriminant::from_bytes(&bytes).unwrap();
            assert_eq!(variant, decoded);
        }
    }

    // ========== Enum Tests: Explicit Discriminants ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    #[repr(u8)]
    enum ExplicitDiscriminant {
        First = 10,
        Second = 20,
        Third = 30,
    }

    #[test]
    fn enum_explicit_discriminants() {
        assert_eq!(ExplicitDiscriminant::First.to_bytes().as_ref(), &[10u8]);
        assert_eq!(ExplicitDiscriminant::Second.to_bytes().as_ref(), &[20u8]);
        assert_eq!(ExplicitDiscriminant::Third.to_bytes().as_ref(), &[30u8]);
    }

    #[test]
    fn enum_explicit_discriminant_roundtrip() {
        for variant in [
            ExplicitDiscriminant::First,
            ExplicitDiscriminant::Second,
            ExplicitDiscriminant::Third,
        ] {
            let bytes = variant.to_bytes();
            let decoded = ExplicitDiscriminant::from_bytes(&bytes).unwrap();
            assert_eq!(variant, decoded);
        }
    }

    // ========== Enum Tests: Mixed Discriminants ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    #[repr(u8)]
    enum MixedDiscriminant {
        A,       // 0 (default)
        B = 5,   // 5 (explicit)
        C,       // 6 (auto-increment from B)
        D = 100, // 100 (explicit)
        E,       // 101 (auto-increment from D)
    }

    #[test]
    fn enum_mixed_discriminants() {
        assert_eq!(MixedDiscriminant::A.to_bytes().as_ref(), &[0u8]);
        assert_eq!(MixedDiscriminant::B.to_bytes().as_ref(), &[5u8]);
        assert_eq!(MixedDiscriminant::C.to_bytes().as_ref(), &[6u8]);
        assert_eq!(MixedDiscriminant::D.to_bytes().as_ref(), &[100u8]);
        assert_eq!(MixedDiscriminant::E.to_bytes().as_ref(), &[101u8]);
    }

    #[test]
    fn enum_mixed_discriminant_roundtrip() {
        for variant in [
            MixedDiscriminant::A,
            MixedDiscriminant::B,
            MixedDiscriminant::C,
            MixedDiscriminant::D,
            MixedDiscriminant::E,
        ] {
            let bytes = variant.to_bytes();
            let decoded = MixedDiscriminant::from_bytes(&bytes).unwrap();
            assert_eq!(variant, decoded);
        }
    }

    // ========== Enum Tests: Tuple Variants ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    enum TupleVariants {
        Empty,
        Single(u32),
        Double(u8, u16),
    }

    #[test]
    fn enum_tuple_variants_roundtrip() {
        let variants = [
            TupleVariants::Empty,
            TupleVariants::Single(0xDEADBEEF),
            TupleVariants::Double(0xAB, 0xCDEF),
        ];
        for variant in variants {
            let bytes = variant.to_bytes();
            let decoded = TupleVariants::from_bytes(&bytes).unwrap();
            assert_eq!(variant, decoded);
        }
    }

    #[test]
    fn enum_tuple_variants_encoding() {
        // Empty: just discriminant
        assert_eq!(TupleVariants::Empty.to_bytes().as_ref(), &[0u8]);

        // Single: discriminant + u32
        let single = TupleVariants::Single(0x12345678);
        let bytes = single.to_bytes();
        assert_eq!(bytes[0], 1); // discriminant
        assert_eq!(&bytes[1..5], &0x12345678u32.to_le_bytes());

        // Double: discriminant + u8 + u16
        let double = TupleVariants::Double(0xAA, 0xBBCC);
        let bytes = double.to_bytes();
        assert_eq!(bytes[0], 2); // discriminant
        assert_eq!(bytes[1], 0xAA);
        assert_eq!(&bytes[2..4], &0xBBCCu16.to_le_bytes());
    }

    // ========== Enum Tests: Struct Variants ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    enum StructVariants {
        Unit,
        Named { x: u32, y: u32 },
        Complex { flag: bool, data: Vec<u8> },
    }

    #[test]
    fn enum_struct_variants_roundtrip() {
        let variants = [
            StructVariants::Unit,
            StructVariants::Named { x: 100, y: 200 },
            StructVariants::Complex {
                flag: true,
                data: vec![1, 2, 3, 4],
            },
        ];
        for variant in variants {
            let bytes = variant.to_bytes();
            let decoded = StructVariants::from_bytes(&bytes).unwrap();
            assert_eq!(variant, decoded);
        }
    }

    // ========== Enum Tests: Explicit Discriminants with Data ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    #[repr(u8)]
    enum ExplicitWithData {
        Foo(u32) = 50,
        Bar { val: u16 } = 75,
        Baz = 99,
    }

    #[test]
    fn enum_explicit_with_data_encoding() {
        let foo = ExplicitWithData::Foo(42);
        let bytes = foo.to_bytes();
        assert_eq!(bytes[0], 50); // explicit discriminant
        assert_eq!(&bytes[1..5], &42u32.to_le_bytes());

        let bar = ExplicitWithData::Bar { val: 1000 };
        let bytes = bar.to_bytes();
        assert_eq!(bytes[0], 75);
        assert_eq!(&bytes[1..3], &1000u16.to_le_bytes());

        let baz = ExplicitWithData::Baz;
        assert_eq!(baz.to_bytes().as_ref(), &[99u8]);
    }

    #[test]
    fn enum_explicit_with_data_roundtrip() {
        for variant in [
            ExplicitWithData::Foo(123456),
            ExplicitWithData::Bar { val: 65535 },
            ExplicitWithData::Baz,
        ] {
            let bytes = variant.to_bytes();
            let decoded = ExplicitWithData::from_bytes(&bytes).unwrap();
            assert_eq!(variant, decoded);
        }
    }

    // ========== Error Handling Tests ==========

    #[test]
    fn enum_invalid_discriminant_errors() {
        // Discriminant 3 doesn't exist in DefaultDiscriminant (0, 1, 2)
        let invalid = &[3u8];
        let result = DefaultDiscriminant::from_bytes(invalid);
        assert!(matches!(result, Err(DecodeError::InvalidValue)));
    }

    #[test]
    fn enum_explicit_gaps_invalid() {
        // ExplicitDiscriminant uses 10, 20, 30 - so 15 is invalid
        let invalid = &[15u8];
        let result = ExplicitDiscriminant::from_bytes(invalid);
        assert!(matches!(result, Err(DecodeError::InvalidValue)));
    }

    // ========== Nested Types Tests ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    struct Outer {
        inner: NamedStruct,
        count: u8,
    }

    #[test]
    fn nested_struct_roundtrip() {
        let original = Outer {
            inner: NamedStruct {
                a: 1,
                b: 2,
                c: true,
            },
            count: 42,
        };
        let bytes = original.to_bytes();
        let decoded = Outer::from_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    // ========== Complex Nested Enum Test ==========

    #[derive(Debug, PartialEq, BinaryCodec)]
    #[repr(u8)]
    enum Message {
        Ping = 1,
        Pong = 2,
        Data { payload: Vec<u8> } = 10,
        Error(String) = 255,
    }

    #[test]
    fn complex_enum_roundtrip() {
        let messages = [
            Message::Ping,
            Message::Pong,
            Message::Data {
                payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            },
            Message::Error("something went wrong".to_string()),
        ];
        for msg in messages {
            let bytes = msg.to_bytes();
            let decoded = Message::from_bytes(&bytes).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn complex_enum_discriminants() {
        assert_eq!(Message::Ping.to_bytes()[0], 1);
        assert_eq!(Message::Pong.to_bytes()[0], 2);
        assert_eq!(Message::Data { payload: vec![] }.to_bytes()[0], 10);
        assert_eq!(Message::Error(String::new()).to_bytes()[0], 255);
    }
}

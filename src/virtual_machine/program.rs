//! Bytecode program representation and serialization.
//!
//! A [`Program`] bundles compiled bytecode with its associated string pool,
//! enabling portable serialization with version checking.

use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, DecodeError, Encode};
use blockchain_derive::BinaryCodec;

/// Magic bytes identifying a serialized VM program.
const MAGIC: &[u8; 5] = b"VM_BC";

/// Current bytecode format version.
const CURRENT_VERSION: Version = Version::new(0, 2, 0);

/// Semantic version for bytecode format compatibility.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, BinaryCodec)]
struct Version {
    major: u8,
    minor: u8,
    patch: u8,
}

impl Version {
    /// Creates a new version with the given components.
    const fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// Compiled bytecode program with its string pool.
///
/// Contains all data needed to execute a program: the raw bytecode
/// and any string literals referenced by `LOAD_STR` instructions.
#[derive(Debug, Clone, BinaryCodec)]
pub struct Program {
    /// Interned string literals referenced by index.
    pub strings: Vec<String>,
    /// Compiled instruction bytecode.
    pub bytecode: Vec<u8>,
}

impl Program {
    /// Creates a new program from pre-assembled components.
    pub(crate) fn new(strings: Vec<String>, bytecode: Vec<u8>) -> Program {
        Self { strings, bytecode }
    }
}

impl Program {
    /// Serializes the program to a portable binary format.
    ///
    /// The output includes a magic header and version for compatibility checking.
    pub fn to_bytes(&self) -> Bytes {
        let mut out = Vec::new();
        MAGIC.encode(&mut out);
        CURRENT_VERSION.encode(&mut out);
        self.encode(&mut out);
        Bytes::from_vec(out)
    }

    /// Deserializes a program from its binary representation.
    ///
    /// Validates the magic header and version, rejecting programs from
    /// newer (incompatible) bytecode formats.
    pub fn from_bytes(mut input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() < MAGIC.len() {
            return Err(DecodeError::InvalidValueWithMessage(
                "truncated".to_string(),
            ));
        }

        if &<[u8; 5]>::decode(&mut input)? != MAGIC {
            return Err(DecodeError::InvalidValueWithMessage(
                "bad magic".to_string(),
            ));
        }

        if Version::decode(&mut input)? > CURRENT_VERSION {
            return Err(DecodeError::InvalidValueWithMessage(
                "unsupported version".to_string(),
            ));
        }

        let p = Program::decode(&mut input)?;
        if !input.is_empty() {
            return Err(DecodeError::InvalidValueWithMessage(
                "trailing bytes".to_string(),
            ));
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty_program() {
        let program = Program::new(vec![], vec![]);
        let bytes = program.to_bytes();
        let decoded = Program::from_bytes(&bytes).unwrap();
        assert!(decoded.strings.is_empty());
        assert!(decoded.bytecode.is_empty());
    }

    #[test]
    fn roundtrip_with_bytecode() {
        let program = Program::new(vec![], vec![0x00, 0x01, 0x02]);
        let bytes = program.to_bytes();
        let decoded = Program::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.bytecode, vec![0x00, 0x01, 0x02]);
    }

    #[test]
    fn roundtrip_with_strings() {
        let program = Program::new(vec!["hello".into(), "world".into()], vec![0x01, 0x00]);
        let bytes = program.to_bytes();
        let decoded = Program::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.strings, vec!["hello", "world"]);
        assert_eq!(decoded.bytecode, vec![0x01, 0x00]);
    }

    #[test]
    fn from_bytes_truncated() {
        let err = Program::from_bytes(&[0x00, 0x01]).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidValueWithMessage(msg) if msg == "truncated"));
    }

    #[test]
    fn from_bytes_bad_magic() {
        let err = Program::from_bytes(b"BADMA\x00\x02\x00").unwrap_err();
        assert!(matches!(err, DecodeError::InvalidValueWithMessage(msg) if msg == "bad magic"));
    }

    #[test]
    fn from_bytes_unsupported_version() {
        let mut bytes = Vec::new();
        MAGIC.encode(&mut bytes);
        Version::new(255, 0, 0).encode(&mut bytes);
        let err = Program::from_bytes(&bytes).unwrap_err();
        assert!(
            matches!(err, DecodeError::InvalidValueWithMessage(msg) if msg == "unsupported version")
        );
    }

    #[test]
    fn from_bytes_trailing_bytes() {
        let program = Program::new(vec![], vec![]);
        let mut bytes = program.to_bytes().to_vec();
        bytes.push(0xFF);
        let err = Program::from_bytes(&bytes).unwrap_err();
        assert!(
            matches!(err, DecodeError::InvalidValueWithMessage(msg) if msg == "trailing bytes")
        );
    }
}

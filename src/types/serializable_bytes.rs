//! Borsh-compatible wrapper for `Bytes`.

use borsh::{BorshDeserialize, BorshSerialize};
use bytes::Bytes;
use std::io::{Read, Result, Write};
use std::ops::Deref;

/// Wrapper around `Bytes` that implements Borsh serialization.
///
/// `Bytes` provides zero-copy reference counting for immutable byte data,
/// but lacks Borsh support. This wrapper enables use in derived structs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializableBytes(pub Bytes);

impl SerializableBytes {
    pub fn new(data: impl Into<Bytes>) -> Self {
        SerializableBytes(data.into())
    }
}

impl Deref for SerializableBytes {
    type Target = Bytes;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for SerializableBytes {
    fn from(v: Vec<u8>) -> Self {
        SerializableBytes(Bytes::from(v))
    }
}

impl From<&Vec<u8>> for SerializableBytes {
    fn from(v: &Vec<u8>) -> Self {
        SerializableBytes(Bytes::copy_from_slice(v.as_slice()))
    }
}

impl From<&[u8]> for SerializableBytes {
    fn from(s: &[u8]) -> Self {
        SerializableBytes(Bytes::copy_from_slice(s))
    }
}

impl<const N: usize> From<&[u8; N]> for SerializableBytes {
    fn from(a: &[u8; N]) -> Self {
        SerializableBytes(Bytes::copy_from_slice(a))
    }
}

impl BorshSerialize for SerializableBytes {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<()> {
        let data: &[u8] = &self.0;
        data.serialize(writer)
    }
}

impl BorshDeserialize for SerializableBytes {
    fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let data = Vec::<u8>::deserialize_reader(reader)?;
        Ok(SerializableBytes(Bytes::from(data)))
    }
}

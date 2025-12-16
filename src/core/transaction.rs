//! Transaction structure with reference-counted data storage.

use borsh::{BorshDeserialize, BorshSerialize};
use bytes::Bytes;
use std::io::{Read, Write};

/// A blockchain transaction containing arbitrary data.
///
/// Uses `Bytes` for zero-copy sharing - transactions are immutable after creation
/// and often referenced by multiple blocks during reorganizations. `Bytes` uses
/// reference counting to avoid deep copies.
///
/// # Binary Format
/// ```text
/// [data_len: u32][data: [u8]]
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct Transaction {
    data: Bytes,
}

impl BorshSerialize for Transaction {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let data: &[u8] = &self.data;
        data.serialize(writer)
    }
}

impl BorshDeserialize for Transaction {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let data = Vec::<u8>::deserialize_reader(reader)?;
        Ok(Transaction {
            data: Bytes::from(data),
        })
    }
}

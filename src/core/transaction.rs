//! Transaction structure with reference-counted data storage.

use crate::types::binary_codec::BinaryCodec;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
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

impl BinaryCodec for Transaction {
    fn encode<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_u32::<LittleEndian>(self.data.len() as u32)?;
        w.write_all(&self.data)?;
        Ok(())
    }

    fn decode<R: Read>(&mut self, mut r: R) -> std::io::Result<()> {
        let len = r.read_u32::<LittleEndian>()? as usize;
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        self.data = Bytes::from(buf);
        Ok(())
    }
}

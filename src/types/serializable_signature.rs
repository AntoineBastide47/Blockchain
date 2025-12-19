use borsh::{BorshDeserialize, BorshSerialize};
use k256::schnorr::Signature;
use std::io::{Read, Write};

/// Wrapper around `Signature` that implements Borsh serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerializableSignature(pub Signature);

impl SerializableSignature {
    pub fn new(sig: Signature) -> Self {
        SerializableSignature(sig)
    }
}

impl From<Signature> for SerializableSignature {
    fn from(sig: Signature) -> Self {
        SerializableSignature(sig)
    }
}

impl BorshSerialize for SerializableSignature {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes: [u8; 64] = self.0.to_bytes();
        bytes.serialize(writer)
    }
}

impl BorshDeserialize for SerializableSignature {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes = <[u8; 64]>::deserialize_reader(reader)?;
        let sig = Signature::try_from(bytes.as_slice())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(SerializableSignature(sig))
    }
}

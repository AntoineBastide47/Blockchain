use crate::types::encoding::{Decode, DecodeError, Encode, EncodeSink};
use k256::schnorr::Signature;

/// Wrapper around `Signature` that implements serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerializableSignature(pub Signature);

impl From<Signature> for SerializableSignature {
    fn from(sig: Signature) -> Self {
        SerializableSignature(sig)
    }
}

impl Encode for SerializableSignature {
    fn encode<S: EncodeSink>(&self, out: &mut S) {
        out.write(&self.0.to_bytes());
    }
}

impl Decode for SerializableSignature {
    fn decode(input: &mut &[u8]) -> Result<Self, DecodeError> {
        let bytes = <[u8; 64]>::decode(input)?;
        let sig = Signature::try_from(bytes.as_slice()).map_err(|_| DecodeError::InvalidValue)?;
        Ok(SerializableSignature(sig))
    }
}

//! Finalizer public key identifiers and vote signatures.

use core::fmt;

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use ed25519_zebra::{Signature, VerificationKey};
use snafu::Snafu;

use crate::hash::Blake3Hash;

/// The size of a finalizer public key identifier in bytes.
pub const PUB_KEY_ID_BYTES: usize = 32;

/// The size of a vote signature in bytes.
pub const VOTE_SIGNATURE_BYTES: usize = 64;

/// A signature failed to verify.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SignatureError {
    /// The public key bytes do not encode a valid Ed25519 verification key.
    #[snafu(display("invalid public key: {error}"))]
    InvalidPublicKey {
        /// The underlying Ed25519 error.
        error: ed25519_zebra::Error,
    },
    /// The signature is not valid for the given key and message.
    #[snafu(display("invalid signature: {error}"))]
    InvalidSignature {
        /// The underlying Ed25519 error.
        error: ed25519_zebra::Error,
    },
    /// A batch of signatures failed to verify as a whole.
    #[snafu(display("batch signature verification failed"))]
    BatchVerificationFailed,
}

/// The identifier of a finalizer: its Ed25519 verification key bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKeyId(pub(crate) [u8; PUB_KEY_ID_BYTES]);

impl PubKeyId {
    /// Constructs an identifier from its byte representation.
    pub fn from_bytes(bytes: [u8; PUB_KEY_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the byte representation of this identifier.
    pub fn as_bytes(&self) -> &[u8; PUB_KEY_ID_BYTES] {
        &self.0
    }

    /// Reads an identifier as 32 raw bytes.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; PUB_KEY_ID_BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Writes this identifier as 32 raw bytes.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl fmt::Display for PubKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.iter().rev() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PubKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pub{{{:02x}{:02x}}}", self.0[1], self.0[0])
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PubKeyId {
    /// Serializes as a 64-character hex string of the byte-reversed key.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut le_bytes = self.0;
        le_bytes.reverse();
        serializer.serialize_str(&hex::encode(le_bytes))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PubKeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let le_str: alloc::borrow::Cow<'de, str> = serde::Deserialize::deserialize(deserializer)?;
        let le_str: &str = le_str.as_ref();
        if le_str.len() != 2 * PUB_KEY_ID_BYTES {
            return Err(serde::de::Error::invalid_length(
                le_str.len(),
                &"32 bytes => 64 hex characters",
            ));
        }

        let mut bytes = [0u8; PUB_KEY_ID_BYTES];
        hex::decode_to_slice(le_str, &mut bytes).map_err(serde::de::Error::custom)?;
        bytes.reverse();

        Ok(PubKeyId(bytes))
    }
}

/// An Ed25519 signature over a vote.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VoteSignature(pub(crate) [u8; VOTE_SIGNATURE_BYTES]);

impl VoteSignature {
    /// Constructs a signature from its byte representation.
    pub fn from_bytes(bytes: [u8; VOTE_SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the byte representation of this signature.
    pub fn as_bytes(&self) -> &[u8; VOTE_SIGNATURE_BYTES] {
        &self.0
    }

    /// Reads a signature as 64 raw bytes.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; VOTE_SIGNATURE_BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Writes this signature as 64 raw bytes.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }

    /// Verifies this signature over `signed_data` with the key identified by `pub_key`.
    pub fn verify(&self, pub_key: &PubKeyId, signed_data: &[u8]) -> Result<(), SignatureError> {
        let signature = Signature::from_bytes(&self.0);
        let vk = VerificationKey::try_from(pub_key.0)
            .map_err(|error| SignatureError::InvalidPublicKey { error })?;
        vk.verify(&signature, signed_data)
            .map_err(|error| SignatureError::InvalidSignature { error })
    }

    /// Like [`VoteSignature::verify`], with a vote namespace appended to the signed
    /// data. `None` appends nothing.
    pub fn verify_with_namespace(
        &self,
        pub_key: &PubKeyId,
        signed_data: &[u8],
        namespace: Option<&Blake3Hash>,
    ) -> Result<(), SignatureError> {
        match namespace {
            None => self.verify(pub_key, signed_data),
            Some(namespace) => {
                let mut buf = Vec::with_capacity(signed_data.len() + namespace.as_bytes().len());
                buf.extend_from_slice(signed_data);
                buf.extend_from_slice(namespace.as_bytes());
                self.verify(pub_key, &buf)
            }
        }
    }
}

impl fmt::Debug for VoteSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig{{{:02x}{:02x}}}", self.0[0], self.0[1])
    }
}

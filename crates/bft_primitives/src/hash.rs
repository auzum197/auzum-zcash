//! BLAKE3 hashing for BFT chain data.

use core::fmt;

use corez::io::{self, Read, Write};

/// The size of a BLAKE3 hash in bytes.
pub const BLAKE3_HASH_BYTES: usize = 32;

/// Domain string for deriving the BFT proposer selection hash key.
pub const PROPOSER_DOMAIN: &str = "BFT Proposer";

/// Domain string for deriving the BFT value identity hash key. [`crate::BftBlock::hash`]
/// uses this key.
pub const VALUE_ID_DOMAIN: &str = "BFT Value ID";

/// Domain string for deriving the BFT connect contention hash key.
pub const CONNECT_CONTENTION_DOMAIN: &str = "BFT Connect Contention";

/// Domain string for deriving the BFT proposal signature hash key.
pub const PROPOSAL_SIGNATURE_DOMAIN: &str = "BFT Proposal Signature";

/// Returns a keyed BLAKE3 hasher whose key is derived from `domain`.
pub(crate) fn keyed_hasher(domain: &str) -> blake3::Hasher {
    let key: [u8; BLAKE3_HASH_BYTES] = blake3::Hasher::new_derive_key(domain).finalize().into();
    blake3::Hasher::new_keyed(&key)
}

/// A BLAKE3 hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Blake3Hash(pub(crate) [u8; BLAKE3_HASH_BYTES]);

impl Blake3Hash {
    /// Constructs a hash from its byte representation.
    pub fn from_bytes(bytes: [u8; BLAKE3_HASH_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the byte representation of this hash.
    pub fn as_bytes(&self) -> &[u8; BLAKE3_HASH_BYTES] {
        &self.0
    }

    /// Returns whether every byte of this hash is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; BLAKE3_HASH_BYTES]
    }

    /// Reads a hash as 32 raw bytes.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; BLAKE3_HASH_BYTES];
        reader.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Writes this hash as 32 raw bytes.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.iter() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

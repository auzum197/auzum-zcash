//! Fat pointers: notarization proofs for BFT blocks.

use alloc::vec::Vec;

use corez::io::{self, Read, Write};
use rand_core::{CryptoRng, RngCore};

use crate::{
    encoding::{ReadBytesExt, WriteBytesExt},
    hash::Blake3Hash,
    height::BftHeight,
    keys::{PUB_KEY_ID_BYTES, PubKeyId, SignatureError, VOTE_SIGNATURE_BYTES, VoteSignature},
    vote::{Round, SignedVote, Vote, VoteKind, read_height_u64, read_round_word, write_round_word},
};

/// The size of the serialized vote-template prefix of a fat pointer in bytes.
pub const FAT_POINTER_PREFIX_BYTES: usize = 44;

/// The size of a serialized fat pointer signature entry in bytes.
pub const FAT_POINTER_SIGNATURE_BYTES: usize = PUB_KEY_ID_BYTES + VOTE_SIGNATURE_BYTES;

/// One finalizer's signature entry in a fat pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FatPointerSignature {
    pub(crate) pub_key: PubKeyId,
    pub(crate) signature: VoteSignature,
}

impl FatPointerSignature {
    /// Constructs a signature entry from its parts.
    pub fn from_parts(pub_key: PubKeyId, signature: VoteSignature) -> Self {
        Self { pub_key, signature }
    }

    /// Returns the finalizer key this entry belongs to.
    pub fn pub_key(&self) -> &PubKeyId {
        &self.pub_key
    }

    /// Returns the signature.
    pub fn signature(&self) -> &VoteSignature {
        &self.signature
    }

    /// Reads an entry as a 32-byte key followed by a 64-byte signature.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let pub_key = PubKeyId::read(&mut reader)?;
        let signature = VoteSignature::read(&mut reader)?;
        Ok(Self { pub_key, signature })
    }

    /// Writes this entry as a 32-byte key followed by a 64-byte signature.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.pub_key.write(&mut writer)?;
        self.signature.write(&mut writer)
    }
}

/// A bundle of precommit signatures proving a BFT block was notarized.
///
/// The serialized form is a 44-byte vote-template prefix (32-byte block hash, 8-byte
/// little-endian height, 4-byte round word), a 2-byte little-endian signature count,
/// and the signature entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FatPointerToBftBlock {
    pub(crate) block_hash: Blake3Hash,
    pub(crate) height: BftHeight,
    pub(crate) round: Round,
    pub(crate) kind: VoteKind,
    pub(crate) signatures: Vec<FatPointerSignature>,
}

impl FatPointerToBftBlock {
    /// Constructs a fat pointer over precommit votes for the given block hash.
    pub fn from_parts(
        block_hash: Blake3Hash,
        height: BftHeight,
        round: Round,
        signatures: Vec<FatPointerSignature>,
    ) -> Self {
        Self {
            block_hash,
            height,
            round,
            kind: VoteKind::Precommit,
            signatures,
        }
    }

    /// Returns the all-zero fat pointer that precedes the first BFT block.
    pub fn null() -> Self {
        Self {
            block_hash: Blake3Hash::from_bytes([0u8; 32]),
            height: BftHeight::ZERO,
            round: Round::ZERO,
            kind: VoteKind::Prevote,
            signatures: Vec::new(),
        }
    }

    /// Returns the hash of the block this fat pointer points at.
    pub fn block_hash(&self) -> &Blake3Hash {
        &self.block_hash
    }

    /// Returns the BFT height the votes apply to.
    pub fn height(&self) -> BftHeight {
        self.height
    }

    /// Returns the round the votes were cast in.
    pub fn round(&self) -> Round {
        self.round
    }

    /// Returns the kind carried by the serialized round word.
    pub fn vote_kind(&self) -> VoteKind {
        self.kind
    }

    /// Returns the signature entries.
    pub fn signatures(&self) -> &[FatPointerSignature] {
        &self.signatures
    }

    /// Expands each signature entry into the signed vote it attests to. A zero block
    /// hash expands to Nil votes.
    pub fn inflate(&self) -> Vec<SignedVote> {
        let value = if self.block_hash.is_zero() {
            None
        } else {
            Some(self.block_hash)
        };
        self.signatures
            .iter()
            .map(|entry| {
                SignedVote::from_parts(
                    Vote::new(entry.pub_key, value, self.height, self.kind, self.round),
                    entry.signature,
                )
            })
            .collect()
    }

    /// Batch-verifies every signature entry, with the vote namespace (if any)
    /// appended to each signed vote's bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::BatchVerificationFailed`] if any signature in the
    /// batch is invalid.
    pub fn verify_signatures<R: RngCore + CryptoRng>(
        &self,
        namespace: Option<&Blake3Hash>,
        rng: R,
    ) -> Result<(), SignatureError> {
        let mut batch = ed25519_zebra::batch::Verifier::new();
        for signed_vote in self.inflate() {
            let vk_bytes = ed25519_zebra::VerificationKeyBytes::from(
                *signed_vote.vote().validator().as_bytes(),
            );
            let sig = ed25519_zebra::Signature::from_bytes(signed_vote.signature().as_bytes());
            let msg = signed_vote.vote().to_bytes();
            match namespace {
                None => batch.queue((vk_bytes, sig, &msg[..])),
                Some(namespace) => {
                    let mut buf = Vec::with_capacity(msg.len() + namespace.as_bytes().len());
                    buf.extend_from_slice(&msg);
                    buf.extend_from_slice(namespace.as_bytes());
                    batch.queue((vk_bytes, sig, buf.as_slice()));
                }
            }
        }
        batch
            .verify(rng)
            .map_err(|_| SignatureError::BatchVerificationFailed)
    }

    /// Reads a fat pointer.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let block_hash = Blake3Hash::read(&mut reader)?;
        let height = read_height_u64(&mut reader)?;
        let (kind, round) = read_round_word(&mut reader)?;

        let count = (&mut reader).read_u16_le()?;
        let mut signatures = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            signatures.push(FatPointerSignature::read(&mut reader)?);
        }

        Ok(Self {
            block_hash,
            height,
            round,
            kind,
            signatures,
        })
    }

    /// Writes this fat pointer.
    ///
    /// # Errors
    ///
    /// Returns an error if there are more than `u16::MAX` signature entries.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.block_hash.write(&mut writer)?;
        (&mut writer).write_u64_le(u64::from(self.height))?;
        write_round_word(&mut writer, self.kind, self.round)?;

        let count = u16::try_from(self.signatures.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too many signatures"))?;
        (&mut writer).write_u16_le(count)?;
        for signature in &self.signatures {
            signature.write(&mut writer)?;
        }
        Ok(())
    }

    /// Serializes this fat pointer to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write(&mut buf)
            .expect("writing to a Vec is infallible below the signature-count limit");
        buf
    }
}

#[cfg(feature = "serde")]
mod serde_impls {
    use alloc::vec::Vec;

    use serde::{Deserialize, Serialize};
    use serde_big_array::BigArray;

    use super::{
        FAT_POINTER_PREFIX_BYTES, FatPointerSignature, FatPointerToBftBlock, PubKeyId,
        VOTE_SIGNATURE_BYTES, VoteSignature,
    };
    use crate::{
        hash::Blake3Hash,
        vote::{read_height_u64, read_round_word, round_word},
    };

    #[derive(Serialize, Deserialize)]
    struct FatPointerSignatureRepr {
        pub_key: PubKeyId,
        #[serde(with = "BigArray")]
        vote_signature: [u8; VOTE_SIGNATURE_BYTES],
    }

    #[derive(Serialize, Deserialize)]
    struct FatPointerToBftBlockRepr {
        #[serde(with = "BigArray")]
        vote_for_block_without_finalizer_public_key: [u8; FAT_POINTER_PREFIX_BYTES],
        signatures: Vec<FatPointerSignatureRepr>,
    }

    impl Serialize for FatPointerSignature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            FatPointerSignatureRepr {
                pub_key: self.pub_key,
                vote_signature: *self.signature.as_bytes(),
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for FatPointerSignature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let repr = FatPointerSignatureRepr::deserialize(deserializer)?;
            Ok(Self {
                pub_key: repr.pub_key,
                signature: VoteSignature::from_bytes(repr.vote_signature),
            })
        }
    }

    impl Serialize for FatPointerToBftBlock {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut prefix = [0u8; FAT_POINTER_PREFIX_BYTES];
            prefix[0..32].copy_from_slice(self.block_hash.as_bytes());
            prefix[32..40].copy_from_slice(&u64::from(self.height).to_le_bytes());
            prefix[40..44].copy_from_slice(&round_word(self.kind, self.round).to_le_bytes());
            FatPointerToBftBlockRepr {
                vote_for_block_without_finalizer_public_key: prefix,
                signatures: self
                    .signatures
                    .iter()
                    .map(|entry| FatPointerSignatureRepr {
                        pub_key: entry.pub_key,
                        vote_signature: *entry.signature.as_bytes(),
                    })
                    .collect(),
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for FatPointerToBftBlock {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let repr = FatPointerToBftBlockRepr::deserialize(deserializer)?;
            let mut cursor = &repr.vote_for_block_without_finalizer_public_key[..];
            let block_hash = Blake3Hash::read(&mut cursor).map_err(serde::de::Error::custom)?;
            let height = read_height_u64(&mut cursor).map_err(serde::de::Error::custom)?;
            let (kind, round) = read_round_word(&mut cursor).map_err(serde::de::Error::custom)?;
            Ok(Self {
                block_hash,
                height,
                round,
                kind,
                signatures: repr
                    .signatures
                    .into_iter()
                    .map(|entry| FatPointerSignature {
                        pub_key: entry.pub_key,
                        signature: VoteSignature::from_bytes(entry.vote_signature),
                    })
                    .collect(),
            })
        }
    }
}

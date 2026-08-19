//! Votes for BFT blocks.

use corez::io;
use snafu::Snafu;

use crate::{
    encoding::{ReadBytesExt, WriteBytesExt},
    hash::{BLAKE3_HASH_BYTES, Blake3Hash},
    height::BftHeight,
    keys::{PUB_KEY_ID_BYTES, PubKeyId, SignatureError, VoteSignature},
};

/// The size of a serialized vote in bytes.
pub const VOTE_BYTES: usize = 76;

/// The bit in the serialized round word that carries the vote kind.
const COMMIT_FLAG: u32 = 0x8000_0000;

/// The bits of the serialized round word that carry the round index.
const ROUND_MASK: u32 = 0x7fff_ffff;

/// A round index exceeds [`Round::MAX`].
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[snafu(display("round {round} exceeds the 31-bit maximum"))]
pub struct InvalidRound {
    /// The rejected round index.
    pub(crate) round: u32,
}

/// A 31-bit BFT round index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Round(pub(crate) u32);

impl Round {
    /// The first round.
    pub const ZERO: Self = Self(0);

    /// The largest representable round index.
    pub const MAX: u32 = ROUND_MASK;

    /// Constructs a round index, rejecting values above [`Round::MAX`].
    pub fn new(round: u32) -> Result<Self, InvalidRound> {
        if round > Self::MAX {
            Err(InvalidRound { round })
        } else {
            Ok(Self(round))
        }
    }

    /// Returns the numeric value of this round index.
    pub fn value(&self) -> u32 {
        self.0
    }
}

/// The kind of a vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VoteKind {
    /// A first-phase vote.
    Prevote,
    /// A second-phase (commit) vote.
    Precommit,
}

/// A vote by a finalizer for a value in a round.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vote {
    pub(crate) validator: PubKeyId,
    pub(crate) value: Option<Blake3Hash>,
    pub(crate) height: BftHeight,
    pub(crate) kind: VoteKind,
    pub(crate) round: Round,
}

impl Vote {
    /// Constructs a vote. A `value` of `None` is a Nil vote.
    pub fn new(
        validator: PubKeyId,
        value: Option<Blake3Hash>,
        height: BftHeight,
        kind: VoteKind,
        round: Round,
    ) -> Self {
        Self {
            validator,
            value,
            height,
            kind,
            round,
        }
    }

    /// Returns the finalizer this vote belongs to.
    pub fn validator(&self) -> &PubKeyId {
        &self.validator
    }

    /// Returns the voted-for block hash, or `None` for a Nil vote.
    pub fn value(&self) -> Option<&Blake3Hash> {
        self.value.as_ref()
    }

    /// Returns the BFT height this vote applies to.
    pub fn height(&self) -> BftHeight {
        self.height
    }

    /// Returns the kind of this vote.
    pub fn kind(&self) -> VoteKind {
        self.kind
    }

    /// Returns the round this vote was cast in.
    pub fn round(&self) -> Round {
        self.round
    }

    /// Serializes this vote to its 76-byte signing layout: 32-byte validator key,
    /// 32-byte value hash (zero for Nil), 8-byte little-endian height, 4-byte
    /// little-endian round word whose most significant bit is set for a precommit.
    pub fn to_bytes(&self) -> [u8; VOTE_BYTES] {
        let mut buf = [0u8; VOTE_BYTES];
        buf[0..32].copy_from_slice(self.validator.as_bytes());
        if let Some(value) = &self.value {
            buf[32..64].copy_from_slice(value.as_bytes());
        }
        buf[64..72].copy_from_slice(&u64::from(self.height).to_le_bytes());
        buf[72..76].copy_from_slice(&round_word(self.kind, self.round).to_le_bytes());
        buf
    }

    /// Parses a vote from its 76-byte signing layout.
    ///
    /// A zero value hash parses as a Nil vote. The 8-byte serialized height must fit
    /// in `u32`; larger values are rejected as they cannot appear in
    /// honestly-produced chain data.
    pub fn from_bytes(bytes: &[u8; VOTE_BYTES]) -> io::Result<Self> {
        let mut cursor: &[u8] = bytes;
        let validator = PubKeyId::read(&mut cursor)?;

        let mut value_bytes = [0u8; BLAKE3_HASH_BYTES];
        corez::io::Read::read_exact(&mut cursor, &mut value_bytes)?;
        let value = if value_bytes == [0u8; BLAKE3_HASH_BYTES] {
            None
        } else {
            Some(Blake3Hash::from_bytes(value_bytes))
        };

        let height = read_height_u64(&mut cursor)?;
        let (kind, round) = read_round_word(&mut cursor)?;

        Ok(Self {
            validator,
            value,
            height,
            kind,
            round,
        })
    }
}

/// Reads an 8-byte little-endian height and narrows it to [`BftHeight`], rejecting
/// values above `u32::MAX` as they cannot appear in honestly-produced chain data.
pub(crate) fn read_height_u64<R: corez::io::Read>(mut reader: R) -> io::Result<BftHeight> {
    let height = (&mut reader).read_u64_le()?;
    let height = u32::try_from(height)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "BFT height out of range"))?;
    Ok(BftHeight::new(height))
}

/// Reads a 4-byte little-endian round word into its vote kind and round index.
pub(crate) fn read_round_word<R: corez::io::Read>(mut reader: R) -> io::Result<(VoteKind, Round)> {
    let word = (&mut reader).read_u32_le()?;
    let kind = if word & COMMIT_FLAG != 0 {
        VoteKind::Precommit
    } else {
        VoteKind::Prevote
    };
    Ok((kind, Round(word & ROUND_MASK)))
}

/// Combines a vote kind and round index into the serialized round word.
pub(crate) fn round_word(kind: VoteKind, round: Round) -> u32 {
    let mut word = round.value() & ROUND_MASK;
    if kind == VoteKind::Precommit {
        word |= COMMIT_FLAG;
    }
    word
}

/// Writes a round word from its vote kind and round index.
pub(crate) fn write_round_word<W: corez::io::Write>(
    mut writer: W,
    kind: VoteKind,
    round: Round,
) -> io::Result<()> {
    (&mut writer).write_u32_le(round_word(kind, round))
}

/// A vote together with its finalizer's signature over the vote's byte layout.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedVote {
    pub(crate) vote: Vote,
    pub(crate) signature: VoteSignature,
}

impl SignedVote {
    /// Constructs a signed vote from its parts.
    pub fn from_parts(vote: Vote, signature: VoteSignature) -> Self {
        Self { vote, signature }
    }

    /// Returns the vote.
    pub fn vote(&self) -> &Vote {
        &self.vote
    }

    /// Returns the signature.
    pub fn signature(&self) -> &VoteSignature {
        &self.signature
    }

    /// Verifies the signature over the vote's byte layout, with the vote namespace
    /// (if any) appended to the signed data.
    pub fn verify(&self, namespace: Option<&Blake3Hash>) -> Result<(), SignatureError> {
        self.signature
            .verify_with_namespace(&self.vote.validator, &self.vote.to_bytes(), namespace)
    }
}

// Assert the layout constants line up with the field sizes.
const _: () = assert!(VOTE_BYTES == PUB_KEY_ID_BYTES + BLAKE3_HASH_BYTES + 8 + 4);

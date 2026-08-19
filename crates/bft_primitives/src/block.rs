//! BFT blocks and the PoW headers they carry.

use core::fmt;

use alloc::vec::Vec;

use corez::io::{self, Read, Write};
use sha2::{Digest, Sha256};
use snafu::Snafu;
use zcash_encoding::CompactSize;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    encoding::{ReadBytesExt, WriteBytesExt},
    fat_pointer::{FatPointerSignature, FatPointerToBftBlock},
    hard_fork::HardForkConfig,
    hash::{Blake3Hash, VALUE_ID_DOMAIN, keyed_hasher},
    height::BftHeight,
    params::{EquihashParameters, ZcashCrosslinkParameters},
    vote::Round,
};

/// The size of the fixed-width prefix of a PoW block header in bytes: version,
/// previous block hash, merkle root, commitment, time, difficulty bits, and nonce.
pub const HEADER_PREFIX_BYTES: usize = 140;

/// The length of the header prefix used as input when verifying Equihash solutions,
/// in bytes. Excludes the nonce, which the verifier takes separately.
pub const EQUIHASH_INPUT_BYTES: usize = 108;

/// The size of the header nonce in bytes.
pub const HEADER_NONCE_BYTES: usize = HEADER_PREFIX_BYTES - EQUIHASH_INPUT_BYTES;

/// The size of an Equihash solution on Mainnet and Testnet in bytes.
pub const SOLUTION_BYTES_MAINNET: usize = 1344;

/// The size of an Equihash solution on Regtest in bytes.
pub const SOLUTION_BYTES_REGTEST: usize = 36;

/// The lowest accepted PoW block header version.
pub const MIN_HEADER_VERSION: u32 = 4;

/// The lowest PoW block header version that carries a fat pointer.
pub const FAT_POINTER_HEADER_VERSION: u32 = 5;

/// Upper bound on the header count accepted by [`BftBlock::read`].
pub const MAX_HEADER_COUNT: u32 = 2048;

/// Upper bound on the hardfork rules a single BFT block can carry.
pub const MAX_HARDFORKS_PER_BLOCK: usize = u8::MAX as usize;

/// A BFT block failed validation.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum InvalidBftBlock {
    /// A version below 2 was supplied for a v2+ block.
    #[snafu(display("version {version} is not a v2+ BFT block version"))]
    UnsupportedVersion {
        /// The rejected version.
        version: u32,
    },
    /// More hardfork rules than a block can carry.
    #[snafu(display("{count} hardforks exceed the per-block maximum"))]
    TooManyHardforks {
        /// The rejected count.
        count: usize,
    },
    /// An incorrect number of headers was present.
    #[snafu(display(
        "invalid confirmation depth: Crosslink requires {expected} while {actual} were present"
    ))]
    IncorrectConfirmationDepth {
        /// The expected number of headers.
        expected: u64,
        /// The number of headers present.
        actual: u64,
    },
    /// A header's version is not a known value.
    #[snafu(display("header {index} has unknown version {version}"))]
    UnknownHeaderVersion {
        /// The position of the offending header.
        index: usize,
        /// The rejected version.
        version: u32,
    },
    /// A header's previous-block hash does not match the header before it.
    #[snafu(display("header {index} does not link to the header before it"))]
    BrokenHeaderChain {
        /// The position of the offending header.
        index: usize,
    },
    /// A header's Equihash solution failed to verify.
    #[snafu(display("header {index} has an invalid Equihash solution: {error}"))]
    InvalidEquihashSolution {
        /// The position of the offending header.
        index: usize,
        /// The underlying Equihash error.
        error: equihash::Error,
    },
}

/// The double-SHA256 hash of a PoW block header.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BcBlockHash(pub(crate) [u8; 32]);

impl BcBlockHash {
    /// Constructs a hash from its byte representation.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the byte representation of this hash.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for BcBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.iter().rev() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for BcBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BcBlockHash(\"{self}\")")
    }
}

/// A PoW block header, kept as its exact serialized bytes.
///
/// Parsing checks the fixed prefix, Equihash solution, and fat-pointer framing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedBcHeader {
    pub(crate) bytes: Vec<u8>,
    pub(crate) solution_start: usize,
    pub(crate) solution_len: usize,
}

impl EncodedBcHeader {
    /// Reads a header, preserving its bytes exactly.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = Vec::new();

        let mut prefix = [0u8; HEADER_PREFIX_BYTES];
        reader.read_exact(&mut prefix)?;
        bytes.extend_from_slice(&prefix);

        let version = u32::from_le_bytes(
            prefix[0..4]
                .try_into()
                .expect("slice length matches the array length"),
        );
        if version < MIN_HEADER_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header version must be at least 4",
            ));
        }

        let solution_len = CompactSize::read(&mut reader)?;
        let solution_len = usize::try_from(solution_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "solution length overflow"))?;
        if solution_len != SOLUTION_BYTES_MAINNET && solution_len != SOLUTION_BYTES_REGTEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incorrect equihash solution size",
            ));
        }
        CompactSize::write(&mut bytes, solution_len)?;
        let solution_start = bytes.len();

        let mut solution = [0u8; SOLUTION_BYTES_MAINNET];
        let solution = &mut solution[..solution_len];
        reader.read_exact(solution)?;
        bytes.extend_from_slice(solution);

        #[cfg(zcash_unstable = "crosslink")]
        let has_fat_pointer = true;
        #[cfg(not(zcash_unstable = "crosslink"))]
        let has_fat_pointer = logical_header_version(version) >= FAT_POINTER_HEADER_VERSION;

        if has_fat_pointer {
            let fat_pointer = FatPointerToBftBlock::read(&mut reader)?;
            fat_pointer.write(&mut bytes)?;
        }

        Ok(Self {
            bytes,
            solution_start,
            solution_len,
        })
    }

    /// Writes this header's exact bytes.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.bytes)
    }

    /// Returns this header's exact serialized bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the raw header version.
    pub fn version(&self) -> u32 {
        u32::from_le_bytes(
            self.bytes[0..4]
                .try_into()
                .expect("slice length matches the array length"),
        )
    }

    /// Returns the hash of the header this header builds on.
    pub fn prev_block_hash(&self) -> BcBlockHash {
        BcBlockHash(
            self.bytes[4..36]
                .try_into()
                .expect("slice length matches the array length"),
        )
    }

    /// Returns this header's double-SHA256 hash.
    pub fn hash(&self) -> BcBlockHash {
        BcBlockHash(Sha256::digest(Sha256::digest(&self.bytes)).into())
    }

    /// Returns the Equihash solution bytes, without the length prefix.
    pub fn solution(&self) -> &[u8] {
        &self.bytes[self.solution_start..self.solution_start + self.solution_len]
    }

    /// Verifies this header's Equihash solution.
    pub fn check_pow(&self, pow: &EquihashParameters) -> Result<(), equihash::Error> {
        equihash::is_valid_solution(
            pow.n,
            pow.k,
            &self.bytes[0..EQUIHASH_INPUT_BYTES],
            &self.bytes[EQUIHASH_INPUT_BYTES..HEADER_PREFIX_BYTES],
            self.solution(),
        )
    }
}

/// Returns the logical version of a raw header version word.
#[cfg(not(zcash_unstable = "crosslink"))]
fn logical_header_version(version: u32) -> u32 {
    if version & 0xffff_0000 != 0 {
        version.reverse_bits()
    } else {
        version
    }
}

/// The fields present only in version 2 and later BFT blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BftBlockV2Data {
    pub(crate) version: u32,
    pub(crate) hardforks: Vec<HardForkConfig>,
    pub(crate) do_not_include_until_bc_height: BlockHeight,
}

impl BftBlockV2Data {
    /// Constructs the v2+ fields, requiring `version >= 2` and at most
    /// [`MAX_HARDFORKS_PER_BLOCK`] hardfork rules. `hardforks` must be in canonical
    /// schedule order (ascending PoW activation height).
    pub fn new(
        version: u32,
        hardforks: Vec<HardForkConfig>,
        do_not_include_until_bc_height: BlockHeight,
    ) -> Result<Self, InvalidBftBlock> {
        if version < 2 {
            return Err(InvalidBftBlock::UnsupportedVersion { version });
        }
        if hardforks.len() > MAX_HARDFORKS_PER_BLOCK {
            return Err(InvalidBftBlock::TooManyHardforks {
                count: hardforks.len(),
            });
        }
        Ok(Self {
            version,
            hardforks,
            do_not_include_until_bc_height,
        })
    }

    /// Returns the raw version number.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Returns the hardfork rules activated by the block.
    pub fn hardforks(&self) -> &[HardForkConfig] {
        &self.hardforks
    }

    /// Returns the PoW height before which the block must not be included.
    pub fn do_not_include_until_bc_height(&self) -> BlockHeight {
        self.do_not_include_until_bc_height
    }
}

/// The version of a BFT block.
///
/// Version 1 blocks cannot carry hardfork rules or an inclusion bound. Versions 2
/// and above share one serialized layout, so unknown future versions round-trip
/// byte-identically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BftBlockVersion {
    /// A version 1 block.
    V1,
    /// A version 2 or later block.
    V2Plus(BftBlockV2Data),
}

/// The BFT block content for Crosslink.
///
/// The serialized form is consensus-critical: it is BLAKE3-hashed, and that hash is
/// the value finalizers sign.
///
/// Headers are ordered deepest first: the first header is the finalization
/// candidate, and each later header builds on the one before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BftBlock {
    pub(crate) version: BftBlockVersion,
    pub(crate) height: BftHeight,
    pub(crate) previous_block_fat_ptr: FatPointerToBftBlock,
    pub(crate) headers: Vec<EncodedBcHeader>,
}

impl BftBlock {
    /// Constructs a BFT block, performing the stateless validations of
    /// [`BftBlock::check_stateless`].
    pub fn new(
        params: &ZcashCrosslinkParameters,
        pow: &EquihashParameters,
        version: BftBlockVersion,
        height: BftHeight,
        previous_block_fat_ptr: FatPointerToBftBlock,
        headers: Vec<EncodedBcHeader>,
    ) -> Result<Self, InvalidBftBlock> {
        check_headers(params, pow, &headers)?;
        Ok(Self {
            version,
            height,
            previous_block_fat_ptr,
            headers,
        })
    }

    /// Returns the version of this block.
    pub fn version(&self) -> &BftBlockVersion {
        &self.version
    }

    /// Returns the numeric version of this block.
    pub fn version_number(&self) -> u32 {
        match &self.version {
            BftBlockVersion::V1 => 1,
            BftBlockVersion::V2Plus(data) => data.version,
        }
    }

    /// Returns the 0-based height of this block on the BFT chain.
    pub fn height(&self) -> BftHeight {
        self.height
    }

    /// Returns the fat pointer to the previous BFT block.
    pub fn previous_block_fat_ptr(&self) -> &FatPointerToBftBlock {
        &self.previous_block_fat_ptr
    }

    /// Returns the hash of the previous BFT block, without its notarization proof.
    pub fn previous_block_hash(&self) -> Blake3Hash {
        *self.previous_block_fat_ptr.block_hash()
    }

    /// Returns the PoW headers carried by this block, deepest first.
    pub fn headers(&self) -> &[EncodedBcHeader] {
        &self.headers
    }

    /// Returns the header that is the finalization candidate for this block, or
    /// `None` if the block carries no headers.
    pub fn finalization_candidate(&self) -> Option<&EncodedBcHeader> {
        self.headers.first()
    }

    /// Returns the hardfork rules activated by this block. Empty for v1 blocks.
    pub fn hardforks(&self) -> &[HardForkConfig] {
        match &self.version {
            BftBlockVersion::V1 => &[],
            BftBlockVersion::V2Plus(data) => &data.hardforks,
        }
    }

    /// Returns the PoW height before which this block must not be included. Zero for
    /// v1 blocks.
    pub fn do_not_include_until_bc_height(&self) -> BlockHeight {
        match &self.version {
            BftBlockVersion::V1 => BlockHeight::from_u32(0),
            BftBlockVersion::V2Plus(data) => data.do_not_include_until_bc_height,
        }
    }

    /// Performs the four stateless validations on this block's headers:
    ///
    /// 1. The header count matches the confirmation depth sigma.
    /// 2. Each header's version is a known value.
    /// 3. Each header links to the header before it.
    /// 4. Each header's Equihash solution verifies.
    ///
    /// [`BftBlock::read`] does not perform these checks; call this on blocks parsed
    /// from untrusted bytes.
    pub fn check_stateless(
        &self,
        params: &ZcashCrosslinkParameters,
        pow: &EquihashParameters,
    ) -> Result<(), InvalidBftBlock> {
        check_headers(params, pow, &self.headers)
    }

    /// Returns this block's BLAKE3 hash: the [`VALUE_ID_DOMAIN`]-keyed hash of its
    /// serialized bytes.
    pub fn hash(&self) -> io::Result<Blake3Hash> {
        let mut hasher = keyed_hasher(VALUE_ID_DOMAIN);
        let bytes = self.to_bytes()?;
        hasher.update(&bytes);
        Ok(Blake3Hash::from_bytes(hasher.finalize().into()))
    }

    /// Reads a BFT block.
    ///
    /// Performs structural parsing only; see [`BftBlock::check_stateless`]. A
    /// serialized version of zero is rejected as it cannot appear in
    /// honestly-produced chain data. For v1 blocks the serialized height is 1-based
    /// and is normalized to the 0-based in-memory height; a stored zero is rejected.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = (&mut reader).read_u32_le()?;
        if version == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BFT block version 0 is not valid",
            ));
        }

        let raw_height = (&mut reader).read_u32_le()?;
        let height = if version < 2 {
            raw_height.checked_sub(1).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "v1 BFT block has a zero serialized height, which cannot be normalized",
                )
            })?
        } else {
            raw_height
        };

        let previous_block_fat_ptr = FatPointerToBftBlock::read(&mut reader)?;

        // The dead 4-byte slot retained by the v1 layout; always written as zero.
        let _ = (&mut reader).read_u32_le()?;

        let header_count = (&mut reader).read_u32_le()?;
        if header_count > MAX_HEADER_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header_count was greater than 2048.",
            ));
        }
        let mut headers = Vec::new();
        for _ in 0..header_count {
            headers.push(EncodedBcHeader::read(&mut reader)?);
        }

        let version = if version >= 2 {
            let hardfork_count = (&mut reader).read_u8()?;
            let mut hardforks = Vec::with_capacity(usize::from(hardfork_count));
            for _ in 0..hardfork_count {
                hardforks.push(HardForkConfig::read(&mut reader)?);
            }
            let do_not_include_until_bc_height = {
                let height = (&mut reader).read_u64_le()?;
                let height = u32::try_from(height).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "PoW height out of range")
                })?;
                BlockHeight::from_u32(height)
            };
            BftBlockVersion::V2Plus(BftBlockV2Data {
                version,
                hardforks,
                do_not_include_until_bc_height,
            })
        } else {
            BftBlockVersion::V1
        };

        Ok(Self {
            version,
            height: BftHeight::new(height),
            previous_block_fat_ptr,
            headers,
        })
    }

    /// Writes this BFT block.
    ///
    /// For v1 blocks the serialized height is the 1-based legacy value, so a v1
    /// height of `u32::MAX` is unrepresentable and returns an error.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        (&mut writer).write_u32_le(self.version_number())?;

        let serialized_height = match &self.version {
            BftBlockVersion::V1 => u32::from(self.height).checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "v1 BFT height out of range")
            })?,
            BftBlockVersion::V2Plus(_) => u32::from(self.height),
        };
        (&mut writer).write_u32_le(serialized_height)?;

        self.previous_block_fat_ptr.write(&mut writer)?;

        // The dead 4-byte slot retained by the v1 layout; always written as zero.
        (&mut writer).write_u32_le(0)?;

        let header_count = u32::try_from(self.headers.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too many headers"))?;
        (&mut writer).write_u32_le(header_count)?;
        for header in &self.headers {
            header.write(&mut writer)?;
        }

        if let BftBlockVersion::V2Plus(data) = &self.version {
            let hardfork_count = u8::try_from(data.hardforks.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too many hardforks"))?;
            (&mut writer).write_u8(hardfork_count)?;
            for hardfork in &data.hardforks {
                hardfork.write(&mut writer)?;
            }
            (&mut writer)
                .write_u64_le(u64::from(u32::from(data.do_not_include_until_bc_height)))?;
        }

        Ok(())
    }

    /// Serializes this block to a byte vector.
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.write(&mut buf)?;
        Ok(buf)
    }
}

/// Runs the stateless header validations shared by [`BftBlock::new`] and
/// [`BftBlock::check_stateless`].
fn check_headers(
    params: &ZcashCrosslinkParameters,
    pow: &EquihashParameters,
    headers: &[EncodedBcHeader],
) -> Result<(), InvalidBftBlock> {
    let expected = params.bc_confirmation_depth_sigma;
    let actual = headers.len() as u64;
    if actual != expected {
        return Err(InvalidBftBlock::IncorrectConfirmationDepth { expected, actual });
    }

    for (index, header) in headers.iter().enumerate() {
        let version = header.version();
        if version < MIN_HEADER_VERSION {
            return Err(InvalidBftBlock::UnknownHeaderVersion { index, version });
        }
    }

    for (index, header) in headers.iter().enumerate() {
        if index > 0 && header.prev_block_hash() != headers[index - 1].hash() {
            return Err(InvalidBftBlock::BrokenHeaderChain { index });
        }
    }

    for (index, header) in headers.iter().enumerate() {
        header
            .check_pow(pow)
            .map_err(|error| InvalidBftBlock::InvalidEquihashSolution { index, error })?;
    }

    Ok(())
}

/// A BFT block together with the fat pointer proving it was notarized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotarizedBftBlock {
    pub(crate) block: BftBlock,
    pub(crate) fat_ptr: FatPointerToBftBlock,
}

impl NotarizedBftBlock {
    /// Bundles a block with a fat pointer built over its hash from the given
    /// signatures.
    pub fn from_parts(
        block: BftBlock,
        height: BftHeight,
        round: Round,
        signatures: Vec<FatPointerSignature>,
    ) -> io::Result<Self> {
        let hash = block.hash()?;
        Ok(Self {
            block,
            fat_ptr: FatPointerToBftBlock::from_parts(hash, height, round, signatures),
        })
    }

    /// Returns the block.
    pub fn block(&self) -> &BftBlock {
        &self.block
    }

    /// Returns the fat pointer proving the block was notarized.
    pub fn fat_pointer(&self) -> &FatPointerToBftBlock {
        &self.fat_ptr
    }

    /// Reads a notarized block as a block followed by a fat pointer.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self {
            block: BftBlock::read(&mut reader)?,
            fat_ptr: FatPointerToBftBlock::read(&mut reader)?,
        })
    }

    /// Writes this notarized block.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.block.write(&mut writer)?;
        self.fat_ptr.write(&mut writer)
    }
}

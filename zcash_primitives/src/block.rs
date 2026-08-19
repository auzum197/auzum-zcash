//! Structs and methods for handling Zcash block headers.

// MSRV lints do not recognize the `clippy::io_other_error` lint
#![allow(unknown_lints)]
// beta lints attempt to rewrite `corez::io::Error::new` calls to `std::io::Error::other`
#![allow(clippy::io_other_error)]

use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;
use corez::io::{self, ErrorKind, Read, Write};
use transparent::bundle::OutPoint;
use zcash_script::{Opcode, opcode::PossiblyBad};

use memuse::DynamicUsage;
use nonempty::NonEmpty;
use sha2::{Digest, Sha256};

use zcash_encoding::{Array, CompactSize, Vector};
use zcash_protocol::consensus::{self, BlockHeight};

#[cfg(zcash_unstable = "crosslink")]
use bft_primitives::{BcBlockHash, EncodedBcHeader, FatPointerToBftBlock};

use crate::{
    encoding::{ReadBytesExt, WriteBytesExt},
    transaction::{Transaction, TxVersion},
};

pub use equihash;

/// The identifier for a Zcash block.
///
/// This is the SHA-256d hash of the encoded [`BlockHeader`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockHash(pub [u8; 32]);

memuse::impl_no_dynamic_usage!(BlockHash);

impl fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The (byte-flipped) hex string is more useful than the raw bytes, because we can
        // look that up in RPC methods and block explorers.
        let block_hash_str = self.to_string();
        f.debug_tuple("BlockHash").field(&block_hash_str).finish()
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut data = self.0;
        data.reverse();
        formatter.write_str(&hex::encode(data))
    }
}

impl BlockHash {
    /// Constructs a [`BlockHash`] from the given slice.
    ///
    /// # Panics
    ///
    /// This function will panic if the slice is not exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::try_from_slice(bytes).unwrap()
    }

    /// Constructs a [`BlockHash`] from the given slice.
    ///
    /// Returns `None` if `bytes` has any length other than 32
    pub fn try_from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut hash = [0; 32];
            hash.copy_from_slice(bytes);
            Some(BlockHash(hash))
        } else {
            None
        }
    }
}

/// A Zcash block header.
#[derive(Debug)]
pub struct BlockHeader {
    hash: BlockHash,
    data: BlockHeaderData,
}

impl Deref for BlockHeader {
    type Target = BlockHeaderData;

    fn deref(&self) -> &BlockHeaderData {
        &self.data
    }
}

/// The information contained in a Zcash block header.
#[derive(Debug)]
pub struct BlockHeaderData {
    pub version: i32,
    pub prev_block: BlockHash,
    pub merkle_root: [u8; 32],
    pub final_sapling_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: [u8; 32],
    pub solution: Vec<u8>,
    /// The latest notarized BFT block.
    #[cfg(zcash_unstable = "crosslink")]
    pub fat_pointer_to_bft_block: FatPointerToBftBlock,
}

impl BlockHeaderData {
    /// Constructs a block header.
    pub fn freeze(self) -> BlockHeader {
        BlockHeader::from_data(self)
    }

    fn read_data<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_i32_le()?;

        let mut prev_block = BlockHash([0; 32]);
        reader.read_exact(&mut prev_block.0)?;

        let mut merkle_root = [0; 32];
        reader.read_exact(&mut merkle_root)?;

        let mut final_sapling_root = [0; 32];
        reader.read_exact(&mut final_sapling_root)?;

        let time = reader.read_u32_le()?;
        let bits = reader.read_u32_le()?;

        let mut nonce = [0; 32];
        reader.read_exact(&mut nonce)?;

        let solution = Vector::read(&mut reader, |r| r.read_u8())?;

        #[cfg(zcash_unstable = "crosslink")]
        let fat_pointer_to_bft_block = FatPointerToBftBlock::read(&mut reader)?;

        Ok(Self {
            version,
            prev_block,
            merkle_root,
            final_sapling_root,
            time,
            bits,
            nonce,
            solution,
            #[cfg(zcash_unstable = "crosslink")]
            fat_pointer_to_bft_block,
        })
    }

    fn write_data<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_i32_le(self.version)?;
        writer.write_all(&self.prev_block.0)?;
        writer.write_all(&self.merkle_root)?;
        writer.write_all(&self.final_sapling_root)?;
        writer.write_u32_le(self.time)?;
        writer.write_u32_le(self.bits)?;
        writer.write_all(&self.nonce)?;
        Vector::write(&mut writer, &self.solution, |w, b| w.write_u8(*b))?;

        #[cfg(zcash_unstable = "crosslink")]
        self.fat_pointer_to_bft_block.write(&mut writer)?;

        Ok(())
    }
}

struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BlockHeader {
    fn from_data(data: BlockHeaderData) -> Self {
        let mut writer = HashWriter(Sha256::new());
        data.write_data(&mut writer)
            .expect("hash writer is infallible");
        let hash = Sha256::digest(writer.0.finalize()).into();

        Self {
            hash: BlockHash(hash),
            data,
        }
    }

    /// Returns the hash of this header.
    pub fn hash(&self) -> BlockHash {
        self.hash
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        BlockHeaderData::read_data(&mut reader).map(Self::from_data)
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.data.write_data(&mut writer)
    }
}

#[cfg(zcash_unstable = "crosslink")]
impl From<BlockHash> for BcBlockHash {
    fn from(hash: BlockHash) -> Self {
        Self::from_bytes(hash.0)
    }
}

#[cfg(zcash_unstable = "crosslink")]
impl From<BcBlockHash> for BlockHash {
    fn from(hash: BcBlockHash) -> Self {
        Self(*hash.as_bytes())
    }
}

#[cfg(zcash_unstable = "crosslink")]
impl From<&BlockHeader> for EncodedBcHeader {
    fn from(header: &BlockHeader) -> Self {
        let mut bytes = Vec::new();
        header.write(&mut bytes).expect("BlockHeader encoding");
        Self::read(&bytes[..]).expect("BlockHeader framing")
    }
}

#[cfg(zcash_unstable = "crosslink")]
impl From<BlockHeader> for EncodedBcHeader {
    fn from(header: BlockHeader) -> Self {
        Self::from(&header)
    }
}

#[cfg(zcash_unstable = "crosslink")]
impl From<&EncodedBcHeader> for BlockHeader {
    fn from(header: &EncodedBcHeader) -> Self {
        Self::read(header.as_bytes()).expect("EncodedBcHeader framing")
    }
}

#[cfg(zcash_unstable = "crosslink")]
impl From<EncodedBcHeader> for BlockHeader {
    fn from(header: EncodedBcHeader) -> Self {
        Self::from(&header)
    }
}

/// Test strategies for block header types.
#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use super::{BlockHash, BlockHeaderData};

    /// Width of each header hash field.
    const HEADER_HASH_BYTES: usize = 32;
    /// Limits generated solution buffers.
    const MAX_ARBITRARY_SOLUTION_BYTES: usize = 64;

    #[cfg(zcash_unstable = "crosslink")]
    proptest::prop_compose! {
        /// Returns arbitrary block header data.
        pub fn arb_block_header_data()(
            version in any::<i32>(),
            prev_block in any::<[u8; HEADER_HASH_BYTES]>(),
            merkle_root in any::<[u8; HEADER_HASH_BYTES]>(),
            final_sapling_root in any::<[u8; HEADER_HASH_BYTES]>(),
            time in any::<u32>(),
            bits in any::<u32>(),
            nonce in any::<[u8; HEADER_HASH_BYTES]>(),
            solution in proptest::collection::vec(any::<u8>(), 0..=MAX_ARBITRARY_SOLUTION_BYTES),
            fat_pointer_to_bft_block in bft_primitives::testing::arb_fat_pointer(),
        ) -> BlockHeaderData {
            BlockHeaderData {
                version,
                prev_block: BlockHash(prev_block),
                merkle_root,
                final_sapling_root,
                time,
                bits,
                nonce,
                solution,
                fat_pointer_to_bft_block,
            }
        }
    }

    #[cfg(not(zcash_unstable = "crosslink"))]
    proptest::prop_compose! {
        /// Returns arbitrary block header data.
        pub fn arb_block_header_data()(
            version in any::<i32>(),
            prev_block in any::<[u8; HEADER_HASH_BYTES]>(),
            merkle_root in any::<[u8; HEADER_HASH_BYTES]>(),
            final_sapling_root in any::<[u8; HEADER_HASH_BYTES]>(),
            time in any::<u32>(),
            bits in any::<u32>(),
            nonce in any::<[u8; HEADER_HASH_BYTES]>(),
            solution in proptest::collection::vec(any::<u8>(), 0..=MAX_ARBITRARY_SOLUTION_BYTES),
        ) -> BlockHeaderData {
            BlockHeaderData {
                version,
                prev_block: BlockHash(prev_block),
                merkle_root,
                final_sapling_root,
                time,
                bits,
                nonce,
                solution,
            }
        }
    }
}

/// A Zcash block.
#[derive(Debug)]
pub struct Block {
    header: BlockHeader,
    vtx: NonEmpty<Transaction>,
    claimed_height: BlockHeight,
}

impl Block {
    /// Parses a block from bytes.
    ///
    /// Limitation: currently this method returns an error if given a genesis block.
    pub fn read<R: Read, P: consensus::Parameters>(mut reader: R, params: &P) -> io::Result<Self> {
        let header = BlockHeader::read(&mut reader)?;

        // Instead of using `Vector::read`, we manually read the length, so we can then
        // individually read the coinbase transaction before the rest.
        let n_tx: usize = CompactSize::read_t(&mut reader)?;
        if n_tx == 0 {
            return Err(corez::io::Error::new(
                ErrorKind::Other,
                "block has no coinbase tx",
            ));
        }

        // Parse with an arbitrary consensus branch ID initially; we will fix it later.
        let coinbase = Transaction::read(&mut reader, consensus::BranchId::Sprout)?;

        // Extract the claimed block height from the coinbase transaction.
        let claimed_height = {
            let coinbase_transparent = coinbase
                .transparent_bundle()
                .filter(|b| b.is_coinbase())
                .ok_or_else(|| {
                    corez::io::Error::new(ErrorKind::Other, "first tx of block is not coinbase")
                })?;

            // Verify some simple structural consensus rules on the coinbase transaction.
            if coinbase.sprout_bundle().is_some() {
                return Err(corez::io::Error::new(
                    ErrorKind::Other,
                    "coinbase tx has sprout data",
                ));
            }

            let coinbase_txin = coinbase_transparent.vin.first().expect("checked above");

            match coinbase_txin.script_sig().0.parse().next() {
                Some(Ok(PossiblyBad::Good(Opcode::PushValue(height)))) => height
                    .to_num()
                    .map_err(|_| {
                        corez::io::Error::new(
                            ErrorKind::Other,
                            "coinbase input specifies an invalid block height",
                        )
                    })
                    .and_then(|h| {
                        BlockHeight::try_from(h).map_err(|_| {
                            corez::io::Error::new(
                                ErrorKind::Other,
                                "coinbase input specifies an invalid block height",
                            )
                        })
                    }),
                // TODO: Permit missing height in genesis blocks by matching their block
                // hash against the provided params.
                _ => Err(corez::io::Error::new(
                    ErrorKind::Other,
                    "coinbase scriptSig missing height",
                )),
            }?
        };

        // Fix the coinbase tx's consensus branch ID if necessary.
        let consensus_branch_id = consensus::BranchId::for_height(params, claimed_height);
        let coinbase = match coinbase.version() {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => coinbase
                .into_data()
                .fix_consensus_branch_id(consensus_branch_id)
                .freeze()
                .expect("valid"),
            // All later tx versions directly commit to the consensus branch ID.
            _ => {
                if coinbase.consensus_branch_id() != consensus_branch_id {
                    return Err(corez::io::Error::new(
                        ErrorKind::Other,
                        "coinbase tx's claimed height doesn't match its consensus branch ID for given network parameters",
                    ));
                }
                coinbase
            }
        };

        // Now parse the rest of the transactions with the expected consensus branch ID.
        let mut non_coinbase = Array::read(&mut reader, n_tx - 1, |r| {
            Transaction::read(r, consensus_branch_id)
        })?;

        // Verify some simple structural consensus rules on the non-coinbase transactions.
        if non_coinbase
            .iter()
            .flat_map(|tx| tx.transparent_bundle())
            .flat_map(|b| &b.vin)
            .any(|txin| txin.prevout() == &OutPoint::NULL)
        {
            return Err(corez::io::Error::new(
                ErrorKind::Other,
                "non-coinbase tx has null transparent input",
            ));
        }

        let mut vtx = NonEmpty::singleton(coinbase);
        vtx.append(&mut non_coinbase);

        Ok(Self {
            header,
            vtx,
            claimed_height,
        })
    }

    /// Writes the block to the given writer.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.header.write(&mut writer)?;
        Vector::write_nonempty(&mut writer, &self.vtx, |w, tx| tx.write(w))?;
        Ok(())
    }

    /// Constructs a block from its component parts.
    ///
    /// This does not validate any consensus rules; in particular, `claimed_height` is not
    /// checked against the height encoded in the coinbase transaction. It is intended for
    /// use in constructing test blocks.
    #[cfg(feature = "test-dependencies")]
    pub fn from_parts(
        header: BlockHeader,
        vtx: NonEmpty<Transaction>,
        claimed_height: BlockHeight,
    ) -> Self {
        Block {
            header,
            vtx,
            claimed_height,
        }
    }

    /// Breaks this block into its component parts for further processing.
    pub fn into_parts(self) -> (BlockHeader, NonEmpty<Transaction>) {
        (self.header, self.vtx)
    }

    /// Returns the block's header.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Returns the block's transactions, in consensus order (the order they are encoded
    /// in the block and applied to chain state).
    ///
    /// The first transaction is always the coinbase transaction.
    pub fn vtx(&self) -> &NonEmpty<Transaction> {
        &self.vtx
    }

    /// Returns the claimed height of this block.
    ///
    /// This is a "claimed height" for two reasons:
    /// - It is the value recorded in the `scriptSig` of the coinbase transaction's null
    ///   transparent input, and thus can only be trusted if the block has been fully
    ///   validated in the context of a chain.
    /// - Blocks not in the main chain **do not have heights** (because heights are by
    ///   definition measured with respect to the longest chain). This value can only be
    ///   used as a "height" if the block is verified to be currently in the main chain.
    pub fn claimed_height(&self) -> BlockHeight {
        self.claimed_height
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    #[cfg(zcash_unstable = "crosslink")]
    use proptest::prelude::*;
    #[cfg(not(zcash_unstable = "crosslink"))]
    use zcash_protocol::consensus::MAIN_NETWORK;

    use super::BlockHeader;

    #[cfg(not(zcash_unstable = "crosslink"))]
    use super::Block;

    #[cfg(zcash_unstable = "crosslink")]
    use {
        super::{BlockHash, BlockHeaderData},
        bft_primitives::{
            BcBlockHash, BftHeight, Blake3Hash, EncodedBcHeader, FatPointerSignature,
            FatPointerToBftBlock, PubKeyId, Round, VoteSignature,
            block::SOLUTION_BYTES_REGTEST,
            hash::BLAKE3_HASH_BYTES,
            keys::{PUB_KEY_ID_BYTES, VOTE_SIGNATURE_BYTES},
        },
    };

    #[cfg(zcash_unstable = "crosslink")]
    const HEADER_HASH_BYTES: usize = 32;
    #[cfg(zcash_unstable = "crosslink")]
    const TEST_HEADER_VERSION: i32 = 4;
    #[cfg(zcash_unstable = "crosslink")]
    const TEST_FIELD_BYTE: u8 = 0x11;
    #[cfg(zcash_unstable = "crosslink")]
    const TEST_SOLUTION_BYTE: u8 = 0x22;
    #[cfg(zcash_unstable = "crosslink")]
    const TEST_TIME: u32 = 1_700_000_000;
    #[cfg(zcash_unstable = "crosslink")]
    const TEST_BITS: u32 = 0x1f07_ffff;
    #[cfg(zcash_unstable = "crosslink")]
    const TEST_BFT_HEIGHT: u32 = 7;
    #[cfg(zcash_unstable = "crosslink")]
    const TEST_ROUND: u32 = 2;
    #[cfg(zcash_unstable = "crosslink")]
    const TEST_BLOCK_HASH_BYTE: u8 = 0x33;
    #[cfg(zcash_unstable = "crosslink")]
    const TEST_PUBLIC_KEY_BYTE: u8 = 0x44;
    #[cfg(zcash_unstable = "crosslink")]
    const TEST_SIGNATURE_BYTE: u8 = 0x55;

    #[cfg(not(zcash_unstable = "crosslink"))]
    const BLOCK_MAINNET_415000: [u8; 1640] = [
        0x04, 0x00, 0x00, 0x00, 0x52, 0x74, 0xb4, 0x3b, 0x9e, 0x4a, 0xd8, 0xf4, 0x3e, 0x93, 0xf7,
        0x84, 0x63, 0xd2, 0x4d, 0xcf, 0xe5, 0x31, 0xae, 0xb4, 0x71, 0x98, 0x19, 0xf4, 0xf9, 0x7f,
        0x7e, 0x03, 0x00, 0x00, 0x00, 0x00, 0x66, 0x30, 0x73, 0xbc, 0x4b, 0xfa, 0x95, 0xc9, 0xbe,
        0xc3, 0x6a, 0xad, 0x72, 0x68, 0xa5, 0x73, 0x04, 0x97, 0x97, 0xbd, 0xfc, 0x5a, 0xa4, 0xc7,
        0x43, 0xfb, 0xe4, 0x82, 0x0a, 0xa3, 0x93, 0xce, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0xbe, 0xcc, 0x5b, 0xe1,
        0xab, 0x03, 0x1c, 0xc2, 0xfd, 0x60, 0x7c, 0x77, 0x6a, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x3e, 0xb2, 0x18, 0x19, 0xfd, 0x40, 0x05, 0x00, 0x94, 0x9d, 0x55, 0xde, 0x0c, 0xc6,
        0x33, 0xe0, 0xcc, 0xe4, 0x1e, 0x46, 0x49, 0xef, 0x4a, 0xa3, 0x34, 0x9f, 0x01, 0x00, 0x29,
        0x0f, 0xfe, 0x28, 0x1b, 0x94, 0x7b, 0x3b, 0x53, 0xfb, 0xd2, 0xf3, 0x5b, 0x1c, 0xe2, 0x92,
        0x64, 0x9b, 0x96, 0xac, 0x6e, 0x08, 0x83, 0xaf, 0x3a, 0x68, 0x44, 0xb9, 0x55, 0x92, 0xe7,
        0x45, 0x56, 0xda, 0x34, 0x4b, 0x47, 0x01, 0x96, 0x1c, 0xd4, 0x13, 0x0c, 0x68, 0x21, 0x9c,
        0xfa, 0x13, 0x41, 0xd5, 0xaf, 0xb5, 0x04, 0x9e, 0xb0, 0xe8, 0xbe, 0x4a, 0x2d, 0x92, 0xd6,
        0x78, 0xc4, 0x07, 0x85, 0xe3, 0x37, 0x05, 0x54, 0x8b, 0x5f, 0x3a, 0x54, 0xf0, 0xa4, 0xc3,
        0x9a, 0x2f, 0x58, 0xee, 0x78, 0x4a, 0x24, 0x16, 0x3c, 0xd8, 0x6f, 0x54, 0x81, 0x23, 0x27,
        0xdf, 0x55, 0xe1, 0xd5, 0x5c, 0xa8, 0x4b, 0x6e, 0x7b, 0x88, 0x7a, 0x7c, 0xbf, 0xb9, 0x09,
        0x1a, 0x58, 0x5b, 0xdb, 0x8e, 0xa4, 0x75, 0x93, 0x07, 0xc5, 0x6c, 0x1b, 0x3d, 0xaf, 0xc6,
        0x69, 0x24, 0x5a, 0x6f, 0x65, 0x4b, 0x6f, 0x73, 0x00, 0x52, 0x26, 0x6a, 0x01, 0xad, 0x4f,
        0x9c, 0x0b, 0x59, 0xed, 0x4e, 0x17, 0x71, 0x2b, 0x3e, 0x72, 0xdf, 0x04, 0x98, 0xaa, 0x8d,
        0xe4, 0x88, 0x8f, 0x99, 0x35, 0x31, 0xc6, 0x0a, 0xcd, 0xed, 0x1d, 0x4b, 0x66, 0xe8, 0x9d,
        0xe0, 0xb6, 0x48, 0x2c, 0xcc, 0xd4, 0xa7, 0x12, 0xf5, 0xcf, 0x9d, 0x4c, 0xa8, 0x3b, 0xe0,
        0xf9, 0x22, 0xde, 0x2c, 0x1d, 0xbb, 0x3a, 0x14, 0x07, 0x48, 0x0d, 0xbe, 0x87, 0x95, 0x99,
        0x3d, 0x8b, 0xe6, 0x40, 0x98, 0x8a, 0xbf, 0xe7, 0xa8, 0xa1, 0xb3, 0x3a, 0x12, 0x13, 0x1c,
        0x45, 0x1e, 0x1a, 0xbc, 0x0d, 0x83, 0xfb, 0x85, 0x18, 0x62, 0xc6, 0x37, 0xce, 0x72, 0x4d,
        0x5f, 0xe9, 0x7a, 0xa9, 0xa8, 0x06, 0xcf, 0x34, 0xba, 0xb5, 0x09, 0xf4, 0x55, 0x4b, 0x0c,
        0xd1, 0x0a, 0x7d, 0xdf, 0xd5, 0x82, 0x1b, 0x09, 0x1a, 0xd2, 0xc9, 0x0c, 0x1a, 0xa1, 0xd8,
        0x1e, 0xb3, 0xd7, 0x2d, 0xb4, 0x19, 0x93, 0xb6, 0x48, 0xf4, 0x1e, 0x21, 0x38, 0xff, 0x95,
        0x31, 0xa3, 0x0f, 0xf7, 0x3b, 0x22, 0x14, 0x0e, 0x4e, 0xbd, 0x7b, 0xaa, 0x33, 0x84, 0x8e,
        0x51, 0x2d, 0x99, 0x30, 0x0c, 0x5c, 0x13, 0x1c, 0x6e, 0x75, 0xf5, 0x71, 0x4a, 0x5c, 0x6d,
        0xcb, 0x17, 0x8b, 0x4a, 0x49, 0x78, 0xda, 0xc8, 0x3a, 0xd4, 0x12, 0xfb, 0xd6, 0x92, 0x01,
        0x92, 0x50, 0xc5, 0x53, 0x04, 0x9a, 0xad, 0x45, 0x79, 0x84, 0xbe, 0xdf, 0xc9, 0x6a, 0xe7,
        0x01, 0xc6, 0x59, 0xbc, 0x70, 0x07, 0xa9, 0x7d, 0x0a, 0x90, 0x02, 0xb9, 0x45, 0xbd, 0xec,
        0x45, 0xa9, 0x45, 0xef, 0x62, 0x85, 0xb2, 0xcd, 0x55, 0x3b, 0x4c, 0x09, 0xd9, 0x07, 0xc6,
        0x27, 0x86, 0x3f, 0x03, 0x99, 0xe8, 0x72, 0x5b, 0x4f, 0xf7, 0xfc, 0x59, 0x79, 0xe3, 0xcf,
        0xf2, 0x28, 0x14, 0x50, 0x84, 0x48, 0xef, 0x8b, 0x98, 0x31, 0xc2, 0x85, 0x95, 0x93, 0x33,
        0x39, 0x6a, 0xa3, 0x62, 0xa5, 0x1c, 0xf2, 0x05, 0x09, 0x7a, 0xfa, 0xbe, 0xc1, 0x5e, 0x41,
        0xfb, 0x6e, 0x30, 0xb6, 0x22, 0x37, 0x4b, 0xf5, 0x8b, 0x37, 0xef, 0x9d, 0x1b, 0x24, 0x1e,
        0xad, 0x5a, 0x68, 0x2b, 0x98, 0xb6, 0x57, 0x49, 0xa5, 0x75, 0x68, 0xe2, 0x38, 0xd5, 0x0a,
        0xfd, 0x41, 0x7e, 0x1e, 0x96, 0x0e, 0x7b, 0x5a, 0x06, 0x4f, 0xd9, 0xf6, 0x94, 0xd7, 0x83,
        0xa2, 0xcb, 0xcd, 0x58, 0x55, 0x2d, 0xed, 0xbb, 0x9e, 0x5e, 0x11, 0x23, 0x67, 0x4e, 0xf7,
        0x3a, 0x52, 0x41, 0x96, 0xcf, 0x05, 0xd3, 0xe5, 0x24, 0x66, 0x05, 0x49, 0xff, 0xe7, 0xbd,
        0x65, 0x68, 0x05, 0x71, 0x35, 0xff, 0xd5, 0xaf, 0xd9, 0x43, 0xf6, 0xda, 0x11, 0xcb, 0xb5,
        0x97, 0xe8, 0xcc, 0xec, 0xd7, 0x7e, 0xcb, 0xe9, 0x09, 0xde, 0x06, 0x31, 0xbf, 0xa2, 0x9c,
        0xd3, 0xe3, 0xd5, 0x54, 0x46, 0x71, 0xba, 0x80, 0x25, 0x61, 0x53, 0xd6, 0xe9, 0x99, 0x0b,
        0x88, 0xad, 0x8e, 0x0c, 0xf4, 0x98, 0x9b, 0xef, 0x4b, 0xe4, 0x57, 0xf9, 0xc7, 0xb0, 0xf1,
        0xaa, 0xcd, 0x6e, 0x0e, 0xf3, 0x20, 0x60, 0x5c, 0x29, 0xed, 0x0c, 0xd2, 0xeb, 0x6c, 0xfc,
        0xe2, 0x16, 0xc5, 0x2a, 0x31, 0x75, 0x80, 0x20, 0x1c, 0xad, 0x7a, 0x09, 0x43, 0xd2, 0x4b,
        0x7b, 0x06, 0xd5, 0xbf, 0x75, 0x87, 0x61, 0xdd, 0x96, 0xe1, 0x19, 0x70, 0xb5, 0xde, 0xd6,
        0x97, 0x22, 0x2b, 0x2c, 0x77, 0xe7, 0xf2, 0x56, 0xa6, 0x05, 0xac, 0x75, 0x55, 0x49, 0xc1,
        0x65, 0x1f, 0x25, 0xad, 0xfc, 0x9d, 0x53, 0xd9, 0x11, 0x7e, 0x3a, 0x0b, 0xb4, 0x09, 0xee,
        0xe4, 0xa6, 0x00, 0x12, 0x04, 0x72, 0x94, 0x9c, 0x7d, 0xda, 0x1c, 0x2e, 0xdb, 0x3c, 0x33,
        0x0c, 0x7f, 0x96, 0x17, 0x99, 0x82, 0x91, 0x64, 0x57, 0xd3, 0x31, 0xe9, 0x63, 0x09, 0xdd,
        0x24, 0xdf, 0x74, 0xee, 0xdd, 0x00, 0xe7, 0xdb, 0x49, 0x7e, 0xe1, 0x30, 0xf7, 0x7d, 0xe6,
        0x66, 0xeb, 0x55, 0x7f, 0xb3, 0x16, 0xe8, 0x7a, 0xda, 0xf1, 0x81, 0x3c, 0xe4, 0x26, 0xa4,
        0x58, 0xa6, 0xee, 0xe3, 0xa8, 0x5b, 0x2a, 0xb8, 0x8f, 0x65, 0x53, 0xaa, 0xda, 0xe8, 0xde,
        0x65, 0x2e, 0x21, 0x1a, 0x1d, 0x9f, 0x33, 0x4d, 0x59, 0x6b, 0x5e, 0xb6, 0x17, 0x34, 0x07,
        0xef, 0xcc, 0x2e, 0x81, 0x54, 0xbb, 0x9c, 0xa1, 0x21, 0x2a, 0xa9, 0xa1, 0xa1, 0x12, 0x1d,
        0x2f, 0x5a, 0x77, 0x12, 0xcf, 0x25, 0xcc, 0x81, 0x48, 0xb8, 0x05, 0x2e, 0x0d, 0x2e, 0x09,
        0xf2, 0x0e, 0x5b, 0xa2, 0xa9, 0x82, 0x77, 0xe9, 0x75, 0xb0, 0xee, 0xd9, 0xa8, 0x92, 0x06,
        0x96, 0x63, 0x37, 0x16, 0x3f, 0x21, 0x5c, 0x9d, 0x04, 0xa6, 0x59, 0x8b, 0x09, 0x58, 0xd3,
        0x33, 0xd8, 0x46, 0x77, 0x3c, 0x69, 0xe5, 0xab, 0xfd, 0x0a, 0x04, 0x27, 0xf3, 0x66, 0x06,
        0x14, 0xdd, 0x82, 0xb7, 0x9a, 0xdb, 0x85, 0x1a, 0x0d, 0x58, 0xb6, 0x2d, 0xf5, 0xf0, 0xb3,
        0xac, 0x83, 0x6e, 0x6e, 0x25, 0xf3, 0xa5, 0x1f, 0x49, 0xa9, 0x9a, 0xde, 0x57, 0x79, 0x6f,
        0xe9, 0xfc, 0xc2, 0x6f, 0x0a, 0x1f, 0x94, 0xff, 0x08, 0x19, 0xfe, 0x52, 0xb7, 0x50, 0x87,
        0xed, 0xbe, 0xd3, 0xa8, 0x16, 0x26, 0xeb, 0x54, 0x16, 0xc6, 0x65, 0x57, 0xf1, 0x1c, 0x0f,
        0xce, 0xdf, 0xf2, 0x23, 0xd6, 0xaa, 0x8c, 0xd5, 0xc3, 0x53, 0x86, 0xe5, 0xb4, 0xb9, 0x5a,
        0x0f, 0x03, 0x92, 0xca, 0x30, 0x1a, 0x38, 0xb3, 0x68, 0x7d, 0x09, 0x44, 0x93, 0xb9, 0xe9,
        0xd2, 0x64, 0xd0, 0x7a, 0x19, 0x0c, 0xe5, 0x7d, 0x11, 0x68, 0x04, 0x38, 0x2a, 0x3f, 0xab,
        0xe1, 0x5a, 0xf4, 0xdf, 0x4f, 0xa0, 0x43, 0xf0, 0x28, 0x7a, 0xa1, 0xed, 0x55, 0x68, 0xd9,
        0xef, 0x5d, 0x12, 0x51, 0x0d, 0x01, 0x0c, 0xcd, 0xab, 0x4e, 0xb6, 0x16, 0xf6, 0xdf, 0x13,
        0xbb, 0x31, 0x26, 0xef, 0x43, 0xd9, 0xd6, 0x57, 0x35, 0xe4, 0xe4, 0xc0, 0x4b, 0x57, 0x63,
        0x48, 0xd0, 0x40, 0xb5, 0x35, 0x05, 0x5a, 0x3d, 0x5a, 0xe1, 0x91, 0xb7, 0x5f, 0x06, 0x12,
        0xf3, 0xb2, 0x40, 0x66, 0xa0, 0x52, 0x45, 0xf2, 0x7f, 0xe5, 0x7b, 0xda, 0x66, 0xbd, 0x6d,
        0xec, 0x7e, 0x4f, 0xc9, 0xcb, 0x23, 0x68, 0x02, 0x06, 0x2a, 0xdd, 0xe3, 0xcd, 0x0e, 0x31,
        0x34, 0x82, 0xc9, 0x2a, 0x0c, 0x72, 0x11, 0x02, 0xb1, 0xf3, 0x8b, 0x01, 0x5a, 0xb8, 0xd0,
        0x15, 0x59, 0xcb, 0xcb, 0x40, 0xf6, 0x74, 0xe9, 0xef, 0xad, 0x5e, 0xe9, 0xc2, 0xfe, 0x13,
        0x3f, 0xaa, 0x55, 0xca, 0x1d, 0xd0, 0xff, 0x26, 0x71, 0x0f, 0x9d, 0xa8, 0x19, 0xcc, 0x14,
        0x59, 0xcb, 0x7e, 0xd2, 0x60, 0xda, 0xd3, 0xdb, 0x05, 0x96, 0x25, 0x8d, 0x47, 0xc7, 0x4c,
        0x32, 0xa8, 0xb8, 0x52, 0xb6, 0x71, 0xc5, 0xa0, 0xca, 0xa2, 0x00, 0x16, 0x03, 0xd9, 0x0c,
        0x91, 0xa7, 0xdf, 0x2e, 0x2d, 0x4e, 0xe9, 0xae, 0x9b, 0xf1, 0xa6, 0xb1, 0xec, 0x88, 0x15,
        0x1c, 0x62, 0x36, 0x0d, 0x03, 0x02, 0x4d, 0x2e, 0x2d, 0x01, 0x14, 0x08, 0x4f, 0x6b, 0x88,
        0xc5, 0xbb, 0xa2, 0x4a, 0xa7, 0xce, 0xcf, 0xac, 0x16, 0xe9, 0x1e, 0x0b, 0xaf, 0x3d, 0x86,
        0x53, 0xe2, 0x18, 0x09, 0x3e, 0x81, 0xd2, 0xa6, 0x3c, 0x32, 0xef, 0xf1, 0xd9, 0x03, 0x0f,
        0x9e, 0x14, 0x14, 0xec, 0xe4, 0x20, 0xda, 0xa2, 0x4e, 0x0d, 0xd5, 0xb8, 0x45, 0xb3, 0x27,
        0x4b, 0xb8, 0x39, 0xca, 0x1c, 0x53, 0xbc, 0xc0, 0x19, 0x42, 0x42, 0xd7, 0x4b, 0x26, 0x31,
        0xb9, 0x49, 0x5a, 0x65, 0x4f, 0xbb, 0xdc, 0xbf, 0xad, 0x77, 0x9f, 0x73, 0x22, 0xb6, 0x07,
        0x36, 0x24, 0x98, 0x80, 0x60, 0x48, 0x21, 0xd9, 0x69, 0x24, 0xe3, 0xfa, 0x39, 0x7f, 0x35,
        0x4a, 0x5e, 0xcc, 0xa3, 0x4f, 0x61, 0x4d, 0xa5, 0x45, 0x6f, 0x9b, 0x36, 0x33, 0x8c, 0x37,
        0xd8, 0xf6, 0xfb, 0xf6, 0x26, 0xbe, 0x98, 0x34, 0x77, 0x76, 0x60, 0x22, 0x87, 0x27, 0x46,
        0xda, 0x10, 0xa1, 0x77, 0x1c, 0xeb, 0x02, 0xdd, 0x8a, 0xac, 0x01, 0xba, 0x18, 0x6b, 0xf1,
        0x48, 0x86, 0x30, 0x47, 0x9e, 0x12, 0x84, 0xda, 0x01, 0x90, 0xfc, 0xe8, 0xb5, 0x9a, 0xc6,
        0xb0, 0xfd, 0x41, 0x6b, 0xee, 0x56, 0xb7, 0x2f, 0x0a, 0x58, 0x45, 0x15, 0x35, 0x57, 0xff,
        0x0f, 0x49, 0x50, 0xa0, 0xdc, 0x5b, 0xe6, 0x5c, 0xe9, 0x42, 0xd2, 0x2e, 0x18, 0x53, 0x4c,
        0x4e, 0x0e, 0xfa, 0xbb, 0x2d, 0x15, 0x25, 0xdc, 0x48, 0x58, 0xb9, 0xb0, 0xf7, 0x7d, 0x47,
        0x4a, 0x12, 0x5e, 0xbc, 0x25, 0x0e, 0x08, 0xfe, 0xdb, 0xfa, 0xa6, 0x6f, 0x45, 0x3d, 0x90,
        0x93, 0x2c, 0xab, 0x3f, 0xf4, 0x52, 0x21, 0x90, 0x99, 0x68, 0xe5, 0x1e, 0x6b, 0xc2, 0x54,
        0xd5, 0x09, 0xad, 0xeb, 0x75, 0xcb, 0xa7, 0x6d, 0x48, 0xfe, 0x02, 0x4e, 0x3e, 0x66, 0xd8,
        0xdf, 0x5e, 0x01, 0x03, 0x00, 0x00, 0x80, 0x70, 0x82, 0xc4, 0x03, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
        0xff, 0xff, 0xff, 0x1a, 0x03, 0x18, 0x55, 0x06, 0x15, 0x2f, 0x56, 0x69, 0x61, 0x42, 0x54,
        0x43, 0x2f, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x2f,
        0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0xca, 0x9a, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76,
        0xa9, 0x14, 0xfb, 0x8a, 0x6a, 0x4c, 0x11, 0xcb, 0x21, 0x6c, 0xe2, 0x1f, 0x9f, 0x37, 0x1d,
        0xfc, 0x92, 0x71, 0xa4, 0x69, 0xbd, 0x6d, 0x88, 0xac, 0x80, 0xb2, 0xe6, 0x0e, 0x00, 0x00,
        0x00, 0x00, 0x17, 0xa9, 0x14, 0xe0, 0xa5, 0xea, 0x13, 0x40, 0xcc, 0x6b, 0x1d, 0x6a, 0x82,
        0xc0, 0x6c, 0x0a, 0x9c, 0x60, 0xb9, 0x89, 0x8b, 0x6a, 0xe9, 0x87, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[cfg(zcash_unstable = "crosslink")]
    fn populated_fat_pointer() -> FatPointerToBftBlock {
        FatPointerToBftBlock::from_parts(
            Blake3Hash::from_bytes([TEST_BLOCK_HASH_BYTE; BLAKE3_HASH_BYTES]),
            BftHeight::new(TEST_BFT_HEIGHT),
            Round::new(TEST_ROUND).unwrap(),
            vec![FatPointerSignature::from_parts(
                PubKeyId::from_bytes([TEST_PUBLIC_KEY_BYTE; PUB_KEY_ID_BYTES]),
                VoteSignature::from_bytes([TEST_SIGNATURE_BYTE; VOTE_SIGNATURE_BYTES]),
            )],
        )
    }

    #[cfg(zcash_unstable = "crosslink")]
    fn test_header_data(fat_pointer_to_bft_block: FatPointerToBftBlock) -> BlockHeaderData {
        BlockHeaderData {
            version: TEST_HEADER_VERSION,
            prev_block: BlockHash([TEST_FIELD_BYTE; HEADER_HASH_BYTES]),
            merkle_root: [TEST_FIELD_BYTE; HEADER_HASH_BYTES],
            final_sapling_root: [TEST_FIELD_BYTE; HEADER_HASH_BYTES],
            time: TEST_TIME,
            bits: TEST_BITS,
            nonce: [TEST_FIELD_BYTE; HEADER_HASH_BYTES],
            solution: vec![TEST_SOLUTION_BYTE; SOLUTION_BYTES_REGTEST],
            fat_pointer_to_bft_block,
        }
    }

    #[cfg(zcash_unstable = "crosslink")]
    fn encode_header(header: &BlockHeader) -> Vec<u8> {
        let mut encoded = Vec::new();
        header.write(&mut encoded).unwrap();
        encoded
    }

    #[cfg(zcash_unstable = "crosslink")]
    #[test]
    fn null_fat_pointer_round_trip() {
        let header = test_header_data(FatPointerToBftBlock::null()).freeze();
        let encoded = encode_header(&header);
        let parsed = BlockHeader::read(&encoded[..]).unwrap();

        assert_eq!(
            parsed.fat_pointer_to_bft_block,
            FatPointerToBftBlock::null()
        );
        assert_eq!(encode_header(&parsed), encoded);
    }

    #[cfg(zcash_unstable = "crosslink")]
    #[test]
    fn populated_fat_pointer_round_trip_and_hash() {
        const EXPECTED_HASH: &str =
            "d425aa118b289ed118ef040b970dbd4c407fe2f4a74027127ddb1ac0f419f85d";

        let fat_pointer = populated_fat_pointer();
        let header = test_header_data(fat_pointer.clone()).freeze();
        let encoded = encode_header(&header);
        let parsed = BlockHeader::read(&encoded[..]).unwrap();

        assert_eq!(parsed.fat_pointer_to_bft_block, fat_pointer);
        assert_eq!(format!("{}", parsed.hash()), EXPECTED_HASH);
        assert_eq!(encode_header(&parsed), encoded);
    }

    #[cfg(zcash_unstable = "crosslink")]
    #[test]
    fn malformed_fat_pointer_is_rejected() {
        let pointer = populated_fat_pointer();
        let pointer_bytes = pointer.to_bytes();
        let header = test_header_data(pointer).freeze();
        let mut encoded = encode_header(&header);
        let pointer_start = encoded.len() - pointer_bytes.len();
        let height_start = pointer_start + populated_fat_pointer().block_hash().as_bytes().len();
        let height_end = height_start + core::mem::size_of::<u64>();
        encoded[height_start..height_end].copy_from_slice(&u64::MAX.to_le_bytes());

        assert!(BlockHeader::read(&encoded[..]).is_err());
    }

    #[cfg(zcash_unstable = "crosslink")]
    #[test]
    fn truncated_fat_pointer_is_rejected() {
        let header = test_header_data(populated_fat_pointer()).freeze();
        let mut encoded = encode_header(&header);
        encoded.pop();

        assert!(BlockHeader::read(&encoded[..]).is_err());
    }

    #[cfg(zcash_unstable = "crosslink")]
    #[test]
    fn bft_header_conversions_are_lossless() {
        let header = test_header_data(populated_fat_pointer()).freeze();
        let expected_hash = header.hash();
        let encoded = encode_header(&header);

        let bft_header = EncodedBcHeader::from(header);
        assert_eq!(bft_header.as_bytes(), encoded);
        assert_eq!(BlockHash::from(bft_header.hash()), expected_hash);
        assert_eq!(
            BlockHash::from(BcBlockHash::from(expected_hash)),
            expected_hash
        );

        let converted = BlockHeader::from(bft_header);
        assert_eq!(encode_header(&converted), encoded);
        assert_eq!(converted.hash(), expected_hash);
    }

    #[cfg(zcash_unstable = "crosslink")]
    proptest! {
        #[test]
        fn arbitrary_header_data_round_trips(
            data in super::testing::arb_block_header_data()
        ) {
            let encoded = encode_header(&data.freeze());
            let parsed = BlockHeader::read(&encoded[..]).unwrap();
            prop_assert_eq!(encode_header(&parsed), encoded);
        }
    }

    #[cfg(not(zcash_unstable = "crosslink"))]
    #[test]
    fn header_read_write() {
        let header_mainnet_415000 = &BLOCK_MAINNET_415000[..1487];

        let header = BlockHeader::read(header_mainnet_415000).unwrap();
        assert_eq!(
            format!("{}", header.hash()),
            "0000000001ab37793ce771262b2ffa082519aa3fe891250a1adb43baaf856168"
        );
        let mut encoded = Vec::with_capacity(header_mainnet_415000.len());
        header.write(&mut encoded).unwrap();
        assert_eq!(header_mainnet_415000, &encoded[..]);
    }

    #[cfg(not(zcash_unstable = "crosslink"))]
    #[test]
    fn block_read_write() {
        let block = Block::read(&BLOCK_MAINNET_415000[..], &MAIN_NETWORK).unwrap();
        assert_eq!(
            format!("{}", block.header().hash()),
            "0000000001ab37793ce771262b2ffa082519aa3fe891250a1adb43baaf856168"
        );
        assert_eq!(block.claimed_height(), 415000.into());
        assert_eq!(block.vtx().len(), 1);

        let mut encoded = Vec::with_capacity(BLOCK_MAINNET_415000.len());
        block.write(&mut encoded).unwrap();
        assert_eq!(&BLOCK_MAINNET_415000[..], &encoded[..]);
    }
}

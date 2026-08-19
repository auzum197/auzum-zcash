//! *Core data types for the Zcash Crosslink BFT protocol.*
//!
//! `bft_primitives` provides the BFT chain types (blocks, votes, fat pointers) and
//! staking-roster types used by Crosslink, together with their canonical binary
//! serialization and signature verification. It contains no signing APIs and no
//! stateful chain validation.
//!
#![cfg_attr(feature = "std", doc = "## Feature flags")]
#![cfg_attr(feature = "std", doc = document_features::document_features!())]
//!

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod block;
pub mod fat_pointer;
pub mod hard_fork;
pub mod hash;
pub mod height;
pub mod keys;
pub mod params;
pub mod roster;
pub mod vote;

pub(crate) mod encoding;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing;

#[cfg(test)]
mod tests;

pub use block::{
    BcBlockHash, BftBlock, BftBlockV2Data, BftBlockVersion, EncodedBcHeader, InvalidBftBlock,
    NotarizedBftBlock,
};
pub use fat_pointer::{FatPointerSignature, FatPointerToBftBlock};
pub use hard_fork::{HardForkConfig, InvalidHardForkConfig};
pub use hash::Blake3Hash;
pub use height::BftHeight;
pub use keys::{PubKeyId, SignatureError, VoteSignature};
pub use params::{
    EquihashParameters, InvalidParameters, PROTOTYPE_PARAMETERS, ZcashCrosslinkParameters,
};
pub use roster::{RosterMember, StakeTxId};
pub use vote::{InvalidRound, Round, SignedVote, Vote, VoteKind};

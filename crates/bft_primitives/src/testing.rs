//! Proptest strategies for the types in this crate.

use alloc::vec::Vec;

use proptest::{collection::vec, prelude::*};
use zcash_protocol::consensus::BlockHeight;

use crate::{
    block::{
        BftBlock, BftBlockV2Data, BftBlockVersion, EncodedBcHeader, HEADER_PREFIX_BYTES,
        MIN_HEADER_VERSION, NotarizedBftBlock, SOLUTION_BYTES_MAINNET, SOLUTION_BYTES_REGTEST,
    },
    fat_pointer::{FatPointerSignature, FatPointerToBftBlock},
    hard_fork::HardForkConfig,
    hash::Blake3Hash,
    height::BftHeight,
    keys::{PubKeyId, VoteSignature},
    roster::{RosterMember, StakeTxId},
    vote::{Round, SignedVote, Vote, VoteKind},
};

prop_compose! {
    /// Returns a strategy for arbitrary [`Blake3Hash`] values.
    pub fn arb_blake3_hash()(bytes in any::<[u8; 32]>()) -> Blake3Hash {
        Blake3Hash::from_bytes(bytes)
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`PubKeyId`] values.
    pub fn arb_pub_key_id()(bytes in any::<[u8; 32]>()) -> PubKeyId {
        PubKeyId::from_bytes(bytes)
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`VoteSignature`] values.
    pub fn arb_vote_signature()(bytes in any::<[u8; 64]>()) -> VoteSignature {
        VoteSignature::from_bytes(bytes)
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`BftHeight`] values.
    pub fn arb_bft_height()(height in any::<u32>()) -> BftHeight {
        BftHeight::new(height)
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`Round`] values.
    pub fn arb_round()(round in 0u32..=Round::MAX) -> Round {
        Round::new(round).expect("the range is bounded by Round::MAX")
    }
}

/// Returns a strategy for arbitrary [`VoteKind`] values.
pub fn arb_vote_kind() -> impl Strategy<Value = VoteKind> {
    prop_oneof![Just(VoteKind::Prevote), Just(VoteKind::Precommit)]
}

prop_compose! {
    /// Returns a strategy for arbitrary [`Vote`] values.
    pub fn arb_vote()(
        validator in arb_pub_key_id(),
        value in proptest::option::of(arb_blake3_hash().prop_filter("Nil is represented as None", |h| !h.is_zero())),
        height in arb_bft_height(),
        kind in arb_vote_kind(),
        round in arb_round(),
    ) -> Vote {
        Vote::new(validator, value, height, kind, round)
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`SignedVote`] values. The signature is not
    /// valid for the vote.
    pub fn arb_signed_vote()(
        vote in arb_vote(),
        signature in arb_vote_signature(),
    ) -> SignedVote {
        SignedVote::from_parts(vote, signature)
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`FatPointerSignature`] values.
    pub fn arb_fat_pointer_signature()(
        pub_key in arb_pub_key_id(),
        signature in arb_vote_signature(),
    ) -> FatPointerSignature {
        FatPointerSignature::from_parts(pub_key, signature)
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`FatPointerToBftBlock`] values. The
    /// signatures are not valid.
    pub fn arb_fat_pointer()(
        block_hash in arb_blake3_hash(),
        height in arb_bft_height(),
        round in arb_round(),
        signatures in vec(arb_fat_pointer_signature(), 0..4),
    ) -> FatPointerToBftBlock {
        FatPointerToBftBlock::from_parts(block_hash, height, round, signatures)
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`StakeTxId`] values.
    pub fn arb_stake_tx_id()(
        txid in zcash_protocol::testing::arb_txid(),
        zats in zcash_protocol::value::testing::arb_zatoshis(),
    ) -> StakeTxId {
        StakeTxId::new(txid, zats)
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`RosterMember`] values.
    pub fn arb_roster_member()(
        pub_key in arb_pub_key_id(),
        voting_power in zcash_protocol::value::testing::arb_zatoshis(),
        txids in vec(arb_stake_tx_id(), 0..4),
    ) -> RosterMember {
        RosterMember::new(pub_key, voting_power, txids)
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`HardForkConfig`] values.
    pub fn arb_hard_fork_config()(
        pow_activation_height in any::<u32>(),
        bft_certificate_height in arb_bft_height(),
        finalizers in proptest::collection::btree_set(any::<[u8; 32]>(), 1..4),
    ) -> HardForkConfig {
        HardForkConfig::new(
            BlockHeight::from_u32(pow_activation_height),
            bft_certificate_height,
            finalizers.into_iter().map(PubKeyId::from_bytes).collect(),
        )
        .expect("the finalizer set is non-empty and duplicate-free")
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary structurally-valid [`EncodedBcHeader`]
    /// values. The Equihash solution is not valid.
    pub fn arb_encoded_bc_header()(
        prefix in any::<[u8; HEADER_PREFIX_BYTES]>(),
        version in MIN_HEADER_VERSION..=6u32,
        regtest_solution in any::<bool>(),
        fat_pointer in arb_fat_pointer(),
    ) -> EncodedBcHeader {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&prefix);
        bytes[0..4].copy_from_slice(&version.to_le_bytes());

        let solution_len = if regtest_solution {
            SOLUTION_BYTES_REGTEST
        } else {
            SOLUTION_BYTES_MAINNET
        };
        zcash_encoding::CompactSize::write(&mut bytes, solution_len)
            .expect("writing to a Vec is infallible");
        let solution_start = bytes.len();
        bytes.resize(bytes.len() + solution_len, 0);

        #[cfg(zcash_unstable = "crosslink")]
        let has_fat_pointer = true;
        #[cfg(not(zcash_unstable = "crosslink"))]
        let has_fat_pointer = version >= crate::block::FAT_POINTER_HEADER_VERSION;

        if has_fat_pointer {
            fat_pointer
                .write(&mut bytes)
                .expect("the signature count is below the limit");
        }

        EncodedBcHeader {
            bytes,
            solution_start,
            solution_len,
        }
    }
}

/// Returns a strategy for arbitrary [`BftBlockVersion`] values.
pub fn arb_bft_block_version() -> impl Strategy<Value = BftBlockVersion> {
    prop_oneof![
        Just(BftBlockVersion::V1),
        (
            2u32..=4,
            vec(arb_hard_fork_config(), 0..3),
            any::<u32>().prop_map(BlockHeight::from_u32),
        )
            .prop_map(|(version, hardforks, height)| {
                BftBlockVersion::V2Plus(
                    BftBlockV2Data::new(version, hardforks, height)
                        .expect("the version and hardfork count are in range"),
                )
            }),
    ]
}

prop_compose! {
    /// Returns a strategy for arbitrary structurally-parseable [`BftBlock`] values.
    /// The blocks do not satisfy the stateless header validations.
    pub fn arb_bft_block()(
        version in arb_bft_block_version(),
        height in 0u32..u32::MAX,
        previous_block_fat_ptr in arb_fat_pointer(),
        headers in vec(arb_encoded_bc_header(), 0..3),
    ) -> BftBlock {
        BftBlock {
            version,
            height: BftHeight::new(height),
            previous_block_fat_ptr,
            headers,
        }
    }
}

prop_compose! {
    /// Returns a strategy for arbitrary [`NotarizedBftBlock`] values. The signatures
    /// are not valid.
    pub fn arb_notarized_bft_block()(
        block in arb_bft_block(),
        fat_ptr in arb_fat_pointer(),
    ) -> NotarizedBftBlock {
        NotarizedBftBlock { block, fat_ptr }
    }
}

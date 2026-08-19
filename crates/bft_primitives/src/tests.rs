use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use proptest::{prelude::*, strategy::ValueTree};

use crate::{
    BcBlockHash, BftBlock, BftBlockVersion, BftHeight, Blake3Hash, EquihashParameters,
    FatPointerSignature, FatPointerToBftBlock, HardForkConfig, InvalidBftBlock,
    InvalidHardForkConfig, NotarizedBftBlock, PROTOTYPE_PARAMETERS, PubKeyId, RosterMember, Round,
    Vote, VoteKind, VoteSignature, ZcashCrosslinkParameters,
    testing::{
        arb_bft_block, arb_encoded_bc_header, arb_fat_pointer, arb_hard_fork_config,
        arb_roster_member, arb_vote,
    },
    vote::VOTE_BYTES,
};

fn keypair() -> (ed25519_zebra::SigningKey, PubKeyId) {
    let sk = ed25519_zebra::SigningKey::new(rand_core::OsRng);
    let vk = ed25519_zebra::VerificationKey::from(&sk);
    (sk, PubKeyId::from_bytes(vk.into()))
}

proptest! {
    #[test]
    fn vote_round_trip(vote in arb_vote()) {
        let bytes = vote.to_bytes();
        let parsed = Vote::from_bytes(&bytes).unwrap();
        prop_assert_eq!(vote, parsed);
    }

    #[test]
    fn fat_pointer_round_trip(fat_pointer in arb_fat_pointer()) {
        let bytes = fat_pointer.to_bytes();
        let parsed = FatPointerToBftBlock::read(&bytes[..]).unwrap();
        prop_assert_eq!(fat_pointer, parsed);
    }

    #[test]
    fn encoded_bc_header_round_trip(header in arb_encoded_bc_header()) {
        let bytes = header.as_bytes().to_vec();
        let parsed = crate::EncodedBcHeader::read(&bytes[..]).unwrap();
        prop_assert_eq!(header, parsed);
    }

    #[test]
    fn bft_block_round_trip(block in arb_bft_block()) {
        let bytes = block.to_bytes().unwrap();
        let parsed = BftBlock::read(&bytes[..]).unwrap();
        prop_assert_eq!(block, parsed);
    }

    #[test]
    fn notarized_bft_block_round_trip(
        block in arb_bft_block(),
        fat_pointer in arb_fat_pointer(),
    ) {
        let notarized = NotarizedBftBlock { block, fat_ptr: fat_pointer };
        let mut bytes = Vec::new();
        notarized.write(&mut bytes).unwrap();
        let parsed = NotarizedBftBlock::read(&bytes[..]).unwrap();
        prop_assert_eq!(notarized, parsed);
    }

    #[test]
    fn hard_fork_config_round_trip(config in arb_hard_fork_config()) {
        let mut bytes = Vec::new();
        config.write(&mut bytes).unwrap();
        let parsed = HardForkConfig::read(&bytes[..]).unwrap();
        prop_assert_eq!(config, parsed);
    }

    #[test]
    fn roster_member_round_trip(member in arb_roster_member()) {
        let mut bytes = Vec::new();
        member.write(&mut bytes).unwrap();
        let parsed = RosterMember::read(&bytes[..]).unwrap();
        prop_assert_eq!(member, parsed);
    }
}

#[test]
fn vote_byte_layout() {
    let vote = Vote::new(
        PubKeyId::from_bytes([1u8; 32]),
        Some(Blake3Hash::from_bytes([2u8; 32])),
        BftHeight::new(0x0403_0201),
        VoteKind::Precommit,
        Round::new(5).unwrap(),
    );
    let bytes = vote.to_bytes();
    assert_eq!(&bytes[0..32], &[1u8; 32]);
    assert_eq!(&bytes[32..64], &[2u8; 32]);
    assert_eq!(&bytes[64..72], &[0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0]);
    assert_eq!(&bytes[72..76], &(5u32 | 0x8000_0000).to_le_bytes());
}

#[test]
fn nil_vote_value_is_zero_bytes() {
    let vote = Vote::new(
        PubKeyId::from_bytes([1u8; 32]),
        None,
        BftHeight::ZERO,
        VoteKind::Prevote,
        Round::ZERO,
    );
    let bytes = vote.to_bytes();
    assert_eq!(&bytes[32..64], &[0u8; 32]);
    assert_eq!(Vote::from_bytes(&bytes).unwrap().value(), None);
}

#[test]
fn null_fat_pointer_bytes_are_zero() {
    let bytes = FatPointerToBftBlock::null().to_bytes();
    assert_eq!(bytes, vec![0u8; VOTE_BYTES - 32 + 2]);
}

#[test]
fn from_parts_sets_the_commit_bit() {
    let fat_pointer = FatPointerToBftBlock::from_parts(
        Blake3Hash::from_bytes([3u8; 32]),
        BftHeight::new(7),
        Round::ZERO,
        Vec::new(),
    );
    let bytes = fat_pointer.to_bytes();
    assert_eq!(&bytes[40..44], &0x8000_0000u32.to_le_bytes());
}

#[test]
fn signature_verification_round_trip() {
    let (sk, pub_key) = keypair();
    let msg = b"vote bytes";
    let signature = VoteSignature::from_bytes(sk.sign(msg).into());

    assert!(signature.verify(&pub_key, msg).is_ok());
    assert!(signature.verify(&pub_key, b"other bytes").is_err());

    let namespace = Blake3Hash::from_bytes([9u8; 32]);
    let mut namespaced = msg.to_vec();
    namespaced.extend_from_slice(namespace.as_bytes());
    let namespaced_signature = VoteSignature::from_bytes(sk.sign(&namespaced).into());

    assert!(
        namespaced_signature
            .verify_with_namespace(&pub_key, msg, Some(&namespace))
            .is_ok()
    );
    assert!(
        namespaced_signature
            .verify_with_namespace(&pub_key, msg, None)
            .is_err()
    );
}

#[test]
fn fat_pointer_signature_batch_verification() {
    let block_hash = Blake3Hash::from_bytes([4u8; 32]);
    let height = BftHeight::new(3);
    let round = Round::new(1).unwrap();

    let template = Vote::new(
        PubKeyId::from_bytes([0u8; 32]),
        Some(block_hash),
        height,
        VoteKind::Precommit,
        round,
    );

    let signatures: Vec<FatPointerSignature> = (0..3)
        .map(|_| {
            let (sk, pub_key) = keypair();
            let mut vote = template.clone();
            vote = Vote::new(
                pub_key,
                vote.value().copied(),
                height,
                VoteKind::Precommit,
                round,
            );
            FatPointerSignature::from_parts(
                pub_key,
                VoteSignature::from_bytes(sk.sign(&vote.to_bytes()).into()),
            )
        })
        .collect();

    let fat_pointer = FatPointerToBftBlock::from_parts(block_hash, height, round, signatures);
    assert!(
        fat_pointer
            .verify_signatures(None, rand_core::OsRng)
            .is_ok()
    );

    let mut tampered = fat_pointer.clone();
    tampered.signatures[0].signature = VoteSignature::from_bytes([1u8; 64]);
    assert!(tampered.verify_signatures(None, rand_core::OsRng).is_err());
}

#[test]
fn v1_serialized_height_is_one_based() {
    let block = BftBlock {
        version: BftBlockVersion::V1,
        height: BftHeight::new(4),
        previous_block_fat_ptr: FatPointerToBftBlock::null(),
        headers: Vec::new(),
    };
    let bytes = block.to_bytes().unwrap();
    assert_eq!(&bytes[4..8], &5u32.to_le_bytes());
    assert_eq!(
        BftBlock::read(&bytes[..]).unwrap().height(),
        BftHeight::new(4)
    );
}

#[test]
fn v1_zero_serialized_height_is_rejected() {
    let block = BftBlock {
        version: BftBlockVersion::V1,
        height: BftHeight::ZERO,
        previous_block_fat_ptr: FatPointerToBftBlock::null(),
        headers: Vec::new(),
    };
    let mut bytes = block.to_bytes().unwrap();
    bytes[4..8].copy_from_slice(&0u32.to_le_bytes());
    assert!(BftBlock::read(&bytes[..]).is_err());
}

#[test]
fn incorrect_confirmation_depth_is_rejected() {
    let result = BftBlock::new(
        &PROTOTYPE_PARAMETERS,
        &EquihashParameters::ZCASH,
        BftBlockVersion::V1,
        BftHeight::ZERO,
        FatPointerToBftBlock::null(),
        Vec::new(),
    );
    assert!(matches!(
        result,
        Err(InvalidBftBlock::IncorrectConfirmationDepth {
            expected: 3,
            actual: 0
        })
    ));
}

#[test]
fn broken_header_chain_is_rejected() {
    let params = ZcashCrosslinkParameters::new(2, 4).unwrap();
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let header = arb_encoded_bc_header()
        .new_tree(&mut runner)
        .unwrap()
        .current();

    let headers = vec![header.clone(), header];
    let result = BftBlock::new(
        &params,
        &EquihashParameters::ZCASH,
        BftBlockVersion::V1,
        BftHeight::ZERO,
        FatPointerToBftBlock::null(),
        headers,
    );
    assert!(matches!(
        result,
        Err(InvalidBftBlock::BrokenHeaderChain { index: 1 })
    ));
}

#[test]
fn hard_fork_constructor_sorts_and_rejects_duplicates() {
    let a = PubKeyId::from_bytes([1u8; 32]);
    let b = PubKeyId::from_bytes([2u8; 32]);

    let config = HardForkConfig::new(150.into(), BftHeight::new(1), vec![b, a]).unwrap();
    assert_eq!(config.terminated_finalizers(), &[a, b]);

    assert!(matches!(
        HardForkConfig::new(150.into(), BftHeight::new(1), Vec::new()),
        Err(InvalidHardForkConfig::NoTerminatedFinalizers)
    ));
    assert!(matches!(
        HardForkConfig::new(150.into(), BftHeight::new(1), vec![a, a]),
        Err(InvalidHardForkConfig::DuplicateFinalizer { .. })
    ));
}

#[test]
fn roster_member_rejects_out_of_range_amounts() {
    let mut bytes = Vec::new();
    RosterMember::new(
        PubKeyId::from_bytes([1u8; 32]),
        zcash_protocol::value::Zatoshis::const_from_u64(5),
        Vec::new(),
    )
    .write(&mut bytes)
    .unwrap();
    bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(RosterMember::read(&bytes[..]).is_err());
}

#[test]
fn bc_block_hash_displays_reversed() {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xab;
    assert!(alloc::format!("{}", BcBlockHash::from_bytes(bytes)).ends_with("ab"));
}

#[cfg(feature = "serde")]
mod serde_tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn pub_key_id_serializes_as_reversed_hex() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x01;
        bytes[31] = 0xff;
        let id = PubKeyId::from_bytes(bytes);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(
            json,
            "\"ff00000000000000000000000000000000000000000000000000000000000001\""
        );
        assert_eq!(serde_json::from_str::<PubKeyId>(&json).unwrap(), id);
    }

    #[test]
    fn fat_pointer_serde_round_trip() {
        let fat_pointer = FatPointerToBftBlock::from_parts(
            Blake3Hash::from_bytes([7u8; 32]),
            BftHeight::new(9),
            Round::new(2).unwrap(),
            vec![FatPointerSignature::from_parts(
                PubKeyId::from_bytes([1u8; 32]),
                VoteSignature::from_bytes([2u8; 64]),
            )],
        );
        let json = serde_json::to_string(&fat_pointer).unwrap();
        assert!(json.contains("vote_for_block_without_finalizer_public_key"));
        assert_eq!(
            serde_json::from_str::<FatPointerToBftBlock>(&json).unwrap(),
            fat_pointer
        );
    }

    #[test]
    fn roster_member_serde_round_trip() {
        let member = RosterMember::new(
            PubKeyId::from_bytes([3u8; 32]),
            zcash_protocol::value::Zatoshis::const_from_u64(11),
            vec![crate::StakeTxId::new(
                zcash_protocol::TxId::from_bytes([4u8; 32]),
                zcash_protocol::value::Zatoshis::const_from_u64(7),
            )],
        );
        let json = serde_json::to_string(&member).unwrap();
        assert!(json.contains(&hex::encode([3u8; 32])));
        assert_eq!(serde_json::from_str::<RosterMember>(&json).unwrap(), member);
    }

    #[test]
    fn hard_fork_config_serde_validations() {
        let valid = "{\"pow_activation_height\":150,\"bft_certificate_height\":1,\"terminated_finalizers\":[\"0000000000000000000000000000000000000000000000000000000000000001\"]}";
        let config = serde_json::from_str::<HardForkConfig>(valid);
        #[cfg(zcash_unstable = "crosslink")]
        assert!(config.is_ok());
        #[cfg(not(zcash_unstable = "crosslink"))]
        assert!(config.is_ok());

        let empty = "{\"pow_activation_height\":150,\"bft_certificate_height\":1,\"terminated_finalizers\":[]}";
        assert!(serde_json::from_str::<HardForkConfig>(empty).is_err());

        #[cfg(zcash_unstable = "crosslink")]
        {
            let misaligned = "{\"pow_activation_height\":151,\"bft_certificate_height\":1,\"terminated_finalizers\":[\"0000000000000000000000000000000000000000000000000000000000000001\"]}";
            assert!(serde_json::from_str::<HardForkConfig>(misaligned).is_err());
        }
    }
}

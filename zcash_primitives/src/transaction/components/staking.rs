//! Staking actions carried by version 7 (VCrosslink) transactions.

use corez::io::{self, Read, Write};

use bft_primitives::PubKeyId;
use zcash_protocol::value::{ZatBalance, Zatoshis};

use crate::encoding::{ReadBytesExt, WriteBytesExt};

const TAG_ABSENT: u8 = 0;
const TAG_CREATE_NEW_DELEGATION_BOND: u8 = 1;
const TAG_BEGIN_DELEGATION_UNBONDING: u8 = 2;
const TAG_WITHDRAW_DELEGATION_BOND: u8 = 3;
const TAG_RETARGET_DELEGATION_BOND: u8 = 4;
const TAG_REGISTER_FINALIZER: u8 = 5;
const TAG_CONVERT_FINALIZER_REWARD_TO_DELEGATION_BOND: u8 = 6;
const TAG_UPDATE_FINALIZER_KEY: u8 = 7;

fn read_zatoshis<R: Read>(mut reader: R) -> io::Result<Zatoshis> {
    Zatoshis::from_u64(reader.read_u64_le()?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "staking amount out of range"))
}

fn write_zatoshis<W: Write>(amount: Zatoshis, mut writer: W) -> io::Result<()> {
    writer.write_u64_le(amount.into_u64())
}

/// Identifier of a delegation bond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondId(pub(crate) [u8; 32]);

impl BondId {
    /// Constructs a [`BondId`] from its 32-byte representation.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        BondId(bytes)
    }

    /// Returns the 32-byte representation of this identifier.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        Ok(BondId(bytes))
    }

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }
}

/// An unauthenticated challenge attached to a staking action.
///
/// This value is committed to by the transaction identifier but is not verified by consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakingAuthChallenge(pub(crate) [u8; 32]);

impl StakingAuthChallenge {
    /// Constructs a [`StakingAuthChallenge`] from its 32-byte representation.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        StakingAuthChallenge(bytes)
    }

    /// Returns the 32-byte representation of this challenge.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        Ok(StakingAuthChallenge(bytes))
    }

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }
}

/// An unauthenticated signature attached to a staking action.
///
/// This value is committed to by the transaction identifier but is not verified by consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakingAuthSig(pub(crate) [u8; 64]);

impl StakingAuthSig {
    /// Constructs a [`StakingAuthSig`] from its 64-byte representation.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        StakingAuthSig(bytes)
    }

    /// Returns the 64-byte representation of this signature.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub(crate) fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 64];
        reader.read_exact(&mut bytes)?;
        Ok(StakingAuthSig(bytes))
    }

    pub(crate) fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }
}

/// Opens a new delegation bond funding a finalizer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateNewDelegationBond {
    pub(crate) unique_pubkey: BondId,
    pub(crate) challenge: StakingAuthChallenge,
    pub(crate) signature: StakingAuthSig,
    pub(crate) target_finalizer: PubKeyId,
    pub(crate) amount: Zatoshis,
}

impl CreateNewDelegationBond {
    /// Constructs a [`CreateNewDelegationBond`] action from its parts.
    pub fn new(
        unique_pubkey: BondId,
        challenge: StakingAuthChallenge,
        signature: StakingAuthSig,
        target_finalizer: PubKeyId,
        amount: Zatoshis,
    ) -> Self {
        CreateNewDelegationBond {
            unique_pubkey,
            challenge,
            signature,
            target_finalizer,
            amount,
        }
    }

    /// Returns the bond identifier.
    pub fn unique_pubkey(&self) -> BondId {
        self.unique_pubkey
    }

    /// Returns the challenge.
    pub fn challenge(&self) -> StakingAuthChallenge {
        self.challenge
    }

    /// Returns the signature.
    pub fn signature(&self) -> StakingAuthSig {
        self.signature
    }

    /// Returns the finalizer key the bond delegates to.
    pub fn target_finalizer(&self) -> PubKeyId {
        self.target_finalizer
    }

    /// Returns the bonded amount.
    pub fn amount(&self) -> Zatoshis {
        self.amount
    }

    fn write_fields<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.unique_pubkey.write(&mut writer)?;
        self.challenge.write(&mut writer)?;
        self.signature.write(&mut writer)?;
        self.target_finalizer.write(&mut writer)?;
        write_zatoshis(self.amount, &mut writer)
    }

    fn read_fields<R: Read>(mut reader: R) -> io::Result<Self> {
        let unique_pubkey = BondId::read(&mut reader)?;
        let challenge = StakingAuthChallenge::read(&mut reader)?;
        let signature = StakingAuthSig::read(&mut reader)?;
        let target_finalizer = PubKeyId::read(&mut reader)?;
        let amount = read_zatoshis(&mut reader)?;
        Ok(CreateNewDelegationBond {
            unique_pubkey,
            challenge,
            signature,
            target_finalizer,
            amount,
        })
    }
}

/// Begins unbonding an existing delegation bond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeginDelegationUnbonding {
    pub(crate) unique_pubkey: BondId,
    pub(crate) challenge: StakingAuthChallenge,
    pub(crate) signature: StakingAuthSig,
}

impl BeginDelegationUnbonding {
    /// Constructs a [`BeginDelegationUnbonding`] action from its parts.
    pub fn new(
        unique_pubkey: BondId,
        challenge: StakingAuthChallenge,
        signature: StakingAuthSig,
    ) -> Self {
        BeginDelegationUnbonding {
            unique_pubkey,
            challenge,
            signature,
        }
    }

    /// Returns the bond identifier.
    pub fn unique_pubkey(&self) -> BondId {
        self.unique_pubkey
    }

    /// Returns the challenge.
    pub fn challenge(&self) -> StakingAuthChallenge {
        self.challenge
    }

    /// Returns the signature.
    pub fn signature(&self) -> StakingAuthSig {
        self.signature
    }

    fn write_fields<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.unique_pubkey.write(&mut writer)?;
        self.challenge.write(&mut writer)?;
        self.signature.write(&mut writer)
    }

    fn read_fields<R: Read>(mut reader: R) -> io::Result<Self> {
        let unique_pubkey = BondId::read(&mut reader)?;
        let challenge = StakingAuthChallenge::read(&mut reader)?;
        let signature = StakingAuthSig::read(&mut reader)?;
        Ok(BeginDelegationUnbonding {
            unique_pubkey,
            challenge,
            signature,
        })
    }
}

/// Withdraws value from a delegation bond that has finished unbonding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawDelegationBond {
    pub(crate) unique_pubkey: BondId,
    pub(crate) challenge: StakingAuthChallenge,
    pub(crate) signature: StakingAuthSig,
    pub(crate) amount: Zatoshis,
}

impl WithdrawDelegationBond {
    /// Constructs a [`WithdrawDelegationBond`] action from its parts.
    pub fn new(
        unique_pubkey: BondId,
        challenge: StakingAuthChallenge,
        signature: StakingAuthSig,
        amount: Zatoshis,
    ) -> Self {
        WithdrawDelegationBond {
            unique_pubkey,
            challenge,
            signature,
            amount,
        }
    }

    /// Returns the bond identifier.
    pub fn unique_pubkey(&self) -> BondId {
        self.unique_pubkey
    }

    /// Returns the challenge.
    pub fn challenge(&self) -> StakingAuthChallenge {
        self.challenge
    }

    /// Returns the signature.
    pub fn signature(&self) -> StakingAuthSig {
        self.signature
    }

    /// Returns the withdrawn amount.
    pub fn amount(&self) -> Zatoshis {
        self.amount
    }

    fn write_fields<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.unique_pubkey.write(&mut writer)?;
        self.challenge.write(&mut writer)?;
        self.signature.write(&mut writer)?;
        write_zatoshis(self.amount, &mut writer)
    }

    fn read_fields<R: Read>(mut reader: R) -> io::Result<Self> {
        let unique_pubkey = BondId::read(&mut reader)?;
        let challenge = StakingAuthChallenge::read(&mut reader)?;
        let signature = StakingAuthSig::read(&mut reader)?;
        let amount = read_zatoshis(&mut reader)?;
        Ok(WithdrawDelegationBond {
            unique_pubkey,
            challenge,
            signature,
            amount,
        })
    }
}

/// Retargets a delegation bond to a different finalizer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetargetDelegationBond {
    pub(crate) unique_pubkey: BondId,
    pub(crate) challenge: StakingAuthChallenge,
    pub(crate) signature: StakingAuthSig,
    pub(crate) target_finalizer: PubKeyId,
}

impl RetargetDelegationBond {
    /// Constructs a [`RetargetDelegationBond`] action from its parts.
    pub fn new(
        unique_pubkey: BondId,
        challenge: StakingAuthChallenge,
        signature: StakingAuthSig,
        target_finalizer: PubKeyId,
    ) -> Self {
        RetargetDelegationBond {
            unique_pubkey,
            challenge,
            signature,
            target_finalizer,
        }
    }

    /// Returns the bond identifier.
    pub fn unique_pubkey(&self) -> BondId {
        self.unique_pubkey
    }

    /// Returns the challenge.
    pub fn challenge(&self) -> StakingAuthChallenge {
        self.challenge
    }

    /// Returns the signature.
    pub fn signature(&self) -> StakingAuthSig {
        self.signature
    }

    /// Returns the finalizer key the bond is retargeted to.
    pub fn target_finalizer(&self) -> PubKeyId {
        self.target_finalizer
    }

    fn write_fields<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.unique_pubkey.write(&mut writer)?;
        self.challenge.write(&mut writer)?;
        self.signature.write(&mut writer)?;
        self.target_finalizer.write(&mut writer)
    }

    fn read_fields<R: Read>(mut reader: R) -> io::Result<Self> {
        let unique_pubkey = BondId::read(&mut reader)?;
        let challenge = StakingAuthChallenge::read(&mut reader)?;
        let signature = StakingAuthSig::read(&mut reader)?;
        let target_finalizer = PubKeyId::read(&mut reader)?;
        Ok(RetargetDelegationBond {
            unique_pubkey,
            challenge,
            signature,
            target_finalizer,
        })
    }
}

/// Registers a finalizer key. Serialization-only; no consensus semantics are defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterFinalizer {
    pub(crate) unique_pubkey: BondId,
    pub(crate) challenge: StakingAuthChallenge,
    pub(crate) signature: StakingAuthSig,
}

impl RegisterFinalizer {
    /// Constructs a [`RegisterFinalizer`] action from its parts.
    pub fn new(
        unique_pubkey: BondId,
        challenge: StakingAuthChallenge,
        signature: StakingAuthSig,
    ) -> Self {
        RegisterFinalizer {
            unique_pubkey,
            challenge,
            signature,
        }
    }

    /// Returns the bond identifier.
    pub fn unique_pubkey(&self) -> BondId {
        self.unique_pubkey
    }

    /// Returns the challenge.
    pub fn challenge(&self) -> StakingAuthChallenge {
        self.challenge
    }

    /// Returns the signature.
    pub fn signature(&self) -> StakingAuthSig {
        self.signature
    }

    fn write_fields<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.unique_pubkey.write(&mut writer)?;
        self.challenge.write(&mut writer)?;
        self.signature.write(&mut writer)
    }

    fn read_fields<R: Read>(mut reader: R) -> io::Result<Self> {
        let unique_pubkey = BondId::read(&mut reader)?;
        let challenge = StakingAuthChallenge::read(&mut reader)?;
        let signature = StakingAuthSig::read(&mut reader)?;
        Ok(RegisterFinalizer {
            unique_pubkey,
            challenge,
            signature,
        })
    }
}

/// Converts a finalizer reward into a delegation bond. Serialization-only; no consensus
/// semantics are defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConvertFinalizerRewardToDelegationBond {
    pub(crate) unique_pubkey: BondId,
    pub(crate) challenge: StakingAuthChallenge,
    pub(crate) signature: StakingAuthSig,
    pub(crate) this_finalizer: PubKeyId,
    pub(crate) amount: Zatoshis,
    pub(crate) second_challenge: StakingAuthChallenge,
    pub(crate) finalizer_signature: StakingAuthSig,
}

impl ConvertFinalizerRewardToDelegationBond {
    /// Constructs a [`ConvertFinalizerRewardToDelegationBond`] action from its parts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        unique_pubkey: BondId,
        challenge: StakingAuthChallenge,
        signature: StakingAuthSig,
        this_finalizer: PubKeyId,
        amount: Zatoshis,
        second_challenge: StakingAuthChallenge,
        finalizer_signature: StakingAuthSig,
    ) -> Self {
        ConvertFinalizerRewardToDelegationBond {
            unique_pubkey,
            challenge,
            signature,
            this_finalizer,
            amount,
            second_challenge,
            finalizer_signature,
        }
    }

    /// Returns the bond identifier.
    pub fn unique_pubkey(&self) -> BondId {
        self.unique_pubkey
    }

    /// Returns the challenge.
    pub fn challenge(&self) -> StakingAuthChallenge {
        self.challenge
    }

    /// Returns the signature.
    pub fn signature(&self) -> StakingAuthSig {
        self.signature
    }

    /// Returns the finalizer key.
    pub fn this_finalizer(&self) -> PubKeyId {
        self.this_finalizer
    }

    /// Returns the converted amount.
    pub fn amount(&self) -> Zatoshis {
        self.amount
    }

    /// Returns the second challenge.
    pub fn second_challenge(&self) -> StakingAuthChallenge {
        self.second_challenge
    }

    /// Returns the finalizer signature.
    pub fn finalizer_signature(&self) -> StakingAuthSig {
        self.finalizer_signature
    }

    fn write_fields<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.unique_pubkey.write(&mut writer)?;
        self.challenge.write(&mut writer)?;
        self.signature.write(&mut writer)?;
        self.this_finalizer.write(&mut writer)?;
        write_zatoshis(self.amount, &mut writer)?;
        self.second_challenge.write(&mut writer)?;
        self.finalizer_signature.write(&mut writer)
    }

    fn read_fields<R: Read>(mut reader: R) -> io::Result<Self> {
        let unique_pubkey = BondId::read(&mut reader)?;
        let challenge = StakingAuthChallenge::read(&mut reader)?;
        let signature = StakingAuthSig::read(&mut reader)?;
        let this_finalizer = PubKeyId::read(&mut reader)?;
        let amount = read_zatoshis(&mut reader)?;
        let second_challenge = StakingAuthChallenge::read(&mut reader)?;
        let finalizer_signature = StakingAuthSig::read(&mut reader)?;
        Ok(ConvertFinalizerRewardToDelegationBond {
            unique_pubkey,
            challenge,
            signature,
            this_finalizer,
            amount,
            second_challenge,
            finalizer_signature,
        })
    }
}

/// Updates a finalizer key. Serialization-only; no consensus semantics are defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateFinalizerKey {
    pub(crate) unique_pubkey: BondId,
    pub(crate) challenge: StakingAuthChallenge,
    pub(crate) signature: StakingAuthSig,
    pub(crate) this_finalizer: PubKeyId,
    pub(crate) second_challenge: StakingAuthChallenge,
    pub(crate) finalizer_signature: StakingAuthSig,
}

impl UpdateFinalizerKey {
    /// Constructs an [`UpdateFinalizerKey`] action from its parts.
    pub fn new(
        unique_pubkey: BondId,
        challenge: StakingAuthChallenge,
        signature: StakingAuthSig,
        this_finalizer: PubKeyId,
        second_challenge: StakingAuthChallenge,
        finalizer_signature: StakingAuthSig,
    ) -> Self {
        UpdateFinalizerKey {
            unique_pubkey,
            challenge,
            signature,
            this_finalizer,
            second_challenge,
            finalizer_signature,
        }
    }

    /// Returns the bond identifier.
    pub fn unique_pubkey(&self) -> BondId {
        self.unique_pubkey
    }

    /// Returns the challenge.
    pub fn challenge(&self) -> StakingAuthChallenge {
        self.challenge
    }

    /// Returns the signature.
    pub fn signature(&self) -> StakingAuthSig {
        self.signature
    }

    /// Returns the finalizer key.
    pub fn this_finalizer(&self) -> PubKeyId {
        self.this_finalizer
    }

    /// Returns the second challenge.
    pub fn second_challenge(&self) -> StakingAuthChallenge {
        self.second_challenge
    }

    /// Returns the finalizer signature.
    pub fn finalizer_signature(&self) -> StakingAuthSig {
        self.finalizer_signature
    }

    fn write_fields<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.unique_pubkey.write(&mut writer)?;
        self.challenge.write(&mut writer)?;
        self.signature.write(&mut writer)?;
        self.this_finalizer.write(&mut writer)?;
        self.second_challenge.write(&mut writer)?;
        self.finalizer_signature.write(&mut writer)
    }

    fn read_fields<R: Read>(mut reader: R) -> io::Result<Self> {
        let unique_pubkey = BondId::read(&mut reader)?;
        let challenge = StakingAuthChallenge::read(&mut reader)?;
        let signature = StakingAuthSig::read(&mut reader)?;
        let this_finalizer = PubKeyId::read(&mut reader)?;
        let second_challenge = StakingAuthChallenge::read(&mut reader)?;
        let finalizer_signature = StakingAuthSig::read(&mut reader)?;
        Ok(UpdateFinalizerKey {
            unique_pubkey,
            challenge,
            signature,
            this_finalizer,
            second_challenge,
            finalizer_signature,
        })
    }
}

/// The kind of a [`StakingAction`], without its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StakingActionKind {
    /// See [`CreateNewDelegationBond`].
    CreateNewDelegationBond,
    /// See [`BeginDelegationUnbonding`].
    BeginDelegationUnbonding,
    /// See [`WithdrawDelegationBond`].
    WithdrawDelegationBond,
    /// See [`RetargetDelegationBond`].
    RetargetDelegationBond,
    /// See [`RegisterFinalizer`].
    RegisterFinalizer,
    /// See [`ConvertFinalizerRewardToDelegationBond`].
    ConvertFinalizerRewardToDelegationBond,
    /// See [`UpdateFinalizerKey`].
    UpdateFinalizerKey,
}

/// A staking action carried by a version 7 (VCrosslink) transaction.
///
/// The `challenge` and `signature` values carried by each variant are committed to by the
/// transaction identifier but are not verified by consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StakingAction {
    /// See [`CreateNewDelegationBond`].
    CreateNewDelegationBond(CreateNewDelegationBond),
    /// See [`BeginDelegationUnbonding`].
    BeginDelegationUnbonding(BeginDelegationUnbonding),
    /// See [`WithdrawDelegationBond`].
    WithdrawDelegationBond(WithdrawDelegationBond),
    /// See [`RetargetDelegationBond`].
    RetargetDelegationBond(RetargetDelegationBond),
    /// See [`RegisterFinalizer`].
    RegisterFinalizer(RegisterFinalizer),
    /// See [`ConvertFinalizerRewardToDelegationBond`].
    ConvertFinalizerRewardToDelegationBond(ConvertFinalizerRewardToDelegationBond),
    /// See [`UpdateFinalizerKey`].
    UpdateFinalizerKey(UpdateFinalizerKey),
}

impl StakingAction {
    /// Returns the kind of this action.
    pub fn kind(&self) -> StakingActionKind {
        match self {
            StakingAction::CreateNewDelegationBond(_) => StakingActionKind::CreateNewDelegationBond,
            StakingAction::BeginDelegationUnbonding(_) => {
                StakingActionKind::BeginDelegationUnbonding
            }
            StakingAction::WithdrawDelegationBond(_) => StakingActionKind::WithdrawDelegationBond,
            StakingAction::RetargetDelegationBond(_) => StakingActionKind::RetargetDelegationBond,
            StakingAction::RegisterFinalizer(_) => StakingActionKind::RegisterFinalizer,
            StakingAction::ConvertFinalizerRewardToDelegationBond(_) => {
                StakingActionKind::ConvertFinalizerRewardToDelegationBond
            }
            StakingAction::UpdateFinalizerKey(_) => StakingActionKind::UpdateFinalizerKey,
        }
    }

    /// Returns the signed value this action moves in or out of the transaction's value balance.
    pub(crate) fn value_balance_contribution(&self) -> ZatBalance {
        match self {
            StakingAction::CreateNewDelegationBond(a) => -ZatBalance::from(a.amount),
            StakingAction::WithdrawDelegationBond(a) => ZatBalance::from(a.amount),
            _ => ZatBalance::zero(),
        }
    }

    pub(crate) fn write_body<W: Write>(&self, mut writer: W) -> io::Result<()> {
        match self {
            StakingAction::CreateNewDelegationBond(a) => {
                writer.write_u8(TAG_CREATE_NEW_DELEGATION_BOND)?;
                a.write_fields(writer)
            }
            StakingAction::BeginDelegationUnbonding(a) => {
                writer.write_u8(TAG_BEGIN_DELEGATION_UNBONDING)?;
                a.write_fields(writer)
            }
            StakingAction::WithdrawDelegationBond(a) => {
                writer.write_u8(TAG_WITHDRAW_DELEGATION_BOND)?;
                a.write_fields(writer)
            }
            StakingAction::RetargetDelegationBond(a) => {
                writer.write_u8(TAG_RETARGET_DELEGATION_BOND)?;
                a.write_fields(writer)
            }
            StakingAction::RegisterFinalizer(a) => {
                writer.write_u8(TAG_REGISTER_FINALIZER)?;
                a.write_fields(writer)
            }
            StakingAction::ConvertFinalizerRewardToDelegationBond(a) => {
                writer.write_u8(TAG_CONVERT_FINALIZER_REWARD_TO_DELEGATION_BOND)?;
                a.write_fields(writer)
            }
            StakingAction::UpdateFinalizerKey(a) => {
                writer.write_u8(TAG_UPDATE_FINALIZER_KEY)?;
                a.write_fields(writer)
            }
        }
    }

    /// Serializes an optional staking action, using a single leading tag byte.
    pub fn write<W: Write>(action: &Option<StakingAction>, mut writer: W) -> io::Result<()> {
        match action {
            None => writer.write_u8(TAG_ABSENT),
            Some(action) => action.write_body(writer),
        }
    }

    /// Deserializes an optional staking action from its single leading tag byte and body.
    ///
    /// Returns `Ok(None)` for the absence tag, and an error for an unknown tag.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Option<StakingAction>> {
        let tag = reader.read_u8()?;
        Ok(match tag {
            TAG_ABSENT => None,
            TAG_CREATE_NEW_DELEGATION_BOND => Some(StakingAction::CreateNewDelegationBond(
                CreateNewDelegationBond::read_fields(reader)?,
            )),
            TAG_BEGIN_DELEGATION_UNBONDING => Some(StakingAction::BeginDelegationUnbonding(
                BeginDelegationUnbonding::read_fields(reader)?,
            )),
            TAG_WITHDRAW_DELEGATION_BOND => Some(StakingAction::WithdrawDelegationBond(
                WithdrawDelegationBond::read_fields(reader)?,
            )),
            TAG_RETARGET_DELEGATION_BOND => Some(StakingAction::RetargetDelegationBond(
                RetargetDelegationBond::read_fields(reader)?,
            )),
            TAG_REGISTER_FINALIZER => Some(StakingAction::RegisterFinalizer(
                RegisterFinalizer::read_fields(reader)?,
            )),
            TAG_CONVERT_FINALIZER_REWARD_TO_DELEGATION_BOND => {
                Some(StakingAction::ConvertFinalizerRewardToDelegationBond(
                    ConvertFinalizerRewardToDelegationBond::read_fields(reader)?,
                ))
            }
            TAG_UPDATE_FINALIZER_KEY => Some(StakingAction::UpdateFinalizerKey(
                UpdateFinalizerKey::read_fields(reader)?,
            )),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown staking action kind",
                ));
            }
        })
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use bft_primitives::testing::arb_pub_key_id;
    use zcash_protocol::value::testing::arb_zatoshis;

    use super::{
        BeginDelegationUnbonding, BondId, ConvertFinalizerRewardToDelegationBond,
        CreateNewDelegationBond, RegisterFinalizer, RetargetDelegationBond, StakingAction,
        StakingAuthChallenge, StakingAuthSig, UpdateFinalizerKey, WithdrawDelegationBond,
    };

    prop_compose! {
        /// Generates an arbitrary [`BondId`].
        pub fn arb_bond_id()(bytes in any::<[u8; 32]>()) -> BondId {
            BondId::from_bytes(bytes)
        }
    }

    prop_compose! {
        /// Generates an arbitrary [`StakingAuthChallenge`].
        pub fn arb_staking_auth_challenge()(bytes in any::<[u8; 32]>()) -> StakingAuthChallenge {
            StakingAuthChallenge::from_bytes(bytes)
        }
    }

    prop_compose! {
        /// Generates an arbitrary [`StakingAuthSig`].
        pub fn arb_staking_auth_sig()(bytes in any::<[u8; 64]>()) -> StakingAuthSig {
            StakingAuthSig::from_bytes(bytes)
        }
    }

    /// Generates an arbitrary [`StakingAction`] of any kind.
    pub fn arb_staking_action() -> impl Strategy<Value = StakingAction> {
        prop_oneof![
            (
                arb_bond_id(),
                arb_staking_auth_challenge(),
                arb_staking_auth_sig(),
                arb_pub_key_id(),
                arb_zatoshis(),
            )
                .prop_map(|(u, c, s, f, a)| StakingAction::CreateNewDelegationBond(
                    CreateNewDelegationBond::new(u, c, s, f, a)
                )),
            (
                arb_bond_id(),
                arb_staking_auth_challenge(),
                arb_staking_auth_sig()
            )
                .prop_map(|(u, c, s)| StakingAction::BeginDelegationUnbonding(
                    BeginDelegationUnbonding::new(u, c, s)
                )),
            (
                arb_bond_id(),
                arb_staking_auth_challenge(),
                arb_staking_auth_sig(),
                arb_zatoshis(),
            )
                .prop_map(|(u, c, s, a)| StakingAction::WithdrawDelegationBond(
                    WithdrawDelegationBond::new(u, c, s, a)
                )),
            (
                arb_bond_id(),
                arb_staking_auth_challenge(),
                arb_staking_auth_sig(),
                arb_pub_key_id(),
            )
                .prop_map(|(u, c, s, f)| StakingAction::RetargetDelegationBond(
                    RetargetDelegationBond::new(u, c, s, f)
                )),
            (
                arb_bond_id(),
                arb_staking_auth_challenge(),
                arb_staking_auth_sig()
            )
                .prop_map(|(u, c, s)| StakingAction::RegisterFinalizer(
                    RegisterFinalizer::new(u, c, s)
                )),
            (
                arb_bond_id(),
                arb_staking_auth_challenge(),
                arb_staking_auth_sig(),
                arb_pub_key_id(),
                arb_zatoshis(),
                arb_staking_auth_challenge(),
                arb_staking_auth_sig(),
            )
                .prop_map(|(u, c, s, f, a, c2, s2)| {
                    StakingAction::ConvertFinalizerRewardToDelegationBond(
                        ConvertFinalizerRewardToDelegationBond::new(u, c, s, f, a, c2, s2),
                    )
                }),
            (
                arb_bond_id(),
                arb_staking_auth_challenge(),
                arb_staking_auth_sig(),
                arb_pub_key_id(),
                arb_staking_auth_challenge(),
                arb_staking_auth_sig(),
            )
                .prop_map(|(u, c, s, f, c2, s2)| StakingAction::UpdateFinalizerKey(
                    UpdateFinalizerKey::new(u, c, s, f, c2, s2)
                )),
        ]
    }

    /// Generates an arbitrary optional [`StakingAction`], including the absence case.
    pub fn arb_optional_staking_action() -> impl Strategy<Value = Option<StakingAction>> {
        prop_oneof![
            1 => Just(None),
            7 => arb_staking_action().prop_map(Some),
        ]
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{StakingAction, testing::arb_optional_staking_action};

    proptest! {
        #[test]
        fn staking_action_round_trip(action in arb_optional_staking_action()) {
            let mut bytes = alloc::vec::Vec::new();
            StakingAction::write(&action, &mut bytes).unwrap();
            let decoded = StakingAction::read(&bytes[..]).unwrap();
            prop_assert_eq!(action, decoded);
        }
    }
}

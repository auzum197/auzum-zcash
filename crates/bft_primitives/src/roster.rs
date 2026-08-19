//! Staking roster state.

use alloc::vec::Vec;

use corez::io::{self, Read, Write};
use zcash_protocol::{TxId, value::Zatoshis};

use crate::{
    encoding::{ReadBytesExt, WriteBytesExt},
    keys::PubKeyId,
};

/// A staking transaction backing part of a roster member's voting power.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeTxId {
    pub(crate) txid: TxId,
    pub(crate) zats: Zatoshis,
}

impl StakeTxId {
    /// Constructs an entry from its parts. `zats` is the accumulated value, not the
    /// initial bond value.
    pub fn new(txid: TxId, zats: Zatoshis) -> Self {
        Self { txid, zats }
    }

    /// Returns the staking transaction id.
    pub fn txid(&self) -> &TxId {
        &self.txid
    }

    /// Returns the accumulated value of the stake.
    pub fn zats(&self) -> Zatoshis {
        self.zats
    }

    /// Reads an entry as a 32-byte txid followed by an 8-byte little-endian amount.
    ///
    /// Amounts above `MAX_MONEY` are rejected; they cannot appear in
    /// honestly-produced chain data.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut txid = [0u8; 32];
        reader.read_exact(&mut txid)?;
        let zats = read_zatoshis(&mut reader)?;
        Ok(Self {
            txid: TxId::from_bytes(txid),
            zats,
        })
    }

    /// Writes this entry.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.txid.as_ref())?;
        (&mut writer).write_u64_le(u64::from(self.zats))
    }
}

/// One finalizer's entry in the staking roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterMember {
    pub(crate) pub_key: PubKeyId,
    pub(crate) voting_power: Zatoshis,
    pub(crate) txids: Vec<StakeTxId>,
}

impl RosterMember {
    /// Constructs a roster member from its parts.
    pub fn new(pub_key: PubKeyId, voting_power: Zatoshis, txids: Vec<StakeTxId>) -> Self {
        Self {
            pub_key,
            voting_power,
            txids,
        }
    }

    /// Returns the finalizer's public key.
    pub fn pub_key(&self) -> &PubKeyId {
        &self.pub_key
    }

    /// Returns the finalizer's voting power.
    pub fn voting_power(&self) -> Zatoshis {
        self.voting_power
    }

    /// Returns the staking transactions backing this member's voting power.
    pub fn txids(&self) -> &[StakeTxId] {
        &self.txids
    }

    /// Reads a roster member as a 32-byte key, an 8-byte little-endian voting power,
    /// an 8-byte little-endian entry count, and the entries.
    ///
    /// Amounts above `MAX_MONEY` are rejected; they cannot appear in
    /// honestly-produced chain data.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let pub_key = PubKeyId::read(&mut reader)?;
        let voting_power = read_zatoshis(&mut reader)?;
        let count = (&mut reader).read_u64_le()?;
        let mut txids = Vec::new();
        for _ in 0..count {
            txids.push(StakeTxId::read(&mut reader)?);
        }
        Ok(Self {
            pub_key,
            voting_power,
            txids,
        })
    }

    /// Writes this roster member.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.pub_key.write(&mut writer)?;
        (&mut writer).write_u64_le(u64::from(self.voting_power))?;
        (&mut writer).write_u64_le(self.txids.len() as u64)?;
        for txid in &self.txids {
            txid.write(&mut writer)?;
        }
        Ok(())
    }
}

/// Reads an 8-byte little-endian amount as [`Zatoshis`].
fn read_zatoshis<R: Read>(mut reader: R) -> io::Result<Zatoshis> {
    let zats = (&mut reader).read_u64_le()?;
    Zatoshis::from_u64(zats)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "amount out of range"))
}

#[cfg(feature = "serde")]
mod serde_impls {
    use alloc::string::String;
    use alloc::vec::Vec;

    use serde::{Deserialize, Serialize};
    use zcash_protocol::{TxId, value::Zatoshis};

    use super::{RosterMember, StakeTxId};
    use crate::keys::{PUB_KEY_ID_BYTES, PubKeyId};

    fn decode_hex_32<'de, D>(hex_str: &str) -> Result<[u8; 32], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes).map_err(serde::de::Error::custom)?;
        Ok(bytes)
    }

    fn zatoshis_from_u64<'de, D>(zats: u64) -> Result<Zatoshis, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Zatoshis::from_u64(zats).map_err(serde::de::Error::custom)
    }

    #[derive(Serialize, Deserialize)]
    struct StakeTxIdRepr {
        txid: String,
        zats: u64,
    }

    #[derive(Serialize, Deserialize)]
    struct RosterMemberRepr {
        pub_key: String,
        voting_power: u64,
        txids: Vec<StakeTxIdRepr>,
    }

    impl Serialize for StakeTxId {
        /// Serializes the txid as a hex string of its raw bytes.
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            StakeTxIdRepr {
                txid: hex::encode(self.txid.as_ref()),
                zats: u64::from(self.zats),
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for StakeTxId {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let repr = StakeTxIdRepr::deserialize(deserializer)?;
            Ok(Self {
                txid: TxId::from_bytes(decode_hex_32::<D>(&repr.txid)?),
                zats: zatoshis_from_u64::<D>(repr.zats)?,
            })
        }
    }

    impl Serialize for RosterMember {
        /// Serializes the public key as a hex string of its raw bytes.
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            RosterMemberRepr {
                pub_key: hex::encode(self.pub_key.as_bytes()),
                voting_power: u64::from(self.voting_power),
                txids: self
                    .txids
                    .iter()
                    .map(|entry| StakeTxIdRepr {
                        txid: hex::encode(entry.txid.as_ref()),
                        zats: u64::from(entry.zats),
                    })
                    .collect(),
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for RosterMember {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let repr = RosterMemberRepr::deserialize(deserializer)?;
            let pub_key: [u8; PUB_KEY_ID_BYTES] = decode_hex_32::<D>(&repr.pub_key)?;
            Ok(Self {
                pub_key: PubKeyId::from_bytes(pub_key),
                voting_power: zatoshis_from_u64::<D>(repr.voting_power)?,
                txids: repr
                    .txids
                    .into_iter()
                    .map(|entry| {
                        Ok(StakeTxId {
                            txid: TxId::from_bytes(decode_hex_32::<D>(&entry.txid)?),
                            zats: zatoshis_from_u64::<D>(entry.zats)?,
                        })
                    })
                    .collect::<Result<Vec<_>, D::Error>>()?,
            })
        }
    }
}

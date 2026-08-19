//! User-led hardfork rules carried in BFT blocks.

use alloc::vec::Vec;

use corez::io::{self, Read, Write};
use snafu::Snafu;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    encoding::{ReadBytesExt, WriteBytesExt},
    height::BftHeight,
    keys::PubKeyId,
};

/// Upper bound on `terminated_finalizers` accepted by [`HardForkConfig::read`].
pub const MAX_TERMINATED_FINALIZERS: u32 = 4096;

/// The hardfork rule is not well formed.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum InvalidHardForkConfig {
    /// The rule must terminate at least one finalizer.
    #[snafu(display("`terminated_finalizers` must list at least one finalizer"))]
    NoTerminatedFinalizers,
    /// The rule lists the same finalizer more than once.
    #[snafu(display("`terminated_finalizers` contains duplicate finalizer {finalizer}"))]
    DuplicateFinalizer {
        /// The duplicated finalizer.
        finalizer: PubKeyId,
    },
}

/// A single user-led hardfork rule.
///
/// The serialized form is an 8-byte little-endian PoW activation height, an 8-byte
/// little-endian BFT certificate height, a 4-byte little-endian count, and the
/// 32-byte terminated finalizer keys. It is committed to by the containing block's
/// hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardForkConfig {
    pub(crate) pow_activation_height: BlockHeight,
    pub(crate) bft_certificate_height: BftHeight,
    pub(crate) terminated_finalizers: Vec<PubKeyId>,
}

impl HardForkConfig {
    /// Constructs a hardfork rule, sorting `terminated_finalizers` into canonical
    /// (ascending key byte) order.
    ///
    /// # Errors
    ///
    /// Returns an error if the list is empty or contains duplicates.
    pub fn new(
        pow_activation_height: BlockHeight,
        bft_certificate_height: BftHeight,
        mut terminated_finalizers: Vec<PubKeyId>,
    ) -> Result<Self, InvalidHardForkConfig> {
        if terminated_finalizers.is_empty() {
            return Err(InvalidHardForkConfig::NoTerminatedFinalizers);
        }
        terminated_finalizers.sort_unstable();
        for pair in terminated_finalizers.windows(2) {
            if pair[0] == pair[1] {
                return Err(InvalidHardForkConfig::DuplicateFinalizer { finalizer: pair[0] });
            }
        }
        Ok(Self {
            pow_activation_height,
            bft_certificate_height,
            terminated_finalizers,
        })
    }

    /// Returns the PoW block height at which this hardfork activates.
    pub fn pow_activation_height(&self) -> BlockHeight {
        self.pow_activation_height
    }

    /// Returns the BFT certificate height at which this hardfork activates.
    pub fn bft_certificate_height(&self) -> BftHeight {
        self.bft_certificate_height
    }

    /// Returns the finalizers terminated by this hardfork.
    pub fn terminated_finalizers(&self) -> &[PubKeyId] {
        &self.terminated_finalizers
    }

    /// Reads a hardfork rule.
    ///
    /// This parse accepts an empty or unsorted finalizer list; the ordering and
    /// non-emptiness invariants are enforced only by [`HardForkConfig::new`]. The
    /// serialized heights must fit in `u32`; larger values are rejected as they
    /// cannot appear in honestly-produced chain data.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let pow_activation_height = read_block_height_u64(&mut reader)?;
        let bft_certificate_height = crate::vote::read_height_u64(&mut reader)?;
        let count = (&mut reader).read_u32_le()?;
        if count > MAX_TERMINATED_FINALIZERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "terminated_finalizers count exceeds maximum",
            ));
        }
        let mut terminated_finalizers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            terminated_finalizers.push(PubKeyId::read(&mut reader)?);
        }
        Ok(Self {
            pow_activation_height,
            bft_certificate_height,
            terminated_finalizers,
        })
    }

    /// Writes this hardfork rule.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        (&mut writer).write_u64_le(u64::from(u32::from(self.pow_activation_height)))?;
        (&mut writer).write_u64_le(u64::from(self.bft_certificate_height))?;
        let count = u32::try_from(self.terminated_finalizers.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too many finalizers"))?;
        (&mut writer).write_u32_le(count)?;
        for finalizer in &self.terminated_finalizers {
            finalizer.write(&mut writer)?;
        }
        Ok(())
    }
}

/// Reads an 8-byte little-endian PoW height and narrows it to [`BlockHeight`],
/// rejecting values above `u32::MAX` as they cannot appear in honestly-produced
/// chain data.
fn read_block_height_u64<R: Read>(mut reader: R) -> io::Result<BlockHeight> {
    let height = (&mut reader).read_u64_le()?;
    let height = u32::try_from(height)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "PoW height out of range"))?;
    Ok(BlockHeight::from_u32(height))
}

#[cfg(feature = "serde")]
mod serde_impls {
    use alloc::format;
    use alloc::vec::Vec;

    use serde::{Deserialize, Serialize};
    use zcash_protocol::consensus::BlockHeight;

    use super::HardForkConfig;
    use crate::{height::BftHeight, keys::PubKeyId};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HardForkConfigRepr {
        pow_activation_height: u64,
        bft_certificate_height: u64,
        terminated_finalizers: Vec<PubKeyId>,
    }

    impl Serialize for HardForkConfig {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            HardForkConfigRepr {
                pow_activation_height: u64::from(u32::from(self.pow_activation_height)),
                bft_certificate_height: u64::from(self.bft_certificate_height),
                terminated_finalizers: self.terminated_finalizers.clone(),
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for HardForkConfig {
        /// Deserializes with validation: `pow_activation_height` must be a nonzero
        /// multiple of the staking period, and `terminated_finalizers` must be
        /// non-empty without duplicates.
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::Error;

            let repr = HardForkConfigRepr::deserialize(deserializer)?;

            #[cfg(zcash_unstable = "crosslink")]
            {
                let period = u64::from(zcash_protocol::constants::STAKING_PERIOD);
                if repr.pow_activation_height == 0 {
                    return Err(D::Error::custom(format!(
                        "`pow_activation_height` must be greater than zero and a multiple of the staking period ({period})"
                    )));
                }
                if repr.pow_activation_height % period != 0 {
                    return Err(D::Error::custom(format!(
                        "`pow_activation_height` must be a multiple of the staking period ({period}); got {} (nearest valid: {} or {})",
                        repr.pow_activation_height,
                        repr.pow_activation_height / period * period,
                        (repr.pow_activation_height / period + 1) * period,
                    )));
                }
            }

            if repr.terminated_finalizers.is_empty() {
                return Err(D::Error::custom(
                    "`terminated_finalizers` must list at least one finalizer",
                ));
            }
            let mut seen: Vec<&PubKeyId> = Vec::with_capacity(repr.terminated_finalizers.len());
            for finalizer in &repr.terminated_finalizers {
                if seen.contains(&finalizer) {
                    return Err(D::Error::custom(format!(
                        "`terminated_finalizers` contains duplicate finalizer \"{finalizer}\", which was already specified"
                    )));
                }
                seen.push(finalizer);
            }

            let pow_activation_height = u32::try_from(repr.pow_activation_height)
                .map_err(|_| D::Error::custom("`pow_activation_height` out of range"))?;
            let bft_certificate_height = u32::try_from(repr.bft_certificate_height)
                .map_err(|_| D::Error::custom("`bft_certificate_height` out of range"))?;

            Ok(Self {
                pow_activation_height: BlockHeight::from_u32(pow_activation_height),
                bft_certificate_height: BftHeight::new(bft_certificate_height),
                terminated_finalizers: repr.terminated_finalizers,
            })
        }
    }
}

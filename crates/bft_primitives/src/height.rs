//! Heights on the BFT chain.

use core::fmt;

/// The 0-based position of a block on the BFT chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct BftHeight(pub(crate) u32);

impl BftHeight {
    /// The height of the first block on the BFT chain.
    pub const ZERO: Self = Self(0);

    /// Constructs a height from its numeric value.
    pub const fn new(height: u32) -> Self {
        Self(height)
    }
}

impl From<u32> for BftHeight {
    fn from(height: u32) -> Self {
        Self(height)
    }
}

impl From<BftHeight> for u32 {
    fn from(height: BftHeight) -> Self {
        height.0
    }
}

impl From<BftHeight> for u64 {
    fn from(height: BftHeight) -> Self {
        u64::from(height.0)
    }
}

impl fmt::Display for BftHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

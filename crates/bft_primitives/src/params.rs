//! Crosslink protocol parameters.

use snafu::Snafu;

/// The parameters are not internally consistent.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum InvalidParameters {
    /// The confirmation depth must be at least one.
    #[snafu(display("the confirmation depth sigma must be at least 1"))]
    ZeroConfirmationDepth,
    /// The finalization gap bound must be at least twice the confirmation depth.
    #[snafu(display(
        "the finalization gap bound {gap} is below twice the confirmation depth {sigma}"
    ))]
    GapBelowTwiceSigma {
        /// The confirmation depth.
        sigma: u64,
        /// The rejected gap bound.
        gap: u64,
    },
}

/// Zcash Crosslink protocol parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZcashCrosslinkParameters {
    pub(crate) bc_confirmation_depth_sigma: u64,
    pub(crate) finalization_gap_bound: u64,
}

impl ZcashCrosslinkParameters {
    /// Constructs parameters, requiring `sigma >= 1` and
    /// `finalization_gap_bound >= 2 * sigma`.
    pub fn new(
        bc_confirmation_depth_sigma: u64,
        finalization_gap_bound: u64,
    ) -> Result<Self, InvalidParameters> {
        if bc_confirmation_depth_sigma == 0 {
            return Err(InvalidParameters::ZeroConfirmationDepth);
        }
        if finalization_gap_bound < 2 * bc_confirmation_depth_sigma {
            return Err(InvalidParameters::GapBelowTwiceSigma {
                sigma: bc_confirmation_depth_sigma,
                gap: finalization_gap_bound,
            });
        }
        Ok(Self {
            bc_confirmation_depth_sigma,
            finalization_gap_bound,
        })
    }

    /// The best-chain confirmation depth, sigma: the number of PoW headers each BFT
    /// block carries.
    pub fn bc_confirmation_depth_sigma(&self) -> u64 {
        self.bc_confirmation_depth_sigma
    }

    /// The depth of unfinalized PoW blocks past which Stalled Mode activates.
    pub fn finalization_gap_bound(&self) -> u64 {
        self.finalization_gap_bound
    }
}

/// Crosslink parameters chosen for prototyping and testing.
///
/// <div class="warning">No verification has been done on the security or performance
/// of these parameters.</div>
pub const PROTOTYPE_PARAMETERS: ZcashCrosslinkParameters = ZcashCrosslinkParameters {
    bc_confirmation_depth_sigma: 3,
    finalization_gap_bound: 7,
};

/// Equihash proof-of-work parameters used when validating PoW headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EquihashParameters {
    pub(crate) n: u32,
    pub(crate) k: u32,
}

impl EquihashParameters {
    /// The Equihash parameters used in Zcash production networks (`n = 200, k = 9`).
    pub const ZCASH: Self = Self { n: 200, k: 9 };

    /// Constructs Equihash parameters.
    pub const fn new(n: u32, k: u32) -> Self {
        Self { n, k }
    }

    /// The Equihash `n` parameter.
    pub fn n(&self) -> u32 {
        self.n
    }

    /// The Equihash `k` parameter.
    pub fn k(&self) -> u32 {
        self.k
    }
}

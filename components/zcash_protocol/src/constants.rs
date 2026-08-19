//! Network-specific Zcash constants.

pub mod mainnet;
pub mod regtest;
pub mod testnet;

#[cfg(zcash_unstable = "crosslink")]
use crate::consensus::BlockHeight;

// The `V<n>_TX_VERSION` constants, although trivial, serve to clarify that a
// transaction version is meant in APIs that use a bare `u32`. Consider using
// `zcash_primitives::transaction::TxVersion` instead.

/// Transaction version 3, which was introduced by the Overwinter network upgrade
/// and allowed until Sapling activation. It is specified in
/// [§ 7.1 Transaction Encoding and Consensus](https://zips.z.cash/protocol/protocol.pdf#txnencoding).
///
/// This constant is called `OVERWINTER_TX_VERSION` in the zcashd source.
pub const V3_TX_VERSION: u32 = 3;
/// The version group ID for Zcash v3 transactions.
///
/// This constant is called `OVERWINTER_VERSION_GROUP_ID` in the zcashd source.
pub const V3_VERSION_GROUP_ID: u32 = 0x03C48270;

/// Transaction version 4, which was introduced by the Sapling network upgrade.
/// It is specified in [§ 7.1 Transaction Encoding and Consensus](https://zips.z.cash/protocol/protocol.pdf#txnencoding).
///
/// This constant is called `SAPLING_TX_VERSION` in the zcashd source.
pub const V4_TX_VERSION: u32 = 4;
/// The version group ID for Zcash v4 transactions.
///
/// This constant is called `SAPLING_VERSION_GROUP_ID` in the zcashd source.
pub const V4_VERSION_GROUP_ID: u32 = 0x892F2085;

/// Transaction version 5, which was introduced by the NU5 network upgrade.
/// It is specified in [§ 7.1 Transaction Encoding and Consensus](https://zips.z.cash/protocol/protocol.pdf#txnencoding)
/// and [ZIP 225](https://zips.z.cash/zip-0225).
pub const V5_TX_VERSION: u32 = 5;
/// The version group ID for Zcash v5 transactions.
pub const V5_VERSION_GROUP_ID: u32 = 0x26A7270A;

/// Transaction version 6, specified in [ZIP 229](https://zips.z.cash/zip-0229).
pub const V6_TX_VERSION: u32 = 6;
/// The version group ID for Zcash v6 transactions.
pub const V6_VERSION_GROUP_ID: u32 = 0xD884B698;

/// Transaction version 7 (`VCrosslink`). Gated behind the `zcash_unstable = "crosslink"`
/// cfg flag. It has no mainnet activation height.
#[cfg(zcash_unstable = "crosslink")]
pub const VCROSSLINK_TX_VERSION: u32 = 7;
/// The version group ID for Zcash `VCrosslink` transactions.
#[cfg(zcash_unstable = "crosslink")]
pub const VCROSSLINK_VERSION_GROUP_ID: u32 = 0xFFFF_FFFE;

/// The number of blocks between the start of one staking day and the start of the next.
///
/// This is a prototype value that is not yet finalized.
#[cfg(zcash_unstable = "crosslink")]
pub const STAKING_PERIOD: u32 = 150;

/// The width, in blocks, of the window at the start of each staking day during which
/// staking actions are permitted. A staking action is valid only at a height where
/// `height % STAKING_PERIOD < STAKING_DAY_WINDOW`; see [`is_in_staking_day_window`].
///
/// This is a prototype value that is not yet finalized.
#[cfg(zcash_unstable = "crosslink")]
pub const STAKING_DAY_WINDOW: u32 = 70;

/// The number of blocks behind the chain tip within which a bond remains eligible for
/// slashing analysis.
///
/// This is a prototype value that is not yet finalized.
#[cfg(zcash_unstable = "crosslink")]
pub const SLASH_ANALYSIS_WINDOW: u32 = 2 * STAKING_PERIOD;

/// Returns `true` if a staking action is permitted at the given block height.
///
/// A staking action is valid exactly when `height % STAKING_PERIOD < STAKING_DAY_WINDOW`.
/// The transaction builder does not consult this.
#[cfg(zcash_unstable = "crosslink")]
pub fn is_in_staking_day_window(height: BlockHeight) -> bool {
    u32::from(height) % STAKING_PERIOD < STAKING_DAY_WINDOW
}

/// The maximum size in bytes of a Zcash block, and therefore the maximum size of any single
/// transaction within one.
///
/// It is specified as `MAX_BLOCK_SIZE` in
/// [§ 7.6 Block Header Encoding and Consensus](https://zips.z.cash/protocol/protocol.pdf#blockheader).
///
/// This constant is called `MAX_BLOCK_SIZE` in the zcashd source.
pub const MAX_BLOCK_BYTES: usize = 2_000_000;

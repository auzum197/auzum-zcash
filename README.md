# Zcash Rust crates

This repository contains Rust crates for working with Zcash Crosslink,
including BFT consensus data and staking transactions.

⚠️ IMPORTANT: The only way to check Zcash consensus validity is to use a Zcash
consensus node. ⚠️

The public API surfaces of these crates include many APIs that are used by the
zcashd and Zebra node implementations, as well as other critical components in
the Zcash ecosystem, but none of them expose any way to check consensus validity
of transactions. In particular, APIs for parsing transactions only check a subset
of validity constraints. The specific subset they check is not sufficient to
guarantee any meaningful user-level validity constraints, and is not necessarily
stable over time, or consistent with other implementations of parsers for Zcash
transactions.

<!-- START mermaid-dependency-graph -->

```mermaid
graph TB
    subgraph workspace
        bft_primitives
        zcash_primitives
        zcash_protocol
    end

    subgraph published_zcash_crates
        equihash
        zcash_address
        zcash_encoding
        zcash_transparent
    end

    subgraph shielded_protocols
        sapling-crypto
        orchard
    end

    subgraph protocol_components
        zcash_note_encryption
        zip32
        zcash_spec
    end

    zcash_primitives --> bft_primitives
    zcash_primitives --> zcash_transparent
    %% zcash_primitives --> zcash_protocol
    %% zcash_primitives --> zcash_encoding

    bft_primitives --> equihash
    bft_primitives --> zcash_encoding
    bft_primitives --> zcash_protocol

    zcash_protocol --> zcash_encoding

    zcash_primitives --> equihash
    zcash_primitives --> orchard
    zcash_primitives --> sapling-crypto
    zcash_primitives --> zcash_note_encryption

    zcash_transparent --> zcash_address
    zcash_transparent --> zcash_encoding
    zcash_transparent --> zcash_protocol
    zcash_transparent --> zcash_spec
    zcash_transparent --> zip32

    zcash_address --> zcash_encoding
    zcash_address --> zcash_protocol

    orchard --> zcash_note_encryption
    sapling-crypto --> zcash_note_encryption
    orchard --> zip32
    sapling-crypto --> zip32

    orchard --> zcash_spec
    sapling-crypto --> zcash_spec
    zip32 --> zcash_spec

    click equihash "https://docs.rs/equihash/" _blank
    click bft_primitives "https://docs.rs/bft_primitives/" _blank
    click orchard "https://docs.rs/orchard/" _blank
    click sapling-crypto "https://docs.rs/sapling-crypto/" _blank
    click zcash_address "https://docs.rs/zcash_address/" _blank
    click zcash_encoding "https://docs.rs/zcash_encoding/" _blank
    click zcash_note_encryption "https://docs.rs/zcash_note_encryption/" _blank
    click zcash_primitives "https://docs.rs/zcash_primitives/" _blank
    click zcash_protocol "https://docs.rs/zcash_protocol/" _blank
    click zcash_spec "https://docs.rs/zcash_spec/" _blank
    click zcash_transparent "https://docs.rs/zcash_transparent/" _blank
    click zip32 "https://docs.rs/zip32/" _blank
```

<!-- END mermaid-dependency-graph -->

## Workspace crates

* `zcash_protocol`: Network constants and common protocol types
  - consensus parameters and network upgrades, including Crosslink
  - bounded value types and memos
  - staking timing parameters
* `bft_primitives`: Crosslink BFT data types
  - BFT blocks, votes, fat pointers, hard forks, and staking rosters
  - canonical binary encoding and signature verification
* `zcash_primitives`: Transaction construction and serialization
  - legacy and VCrosslink transaction formats
  - BFT references in block headers
  - staking actions and transaction builder support
  - transparent, Sapling, and Orchard transaction components


## Security Warnings

These libraries are under development and have not been fully reviewed.

## License

All code in this workspace is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

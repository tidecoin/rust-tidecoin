//! Serializing consensus-encoded types with `serde`
//!
//! All types that implement consensus encoding traits can be serde de/serialized.
//! For integer types that can have multiple units we typically provide a few different modules.

use serde::{Deserialize, Serialize};
use tidecoin::block::{Header, Version};
use tidecoin::{
    amount, fee_rate, Amount, BlockHash, BlockTime, CompactTarget, FeeRate, TxMerkleNode,
};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Foo {
    /// Use `serde_as_consensus` for any type that implements `encoding::{Decodable, Encodable}`.
    ///
    /// Consensus encode then use hex or binary depending on the serializer.
    #[serde(with = "primitives::serde_as_consensus")]
    header: Header,

    /// `Amount` can use sats or TDC (`as_tdc`).
    #[serde(with = "amount::serde::as_sat")]
    amount: Amount,

    /// `FeeRate` can use kilo weight units or virtual bytes, both floor and ceil.
    #[serde(with = "fee_rate::serde::as_sat_per_kwu_floor")]
    fee_rate: FeeRate,
}

fn main() {
    let f = Foo { header: dummy_header(), amount: Amount::ONE_TDC, fee_rate: FeeRate::DUST };

    let s = serde_json::to_string(&f).unwrap();
    println!("{s}");

    let deser = serde_json::from_str::<Foo>(&s).unwrap();
    assert_eq!(deser, f);
}

fn dummy_header() -> Header {
    Header {
        version: Version::ONE,
        prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0x77; 32]),
        time: BlockTime::from(2),
        bits: CompactTarget::from_consensus(3),
        nonce: 4,
        auxpow: None,
    }
}

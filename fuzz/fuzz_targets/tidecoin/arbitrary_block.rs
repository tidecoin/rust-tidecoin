#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tidecoin::block::{self, Block, BlockCheckedExt as _};
use tidecoin_consensus_encoding::{decode_from_slice, encode_to_vec};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let b = Block::arbitrary(&mut u);

    if let Ok(block) = b {
        let serialized = encode_to_vec(&block);

        // Manually call all compute functions with unchecked block data.
        let (header, transactions) = block.clone().into_parts();
        block::compute_merkle_root(&transactions);
        // Use the 32-byte zero witness reserved value required by Tidecoin witness commitment rules.
        block.compute_witness_commitment(&[0u8; 32]);
        block::compute_witness_root(&transactions);

        if let Ok(block) = Block::new_checked(header, transactions) {
            let _ = block.bip34_block_height();
            block.block_hash();
            block.weight();
        }

        let deserialized: Result<Block, _> = decode_from_slice(serialized.as_slice());
        assert_eq!(deserialized.unwrap(), block);
    }
}

fuzz_target!(|data| {
    do_test(data);
});

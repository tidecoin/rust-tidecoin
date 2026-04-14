#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tidecoin::block::{self, Block, BlockCheckedExt as _};
use tidecoin_consensus_encoding::{decode_from_slice, encode_to_vec};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    if let Ok(block) = decode_from_slice::<Block>(data) {
        exercise_block(&block);
    }

    let mut u = Unstructured::new(data);
    if let Ok(block) = Block::arbitrary(&mut u) {
        exercise_block(&block);
    }
}

fn exercise_block(block: &Block) {
    let sanity = block::check_block_sanity(block);
    if sanity.is_ok() {
        let (header, transactions) = block.clone().into_parts();
        let checked = Block::new_checked(header, transactions)
            .expect("checked construction should accept sanity-valid block");
        let _ = checked.block_hash();
        let _ = checked.weight();
        let _ = checked.bip34_block_height();
    }

    let encoded = encode_to_vec(block);
    if let Ok(decoded) = decode_from_slice::<Block>(&encoded) {
        assert_eq!(decoded, *block);
    }

    let (_, transactions) = block.clone().into_parts();
    let _ = block::compute_merkle_root(&transactions);
    let _ = block::compute_witness_root(&transactions);
    let _ = block.compute_witness_commitment(&[0u8; 32]);
}

fuzz_target!(|data| {
    do_test(data);
});

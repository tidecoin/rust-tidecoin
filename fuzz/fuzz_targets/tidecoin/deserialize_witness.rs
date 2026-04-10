#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;
use tidecoin::witness::Witness;
use tidecoin_consensus_encoding::{decode_from_slice, encode_to_vec};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let witness_result: Result<Witness, _> = decode_from_slice(data);

    match witness_result {
        Err(_) => {}
        Ok(witness) => {
            let ser = encode_to_vec(&witness);
            assert_eq!(&ser[..], data);
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});

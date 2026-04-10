#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tidecoin::blockdata::witness::WitnessExt;
use tidecoin::Witness;
use tidecoin_consensus_encoding::{decode_from_slice, encode_to_vec};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);

    if let Ok(mut witness) = Witness::arbitrary(&mut u) {
        let serialized = encode_to_vec(&witness);

        let _ = witness.witness_script();
        let deserialized: Result<Witness, _> = decode_from_slice(serialized.as_slice());
        assert_eq!(deserialized.unwrap(), witness);

        if let Ok(element_bytes) = Vec::<u8>::arbitrary(&mut u) {
            witness.push(element_bytes.as_slice());
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});

// SPDX-License-Identifier: CC0-1.0

//! A witness.
//!
//! This module contains the [`Witness`] struct and related methods to operate on it

use crate::crypto::pq::{PqPublicKey, PqSignature};
use crate::{internal_macros, WitnessScript};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::witness::{Iter, Witness, WitnessDecoder, WitnessEncoder};
#[doc(no_inline)]
pub use primitives::witness::{UnexpectedEofError, WitnessDecoderError};

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Witness`] type.
    pub trait WitnessExt impl for Witness {
        /// Constructs the witness required to spend a Tidecoin P2WSH-512 PQ output.
        fn p2wsh512_pq(signature: PqSignature, pubkey: PqPublicKey) -> Self {
            let mut witness = Witness::new();
            witness.push(signature.as_bytes());
            witness.push(pubkey.to_prefixed_bytes());
            witness
        }

        /// Get the Segwit version 0 witness script.
        ///
        /// We do no validation to determine whether this is a witness script; if you are not
        /// certain whether the output being spent is Segwit v0,
        /// use [`crate::script::ScriptExt::is_p2wsh`] on the output's script.
        fn witness_script(&self) -> Option<&WitnessScript> { self.last().map(WitnessScript::from_bytes) }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Witness {}
}

#[cfg(test)]
mod test {
    use alloc::vec::Vec;

    use hex_unstable::{hex, DisplayHex};

    use super::*;
    use crate::Transaction;

    #[test]
    fn exact_sized_iterator() {
        let mut witness = Witness::default();
        for i in 0..5 {
            assert_eq!(witness.iter().len(), i);
            witness.push([0u8]);
        }
        let mut iter = witness.iter();
        for i in (0..=5).rev() {
            assert_eq!(iter.len(), i);
            iter.next();
        }
    }

    #[test]
    fn consensus_serialize() {
        let el_0 =
            hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105").to_vec();
        let el_1 = hex!("000000").to_vec();

        let mut want_witness = Witness::default();
        want_witness.push(&el_0);
        want_witness.push(&el_1);

        let vec = vec![el_0, el_1];
        let mut want_ser = Vec::new();
        want_ser.push(2);
        want_ser.push(vec[0].len() as u8);
        want_ser.extend_from_slice(&vec[0]);
        want_ser.push(vec[1].len() as u8);
        want_ser.extend_from_slice(&vec[1]);

        // `from_slice` expects bytes slices _without_ leading `CompactSize`.
        let got_witness = Witness::from_slice(&vec);
        assert_eq!(got_witness, want_witness);

        let got_ser = encoding::encode_to_vec(&got_witness);
        assert_eq!(got_ser, want_ser);

        let roundtrip: Witness = encoding::decode_from_slice(&got_ser).unwrap();
        assert_eq!(roundtrip, want_witness)
    }

    #[test]
    fn tx() {
        const S: &str = "02000000000102b44f26b275b8ad7b81146ba3dbecd081f9c1ea0dc05b97516f56045cfcd3df030100000000ffffffff1cb4749ae827c0b75f3d0a31e63efc8c71b47b5e3634a4c698cd53661cab09170100000000ffffffff020b3a0500000000001976a9143ea74de92762212c96f4dd66c4d72a4deb20b75788ac630500000000000016001493a8dfd1f0b6a600ab01df52b138cda0b82bb7080248304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c0121026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e950247304402203ef00489a0d549114977df2820fab02df75bebb374f5eee9e615107121658cfa02204751f2d1784f8e841bff6d3bcf2396af2f1a5537c0e4397224873fbd3bfbe9cf012102ae6aa498ce2dd204e9180e71b4fb1260fe3d1a95c8025b34e56a9adf5f278af200000000";
        let tx_bytes = hex!(S);
        let tx: Transaction = encoding::decode_from_slice(&tx_bytes).unwrap();

        let expected_wit = ["304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c01", "026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e95"];
        for (i, wit_el) in tx.inputs[0].witness.iter().enumerate() {
            assert_eq!(expected_wit[i], wit_el.to_lower_hex_string());
        }
        assert_eq!(expected_wit[1], tx.inputs[0].witness.last().unwrap().to_lower_hex_string());
        assert_eq!(
            expected_wit[0],
            tx.inputs[0].witness.get_back(1).unwrap().to_lower_hex_string()
        );
        assert_eq!(expected_wit[0], tx.inputs[0].witness.get(0).unwrap().to_lower_hex_string());
        assert_eq!(expected_wit[1], tx.inputs[0].witness.get(1).unwrap().to_lower_hex_string());
        assert_eq!(None, tx.inputs[0].witness.get(2));
        assert_eq!(expected_wit[0], tx.inputs[0].witness[0].to_lower_hex_string());
        assert_eq!(expected_wit[1], tx.inputs[0].witness[1].to_lower_hex_string());

        let tx_bytes_back = encoding::encode_to_vec(&tx);
        assert_eq!(tx_bytes_back, tx_bytes);
    }

    #[test]
    fn fuzz_cases() {
        let bytes = hex!("26ff0000000000c94ce592cf7a4cbb68eb00ce374300000057cd0000000000000026");
        assert!(encoding::decode_from_slice::<Witness>(&bytes).is_err()); // OversizedVectorAllocation

        let bytes = hex!("24000000ffffffffffffffffffffffff");
        assert!(encoding::decode_from_slice::<Witness>(&bytes).is_err()); // OversizedVectorAllocation
    }

    #[test]
    fn p2wsh512_pq_witness_layout() {
        let signature = PqSignature::from_slice(&[0xAA, 0xBB, 0xCC]);
        let mut pubkey_bytes = vec![crate::PqScheme::Falcon512.prefix()];
        pubkey_bytes.extend(core::iter::repeat_n(0x42, crate::PqScheme::Falcon512.pubkey_len()));
        let pubkey = PqPublicKey::from_prefixed_slice(&pubkey_bytes).unwrap();

        let witness = Witness::p2wsh512_pq(signature, pubkey.clone());
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[0], [0xAA, 0xBB, 0xCC]);
        assert_eq!(witness[1], pubkey.to_prefixed_bytes());
    }
}

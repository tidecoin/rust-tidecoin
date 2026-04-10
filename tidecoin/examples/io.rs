// SPDX-License-Identifier: CC0-1.0

//! Demonstrate encoding and decoding Tidecoin objects without the old reader/writer codec facade.

use std::io::{self, Write};

use tidecoin::{OutPoint, Txid};

fn main() {
    encode_decode_from_vec();
    encode_to_std_writer();
    encode_to_custom_writer();
}

fn encode_decode_from_vec() {
    let data = dummy_utxo();

    let bytes = encoding::encode_to_vec(&data);
    let decoded: OutPoint = encoding::decode_from_slice(&bytes).expect("failed to decode bytes");

    assert_eq!(decoded, data);
}

fn encode_to_std_writer() {
    let data = dummy_utxo();

    let mut bytes = Vec::new();
    encoding::encode_to_writer(&data, &mut bytes).expect("failed to encode to writer");

    assert_eq!(bytes, encoding::encode_to_vec(&data));
}

fn encode_to_custom_writer() {
    struct WriteCounter {
        count: usize,
    }

    impl Write for WriteCounter {
        fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
            self.count += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), io::Error> {
            Ok(())
        }
    }

    let data = dummy_utxo();

    let mut counter = WriteCounter { count: 0 };
    encoding::encode_to_writer(&data, &mut counter).expect("failed to encode to writer");
    assert_eq!(counter.count, 36); // 32 bytes for txid + 4 bytes for vout.
}

fn dummy_utxo() -> OutPoint {
    let txid = Txid::from_byte_array([0xFF; 32]); // Arbitrary invalid dummy value.
    OutPoint { txid, vout: 1 }
}

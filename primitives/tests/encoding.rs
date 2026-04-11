// SPDX-License-Identifier: CC0-1.0

#![cfg(all(feature = "alloc", feature = "hex"))]

use encoding::{Encodable as _, Encoder as _};
use tidecoin_primitives::absolute::LockTime;
use tidecoin_primitives::merkle_tree::TxMerkleNode;
use tidecoin_primitives::{
    Amount, Block, BlockHash, BlockHeader, BlockTime, BlockVersion, CompactTarget, OutPoint,
    ScriptPubKeyBuf, ScriptSigBuf, Sequence, Transaction, TransactionVersion, TxIn, TxOut, Txid,
    Witness,
};

const TC_TXID_BYTES: [u8; 32] = [
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9,
    8, 7, 6, 5, 4, 3, 2, 1,
];
const TC_VOUT_BYTES: [u8; 4] = [1, 0, 0, 0];
const TC_SCRIPT_BYTES: [u8; 3] = [1, 2, 3];
const TC_SEQ_MAX_BYTES: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
const TC_LOCK_TIME_ZERO_BYTES: [u8; 4] = [0, 0, 0, 0];
const TC_ONE_SAT_BYTES: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
const TC_SEGWIT_MARKER_AND_FLAG: [u8; 2] = [0, 1];
const TC_WITNESS_ELEM_LEN_AND_DATA: [u8; 4] = [3, 1, 2, 3];

#[test]
fn encode_block() {
    let seconds: u32 = 1_653_195_600; // Arbitrary timestamp: May 22nd, 5am UTC.

    let header = BlockHeader {
        version: BlockVersion::TWO,
        prev_blockhash: BlockHash::from_byte_array([0xab; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0xcd; 32]),
        time: BlockTime::from(seconds),
        bits: CompactTarget::from_consensus(0xbeef),
        nonce: 0xcafe,
        auxpow: None,
    };

    let tx = Transaction {
        version: TransactionVersion::TWO,
        lock_time: LockTime::ZERO,
        inputs: vec![segwit_tx_in()],
        outputs: vec![tx_out()],
    };

    let block = Block::new_unchecked(header, vec![tx]);
    let mut encoder = block.encoder();

    // The block header, 6 encoders, 1 chunk per encoder.
    assert_eq!(encoder.current_chunk(), &[2u8, 0, 0, 0][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[171u8; 32][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[205u8; 32][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[80, 195, 137, 98][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[239, 190, 0, 0][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[254, 202, 0, 0][..]);
    assert!(encoder.advance());

    // The transaction list length prefix.
    assert_eq!(encoder.current_chunk(), &[1u8][..]);
    assert!(encoder.advance());

    // The transaction.
    assert_eq!(encoder.current_chunk(), &[2u8, 0, 0, 0][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &TC_SEGWIT_MARKER_AND_FLAG[..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[1u8][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &TC_TXID_BYTES[..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &TC_VOUT_BYTES[..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[3u8][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &TC_SCRIPT_BYTES[..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &TC_SEQ_MAX_BYTES[..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[1u8][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &TC_ONE_SAT_BYTES[..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[3u8][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &TC_SCRIPT_BYTES[..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &[1u8][..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &TC_WITNESS_ELEM_LEN_AND_DATA[..]);
    assert!(encoder.advance());
    assert_eq!(encoder.current_chunk(), &TC_LOCK_TIME_ZERO_BYTES[..]);
    assert!(!encoder.advance());
    assert!(encoder.current_chunk().is_empty());
}

fn tx_out() -> TxOut {
    TxOut { amount: Amount::ONE_SAT, script_pubkey: tc_script_pubkey() }
}

fn segwit_tx_in() -> TxIn {
    let data = [&TC_SCRIPT_BYTES[..]];
    let witness = Witness::from_iter(data);

    TxIn {
        previous_output: tc_out_point(),
        script_sig: tc_script_sig(),
        sequence: Sequence::MAX,
        witness,
    }
}

fn tc_out_point() -> OutPoint {
    OutPoint { txid: Txid::from_byte_array(TC_TXID_BYTES), vout: 1 }
}

fn tc_script_pubkey() -> ScriptPubKeyBuf {
    ScriptPubKeyBuf::from_bytes(TC_SCRIPT_BYTES.to_vec())
}

fn tc_script_sig() -> ScriptSigBuf {
    ScriptSigBuf::from_bytes(TC_SCRIPT_BYTES.to_vec())
}

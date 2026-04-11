// SPDX-License-Identifier: CC0-1.0

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// Verifies a single transaction input against the Tidecoin node interpreter.
    pub fn tidecoin_node_verify_tx_input(
        tx_hex: *const c_char,
        input_index: usize,
        prev_script: *const u8,
        prev_script_len: usize,
        amount: i64,
        flags: u32,
        script_error_out: *mut c_int,
    ) -> c_int;

    /// Runs Tidecoin node `CheckTransaction` on a serialized transaction.
    pub fn tidecoin_node_check_transaction(tx_hex: *const c_char) -> c_int;

    /// Runs Tidecoin node `pq::VSizeP2WPKHInput`.
    pub fn tidecoin_node_pq_p2wpkh_input_vsize(sig_len: usize, pubkey_len: usize) -> i64;

    /// Runs Tidecoin node `pq::VSizeP2SH_P2WPKHInput`.
    pub fn tidecoin_node_pq_p2sh_p2wpkh_input_vsize(sig_len: usize, pubkey_len: usize) -> i64;

    /// Deterministically generates a PQ keypair from a raw seed using the Tidecoin node.
    pub fn tidecoin_node_pq_keygen_from_seed(
        scheme_prefix: u8,
        seed: *const u8,
        seed_len: usize,
        pk_out: *mut u8,
        pk_len: usize,
        sk_out: *mut u8,
        sk_len: usize,
    ) -> c_int;

    /// Deterministically generates a PQHD keypair from a stream key using the Tidecoin node.
    pub fn tidecoin_node_pqhd_keygen_from_stream_key(
        scheme_prefix: u8,
        stream_key: *const u8,
        stream_key_len: usize,
        pk_out: *mut u8,
        pk_len: usize,
        sk_out: *mut u8,
        sk_len: usize,
    ) -> c_int;

    /// Computes a PQ public key from a secret key using the Tidecoin node.
    pub fn tidecoin_node_pq_compute_public_key(
        scheme_prefix: u8,
        sk: *const u8,
        sk_len: usize,
        pk_out: *mut u8,
        pk_len: usize,
    ) -> c_int;

    /// Signs a message using the Tidecoin node PQ API.
    pub fn tidecoin_node_pq_sign_message(
        scheme_prefix: u8,
        msg: *const u8,
        msg_len: usize,
        sk: *const u8,
        sk_len: usize,
        legacy_mode: c_int,
        sig_out: *mut u8,
        sig_len: *mut usize,
    ) -> c_int;

    /// Verifies a message signature using the Tidecoin node PQ API.
    pub fn tidecoin_node_pq_verify_message(
        scheme_prefix: u8,
        msg: *const u8,
        msg_len: usize,
        sig: *const u8,
        sig_len: usize,
        pk: *const u8,
        pk_len: usize,
        legacy_mode: c_int,
    ) -> c_int;

    /// Parses script assembly text using Tidecoin node helpers.
    pub fn tidecoin_node_parse_script_asm(
        script_asm: *const c_char,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    /// Verifies an isolated script test case against the Tidecoin node interpreter.
    pub fn tidecoin_node_verify_script_case(
        script_sig: *const u8,
        script_sig_len: usize,
        script_pubkey: *const u8,
        script_pubkey_len: usize,
        witness_items: *const *const u8,
        witness_lens: *const usize,
        witness_count: usize,
        amount: i64,
        flags: u32,
        script_error_out: *mut c_int,
    ) -> c_int;
}

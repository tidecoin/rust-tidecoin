// SPDX-License-Identifier: CC0-1.0

use std::ffi::CString;
use std::path::PathBuf;

use crate::error::{NodeParityError, ScriptError};
use crate::ffi::{
    tidecoin_node_check_transaction, tidecoin_node_parse_script_asm,
    tidecoin_node_pq_compute_public_key, tidecoin_node_pq_keygen_from_seed,
    tidecoin_node_pq_sign_message, tidecoin_node_pq_verify_message,
    tidecoin_node_pqhd_keygen_from_stream_key, tidecoin_node_verify_script_case,
    tidecoin_node_verify_tx_input,
};
use crate::fixtures::TIDECOIN_NODE_REPO_ENV;

/// Shared byte-oriented handle for Tidecoin node-backed parity calls.
#[derive(Debug, Clone)]
pub struct TidecoinNodeHarness {
    node_repo: PathBuf,
}

impl TidecoinNodeHarness {
    /// Creates the harness from the configured `TIDECOIN_NODE_REPO`.
    pub fn from_env() -> Result<Self, NodeParityError> {
        let node_repo = std::env::var_os(TIDECOIN_NODE_REPO_ENV)
            .map(PathBuf::from)
            .ok_or(NodeParityError::Environment("TIDECOIN_NODE_REPO is not configured"))?;
        if !node_repo.exists() {
            return Err(NodeParityError::Environment(
                "configured TIDECOIN_NODE_REPO does not exist",
            ));
        }
        if !node_repo.join("src").exists() {
            return Err(NodeParityError::Environment(
                "configured TIDECOIN_NODE_REPO is not a Tidecoin node checkout",
            ));
        }
        Ok(Self { node_repo })
    }

    /// Returns a short human-readable label for diagnostics.
    pub fn backend_label(&self) -> String {
        format!("tidecoin-node:{}", self.node_repo.display())
    }

    /// Returns the configured Tidecoin node checkout path.
    pub fn node_repo(&self) -> &std::path::Path {
        &self.node_repo
    }

    /// Runs Tidecoin node `CheckTransaction` on a serialized transaction hex string.
    pub fn check_transaction_hex(&self, tx_hex: &str) -> Result<(), NodeParityError> {
        let tx_hex = CString::new(tx_hex).map_err(|_| NodeParityError::InvalidCString("tx hex"))?;
        let rc = unsafe { tidecoin_node_check_transaction(tx_hex.as_ptr()) };
        match rc {
            1 => Ok(()),
            0 => Err(NodeParityError::BridgeFailure("invalid transaction")),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_check_transaction")),
        }
    }

    /// Verifies a single transaction input using raw serialized transaction hex.
    pub fn verify_tx_input_hex(
        &self,
        tx_hex: &str,
        input_index: usize,
        prev_script: &[u8],
        amount_sat: i64,
        flags: u32,
    ) -> Result<(), NodeParityError> {
        let tx_hex = CString::new(tx_hex).map_err(|_| NodeParityError::InvalidCString("tx hex"))?;
        let mut script_error = 0;
        let rc = unsafe {
            tidecoin_node_verify_tx_input(
                tx_hex.as_ptr(),
                input_index,
                prev_script.as_ptr(),
                prev_script.len(),
                amount_sat,
                flags,
                &mut script_error,
            )
        };
        match rc {
            1 => Ok(()),
            0 => Err(NodeParityError::Script(Self::script_error_or_unknown(script_error))),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_verify_tx_input")),
        }
    }

    /// Verifies an isolated script-case payload against the Tidecoin node interpreter.
    pub fn verify_script_case(
        &self,
        script_sig: &[u8],
        script_pubkey: &[u8],
        witness: &[&[u8]],
        amount_sat: i64,
        flags: u32,
    ) -> Result<(), NodeParityError> {
        let witness_items: Vec<*const u8> = witness.iter().map(|item| item.as_ptr()).collect();
        let witness_lens: Vec<usize> = witness.iter().map(|item| item.len()).collect();
        let mut script_error = 0;
        let rc = unsafe {
            tidecoin_node_verify_script_case(
                script_sig.as_ptr(),
                script_sig.len(),
                script_pubkey.as_ptr(),
                script_pubkey.len(),
                witness_items.as_ptr(),
                witness_lens.as_ptr(),
                witness.len(),
                amount_sat,
                flags,
                &mut script_error,
            )
        };
        match rc {
            1 => Ok(()),
            0 => Err(NodeParityError::Script(Self::script_error_or_unknown(script_error))),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_verify_script_case")),
        }
    }

    /// Parses script assembly using Tidecoin node helpers.
    pub fn parse_script_asm(&self, script_asm: &str) -> Result<Vec<u8>, NodeParityError> {
        let script_asm =
            CString::new(script_asm).map_err(|_| NodeParityError::InvalidCString("script asm"))?;
        let mut out_len = 0usize;
        let probe = unsafe {
            tidecoin_node_parse_script_asm(script_asm.as_ptr(), core::ptr::null_mut(), &mut out_len)
        };
        if probe != 0 {
            return Err(NodeParityError::BridgeFailure("tidecoin_node_parse_script_asm"));
        }
        let mut out = vec![0u8; out_len];
        let rc = unsafe {
            tidecoin_node_parse_script_asm(script_asm.as_ptr(), out.as_mut_ptr(), &mut out_len)
        };
        if rc != 1 {
            return Err(NodeParityError::BridgeFailure("tidecoin_node_parse_script_asm"));
        }
        out.truncate(out_len);
        Ok(out)
    }

    /// Deterministically generates a PQ keypair using the Tidecoin node.
    pub fn pq_keypair_from_seed(
        &self,
        scheme_prefix: u8,
        seed: &[u8],
        pubkey_len: usize,
        seckey_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), NodeParityError> {
        let mut pk = vec![0u8; pubkey_len];
        let mut sk = vec![0u8; seckey_len];
        let rc = unsafe {
            tidecoin_node_pq_keygen_from_seed(
                scheme_prefix,
                seed.as_ptr(),
                seed.len(),
                pk.as_mut_ptr(),
                pk.len(),
                sk.as_mut_ptr(),
                sk.len(),
            )
        };
        match rc {
            1 => Ok((pk, sk)),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_pq_keygen_from_seed")),
        }
    }

    /// Deterministically generates a PQHD keypair using the Tidecoin node.
    pub fn pq_keypair_from_stream_key(
        &self,
        scheme_prefix: u8,
        stream_key: &[u8],
        pubkey_len: usize,
        seckey_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), NodeParityError> {
        let mut pk = vec![0u8; pubkey_len];
        let mut sk = vec![0u8; seckey_len];
        let rc = unsafe {
            tidecoin_node_pqhd_keygen_from_stream_key(
                scheme_prefix,
                stream_key.as_ptr(),
                stream_key.len(),
                pk.as_mut_ptr(),
                pk.len(),
                sk.as_mut_ptr(),
                sk.len(),
            )
        };
        match rc {
            1 => Ok((pk, sk)),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_pqhd_keygen_from_stream_key")),
        }
    }

    /// Computes a PQ public key from a secret key using the Tidecoin node.
    pub fn pq_public_key_from_secret(
        &self,
        scheme_prefix: u8,
        secret_key: &[u8],
        pubkey_len: usize,
    ) -> Result<Vec<u8>, NodeParityError> {
        let mut pk = vec![0u8; pubkey_len];
        let rc = unsafe {
            tidecoin_node_pq_compute_public_key(
                scheme_prefix,
                secret_key.as_ptr(),
                secret_key.len(),
                pk.as_mut_ptr(),
                pk.len(),
            )
        };
        match rc {
            1 => Ok(pk),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_pq_compute_public_key")),
        }
    }

    /// Signs a message using the Tidecoin node PQ API.
    pub fn pq_sign_message(
        &self,
        scheme_prefix: u8,
        message: &[u8],
        secret_key: &[u8],
        max_sig_len: usize,
        legacy: bool,
    ) -> Result<Vec<u8>, NodeParityError> {
        let mut sig_len = max_sig_len;
        let probe = unsafe {
            tidecoin_node_pq_sign_message(
                scheme_prefix,
                message.as_ptr(),
                message.len(),
                secret_key.as_ptr(),
                secret_key.len(),
                if legacy { 1 } else { 0 },
                core::ptr::null_mut(),
                &mut sig_len,
            )
        };
        if probe != 0 {
            return Err(NodeParityError::BridgeFailure("tidecoin_node_pq_sign_message"));
        }
        let mut sig = vec![0u8; sig_len];
        let rc = unsafe {
            tidecoin_node_pq_sign_message(
                scheme_prefix,
                message.as_ptr(),
                message.len(),
                secret_key.as_ptr(),
                secret_key.len(),
                if legacy { 1 } else { 0 },
                sig.as_mut_ptr(),
                &mut sig_len,
            )
        };
        if rc != 1 {
            return Err(NodeParityError::BridgeFailure("tidecoin_node_pq_sign_message"));
        }
        sig.truncate(sig_len);
        Ok(sig)
    }

    /// Verifies a message using the Tidecoin node PQ API.
    pub fn pq_verify_message(
        &self,
        scheme_prefix: u8,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        legacy: bool,
    ) -> Result<bool, NodeParityError> {
        let rc = unsafe {
            tidecoin_node_pq_verify_message(
                scheme_prefix,
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
                public_key.as_ptr(),
                public_key.len(),
                if legacy { 1 } else { 0 },
            )
        };
        match rc {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_pq_verify_message")),
        }
    }

    fn script_error_or_unknown(code: i32) -> ScriptError {
        match ScriptError::from_ffi(code) {
            ScriptError::Ok => ScriptError::UnknownError,
            other => other,
        }
    }
}

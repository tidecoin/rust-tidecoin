// SPDX-License-Identifier: CC0-1.0

use std::ffi::{c_int, CString};
use std::path::{Path, PathBuf};

use crate::error::{NodeParityError, ScriptError};
use crate::ffi::{
    tidecoin_node_check_transaction, tidecoin_node_eval_script, tidecoin_node_mlkem512_decaps,
    tidecoin_node_mlkem512_encaps_deterministic, tidecoin_node_mlkem512_keypair_from_coins,
    tidecoin_node_parse_script_asm, tidecoin_node_permitted_difficulty_transition,
    tidecoin_node_pq_compute_public_key, tidecoin_node_pq_keygen_from_seed,
    tidecoin_node_pq_p2sh_p2wpkh_input_vsize, tidecoin_node_pq_p2wpkh_input_vsize,
    tidecoin_node_pq_sign_message, tidecoin_node_pq_verify_message,
    tidecoin_node_pqhd_keygen_from_stream_key, tidecoin_node_scrypt_pow_hash,
    tidecoin_node_verify_script_case, tidecoin_node_verify_tx_input,
    tidecoin_node_yespower_pow_hash,
};
use crate::fixtures::TIDECOIN_NODE_REPO_ENV;

/// A previous output, in transaction input order (including the current input).
#[derive(Debug, Clone, Copy)]
pub struct SpentOutput<'a> {
    /// Value in satoshis.
    pub amount: i64,
    /// Locking script of the output being spent.
    pub script_pubkey: &'a [u8],
}

fn native_outputs(outputs: &[SpentOutput<'_>]) -> Vec<crate::ffi::NodeSpentOutput> {
    outputs
        .iter()
        .map(|out| crate::ffi::NodeSpentOutput {
            amount: out.amount,
            script: out.script_pubkey.as_ptr(),
            script_len: out.script_pubkey.len(),
        })
        .collect()
}

/// Decodes the bridge stack format: per item, u32 LE length then bytes.
fn decode_stack(mut bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut stack = Vec::new();
    while !bytes.is_empty() {
        let (len, rest) = bytes.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;
        if rest.len() < len {
            return None;
        }
        let (item, rest) = rest.split_at(len);
        stack.push(item.to_vec());
        bytes = rest;
    }
    Some(stack)
}

/// Shared byte-oriented handle for Tidecoin node-backed parity calls.
#[derive(Debug, Clone)]
pub struct TidecoinNodeHarness {
    node_repo: PathBuf,
}

impl TidecoinNodeHarness {
    /// Optional local test entrypoint. Only an unconfigured, non-required run skips.
    /// Invalid configuration (including a stub build) fails loudly.
    pub fn optional_from_env() -> Option<Self> {
        let required = match std::env::var("TIDECOIN_NODE_PARITY_REQUIRED").as_deref() {
            Ok("1") => true,
            Err(std::env::VarError::NotPresent) | Ok("0") => false,
            _ => panic!("TIDECOIN_NODE_PARITY_REQUIRED must be 0 or 1"),
        } || env!("TIDECOIN_NODE_PARITY_BUILT_REQUIRED") == "1";
        if !required && std::env::var_os(TIDECOIN_NODE_REPO_ENV).is_none() {
            eprintln!("SKIP node parity: TIDECOIN_NODE_REPO is not configured");
            return None;
        }
        Some(Self::from_env().expect("configured/required node parity must be available"))
    }

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
        let built_repo = env!("TIDECOIN_NODE_PARITY_BUILT_REPO");
        if built_repo.is_empty() {
            return Err(NodeParityError::Environment(
                "node bridge was built as a stub; rebuild with TIDECOIN_NODE_REPO",
            ));
        }
        let node_repo = node_repo
            .canonicalize()
            .map_err(|_| NodeParityError::Environment("cannot resolve node checkout"))?;
        if node_repo != Path::new(built_repo) {
            return Err(NodeParityError::Environment(
                "runtime node checkout differs from compiled bridge",
            ));
        }
        // Validate once per process, before any oracle call. Test subprocesses exercise failures.
        static SOURCE_CHECK: std::sync::OnceLock<Result<(), NodeParityError>> =
            std::sync::OnceLock::new();
        SOURCE_CHECK
            .get_or_init(|| {
                let output = std::process::Command::new("git")
                    .args(["rev-parse", "HEAD"])
                    .current_dir(&node_repo)
                    .output()
                    .map_err(|_| NodeParityError::Environment("cannot read node revision"))?;
                if !output.status.success()
                    || String::from_utf8_lossy(&output.stdout).trim()
                        != env!("TIDECOIN_NODE_PARITY_BUILT_REVISION")
                {
                    return Err(NodeParityError::Environment(
                        "node revision differs from compiled bridge",
                    ));
                }
                let status = std::process::Command::new("git")
                    .args(["status", "--porcelain", "--untracked-files=normal", "--", "src"])
                    .current_dir(&node_repo)
                    .output()
                    .map_err(|_| {
                        NodeParityError::Environment("cannot inspect node source changes")
                    })?;
                if !status.status.success() || !status.stdout.is_empty() {
                    return Err(NodeParityError::Environment(
                        "node source tree must be clean for parity evidence",
                    ));
                }
                Ok(())
            })
            .clone()?;
        Ok(Self { node_repo })
    }

    /// Returns a short human-readable label for diagnostics.
    pub fn backend_label(&self) -> String {
        format!(
            "tidecoin-node:{}@{}",
            self.node_repo.display(),
            env!("TIDECOIN_NODE_PARITY_BUILT_REVISION")
        )
    }

    /// Returns the configured Tidecoin node checkout path.
    pub fn node_repo(&self) -> &std::path::Path {
        &self.node_repo
    }

    /// Calls node `UseScryptPoW`, including regtest's fixed genesis exception.
    /// Network IDs are mainnet=0, testnet=1, regtest=2; `i32::MAX` disables activation.
    pub fn uses_scrypt_pow(
        &self,
        network: i32,
        height: i32,
        activation_height: i32,
    ) -> Result<bool, NodeParityError> {
        match unsafe {
            crate::ffi::tidecoin_node_uses_scrypt_pow(network, height, activation_height)
        } {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_uses_scrypt_pow")),
        }
    }

    /// Strict witness-aware wire decoding followed by original `CheckTransaction`.
    /// Returns 0 for malformed bytes, 1 for a decoded sanity-invalid transaction,
    /// and 2 for a sane transaction. Infrastructure errors are never rejection verdicts.
    pub fn transaction_decode_status(&self, bytes: &[u8]) -> Result<u8, NodeParityError> {
        match unsafe { crate::ffi::tidecoin_node_transaction_status(bytes.as_ptr(), bytes.len()) } {
            status @ 0..=2 => Ok(status as u8),
            _ => Err(NodeParityError::BridgeFailure("transaction_decode_status")),
        }
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

    /// Computes the Tidecoin node scrypt mining hash for a pure 80-byte header.
    pub fn scrypt_pow_hash(&self, header: &[u8; 80]) -> Result<[u8; 32], NodeParityError> {
        let mut out = [0u8; 32];
        let rc = unsafe {
            tidecoin_node_scrypt_pow_hash(
                header.as_ptr(),
                header.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        match rc {
            1 => Ok(out),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_scrypt_pow_hash")),
        }
    }

    /// Computes the Tidecoin node yespower mining hash for a pure 80-byte header.
    pub fn yespower_pow_hash(&self, header: &[u8; 80]) -> Result<[u8; 32], NodeParityError> {
        let mut out = [0u8; 32];
        let rc = unsafe {
            tidecoin_node_yespower_pow_hash(
                header.as_ptr(),
                header.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        match rc {
            1 => Ok(out),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_yespower_pow_hash")),
        }
    }

    /// Runs header proof validation, including the AuxPoW proof checks.
    /// Does not run `ContextualCheckBlockHeader` (versions, timestamps, expected difficulty).
    pub fn has_valid_header_pow_hex(
        &self,
        header_hex: &str,
        network: i32,
        height: Option<i32>,
    ) -> Result<(), NodeParityError> {
        crate::validation::verdict(crate::validation::one(serde_json::json!({
            "op": "proof", "header": header_hex, "network": network, "height": height,
        })))
    }

    /// Runs original-node context-free block sanity validation.
    pub fn check_block_hex(
        &self,
        block_hex: &str,
        network: i32,
        check_pow: bool,
        check_merkle_root: bool,
    ) -> Result<(), NodeParityError> {
        crate::validation::verdict(crate::validation::one(serde_json::json!({
            "op": "block", "block": block_hex, "network": network,
            "check_pow": check_pow, "check_merkle": check_merkle_root,
        })))
    }

    /// Runs original-node UTXO-independent contextual block validation.
    pub fn check_contextual_block_hex(
        &self,
        block_hex: &str,
        network: i32,
        height: i32,
        lock_time_cutoff: i64,
        enforce_bip34_height: bool,
        expect_witness_commitment: bool,
    ) -> Result<(), NodeParityError> {
        crate::validation::verdict(crate::validation::one(serde_json::json!({
            "op": "contextual_block_flags", "block": block_hex, "network": network,
            "height": height, "cutoff": lock_time_cutoff,
            "enforce_bip34": enforce_bip34_height, "expect_witness": expect_witness_commitment,
        })))
    }

    /// Runs node-equivalent permitted difficulty transition validation.
    pub fn permitted_difficulty_transition(
        &self,
        network: i32,
        height: i64,
        old_nbits: u32,
        new_nbits: u32,
    ) -> Result<bool, NodeParityError> {
        let rc = unsafe {
            tidecoin_node_permitted_difficulty_transition(network, height, old_nbits, new_nbits)
        };
        match rc {
            1 => Ok(true),
            0 => Ok(false),
            _ => {
                Err(NodeParityError::BridgeFailure("tidecoin_node_permitted_difficulty_transition"))
            }
        }
    }

    /// Returns the node block subsidy in satoshis for the selected network and height.
    pub fn block_subsidy(&self, network: i32, height: i32) -> Result<u64, NodeParityError> {
        let value = crate::validation::one(serde_json::json!({
            "op": "subsidy", "network": network, "height": height,
        }));
        Ok(value["subsidy"].as_u64().expect("node subsidy must be nonnegative"))
    }

    /// Returns Tidecoin node `pq::VSizeP2WPKHInput` for the provided serialized PQ lengths.
    pub fn pq_p2wpkh_input_vsize(
        &self,
        sig_len: usize,
        pubkey_len: usize,
    ) -> Result<i64, NodeParityError> {
        match unsafe { tidecoin_node_pq_p2wpkh_input_vsize(sig_len, pubkey_len) } {
            v if v >= 0 => Ok(v),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_pq_p2wpkh_input_vsize")),
        }
    }

    /// Returns Tidecoin node `pq::VSizeP2SH_P2WPKHInput` for the provided serialized PQ lengths.
    pub fn pq_p2sh_p2wpkh_input_vsize(
        &self,
        sig_len: usize,
        pubkey_len: usize,
    ) -> Result<i64, NodeParityError> {
        match unsafe { tidecoin_node_pq_p2sh_p2wpkh_input_vsize(sig_len, pubkey_len) } {
            v if v >= 0 => Ok(v),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_pq_p2sh_p2wpkh_input_vsize")),
        }
    }

    /// Verifies without foreign spent-output data.
    ///
    /// Use `verify_tx_input_with_spent_outputs` for rc2 non-ANYONECANPAY witness-v1.
    pub fn verify_tx_input_hex(
        &self,
        tx_hex: &str,
        input_index: usize,
        prev_script: &[u8],
        amount_sat: i64,
        flags: u32,
    ) -> Result<(), NodeParityError> {
        self.verify_tx_input_with_spent_outputs(
            tx_hex,
            input_index,
            prev_script,
            amount_sat,
            flags,
            &[],
        )
    }

    /// Runs original `EvalScript` on `stack` with the transaction checker used by
    /// [`Self::verify_tx_input_with_spent_outputs`]. Returns the final stack,
    /// bottom first. `sigversion` is 0 (base), 1 (witness v0) or 2 (witness v1).
    #[allow(clippy::too_many_arguments)]
    pub fn eval_script(
        &self,
        tx_hex: &str,
        input_index: usize,
        amount_sat: i64,
        flags: u32,
        spent_outputs: &[SpentOutput<'_>],
        script: &[u8],
        stack: &[Vec<u8>],
        sigversion: u8,
    ) -> Result<Vec<Vec<u8>>, NodeParityError> {
        const NAME: &str = "tidecoin_node_eval_script";
        let tx_hex = CString::new(tx_hex).map_err(|_| NodeParityError::InvalidCString("tx hex"))?;
        let outputs = native_outputs(spent_outputs);
        let items: Vec<*const u8> = stack.iter().map(|item| item.as_ptr()).collect();
        let lens: Vec<usize> = stack.iter().map(Vec::len).collect();
        let mut out = vec![0u8; stack.iter().map(|item| 4 + item.len()).sum::<usize>() + 1024];
        loop {
            let mut out_len = out.len();
            let mut script_error = 0;
            let rc = unsafe {
                tidecoin_node_eval_script(
                    tx_hex.as_ptr(),
                    input_index,
                    amount_sat,
                    flags,
                    outputs.as_ptr(),
                    outputs.len(),
                    script.as_ptr(),
                    script.len(),
                    items.as_ptr(),
                    lens.as_ptr(),
                    stack.len(),
                    c_int::from(sigversion),
                    out.as_mut_ptr(),
                    &mut out_len,
                    &mut script_error,
                )
            };
            match rc {
                2 if out_len > out.len() => out.resize(out_len, 0),
                1 | 0 => {
                    Self::script_verdict(rc, script_error, NAME)?;
                    return decode_stack(&out[..out_len])
                        .ok_or(NodeParityError::BridgeFailure(NAME));
                }
                _ => return Err(NodeParityError::BridgeFailure(NAME)),
            }
        }
    }

    /// Verifies with all previous outputs in input order. Empty means unavailable;
    /// a nonempty partial list is a bridge error, never a node consensus verdict.
    pub fn verify_tx_input_with_spent_outputs(
        &self,
        tx_hex: &str,
        input_index: usize,
        prev_script: &[u8],
        amount_sat: i64,
        flags: u32,
        spent_outputs: &[SpentOutput<'_>],
    ) -> Result<(), NodeParityError> {
        let tx_hex = CString::new(tx_hex).map_err(|_| NodeParityError::InvalidCString("tx hex"))?;
        let outputs = native_outputs(spent_outputs);
        let mut script_error = 0;
        let rc = unsafe {
            tidecoin_node_verify_tx_input(
                tx_hex.as_ptr(),
                input_index,
                prev_script.as_ptr(),
                prev_script.len(),
                amount_sat,
                flags,
                outputs.as_ptr(),
                outputs.len(),
                &mut script_error,
            )
        };
        Self::script_verdict(rc, script_error, "tidecoin_node_verify_tx_input")
    }

    /// Calls the original node CountWitnessSigOps, with explicit candidate flags.
    pub fn count_witness_sigops(
        &self,
        tx_hex: &str,
        index: usize,
        prev_script: &[u8],
        flags: u32,
    ) -> Result<usize, NodeParityError> {
        let tx = CString::new(tx_hex).map_err(|_| NodeParityError::InvalidCString("tx hex"))?;
        let result = unsafe {
            crate::ffi::tidecoin_node_count_witness_sigops(
                tx.as_ptr(),
                index,
                prev_script.as_ptr(),
                prev_script.len(),
                flags,
            )
        };
        usize::try_from(result).map_err(|_| NodeParityError::BridgeFailure("CountWitnessSigOps"))
    }

    /// Calls node `SignatureHash512`, forcing precomputation as its signing callers do.
    ///
    /// `None` is the node's failure to produce a digest (missing non-ANYONECANPAY
    /// spent outputs or SINGLE without a matching output). Bytes are in hash
    /// serialization order, the reverse of node `uint512::GetHex`.
    pub fn signature_hash_512(
        &self,
        tx_hex: &str,
        input_index: usize,
        script_code: &[u8],
        amount_sat: i64,
        hash_type: i32,
        spent_outputs: &[SpentOutput<'_>],
    ) -> Result<Option<[u8; 64]>, NodeParityError> {
        let tx_hex = CString::new(tx_hex).map_err(|_| NodeParityError::InvalidCString("tx hex"))?;
        let outputs = native_outputs(spent_outputs);
        let mut hash = [0; 64];
        let rc = unsafe {
            crate::ffi::tidecoin_node_signature_hash_512(
                tx_hex.as_ptr(),
                input_index,
                script_code.as_ptr(),
                script_code.len(),
                amount_sat,
                hash_type,
                outputs.as_ptr(),
                outputs.len(),
                hash.as_mut_ptr(),
            )
        };
        match rc {
            1 => Ok(Some(hash)),
            0 => Ok(None),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_signature_hash_512")),
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
        Self::script_verdict(rc, script_error, "tidecoin_node_verify_script_case")
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

    /// Deterministically generates an ML-KEM-512 keypair using the Tidecoin node.
    pub fn mlkem512_keypair_from_coins(
        &self,
        coins: &[u8],
        pubkey_len: usize,
        seckey_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), NodeParityError> {
        let mut pk = vec![0u8; pubkey_len];
        let mut sk = vec![0u8; seckey_len];
        let rc = unsafe {
            tidecoin_node_mlkem512_keypair_from_coins(
                coins.as_ptr(),
                coins.len(),
                pk.as_mut_ptr(),
                pk.len(),
                sk.as_mut_ptr(),
                sk.len(),
            )
        };
        match rc {
            1 => Ok((pk, sk)),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_mlkem512_keypair_from_coins")),
        }
    }

    /// Deterministically encapsulates an ML-KEM-512 shared secret using the Tidecoin node.
    pub fn mlkem512_encaps_deterministic(
        &self,
        public_key: &[u8],
        coins: &[u8],
        ciphertext_len: usize,
        shared_secret_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), NodeParityError> {
        let mut ct = vec![0u8; ciphertext_len];
        let mut ss = vec![0u8; shared_secret_len];
        let rc = unsafe {
            tidecoin_node_mlkem512_encaps_deterministic(
                public_key.as_ptr(),
                public_key.len(),
                coins.as_ptr(),
                coins.len(),
                ct.as_mut_ptr(),
                ct.len(),
                ss.as_mut_ptr(),
                ss.len(),
            )
        };
        match rc {
            1 => Ok((ct, ss)),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_mlkem512_encaps_deterministic")),
        }
    }

    /// Decapsulates an ML-KEM-512 ciphertext using the Tidecoin node.
    pub fn mlkem512_decaps(
        &self,
        ciphertext: &[u8],
        secret_key: &[u8],
        shared_secret_len: usize,
    ) -> Result<Vec<u8>, NodeParityError> {
        let mut ss = vec![0u8; shared_secret_len];
        let rc = unsafe {
            tidecoin_node_mlkem512_decaps(
                ciphertext.as_ptr(),
                ciphertext.len(),
                secret_key.as_ptr(),
                secret_key.len(),
                ss.as_mut_ptr(),
                ss.len(),
            )
        };
        match rc {
            1 => Ok(ss),
            _ => Err(NodeParityError::BridgeFailure("tidecoin_node_mlkem512_decaps")),
        }
    }

    /// Original `VerifyScript` reports `SCRIPT_ERR_OK` exactly when it accepts.
    /// Any other combination, or an unknown code, is a bridge fault. It must
    /// not be read as a script verdict: mapping it to `UNKNOWN_ERROR` would
    /// compare equal to a genuine Rust `UNKNOWN_ERROR`.
    fn script_verdict(rc: i32, code: i32, name: &'static str) -> Result<(), NodeParityError> {
        match (rc, ScriptError::try_from_ffi(code)) {
            (1, Some(ScriptError::Ok)) => Ok(()),
            (0, Some(error)) if error != ScriptError::Ok => Err(NodeParityError::Script(error)),
            _ => Err(NodeParityError::BridgeFailure(name)),
        }
    }
}

# Falcon/PQ Gap Report

This report captures the validated Tidecoin node Falcon/PQ behaviors that are still missing from the Rust port.

Validation basis:

- Tidecoin node source under `/home/kiel/work/tidecoin-node`
- Rust port source under `/home/kiel/work/rust-tidecoin`
- independent multi-agent cross-checks against the node crypto, interpreter, test, wallet, and transport surfaces
- publish state confirmed at `origin/v2` commit `d8bbe1eddf4d27263bdfeb1e3d43f5541d4e6271`

## What Exists In Rust Today

- PQ container types and scheme prefixes in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs)
- PQHD v1 KDF/path validation primitives in [bitcoin/src/pqhd.rs](bitcoin/src/pqhd.rs)
- Tidecoin PSBT PQHD proprietary-origin helpers in [bitcoin/src/psbt/tidecoin.rs](bitcoin/src/psbt/tidecoin.rs)
- PQ address HRPs and `p2wsh512` address construction in [bitcoin/src/address/mod.rs](bitcoin/src/address/mod.rs)
- witness v1 64-byte program recognition in [bitcoin/src/blockdata/script/witness_program.rs](bitcoin/src/blockdata/script/witness_program.rs)
- `OP_SHA512` opcode naming/serialization in [bitcoin/src/blockdata/opcodes.rs](bitcoin/src/blockdata/opcodes.rs) and [primitives/src/opcodes.rs](primitives/src/opcodes.rs)
- node-backed address/WIF corpus coverage in [bitcoin/tests/key_io_vectors.rs](bitcoin/tests/key_io_vectors.rs)

These pieces still do not provide the node's full Falcon/PQ runtime behavior, but PQHD derivation and PSBT metadata are no longer just placeholders.

## Validated Missing Behaviors

1. Real PQ crypto backend parity is missing.
Node exposes public-key derivation, Falcon signing/verification, ML-DSA public-key derivation, ML-KEM-512 keypair/encap/decap, prefixed-key encode/decode helpers, and legacy-secret-key handling in [src/pq/pq_api.h](/home/kiel/work/tidecoin-node/src/pq/pq_api.h) and scheme metadata in [src/pq/pq_scheme.h](/home/kiel/work/tidecoin-node/src/pq/pq_scheme.h).
Rust only exposes containers and length tables in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs). Active signing/key APIs still use secp in [bitcoin/src/crypto/key.rs](bitcoin/src/crypto/key.rs), [bitcoin/src/bip32.rs](bitcoin/src/bip32.rs), and [bitcoin/src/sign_message.rs](bitcoin/src/sign_message.rs).

2. Scheme policy parity is missing.
Node gates PQ schemes by height in [src/pq/pq_scheme.h](/home/kiel/work/tidecoin-node/src/pq/pq_scheme.h): before auxpow only Falcon-512 is allowed.
Rust accepts all five prefixes in [bitcoin/src/crypto/pq.rs](bitcoin/src/crypto/pq.rs) with no height/policy layer.

3. PQHD descriptor/wallet integration and deterministic key generation remain missing.
Node defines PQHD constants in [src/pq/pqhd_params.h](/home/kiel/work/tidecoin-node/src/pq/pqhd_params.h), derives deterministic leaf material in [src/pq/pqhd_kdf.h](/home/kiel/work/tidecoin-node/src/pq/pqhd_kdf.h), and generates `pqhd(...)`-based descriptors with network and height checks in [src/wallet/walletutil.cpp](/home/kiel/work/tidecoin-node/src/wallet/walletutil.cpp).
Rust now has a matching KDF/path-validation module in [bitcoin/src/pqhd.rs](bitcoin/src/pqhd.rs), but it still lacks `pqhd(...)` key-expression parsing, wallet/descriptor generation, and deterministic PQ key generation from the derived stream material.

4. Interpreter/runtime support for Falcon/PQ script verification is missing.
Node defines and uses `SCRIPT_VERIFY_PQ_STRICT`, `SCRIPT_VERIFY_WITNESS_V1_512`, `SCRIPT_VERIFY_SHA512`, `SigVersion::WITNESS_V1_512`, `SignatureHash512`, and PQ signature checking in [src/script/interpreter.h](/home/kiel/work/tidecoin-node/src/script/interpreter.h) and [src/script/interpreter.cpp](/home/kiel/work/tidecoin-node/src/script/interpreter.cpp).
Rust currently stops at address/program/opcode modeling; there is no equivalent script interpreter or Falcon verification path.

5. `OP_SHA512` execution semantics are missing.
Node tests enabled/disabled behavior, discouragement, stack failures, and element-size boundaries in [src/test/script_tests.cpp](/home/kiel/work/tidecoin-node/src/test/script_tests.cpp).
Rust only serializes and names the opcode in [bitcoin/tests/serde_opcodes.rs](bitcoin/tests/serde_opcodes.rs), [bitcoin/src/blockdata/opcodes.rs](bitcoin/src/blockdata/opcodes.rs), and [primitives/src/opcodes.rs](primitives/src/opcodes.rs).

6. Witness v1 64-byte spending and SHA-512 sighash behavior are missing.
Node validates witness-v1-512 spending behavior and `SignatureHash512` edge cases in [src/test/script_tests.cpp](/home/kiel/work/tidecoin-node/src/test/script_tests.cpp) and [src/test/transaction_tests.cpp](/home/kiel/work/tidecoin-node/src/test/transaction_tests.cpp).
Rust supports only structural witness-program and address construction in [bitcoin/src/blockdata/script/witness_program.rs](bitcoin/src/blockdata/script/witness_program.rs) and [bitcoin/src/address/mod.rs](bitcoin/src/address/mod.rs).

7. PQ corpus migration is incomplete.
Node executes `script_tests_pq.json`, `tx_valid_pq.json`, `tx_invalid_pq.json`, PQ asset coverage, and PQ script coverage linting in [src/test/script_tests.cpp](/home/kiel/work/tidecoin-node/src/test/script_tests.cpp), [src/test/transaction_tests.cpp](/home/kiel/work/tidecoin-node/src/test/transaction_tests.cpp), [src/test/script_assets_tests.cpp](/home/kiel/work/tidecoin-node/src/test/script_assets_tests.cpp), and [test/lint/lint-pq-script-coverage.py](/home/kiel/work/tidecoin-node/test/lint/lint-pq-script-coverage.py).
Rust has migrated node key/address/WIF corpora in [bitcoin/tests/key_io_vectors.rs](bitcoin/tests/key_io_vectors.rs) and node-style PQHD origin/KDF tests in [bitcoin/src/psbt/tidecoin.rs](bitcoin/src/psbt/tidecoin.rs) and [bitcoin/src/pqhd.rs](bitcoin/src/pqhd.rs), but not the node PQ script/transaction corpora.

8. PQ multisig, standardness, and sigop/policy parity are missing.
Node has dedicated Falcon/PQ multisig and policy tests in [src/test/pq_multisig_tests.cpp](/home/kiel/work/tidecoin-node/src/test/pq_multisig_tests.cpp), [src/test/sigopcount_tests.cpp](/home/kiel/work/tidecoin-node/src/test/sigopcount_tests.cpp), and [src/test/transaction_tests.cpp](/home/kiel/work/tidecoin-node/src/test/transaction_tests.cpp).
Rust has generic policy helpers in [bitcoin/src/policy.rs](bitcoin/src/policy.rs) and generic sigop/script tests, but not node-equivalent PQ execution/policy regressions.

9. Tidecoin PQ transport is missing.
Node ships a dedicated PQ packet cipher in [src/bip324_pq.h](/home/kiel/work/tidecoin-node/src/bip324_pq.h).
Rust has no corresponding BIP324 PQ transport implementation.

## Bottom Line

The Rust port currently contains Falcon/PQ plumbing, not Falcon/PQ runtime parity.

The main missing implementation layers are:

- real PQ crypto operations
- scheme/height policy enforcement
- PQHD descriptor/wallet/keygen integration
- interpreter and sighash runtime support
- migration of node PQ script/transaction corpora
- PQ multisig/policy parity
- Tidecoin PQ transport

## Recommended Execution Order

1. Implement a real Rust PQ crypto backend that matches node `pq_api.h` and `pq_scheme.h`.
2. Add PQHD derivation and PSBT proprietary-origin support.
3. Add `SignatureHash512`, `OP_SHA512`, `SCRIPT_VERIFY_PQ_STRICT`, and witness-v1-512 runtime behavior.
4. Migrate node PQ script/transaction/multisig corpus tests.
5. Implement the Tidecoin PQ transport layer from `bip324_pq.h`.

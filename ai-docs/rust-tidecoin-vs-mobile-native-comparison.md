# rust-tidecoin vs mobile-native/rust-core: Full Comparison

## Scheme Support

| Aspect | `rust-tidecoin` | `mobile-native/rust-core` |
|---|---|---|
| Falcon-512 | Yes (prefix `0x07`) | Yes (only scheme, implicit) |
| Falcon-1024 | Yes (prefix `0x08`) | No |
| ML-DSA-44 | Yes (prefix `0x09`) | No |
| ML-DSA-65 | Yes (prefix `0x0A`) | No |
| ML-DSA-87 | Yes (prefix `0x0B`) | No |
| ML-KEM-512 | Yes (KEM, not signatures) | No |
| Scheme selection | `PqScheme` enum, 5 variants | None, Falcon-512 hardcoded throughout |

## Falcon Backend

| Aspect | `rust-tidecoin` | `mobile-native/rust-core` |
|---|---|---|
| Crate(s) | `tide-fn-dsa` (local path `../../tide-fn-dsa/tide-fn-dsa`) | `falcon` (local path `../falcon-rust/falcon`, v1.0.0) |
| What the Falcon backend provides | Deterministic keygen, pubkey derivation, strict Falcon sign/verify, and Tidecoin legacy Falcon-512 sign/verify | Keygen, sign, verify (entire Falcon implementation) |
| Signing randomness | `rand_core::OsRng` passed to `sign_falcon()` | `OsRng.fill_bytes()` into SHAKE256 seed for `falcon_sign_dyn` |
| Signing call | `SigningKeyStandard::sign_falcon(&mut OsRng, FalconProfile::PqClean, msg, &mut sig)` | `falcon_sign_dyn(&mut rng, &mut sig, MAX_LEN, FALCON_SIG_COMPRESS, sk, ...)` |
| Signature format | Strict mode uses PQClean-compatible compressed Falcon signatures; Falcon-512 also supports the Tidecoin legacy 690-byte envelope | Compressed format (`FALCON_SIG_COMPRESS = 1`) |

## Key Size Constants

| Constant | `rust-tidecoin` | `mobile-native/rust-core` |
|---|---|---|
| Falcon-512 pubkey | 897 (`pubkey_len()`) | `falcon_publickey_size!(9)` (evaluates to 897) |
| Falcon-512 seckey | 1281 (`seckey_len()`) | `falcon_privatekey_size!(9)` (evaluates to 1281) |
| Falcon-512 max sig | 752 (`max_sig_len()`) | `falcon_sig_compressed_maxsize!(9)` (evaluates to 752) |
| Falcon-512 seed | 48 (`deterministic_seed_len()`) | `FALCON_SEED_SIZE = 48` |
| Constants style | Integer literals in match arms | Macros computed from `FALCON_LOGN = 9` |

## Signing API

| Aspect | `rust-tidecoin` | `mobile-native/rust-core` |
|---|---|---|
| Public signing methods | `sign_msg32`, `sign_msg64`, `sign_msg32_legacy`, `sign_msg64_legacy` | `sign(message: &[u8], private_key: &[u8])` |
| Arbitrary-length message signing | No public API (internal `sign_message` is private) | Yes, `sign()` accepts `&[u8]` of any length |
| Legacy signing mode | Distinct only for Falcon-512: trims trailing zeros with a 42-byte minimum floor; other schemes fall back to normal signing | No distinct modes, only compressed format with truncation to actual length |
| Strict signing mode | Falcon strict signing uses full `signature_size(logn)` buffers; ML-DSA uses its own FIPS 204 signing path | N/A |
| Verification | `verify_msg32`, `verify_msg64`, `verify_msg32_legacy`, `verify_msg64_legacy`, `verify_msg32_allow_legacy`, `verify_msg64_allow_legacy` | `verify(message: &[u8], signature: &[u8], public_key: &[u8])` |
| Falcon verify fallback | Tries `vk.verify()` then `vk.verify_varlen()`; current `VERIFY_PQ_STRICT` still routes through this dual-path verifier | Single `falcon_verify()` with `FALCON_SIG_COMPRESS` |

## HD Key Derivation

| Aspect | `rust-tidecoin` | `mobile-native/rust-core` |
|---|---|---|
| Module | `pqhd` | `bip44` |
| Master node KDF | `hmac_sha512(b"Tidecoin PQHD seed", master_seed)` | `pbkdf2_hmac::<Sha512>(b"Tidecoin seed", bip39_seed, 10, &mut out)` |
| Master input | 32-byte master seed | 64-byte seed input to `from_seed()`; in normal mobile flow this comes from a separate mnemonic PBKDF2 step |
| Master output split | HMAC-SHA512 -> 32-byte node_secret + 32-byte chain_code | PBKDF2 96-byte -> 48-byte Falcon seed + 48-byte chain_code |
| Child derivation KDF | HMAC-SHA512 | PBKDF2-SHA512 (10 iterations) |
| Path structure | 6 hardened elements: `PURPOSE/COIN_TYPE/scheme/account/change/index` | Caller-supplied string path parsed by `derive_path()`; commonly BIP44-shaped, but not structurally enforced |
| PURPOSE | 10007 | Conventionally `44'` in caller-supplied mobile paths; not enforced by `rust-core` |
| COIN_TYPE | 6868 | User-supplied in path string |
| Scheme in path | Element 2 = `HARDENED \| scheme_prefix` | N/A |
| Non-hardened derivation | Not supported (hardened-only tree) | Supported |
| Keygen from leaf | Stream-based: HMAC-SHA512 extract/expand -> stream key -> retry loop (max 1024 attempts) | Direct: 48-byte seed -> `falcon_keygen_make` |
| Seed ID | `SeedId` = SHA256(`"Tidecoin PQHD seedid v1"` \|\| master_seed) | N/A |

## Public Key Prefix

| Aspect | `rust-tidecoin` | `mobile-native/rust-core` |
|---|---|---|
| Source | `PqScheme::prefix()` per scheme | Hardcoded `PUBLIC_KEY_PREFIX = 0x07` in `bip44.rs`, `ADDRESS_PREFIX = 0x07` in `address.rs` |
| Falcon-512 | `0x07` | `0x07` |
| Other schemes | `0x08`..`0x0B` | N/A |

## Address Types and Encoding

| Aspect | `rust-tidecoin` | `mobile-native/rust-core` |
|---|---|---|
| Address type enum | `P2pkh`, `P2sh`, `P2wpkh`, `P2wsh`, `P2wsh512` | `P2WPKH`, `P2SH`, `P2PKH` |
| P2WSH512 (PQ-native) | Yes: witness v1, 64-byte program in a PQ Bech32m namespace; SHA-512 relation is checked during spend validation | No |
| Standard HRPs | `tbc` (mainnet), `ttbc` (testnet), `rtbc` (regtest) | `tbc` only (hardcoded `ADDRESS_HRP`) |
| PQ HRPs | `q` (mainnet), `tq` (testnet), `rq` (regtest) | N/A |
| PQ address encoding | Bech32m with PQ HRP | N/A |
| P2PKH version | Network-dependent | `0x21` |
| P2SH version | Network-dependent | `0x41` |
| Taproot / P2TR | Accepted but unclassified (`v1+32 bytes` returns `None` from `address_type()`) | Not supported |

## Fee and Dust

| Aspect | `rust-tidecoin` | `mobile-native/rust-core` |
|---|---|---|
| Sig size for fee estimation | Policy uses `max_known_sig_bytes_in_script()` = max across all 5 schemes (4628 with sighash byte) | `FALCON_SIG_SIZE = 690` (hardcoded estimate, not the Falcon-512 max) |
| Pubkey size for fee estimation | `max_known_pubkey_bytes_in_script()` = max across all 5 schemes | `FALCON_PUBKEY_SIZE = 897` + `PUBKEY_PREFIX_SIZE = 1` = 898 |
| Fee rate tiers | N/A (full-node library, no wallet fee modes) | `Slow = 1`, `Normal = 5`, `Fast = 20`, `Custom(u64)` sat/vB |
| Dust threshold (P2WSH512) | 5,772 sat | N/A |
| Dust threshold (legacy) | Computed from `dust_relay_fee` and non-witness PQ `scriptSig` sizing | `DUST_THRESHOLD = 546` sat |

## Consensus and Policy

| Aspect | `rust-tidecoin` | `mobile-native/rust-core` |
|---|---|---|
| Height-gated activation | Yes: Falcon-512 always allowed; other 4 schemes require `auxpow_start_height = Some(start)` and `height >= start` | No |
| P2WSH512 consensus validation | Yes: native validation in `consensus_validation_tidecoin.rs`, with node-backed routing/parity coverage in `consensus_validation_node.rs` | No |
| P2WSH512 sighash | `p2wsh512_signature_hash()` delegates to the shared `consensus-core` implementation | N/A |
| Witness construction for PQ | Spend validation expects a witness-script-based stack; `Witness::p2wsh512_pq(signature, pubkey)` is only a helper, not the full consensus shape | N/A |
| WIF encoding | `PqWifKey` with `Prefixed` and `LegacyFalcon512` formats; recommended mobile integration should use `Prefixed` only | N/A |
| Secret key header validation | `0x59` for Falcon-512, `0x5A` for Falcon-1024, none for ML-DSA | None |

## Architecture

| Aspect | `rust-tidecoin` | `mobile-native/rust-core` |
|---|---|---|
| Role | General-purpose Tidecoin protocol library (serialization/parsing, scripts, PSBT, validation helpers, P2P message types) | Mobile wallet core (derive, sign, build tx) |
| API surface | Rust library types | Protobuf FFI (`tidecoin_call` for iOS C, `Java_com_tidecoin_core_FFIBridge_call` for Android JNI) |
| PSBT support | Yes | No |
| P2P / BIP324 with ML-KEM | Yes: protocol/message surfaces plus PQ transport primitives | No |
| Script types for signing | Full transaction/script validation entrypoints; classic script validation is feature-gated and Tidecoin-specific/PQ execution uses internal eval paths | P2WPKH, P2SH (nested SegWit), P2PKH |

---

# P2WSH512: The New PQ Address Type in rust-tidecoin

A witness v1 64-byte program in a dedicated PQ Bech32m namespace. During spend validation, the last witness item is treated as the witness script and must SHA-512-hash to that 64-byte program.

| Property | Value |
|---|---|
| Witness version | v1 |
| Program size | 64 bytes (SHA-512 hash) |
| Mainnet HRP | `q` (not `tbc`) |
| Testnet HRP | `tq` (not `ttbc`) |
| Regtest HRP | `rq` (not `rtbc`) |
| Encoding | Bech32m |
| Sighash | Custom `p2wsh512_signature_hash` backed by the shared `consensus-core` implementation |
| Witness stack | Witness-script-based; the final witness item is the script whose SHA-512 matches the program |
| Consensus gating | Native validation in `consensus_validation_tidecoin.rs`, with node-backed routing/parity coverage in `consensus_validation_node.rs` |
| Dust threshold | 5,772 sat (much higher than 546, due to large PQ witness sizes) |

Mainnet PQ addresses start with `q1...` instead of `tbc1...`, but `q1` is only a namespace prefix: validity still requires the PQ HRP to be paired with a witness-v1 64-byte program. This address type has its own sighash algorithm, its own witness-script spend path, and a higher dust threshold. The mobile app currently has no way to create or spend to PQ-native addresses.

---

# What New Features Integration Unlocks for Mobile

The points below are integration projections from the `rust-tidecoin` APIs that exist today. There is no standalone `tidecoin-pq` crate in this repository yet, so these should be read as "what a mobile-facing extraction of the PQ pieces would unlock", not as a current published crate surface.

Where the right-hand column says `mobile-native/rust-core`, note that the wider `mobile-native` repo sometimes adds Swift/Kotlin helpers on top of `rust-core`. Those app-layer additions are called out explicitly below when they matter.

## New Signature Schemes

The mobile app currently only knows Falcon-512. With `tidecoin-pq`, it gains four more schemes, each with different size and security tradeoffs:

| Scheme | Pubkey | Max Sig | Seed | Prefix | When allowed |
|---|---|---|---|---|---|
| Falcon-512 | 897 B | 752 B | 48 B | `0x07` | Always |
| Falcon-1024 | 1,793 B | 1,462 B | 48 B | `0x08` | When `auxpow_start_height = Some(start)` and `height >= start` |
| ML-DSA-44 | 1,312 B | 2,420 B | 32 B | `0x09` | When `auxpow_start_height = Some(start)` and `height >= start` |
| ML-DSA-65 | 1,952 B | 3,309 B | 32 B | `0x0A` | When `auxpow_start_height = Some(start)` and `height >= start` |
| ML-DSA-87 | 2,592 B | 4,627 B | 32 B | `0x0B` | When `auxpow_start_height = Some(start)` and `height >= start` |

Falcon-1024 gives a larger security margin with relatively compact signatures. The ML-DSA variants are NIST FIPS 204 standardized, which matters for compliance contexts, but their signatures are significantly larger than Falcon's. Under current network defaults, that activation rule is network-dependent: mainnet currently uses `auxpow_start_height = None`, testnet uses `Some(1000)`, and regtest uses `Some(0)`.

## New Address Type: P2WSH512

The mobile app currently creates P2WPKH (`tbc1...`), P2SH (Base58 version `0x41`), and P2PKH (Base58 version `0x21`) addresses. `rust-tidecoin` defines a PQ-native address type that the mobile app can't create or spend today.

P2WSH512 is a witness v1 64-byte program encoded in a separate Bech32m namespace. During spend validation, the witness script must SHA-512-hash to that program:

| Network | Standard HRP | PQ HRP |
|---|---|---|
| Mainnet | `tbc` | `q` |
| Testnet | `ttbc` | `tq` |
| Regtest | `rtbc` | `rq` |

Mainnet PQ addresses start with `q1...` instead of `tbc1...`. This address type has its own sighash algorithm (`p2wsh512_signature_hash`), its own witness-script spend path, and a higher dust threshold of 5,772 sat (vs the current 546 sat hardcoded in mobile).

Adding P2WSH512 support to mobile means the app could create and spend to PQ-native addresses, not just sign with PQ keys behind legacy address formats.

Whole-repo note: the current iOS/Android app-side recipient parsers accept `tbc` and `bel` HRPs for witness-v0 addresses, but they still reject PQ `q` / `tq` / `rq` addresses and have no P2WSH512 spend/build path.

## New Signing Modes

The mobile app currently has one signing path: `falcon_sign_dyn` with compressed format and random nonce, producing variable-length signatures truncated to actual length. With `tidecoin-pq`, it gains:

- **Strict signing** (`sign_msg32`, `sign_msg64`): Falcon uses `tide-fn-dsa` PQClean-compatible signing, while ML-DSA uses its FIPS 204 signing path.
- **Legacy signing** (`sign_msg32_legacy`, `sign_msg64_legacy`): publicly available for all schemes, but only Falcon-512 gets distinct trailing-zero trimming with a 42-byte floor; other schemes fall back to normal signing.
- **Hybrid verification** (`verify_msg32_allow_legacy`, `verify_msg64_allow_legacy`): adds legacy fallback for Falcon-512 and otherwise behaves like normal verification.

The mobile app's current `sign(arbitrary &[u8])` API doesn't have a direct equivalent in a mobile-facing extraction of the PQ API, which currently only exposes public `msg32` and `msg64` signers. That gap still needs to be closed before the mobile `SignMessage` handler can switch over.

## New Key Derivation: PQHD v1

The mobile app uses a caller-driven path parser plus PBKDF2-SHA512 (10 iterations, `"Tidecoin seed"` master secret) after a separate mnemonic-to-seed PBKDF2 stage. PQHD v1 is a fundamentally different system:

- HMAC-SHA512 based (not PBKDF2)
- 32-byte master seed input (not 64-byte BIP39 seed)
- Hardened-only tree (no non-hardened children)
- Scheme encoded in the path itself (element 2 = scheme prefix)
- Stream-based deterministic keygen with retry loop (up to 1024 attempts)
- `SeedId` for wallet identification across nodes

This doesn't replace the existing BIP44 derivation for current wallets. Existing Falcon-512 wallets must keep their current derivation to produce the same keys and addresses. PQHD v1 would be used for new wallets that want to use non-Falcon schemes or want to be compatible with the full node's derivation system.

## ML-KEM-512 Key Encapsulation

Not a signing primitive, but a key encapsulation mechanism. `rust-tidecoin` contains ML-KEM-backed BIP324 transport primitives and packet-cipher code today. Any mobile use beyond that would be future work rather than a current wallet feature.

## Scheme-Aware Fee Estimation

The mobile app hardcodes `FALCON_SIG_SIZE = 690` for all fee calculations. A future mobile-facing PQ extraction should expose per-scheme signature sizing instead of reusing that single constant. This matters because:

- ML-DSA-87 signatures are up to 4,627 bytes, over 6x larger than Falcon-512
- Fee estimates based on 690 bytes would be materially wrong for those schemes
- Even for strict Falcon-512, the correct max is 752, not 690

## WIF Key Import/Export

At the `rust-core` layer, there is no node-compatible PQ WIF type today. At the whole-`mobile-native` repo layer, the apps implement Falcon-512-only WIF/hex helpers in Swift/Kotlin using an app-local format.

### Migration Decision

Mobile should adopt canonical node-compatible PQ WIF and remove the current app-local Falcon-only WIF format entirely.

- Canonical mobile PQ WIF format: `PqWifKey::Prefixed`
- Backward compatibility with the current custom mobile WIF: intentionally dropped
- `LegacyFalcon512`: keep as a node-side compatibility format, but do not use it as the new mobile import/export target

That means existing app-local WIF strings should be treated as unsupported once the migration lands, rather than silently accepted or auto-converted.

Recommended direction: replace that app-local WIF completely with canonical node-compatible PQ WIF, and do not preserve backward compatibility with the current custom mobile encoding.

- New mobile WIF should be `PqWifKey::Prefixed` only.
- The current app-local Falcon-only format should be removed rather than supported in parallel.
- `LegacyFalcon512` exists in `rust-tidecoin`, but it should not be the new mobile import/export target if the goal is a clean break.

That yields a single scheme-aware, node-compatible PQ WIF path instead of the current app-local Falcon-only format.

### Proposed `rust-core` API Surface

To fit the existing protobuf FFI style, mobile PQ WIF support should live in `crypto.proto`, be routed through `ffi.proto`, and be implemented in `rust-core/src/crypto/handlers.rs`.

Suggested protobuf surface:

```proto
message ExportPqWifRequest {
  bytes private_key = 1;   // prefixed PQ secret key bytes
  uint32 network = 2;      // Tidecoin mainnet/testnet/regtest enum value
}

message ExportPqWifResponse {
  oneof result {
    ExportPqWifSuccess success = 1;
    tidecoin.ffi.Error error = 2;
  }
}

message ExportPqWifSuccess {
  string wif = 1;
}

message ParsePqWifRequest {
  string wif = 1;
}

message ParsePqWifResponse {
  oneof result {
    ParsePqWifSuccess success = 1;
    tidecoin.ffi.Error error = 2;
  }
}

message ParsePqWifSuccess {
  bytes private_key = 1;   // prefixed PQ secret key bytes
  bytes public_key = 2;    // prefixed PQ public key bytes, derived from the secret
  uint32 network = 3;      // Tidecoin mainnet/testnet/regtest enum value
}
```

Suggested FFI routing:

- Add `export_pq_wif` and `parse_pq_wif` requests/responses to `ffi.proto`
- Implement `handle_export_pq_wif(...)` and `handle_parse_pq_wif(...)` in `rust-core/src/crypto/handlers.rs`
- Put the actual encode/decode logic in a dedicated Rust helper module rather than in Swift/Kotlin

Suggested semantics:

- Accept and emit `PqWifKey::Prefixed` only
- Reject the current custom mobile WIF format instead of auto-migrating it
- Return prefixed PQ secret/public keys so the rest of mobile keeps using the same key representation it already uses in address and transaction code
- Derive `public_key` from the parsed secret on import so callers do not need to reconstruct it separately

## What Stays Node-Only

Some things in `rust-tidecoin` exist outside the likely scope of a mobile PQ extraction:

- Full consensus validation and script interpreter
- Height-gated scheme activation policy (`is_allowed_at_height`)
- P2P protocol/message surfaces and BIP324 transport primitives
- PSBT construction and parsing
- Multi-network address validation and namespace rules (`is_valid_for_network`, `require_network`, PQ HRP checks)

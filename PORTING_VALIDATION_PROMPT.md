# Validation Prompt for rust-tidecoin Port

Use this prompt with a fresh AI agent to validate the completeness and correctness of the rust-tidecoin library port.

---

## Source Repositories

| Repo | Location | Purpose |
|------|----------|---------|
| **rust-tidecoin** (the port) | `/home/kiel/work/rust-tidecoin/` | The deliverable - forked from rust-bitcoin |
| **rust-bitcoin upstream** | `/home/kiel/work/rust-bitcoin-upstream/` | Original unmodified rust-bitcoin HEAD |
| **Tidecoin C++ node** | `/home/kiel/work/tidecoin-node/` | Authoritative source of truth for all protocol params |
| **falcon-wasm** | `/home/kiel/work/falcon-wasm/` | Pure-Rust Falcon-512 implementation (no_std) |
| **Old rust-tidecoin** | `/home/kiel/work/rust-tidecoin-old/` | Previous incomplete port (v0.28.2 base, for reference only) |

## Research Documents Produced During Porting

Each document was produced by a dedicated research subagent that deeply explored one codebase:

| Document | Size | Contents |
|----------|------|----------|
| `/home/kiel/work/RESEARCH_TIDECOIN_NODE.md` | 24KB | **12 sections**: network params (magic, ports, prefixes, HRPs), consensus params (halving, PoW, difficulty), block/tx structure, mining algorithm (Yespower/Scrypt), PQ cryptography (5 schemes with exact sizes), script system (TxoutType, witness v1/P2WSH-512, SigVersion, OP_SHA512, verify flags), address types, PQHD wallet derivation, protocol versions, BIP324 PQ transport, versionbits, and comprehensive diff summary vs Bitcoin |
| `/home/kiel/work/RESEARCH_RUST_BITCOIN.md` | 27KB | **12 sections**: 16-crate workspace inventory, Network/Params/Magic/ports/genesis/ChainHash definitions with exact line numbers, address system (AddressType/KnownHrp/WitnessVersion/WitnessProgram), script/opcode system, key/signature types (secp256k1 integration), tx/block structures, consensus encoding traits, testing infrastructure, build system, and a 14-item modification checklist with file:line references |
| `/home/kiel/work/RESEARCH_OLD_PORT.md` | 20KB | Analysis of the v0.28.2-based previous port: 11-commit git history, what was changed (magic bytes, prefixes, HRPs, PoW limits, BIP heights), what was incomplete (genesis block placeholder, denomination strings still "BTC", rust-yespower unused, no Falcon/PQC), what was removed (Taproot, bitcoinconsensus, Signet/Regtest), full parameter comparison table |
| `/home/kiel/work/RESEARCH_FALCON.md` | 18KB | Falcon-wasm library deep-dive: Falcon-512 LOGN=9, key/sig sizes (PK 897, SK 1281, sig max 752), serialization formats (header bytes 0x59/0x09/0x39), WASM vs native architecture, Tidecoin node integration (PQClean C code, scheme prefix bytes 0x07-0x0B, legacy vs strict verification modes with different L2 norm bounds), PQHD deterministic keygen, compatibility analysis |
| `/home/kiel/work/VALIDATION_REPORT.md` | 15KB | Post-port cross-reference of every parameter in Rust vs C++ node. **Findings**: 10/12 items match exactly, 2 fixed (enforce_bip94 regtest, BIP0031_VERSION), 1 architectural limitation (regtest base58 prefixes share testnet values due to NetworkKind grouping) |
| `/home/kiel/work/TEST_AUDIT_REPORT.md` | 14KB | Test quality audit: 1798 passing, 21 ignored (12 fixable with new test vectors, 1 correctly ignored for Taproot), stale references found (from_btc/to_btc naming, 4 no_run doc examples with Bitcoin addresses), coverage gaps (P2WSH-512 needs end-to-end test, PQ module needs integration test, subsidy calculation untested), C++ tests worth porting (PQ key/sign/verify, address encoding vectors from key_io_tests.cpp) |

## Porting Process (Wave Structure)

### Wave 1: Deep Research (4 parallel agents)
Each agent explored one repository and wrote a research document (listed above). These documents were the foundation for all subsequent porting decisions.

### Wave 2: Core Parameter Port (6 parallel agents)
| Agent | Files Modified | Changes |
|-------|---------------|---------|
| Network crate | `network/src/lib.rs` | Enum: Tidecoin/Testnet/Regtest, removed Signet/TestnetVersion |
| P2P crate | `p2p/src/lib.rs`, `p2p/src/network_ext.rs`, `p2p/src/message.rs` | Magic bytes, ports, service flag docs |
| Units crate | `units/src/amount/*.rs` | TDC/tidoshi denominations, FORTY_TDC/FIFTY_TDC constants |
| Bitcoin crate constants | `bitcoin/src/blockdata/constants.rs`, `bitcoin/src/network/params.rs`, `bitcoin/src/network/mod.rs`, `bitcoin/src/pow.rs` | Genesis blocks, consensus params, chain hashes, PoW targets |
| Address & crypto | `bitcoin/src/address/mod.rs`, `bitcoin/src/crypto/key.rs`, `bitcoin/src/bip32.rs` | Bech32 HRPs (tbc/ttbc/rtbc), WIF prefixes (125/180), BIP32 HMAC seed |
| Cargo.toml & branding | All 16 `Cargo.toml` files + source crate refs | Package names, internal dependency refs, doc comments |

### Wave 3: Structural Changes (3 parallel agents)
| Agent | Files Created/Modified | Changes |
|-------|----------------------|---------|
| PQ crypto types | Created `bitcoin/src/crypto/pq.rs`, modified `bitcoin/src/crypto/mod.rs` | PqScheme enum (5 schemes), PqPublicKey, PqSecretKey, PqSignature with all sizes from node |
| P2WSH-512 addresses | Modified `bitcoin/src/address/mod.rs`, `primitives/src/script/witness_program.rs`, `bitcoin/src/blockdata/script/borrowed.rs`, `bitcoin/src/blockdata/script/mod.rs` | AddressType::P2wsh512, PQ HRP variants (q/tq/rq), WitnessProgram MAX_SIZE=64, custom bech32m encoder bypassing 90-char limit |
| Opcodes & script | Modified `bitcoin/src/blockdata/opcodes.rs`, `primitives/src/opcodes.rs`, `bitcoin/src/sign_message.rs`, `bitcoin/src/blockdata/script/borrowed.rs` | OP_SHA512 at 0xb3, "Tidecoin Signed Message:\n", witness_version() accepts 66-byte scripts, is_p2tr() returns false |

### Wave 4: Test Fixes & Validation (multiple agents + direct fixes)
- Fixed all test compilation errors across workspace
- Updated test vectors for Tidecoin (address strings, denomination strings, network variants)
- Marked 21 tests as `#[ignore]` with documented reasons (Bitcoin-specific test vectors, Taproot, PoW overflow)
- Populated real 898-byte Falcon-512 genesis pubkey from C++ node source
- Cross-referenced all parameters against C++ node (VALIDATION_REPORT.md)
- Audited test quality and coverage (TEST_AUDIT_REPORT.md)

---

## Validation Tasks

### 1. Compilation Verification
```bash
cd /home/kiel/work/rust-tidecoin
cargo check --workspace
cargo test --workspace --no-run
```
Both must succeed with zero errors. Warnings about dead code in `crypto/pq.rs` are expected.

### 2. Test Suite Verification
```bash
cargo test --workspace
```
Must show zero failures. Expected: ~1798 passed, 0 failed, ~21 ignored.

Verify every `#[ignore]`d test has a TODO comment:
```bash
grep -rn '#\[ignore\]' /home/kiel/work/rust-tidecoin/ --include='*.rs'
```

### 3. Parameter Cross-Reference (against C++ node)

Read both the Rust source and the C++ node source for each parameter. Key file mappings:

**C++ node files:**
- `tidecoin-node/src/kernel/chainparams.cpp` — magic bytes, genesis block, base58 prefixes, bech32 HRPs, consensus params
- `tidecoin-node/src/chainparamsbase.cpp` — RPC ports
- `tidecoin-node/src/consensus/consensus.h` — block size/weight limits
- `tidecoin-node/src/consensus/amount.h` — MAX_MONEY
- `tidecoin-node/src/script/script.h` — script limits, OP_SHA512
- `tidecoin-node/src/pq/pq_scheme.h` — PQ scheme IDs, key/sig sizes, scheme availability by height
- `tidecoin-node/src/node/protocol_version.h` — protocol version constants
- `tidecoin-node/src/consensus/params.h` — auxpow params, difficulty window
- `tidecoin-node/src/validation.cpp` — subsidy schedule (GetBlockSubsidy)
- `tidecoin-node/src/script/interpreter.h` — witness sizes, SigVersion, verify flags
- `tidecoin-node/src/addresstype.h` — CTxDestination variant
- `tidecoin-node/src/key_io.cpp` — address encoding/decoding, WIF encoding
- `tidecoin-node/src/pq/pqhd_params.h` — PQHD purpose (10007), coin type (6868)

**Rust library files:**
- `p2p/src/lib.rs` — Magic bytes, protocol versions
- `p2p/src/network_ext.rs` — P2P ports
- `network/src/lib.rs` — Network enum
- `bitcoin/src/blockdata/constants.rs` — genesis block, block limits, address prefixes, subsidy interval
- `bitcoin/src/network/params.rs` — consensus params
- `bitcoin/src/address/mod.rs` — bech32 HRPs, address types, PQ HRP variants
- `bitcoin/src/crypto/key.rs` — WIF prefix bytes (125/180)
- `bitcoin/src/crypto/pq.rs` — PQ scheme definitions and sizes
- `bitcoin/src/pow.rs` — PoW target constants
- `bitcoin/src/blockdata/opcodes.rs` — OP_SHA512
- `bitcoin/src/sign_message.rs` — signed message prefix
- `units/src/amount/unsigned.rs` — MAX_MONEY, denomination constants
- `units/src/amount/mod.rs` — Denomination enum (TDC, tidoshi, etc.)
- `bitcoin/src/bip32.rs` — HMAC seed ("Tidecoin seed")

Verify each parameter matches:

| Parameter | Rust File | C++ File | Expected Value |
|-----------|-----------|----------|---------------|
| Mainnet magic | `p2p/src/lib.rs` | `chainparams.cpp` | `[0xec, 0xfa, 0xce, 0xa5]` |
| Testnet magic | `p2p/src/lib.rs` | `chainparams.cpp` | `[0xba, 0xce, 0x3f, 0xda]` |
| Mainnet P2P port | `p2p/src/network_ext.rs` | `chainparamsbase.cpp` | 8755 |
| Testnet P2P port | `p2p/src/network_ext.rs` | `chainparamsbase.cpp` | 18755 |
| Regtest P2P port | `p2p/src/network_ext.rs` | `chainparamsbase.cpp` | 18778 |
| Mainnet pubkey prefix | `constants.rs` | `chainparams.cpp` | 33 |
| Mainnet script prefix | `constants.rs` | `chainparams.cpp` | 65 |
| Testnet pubkey prefix | `constants.rs` | `chainparams.cpp` | 92 |
| Testnet script prefix | `constants.rs` | `chainparams.cpp` | 127 |
| Mainnet WIF prefix | `crypto/key.rs` | `chainparams.cpp` | 125 |
| Testnet WIF prefix | `crypto/key.rs` | `chainparams.cpp` | 180 |
| Mainnet bech32 HRP | `address/mod.rs` | `chainparams.cpp` | "tbc" |
| Testnet bech32 HRP | `address/mod.rs` | `chainparams.cpp` | "ttbc" |
| Regtest bech32 HRP | `address/mod.rs` | `chainparams.cpp` | "rtbc" |
| PQ mainnet HRP | `address/mod.rs` | `chainparams.cpp` | "q" |
| PQ testnet HRP | `address/mod.rs` | `chainparams.cpp` | "tq" |
| PQ regtest HRP | `address/mod.rs` | `chainparams.cpp` | "rq" |
| Genesis nTime | `constants.rs` | `chainparams.cpp` | 1609074580 |
| Genesis nBits | `constants.rs` | `chainparams.cpp` | 0x2001ffff |
| Genesis nNonce | `constants.rs` | `chainparams.cpp` | 11033477 |
| Genesis reward | `constants.rs` | `chainparams.cpp` | 50 * COIN |
| Halving interval | `constants.rs` | `chainparams.cpp` | 262800 |
| Block spacing | `constants.rs` | `chainparams.cpp` | 60 seconds |
| Diff timespan | `constants.rs` | `chainparams.cpp` | 432000 |
| Diff interval | `constants.rs` | `chainparams.cpp` | 7200 |
| MAX_MONEY | `unsigned.rs` | `amount.h` | 21000000 * 100000000 |
| MAX_BLOCK_SIZE | `constants.rs` | `consensus.h` | 6000000 |
| MAX_SCRIPT_ELEMENT | `constants.rs` | `script.h` | 8192 |
| MAX_WITNESS_SCRIPT | `constants.rs` | `script.h` | 65536 |
| OP_SHA512 | `opcodes.rs` | `script.h` | 0xb3 |
| Signed msg prefix | `sign_message.rs` | N/A | "Tidecoin Signed Message:\n" |
| Falcon-512 prefix | `crypto/pq.rs` | `pq_scheme.h` | 0x07 |
| Falcon-512 PK size | `crypto/pq.rs` | `pq_scheme.h` | 897 |
| Falcon-512 SK size | `crypto/pq.rs` | `pq_scheme.h` | 1281 |
| Falcon-512 max sig | `crypto/pq.rs` | `pq_scheme.h` | 752 |
| Falcon-1024 prefix | `crypto/pq.rs` | `pq_scheme.h` | 0x08 |
| ML-DSA-44 prefix | `crypto/pq.rs` | `pq_scheme.h` | 0x09 |
| ML-DSA-65 prefix | `crypto/pq.rs` | `pq_scheme.h` | 0x0A |
| ML-DSA-87 prefix | `crypto/pq.rs` | `pq_scheme.h` | 0x0B |

### 4. Structural Completeness Checks

Verify these Tidecoin-specific features exist and are correct:

- [ ] **PQ crypto types** (`bitcoin/src/crypto/pq.rs`): `PqScheme` enum with all 5 schemes, `PqPublicKey` with `from_prefixed_slice`/`to_prefixed_bytes`/`key_id` (HASH160), `PqSecretKey`, `PqSignature`, `PqError` with Display/Error impls, unit tests
- [ ] **P2WSH-512 address type**: `AddressType::P2wsh512` with Display("p2wsh512")/FromStr, `KnownHrp::PqMainnet/PqTestnets/PqRegtest` with HRPs "q"/"tq"/"rq", `Address::p2wsh512([u8; 64], Network)` constructor, `from_bech32_pq()` custom decoder bypassing 90-char limit, `encode_pq_bech32m()` custom encoder
- [ ] **WitnessProgram**: `MAX_SIZE = 64` in `primitives/src/script/witness_program.rs`, `p2wsh512([u8; 64])` constructor, `is_p2wsh512()` method
- [ ] **Script validation**: `witness_version()` accepts up to `OP_PUSHBYTES_64` (66-byte scripts), `is_p2wsh512()` in ScriptExt trait
- [ ] **OP_SHA512**: opcode 0xb3 named "OP_SHA512" in both `opcodes.rs` and `primitives/src/opcodes.rs` display, backward-compat alias `OP_NOP4 = OP_SHA512`
- [ ] **Taproot de-emphasis**: `is_p2tr()` on ScriptPubKey always returns false, `Address::p2tr()` removed, `bip_341_tests` ignored
- [ ] **Network enum**: 3 variants (Tidecoin, Testnet, Regtest), no Signet, no TestnetVersion, correct string representations ("tidecoin"/"testnet"/"regtest")
- [ ] **Denominations**: TDC, cTDC, mTDC, µTDC, bit, tidoshi with correct Display/FromStr/serde
- [ ] **All 16 Cargo.toml renamed**: tidecoin, tidecoin-primitives, tidecoin-units, tidecoin-hashes, tidecoin-io, tidecoin-internals, tidecoin-network-kind, tidecoin-p2p-messages, tidecoin-consensus-encoding, tidecoin-addresses, tidecoin-crypto, tidecoin-bip158, tidecoin-key-expression, tidecoin-fuzz, tidecoin-benches, plus base58ck and chacha20-poly1305 kept generic
- [ ] **Genesis pubkey**: 898-byte array (0x07 prefix + 897 Falcon-512 raw pubkey) matching C++ node's genesisOutputScript

### 5. Known Limitations

These are intentional and documented:

1. **Regtest base58 prefixes** use testnet values (92/127/180 instead of C++ node's 117/122/15) because upstream's `NetworkKind::Test` groups both. This means regtest-generated addresses won't match the C++ node.
2. **Taproot module still exists** but is non-functional for Tidecoin: `is_p2tr()` returns false, `Address::p2tr()` removed, all Taproot tests ignored. Full removal is deferred to avoid cascading breakage across PSBT/sighash/pushbytes.
3. **PQ crypto types are containers only** — no signing/verification. Actual crypto requires linking to falcon/ML-DSA native libraries (the falcon crate at `/home/kiel/work/falcon-wasm/rust/falcon/` is `no_std` and could be integrated).
4. **BIP32 retained** but Tidecoin uses PQHD (purpose 10007, coin type 6868). HMAC seed changed to "Tidecoin seed". BIP32 test vectors ignored since they were computed with "Bitcoin seed".
5. **`from_btc()`/`to_btc()`/`from_btc_u16()` method names retained** for API stability. They operate on TDC internally. The denomination system (Display/FromStr) correctly uses "TDC"/"tidoshi".
6. **PoW validation not implemented** — Tidecoin uses Yespower 1.0 (pre-auxpow) and Scrypt (post-auxpow), not SHA256d. The library's PoW targets are set correctly but no PoW hash verification exists.
7. **Subsidy schedule not implemented** — Tidecoin uses a doubling-interval quartering schedule (40 TDC base, >>2 per era, interval doubles). The constant `SUBSIDY_HALVING_INTERVAL = 262800` is set but `GetBlockSubsidy` logic is not ported.
8. **Auxpow not implemented** — Tidecoin supports auxiliary proof-of-work (merge mining) with chain ID 8. Block header version bit 8 indicates auxpow. Not ported.
9. **SignatureHash512 not implemented** — Tidecoin's witness v1 uses SHA-512 based sighash producing uint512. The library defines the address type but not the sighash computation.
10. **Legacy vs strict PQ verification modes not implemented** — Pre-auxpow blocks use relaxed Falcon norm bound (43,533,782) and 690-byte max sig; post-auxpow uses standard bound (34,034,726) and 752-byte max.

### 6. Search for Remaining "Bitcoin" References

These greps should return zero results in non-test, non-comment, non-external-URL code:
```bash
grep -rn 'Network::Bitcoin' --include='*.rs' /home/kiel/work/rust-tidecoin/
grep -rn '0xF9, 0xBE, 0xB4, 0xD9' --include='*.rs' /home/kiel/work/rust-tidecoin/
grep -rn 'Magic::BITCOIN\b' --include='*.rs' /home/kiel/work/rust-tidecoin/
grep -rn 'ChainHash::BITCOIN\b' --include='*.rs' /home/kiel/work/rust-tidecoin/
grep -rn 'Params::TESTNET3\|Params::SIGNET' --include='*.rs' /home/kiel/work/rust-tidecoin/
```

These may have legitimate hits in doc comments, external URLs, or the retained taproot module's test data:
```bash
grep -rn '"bitcoin"' --include='*.rs' /home/kiel/work/rust-tidecoin/bitcoin/src/ | grep -v '//\|/\*\|test\|example\|bips\|wiki\|serde'
grep -rn '"BTC"' --include='*.rs' /home/kiel/work/rust-tidecoin/ | grep -v '//\|test\|#\[ignore\]'
```

### 7. Tidecoin-Specific Features NOT Yet Implemented (Future Work)

From the research documents, these features exist in the C++ node but are not yet in the Rust library:

1. **Actual PQ signing/verification** — integrate falcon crate or PQClean bindings
2. **PQHD key derivation** — purpose 10007, coin type 6868, hardened-only, scheme-specific leaf material
3. **SignatureHash512** — SHA-512 based BIP143 variant for witness v1_512
4. **Auxpow support** — merge-mined blocks with parent chain proof
5. **Yespower/Scrypt PoW** — mining hash verification
6. **Subsidy calculation** — doubling-interval quartering schedule
7. **SCRIPT_VERIFY_PQ_STRICT** — legacy vs strict Falcon verification mode flag
8. **SCRIPT_VERIFY_WITNESS_V1_512** — enable v1 64-byte witness execution
9. **SCRIPT_VERIFY_SHA512** — enable OP_SHA512 opcode
10. **ML-KEM-512 transport** — PQ key exchange for BIP324-like v2 transport
11. **SCRIPT_ADDRESS2** — Tidecoin's dual P2SH prefix (encode with 65, decode accepts both 65 and 70)
12. **Bech32 PQ character limit** — PQ addresses allow 120 chars vs standard 90 (partially implemented in custom encoder)

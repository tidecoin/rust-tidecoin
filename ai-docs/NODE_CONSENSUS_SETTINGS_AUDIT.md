# Tidecoin Node Consensus and Settings Audit

Status: active audit, 2026-04-12.

This document compares the current Rust workspace against the local Tidecoin
node checkout at `/home/yaroslav/dev/tidecoin/tidecoin`. The node is the
acceptance standard for consensus-sensitive behavior.

## Scope

Audited Rust surfaces:

- `tidecoin/src/network/params.rs`
- `tidecoin/src/pow.rs`
- `tidecoin/src/blockdata/block.rs`
- `tidecoin/src/blockdata/subsidy.rs`
- `primitives/src/block.rs`
- `primitives/src/transaction.rs`
- `consensus/src/lib.rs`
- `consensus-core/src/*`
- `ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md`
- `node-parity/src/*`
- selected p2p/network settings where they overlap exposed chain settings

Primary node references:

- `/home/yaroslav/dev/tidecoin/tidecoin/src/consensus/params.h`
- `/home/yaroslav/dev/tidecoin/tidecoin/src/kernel/chainparams.cpp`
- `/home/yaroslav/dev/tidecoin/tidecoin/src/pow.cpp`
- `/home/yaroslav/dev/tidecoin/tidecoin/src/pow.h`
- `/home/yaroslav/dev/tidecoin/tidecoin/src/primitives/pureheader.cpp`
- `/home/yaroslav/dev/tidecoin/tidecoin/src/auxpow.cpp`
- `/home/yaroslav/dev/tidecoin/tidecoin/src/auxpow.h`
- `/home/yaroslav/dev/tidecoin/tidecoin/src/validation.cpp`
- `/home/yaroslav/dev/tidecoin/tidecoin/src/consensus/tx_check.cpp`
- `/home/yaroslav/dev/tidecoin/tidecoin/src/consensus/validation.h`

## Executive Status

The Rust script/spend validation engine is no longer the main problem. The
current high-risk gap is the chain-level envelope around it: chain parameters,
header proof selection, AuxPoW context checks, difficulty transition rules, and
block/contextual validation.

The most important current facts:

- `consensus-core` owns the Tidecoin script interpreter, typed transaction
  context, sighash logic, PQ verification, and witness execution planning.
- `consensus` is a byte-oriented adapter over `consensus-core`; it is not a full
  block or chain validator.
- `primitives` owns block/header/AuxPoW/transaction wire types and codecs.
- `tidecoin::network::Params` now exposes the node fields required by PoW,
  AuxPoW retargeting, CSV, and Segwit-height contextual validation, but still
  omits deployment/chain-selection fields that only matter for full node
  validation.
- `tidecoin::pow` now has the node-style yespower/scrypt height selector,
  yespower and scrypt mining hashes, target derivation, pure-header PoW
  validation, heightless `CheckProofOfWorkAny` parity, AuxPoW context
  validation, pre/post-AuxPoW retarget switch, and
  `PermittedDifficultyTransition` parity. The yespower implementation comes
  from the published `rust-yespower` crate with default features disabled.
  Real testnet header and retarget-window fixtures now cover the AuxPoW
  activation area; broader historical chain walks remain open.
- `HeaderExt::validate_pow(params, height, required_target)` is now
  params/height-aware for the pure-header path and no longer falls back to
  `block_hash()`. It is not the right API for AuxPoW context validation.

## Current Implementation Matrix

| Surface | Current Rust owner | Node owner | Status |
| --- | --- | --- | --- |
| Script interpreter and witness/PQ spend rules | `consensus-core`; exposed by `consensus` and `tidecoin` | `script/interpreter.*`, `validation.cpp` script-flag scheduling | Mostly implemented. Needs exact Params/block-hash flag scheduling only if Rust grows block-context validation. |
| Byte-oriented single-input spend verification | `consensus/src/lib.rs` | No direct equivalent; node validates spends during `ConnectBlock` | Implemented as a library adapter. It is not a block, header, or chain validator. |
| Transaction, block, header, AuxPoW wire codecs | `primitives` | `primitives/block.*`, `primitives/transaction.*`, serialization code | Mostly implemented. AuxPoW wire modeling lives here; context validation lives in `tidecoin::pow`. |
| Exposed consensus params | `tidecoin/src/network/params.rs` | `consensus/params.h`, `kernel/chainparams.cpp` | Partial. PoW/AuxPoW retarget fields plus CSV and Segwit heights are now exposed; full-node fields like BIP34 hash, versionbits deployments, minimum chain work, and assume-valid are still intentionally not modeled. Also exposes a `bip16_time` field that is not present in node `Consensus::Params`. |
| Subsidy schedule | `tidecoin::subsidy::block_subsidy` in `tidecoin/src/blockdata/subsidy.rs` | `validation.cpp::GetBlockSubsidy`, `nSubsidyHalvingInterval` | Implemented. Rust tests now mirror the node's transition-boundary and fixed-height total-emission tests, and the node-parity bridge walks every representable transition boundary for mainnet, testnet, and regtest. Coinbase reward-claim validation remains `ConnectBlock` scope because it requires UTXO-derived fees. |
| Target/work integer math | `tidecoin/src/pow.rs` | `pow.cpp`, `arith_uint256` | Mostly implemented for library-level header validation. Node-style `derive_target(...)`, height-aware proof checks, heightless `validate_pow_any(...)`, and transition bounds exist; remaining work is broader node-vector coverage. |
| Header PoW validation | `tidecoin/src/blockdata/block.rs::HeaderExt::validate_pow`, `tidecoin::pow::validate_pow_any`, and `tidecoin::pow::validate_auxpow_context` | `CheckProofOfWork`, `CheckProofOfWorkAny`, `CheckBlockHeader`, `CheckAuxPowContext`, `HasValidProofOfWork` | Partially implemented. Rust derives target from `nBits`, takes params and height when available, uses selected yespower/scrypt mining hashes for pure headers, exposes the heightless node path, and validates AuxPoW context rules with synthetic, node-generated, node-bridge, and real testnet header fixtures. |
| Difficulty retargeting | `tidecoin/src/pow.rs::next_target_after` and `tidecoin/src/pow.rs::permitted_difficulty_transition` | `GetNextWorkRequired*`, `CalculateNextWorkRequired*`, `PermittedDifficultyTransition` | Partially implemented. The old/new switch, post-AuxPoW averaging-window path, node legacy overflow-guarded scaling, first mainnet historical retarget, permitted transition envelope, and active-chain RPC testnet genesis-to-activation, activation, first-AuxPoW, early post-AuxPoW, and later AuxPoW retarget windows through height 16120 exist; broader historical chains remain missing. |
| AuxPoW validation | Wire structs in `primitives`; context validator in `tidecoin::pow` | `CheckAuxPowContext`, `CAuxPow::check`, `HasValidProofOfWork` | Partially implemented. Synthetic and node-generated fixtures cover flag/payload consistency, activation, strict chain ID, merge-mining commitment shape, deterministic chain index, parent scrypt PoW, and real testnet AuxPoW headers. Invalid historical real-chain edge cases remain open if discovered. |
| Context-free transaction sanity | `primitives::transaction::check_transaction_sanity`; decoder calls the same function | `CheckTransaction` | Implemented for library-scope context-free sanity: empty input/output rejection, stripped-weight limit, money range, duplicate inputs, null-prevout rules, and coinbase scriptSig length 2..=106. Node-backed edge tests exist. |
| Context-free block sanity | `primitives::block::check_block_sanity`; high-level `tidecoin` re-export | `CheckBlock` | Implemented for context-free block structure: empty block, first/only coinbase, merkle root and Merkle-mutation duplicate txid rejection, per-transaction sanity, stripped-size limit, and legacy sigop cost. Header PoW/AuxPoW, witness commitment, and full witness-inclusive weight are intentionally separate because the node handles those outside the context-free `CheckBlock` body. Node-backed edge tests exist. |
| Contextual header/block validation | `tidecoin::block_validation` | `ContextualCheckBlockHeader`, `ContextualCheckBlock`, `AcceptBlockHeader`, `ConnectBlock` | Header-context pass implemented: previous-hash link, exact next `nBits`, previous MTP, BIP94 timewarp bound, optional future-time check, buried version gates, post-AuxPoW base-version check, and PoW/AuxPoW validation. Non-UTXO block-context checks now cover transaction finality, BIP34 coinbase height, pre-activation witness rejection, witness commitment validation, and full block weight, with focused node-bridge parity tests. UTXO/chain-connect validation is deferred to a future separate crate. |
| UTXO/chain connect | Deferred separate crate; design note in `ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md` | `ConnectBlock`, `CheckTxInputs`, `SequenceLocks`, chainstate code | Out of current `rust-tidecoin` protocol-crate scope. This requires chainstate/UTXO database ownership and should be implemented later as a dedicated chain-validation crate, not folded into `tidecoin`, `primitives`, `consensus-core`, or `consensus`. |

## Consensus Parameter Audit

Node `Consensus::Params` contains more fields than Rust currently exposes in
`tidecoin::network::Params`.

### Node Values by Network

These are the current node values observed in
`/home/yaroslav/dev/tidecoin/tidecoin/src/kernel/chainparams.cpp`.

| Field | Mainnet | Testnet | Regtest | Rust status |
| --- | --- | --- | --- | --- |
| `nSubsidyHalvingInterval` | `262800` | `262800` | `20` | Exposed as `subsidy_initial_interval`. |
| `BIP34Height` | `1` | `1` | `1`, overrideable in node regtest options | Exposed as `bip34_height`; no regtest override model. |
| `BIP65Height` | `1` | `1` | `1`, overrideable in node regtest options | Exposed as `bip65_height`; no regtest override model. |
| `BIP66Height` | `1` | `1` | `1` | Exposed as `bip66_height`. |
| `CSVHeight` | `1` | `1` | `1`, overrideable in node regtest options | Exposed as `csv_height`; no regtest override model. |
| `SegwitHeight` | `1` | `1` | `0`, overrideable in node regtest options | Exposed as `segwit_height`; no regtest override model. |
| `nAuxpowStartHeight` | disabled | `1000` | `0` | Exposed as `auxpow_start_height`. |
| `nAuxpowChainId` | `8` | `8` | `8` | Exposed as `auxpow_chain_id`. |
| `fStrictChainId` | `true` | `true` | `true` | Exposed as `strict_auxpow_chain_id`. |
| `powLimit` | `01ff...ffff` | `01ff...ffff` | `0f0f...0f0f` | Exposed indirectly as `max_attainable_target`; exact raw target derivation API is missing. |
| `nPowTargetTimespan` | `432000` | `432000` | `14400` | Exposed as `pow_target_timespan`. |
| `nPowTargetSpacing` | `60` | `60` | `60` | Exposed as `pow_target_spacing`. |
| `fPowAllowMinDifficultyBlocks` | `false` | `true` | `true` | Exposed as `allow_min_difficulty_blocks`; the legacy path and permitted-transition envelope use it. |
| `enforce_BIP94` | `false` | `false` | `true` | Exposed as `enforce_bip94`; contextual header validation uses it for the timewarp bound on adjustment blocks. |
| `fPowNoRetargeting` | `false` | `false` | `true` | Exposed as `no_pow_retargeting`; Rust applies it in legacy and post-AuxPoW retarget paths. |
| `nPowAllowMinDifficultyBlocksAfterHeight` | `nullopt` | `nullopt` | `nullopt` | Exposed as `pow_allow_min_difficulty_blocks_after_height`. |
| `nPowAveragingWindow` | `17` | `17` | `17` | Exposed as `pow_averaging_window`. |
| `nPowMaxAdjustDown` | `32` | `32` | `0` | Exposed as `pow_max_adjust_down`. |
| `nPowMaxAdjustUp` | `16` | `16` | `0` | Exposed as `pow_max_adjust_up`. |
| P2P message start | `ec fa ce a5` | `ba ce 3f da` | `ba ce 3f da` | Implemented in `p2p`; not consensus params. |
| Default P2P port | `8755` | `18755` | `18778` | Implemented in `p2p`; not consensus params. |
| Bech32 HRP | `tbc` | `ttbc` | `rtbc` | Implemented in address/network-facing APIs. |

### Field-Level Status

| Node field | Rust status | Required action |
| --- | --- | --- |
| `hashGenesisBlock` | Not in `Params`; Rust exposes genesis via `genesis_block(...)`, `ChainHash`, and `NetworkExt::chain_hash()`. | Acceptable unless we want one params object to carry every node consensus field. If full node-param parity is desired, add `genesis_hash` to `Params` and derive it from the existing constants. |
| `nSubsidyHalvingInterval` | Implemented as `subsidy_initial_interval`. Main/testnet use `262_800`, regtest uses `20`. | Keep Rust naming because Tidecoin schedule is quartering with a doubling interval, not literal halving. |
| `script_flag_exceptions` | Not exposed. Current chainparams scan did not find assignments in the local node checkout. | Not a live gap if the map stays empty. If implementing exact `GetBlockScriptFlags`, model it as an optional exception map or document that Tidecoin has no active entries. |
| `BIP34Height` | Exposed as `bip34_height`. | Keep name as node-aligned. |
| `BIP34Hash` | Not exposed. Node uses it for BIP30 enforcement logic in `validation.cpp`. | Add only if Rust grows UTXO/chain-connect validation or BIP30 checks. Not required for standalone script validation. |
| `BIP65Height` | Exposed as `bip65_height`. | Keep name as node-aligned. |
| `BIP66Height` | Exposed as `bip66_height`. | Keep name as node-aligned. |
| `CSVHeight` | Exposed as `csv_height`. The contextual block path uses it to select the node's lock-time cutoff source for finality. | Keep. If exact regtest override parity becomes a goal, add a separate regtest settings override layer instead of mutating the static params. |
| `SegwitHeight` | Exposed as `segwit_height`. The contextual block path uses it to reject witness data before activation. | Keep. If exact regtest override parity becomes a goal, add a separate regtest settings override layer. |
| `nAuxpowStartHeight` | Exposed as `auxpow_start_height`. Mainnet disabled as `None`, testnet `Some(1000)`, regtest `Some(0)`. | Keep. This field must become the switch for PoW hash selection, AuxPoW validation, PQ strict flags, witness-v1-512, and `OP_SHA512`. |
| `nAuxpowChainId` | Exposed as `auxpow_chain_id`. | Keep. Must be used by AuxPoW chain ID validation, not only stored. |
| `fStrictChainId` | Exposed as `strict_auxpow_chain_id`. Node sets it to `true` on mainnet, testnet, and regtest. | Use it when implementing AuxPoW context validation. |
| `MinBIP9WarningHeight` | Not exposed. | Likely out of Rust library consensus scope unless implementing versionbits warning behavior. |
| `vDeployments` | Not exposed except indirectly through `rule_change_activation_threshold` and `miner_confirmation_window`. | If versionbits state is a library goal, expose deployments. For current validation focus, buried heights and AuxPoW height are more important. |
| `powLimit` | Exposed as `max_attainable_target`, not raw `powLimit`. `derive_target(bits, params)` now matches node rejection semantics for zero, negative, overflow, and above-limit targets. | Keep using `derive_target(...)` in future proof-check APIs. |
| `fPowAllowMinDifficultyBlocks` | Exposed as `allow_min_difficulty_blocks`. | Keep. The legacy path uses it; the post-AuxPoW path follows the node's separate optional height gate. |
| `enforce_BIP94` | Exposed as `enforce_bip94`. | Keep name as node-aligned. Used by contextual header timestamp checks. |
| `fPowNoRetargeting` | Exposed as `no_pow_retargeting`. | Keep. Rust now applies it in both legacy and post-AuxPoW retarget paths. |
| `nPowTargetSpacing` | Exposed as `pow_target_spacing`. | Keep. |
| `nPowTargetTimespan` | Exposed as `pow_target_timespan`. | Keep. |
| `nPowAllowMinDifficultyBlocksAfterHeight` | Exposed as `pow_allow_min_difficulty_blocks_after_height`, defaulting to `None` for current mainnet/testnet/regtest. | Keep for literal node algorithm parity. |
| `nPowAveragingWindow` | Exposed as `pow_averaging_window`. Node sets `17`. | Keep and use in post-AuxPoW retargeting. |
| `nPowMaxAdjustDown` | Exposed as `pow_max_adjust_down`. Node sets `32` on main/testnet and `0` on regtest. | Keep; used by post-AuxPoW retargeting and `permitted_difficulty_transition(...)`. |
| `nPowMaxAdjustUp` | Exposed as `pow_max_adjust_up`. Node sets `16` on main/testnet and `0` on regtest. | Keep; used by post-AuxPoW retargeting and `permitted_difficulty_transition(...)`. |
| `nMinimumChainWork` | Not exposed. | Out of scope unless Rust implements chain selection/header sync. |
| `defaultAssumeValid` | Not exposed. | Out of scope unless Rust implements node-like chain validation shortcuts. |

Rust-only exposed field:

| Rust field | Node status | Required action |
| --- | --- | --- |
| `bip16_time` | Not present in node `Consensus::Params`. The node's `GetBlockScriptFlags` starts from `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS` and then applies `script_flag_exceptions`. | Remove from consensus params or clearly move to a historical/provenance-only compatibility surface. It should not be treated as an active Tidecoin node consensus parameter. |

Regtest-specific node options are also not represented: the node can override
buried deployment heights and versionbits params through `RegTestOptions`. Rust
only exposes fixed `Params::REGTEST`. That is acceptable for simple library
usage, but it is not full node settings parity.

## Exposed Network Settings

The P2P/network constants are mostly in good shape:

- P2P magic values match the node: mainnet `ec fa ce a5`, testnet/regtest
  `ba ce 3f da`.
- Default P2P ports match the node: mainnet `8755`, testnet `18755`,
  regtest `18778`.
- Base58 prefixes and Bech32/PQ HRPs are implemented in the address layer and
  line up with the node values visible in `chainparams.cpp`.

Remaining caveat:

- These settings are split across `p2p`, `tidecoin::address`, and
  `tidecoin::network::Params`. That split is acceptable because ports/magic are
  transport settings, not chain consensus parameters. Do not move P2P magic or
  ports into consensus params unless a single node-settings object is explicitly
  introduced.

## Header PoW and Difficulty Audit

### Implemented

- Rust has `Target`, `CompactTarget`, work/difficulty helpers, and compact
  encoding/decoding.
- Rust has `next_target_after(...)` with the node's pre/post-AuxPoW switch and
  post-AuxPoW averaging-window retarget algorithm.
- Rust has `pow_hash_algorithm_at_height(...)`, which mirrors the node's
  yespower-before-AuxPoW and scrypt-at/after-AuxPoW selector.
- Rust stores `auxpow_start_height`, `auxpow_chain_id`, and AuxPoW wire payloads.

### Not implemented or wrong

| Node behavior | Rust status | Required action |
| --- | --- | --- |
| `CPureBlockHeader::GetPoWHash()` uses Tidecoin yespower over the pure 80-byte header. | Implemented as `yespower_pow_hash(...)` through the published `rust-yespower` crate, with node-backed bridge coverage. | Keep node fixture coverage and dependency feature hygiene. |
| `CPureBlockHeader::GetScryptPoWHash()` uses scrypt-1024-1-1-256 over the pure 80-byte header. | Implemented as `scrypt_pow_hash(...)` using `Header::pure_header_bytes()` and node-backed bridge coverage. | Keep node fixture coverage. |
| `UseScryptPoW(params, height)` switches at AuxPoW activation. | Implemented as `pow_hash_algorithm_at_height(...)`. | Keep covered by activation-boundary tests. |
| `GetPoWHashForHeight(block, params, height)` selects yespower before AuxPoW and scrypt at/after AuxPoW. | Implemented as `mining_hash_for_height(...)`; both branches have node-bridge coverage. | Add broader height/window vectors. |
| `CheckProofOfWork(hash, nBits, params)` derives and validates target from `nBits` and `powLimit`. | Target derivation exists as `derive_target(...)`; pure-header validation uses it. | Add direct hash+bits helper only if a public low-level API is needed. |
| `CheckProofOfWork(block, params, height)` validates selected mining hash against `nBits`. | Implemented for pure headers as `validate_pow_at_height(header, params, height)`, with node-bridge pass/fail coverage for yespower and scrypt. `validate_pow_at_height_against_target(...)` and `HeaderExt::validate_pow(...)` add the separate contextual expected-target check. | Keep contextual AuxPoW validation separate. |
| `CheckProofOfWorkAny(block, params)` accepts either yespower or scrypt for anti-DoS/header-sync contexts without height. | Implemented as `validate_pow_any(...)`, with node-bridge pass/fail coverage for yespower and scrypt through the header PoW bridge. | Keep separate from height-known consensus validation. |
| `CheckAuxPowContext(...)` validates AuxPoW flag/payload, activation, chain ID, merkle commitment, and parent scrypt PoW. | Implemented as `validate_auxpow_context(...)` in `tidecoin::pow` for the pure-header context path, with node-bridge header PoW coverage, a node-generated fixture matrix, and real testnet AuxPoW headers. | Add any remaining historical edge fixtures if discovered. Mainnet currently has no AuxPoW activation height. The current bridge deliberately avoids linking full `validation.cpp` but mirrors `HasValidProofOfWork` header behavior. |
| `GetNextWorkRequired(...)` switches old/new difficulty rules by AuxPoW activation height. | Implemented in `next_target_after(...)`. | Add more node-vector coverage. |
| `GetNextWorkRequiredNew(...)` uses averaging window, median-time-past, min/max actual timespan, and no-retargeting behavior. | Implemented for `next_target_after(...)`. | Add historical chain vectors and any edge-case coverage missing from the synthetic tests. |
| `PermittedDifficultyTransition(...)` enforces pre-activation old bounds and post-activation max-adjust bounds with compact rounding tolerance. | Implemented as `permitted_difficulty_transition(...)` with node-bridge coverage for mainnet legacy transition cases and synthetic post-AuxPoW coverage. | Add broader historical and post-activation vectors if/when a network exposes non-min-difficulty post-AuxPoW transition checks. |

### Required implementation boundary

- `primitives`: continue to own pure header and AuxPoW wire codecs.
- `tidecoin::pow`: own target derivation, yespower/scrypt mining hashes,
  AuxPoW context checks, and difficulty transitions.
- `consensus-core`: should not depend on mining hash algorithms unless the
  workspace intentionally redefines it as the full chain consensus engine.
- `consensus`: should remain a byte-oriented spend-verification adapter, not a
  block/header chain validator.

## AuxPoW Audit

### Implemented

- `primitives::block::AuxPow` models the node wire layout.
- Header decoding attaches AuxPoW payloads when the AuxPoW version flag is set.
- Header pure encoding exists for parent header serialization.
- Tests cover AuxPoW roundtrip and minimal synthetic AuxPoW payload shape.

### Implemented context checks

- Reject AuxPoW flag with missing payload.
- Reject AuxPoW payload without flag.
- Reject AuxPoW before activation height.
- Reject chain ID mismatch when `strict_chain_id` is active.
- Reject chain ID bits when AuxPoW flag is absent.
- Validate parent coinbase merkle branch against parent block merkle root.
- Validate chain merkle branch from child block hash into the parent coinbase
  merged-mining commitment.
- Enforce merged-mining header placement and uniqueness.
- Enforce chain merkle branch length limit.
- Enforce expected chain index from nonce, chain ID, and branch height.
- Validate parent PoW using the parent header scrypt hash against the child
  block `nBits`.

Required node parity tests:

- missing AuxPoW payload
- unexpected AuxPoW payload
- AuxPoW pre-activation
- wrong chain ID
- parent has Tidecoin chain ID when strict-chain-ID is enabled
- invalid parent coinbase merkle branch
- invalid chain merkle branch / missing chain merkle root
- missing merged-mining header
- duplicate merged-mining header
- merged-mining header not immediately before the root
- wrong chain merkle size/nonce/index
- missing chain merkle size/nonce metadata
- parent PoW failure
- valid minimal AuxPoW fixture generated by the node

## Script and Spend Consensus Audit

### Implemented

- Tidecoin script flags exist in `consensus-core` and are re-exported by
  `consensus` and `tidecoin`.
- `VERIFY_PQ_STRICT`, `VERIFY_WITNESS_V1_512`, and `VERIFY_SHA512` match the
  node flag bit positions.
- `consensus-core` owns the interpreter, witness-v1-512 execution planning, PQ
  verification facade, and sighash behavior.
- The node-backed harness covers imported Tidecoin PQ script/transaction corpora.

### Remaining gaps

| Node behavior | Rust status | Required action |
| --- | --- | --- |
| `GetBlockScriptFlags(block_index, chainman)` derives flags from buried deployment state, script exceptions, and AuxPoW height. | Rust has `height_to_flags_with_auxpow_start_height(height, auxpow_start_height)` and manual flags. The helper enables CLTV/CSV/NULLDUMMY unconditionally in its base set, so it is not exact for pre-activation heights, genesis/regtest overrides, or future script exceptions. | Add a Params-based helper if the library wants node-like block validation: `block_script_flags(params, height, block_hash)`. It should start from P2SH/WITNESS, apply script exceptions, then add CLTV/CSV/NULLDUMMY from deployment heights, and add PQ_STRICT/WITNESS_V1_512/SHA512 at AuxPoW height. |
| Node script flags for historical blocks can be exception-mapped. | Not represented. No active exception assignments were found in current `chainparams.cpp`. | Document no active Tidecoin exceptions or add an empty exception table for forward compatibility. |
| `verify(...)` in `consensus` defaults to `VERIFY_ALL_TIDECOIN`. | Works for post-AuxPoW validation but is not height-aware. | Keep for explicit post-AuxPoW verification. For chain validation, call a height-derived flag helper instead. |

## Transaction Sanity Audit

Node `CheckTransaction(...)` is context-free and currently does:

- reject empty inputs
- reject empty outputs
- reject stripped transaction weight above `MAX_BLOCK_WEIGHT`
- reject negative output values
- reject output values above `MAX_MONEY`
- reject total output sum above `MAX_MONEY`
- reject duplicate inputs
- for coinbase, require scriptSig length between 2 and 106 bytes
- for non-coinbase, reject null prevouts

Rust status:

| Check | Rust status | Required action |
| --- | --- | --- |
| Empty inputs | Implemented in `check_transaction_sanity(...)` and enforced by decoder finalization. | Keep node-backed edge coverage. |
| Empty outputs | Implemented in `check_transaction_sanity(...)` and enforced by decoder finalization. | Keep. |
| Stripped weight limit | Implemented in `check_transaction_sanity(...)` using Tidecoin `MAX_BLOCK_WEIGHT = 6_000_000`. | Keep direct oversize coverage and node-backed block/transaction edge tests. |
| Output values above `MAX_MONEY` | Implemented by `Amount` decoding and total-sum validation. | Keep. |
| Negative output values | Encoded negative node values become out-of-range unsigned amounts in Rust. | Add explicit test vectors if not already covered by node corpus. |
| Duplicate inputs | Implemented in `check_transaction_sanity(...)` and enforced by decoder finalization. | Keep. |
| Null prevout in non-coinbase | Implemented in `check_transaction_sanity(...)` and enforced by decoder finalization. | Keep node-backed edge coverage. |
| Coinbase scriptSig upper bound | Implemented as node limit `106`; tests cover 1, 2, 100, 101, 106, and 107. | Keep. |

Architectural note: putting all node `CheckTransaction` semantics in the
decoder is awkward because decoding and consensus sanity are different
responsibilities. The current design uses a canonical explicit
`check_transaction_sanity(tx)` function and has the decoder call the same
function at finalization so there is one sanity source of truth.

## Block Validation Audit

Rust `Block::validate()` in `primitives` currently delegates to
`check_block_sanity(...)`, which checks:

- block has transactions
- first transaction is coinbase
- no later transaction is coinbase
- transaction merkle root matches header
- every transaction passes `check_transaction_sanity(...)`
- stripped block size and full block weight respect Tidecoin
  `MAX_BLOCK_WEIGHT`
- legacy signature operation cost respects `MAX_BLOCK_SIGOPS_COST`
- witness commitment matches witness data when witness data exists

Header PoW and AuxPoW context remain separate because they require selected
mining-hash and chain-height context. Exact node reject-reason strings are not
part of the Rust public error contract.

Implemented contextual header parity:

- previous-hash linkage to the supplied previous header
- `bad-diffbits`: candidate `nBits` must equal `GetNextWorkRequired(...)`
- `time-too-old`: block time must be greater than previous median time past
- BIP94 timewarp mitigation on difficulty-adjustment blocks
- optional future timestamp limit when the caller supplies current time
- version gates for BIP34, BIP66, BIP65
- post-AuxPoW base-version validity
- selected pure-header PoW or AuxPoW-context validation at candidate height

Implemented non-UTXO contextual block parity:

- final transaction checks at height/time
- BIP34 coinbase height enforcement at active height
- witness malleation validation using active Segwit deployment state
- focused node-bridge parity tests for finality, BIP34 coinbase height, and
  pre-activation witness rejection

Deferred UTXO-dependent block/chain-connect scope:

- BIP30 duplicate transaction overwrite checks
- sequence-lock validation
- UTXO-dependent spend/input checks and fee validation

Required design split:

- `primitives::Block::validate()` should not become a full chain validator.
  It can stay as structural validation if clearly documented.
- `tidecoin::block_validation` owns node-style contextual header and non-UTXO
  contextual block checks over an explicit previous-header/history callback.
- UTXO-dependent block acceptance should be a later separate crate with an
  explicit chainstate/UTXO abstraction, not part of the current protocol
  library boundary.

## Deferred UTXO and Chain-Connect Scope

The current Rust library intentionally does not implement full node chain
connection, matching the usual `rust-bitcoin`-style protocol-library boundary.
The following checks require a chainstate/UTXO database, block index, and
undo/state-management model, so they are deferred to a future dedicated
chain-validation crate:

- UTXO lookup and spend availability checks
- fee and value-in/value-out checks
- coinbase maturity
- BIP30 duplicate transaction overwrite behavior
- sequence locks against active chain state
- signature-cache or assume-valid shortcuts
- chainwork comparison and minimum-chainwork policy
- assume-valid behavior

This is not a defect in the current `rust-tidecoin` crate. The crate should not
claim full chain consensus coverage, and it should not grow ad-hoc database-like
state to close these items. When this functionality is needed, add it as a
separate crate layered over the existing primitives, PoW, contextual validation,
and consensus-core surfaces.

The concrete design handoff for this future crate is
[`CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md`](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/CHAIN_CONNECT_VALIDATION_CRATE_SPEC.md).
That spec defines the intended layer split:

- `primitives::transaction::check_transaction_sanity` mirrors node
  `CheckTransaction`
- `primitives::block::check_block_sanity` mirrors context-free node
  `CheckBlock`
- `tidecoin::block_validation` mirrors node contextual header/block checks that
  do not need UTXO state
- the future chain-validation crate mirrors `ConnectBlock`, `CheckTxInputs`,
  sequence locks, fee accounting, BIP30, coinbase maturity, and coinbase
  reward-claim validation

## Priority Implementation Plan

1. Keep `validate_pow_at_height(header, params, height)` as the node-shaped
   pure-header `CheckProofOfWork(block, params, height)` equivalent: it derives
   the target from header `nBits`, selects yespower or scrypt by height, and
   checks the selected hash against the header target.
2. Keep `HeaderExt::validate_pow(params, height, required_target)` scoped as a
   pure-header helper. It is not an AuxPoW context validator.
3. Keep AuxPoW context validation in the chain/Pow layer, not in `primitives`.
4. Add broader node-vector coverage around `GetNextWorkRequired(...)`,
   `PermittedDifficultyTransition(...)`, and node-generated AuxPoW fixtures.
5. Keep the explicit node-parity transaction sanity API aligned with node
   `CheckTransaction(...)`.
6. Add a height/params-derived script flag helper for chain validation.
7. Keep `tidecoin::block_validation` limited to UTXO-independent contextual
   block checks. UTXO-dependent validation is a future separate-crate scope.

## Concrete Implementation Backlog

This is the current code-facing backlog implied by the audit.

### Params and Settings

- `strict_auxpow_chain_id`, `pow_allow_min_difficulty_blocks_after_height`,
  `pow_averaging_window`, `pow_max_adjust_down`, and `pow_max_adjust_up` are now
  present in `tidecoin::network::Params`.
- `csv_height` and `segwit_height` are now present because contextual block
  validation needs node-aligned finality and witness activation behavior.
- Decide whether `Params` should also carry `genesis_hash`, `BIP34Hash`,
  `script_flag_exceptions`, `MinBIP9WarningHeight`, `vDeployments`,
  `nMinimumChainWork`, and `defaultAssumeValid`. If Rust remains a protocol
  library rather than a header-sync/full-node library, keep these out and
  document that boundary.
- Remove or demote `bip16_time` from active consensus params because the node
  no longer models it as a consensus-param field.
- Add a regtest override settings type only if node-style regtest parameter
  mutation becomes part of the public Rust API.

### PoW and Difficulty

- Tidecoin pure-header yespower is wired through the published `rust-yespower`
  crate and covered against the node bridge.
- `pow_hash_algorithm_at_height(params, height)` now mirrors the node's
  yespower/scrypt switch, `scrypt_pow_hash(...)` covers the post-AuxPoW mining
  hash, and `mining_hash_for_height(...)` returns the selected yespower or
  scrypt hash.
- `derive_target(bits, params)` now has node rejection semantics: negative,
  zero, overflow, and above-`powLimit` targets all fail.
- `validate_pow_at_height(header, params, height)` now performs node-shaped
  pure-header PoW validation without requiring a caller-supplied expected
  target; node-bridge tests assert that the returned yespower/scrypt hash
  matches the node oracle.
- `HeaderExt::validate_pow(params, height, required_target)` is now
  params/height-aware and no longer uses `block_hash()` for mining proof checks.
  It delegates to `validate_pow_at_height_against_target(...)` for callers that
  have also computed the contextual difficulty target. Do not route AuxPoW
  context validation through it.
- `validate_pow_any(...)` now mirrors the node's heightless
  `CheckProofOfWorkAny(...)` path for header-sync/anti-DoS contexts where height
  is unavailable, with node-bridge pass/fail coverage for both yespower and
  scrypt headers.
- `next_target_after(...)` now covers the `GetNextWorkRequired` old/new switch,
  node legacy overflow-guarded scaling, the first mainnet historical retarget,
  `CalculateNextWorkRequiredNew` behavior, and active-chain RPC testnet windows
  spanning genesis-to-activation, activation, the first local AuxPoW payload,
  an early post-AuxPoW range, and later AuxPoW ranges through height 16120. The
  early testnet windows intentionally include genesis history so the legacy
  min-difficulty walk-back rule has the same ancestor context as the node.
- `permitted_difficulty_transition(...)` now covers the node's legacy and
  post-AuxPoW transition envelope, with a node-bridge comparison for mainnet
  legacy cases. Remaining work is broader historical chain vectors beyond the
  current active-chain RPC fixture set.

### AuxPoW

- Keep `AuxPow` and header wire codecs in `primitives`.
- `tidecoin::pow::validate_auxpow_context(...)` now owns chain-context AuxPoW
  validation for pure headers: flag/payload consistency, activation height,
  chain ID, parent chain ID, parent coinbase merkle branch, merged-mining
  commitment placement, chain-merkle size/nonce/index, branch length, and parent
  scrypt PoW.
- Node-generated positive/negative AuxPoW fixtures and real testnet headers now
  cover the first library-scope pass, including contiguous contextual header
  walks over genesis-to-activation and active-chain post-AuxPoW testnet spans.
  Remaining coverage should focus on any discovered historical real-chain edge
  cases outside the current active-chain fixture set.

### Transaction and Block Validation

- `primitives::transaction::check_transaction_sanity(...)` is now the explicit
  node-shaped context-free transaction sanity owner; the decoder calls it at
  finalization.
- `primitives::block::check_block_sanity(...)` is now the explicit
  context-free `CheckBlock` sanity owner and is re-exported by `tidecoin`.
  It intentionally stops before witness commitment and full block weight,
  matching the node's `CheckBlock`/`ContextualCheckBlock` split.
- `tidecoin::block_validation::contextual_check_block_header(...)` now owns
  contextual header rules over an explicit previous-header/history callback.
- `tidecoin::block_validation::contextual_check_block(...)` now owns non-UTXO
  contextual block rules: context-free block sanity, header context,
  transaction finality, BIP34 coinbase height, witness malleation, and full
  block weight, with focused node-bridge parity coverage.
- Node-backed context-free block sanity coverage includes empty blocks, missing
  coinbase, multiple coinbase, bad merkle root, Merkle-mutation duplicate txids,
  invalid coinbase transaction, legacy sigop limit, and a valid-merkle
  oversized stripped block.
- Node-backed contextual block coverage includes finality, BIP34 coinbase
  height, pre-activation witness rejection, witness commitment mismatch, full
  witness-inclusive weight rejection, and larger 65-transaction final and
  non-final blocks.
- UTXO/chain-connect validation is deferred to a future separate crate with an
  explicit chainstate/UTXO abstraction.

### Consensus Adapter Boundary

- Keep `consensus` as byte-oriented spend verification over `consensus-core`.
- Do not add block/header chain validation to `consensus` unless the crate is
  explicitly re-scoped.
- Add Params-derived script flag scheduling to the high-level validation layer,
  then make `consensus` expose only explicit-flag or post-AuxPoW convenience
  APIs.

## Required Node-Parity Fixtures

Minimum fixture set before claiming this layer is covered:

- yespower hash for a pure header before AuxPoW activation beyond the current
  node-bridge vector
- scrypt hash for a pure header at/after AuxPoW activation beyond the current
  standalone and node-bridge scrypt-1024-1-1-256 vector
- AuxPoW fixture matrix beyond the current
  `tidecoin/tests/data/auxpow_headers.json` coverage. The current node-generated
  file covers valid regtest AuxPoW, parent PoW failure, wrong chain ID, parent
  chain ID collision, wrong chain index, invalid transaction merkle branch,
  invalid chain merkle branch, missing chain merkle root, missing and duplicated
  merged-mining headers, misplaced merged-mining header, merkle-size mismatch,
  missing size/nonce metadata, testnet activation acceptance, pre-activation
  rejection, and missing payload decode rejection.
- Remaining historical AuxPoW edge fixtures discovered from node data. Mainnet
  AuxPoW vectors are not applicable while mainnet `auxpow_start_height` is
  disabled in Tidecoin chain params.
- `GetNextWorkRequired` legacy pre-activation vectors outside the current
  genesis-to-activation testnet fixture window
- `GetNextWorkRequiredNew` post-activation averaging-window vectors beyond the
  current active-chain testnet spans through height 16120
- `PermittedDifficultyTransition` historical pre-activation and post-activation
  bounds beyond the current synthetic/node-bridge cases
- additional `CheckTransaction` corpus vectors beyond the current edge matrix
- block with second coinbase transaction beyond the current synthetic node-edge
  matrix, if a real fixture is found
- additional contextual header vectors beyond current bad `nBits`, previous
  MTP, previous-hash, activation-boundary, AuxPoW, and contiguous real testnet
  window cases
- additional contextual block vectors beyond the current focused finality,
  BIP34 coinbase-height, pre-activation witness, and larger synthetic
  node-bridge coverage, especially larger real-block fixtures and deferred
  full-chain sequence-lock cases for the future chain-validation crate

### Active-Chain Retarget Fixture Workflow

Regenerate `tidecoin/tests/data/testnet_retarget_windows.json` from node active
chain RPC, not from raw `blk*.dat` file order. Raw block files may include stale
or side-chain blocks, so they are not acceptable provenance for contextual
header or retarget parity windows.

Prerequisites:
- a local testnet `tidecoind` with the target active-chain heights available
- `TIDECOIN_NODE_REPO` pointing at the Tidecoin node checkout, unless the node
  checkout is the default sibling path
- `TIDECOIN_CLI` pointing at `tidecoin-cli`, unless the default sibling build
  path is valid

Current command:

```sh
python3 contrib/extract-testnet-auxpow-fixtures.py \
  --active-chain-rpc \
  --heights 999,1000,1100,1101,1102 \
  --include-last-auxpow \
  --retarget-windows pre_activation_long=0-999,activation=0-1000,first_auxpow=1013-1102@1041,post_auxpow_long=1013-1600@1041,late_auxpow_active=11333-11567@11361,latest_auxpow_active=15000-16120@15028 \
  --output tidecoin/tests/data/testnet_retarget_windows.json
```

Required post-generation checks:
- fixture provenance says `Tidecoin testnet active chain through node RPC`
- every generated case/header has `"source": "active-chain-rpc"`
- no `datadir`, absolute path, or `block_file` field is present
- post-AuxPoW windows carry prehistory headers before
  `first_checked_candidate_height`, so retarget tests do not skip missing
  averaging-window or median-time-past history
- `cargo test -p tidecoin --lib real_testnet -- --nocapture` passes

## Non-Goals Unless Full Node Validation Is Added

These node behaviors should stay out of the current Rust script/byte-consensus
adapter unless a real chain validator is built:

- assume-valid and signature-cache policy
- chainwork candidate selection
- block index persistence
- mempool standardness and relay policy
- wallet signing policy
- P2P peer punishment or anti-DoS scoring

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
- `tidecoin::network::Params` exposes only part of the node consensus parameter
  table.
- `tidecoin::pow` still contains a pre-AuxPoW/legacy-shaped difficulty helper
  and does not yet implement node PoW hash selection or AuxPoW-aware proof
  checks.
- `HeaderExt::validate_pow(required_target)` is not a valid Tidecoin consensus
  API because it lacks height, network params, target-derivation context, and
  AuxPoW payload context.

## Current Implementation Matrix

| Surface | Current Rust owner | Node owner | Status |
| --- | --- | --- | --- |
| Script interpreter and witness/PQ spend rules | `consensus-core`; exposed by `consensus` and `tidecoin` | `script/interpreter.*`, `validation.cpp` script-flag scheduling | Mostly implemented. Needs exact Params/block-hash flag scheduling only if Rust grows block-context validation. |
| Byte-oriented single-input spend verification | `consensus/src/lib.rs` | No direct equivalent; node validates spends during `ConnectBlock` | Implemented as a library adapter. It is not a block, header, or chain validator. |
| Transaction, block, header, AuxPoW wire codecs | `primitives` | `primitives/block.*`, `primitives/transaction.*`, serialization code | Mostly implemented. AuxPoW is wire-modeled but not context-validated. |
| Exposed consensus params | `tidecoin/src/network/params.rs` | `consensus/params.h`, `kernel/chainparams.cpp` | Partial. Missing several fields required for PoW/AuxPoW/difficulty parity; also exposes a `bip16_time` field that is not present in node `Consensus::Params`. |
| Subsidy schedule | `tidecoin/src/blockdata/subsidy.rs` | node subsidy code and `nSubsidyHalvingInterval` | Implemented and node-parity tested for the current schedule. |
| Target/work integer math | `tidecoin/src/pow.rs` | `pow.cpp`, `arith_uint256` | Partially implemented. Generic compact target helpers exist; exact node `DeriveTarget` error semantics and proof-class selection are missing. |
| Header PoW validation | `tidecoin/src/blockdata/block.rs::HeaderExt::validate_pow` | `CheckProofOfWork`, `CheckProofOfWorkAny`, `CheckBlockHeader`, `CheckAuxPowContext` | Not Tidecoin-consensus-correct. Rust validates `block_hash()` against a caller target; node selects yespower/scrypt/AuxPoW based on params and height. |
| Difficulty retargeting | `tidecoin/src/pow.rs::next_target_after` | `GetNextWorkRequired*`, `CalculateNextWorkRequired*`, `PermittedDifficultyTransition` | Old/legacy-shaped only. Post-AuxPoW averaging-window retargeting is missing. |
| AuxPoW validation | Wire structs in `primitives`; no chain validator | `CheckAuxPowContext`, `CAuxPow::check` | Missing as consensus validation. |
| Context-free transaction sanity | Transaction decoder in `primitives` | `CheckTransaction` | Partially implemented, but mixed into decoding and not node-exact. Zero-input rejection is missing and coinbase scriptSig max is wrong. |
| Context-free block sanity | `primitives::Block::validate` | `CheckBlock` | Structural only. Missing PoW/AuxPoW, size, extra coinbase, transaction sanity, and sigop limit parity. |
| Contextual header/block validation | No complete Rust owner | `ContextualCheckBlockHeader`, `ContextualCheckBlock`, `AcceptBlockHeader`, `ConnectBlock` | Missing. Requires previous-header/index abstraction and chain params. |
| UTXO/chain connect | No Rust owner | `ConnectBlock`, `CheckTxInputs`, chainstate code | Missing and should not be claimed unless intentionally built. |

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
| `CSVHeight` | `1` | `1` | `1`, overrideable in node regtest options | Not exposed. |
| `SegwitHeight` | `1` | `1` | `0`, overrideable in node regtest options | Not exposed. |
| `nAuxpowStartHeight` | disabled | `1000` | `0` | Exposed as `auxpow_start_height`. |
| `nAuxpowChainId` | `8` | `8` | `8` | Exposed as `auxpow_chain_id`. |
| `fStrictChainId` | `true` | `true` | `true` | Not exposed. |
| `powLimit` | `01ff...ffff` | `01ff...ffff` | `0f0f...0f0f` | Exposed indirectly as `max_attainable_target`; exact raw target derivation API is missing. |
| `nPowTargetTimespan` | `432000` | `432000` | `14400` | Exposed as `pow_target_timespan`. |
| `nPowTargetSpacing` | `60` | `60` | `60` | Exposed as `pow_target_spacing`. |
| `fPowAllowMinDifficultyBlocks` | `false` | `true` | `true` | Exposed as `allow_min_difficulty_blocks`; only legacy path currently uses it. |
| `enforce_BIP94` | `false` | `false` | `true` | Exposed as `enforce_bip94`; contextual header use is missing. |
| `fPowNoRetargeting` | `false` | `false` | `true` | Exposed as `no_pow_retargeting`; only legacy path currently uses it. |
| `nPowAllowMinDifficultyBlocksAfterHeight` | `nullopt` | `nullopt` | `nullopt` | Not exposed. |
| `nPowAveragingWindow` | `17` | `17` | `17` | Not exposed. |
| `nPowMaxAdjustDown` | `32` | `32` | `0` | Not exposed. |
| `nPowMaxAdjustUp` | `16` | `16` | `0` | Not exposed. |
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
| `CSVHeight` | Not exposed. Rust script flags currently assume CSV is active when requested via flags. | Add `csv_height` if we implement node-like `GetBlockScriptFlags(params, height, hash)` or contextual block validation. |
| `SegwitHeight` | Not exposed. Rust generally assumes witness rules are active when flags include `VERIFY_WITNESS`. | Add `segwit_height` if we implement node-like `GetBlockScriptFlags` or contextual block validation. Regtest override support matters here. |
| `nAuxpowStartHeight` | Exposed as `auxpow_start_height`. Mainnet disabled as `None`, testnet `Some(1000)`, regtest `Some(0)`. | Keep. This field must become the switch for PoW hash selection, AuxPoW validation, PQ strict flags, witness-v1-512, and `OP_SHA512`. |
| `nAuxpowChainId` | Exposed as `auxpow_chain_id`. | Keep. Must be used by AuxPoW chain ID validation, not only stored. |
| `fStrictChainId` | Not exposed. Node sets it to `true` on mainnet, testnet, and regtest. | Add `strict_chain_id: bool` to `Params` before implementing AuxPoW context validation. |
| `MinBIP9WarningHeight` | Not exposed. | Likely out of Rust library consensus scope unless implementing versionbits warning behavior. |
| `vDeployments` | Not exposed except indirectly through `rule_change_activation_threshold` and `miner_confirmation_window`. | If versionbits state is a library goal, expose deployments. For current validation focus, buried heights and AuxPoW height are more important. |
| `powLimit` | Exposed as `max_attainable_target`, not raw `powLimit`. | Add a raw compact/target validity helper matching node `DeriveTarget(nBits, powLimit)`. `max_attainable_target` is not sufficient on its own because consensus rejects zero, negative, overflow, and above-limit targets. |
| `fPowAllowMinDifficultyBlocks` | Exposed as `allow_min_difficulty_blocks`. | Keep, but current Rust logic only covers the legacy path. |
| `enforce_BIP94` | Exposed as `enforce_bip94`. | Keep name as node-aligned. Must be used by contextual header timestamp checks if those are implemented. |
| `fPowNoRetargeting` | Exposed as `no_pow_retargeting`. | Keep. Current Rust logic uses it only in the old retarget path. |
| `nPowTargetSpacing` | Exposed as `pow_target_spacing`. | Keep. |
| `nPowTargetTimespan` | Exposed as `pow_target_timespan`. | Keep. |
| `nPowAllowMinDifficultyBlocksAfterHeight` | Not exposed. Node currently sets `std::nullopt` in the checked chainparams, but the algorithm uses it. | Add if porting `GetNextWorkRequiredNew(...)` literally; it can default to `None`. |
| `nPowAveragingWindow` | Not exposed. Node sets `17`. | Add `pow_averaging_window`. Required for post-AuxPoW difficulty. |
| `nPowMaxAdjustDown` | Not exposed. Node sets `32` on main/testnet and `0` on regtest. | Add `pow_max_adjust_down`. Required for `PermittedDifficultyTransition`. |
| `nPowMaxAdjustUp` | Not exposed. Node sets `16` on main/testnet and `0` on regtest. | Add `pow_max_adjust_up`. Required for `PermittedDifficultyTransition`. |
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
- Rust has `next_target_after(...)`, but it currently mirrors the old
  interval-based path.
- Rust stores `auxpow_start_height`, `auxpow_chain_id`, and AuxPoW wire payloads.

### Not implemented or wrong

| Node behavior | Rust status | Required action |
| --- | --- | --- |
| `CPureBlockHeader::GetPoWHash()` uses Tidecoin yespower over the pure 80-byte header. | Missing. | Add a pure-header `yespower_pow_hash` implementation. |
| `CPureBlockHeader::GetScryptPoWHash()` uses scrypt-1024-1-1-256 over the pure 80-byte header. | Missing. | Add a pure-header `scrypt_pow_hash` implementation. |
| `UseScryptPoW(params, height)` switches at AuxPoW activation. | Missing as a Rust API. | Add `use_scrypt_pow(params, height)` or `pow_hash_algorithm_at_height(...)`. |
| `GetPoWHashForHeight(block, params, height)` selects yespower before AuxPoW and scrypt at/after AuxPoW. | Missing. | Add `pow_hash_for_height(header, params, height)`. |
| `CheckProofOfWork(hash, nBits, params)` derives and validates target from `nBits` and `powLimit`. | Partially present via `Target::from_compact` and `Target::is_met_by`, but no exact `DeriveTarget` equivalent. | Implement `derive_target(bits, params) -> Result<Target, PowError>` rejecting negative/zero/overflow/above-limit targets like the node. |
| `CheckProofOfWork(block, params, height)` validates selected mining hash against `nBits`. | Missing. `HeaderExt::validate_pow(required_target)` checks `header.block_hash()` against caller-supplied target. | Replace with height/params-aware Tidecoin PoW validation. |
| `CheckProofOfWorkAny(block, params)` accepts either yespower or scrypt for anti-DoS/header-sync contexts without height. | Missing. | Add only if Rust needs to mirror node header-sync behavior. Keep separate from height-known consensus validation. |
| `CheckAuxPowContext(...)` validates AuxPoW flag/payload, activation, chain ID, merkle commitment, and parent scrypt PoW. | Missing. Rust only decodes and serializes AuxPoW. | Implement in `tidecoin::pow` or a chain-validation module. Keep wire structs in `primitives`. |
| `GetNextWorkRequired(...)` switches old/new difficulty rules by AuxPoW activation height. | Missing. Rust only has the old path. | Port the switch exactly. |
| `GetNextWorkRequiredNew(...)` uses averaging window, median-time-past, min/max actual timespan, and no-retargeting behavior. | Missing. | Port after adding the missing params. |
| `PermittedDifficultyTransition(...)` enforces pre-activation old bounds and post-activation max-adjust bounds with compact rounding tolerance. | Missing. | Port for header-window validation. |

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

### Not implemented

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
- missing merged-mining header
- duplicate merged-mining header
- wrong chain merkle size/nonce/index
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
| Empty outputs | Implemented in transaction decoder. | Keep. |
| Output values above `MAX_MONEY` | Implemented by `Amount` decoding and total-sum validation. | Keep. |
| Negative output values | Encoded negative node values become out-of-range unsigned amounts in Rust. | Add explicit test vectors if not already covered by node corpus. |
| Duplicate inputs | Implemented in transaction decoder. | Keep. |
| Null prevout in non-coinbase | Mostly implemented through `validate_non_coinbase_prevouts`. | Add direct node-parity tests for single-input and multi-input edge cases. |
| Empty inputs | Not implemented. Rust can currently construct/decode zero-input transactions with outputs in decoder-internal paths. | Add a context-free transaction sanity API that rejects empty inputs, or move this validation into the decoder if decoding remains consensus-validating. |
| Stripped weight limit | Not implemented as a transaction sanity check. | Add `check_transaction_sanity` equivalent if Rust should mirror node `CheckTransaction`. |
| Coinbase scriptSig upper bound | Rust uses 100 bytes; node uses 106 bytes. | Fix to 106 and add node-parity tests at 100, 101, 106, and 107 bytes. |

Architectural note: putting all node `CheckTransaction` semantics in the
decoder is awkward because decoding and consensus sanity are different
responsibilities. The clean design is a canonical decoder plus an explicit
`check_transaction_sanity(tx)` function that exactly mirrors the node. If we
keep decoder-time rejection, it must still match the node exactly.

## Block Validation Audit

Rust `Block::validate()` in `primitives` currently checks:

- block has transactions
- first transaction is coinbase
- transaction merkle root matches header
- witness commitment matches witness data when witness data exists

Node `CheckBlock(...)` and `ContextualCheckBlock(...)` do more.

Missing context-free `CheckBlock(...)` parity:

- header PoW with AuxPoW context
- block size limit using no-witness serialization and `MAX_BLOCK_WEIGHT`
- reject coinbase transactions after the first transaction
- run full `CheckTransaction(...)` for every transaction
- legacy sigop count limit against `MAX_BLOCK_SIGOPS_COST`
- exact node error/reject reason mapping if Rust exposes diagnostic errors

Missing contextual block/header parity:

- `bad-diffbits`: candidate `nBits` must equal `GetNextWorkRequired(...)`
- `time-too-old`: block time must be greater than previous median time past
- BIP94 timewarp mitigation on difficulty-adjustment blocks
- future timestamp limit
- version gates for BIP34, BIP66, BIP65
- post-AuxPoW base-version validity
- final transaction checks at height/time
- BIP34 coinbase height enforcement at active height
- BIP30 duplicate transaction overwrite checks
- sequence-lock validation
- witness malleation validation using active Segwit deployment state
- block weight validation after witness commitment validation

Required design split:

- `primitives::Block::validate()` should not become a full chain validator.
  It can stay as structural validation if clearly documented.
- Add a higher-level `tidecoin::block_validation` or `tidecoin::chain` module
  for node-style `check_block`, `contextual_check_block_header`, and
  `contextual_check_block` behavior.
- That module needs a previous-header/index abstraction, not just a standalone
  header, because median time past, difficulty, version gates, and finality are
  contextual.

## UTXO and Chain-Connect Audit

The Rust library does not implement full node chain connection. Missing if full
consensus validation is a goal:

- UTXO lookup and spend availability checks
- fee and value-in/value-out checks
- coinbase maturity
- BIP30 duplicate transaction overwrite behavior
- sequence locks against active chain state
- signature-cache or assume-valid shortcuts
- chainwork comparison and minimum-chainwork policy
- assume-valid behavior

This is not a bug in the current script/spend API, but it must not be described
as full chain consensus coverage.

## Priority Implementation Plan

1. Add missing params required for PoW/AuxPoW:
   `strict_chain_id`, `pow_averaging_window`, `pow_max_adjust_down`,
   `pow_max_adjust_up`, and
   `pow_allow_min_difficulty_blocks_after_height`.
2. Add exact node-style target derivation:
   `derive_target(bits, params)` must reject zero, negative, overflow, and
   above-limit targets.
3. Add pure-header mining hash APIs:
   `yespower_pow_hash`, `scrypt_pow_hash`, and `pow_hash_for_height`.
4. Replace or narrow `HeaderExt::validate_pow(required_target)` so it is not
   presented as Tidecoin consensus validation.
5. Implement AuxPoW context validation in the chain/Pow layer, not in
   `primitives`.
6. Port `GetNextWorkRequired(...)`, `GetNextWorkRequiredNew(...)`,
   `CalculateNextWorkRequiredNew(...)`, and
   `PermittedDifficultyTransition(...)`.
7. Add a node-parity transaction sanity API or align decoder-time validation
   with node `CheckTransaction(...)`; fix the 100 vs 106 coinbase scriptSig
   mismatch.
8. Add a height/params-derived script flag helper for chain validation.
9. Add block/header contextual validation APIs only after the PoW and
   transaction sanity foundations are node-parity tested.

## Concrete Implementation Backlog

This is the current code-facing backlog implied by the audit.

### Params and Settings

- Add `strict_chain_id`, `csv_height`, `segwit_height`,
  `pow_allow_min_difficulty_blocks_after_height`, `pow_averaging_window`,
  `pow_max_adjust_down`, and `pow_max_adjust_up` to
  `tidecoin::network::Params`.
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

- Implement Tidecoin pure-header yespower and scrypt mining hashes against
  node fixtures from `CPureBlockHeader::GetPoWHash()` and
  `CPureBlockHeader::GetScryptPoWHash()`.
- Implement `use_post_auxpow_pow_rules(params, height)` and
  `pow_hash_for_height(header, params, height)` as direct equivalents of the
  node switch.
- Implement exact `derive_target(bits, params)` with node rejection semantics:
  negative, zero, overflow, and above-`powLimit` targets all fail.
- Replace the public meaning of `HeaderExt::validate_pow(required_target)` with
  either a non-consensus helper name or a deprecated/internal status; add a new
  params/height-aware PoW validation API.
- Port `GetNextWorkRequiredOld`, `CalculateNextWorkRequiredOld`,
  `GetNextWorkRequiredNew`, `CalculateNextWorkRequiredNew`, and
  `PermittedDifficultyTransition` exactly.

### AuxPoW

- Keep `AuxPow` and header wire codecs in `primitives`.
- Add chain-context AuxPoW validation in a higher Tidecoin validation layer:
  flag/payload consistency, activation height, chain ID, parent chain ID,
  parent coinbase merkle branch, merged-mining commitment placement,
  chain-merkle size/nonce/index, branch length, and parent scrypt PoW.
- Add node-generated positive and negative AuxPoW fixtures before claiming
  this surface covered.

### Transaction and Block Validation

- Split node `CheckTransaction` parity out of decoding into an explicit sanity
  validator, or make the decoder validation exactly node-equivalent. The clean
  design is explicit validation, not consensus rejection hidden in byte
  decoding.
- Fix coinbase scriptSig max length from `100` to node `106`.
- Reject zero-input transactions in the context-free transaction sanity layer.
- Enforce stripped transaction weight limit.
- Add `check_block`/`contextual_check_block_header`/`contextual_check_block`
  APIs only after the Params, PoW, AuxPoW, and transaction-sanity foundations
  are implemented.

### Consensus Adapter Boundary

- Keep `consensus` as byte-oriented spend verification over `consensus-core`.
- Do not add block/header chain validation to `consensus` unless the crate is
  explicitly re-scoped.
- Add Params-derived script flag scheduling to the high-level validation layer,
  then make `consensus` expose only explicit-flag or post-AuxPoW convenience
  APIs.

## Required Node-Parity Fixtures

Minimum fixture set before claiming this layer is covered:

- yespower hash for a pure header before AuxPoW activation
- scrypt hash for a pure header at/after AuxPoW activation
- `CheckProofOfWork` pass/fail vectors for both algorithms
- `CheckProofOfWorkAny` vectors if Rust exposes the heightless node path
- AuxPoW valid/minimal fixture from the node
- AuxPoW invalid cases listed above
- `GetNextWorkRequired` legacy pre-activation vector
- `GetNextWorkRequiredNew` post-activation averaging-window vector
- `PermittedDifficultyTransition` pre-activation and post-activation bounds
- `CheckTransaction` empty-input rejection
- `CheckTransaction` coinbase scriptSig length edges: 1, 2, 100, 101, 106, 107
- block with second coinbase transaction
- block with valid merkle root but excessive stripped size
- contextual block with bad `nBits`
- contextual block with timestamp equal to previous median time past
- contextual block with invalid post-AuxPoW base version

## Non-Goals Unless Full Node Validation Is Added

These node behaviors should stay out of the current Rust script/byte-consensus
adapter unless a real chain validator is built:

- assume-valid and signature-cache policy
- chainwork candidate selection
- block index persistence
- mempool standardness and relay policy
- wallet signing policy
- P2P peer punishment or anti-DoS scoring

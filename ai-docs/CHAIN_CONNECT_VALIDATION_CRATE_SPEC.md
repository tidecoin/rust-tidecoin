# Tidecoin Chain-Connect Validation Crate Spec

Status: active design note, not yet implemented.

This document defines the boundary for a future Rust crate that validates full
Tidecoin block connection against chainstate. It exists to keep the current
protocol crates from growing ad-hoc UTXO/database responsibilities while still
recording the exact work required for node-level parity.

## Current Layer Split

The current `rust-tidecoin` workspace owns three validation layers:

| Layer | Current owner | Node analogue | Scope |
| --- | --- | --- | --- |
| Context-free transaction sanity | `primitives::transaction::check_transaction_sanity` | `CheckTransaction` | Structural transaction validity that does not need chainstate. |
| Context-free block sanity | `primitives::block::check_block_sanity` | `CheckBlock` | Block structure, Merkle root/mutation, coinbase placement, stripped-size, and legacy sigop-cost checks. |
| Non-UTXO contextual block/header checks | `tidecoin::block_validation` | `ContextualCheckBlockHeader`, `ContextualCheckBlock` | Previous-header linkage, difficulty target, MTP, timewarp, version gates, PoW/AuxPoW, finality, BIP34 coinbase height, witness commitment, and full block weight. |

The future crate owns the fourth layer:

| Layer | Future owner | Node analogue | Scope |
| --- | --- | --- | --- |
| Chain-connect validation | proposed `tidecoin-chain-validation` | `ConnectBlock`, `CheckTxInputs`, `SequenceLocks`, chainstate code | UTXO lookup, spend availability, fees, reward claim, BIP30, coinbase maturity, sequence locks, and script execution with chain-derived flags. |

It should also be the first Rust layer that consumes full-node consensus
settings that are not needed by current context-free or contextual checks:

| Node setting | Future use |
| --- | --- |
| `BIP34Hash` | BIP30 enforcement exception in `ConnectBlock`. |
| `script_flag_exceptions` | Exact `GetBlockScriptFlags(...)` parity if Tidecoin ever has active exception entries. |
| `vDeployments` | Versionbits state for non-buried deployments once a header-index state machine exists. |
| `MinBIP9WarningHeight` | Unknown-versionbits warning policy if the crate grows node-style warning behavior. |
| `nMinimumChainWork` | Header-sync/chain-selection acceptance threshold, likely in a sibling header-sync layer if chain selection is not part of the first crate. |
| `defaultAssumeValid` | Optional script-check shortcut policy for historical ancestors. It must not affect explicit script verification results. |

These settings should not be added to `consensus-core`. The interpreter remains
flag-driven and should not know about deployment state, assume-valid policy, or
chain-selection thresholds.

## Why This Must Be a Separate Crate

`ConnectBlock` parity needs a stateful view of the chain. Folding that into
`tidecoin`, `primitives`, `consensus-core`, or `consensus` would blur crate
levels and duplicate node responsibilities.

The future crate needs:

- a UTXO set abstraction
- block-index/header lookup
- coin spend and undo modeling
- height and median-time-past state
- per-input spent-output access
- accumulated fee accounting
- chain-derived script flag scheduling
- optional cache policy for script verification

Those are not protocol data structures. They are chainstate semantics.

## Responsibilities

The future crate should implement node-parity equivalents for:

- `ConnectBlock`
- `CheckTxInputs`
- BIP30 duplicate transaction overwrite checks, including the node's BIP34-hash
  condition
- sequence-lock evaluation against active-chain heights and MTP
- coinbase maturity
- value-in/value-out and fee calculation
- coinbase reward claim:
  `coinbase_value <= fees + tidecoin::subsidy::block_subsidy(height, params)`
- chain-derived script verification flags
- per-transaction script execution using `consensus-core`
- UTXO update/undo data construction if the crate owns state mutation, or a
  pure check result if state mutation is left to the caller

It should call existing lower-level owners instead of reimplementing them:

- `primitives::transaction::check_transaction_sanity`
- `primitives::block::check_block_sanity`
- `tidecoin::block_validation::contextual_check_block`
- `tidecoin::pow` for height-aware PoW/AuxPoW/header rules
- `tidecoin::subsidy::block_subsidy`
- `consensus-core` for script execution and sighash rules

## Non-Responsibilities

The future crate should not own:

- transaction/block/witness/script serialization
- primitive transaction or block types
- consensus script interpreter internals
- node-bridge test helper internals
- P2P message handling
- wallet policy or mempool policy
- persistent database implementation in the first version

The first version should prefer traits over a concrete database so parity tests
can use small in-memory fixtures.

## API Draft

The exact names can change, but the shape should stay layered:

```rust
pub trait CoinView {
    type Error;

    fn lookup_coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, Self::Error>;
    fn has_txid(&self, txid: Txid) -> Result<bool, Self::Error>;
}

pub trait ChainView {
    type Error;

    fn header(&self, height: BlockHeight) -> Result<Option<BlockHeader>, Self::Error>;
    fn median_time_past(&self, height: BlockHeight) -> Result<Option<BlockMtp>, Self::Error>;
    fn contains_txid_before_height(
        &self,
        txid: Txid,
        height: BlockHeight,
    ) -> Result<bool, Self::Error>;
}

pub struct ConnectBlockContext<'a, C, H> {
    pub params: &'a Params,
    pub coins: &'a C,
    pub chain: &'a H,
    pub height: BlockHeight,
    pub options: ConnectBlockOptions,
}

pub fn check_connect_block<C, H>(
    block: &Block,
    ctx: ConnectBlockContext<'_, C, H>,
) -> Result<ConnectBlockSummary, ConnectBlockError<C::Error, H::Error>>
where
    C: CoinView,
    H: ChainView;
```

Minimal supporting data:

```rust
pub struct Coin {
    pub txout: TxOut,
    pub height: BlockHeight,
    pub coinbase: bool,
}

pub struct ConnectBlockSummary {
    pub fees: Amount,
    pub subsidy: Amount,
    pub coinbase_output: Amount,
}

pub struct ConnectBlockOptions {
    pub check_scripts: bool,
    pub cache_script_results: bool,
}
```

The first implementation should keep mutation out of the core check unless it
is clearly needed:

- `check_connect_block(...)` validates and returns a summary.
- A later `connect_block(...)` can consume/apply an update model if the crate
  becomes a chainstate owner.

## Required Node-Parity Test Plan

Minimum tests before considering this layer implemented:

- coinbase reward exactly equal to subsidy
- coinbase reward below subsidy, proving unclaimed rewards are valid
- coinbase reward one tidoshi above subsidy
- coinbase reward equal to subsidy plus fees
- coinbase reward one tidoshi above subsidy plus fees
- missing input
- already-spent input
- negative fee/value-out overflow path, if constructible through Rust types
- immature coinbase spend
- mature coinbase spend
- duplicate txid/BIP30 overwrite cases around the node's active BIP30 rules
- sequence-lock pass/fail cases using both height and time locks
- script pass/fail with chain-derived flags after the relevant activation
  heights

Node-backed tests should use the existing node-parity bridge where possible.
If a full in-process node fixture becomes too large, add small synthetic blocks
that mirror the node unit/functional tests and record why the bridge cannot
cheaply construct the case.

## Open Questions Before Implementation

- Whether the first crate version should be pure validation only or also return
  a deterministic UTXO update/undo set.
- Whether BIP30 needs a dedicated historical exception model in Rust or can be
  expressed through the `ChainView` trait.
- Whether script caching belongs in this crate or remains caller-owned.
- How much active-chain fixture data should be committed versus generated on
  demand from a local node.

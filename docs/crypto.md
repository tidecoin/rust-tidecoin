# Tidecoin keys / Tidecoin crypto

The intended split is between a `tidecoin-keys` crate that carries key material and a
`tidecoin-crypto` crate that carries the remaining crypto-oriented helpers.

## `secp256k1`

Both crates depend on `secp256k1`.

Other pieces that need secp directly or indirectly through keys/crypto:

- `addresses` for key-backed address generation
- `bip-32` for hierarchical key derivation
- `psbt` for key handling and signing
- `sign_message` for Tidecoin message signatures

## Keys

Public and private keys.

The split exists so that other crates can depend on key handling without pulling in the entire
`tidecoin` crate.

(Plural crate name, singular module name, matching the existing `address` / `addresses` split.)

Current public types in `tidecoin::crypto::key`:

- `XOnlyPublicKey`
- `PublicKey`
- `SortKey`
- `PubkeyHash`
- `WPubkeyHash`
- `CompressedPublicKey`
- `PrivateKey`
- `SerializedXOnlyPublicKey`
- Various error types

### Current obvious complications

Looking at `tidecoin::crypto::key` there are a few obvious things that will need care when the
split happens.

#### `NetworkKind`

We currently use `tidecoin::network::NetworkKind` in `PrivateKey`.

- It is used to get the first byte of WIF format.
- It is passed to functions that create addresses such as `Address::p2pkh(key, network)`.

#### `ScriptBuf`

This is probably fine if the split depends on `primitives`. It is only used for script code.

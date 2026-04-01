# Tidecoin keys / Tidecoin crypto

The current direction is to keep key handling as a focused piece of the crate graph, with a
possible `tidecoin-keys` split if we decide to separate it from the rest of crypto helpers.

## On `secp256k1`

Any keys/crypto split would depend on `secp256k1`.

Other things that use secp directly or indirectly through keys/crypto:

- `addresses` for key-backed address generation
- `bip-32` for hierarchical derivation
- `psbt` for key handling and signing
- `sign_message` for Tidecoin message signatures

## Related to keys

Public and private keys.

The reason for splitting this out is so that other crates can depend on keys without depending on
`tidecoin` directly.

(Plural crate name, singular module name, matching the existing `address` module and
`addresses` crate.)

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

Looking at `tidecoin::crypto::key` there are a few obvious things that need care.

#### `NetworkKind`

We currently use `tidecoin::network::NetworkKind` in `PrivateKey`.

- It is used to get the first byte of WIF format.
- It is passed to functions that create addresses such as `Address::p2pkh(key, network)`.

#### `ScriptBuf`

Possibly fine if the split depends on `primitives`. It is only used for script code.

# Tidecoin repository roadmap

* ~Release `units v1.0.0-rc.0`~
* Create `tidecoin-consensus-encoding` `v0.1.0`
* Release `tidecoin-consensus-encoding` `v1.0.0-rc.0`
* Release `primitives v1.0.0-rc.0`
  * Implement script tagging
  * Add support for consensus encoding to `primitives`
* Release `tidecoin v0.33.0-beta`
* Split out an address crate (see [addresses.md])
* BIP-0032 and BIP-0380 (see [bip-32.md])
* PSBTv2 (see [psbt.md])
* Split out a crypto/keys crate. Includes discussion of `secp256k1`. See [crypto.md]
* Make it possible for `tidecoin` to depend on `miniscript`
    - Requires [bip-32.md] and [psbt.md]

## RC cycle

We want to do a long release candidate cycle to give time for downstream testing and feedback on the
API of the 1.0 crates. At a minimum this will be 6 months from the release `primitives-1.0-rc.0`.

[addresses.md]: ./addresses.md
[bip-32.md]: ./bip-32.md
[crypto.md]: ./crypto.md
[psbt.md]: ./psbt.md

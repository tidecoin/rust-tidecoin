# Tidecoin keys

The active key surface is Tidecoin-native and PQ-focused.

## Current live API

`tidecoin::crypto::key` currently exposes:

- `PubkeyHash`
- `WPubkeyHash`
- `PqWifKey`
- `PqWifFormat`
- WIF parse/validation errors

It is no longer the home of removed legacy key formats, extended keys, or transaction signing glue.

## Ownership rule

Key wrappers needed by public Tidecoin APIs may live in the top-level crate, but reusable lower
logic must not be duplicated:

- canonical protocol/script/tx data: `primitives`
- consensus verification helpers: `consensus-core`
- public Tidecoin convenience layer: `tidecoin`

If a future dedicated keys crate is created, it should depend only on lower shared crates and must
not reintroduce a second key model parallel to `consensus-core` or `primitives`.

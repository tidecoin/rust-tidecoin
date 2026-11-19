# Changelog

All notable Tidecoin-specific changes for the AEAD helper crate are documented here.

## Unreleased — 0.1.3

- Use safe chunk iteration and enforce the unsafe-code restriction; public APIs are unchanged.

## 0.1.2 — published 2026-04-30

- Kept this crate as the Tidecoin workspace AEAD support layer for transport code.
- Preserved no-std and allocation feature boundaries needed by the p2p stack.
- Aligned crate ownership and MSRV with the Tidecoin workspace.
- Set the crate MSRV to Rust 1.94.1.

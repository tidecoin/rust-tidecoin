# Changelog

All notable Tidecoin-specific changes for the node-parity harness are documented here.

## 0.2.1 — 2026-11-23

- Pin Tidecoin v1.0.0rc4 (78aca4a6b6) and add serialization-only transaction/input weight comparisons using the original C++ functions.

## 0.2.0

- Breaking: expanded public error enums and original-node comparison interfaces. Pin rc3 and package the current oracle support.

## 0.1.0 — published 2026-04-30

- Added the shared harness for comparing Rust behavior against the Tidecoin Core node.
- Centralized node fixture loading and native bridge helpers used by consensus and top-level tests.
- Documented the parity workflow as the replacement for inherited large-corpus validation.
- Kept node integration out of the core consensus engine so production validation remains standalone.
- Set the crate MSRV to Rust 1.94.1.

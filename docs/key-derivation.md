# Tidecoin Key Derivation And Key Expressions

Active key-derivation and key-expression work in this repository is Tidecoin-native:

- `tidecoin::pqhd` owns PQHD v1 seed identifiers, hardened paths, and child key derivation.
- `tidecoin::crypto::pq` owns scheme-prefixed PQ key and signature sizing metadata.
- `tidecoin::key_expression` owns Tidecoin key-expression parsing inside the high-level crate.

Historical upstream wallet-standard provenance belongs under archived docs. Keep this live document
focused on Tidecoin semantics and node-parity requirements.

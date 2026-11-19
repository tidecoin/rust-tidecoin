# Falcon rc3 consumer fixtures

`falcon-rc3.txt` contains 36 unchanged rows from `tide-fn-dsa-vrfy` 0.5.0,
commit `6d4c86d4a275bcd813fedd83a603d601232302d5`,
`tide-fn-dsa-vrfy/tests/data/tidecoin-rc3.txt`, plus `negzero-tail` combining
that file's negative-zero and unused-final-bit variants. Columns are label,
message hex, raw public key hex, raw signature hex, legacy, strict, PQClean,
and noncanonical-classifier expectations. Signatures exclude the sighash byte.
The PQClean column is provenance, not the consumer's verification profile.

Authority is node `ffed4e92e60ff2de30361648a71cba64531f9077`:
`src/pq/falcon512.c`, `src/pq/falcon-{512,1024}/{pqclean,common,codec}.c`.
The consumer's legacy entry point uses strict verification for Falcon-1024.

The original `orig` row and encoding variants come from node regression F27.
Norm endpoints use synthetic keys with s2=(1,0,...) and h=c-s1 mod 12289,
where c hashes the nonce/message. They establish exact norm boundaries and
are not signatures generated using a known private key. Long strict vectors
use s1=0 and s2=(256,...,256), with h=c/s2, and demonstrate verification of
745/1449-byte signatures above the local signing budgets. Synthetic-key
fixtures are not a substitute for signing/key-generation regression tests.

`consensus-core::pq::tests::falcon_rc3_verification_vectors` checks both
message widths through strict, explicit-legacy and fallback public APIs,
classification and malformed/message controls without a C++ checkout.
`tidecoin::consensus_validation_node::tests::falcon_050_vectors_match_original_node_and_public_apis`
reads this same file at runtime in a workspace checkout and compares the
product facade directly with original node verification. It checks the base
rows and changes to message, signature encoding and key encoding. Existing
`consensus/tests/tidecoin_rc2_rules.rs` also compares the classifier directly
with the original C implementation and tests script activation/relay contexts.

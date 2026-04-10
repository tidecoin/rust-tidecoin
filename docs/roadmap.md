# Tidecoin repository roadmap

Current high-value architectural goals:

- keep canonical Tidecoin protocol/script/opcode ownership in `primitives`
- keep `consensus-core` as the single reusable validation engine
- keep `consensus` as the thin byte-oriented standalone adapter
- keep `tidecoin` as the public product wrapper over lower shared crates
- rebase crates like `p2p` onto lower shared crates instead of the top-level `tidecoin` crate
- archive or delete remaining historical Core-era material once it no longer carries engineering value

## RC cycle

We want a long release-candidate cycle to give downstream users time to test the crate boundaries
and public APIs of the 1.0 crates.

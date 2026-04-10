# Policy on adding dependencies

TL;DR: keep dependencies intentional, narrow, reproducible, and level-correct.

This policy applies to crates in the `rust-tidecoin` workspace. A new dependency needs a clear
reason and must fit the crate's layer. Lower crates should not depend upward on product-level crates.

When evaluating a dependency, consider:

- Maintainers are reputable and responsive.
- API is idiomatic, documented, and stable or close to stable.
- MSRV is compatible with the consuming crate.
- Performance and code size fit the use case.
- Test coverage, CI, fuzzing, and lint hygiene are credible.
- `unsafe` usage is limited, documented, and justified.
- Transitive dependencies do not pull in broad or unrelated functionality.

Local development overrides should use Cargo patch/config mechanisms rather than committed external
path dependencies. Committed manifests should prefer workspace paths, versions, or pinned git
revisions so repo-wide tooling remains hermetic.

## Level discipline

- Foundational data types belong in lower shared crates such as `tidecoin-primitives`, `tidecoin-units`, and `tidecoin-hashes`.
- Validation execution belongs in `tidecoin-consensus-core`.
- Canonical byte codecs belong in `tidecoin-consensus-encoding`; higher crates may expose narrow facades but must not duplicate codec implementations.
- Byte-oriented validation entry points belong in `consensus`, backed by `tidecoin-consensus-core`.
- P2P message logic belongs in `tidecoin-p2p-messages` and should depend on lower crates, not the top-level `tidecoin` crate.
- The high-level `tidecoin` crate should compose and reexport lower layers rather than duplicate their implementation.

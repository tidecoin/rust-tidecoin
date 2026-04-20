# Consensus-Core Boundary Cleanup Implementation Plan

Status: archived completed implementation record.

This document records the refactor plan that was used to:

- add the shared typed verification facade in `consensus-core`
- rewire `tidecoin` and `consensus` to that shared facade
- remove node-bridge routing from the product validation path
- preserve real-node parity as explicit test/dev infrastructure

The plan is preserved as historical engineering evidence only. It is no longer
an active implementation checklist.

For the current active state, use:

- [ai-docs/README.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/README.md)
- [ai-docs/VALIDATION_FIX_BACKLOG.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/VALIDATION_FIX_BACKLOG.md)
- [ai-docs/API_STABILIZATION_SURFACE_AUDIT.md](/home/yaroslav/dev/tidecoin/rust-tidecoin/ai-docs/API_STABILIZATION_SURFACE_AUDIT.md)

# Note for Automated Agents

## Compatibility principles

The goal is to make `rust-tidecoin` compatible with the pinned Tidecoin C++ node
and consolidate a foundation for a future pure Rust node.

- The pinned C++ node implementation is the behavioral authority. The active
  [migration plan](ai-docs/RC3_MIGRATION_PLAN.md) identifies the target revision.
  Upstream Bitcoin changes matter through their adoption in Tidecoin; they do
  not independently override Tidecoin behavior.
- Preserve the reviewed node behavior. Do not redesign consensus, silently
  improve rules in Rust, or reopen node design decisions by default.
- Establish compatibility through executable differential tests and reference
  vectors. Consolidate proven behavior into shared implementations and precise
  interfaces rather than duplicating logic or introducing competing rule sets.
- Review the original node implementation and its callers, including context,
  activation flags, failure paths and boundaries. Existing tests are evidence,
  not the complete contract; add source-derived cases wherever coverage is missing.
- Keep documentation limited to implementation plans, evidence, Rust API
  contracts and references to authoritative node behavior. Do not create an
  independent normative protocol specification. Resolve disagreements in prose
  against the pinned implementation and tests; document and investigate any
  unresolved discrepancy rather than inventing a rule.
- Pause compatibility work for node developer review if and only if a clear
  node logic defect is found that could put funds at risk. Provide the affected
  revision and code, reproducible evidence, expected and actual behavior, and
  the concrete path to funds being at risk. Do not silently compensate in Rust.
  Resume the affected work after the node review resolves the issue and the
  compatibility target is explicitly reconciled.
- Design preferences, theoretical alternatives and documentation concerns do
  not trigger that node-defect pause. Ordinary Rust parity failures are work to
  fix, not reasons to reopen the node design.
- Provide any node-defect report to the user. Do not contact developers or
  publish an issue without explicit authorization.

## Commit attribution

If you generate code for this repository, append a commit trailer:

Format:
```
Assisted-by: <AI model> <version>
```

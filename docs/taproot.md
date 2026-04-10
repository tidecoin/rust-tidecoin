# Removed Witness-v1 Variant

The removed witness-v1 variant is not part of Tidecoin's intended supported surface.

The current direction is to keep the codebase focused on the transaction, address, and key paths
used by the Tidecoin network. Any legacy code for unsupported witness-v1 variants that remains in
the tree should be treated as internal residue, not as a feature to extend or document further.

If a new witness-v1 variant ever becomes relevant, it should come through a dedicated design and
validation pass rather than by expanding the current legacy code.

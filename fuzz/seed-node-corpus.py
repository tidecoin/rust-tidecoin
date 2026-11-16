#!/usr/bin/env python3
"""Generate reproducible driver seeds; the signed cases use test-only keys."""
import base64
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
seeds = [bytes([3, i, 0]) for i in range(6)]
for mode in range(6):
    for flags in [0, 0xE1C3, 0x3FFFF]:
        for selector in range(7):
            for boundary in [0, 1, 8, 9, 10, 11, 12, 13, 14, 15, 16]:
                seeds.append(bytes([0, mode]) + flags.to_bytes(4, "little") + bytes([selector, boundary, 0x51]))
for i in range(4):
    seeds.append(bytes([2, i, i, 0, 0, 0, 0, 0, 0x51]))
# Strict wire decoder: one sane transaction, plus prefixes/malformed markers.
tx = bytes.fromhex("0200000001" + "01" * 32 + "0000000000ffffffff0101000000000000000000000000")
seeds.append(bytes([1]) + tx)
for length in [0, 4, 5, 40, len(tx) - 1]:
    seeds.append(bytes([1]) + tx[:length])
# Inputs that previously exposed Rust/C++ mismatches (rc3 review, 2026-11-16).
# Minimized regressions live in fuzz/tests/node_oracle.rs; these keep the
# original driver inputs in every fuzz run.
for encoded in [
    "AAEAg9UAAAAAAAAAAK8CAAAAAAAAABr/4sgWAAAA",  # crash-61efecbb: multisig tail order
    "AAPD4VgAAAABAAAAAAAABgAAAAAAAACnAAAAAAAABABsAGNjAFAA",  # crash-7f6478bd: v1 MINIMALIF
    "//8DA6F8awAEAVEAAAILUQ==",  # crash-8e940121: depth before CScriptNum
    # crash-bf928ece: FindAndDelete push encoding
    "AAAAEFRUACYLxwAmCwMAAAAAAAAAAAAAVFSsVKJUVFTW9sABVFRUXHp6enp6enp6enp6enr4ZX4Aenp6eiFUAlQAAAAAAAAAAABUAAFRpQAAAAAA+/8BUQ==",
]:
    seeds.append(base64.b64decode(encoded))
for i, seed in enumerate(seeds):
    (root / f"seed-{i:04d}").write_bytes(seed)
print(f"wrote {len(seeds)} deterministic oracle seeds to {root}")

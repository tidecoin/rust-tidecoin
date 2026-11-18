#!/usr/bin/env python3
"""Generate reproducible driver seeds; the signed cases use test-only keys."""
import base64
import pathlib
import sys

# Usage: seed-node-corpus.py DIR [--signed-only]. With --signed-only, write only
# the mixed (MX) and signed-shape (SH) seeds in the TIDECOIN_FUZZ_SIGNED_ONLY
# layout: first byte 0 for MX or 1 for SH, then that path's input.
root = pathlib.Path(sys.argv[1])
signed_only = "--signed-only" in sys.argv[2:]
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
# Kind 4: generated transaction shapes for legacy/v0/v1-512 digests. Payload
# bytes choose counts, boundary values, raw hash types and script code. Saved
# corpora from before kind 4 used first byte 0x04 for kind 0; rewrite it to
# 0x00 when importing them.
for i in range(32):
    seeds.append(bytes([4]) + bytes((i * 37 + j * (2 * i + 1)) & 0xFF for j in range(256)))
# Inputs that previously exposed Rust/C++ mismatches (rc3 review, 2026-11-16).
# Minimized regressions live in fuzz/tests/node_oracle.rs; these keep the
# original driver inputs in every fuzz run.
for encoded in [
    "AAEAg9UAAAAAAAAAAK8CAAAAAAAAABr/4sgWAAAA",  # crash-61efecbb: multisig tail order
    "AAPD4VgAAAABAAAAAAAABgAAAAAAAACnAAAAAAAABABsAGNjAFAA",  # crash-7f6478bd: v1 MINIMALIF
    "//8DA6F8awAEAVEAAAILUQ==",  # crash-8e940121: depth before CScriptNum
    # crash-bf928ece: FindAndDelete push encoding
    "AAAAEFRUACYLxwAmCwMAAAAAAAAAAAAAVFSsVKJUVFTW9sABVFRUXHp6enp6enp6enp6enr4ZX4Aenp6eiFUAlQAAAAAAAAAAABUAAFRpQAAAAAA+/8BUQ==",
    # crash-0d0b65f0: witness encoding reread as a zero-input legacy transaction
    # by the bridge's RPC hex heuristics; comparison bridges now decode exactly.
    "BG9Iw+FdZGtyeYCHjpWcoxYdAQAA7/8wswQkKzU4QEdOVVxjbWVf2N/m7fT7AgkQF2pxeH+GjZSboqmwt77FzNPa4eh2fVN0MTNyF2pxeH+GjXF4f4aNlJuiqbC3vsXM09rh6O8=",
]:
    seeds.append(base64.b64decode(encoded))
# Extra kind-3 comparisons use three independent hash modes and paired edits.
for layout in range(6):
    for edit in range(4):
        seeds.append(bytes([3, 0, 0, 0, 0, 0, 0]) + b"MX"
                     + bytes([layout, edit, edit + 1, edit + 2, edit, 0, 1, 0]))
# Kind-3 "SH" signed shapes: every pinned case (SINGLE with 1/2/4 inputs and a
# legacy/v0/v1 last input, with and without its output; multisig/branch mixes
# with each edit set in both orders), then some with one or two unpinned edits.
shape = bytes([3, 0, 0, 0, 0, 0, 0]) + b"SH"
for size in range(3):
    for version in range(3):
        for remove in range(2):
            seeds.append(shape + bytes([0, size, version, remove, 0]))
for branch_first in range(2):
    for true_branch in range(2):
        for edit in [e for e in range(16) if e & 0b1010 != 0b1010]:
            seeds.append(shape + bytes([1, branch_first, true_branch, edit, 0]))
# Each edit is five bytes: selector (edit and bit index), input, then three
# value bytes; the last two form a little-endian byte offset.
for i in range(16):
    first = [i % 8 | (i % 8) << 3, i, i * 7, (i * 97) & 0xFF, i % 4]
    second = [(i + 3) % 8 | ((i + 5) % 8) << 3, i + 1, i * 5, (i * 61) & 0xFF, (i + 1) % 4]
    seeds.append(shape + bytes([i & 1, i >> 1 & 1, i >> 2 & 1, i, 1 + i % 2] + first + second))
if signed_only:
    signed_prefix = bytes([3, 0, 0, 0, 0, 0, 0])
    seeds = [bytes([0 if seed[7:9] == b"MX" else 1]) + seed[9:] for seed in seeds
             if seed[:7] == signed_prefix and seed[7:9] in (b"MX", b"SH")]
for i, seed in enumerate(seeds):
    (root / f"seed-{i:04d}").write_bytes(seed)
print(f"wrote {len(seeds)} deterministic oracle seeds to {root}")

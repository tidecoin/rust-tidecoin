#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
"""Extract Tidecoin testnet header fixtures.

By default the script reads blk*.dat files directly, applies the node block-file
XOR key when present, and prints a JSON fixture to stdout. For node-parity
retarget/contextual-header fixtures, use --active-chain-rpc so extraction asks
the node for canonical block hashes by height and decodes those exact active
chain blocks instead of inferring height from blk-file order. Both paths use the
Tidecoin node functional-test message parser for block deserialization so the
extracted bytes preserve node wire behavior.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import struct
import subprocess
import sys
from io import BytesIO
from pathlib import Path


TESTNET_MAGIC = bytes.fromhex("ba ce 3f da")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--node-repo",
        default=os.environ.get(
            "TIDECOIN_NODE_REPO",
            str(Path(__file__).resolve().parents[2] / "tidecoin"),
        ),
        help="Path to the Tidecoin node repository.",
    )
    parser.add_argument(
        "--datadir",
        default=str(Path.home() / ".tidecoin" / "testnet"),
        help="Path to the testnet datadir containing blocks/blk*.dat.",
    )
    parser.add_argument(
        "--active-chain-rpc",
        action="store_true",
        help=(
            "Extract fixtures from the node's active chain through tidecoin-cli "
            "instead of inferring height from blk*.dat file order."
        ),
    )
    parser.add_argument(
        "--cli",
        default=os.environ.get(
            "TIDECOIN_CLI",
            str(
                Path(__file__).resolve().parents[2]
                / "tidecoin"
                / "build"
                / "bin"
                / "tidecoin-cli"
            ),
        ),
        help="Path to tidecoin-cli for --active-chain-rpc.",
    )
    parser.add_argument(
        "--cli-args",
        default="-testnet",
        help="Extra tidecoin-cli arguments for --active-chain-rpc, parsed with shlex.",
    )
    parser.add_argument(
        "--heights",
        default="999,1000,1100,1101,1102",
        help="Comma-separated block heights to include.",
    )
    parser.add_argument(
        "--include-last-auxpow",
        action="store_true",
        help="Also include the highest AuxPoW block found in the selected source.",
    )
    parser.add_argument(
        "--retarget-windows",
        default="",
        help=(
            "Comma-separated retarget windows as name=start-end. Each window is "
            "inclusive and emits contiguous real headers for next-work tests."
        ),
    )
    parser.add_argument(
        "--output",
        help="Optional output JSON path. Defaults to stdout.",
    )
    return parser.parse_args()


def read_xor_key(blocks_dir: Path) -> bytes:
    path = blocks_dir / "xor.dat"
    if not path.exists():
        return b""
    key = path.read_bytes()
    if key == b"\x00" * len(key):
        return b""
    return key


def xor_at(data: bytes, key: bytes, file_offset: int) -> bytes:
    if not key:
        return data
    return bytes(byte ^ key[(file_offset + index) % len(key)] for index, byte in enumerate(data))


def import_node_messages(node_repo: Path) -> None:
    framework = node_repo / "test" / "functional"
    if not framework.exists():
        raise SystemExit(f"Tidecoin functional test framework not found: {framework}")
    sys.path.insert(0, str(framework))


def parse_retarget_windows(value: str) -> list[dict]:
    windows = []
    if not value:
        return windows
    for item in value.split(","):
        name, sep, span = item.partition("=")
        if not sep:
            raise SystemExit(f"invalid retarget window {item!r}; expected name=start-end")
        start, sep, end = span.partition("-")
        if not sep:
            raise SystemExit(f"invalid retarget window {item!r}; expected name=start-end")
        start_height = int(start)
        end_height = int(end)
        if end_height < start_height:
            raise SystemExit(f"invalid retarget window {item!r}; end is before start")
        windows.append({"name": name, "start_height": start_height, "end_height": end_height})
    return windows


def decode_blocks(
    blocks_dir: Path,
    selected_heights: set[int],
    include_last_auxpow: bool,
    retarget_windows: list[dict],
) -> tuple[list[dict], list[dict]]:
    from test_framework.messages import CBlock, CBlockHeader

    xor_key = read_xor_key(blocks_dir)
    cases: dict[int, dict] = {}
    retarget_heights = {
        height
        for window in retarget_windows
        for height in range(window["start_height"], window["end_height"] + 1)
    }
    retarget_cases: dict[int, dict] = {}
    last_auxpow: dict | None = None
    height = 0

    for block_file in sorted(blocks_dir.glob("blk*.dat")):
        data = block_file.read_bytes()
        offset = 0
        while offset + 8 <= len(data):
            magic = xor_at(data[offset : offset + 4], xor_key, offset)
            if magic == b"\x00\x00\x00\x00":
                break
            size_bytes = xor_at(data[offset + 4 : offset + 8], xor_key, offset + 4)
            size = struct.unpack("<I", size_bytes)[0]
            if magic != TESTNET_MAGIC or size == 0 or offset + 8 + size > len(data):
                break

            payload_offset = offset + 8
            payload = xor_at(data[payload_offset : payload_offset + size], xor_key, payload_offset)
            block = CBlock()
            block.deserialize(BytesIO(payload))
            header_obj = CBlockHeader(block)
            header = header_obj.serialize()
            expected = "valid_auxpow" if block.auxpow is not None else "valid_pure_pow"
            case = {
                "name": f"testnet_height_{height}_{'auxpow' if block.auxpow is not None else 'pure'}",
                "network": 1,
                "height": height,
                "expected": expected,
                "block_hash": header_obj.hash_hex,
                "n_bits": f"0x{block.nBits:08x}",
                "header_hex": header.hex(),
                "block_file": block_file.name,
                "block_file_offset": offset,
            }
            if height in selected_heights:
                cases[height] = case
            if height in retarget_heights:
                retarget_cases[height] = case
            if block.auxpow is not None:
                last_auxpow = case

            height += 1
            offset += 8 + size

    result = [cases[height] for height in sorted(cases)]
    if include_last_auxpow and last_auxpow is not None and last_auxpow["height"] not in cases:
        result.append(last_auxpow)
    windows = [
        {
            **window,
            "network": 1,
            "headers": [
                retarget_cases[height]
                for height in range(window["start_height"], window["end_height"] + 1)
            ],
        }
        for window in retarget_windows
    ]
    return result, windows


def rpc_call(cli: Path, cli_args: list[str], *args: object) -> str:
    command = [str(cli), *cli_args, *(str(arg) for arg in args)]
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as err:
        raise SystemExit(f"tidecoin-cli not found: {cli}") from err
    except subprocess.CalledProcessError as err:
        message = err.stderr.strip() or err.stdout.strip() or str(err)
        raise SystemExit(f"{' '.join(command)} failed: {message}") from err
    return result.stdout.strip()


def case_from_block_hex(block_hex: str, height: int, expected_hash: str | None) -> dict:
    from test_framework.messages import CBlock, CBlockHeader

    block_bytes = bytes.fromhex(block_hex)
    block = CBlock()
    block.deserialize(BytesIO(block_bytes))
    header_obj = CBlockHeader(block)
    header = header_obj.serialize()
    if expected_hash is not None and header_obj.hash_hex != expected_hash:
        raise SystemExit(
            f"active-chain block hash mismatch at height {height}: "
            f"RPC returned {expected_hash}, decoded {header_obj.hash_hex}"
        )
    expected = "valid_auxpow" if block.auxpow is not None else "valid_pure_pow"
    return {
        "name": f"testnet_height_{height}_{'auxpow' if block.auxpow is not None else 'pure'}",
        "network": 1,
        "height": height,
        "expected": expected,
        "block_hash": header_obj.hash_hex,
        "n_bits": f"0x{block.nBits:08x}",
        "header_hex": header.hex(),
        "source": "active-chain-rpc",
    }


def active_chain_case(cli: Path, cli_args: list[str], height: int) -> dict:
    block_hash = rpc_call(cli, cli_args, "getblockhash", height)
    block_hex = rpc_call(cli, cli_args, "getblock", block_hash, "false")
    return case_from_block_hex(block_hex, height, block_hash)


def decode_active_chain(
    cli: Path,
    cli_args: list[str],
    selected_heights: set[int],
    include_last_auxpow: bool,
    retarget_windows: list[dict],
) -> tuple[list[dict], list[dict]]:
    retarget_heights = {
        height
        for window in retarget_windows
        for height in range(window["start_height"], window["end_height"] + 1)
    }
    all_heights = selected_heights | retarget_heights
    cases_by_height = {
        height: active_chain_case(cli, cli_args, height) for height in sorted(all_heights)
    }

    if include_last_auxpow:
        best_height = int(rpc_call(cli, cli_args, "getblockcount"))
        for height in range(best_height, -1, -1):
            case = cases_by_height.get(height)
            if case is None:
                case = active_chain_case(cli, cli_args, height)
            if case["expected"] == "valid_auxpow":
                cases_by_height.setdefault(height, case)
                selected_heights.add(height)
                break

    cases = [cases_by_height[height] for height in sorted(selected_heights)]
    windows = [
        {
            **window,
            "network": 1,
            "headers": [
                cases_by_height[height]
                for height in range(window["start_height"], window["end_height"] + 1)
            ],
        }
        for window in retarget_windows
    ]
    return cases, windows


def main() -> None:
    args = parse_args()
    node_repo = Path(args.node_repo)
    datadir = Path(args.datadir)
    blocks_dir = datadir / "blocks"
    selected_heights = {int(item) for item in args.heights.split(",") if item}
    retarget_windows = parse_retarget_windows(args.retarget_windows)

    import_node_messages(node_repo)
    if args.active_chain_rpc:
        cases, windows = decode_active_chain(
            Path(args.cli),
            shlex.split(args.cli_args),
            selected_heights,
            args.include_last_auxpow,
            retarget_windows,
        )
        source = "Tidecoin testnet active chain through node RPC"
    else:
        cases, windows = decode_blocks(
            blocks_dir,
            selected_heights,
            args.include_last_auxpow,
            retarget_windows,
        )
        source = "local Tidecoin testnet blk*.dat decoded with blocks/xor.dat"

    payload = {
        "provenance": {
            "source": source,
            "note": (
                "Height 1000 activates post-AuxPoW rules; testnet may still contain "
                "pure PoW headers after that because AuxPoW is permitted, not mandatory."
            ),
        },
        "cases": cases,
    }
    if windows:
        payload["retarget_windows"] = windows
    output = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()

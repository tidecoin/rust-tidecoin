#!/usr/bin/env python3

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


def canonical_entries_bytes(entries):
    return json.dumps(
        entries,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def hash_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_node_commit(node_repo: pathlib.Path | None, node_commit: str | None) -> str:
    if node_commit:
        return node_commit
    if node_repo is None:
        raise ValueError("either --node-commit or --node-repo must be provided")
    result = subprocess.run(
        ["git", "-C", str(node_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate Tidecoin script-assets metadata for the generated large corpus "
            "derived from tx_valid_pq.json and tx_invalid_pq.json."
        )
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        required=True,
        help="Path to the generated Tidecoin script-assets JSON corpus.",
    )
    parser.add_argument(
        "--tx-valid",
        dest="tx_valid_path",
        required=True,
        help="Path to Tidecoin tx_valid_pq.json.",
    )
    parser.add_argument(
        "--tx-invalid",
        dest="tx_invalid_path",
        required=True,
        help="Path to Tidecoin tx_invalid_pq.json.",
    )
    parser.add_argument(
        "--output",
        default="tests/data/tidecoin_script_assets_generated_metadata.json",
        help=(
            "Output metadata JSON path "
            "(default: tests/data/tidecoin_script_assets_generated_metadata.json)."
        ),
    )
    parser.add_argument(
        "--node-repo",
        default=None,
        help="Path to a Tidecoin node git checkout (used to resolve source_node_commit).",
    )
    parser.add_argument(
        "--node-commit",
        default=None,
        help="Explicit Tidecoin node commit hash (overrides --node-repo).",
    )
    parser.add_argument(
        "--source-generation",
        default="tidecoin_tx_pq_vectors_monotonicity",
        help="Value for source_generation metadata key.",
    )
    args = parser.parse_args()

    json_path = pathlib.Path(args.json_path)
    tx_valid_path = pathlib.Path(args.tx_valid_path)
    tx_invalid_path = pathlib.Path(args.tx_invalid_path)
    for path in (json_path, tx_valid_path, tx_invalid_path):
        if not path.exists():
            raise FileNotFoundError(f"missing input file: {path}")

    entries = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("generated script-assets JSON must be a top-level array")

    metadata = {
        "schema_version": 1,
        "source_node_commit": resolve_node_commit(
            pathlib.Path(args.node_repo) if args.node_repo else None,
            args.node_commit,
        ),
        "source_generation": args.source_generation,
        "source_fixtures": {
            "tx_valid_pq_sha256": hash_file(tx_valid_path),
            "tx_invalid_pq_sha256": hash_file(tx_invalid_path),
        },
        "generated_case_count": len(entries),
        "generated_sha256": hashlib.sha256(canonical_entries_bytes(entries)).hexdigest(),
    }

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {output_path}")
    print(f"source_node_commit={metadata['source_node_commit']}")
    print(f"generated_case_count={metadata['generated_case_count']}")
    print(f"generated_sha256={metadata['generated_sha256']}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

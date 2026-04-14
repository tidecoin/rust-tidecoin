#!/usr/bin/env python3

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys


SOURCE_FILES = {
    "consensus_h": "src/consensus/consensus.h",
    "descriptor_cpp": "src/script/descriptor.cpp",
    "descriptor_tests": "src/test/descriptor_tests.cpp",
    "descriptor_fuzz": "src/test/fuzz/descriptor_parse.cpp",
    "policy_h": "src/policy/policy.h",
    "policy_cpp": "src/policy/policy.cpp",
    "pq_scheme_h": "src/pq/pq_scheme.h",
    "script_standard_tests": "src/test/script_standard_tests.cpp",
    "pq_txsize_tests": "src/test/pq_txsize_tests.cpp",
    "mempool_datacarrier": "test/functional/mempool_datacarrier.py",
    "mempool_dust": "test/functional/mempool_dust.py",
    "mempool_ephemeral_dust": "test/functional/mempool_ephemeral_dust.py",
    "mempool_truc": "test/functional/mempool_truc.py",
    "p2p_segwit": "test/functional/p2p_segwit.py",
}

PQ_SCHEMES = [
    {"name": "Falcon512", "prefix": 0x07, "pubkey_len": 897},
    {"name": "Falcon1024", "prefix": 0x08, "pubkey_len": 1793},
    {"name": "MlDsa44", "prefix": 0x09, "pubkey_len": 1312},
    {"name": "MlDsa65", "prefix": 0x0A, "pubkey_len": 1952},
    {"name": "MlDsa87", "prefix": 0x0B, "pubkey_len": 2592},
]


def canonical_json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def hash_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def node_commit(node_repo):
    result = subprocess.run(
        ["git", "-C", str(node_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def require_file(node_repo, relative_path):
    path = node_repo / relative_path
    if not path.exists():
        raise FileNotFoundError(f"missing Tidecoin node source file: {path}")
    return path


def read_source(node_repo, key):
    return require_file(node_repo, SOURCE_FILES[key]).read_text(encoding="utf-8")


def extract_braced_int(source, name):
    match = re.search(rf"\b{name}\s*\{{([^}}]+)\}}", source)
    if not match:
        match = re.search(rf"\b{name}\s*=\s*([^;]+);", source)
    if not match:
        raise ValueError(f"missing C++ constant {name}")
    raw = match.group(1).strip().replace("'", "")
    if raw == "false":
        return False
    if raw == "true":
        return True
    if "/" in raw:
        left, right = (part.strip() for part in raw.split("/", 1))
        return extract_braced_int(source, left) // extract_braced_int(source, right)
    return int(raw, 0)


def extract_python_int(source, name):
    match = re.search(rf"^{name}\s*=\s*([0-9_]+)", source, re.MULTILINE)
    if not match:
        raise ValueError(f"missing Python constant {name}")
    return int(match.group(1).replace("_", ""))


def policy_constants(node_repo):
    policy_h = read_source(node_repo, "consensus_h") + "\n" + read_source(node_repo, "policy_h")
    datacarrier_py = read_source(node_repo, "mempool_datacarrier")
    truc_py = read_source(node_repo, "mempool_truc")
    return {
        "MAX_STANDARD_TX_WEIGHT": extract_braced_int(policy_h, "MAX_STANDARD_TX_WEIGHT"),
        "MIN_STANDARD_TX_NONWITNESS_SIZE": extract_braced_int(
            policy_h, "MIN_STANDARD_TX_NONWITNESS_SIZE"
        ),
        "MAX_P2SH_SIGOPS": extract_braced_int(policy_h, "MAX_P2SH_SIGOPS"),
        "MAX_STANDARD_TX_SIGOPS_COST_DIVISOR": 5,
        "MAX_TX_LEGACY_SIGOPS": extract_braced_int(policy_h, "MAX_TX_LEGACY_SIGOPS"),
        "DEFAULT_BYTES_PER_SIGOP": extract_braced_int(policy_h, "DEFAULT_BYTES_PER_SIGOP"),
        "DEFAULT_PERMIT_BAREMULTISIG": extract_braced_int(policy_h, "DEFAULT_PERMIT_BAREMULTISIG"),
        "MAX_STANDARD_P2WSH_STACK_ITEMS": extract_braced_int(
            policy_h, "MAX_STANDARD_P2WSH_STACK_ITEMS"
        ),
        "MAX_STANDARD_P2WSH_STACK_ITEM_SIZE": extract_braced_int(
            policy_h, "MAX_STANDARD_P2WSH_STACK_ITEM_SIZE"
        ),
        "MAX_STANDARD_P2WSH_SCRIPT_SIZE": extract_braced_int(
            policy_h, "MAX_STANDARD_P2WSH_SCRIPT_SIZE"
        ),
        "MAX_STANDARD_SCRIPTSIG_SIZE": extract_braced_int(
            policy_h, "MAX_STANDARD_SCRIPTSIG_SIZE"
        ),
        "DUST_RELAY_TX_FEE": extract_braced_int(policy_h, "DUST_RELAY_TX_FEE"),
        "DEFAULT_MIN_RELAY_TX_FEE": extract_braced_int(policy_h, "DEFAULT_MIN_RELAY_TX_FEE"),
        "MAX_DUST_OUTPUTS_PER_TX": extract_braced_int(policy_h, "MAX_DUST_OUTPUTS_PER_TX"),
        "TX_MIN_STANDARD_VERSION": extract_braced_int(policy_h, "TX_MIN_STANDARD_VERSION"),
        "TX_MAX_STANDARD_VERSION": extract_braced_int(policy_h, "TX_MAX_STANDARD_VERSION"),
        "MAX_OP_RETURN_RELAY": extract_braced_int(policy_h, "MAX_OP_RETURN_RELAY"),
        "CUSTOM_DATACARRIER_ARG": extract_python_int(datacarrier_py, "CUSTOM_DATACARRIER_ARG"),
        "TRUC_MAX_VSIZE": extract_python_int(truc_py, "TRUC_MAX_VSIZE"),
        "TRUC_CHILD_MAX_VSIZE": extract_python_int(truc_py, "TRUC_CHILD_MAX_VSIZE"),
    }


def push_data_len_len(data_len):
    if data_len < 0x4C:
        return 1
    if data_len <= 0xFF:
        return 2
    if data_len <= 0xFFFF:
        return 3
    return 5


def data_elem_size(data_len):
    return push_data_len_len(data_len) + data_len


def descriptor_size_cases():
    out = []
    for scheme in PQ_SCHEMES:
        prefixed_pubkey_len = scheme["pubkey_len"] + 1
        out.append(
            {
                "id": f"descriptor_pk_script_size_{scheme['name']}",
                "partition": "node_unit_tests",
                "source": "descriptor_tests",
                "anchor": "BOOST_CHECK_EQUAL(*parsed.at(0)->ScriptSize(), scripts.back().size())",
                "kind": "descriptor_script_size",
                "descriptor": "pk",
                "scheme": scheme["name"],
                "prefix": scheme["prefix"],
                "prefixed_pubkey_len": prefixed_pubkey_len,
                "expected_script_size": data_elem_size(prefixed_pubkey_len) + 1,
            }
        )
        out.append(
            {
                "id": f"descriptor_multi_1_of_1_script_size_{scheme['name']}",
                "partition": "node_unit_tests",
                "source": "descriptor_cpp",
                "anchor": "acc + DataElemSize(pk->GetSize())",
                "kind": "descriptor_script_size",
                "descriptor": "multi",
                "threshold": 1,
                "pubkeys": [scheme["name"]],
                "prefixes": [scheme["prefix"]],
                "prefixed_pubkey_lens": [prefixed_pubkey_len],
                "expected_script_size": 1 + 1 + data_elem_size(prefixed_pubkey_len) + 1,
            }
        )

    mixed_lens = [PQ_SCHEMES[0]["pubkey_len"] + 1, PQ_SCHEMES[2]["pubkey_len"] + 1]
    out.append(
        {
            "id": "descriptor_multi_mixed_scheme_size_falcon512_mldsa44",
            "partition": "node_unit_tests",
            "source": "descriptor_tests",
            "anchor": "Mixed-scheme multisig is permitted",
            "kind": "descriptor_script_size",
            "descriptor": "multi",
            "threshold": 1,
            "pubkeys": ["Falcon512", "MlDsa44"],
            "prefixes": [PQ_SCHEMES[0]["prefix"], PQ_SCHEMES[2]["prefix"]],
            "prefixed_pubkey_lens": mixed_lens,
            "expected_script_size": 1 + 1 + sum(data_elem_size(length) for length in mixed_lens) + 1,
        }
    )
    return out


def source_hashes(node_repo):
    return {
        key: {"path": path, "sha256": hash_file(require_file(node_repo, path))}
        for key, path in SOURCE_FILES.items()
    }


def cases(constants):
    custom_datacarrier = constants["CUSTOM_DATACARRIER_ARG"]
    return descriptor_size_cases() + [
        {
            "id": "datacarrier_custom_exact",
            "partition": "node_functional_tests",
            "source": "mempool_datacarrier",
            "anchor": "custom_size_data = randbytes(CUSTOM_DATACARRIER_ARG - 3)",
            "kind": "datacarrier",
            "max_datacarrier_bytes": custom_datacarrier,
            "payload": {"shape": "bytes", "len": custom_datacarrier - 3},
            "expected": "ok",
        },
        {
            "id": "datacarrier_custom_one_byte_over",
            "partition": "node_functional_tests",
            "source": "mempool_datacarrier",
            "anchor": "too_long_data = randbytes(CUSTOM_DATACARRIER_ARG - 2)",
            "kind": "datacarrier",
            "max_datacarrier_bytes": custom_datacarrier,
            "payload": {"shape": "bytes", "len": custom_datacarrier - 2},
            "expected": "datacarrier",
        },
        {
            "id": "datacarrier_disabled_rejects_bare_op_return",
            "partition": "node_functional_tests",
            "source": "mempool_datacarrier",
            "anchor": "Testing a null data transaction with -datacarrier=false.",
            "kind": "datacarrier",
            "max_datacarrier_bytes": 0,
            "payload": {"shape": "none"},
            "expected": "datacarrier",
        },
        {
            "id": "datacarrier_tiny_limit_accepts_bare_op_return",
            "partition": "node_functional_tests",
            "source": "mempool_datacarrier",
            "anchor": "\"-datacarriersize=2\" and data=None",
            "kind": "datacarrier",
            "max_datacarrier_bytes": 2,
            "payload": {"shape": "none"},
            "expected": "ok",
        },
        {
            "id": "datacarrier_tiny_limit_accepts_zero_byte_push",
            "partition": "node_functional_tests",
            "source": "mempool_datacarrier",
            "anchor": "\"-datacarriersize=2\" and zero_bytes",
            "kind": "datacarrier",
            "max_datacarrier_bytes": 2,
            "payload": {"shape": "bytes", "len": 0},
            "expected": "ok",
        },
        {
            "id": "datacarrier_tiny_limit_rejects_one_byte_push",
            "partition": "node_functional_tests",
            "source": "mempool_datacarrier",
            "anchor": "\"-datacarriersize=2\" and one_byte",
            "kind": "datacarrier",
            "max_datacarrier_bytes": 2,
            "payload": {"shape": "bytes", "len": 1},
            "expected": "datacarrier",
        },
        {
            "id": "bare_multisig_one_of_one",
            "partition": "node_unit_tests",
            "source": "script_standard_tests",
            "anchor": "TxoutType::MULTISIG / OP_1 <pubkey> OP_1 OP_CHECKMULTISIG",
            "kind": "bare_multisig",
            "required_sigs": 1,
            "pubkeys": 1,
            "standard_with_bare_multisig": True,
        },
        {
            "id": "bare_multisig_one_of_three",
            "partition": "node_unit_tests",
            "source": "policy_cpp",
            "anchor": "Support up to x-of-3 multisig txns as standard",
            "kind": "bare_multisig",
            "required_sigs": 1,
            "pubkeys": 3,
            "standard_with_bare_multisig": True,
        },
        {
            "id": "bare_multisig_three_of_three",
            "partition": "node_unit_tests",
            "source": "policy_cpp",
            "anchor": "Support up to x-of-3 multisig txns as standard",
            "kind": "bare_multisig",
            "required_sigs": 3,
            "pubkeys": 3,
            "standard_with_bare_multisig": True,
        },
        {
            "id": "bare_multisig_zero_of_one",
            "partition": "node_unit_tests",
            "source": "script_standard_tests",
            "anchor": "TxoutType::MULTISIG 0/2",
            "kind": "bare_multisig",
            "required_sigs": 0,
            "pubkeys": 1,
            "standard_with_bare_multisig": False,
        },
        {
            "id": "bare_multisig_two_of_one",
            "partition": "node_unit_tests",
            "source": "script_standard_tests",
            "anchor": "TxoutType::MULTISIG 2/1",
            "kind": "bare_multisig",
            "required_sigs": 2,
            "pubkeys": 1,
            "standard_with_bare_multisig": False,
        },
        {
            "id": "bare_multisig_one_of_four",
            "partition": "node_unit_tests",
            "source": "policy_cpp",
            "anchor": "if (n < 1 || n > 3) return false",
            "kind": "bare_multisig",
            "required_sigs": 1,
            "pubkeys": 4,
            "standard_with_bare_multisig": False,
        },
        {
            "id": "witness_v0_stack_items_at_limit",
            "partition": "node_functional_tests",
            "source": "p2p_segwit",
            "anchor": "exact P2WSH witness stack item count limit",
            "kind": "witness_standard",
            "witness_version": 0,
            "dimension": "stack_items",
            "value": constants["MAX_STANDARD_P2WSH_STACK_ITEMS"],
            "expected": "ok",
        },
        {
            "id": "witness_v0_stack_items_over_limit",
            "partition": "node_functional_tests",
            "source": "p2p_segwit",
            "anchor": "P2WSH witness stack item count limit + 1",
            "kind": "witness_standard",
            "witness_version": 0,
            "dimension": "stack_items",
            "value": constants["MAX_STANDARD_P2WSH_STACK_ITEMS"] + 1,
            "expected": "nonstandard",
        },
        {
            "id": "witness_v1_512_stack_item_at_limit",
            "partition": "node_unit_tests",
            "source": "policy_cpp",
            "anchor": "MAX_STANDARD_P2WSH_STACK_ITEM_SIZE",
            "kind": "witness_standard",
            "witness_version": 1,
            "dimension": "stack_item_size",
            "value": constants["MAX_STANDARD_P2WSH_STACK_ITEM_SIZE"],
            "expected": "ok",
        },
        {
            "id": "witness_v1_512_stack_item_over_limit",
            "partition": "node_unit_tests",
            "source": "policy_cpp",
            "anchor": "MAX_STANDARD_P2WSH_STACK_ITEM_SIZE",
            "kind": "witness_standard",
            "witness_version": 1,
            "dimension": "stack_item_size",
            "value": constants["MAX_STANDARD_P2WSH_STACK_ITEM_SIZE"] + 1,
            "expected": "nonstandard",
        },
        {
            "id": "witness_v0_script_at_limit",
            "partition": "node_functional_tests",
            "source": "p2p_segwit",
            "anchor": "exact 65536 witnessScript size",
            "kind": "witness_standard",
            "witness_version": 0,
            "dimension": "witness_script_size",
            "value": constants["MAX_STANDARD_P2WSH_SCRIPT_SIZE"],
            "expected": "ok",
        },
        {
            "id": "witness_v0_script_over_limit",
            "partition": "node_functional_tests",
            "source": "p2p_segwit",
            "anchor": "65537 witnessScript size",
            "kind": "witness_standard",
            "witness_version": 0,
            "dimension": "witness_script_size",
            "value": constants["MAX_STANDARD_P2WSH_SCRIPT_SIZE"] + 1,
            "expected": "nonstandard",
        },
        {
            "id": "dust_one_output_allowed_by_stateless_standard_policy",
            "partition": "node_functional_tests",
            "source": "mempool_ephemeral_dust",
            "anchor": "single ephemeral dust output is package-valid but solo mempool stateful rules are out of scope",
            "kind": "dust_count",
            "dust_outputs": 1,
            "expected": "ok",
        },
        {
            "id": "dust_two_outputs_rejected",
            "partition": "node_functional_tests",
            "source": "mempool_ephemeral_dust",
            "anchor": "Test that a transaction with multiple ephemeral dusts is not allowed",
            "kind": "dust_count",
            "dust_outputs": 2,
            "expected": "dust",
        },
        {
            "id": "truc_vsize_at_limit",
            "partition": "node_functional_tests",
            "source": "mempool_truc",
            "anchor": "TRUC_MAX_VSIZE",
            "kind": "truc_vsize",
            "target_vsize": constants["TRUC_MAX_VSIZE"],
            "expected": "ok",
        },
        {
            "id": "truc_vsize_over_limit",
            "partition": "node_functional_tests",
            "source": "mempool_truc",
            "anchor": "target_vsize=TRUC_MAX_VSIZE + 1",
            "kind": "truc_vsize",
            "target_vsize": constants["TRUC_MAX_VSIZE"] + 1,
            "expected": "TRUC-violation",
        },
    ]


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Rust-owned Tidecoin node policy provenance corpus."
    )
    parser.add_argument(
        "--node-repo",
        required=True,
        help="Path to a Tidecoin node git checkout.",
    )
    parser.add_argument(
        "--output",
        default="tidecoin/tests/data/node_policy_provenance_corpus.json",
        help="Output JSON path.",
    )
    args = parser.parse_args()

    node_repo = pathlib.Path(args.node_repo)
    constants = policy_constants(node_repo)
    corpus_cases = cases(constants)
    corpus = {
        "schema_version": 1,
        "source_node_commit": node_commit(node_repo),
        "source_files": source_hashes(node_repo),
        "source_partitions": {
            "node_unit_tests": [
                "src/script/descriptor.cpp",
                "src/test/descriptor_tests.cpp",
                "src/test/script_standard_tests.cpp",
                "src/test/pq_txsize_tests.cpp",
                "src/policy/policy.cpp",
            ],
            "node_fuzz_tests": [
                "src/test/fuzz/descriptor_parse.cpp",
            ],
            "node_functional_tests": [
                "test/functional/mempool_datacarrier.py",
                "test/functional/mempool_dust.py",
                "test/functional/mempool_ephemeral_dust.py",
                "test/functional/mempool_truc.py",
                "test/functional/p2p_segwit.py",
            ],
        },
        "constants": constants,
        "case_count": len(corpus_cases),
        "cases_sha256": hashlib.sha256(canonical_json_bytes(corpus_cases)).hexdigest(),
        "cases": corpus_cases,
    }

    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output}")
    print(f"source_node_commit={corpus['source_node_commit']}")
    print(f"case_count={corpus['case_count']}")
    print(f"cases_sha256={corpus['cases_sha256']}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

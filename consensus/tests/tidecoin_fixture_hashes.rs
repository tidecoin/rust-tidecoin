use std::{env, fs, path::Path};

use hashes::sha256;
use node_parity::fixtures::{test_data_path, TIDECOIN_NODE_REPO_ENV};

struct FixtureHash {
    name: &'static str,
    sha256_hex: &'static str,
}

const FIXTURES: &[FixtureHash] = &[
    FixtureHash {
        name: "script_tests_pq.json",
        sha256_hex: "4aca9566a321f29575f62d9830d8e944c9731b249390d0c6780dc9d370183811",
    },
    FixtureHash {
        name: "tx_valid_pq.json",
        sha256_hex: "3933bcfe30291185a09a87163c1925e1342154cf48d4f4c717a3290750ca6658",
    },
    FixtureHash {
        name: "tx_invalid_pq.json",
        sha256_hex: "cb8dc7fa363fa502fa00948c85fcb8a99987989684b054c9eb35417a67f9bde0",
    },
    FixtureHash {
        name: "script_assets_test.json",
        sha256_hex: "297921d17df9ddc93683f65b6da14153b07aa0923ae42c8ea929c6b36cf8f910",
    },
    FixtureHash {
        name: "sighash.json",
        sha256_hex: "52cf23c2076e7f129c71d5508631d3e5ae3be1b1cb0585c0e23bbb4bb373e924",
    },
];

fn hash_file(path: &Path) -> String {
    let bytes =
        fs::read(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    sha256::Hash::hash(&bytes).to_string()
}

#[test]
fn tidecoin_node_fixtures_match_pinned_hashes_when_available() {
    if env::var_os(TIDECOIN_NODE_REPO_ENV).is_none() {
        eprintln!(
            "skipping Tidecoin fixture hash check (set {TIDECOIN_NODE_REPO_ENV} to enable corpus pinning)"
        );
        return;
    }

    for fixture in FIXTURES {
        let path = test_data_path(fixture.name);
        let actual = hash_file(&path);
        assert_eq!(
            actual,
            fixture.sha256_hex,
            "fixture hash mismatch for {} (expected {}, got {}). \
             If you intentionally updated the Tidecoin node corpus, update the pinned hash in {}.",
            path.display(),
            fixture.sha256_hex,
            actual,
            file!()
        );
    }
}

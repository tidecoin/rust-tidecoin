// SPDX-License-Identifier: CC0-1.0

use std::path::{Path, PathBuf};

/// Environment variable pointing at the Tidecoin node checkout.
pub const TIDECOIN_NODE_REPO_ENV: &str = "TIDECOIN_NODE_REPO";

/// Returns the configured Tidecoin node checkout path.
///
/// Panics with a clear message if the environment variable is missing.
pub fn node_repo_dir() -> PathBuf {
    std::env::var_os(TIDECOIN_NODE_REPO_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "missing {TIDECOIN_NODE_REPO_ENV}; set it to the Tidecoin node checkout used for node-backed validation"
            )
        })
}

/// Returns the `src/test/data` directory under the configured Tidecoin node checkout.
pub fn test_data_dir() -> PathBuf {
    node_repo_dir().join("src/test/data")
}

/// Returns a path under the Tidecoin node `src/test/data` directory.
pub fn test_data_path(name: &str) -> PathBuf {
    test_data_dir().join(name)
}

/// Panics if the configured Tidecoin node checkout does not contain `src/`.
pub fn assert_node_src_exists(node_repo: &Path) {
    let node_src = node_repo.join("src");
    assert!(
        node_src.exists(),
        "tidecoin-node-validation requires Tidecoin node sources at {}",
        node_repo.display()
    );
}

#!/usr/bin/env bash
# This script is used to briefly fuzz every target when no target is provided. Otherwise, it will briefly fuzz the
# provided target

set -euox pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

# can't find the file because of the ENV var
# shellcheck source=/dev/null
source "$REPO_DIR/fuzz/fuzz-util.sh"

# Check that input files are correct Windows file names
checkWindowsFiles

if [ -z "${1:-}" ]; then
  targetFiles="$(listTargetFiles)"
else
  targetFiles=fuzz_targets/"$1".rs
fi

cargo --version
rustc --version

# Testing
cargo install --force cargo-fuzz
for targetFile in $targetFiles; do
  targetName=$(targetFileToName "$targetFile")
  echo "Fuzzing target $targetName ($targetFile)"
  features=()
  if [ "$targetName" = consensus_node_differential ]; then
    if [ -z "${TIDECOIN_NODE_REPO:-}" ]; then
      if [ -n "${1:-}" ]; then
        echo "The original-node target requires TIDECOIN_NODE_REPO" >&2
        exit 1
      fi
      echo "Run the original-node target separately with TIDECOIN_NODE_REPO configured"
      continue
    fi
    features=(--features node-oracle)
  fi
  # cargo-fuzz will check for the corpus at fuzz/corpus/<target>
  cargo +nightly fuzz run "${features[@]}" "$targetName" -- -runs=100000
  checkReport "$targetName"
done

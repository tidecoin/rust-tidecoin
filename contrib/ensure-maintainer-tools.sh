#!/usr/bin/env bash
#
# Ensure maintainer tools are available locally for CI task execution.

set -euo pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

cd "$REPO_DIR"

if ! command -v cargo-rbmt >/dev/null 2>&1; then
    echo "Error: cargo-rbmt is required for maintainer tools but not found in PATH" >&2
    echo "Please install cargo-rbmt using the maintainer-tools source pinned by rbmt-version." >&2
    exit 1
fi

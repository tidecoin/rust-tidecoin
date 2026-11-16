#!/usr/bin/env bash

set -euox pipefail

cd "$(dirname "$0")/.."

. contrib/test_vars.sh

target_features="$(rustc --print target-features | awk '{ if ($1 == "") { exit 0 } if (NR != 1 && $1 != "crt-static" && $1 != "soft-float") { if (NR == 2) { printf "+%s", $1 } else { printf ",+%s", $1 } } }')"

for crate in $CRATES;
do
	# node-parity exists to call the original C++ node through FFI and to
	# manage its checkout on disk. Miri cannot execute foreign C/C++ code and
	# isolates the file system, so the crate cannot run under Miri at all.
	# Its Rust-side unsafe code is limited to those FFI calls.
	if [ "$crate" = node-parity ]; then
		echo "FFI-only crate $crate cannot run under Miri, skipping..." >&2
		continue
	fi

	# Running miri is expensive and not needed for crates that don't contain unsafe
	if RUSTFLAGS="-C target-feature=$target_features -F unsafe-code" cargo check -q --manifest-path "$crate/Cargo.toml" --all-features --target x86_64-unknown-linux-gnu 2>/dev/null;
	then
		echo "No unsafe code in $crate, skipping..." >&2
		continue
	fi

	RUSTFLAGS="-C target-feature=$target_features" RUSTDOCFLAGS="-C target-feature=$target_features" MIRIFLAGS=-Zmiri-backtrace=full cargo miri test --manifest-path "$crate/Cargo.toml" --all-features --target x86_64-unknown-linux-gnu
done

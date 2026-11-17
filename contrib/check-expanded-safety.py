#!/usr/bin/env python3
"""Check expanded Rust ASTs, including code emitted by dependency macros.

Pinned rustc AST output preserves the distinction between compiler-generated
unsafe blocks and user-provided blocks (including external macro expansions).
Unlike the unsafe_code lint, this check sees the latter. A toolchain update must
review this parser and run its compiler-backed regression tests.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
# Explicitly reviewed Miri exemptions. Dependencies are not claimed unsafe-free.
SAFE_CRATES = (
    "base58", "chacha20_poly1305", "consensus", "consensus-core",
    "consensus_encoding", "fuzz", "network", "p2p", "tidecoin", "units",
)
UNSAFE = re.compile(r"^(?:(\w+): )?Unsafe(?:\(|,|$)")


def inspect_ast(lines):
    """Return diagnostics; consume the large rustc dump without retaining it."""
    lines = iter(enumerate(lines, 1))
    errors = []
    first = next(lines, (0, ""))[1].strip()
    if first != "Crate {":
        return ["unrecognized rustc AST format (expected Crate)"]
    for number, line in lines:
        text = line.strip()
        match = UNSAFE.match(text)
        if not match:
            continue
        field = match[1]
        _, origin = next(lines, (0, ""))
        if field == "rules" and origin.strip() == "CompilerGenerated,":
            # rustc sets this marker, not an attribute supplied by a macro.
            # In expanded AST output this covers built-in enum derives.
            continue
        if field == "safety" and origin.strip() == "no-location (#0),":
            # Built-in Clone emits an unsafe TrivialClone impl with a dummy
            # keyword span. Ordinary code and proc/declarative macro output
            # have real spans, even when annotated automatically_derived.
            indent = len(line) - len(line.lstrip())
            header = []
            for _, part in lines:
                if len(part) - len(part.lstrip()) < indent:
                    break
                header.append(part)
            header = "".join(header)
            names = re.findall(r"\bident: ([^#\s]+)#\d+,", header)
            if names == ["$crate", "clone", "TrivialClone"] and not re.search(r"\bUnsafe\(", header):
                continue
        errors.append(f"AST line {number}: {text} {origin.strip()}")
    return errors


def check_command(command):
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, text=True)
    assert process.stdout is not None
    with process.stdout:
        errors = inspect_ast(process.stdout)
    status = process.wait()
    if status:
        raise RuntimeError(f"expansion failed ({status}): {' '.join(command)}")
    if errors:
        raise RuntimeError("unsafe code found:\n" + "\n".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crate", choices=SAFE_CRATES, action="append")
    parser.add_argument("--target", help="Rust target triple (default: host)")
    parser.add_argument("--list", action="store_true", help="print reviewed Miri exemptions")
    args = parser.parse_args()
    if args.list:
        print("\n".join(SAFE_CRATES))
        return
    with (ROOT / "Cargo.toml").open("rb") as manifest:
        nightly = tomllib.load(manifest)["workspace"]["metadata"]["rbmt"]["toolchains"]["nightly"]
    metadata = json.loads(subprocess.check_output(
        ["cargo", f"+{nightly}", "metadata", "--no-deps", "--format-version", "1"], cwd=ROOT))
    packages = {Path(p["manifest_path"]).parent.name: p for p in metadata["packages"]}
    for crate in args.crate or SAFE_CRATES:
        package = packages[crate]
        base = ["cargo", f"+{nightly}", "rustc", "--quiet", "-p", package["name"]]
        if args.target:
            base += ["--target", args.target]
        # Cover feature-dependent production expansions and actual cfg(test)
        # library code (Cargo passes --test for the test-profile library).
        for features in ([], ["--no-default-features"], ["--all-features"]):
            print(f"Checking {crate} library {features or '(default features)'}", flush=True)
            check_command(base + features + ["--lib", "--", "-Zunpretty=ast-tree,expanded"])
        print(f"Checking {crate} unit tests (all features)", flush=True)
        check_command(base + ["--all-features", "--lib", "--profile", "test", "--",
                              "-Zunpretty=ast-tree,expanded"])
        for target in package["targets"]:
            if "test" in target["kind"]:
                print(f"Checking {crate} integration test {target['name']} (all features)", flush=True)
                check_command(base + ["--all-features", "--test", target["name"], "--",
                                      "-Zunpretty=ast-tree,expanded"])
    print("No application or dependency-macro unsafe code in the checked targets/configurations.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))

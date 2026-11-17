#!/usr/bin/env python3
"""Regression tests against actual output from the pinned compiler."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("checker", ROOT / "contrib/check-expanded-safety.py")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
with (ROOT / "Cargo.toml").open("rb") as manifest:
    NIGHTLY = tomllib.load(manifest)["workspace"]["metadata"]["rbmt"]["toolchains"]["nightly"]


class ExpansionTests(unittest.TestCase):
    def expand(self, source, extra=(), macro_source=None):
        with tempfile.TemporaryDirectory(prefix="tide-expanded-") as directory:
            directory = Path(directory)
            rustc = ["rustc", f"+{NIGHTLY}", "--edition=2021", "--crate-type=lib"]
            dependencies = []
            if macro_source:
                macro = directory / "external_macro.rs"
                macro.write_text(macro_source)
                library = directory / "libexternal_macro.rlib"
                subprocess.run(rustc + [str(macro), "-o", str(library)], check=True, capture_output=True)
                dependencies = ["--extern", f"external_macro={library}"]
            source_file = directory / "fixture.rs"
            source_file.write_text(source)
            expanded = subprocess.run(
                rustc + [str(source_file), "-Zunpretty=ast-tree,expanded"] + list(extra) + dependencies,
                check=True, capture_output=True, text=True)
            return CHECKER.inspect_ast(expanded.stdout.splitlines(keepends=True))

    def test_builtin_derives_and_unsafe_text(self):
        self.assertEqual(self.expand('''
            #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
            enum Sample { A(u8), B(u8) }
            const TEXT: &str = "unsafe { pointer.read() }";
            fn name_contains_unsafe() { let _ = vec![1, 2, 3]; }
        '''), [])

    def test_direct_unsafe_forms(self):
        for source in (
            'fn f(p: *const u8) -> u8 { unsafe { *p } }',
            'unsafe fn f() {}',
            'unsafe trait T {}',
            'struct S; unsafe impl Send for S {}',
            'unsafe extern "C" { fn f(); }',
            '#[unsafe(no_mangle)] pub fn f() {}',
            '#[automatically_derived] unsafe impl Send for S {} struct S;',
            '#[automatically_derived] unsafe impl core::clone::TrivialClone for S {} struct S;',
        ):
            with self.subTest(source=source):
                self.assertTrue(self.expand(source))

    def test_external_macro_despite_forbid(self):
        self.assertTrue(self.expand(
            '#![forbid(unsafe_code)] external_macro::cast!();',
            macro_source='''#[macro_export] macro_rules! cast { () => {
                pub fn cast(p: *const u8) -> u8 { unsafe { *p } }
            } }'''))

    def test_unsafe_inside_test_configuration(self):
        source = '#[cfg(test)] fn f(p: *const u8) -> u8 { unsafe { *p } }'
        self.assertEqual(self.expand(source), [])
        self.assertTrue(self.expand(source, ['--test']))

    def test_unknown_format_is_rejected(self):
        self.assertTrue(CHECKER.inspect_ast(['changed compiler format']))


if __name__ == "__main__":
    unittest.main()

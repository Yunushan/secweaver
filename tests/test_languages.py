from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from secweaver.languages import coverage_row, detect_languages, load_catalog


class LanguageCatalogTests(unittest.TestCase):
    def test_catalog_has_exactly_fifty_unique_entries_and_twenty_tier_one(self) -> None:
        catalog = load_catalog()
        self.assertEqual(len(catalog), 50)
        self.assertEqual(len({item.name.casefold() for item in catalog}), 50)
        self.assertEqual(sum(item.tier == 1 for item in catalog), 20)
        self.assertEqual(sum(item.tier == 2 for item in catalog), 30)

    def test_tier_one_names_are_the_declared_priority_twenty(self) -> None:
        expected = {
            "C",
            "C#",
            "C++",
            "Dart",
            "Go",
            "HCL/Terraform",
            "Java",
            "JavaScript",
            "Kotlin",
            "Lua",
            "PHP",
            "Python",
            "R",
            "Ruby",
            "Rust",
            "SQL",
            "Scala",
            "Shell",
            "Swift",
            "TypeScript",
        }
        actual = {item.name for item in load_catalog() if item.tier == 1}
        self.assertEqual(actual, expected)

    def test_every_catalog_row_has_generic_and_declared_coverage(self) -> None:
        for language in load_catalog():
            with self.subTest(language=language.name):
                row = coverage_row(language)
                self.assertEqual(row["name"], language.name)
                self.assertEqual(row["tier"], language.tier)
                self.assertGreaterEqual(len(row["coverage"]), 3)
                self.assertTrue(any("Gitleaks" in item for item in row["coverage"]))
                self.assertTrue(any("Opengrep" in item for item in row["coverage"]))
                if language.ecosystems:
                    self.assertTrue(
                        any(
                            "verify scanner/package-format support" in item
                            for item in row["coverage"]
                        )
                    )

    def test_duplicate_catalog_names_are_rejected_case_insensitively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.toml"
            path.write_text(
                "\n".join(
                    (
                        "[[languages]]",
                        'name = "FixtureLang"',
                        "tier = 1",
                        'extensions = [".fx"]',
                        "",
                        "[[languages]]",
                        'name = "fixturelang"',
                        "tier = 2",
                        'extensions = [".fy"]',
                    )
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate names"):
                load_catalog(path)


class LanguageDetectionTests(unittest.TestCase):
    def test_detection_uses_extensions_filenames_casefolding_and_excludes(self) -> None:
        catalog = load_catalog()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "backend/service.PY": "# inert fixture\n",
                "frontend/view.TSX": "// inert fixture\n",
                "jvm/POM.XML": "<!-- inert fixture -->\n",
                "scripts/.BASHRC": "# inert fixture\n",
                "stats/analysis.R": "# inert fixture\n",
                "native/shared.h": "/* inert fixture */\n",
                "apple/legacy.m": "/* inert fixture */\n",
                "vendor/ignored.go": "// excluded fixture\n",
                "generated/nested/ignored.rs": "// excluded fixture\n",
                "notes/readme.fixture": "unknown extension\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            counts = detect_languages(
                root,
                catalog,
                excludes=("vendor", "generated/**"),
            )

        self.assertEqual(counts["Python"], 1)
        self.assertEqual(counts["TypeScript"], 1)
        self.assertEqual(counts["Java"], 1)
        self.assertEqual(counts["Shell"], 1)
        self.assertEqual(counts["R"], 1)
        self.assertEqual(counts["C"], 1)
        self.assertNotIn("C++", counts)
        # Ambiguous extensions are intentionally assigned to the first catalog row.
        self.assertEqual(counts["Objective-C"], 1)
        self.assertNotIn("MATLAB", counts)
        self.assertNotIn("Go", counts)
        self.assertNotIn("Rust", counts)

    def test_unknown_files_are_omitted_instead_of_returned_as_zeroes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.unknown"
            path.write_text("inert\n", encoding="utf-8")
            self.assertEqual(detect_languages(Path(directory), load_catalog()), {})

    def test_symlinked_files_outside_repository_are_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "workspace"
            root.mkdir()
            outside = base / "outside.py"
            outside.write_text("# inert fixture\n", encoding="utf-8")
            link = root / "linked.py"
            try:
                os.symlink(outside, link)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            self.assertEqual(detect_languages(root, load_catalog()), {})


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import struct
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PNG_PATH = PROJECT_ROOT / "docs/images/ids-rule-converter-safety-comparison.png"
SVG_PATH = PROJECT_ROOT / "docs/images/source/ids-rule-converter-safety-comparison.svg"
ALT_TEXT = (
    "Synthetic two-rule IDS conversion comparison showing strict mode writing no "
    "ruleset and reviewed partial mode separating one accepted rule, one rejected "
    "rule, and a JSON report while returning exit code 2."
)


class ReadmeVisualTests(unittest.TestCase):
    def test_readme_uses_a_public_url_for_the_packaged_safety_visual(self) -> None:
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        image_url = (
            "https://raw.githubusercontent.com/fusiontechstrategies/IDS-Rule-Converter/refs/heads/main/"
            + PNG_PATH.relative_to(PROJECT_ROOT).as_posix()
        )
        expected = f"![{ALT_TEXT}]({image_url})"
        self.assertIn(expected, readme)
        self.assertLess(
            readme.index(expected),
            readme.index("## Commands"),
        )

    def test_visual_assets_are_bounded_and_safe(self) -> None:
        png = PNG_PATH.read_bytes()
        self.assertEqual(b"\x89PNG\r\n\x1a\n", png[:8])
        self.assertEqual((1200, 1400), struct.unpack(">II", png[16:24]))
        self.assertLessEqual(len(png), 400_000)

        svg = SVG_PATH.read_text(encoding="utf-8")
        lowered = svg.lower()
        self.assertIn("SHOWN IN CONSOLE", svg)
        self.assertNotIn("RETAINED IN REPORT", svg)
        self.assertNotIn("\u2014", svg)
        self.assertNotIn("<script", lowered)
        self.assertNotIn("href=", lowered)
        self.assertNotIn("url(http", lowered)


if __name__ == "__main__":
    unittest.main()

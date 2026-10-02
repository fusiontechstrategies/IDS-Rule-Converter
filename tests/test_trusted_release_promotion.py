"""Offline source-data and subject binding at the privileged promotion boundary."""

import shutil
import tempfile
import unittest
from pathlib import Path

import test_security_regressions as fixtures

from scripts import prepare_release, verify_release_handoff

ROOT = Path(__file__).resolve().parents[1]
VERSION = "4.0.2"
COMMIT = "a" * 40


class TrustedReleasePromotionTests(unittest.TestCase):
    def candidate(self, root, source=ROOT):
        dist = root / "dist"
        dist.mkdir()
        fixtures.SecurityRegressions().fixture_distributions(dist)
        assets = root / "assets"
        prepare_release.prepare_release(source, assets, VERSION, COMMIT, dist)
        return assets

    def test_exact_handoff_passes_but_wrong_commit_and_changed_subject_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = self.candidate(root)
            result = verify_release_handoff.verify_handoff(assets, ROOT, COMMIT, 0)
            self.assertEqual(result["tag"], "v" + VERSION)
            self.assertEqual(len(result["manifest"]), 7)
            with self.assertRaisesRegex(ValueError, "authenticated source identity"):
                verify_release_handoff.verify_handoff(assets, ROOT, "b" * 40, 0)
            standalone = assets / f"IDS-Rule-Converter-v{VERSION}.py"
            standalone.write_bytes(standalone.read_bytes() + b"\n# replaced subject\n")
            with self.assertRaises(ValueError):
                verify_release_handoff.verify_handoff(assets, ROOT, COMMIT, 0)

    def test_tagged_release_helper_cannot_execute_in_trusted_reconstruction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            names = set(prepare_release.PACKAGE_FILES) | {
                "pyproject.toml",
                ".github/release-notes/v4.0.2.md",
            }
            names.update(p.relative_to(ROOT).as_posix() for p in (ROOT / "tests").glob("test_*.py"))
            for name in names:
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)
            (source / "scripts").mkdir()
            (source / "scripts/prepare_release.py").write_text(
                "raise RuntimeError('tagged code executed')\n"
            )
            assets = self.candidate(root, source)
            result = verify_release_handoff.verify_handoff(assets, source, COMMIT, 0)
            self.assertEqual(result["version"], VERSION)

    def test_tag_build_cannot_supply_privileged_verification_code(self):
        producer = (ROOT / ".github/workflows/release.yml").read_text()
        promoter = (ROOT / ".github/workflows/release-promotion.yml").read_text()
        for permission in ("contents: write", "id-token: write", "attestations: write"):
            self.assertNotIn(permission, producer)
        self.assertIn("name: release-assets", producer)
        self.assertIn("run['path'] == '.github/workflows/release.yml'", promoter)
        self.assertIn("artifact-ids: ${{ needs.verify.outputs.artifact-id }}", promoter)
        self.assertIn("ref: ${{ needs.verify.outputs.verifier-commit }}", promoter)
        self.assertNotIn("python -I source-data/", promoter)
        self.assertIn('assets readback "$EXPECTED_MANIFEST"', promoter)

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts import prepare_release

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERSION = "4.0.1"
SOURCE_COMMIT = "a" * 40


class ReleasePreparationTests(unittest.TestCase):
    def build(self, parent: Path, name: str) -> tuple[Path, ...]:
        return prepare_release.prepare_release(
            PROJECT_ROOT,
            parent / name,
            VERSION,
            SOURCE_COMMIT,
        )

    def test_repeat_builds_are_byte_identical_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            first = self.build(parent, "first")
            second = self.build(parent, "second")
            self.assertEqual(
                prepare_release.expected_asset_names(VERSION), tuple(p.name for p in first)
            )
            self.assertEqual(
                [path.read_bytes() for path in first],
                [path.read_bytes() for path in second],
            )
            self.assertEqual(
                set(prepare_release.expected_asset_names(VERSION)),
                {path.name for path in (parent / "first").iterdir()},
            )

    def test_runtime_asset_and_checksums_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outputs = self.build(Path(directory), "candidate")
            by_name = {path.name: path for path in outputs}
            runtime_name = f"IDS-Rule-Converter-v{VERSION}.py"
            self.assertEqual(
                (PROJECT_ROOT / "snort_suricata_rule_converter.py").read_bytes(),
                by_name[runtime_name].read_bytes(),
            )

            lines = by_name["SHA256SUMS.txt"].read_text(encoding="ascii").splitlines()
            self.assertEqual(3, len(lines))
            for line in lines:
                digest, name = line.split("  ", maxsplit=1)
                self.assertEqual(hashlib.sha256(by_name[name].read_bytes()).hexdigest(), digest)

    def test_archive_is_portable_and_contains_exact_package_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outputs = self.build(Path(directory), "candidate")
            zip_path = next(path for path in outputs if path.suffix == ".zip")
            prefix = f"IDS-Rule-Converter-v{VERSION}/"
            with zipfile.ZipFile(zip_path) as archive:
                self.assertEqual(
                    [prefix + name for name in sorted(prepare_release.PACKAGE_FILES)],
                    archive.namelist(),
                )
                for info in archive.infolist():
                    self.assertEqual(prepare_release.ARCHIVE_TIMESTAMP, info.date_time)
                    self.assertFalse(info.is_dir())
                    self.assertNotIn("\\", info.filename)
                    self.assertNotIn("..", Path(info.filename).parts)
                self.assertEqual(
                    (PROJECT_ROOT / "snort_suricata_rule_converter.py").read_bytes(),
                    archive.read(prefix + "snort_suricata_rule_converter.py"),
                )

    def test_spdx_and_evidence_bind_the_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outputs = self.build(Path(directory), "candidate")
            by_name = {path.name: path for path in outputs}
            spdx = json.loads(by_name[f"IDS-Rule-Converter-v{VERSION}.spdx.json"].read_text())
            self.assertEqual("SPDX-2.3", spdx["spdxVersion"])
            self.assertEqual(VERSION, spdx["packages"][0]["versionInfo"])
            self.assertEqual(len(prepare_release.PACKAGE_FILES), len(spdx["files"]))

            evidence = json.loads(by_name["release-evidence.json"].read_text())
            self.assertEqual(VERSION, evidence["version"])
            self.assertEqual(SOURCE_COMMIT, evidence["source_commit"])
            self.assertEqual(
                list(prepare_release.expected_asset_names(VERSION)),
                evidence["expected_release_assets"],
            )
            for artifact in evidence["artifacts"]:
                path = by_name[artifact["name"]]
                self.assertEqual(path.stat().st_size, artifact["bytes"])
                self.assertEqual(prepare_release.sha256_file(path), artifact["sha256"])

    def test_invalid_identity_and_nonempty_output_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            with self.assertRaises(prepare_release.ReleaseError):
                prepare_release.prepare_release(
                    PROJECT_ROOT,
                    parent / "mismatch",
                    "4.0.2",
                    SOURCE_COMMIT,
                )
            with self.assertRaises(prepare_release.ReleaseError):
                prepare_release.prepare_release(
                    PROJECT_ROOT,
                    parent / "bad-commit",
                    VERSION,
                    "A" * 40,
                )

            occupied = parent / "occupied"
            occupied.mkdir()
            (occupied / "existing.txt").write_text("preserve", encoding="utf-8")
            with self.assertRaises(prepare_release.ReleaseError):
                prepare_release.prepare_release(PROJECT_ROOT, occupied, VERSION, SOURCE_COMMIT)
            self.assertEqual("preserve", (occupied / "existing.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

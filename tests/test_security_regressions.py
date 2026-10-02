"""Synthetic adversarial cases for parser, output, archive, and distribution boundaries."""

from __future__ import annotations

import gzip
import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import snort_suricata_rule_converter as converter
from scripts import verify_distribution

ROOT = Path(__file__).resolve().parents[1]
RULE = 'alert tcp any any -> any 80 (content:"test"; sid:1001;)'


class SecurityRegressions(unittest.TestCase):
    def test_unclosed_comment_rejects_entire_ruleset(self):
        parsed = converter.RuleParser().parse_text(RULE + "\n/* hidden remaining rules")
        self.assertTrue(parsed.errors)
        self.assertEqual(parsed.rules, [])
        self.assertTrue(any(item.code == "UNTERMINATED_BLOCK_COMMENT" for item in parsed.errors))

    def test_nonmodifier_inline_suffixes_and_wrong_arity_are_rejected(self):
        for suffix in ("sid 999", "flowbits set,admin", "nocase 1", "depth"):
            parsed = converter.RuleParser().parse_text(
                f'alert tcp any any -> any 80 (content:"test",{suffix}; sid:1001;)'
            )
            self.assertTrue(parsed.errors, suffix)

    def test_field_specific_buffer_is_not_silently_broadened(self):
        parsed = converter.RuleParser().parse_text(
            'alert tcp any any -> any 80 (http_header:field user-agent; content:"test"; sid:1001;)'
        )
        self.assertFalse(parsed.errors)
        converted = converter.convert_rules(
            parsed.rules, "snort2", strict=True, source_dialect="snort3"
        )
        self.assertEqual(converted.rules, [])
        self.assertTrue(converted.rejected_rule_indexes)

    @unittest.skipIf(os.name == "nt", "Windows forbids newline filenames")
    def test_filename_cannot_escape_source_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / ("input\n" + RULE + ".rules")
            output = Path(directory) / "output.rules"
            source.write_text(RULE, encoding="utf-8")
            result = converter.main(
                [
                    "convert",
                    str(source),
                    "--target",
                    "snort3",
                    "--source-dialect",
                    "snort3",
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(result, converter.EXIT_OK)
            text = output.read_text(encoding="utf-8")
            self.assertEqual(
                len([line for line in text.splitlines() if line.startswith("alert ")]), 1
            )
            self.assertIn(
                "\\n", next(line for line in text.splitlines() if line.startswith("# Source:"))
            )

    @unittest.skipIf(os.name == "nt", "Symlink privileges differ on Windows")
    def test_symlinked_output_leaf_is_never_followed_even_with_force(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "target"
            target.write_bytes(b"original")
            leaf = parent / "output"
            leaf.symlink_to(target)
            with self.assertRaises(converter.ConverterError):
                converter.atomic_write_bytes(leaf, b"malicious", force=True)
            self.assertEqual(target.read_bytes(), b"original")

    def test_tar_extension_size_is_rejected_before_metadata_read(self):
        header = tarfile.TarInfo("pax")
        header.type = tarfile.XHDTYPE
        header.size = 1024 * 1024 + 1
        # No extension body is provided. The declared budget must win over
        # tarfile trying to read or parse attacker-controlled extension data.
        data = gzip.compress(header.tobuf(format=tarfile.USTAR_FORMAT))
        with self.assertRaisesRegex(converter.ConverterError, "metadata exceeds"):
            converter.validate_tar_archive(data)

    def test_tar_member_count_and_decompressed_stream_are_bounded(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for name in ("one", "two"):
                item = tarfile.TarInfo(name)
                archive.addfile(item)
        with (
            patch.object(converter, "MAX_ARCHIVE_ENTRIES", 1),
            self.assertRaisesRegex(converter.ConverterError, "entry limit"),
        ):
            converter.validate_tar_archive(stream.getvalue())
        bounded = converter.DecompressionBudget(io.BytesIO(b"1234"))
        bounded.limit = 3
        with self.assertRaisesRegex(converter.ConverterError, "byte budget"):
            bounded.read(4)

    @unittest.skipIf(os.name == "nt", "Symlink privileges differ on Windows")
    def test_extraction_root_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "target"
            target.mkdir()
            link = parent / "extract"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(converter.ConverterError):
                converter.extract_archive(b"", "tar.gz", link, force=True)

    def fixture_distributions(self, directory):
        version = "4.0.2"
        wheel = directory / f"ids_rule_converter-{version}-py3-none-any.whl"
        sdist = directory / f"ids_rule_converter-{version}.tar.gz"
        metadata = f"Metadata-Version: 2.4\nName: ids-rule-converter\nVersion: {version}\n".encode()
        entry = b"[console_scripts]\nids-rule-converter = snort_suricata_rule_converter:main\n"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(
                verify_distribution.MODULE, (ROOT / verify_distribution.MODULE).read_bytes()
            )
            for name in (
                "METADATA",
                "WHEEL",
                "RECORD",
                "entry_points.txt",
                "top_level.txt",
                "licenses/LICENSE",
            ):
                data = (
                    metadata
                    if name == "METADATA"
                    else entry
                    if name == "entry_points.txt"
                    else b"synthetic"
                )
                archive.writestr(f"ids_rule_converter-{version}.dist-info/{name}", data)
        reviewed = {verify_distribution.MODULE, "LICENSE", "README.md", "pyproject.toml"}
        reviewed.update(
            path.relative_to(ROOT).as_posix() for path in (ROOT / "tests").glob("test_*.py")
        )
        members = {name: (ROOT / name).read_bytes() for name in reviewed}
        members.update(
            {"PKG-INFO": metadata, "setup.cfg": b"[egg_info]\ntag_build = \ntag_date = 0\n"}
        )
        for name in (
            "PKG-INFO",
            "SOURCES.txt",
            "dependency_links.txt",
            "entry_points.txt",
            "top_level.txt",
        ):
            members[f"ids_rule_converter.egg-info/{name}"] = (
                metadata
                if name == "PKG-INFO"
                else entry
                if name == "entry_points.txt"
                else b"synthetic"
            )
        with tarfile.open(sdist, "w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(f"ids_rule_converter-{version}/{name}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return wheel, sdist

    def test_installation_active_extra_wheel_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel, _ = self.fixture_distributions(root)
            verify_distribution.verify_distribution(root, ROOT, "4.0.2")
            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr("startup.pth", "import malicious")
            with self.assertRaisesRegex(ValueError, "unreviewed installation members"):
                verify_distribution.verify_distribution(root, ROOT, "4.0.2")

    def test_installation_active_extra_sdist_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, sdist = self.fixture_distributions(root)
            with tarfile.open(sdist, "r:gz") as archive:
                members = [(member, archive.extractfile(member).read()) for member in archive]
            with tarfile.open(sdist, "w:gz") as archive:
                for member, data in members:
                    archive.addfile(member, io.BytesIO(data))
                extra = tarfile.TarInfo("ids_rule_converter-4.0.2/setup.py")
                archive.addfile(extra)
            with self.assertRaisesRegex(ValueError, "unreviewed installation members"):
                verify_distribution.verify_distribution(root, ROOT, "4.0.2")

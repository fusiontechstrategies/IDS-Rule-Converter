"""Synthetic adversarial cases for parser, output, archive, and distribution boundaries."""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
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
    def test_required_review_failure_cannot_leave_a_primary_ruleset(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, output, report, rejected = (
                parent / name for name in ("input", "output", "report", "rejected")
            )
            source.write_text(
                RULE
                + '\nalert tcp any any -> any 80 (http_header:field user-agent; content:"ua"; sid:1002;)',
                encoding="utf-8",
            )
            original = converter.atomic_write_text

            def write(path, text, force=False):
                if path == report:
                    raise converter.ConverterError("synthetic review publication failure")
                return original(path, text, force)

            with patch.object(converter, "atomic_write_text", side_effect=write):
                result = converter.main(
                    [
                        "convert",
                        str(source),
                        "--target",
                        "snort2",
                        "--source-dialect",
                        "snort3",
                        "--allow-partial",
                        "--output",
                        str(output),
                        "--report",
                        str(report),
                        "--rejected-output",
                        str(rejected),
                    ]
                )
            self.assertEqual(result, converter.EXIT_OPERATIONAL_ERROR)
            self.assertFalse(output.exists())

    def test_record_traversal_and_unreviewed_metadata_semantics_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unreviewed"):
            verify_distribution.validate_record({"RECORD": b"../../outside,,\n"}, "RECORD")
        import email

        metadata = email.message_from_string(
            "Metadata-Version: 2.4\nName: ids-rule-converter\nVersion: 4.0.2\n"
            "Requires-Python: <3.15,>=3.10\nDescription-Content-Type: text/markdown\n"
            "License-Expression: Apache-2.0\nLicense-File: LICENSE\nProvides-Extra: unreviewed\n"
        )
        with self.assertRaisesRegex(ValueError, "unreviewed installation semantics"):
            verify_distribution.validate_metadata(metadata)

    @unittest.skipIf(os.name == "nt", "POSIX link semantics")
    def test_intermediate_output_parent_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "target"
            target.mkdir()
            (parent / "link").symlink_to(target, target_is_directory=True)
            with self.assertRaises(converter.ConverterError):
                converter.atomic_write_bytes(parent / "link" / "nested" / "out", b"private")
            self.assertEqual(list(target.iterdir()), [])

    @unittest.skipUnless(os.name == "nt", "Windows directory sharing semantics")
    def test_windows_output_parent_is_locked_through_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "reports"
            parent.mkdir()
            original = converter.os.link

            def publish(source, destination):
                with self.assertRaises(PermissionError):
                    parent.rename(Path(directory) / "replaced")
                return original(source, destination)

            with patch.object(converter.os, "link", side_effect=publish):
                converter.atomic_write_bytes(parent / "out", b"synthetic")
            self.assertEqual((parent / "out").read_bytes(), b"synthetic")

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
        reordered = converter.RuleParser().parse_text(
            'alert tcp any any -> any 80 (content:"packet"; http_header:field user-agent; content:"ua"; sid:1001;)'
        )
        for dialect in ("auto", "snort2", "snort3"):
            converted = converter.convert_rules(
                reordered.rules, "snort2", strict=True, source_dialect=dialect
            )
            self.assertEqual(converted.rules, [], dialect)

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
        metadata = (
            f"Metadata-Version: 2.4\nName: ids-rule-converter\nVersion: {version}\nRequires-Python: <3.15,>=3.10\nDescription-Content-Type: text/markdown\nLicense-Expression: Apache-2.0\nLicense-File: LICENSE\n"
        ).encode()
        entry = b"[console_scripts]\nids-rule-converter = snort_suricata_rule_converter:main\n"
        prefix = f"ids_rule_converter-{version}.dist-info/"
        values = {
            verify_distribution.MODULE: (ROOT / verify_distribution.MODULE).read_bytes(),
            prefix + "METADATA": metadata,
            prefix
            + "WHEEL": b"Wheel-Version: 1.0\nGenerator: synthetic\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            prefix + "entry_points.txt": entry,
            prefix + "top_level.txt": b"snort_suricata_rule_converter\n",
            prefix + "licenses/LICENSE": (ROOT / "LICENSE").read_bytes(),
        }
        record = io.StringIO(newline="")
        writer = csv.writer(record)
        for name, data in values.items():
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            writer.writerow([name, "sha256=" + digest, len(data)])
        writer.writerow([prefix + "RECORD", "", ""])
        values[prefix + "RECORD"] = record.getvalue().encode()
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, data in values.items():
                archive.writestr(name, data)
        reviewed = {verify_distribution.MODULE, "LICENSE", "README.md", "pyproject.toml"}
        reviewed.update(
            path.relative_to(ROOT).as_posix() for path in (ROOT / "tests").glob("test_*.py")
        )
        members = {name: (ROOT / name).read_bytes() for name in reviewed}
        members.update(
            {"PKG-INFO": metadata, "setup.cfg": b"[egg_info]\ntag_build = \ntag_date = 0\n"}
        )
        generated = {
            "PKG-INFO": metadata,
            "dependency_links.txt": b"\n",
            "entry_points.txt": entry,
            "top_level.txt": b"snort_suricata_rule_converter\n",
        }
        for name, data in generated.items():
            members[f"ids_rule_converter.egg-info/{name}"] = data
        listed = (set(members) - {"PKG-INFO", "setup.cfg"}) | {
            "ids_rule_converter.egg-info/SOURCES.txt"
        }
        members["ids_rule_converter.egg-info/SOURCES.txt"] = "\n".join(sorted(listed)).encode()
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

"""Adversarial follow-ups for ambiguous semantics and bounded local processing."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import snort_suricata_rule_converter as converter

RULE = 'alert tcp any any -> any 80 (content:"test"; sid:1001;)'
AMBIGUOUS = 'alert tcp any any -> any 80 (content:"A"; http_header; content:"B"; sid:1001;)'


class ExtraHighBoundaries(unittest.TestCase):
    def test_worker_invalid_content_length_rejected_before_body_read(self):
        source_name = next(iter(converter.FEEDS))
        for header in (str(converter.MAX_DOWNLOAD_BYTES + 1), "9" * 10000, "not-a-number", "-1"):
            with self.subTest(header=header[:40]):
                response = MagicMock()
                response.__enter__.return_value = response
                response.geturl.return_value = converter.FEEDS[source_name]["url"]
                response.headers = {"Content-Length": header}
                opener = MagicMock()
                opener.open.return_value = response
                with (
                    patch.object(converter.urllib.request, "build_opener", return_value=opener),
                    self.assertRaises(converter.ConverterError),
                ):
                    converter._download_feed_in_worker(source_name)
                response.read.assert_not_called()

    def test_expanded_inline_modifiers_cannot_bypass_option_cap(self):
        modifiers = ",".join(["within 1"] * 300)
        text = f'alert tcp any any -> any 80 (content:"x",{modifiers}; msg:"x"; sid:1;)'
        with self.assertRaisesRegex(converter.ConverterError, "option budget"):
            converter.RuleParser().parse_text(text)

    def test_unknown_action_with_long_header_or_multiline_body_is_not_ignored(self):
        records = (
            "vendoraction tcp any any" + " " * 600 + '-> any any (msg:"x"; sid:1;)',
            'vendoraction tcp\n(msg:"x"; sid:1;)',
        )
        for record in records:
            with self.subTest(record=record):
                parsed = converter.RuleParser().parse_text(record)
                self.assertEqual(parsed.rules, [])
                self.assertTrue(parsed.errors)
                self.assertEqual(parsed.ignored_directives, 0)

    def test_conversion_and_panorama_diagnostic_fanout_abort(self):
        text = "\n".join(
            f'alert tcp any any -> any 80 (content:"test"; vendor_unknown:1; msg:"x"; sid:{index};)'
            for index in range(1, 6)
        )
        parsed = converter.RuleParser().parse_text(text)
        with patch.object(converter, "MAX_DIAGNOSTICS", 3):
            with self.assertRaisesRegex(converter.ConverterError, "Diagnostic budget"):
                converter.convert_rules(parsed.rules, "suricata")
            with self.assertRaisesRegex(converter.ConverterError, "Diagnostic budget"):
                converter.build_panorama_report(parsed)

    def test_all_numeric_identity_and_threshold_fields_are_bounded(self):
        for field in ("sid", "gid", "rev"):
            text = RULE.replace("sid:1001;", f"sid:1001; {field}:" + "9" * 10000 + ";")
            if field == "sid":
                text = RULE.replace("sid:1001", "sid:" + "9" * 10000)
            with self.subTest(field=field):
                parsed = converter.RuleParser().parse_text(text)
                self.assertEqual(parsed.rules, [])
                self.assertTrue(parsed.errors)
        parsed = converter.RuleParser().parse_text(
            RULE.replace(
                "sid:1001;",
                "threshold:type limit, track by_src, count "
                + "9" * 10000
                + ", seconds 1; sid:1001;",
            )
        )
        _, _, rejected, diagnostics = converter.build_panorama_report(parsed)
        self.assertEqual(len(rejected), 1)
        self.assertIn("PANORAMA_THRESHOLD_NOT_INTEGER", {item.code for item in diagnostics})

    def test_ambiguous_buffer_order_requires_explicit_source(self):
        parsed = converter.RuleParser().parse_text(AMBIGUOUS)
        for strict in (True, False):
            result = converter.convert_rules(parsed.rules, "suricata", strict=strict)
            self.assertEqual(result.rules, [])
            self.assertIn("AMBIGUOUS_SOURCE_DIALECT", {d.code for d in result.diagnostics})
        legacy = converter.convert_rules(parsed.rules, "suricata", source_dialect="snort2")
        sticky = converter.convert_rules(parsed.rules, "suricata", source_dialect="snort3")
        self.assertEqual(len(legacy.rules), 1)
        self.assertEqual(len(sticky.rules), 1)
        self.assertNotEqual(legacy.rules, sticky.rules)
        report, accepted, rejected, _ = converter.build_panorama_report(parsed)
        self.assertEqual(accepted, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn("AMBIGUOUS_SOURCE_DIALECT", str(report))
        self.assertIn(
            'content:"A"; http_header; content:"B";',
            converter.rule_to_dict(parsed.rules[0])["canonical_rule"],
        )

    def test_comment_stripping_memory_does_not_amplify_per_character(self):
        text = "x" * (2 * 1024 * 1024)
        tracemalloc.start()
        try:
            self.assertEqual(converter.strip_rule_comments(text), text)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, len(text) * 6)

    def test_diagnostic_fanout_is_a_fatal_budget(self):
        with (
            patch.object(converter, "MAX_DIAGNOSTICS", 4),
            self.assertRaisesRegex(converter.ConverterError, "diagnostic budget"),
        ):
            converter.RuleParser().parse_text("unsupported\n" * 5)

    def test_option_and_total_rule_budgets_fail_closed(self):
        with (
            patch.object(converter, "MAX_RULE_OPTIONS", 3),
            self.assertRaisesRegex(converter.ConverterError, "option budget"),
        ):
            converter.RuleParser().parse_text(
                RULE.replace("sid:1001;", 'sid:1001; rev:1; msg:"x";')
            )
        with (
            patch.object(converter, "MAX_TOTAL_OPTIONS", 3),
            self.assertRaisesRegex(converter.ConverterError, "total option budget"),
        ):
            converter.RuleParser().parse_text(RULE + "\n" + RULE)
        with (
            patch.object(converter, "MAX_PARSED_RULES", 1),
            self.assertRaisesRegex(converter.ConverterError, "rule count budget"),
        ):
            converter.RuleParser().parse_text(RULE + "\n" + RULE)

    def test_unknown_rule_action_prevents_strict_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "input", Path(directory) / "output"
            source.write_text(
                RULE + "\n" + RULE.replace("alert", "vendoraction", 1), encoding="utf-8"
            )
            with contextlib.redirect_stderr(io.StringIO()):
                result = converter.main(
                    ["convert", str(source), "--target", "suricata", "--output", str(output)]
                )
            self.assertNotEqual(result, 0)
            self.assertFalse(output.exists())

    def test_content_and_pcre_whitespace_remains_semantically_distinct(self):
        for option in ('content:"a b"', 'pcre:"/a b/"'):
            one = converter.RuleParser().parse_text(RULE.replace('content:"test"', option)).rules[0]
            two = (
                converter.RuleParser()
                .parse_text(RULE.replace('content:"test"', option.replace("a b", "a  b")))
                .rules[0]
            )
            self.assertNotEqual(
                converter.semantic_fingerprint(one), converter.semantic_fingerprint(two)
            )

    def test_implicit_archive_directories_count_against_object_budget(self):
        with (
            patch.object(converter, "MAX_ARCHIVE_ENTRIES", 4),
            self.assertRaisesRegex(converter.ConverterError, "object budget"),
        ):
            converter.check_archive_object_budget(["a/b/c.rules", "d/e/f.rules"])
        with self.assertRaises(converter.ConverterError):
            converter.safe_archive_name("/".join(["a"] * 33) + ".rules")

    def test_terminal_diagnostics_escape_control_characters(self):
        diagnostics = [
            converter.Diagnostic("warning", "TEST", "bad\x1b[2J\nforged", "source\rname", 1, 1)
        ]
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream):
            converter.print_diagnostics(diagnostics)
        value = stream.getvalue()
        self.assertNotIn("\x1b", value)
        self.assertNotIn("\r", value)
        self.assertEqual(value.count("\n"), 1)
        self.assertIn("\\u001b", value)

    def test_huge_within_is_reported_without_integer_conversion_crash(self):
        parsed = converter.RuleParser().parse_text(
            RULE.replace("sid:1001;", "within:" + "9" * 10000 + "; sid:1001;")
        )
        report, _, rejected, _ = converter.build_panorama_report(parsed)
        self.assertEqual(len(rejected), 1)
        self.assertIn("NOT_INTEGER", str(report))

    @unittest.skipUnless(os.name == "nt", "Windows ancestor handle sharing")
    def test_windows_mkdir_pins_existing_parent_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "parent"
            parent.mkdir()
            original = Path.mkdir
            checked = []

            def mkdir(path, *args, **kwargs):
                if path.name == "new":
                    with self.assertRaises(PermissionError):
                        parent.rename(Path(directory) / "moved")
                    checked.append(True)
                return original(path, *args, **kwargs)

            with patch.object(Path, "mkdir", mkdir):
                converter.ensure_output_directory(parent / "new" / "child")
            self.assertEqual(checked, [True])
            self.assertTrue((parent / "new" / "child").is_dir())

    @unittest.skipIf(os.name == "nt", "POSIX anchored mkdir")
    def test_posix_mkdir_race_never_creates_in_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent, moved, other = root / "parent", root / "moved", root / "other"
            parent.mkdir()
            other.mkdir()
            original = os.mkdir
            swapped = []

            def mkdir(path, *args, **kwargs):
                if path == "new" and not swapped:
                    parent.rename(moved)
                    parent.symlink_to(other, target_is_directory=True)
                    swapped.append(True)
                return original(path, *args, **kwargs)

            with patch.object(converter.os, "mkdir", mkdir):
                converter.ensure_output_directory(parent / "new" / "child")
            self.assertEqual(list(other.iterdir()), [])
            self.assertTrue((moved / "new" / "child").is_dir())
            with self.assertRaises(converter.ConverterError):
                converter.atomic_write_bytes(parent / "new" / "output", b"synthetic")

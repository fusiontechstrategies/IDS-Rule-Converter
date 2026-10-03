"""Adversarial public entrypoint controls for record and buffer association."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import snort_suricata_rule_converter as c

RULE = 'alert tcp any any -> any 80 (msg:"synthetic"; content:"test"; nocase; sid:1001; rev:1;)'


class FinalTwoGrammar(unittest.TestCase):
    def cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = c.main(argv)
        return status, out.getvalue(), err.getvalue()

    def test_same_line_option_directive_and_close_tails_are_fatal(self):
        for tail in (
            'content:"omitted";',
            'pcre:"/omitted/";',
            "flow:to_server;",
            "http_header;",
            "var HOME_NET any",
            ")",
            '); content:"omitted";',
        ):
            for prefix in (RULE, RULE + " " + RULE.replace("1001", "1002")):
                with self.subTest(tail=tail, prefix=prefix):
                    parsed = c.RuleParser().parse_text(prefix + " " + tail)
                    self.assertEqual(parsed.rules, [])
                    self.assertEqual([d.code for d in parsed.errors], ["TRAILING_RULE_TEXT"])
                    self.assertEqual(parsed.ignored_directives, 0)

    def test_separate_directives_comments_and_multiple_rules_remain_valid(self):
        for text in (
            "var HOME_NET any\n" + RULE,
            RULE + "\nvar HOME_NET any\n" + RULE.replace("1001", "1002"),
            RULE + " /* ordinary comment */ " + RULE.replace("1001", "1002"),
            RULE + "\n# disabled rule\n" + RULE.replace("1001", "1002"),
            RULE.replace('"synthetic"', '"parentheses ) and content: inside quotes"'),
        ):
            with self.subTest(text=text):
                parsed = c.RuleParser().parse_text(text)
                self.assertFalse(parsed.errors)
                self.assertGreaterEqual(len(parsed.rules), 1)
        unmatched = c.RuleParser().parse_text(")\n" + RULE)
        self.assertEqual(unmatched.errors[0].code, "UNMATCHED_CLOSING_PARENTHESIS")
        self.assertEqual([r.sid for r in unmatched.rules], [1001])

    def test_multiline_invalid_tail_discards_its_complete_prefix(self):
        parsed = c.RuleParser().parse_text(
            RULE.replace(" (", "\n(\n") + ' content:"outside";\n' + RULE.replace("1001", "1002")
        )
        self.assertEqual([r.sid for r in parsed.rules], [1002])
        self.assertEqual(parsed.errors[0].code, "TRAILING_RULE_TEXT")

    def test_public_cli_reports_failure_and_publishes_no_conversion_or_panorama(self):
        with tempfile.TemporaryDirectory() as directory:
            root = c.canonical_system_path(Path(directory).absolute())
            source, valid = root / "malformed.rules", root / "valid.rules"
            source.write_text(RULE + ' content:"outside";', encoding="utf-8")
            valid.write_text(RULE, encoding="utf-8")
            for command in ("validate", "analyze"):
                status, out, _ = self.cli([command, str(source)])
                self.assertEqual(status, c.EXIT_FINDINGS)
                if command == "analyze":
                    self.assertEqual(json.loads(out)["rule_count"], 0)
            status, out, _ = self.cli(["diff", str(valid), str(source)])
            self.assertEqual(status, c.EXIT_FINDINGS)
            self.assertEqual(json.loads(out)["summary"]["unchanged"], 0)
            for target, extra in (
                ("snort3", []),
                ("suricata", []),
                ("suricata", ["--allow-unverified"]),
                ("json", []),
            ):
                output = root / (target + ("-permissive" if extra else "") + ".out")
                status, _, _ = self.cli(
                    ["convert", str(source), "--target", target, "--output", str(output), *extra]
                )
                self.assertEqual(status, c.EXIT_FINDINGS)
                self.assertFalse(output.exists())
            output_dir = root / "panorama"
            status, _, _ = self.cli(
                ["panorama-preflight", str(source), "--output-dir", str(output_dir)]
            )
            self.assertEqual(status, c.EXIT_FINDINGS)
            self.assertFalse(output_dir.exists())

    def test_every_orphan_backward_buffer_is_rejected_by_both_public_apis(self):
        for buffer in sorted(set(c.LEGACY_TO_DOTTED_BUFFER) - {"file_data"}):
            for middle in ("flow:to_server;", "metadata:service http;", "", buffer + ";"):
                text = (
                    'alert tcp any any -> any 80 (content:"first"; '
                    + middle
                    + " "
                    + buffer
                    + '; content:"later"; sid:1001;)'
                )
                # Empty middle is a valid adjacent backward modifier, tested below.
                if not middle:
                    text = text.replace('content:"first"; ', "", 1)
                parsed = c.RuleParser().parse_text(text)
                self.assertFalse(parsed.errors)
                for target in ("snort3", "suricata"):
                    for strict in (True, False):
                        with self.subTest(
                            buffer=buffer, middle=middle, target=target, strict=strict
                        ):
                            converted = c.convert_rules(
                                parsed.rules, target, strict=strict, source_dialect="snort2"
                            )
                            self.assertEqual(converted.rules, [])
                            self.assertIn(
                                "AMBIGUOUS_LEGACY_BUFFER", [d.code for d in converted.errors]
                            )
                            with self.assertRaisesRegex(c.ConverterError, "Cannot associate"):
                                c.render_rule(parsed.rules[0], target, "snort2")

    def test_proven_adjacent_modifier_still_maps_and_restores_payload_buffer(self):
        parsed = c.RuleParser().parse_text(
            'alert tcp any any -> any 80 (content:"first"; nocase; http_header; '
            'content:"second"; sid:1001;)'
        )
        for target in ("snort3", "suricata"):
            result = c.convert_rules(parsed.rules, target, source_dialect="snort2")
            self.assertFalse(result.errors)
            self.assertEqual(len(result.rules), 1)
            self.assertIn('pkt_data; content:"second";', result.rules[0])
            self.assertIn('content:"first"', result.rules[0])

    def test_cli_explicit_snort2_rejects_orphan_even_with_allow_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = c.canonical_system_path(Path(directory).absolute())
            source = root / "orphan.rules"
            source.write_text(
                'alert tcp any any -> any 80 (content:"first"; flow:to_server; '
                'http_header; content:"later"; sid:1001;)',
                encoding="utf-8",
            )
            for extra in ([], ["--allow-unverified"]):
                output = root / ("permissive.rules" if extra else "strict.rules")
                status, _, err = self.cli(
                    [
                        "convert",
                        str(source),
                        "--target",
                        "suricata",
                        "--source-dialect",
                        "snort2",
                        "--output",
                        str(output),
                        *extra,
                    ]
                )
                self.assertEqual(status, c.EXIT_FINDINGS)
                self.assertIn("AMBIGUOUS_LEGACY_BUFFER", err)
                self.assertFalse(output.exists())

"""Source-aware backward HTTP associations and Panorama payload case controls."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import snort_suricata_rule_converter as c


def rule(options):
    parsed = c.RuleParser().parse_text(
        'alert tcp any any -> any 80 (msg:"synthetic"; ' + options + " sid:101; rev:1;)"
    )
    if parsed.errors:
        raise AssertionError(parsed.errors)
    return parsed.rules[0]


def forward_contexts(text):
    parsed = c.RuleParser().parse_text(text).rules[0]
    return [(p.value, b, n) for p, b, n in c.pattern_contexts(parsed)]


class BufferCaseSemantics(unittest.TestCase):
    def cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = c.main(argv)
        return status, out.getvalue(), err.getvalue()

    def test_legacy_suricata_maps_preceding_patterns_and_restores_payload(self):
        source = rule('content:"/admin"; http_uri; content:"Host"; http_header; content:"anchor";')
        for strict in (True, False):
            result = c.convert_rules([source], "snort3", strict=strict, source_dialect="suricata")
            self.assertFalse(result.errors)
            self.assertEqual(result.rules, [c.render_rule(source, "snort3", "suricata")])
            self.assertIn('http_uri; content:"/admin";', result.rules[0])
            self.assertIn('http_header; content:"Host";', result.rules[0])
            self.assertIn('pkt_data; content:"anchor";', result.rules[0])
        auto = c.convert_rules([source], "snort3")
        self.assertIn("AMBIGUOUS_SOURCE_DIALECT", [d.code for d in auto.errors])
        snort3 = c.render_rule(source, "snort3", "snort3")
        self.assertIn('content:"/admin"; http_uri; content:"Host";', snort3)
        # Explicit source choices have different meanings. Never infer a choice.
        self.assertNotEqual(snort3, c.render_rule(source, "snort3", "suricata"))

    def test_all_backward_http_modifiers_before_and_after_content_modifiers(self):
        for buffer in sorted(c.SURICATA_BACKWARD_BUFFERS):
            for modifiers in (f"nocase; {buffer};", f"{buffer}; nocase;"):
                source = rule(f'content:"first"; {modifiers} content:"second";')
                for strict in (True, False):
                    for dialect in ("suricata", "snort2"):
                        with self.subTest(
                            buffer=buffer, modifiers=modifiers, strict=strict, dialect=dialect
                        ):
                            result = c.convert_rules(
                                [source], "snort3", strict=strict, source_dialect=dialect
                            )
                            if buffer in c.UNMAPPED_SNORT_BUFFERS:
                                self.assertFalse(result.rules)
                                self.assertIn(
                                    "UNSUPPORTED_TARGET_BUFFER", [d.code for d in result.errors]
                                )
                                with self.assertRaises(c.ConverterError):
                                    c.render_rule(source, "snort3", dialect)
                                continue
                            self.assertFalse(result.errors)
                            self.assertIn(f'{buffer}; content:"first",nocase;', result.rules[0])
                            self.assertIn('pkt_data; content:"second";', result.rules[0])
                            self.assertEqual(
                                result.rules[0], c.render_rule(source, "snort3", dialect)
                            )
                            back = c.convert_rules(
                                [source], "snort2", strict=strict, source_dialect="suricata"
                            )
                            self.assertFalse(back.errors)
                            self.assertIn('content:"first";', back.rules[0])
                # One-shot backward contexts do not replace a sticky payload.
                mixed = rule(f'file.data; content:"first"; {modifiers} content:"second"; nocase;')
                self.assertEqual(
                    [(b, n) for _, b, n in c.pattern_contexts(mixed)],
                    [(buffer, True), ("file_data", True)],
                )

    def test_orphans_mixed_sticky_and_relative_operations_fail_closed(self):
        for buffer in sorted(c.SURICATA_BACKWARD_BUFFERS):
            for middle in ("flow:to_server;", "metadata:service http;", buffer + ";"):
                source = rule(f'content:"first"; {middle} {buffer}; content:"second";')
                for target in ("snort2", "snort3"):
                    for strict in (True, False):
                        result = c.convert_rules(
                            [source], target, strict=strict, source_dialect="suricata"
                        )
                        self.assertFalse(result.rules)
                        self.assertIn("AMBIGUOUS_LEGACY_BUFFER", [d.code for d in result.errors])
                        with self.assertRaises(c.ConverterError):
                            c.render_rule(source, target, "suricata")
            source = rule(f'{buffer}; content:"first";')
            self.assertFalse(c.convert_rules([source], "snort3", source_dialect="suricata").rules)
        for selector in (
            "http.uri",
            "file.data",
            "http_protocol",
            "http_header_names",
            "dns_query",
            "sip_header",
        ):
            source = rule(f'{selector}; content:"first"; http_header; content:"second";')
            for target in ("snort2", "snort3"):
                for strict in (True, False):
                    result = c.convert_rules(
                        [source], target, strict=strict, source_dialect="suricata"
                    )
                    self.assertFalse(result.rules)
                    self.assertIn("MIXED_SURICATA_BUFFER_FORMS", [d.code for d in result.errors])
                    with self.assertRaises(c.ConverterError):
                        c.render_rule(source, target, "suricata")
        for tail in (
            'content:"second"; distance:0;',
            'pcre:"/next/R";',
            "byte_test:1,=,1,0,relative;",
            "isdataat:1,relative;",
        ):
            for neutral in ("", "flow:to_server;", "metadata:service http;"):
                source = rule('content:"first"; http_uri; ' + neutral + tail)
                for strict in (True, False):
                    result = c.convert_rules(
                        [source], "snort3", strict=strict, source_dialect="suricata"
                    )
                    self.assertFalse(result.rules)
                    with self.assertRaises(c.ConverterError):
                        c.render_rule(source, "snort3", "suricata")

    def test_sticky_controls_and_same_buffer_relative_content_remain_valid(self):
        for selector in (
            "http.uri",
            "http.header",
            "file.data",
            "http_protocol",
            "http_header_names",
            "dns_query",
            "sip_header",
        ):
            source = rule(f'{selector}; content:"first"; content:"second"; distance:0;')
            result = c.convert_rules([source], "snort3", source_dialect="suricata")
            if selector in c.UNMAPPED_SNORT_BUFFERS:
                self.assertFalse(result.rules)
                self.assertIn("UNSUPPORTED_TARGET_BUFFER", [d.code for d in result.errors])
                continue
            self.assertFalse(result.errors)
            mapped = c.DOTTED_TO_LEGACY_BUFFER.get(selector, selector)
            self.assertIn(mapped + '; content:"first";', result.rules[0])
        source = rule('content:"first"; http_uri; content:"second"; distance:0; http_uri;')
        result = c.convert_rules([source], "snort3", source_dialect="suricata")
        self.assertFalse(result.errors)
        self.assertIn('content:"second",distance 0;', result.rules[0])
        # Supported forward selectors still become backward Snort2 modifiers.
        source = rule('http.uri; content:"HTTP";')
        result = c.convert_rules([source], "snort2", strict=False, source_dialect="suricata")
        self.assertFalse(result.errors)
        self.assertIn('content:"HTTP"; http_uri;', result.rules[0])

    def test_auto_mixed_forms_and_default_panorama_are_ambiguous(self):
        for selector in ("http_protocol", "http_header_names", "dns_query", "sip_header"):
            for neutral in ("", "flow:to_server;", "metadata:service http;"):
                source = rule(
                    f'{selector}; {neutral} content:"first"; http_header; content:"second"; nocase;'
                )
                self.assertEqual(c.infer_dialect(source), "ambiguous")
                for target in ("snort2", "snort3", "suricata"):
                    for strict in (True, False):
                        result = c.convert_rules([source], target, strict=strict)
                        self.assertFalse(result.rules)
                        self.assertIn("AMBIGUOUS_SOURCE_DIALECT", [d.code for d in result.errors])
                        with self.assertRaises(c.ConverterError):
                            c.render_rule(source, target)
                findings = c.panorama_option_checks(source)
                self.assertEqual([d.code for d in findings], ["AMBIGUOUS_SOURCE_DIALECT"])
                report, accepted, rejected, _ = c.build_panorama_report(
                    c.ParseResult(source="synthetic", rules=[source])
                )
                self.assertFalse(accepted)
                self.assertEqual(len(rejected), 1)
                self.assertEqual(report["accepted_rules"], 0)

    def test_unmapped_target_buffers_are_hard_errors_in_all_public_modes(self):
        for buffer in sorted(c.UNMAPPED_SNORT_BUFFERS):
            for spelling in (buffer, c.LEGACY_TO_DOTTED_BUFFER[buffer]):
                source = rule(f'{spelling}; content:"first";')
                for target in ("snort2", "snort3"):
                    for dialect in ("snort2", "snort3", "suricata"):
                        for strict in (True, False):
                            result = c.convert_rules(
                                [source], target, strict=strict, source_dialect=dialect
                            )
                            self.assertFalse(result.rules)
                            self.assertIn(
                                "UNSUPPORTED_TARGET_BUFFER", [d.code for d in result.errors]
                            )
                            with self.assertRaises(c.ConverterError):
                                c.render_rule(source, target, dialect)

    def test_file_data_case_and_packet_transitions_for_content_and_pcre(self):
        for protocol in ("tcp", "udp"):
            for neutral in ("", "flow:to_server;", "metadata:service http;"):
                for nocase in (False, True):
                    for pattern in (
                        'content:"payload"; ' + ("nocase;" if nocase else ""),
                        'pcre:"/payload/' + ("i" if nocase else "") + '";',
                    ):
                        source = rule("file_data; " + neutral + pattern)
                        source.protocol = protocol
                        contexts = c.pattern_contexts(source)
                        self.assertEqual([(b, n) for _, b, n in contexts], [("file_data", nocase)])
                        findings = c.panorama_option_checks(source)
                        errors = [d.code for d in findings if d.severity == "error"]
                        self.assertEqual("PANORAMA_CASE_SEMANTICS_CHANGED" in errors, nocase)
                        parsed = c.ParseResult(source="synthetic", rules=[source])
                        _, accepted, rejected, _ = c.build_panorama_report(parsed)
                        self.assertEqual(
                            len(accepted), 0 if nocase or pattern.startswith("pcre") else 1
                        )
                        self.assertEqual(
                            len(rejected), 1 if nocase or pattern.startswith("pcre") else 0
                        )
        source = rule('file_data; content:"file"; pkt_data; content:"packet"; nocase;')
        self.assertEqual(
            [(b, n) for _, b, n in c.pattern_contexts(source)],
            [("file_data", False), ("pkt_data", True)],
        )
        self.assertFalse(
            [
                d
                for d in c.panorama_option_checks(source)
                if d.code == "PANORAMA_CASE_SEMANTICS_CHANGED"
            ]
        )
        for selector in c.EXPLICIT_PAYLOAD_SELECTORS:
            source = rule(f'{selector}; content:"first"; pcre:"/second/";')
            self.assertEqual([b for _, b, _ in c.pattern_contexts(source)], [selector, selector])
        source = rule('file_data; pcre:"/header/Hi"; content:"file";')
        self.assertEqual(
            [(b, n) for _, b, n in c.pattern_contexts(source)],
            [("http_header", True), ("file_data", False)],
        )
        source = rule('file_data; content:"file",nocase;')
        self.assertEqual(c.infer_dialect(source), "snort3")
        self.assertIn(
            "PANORAMA_CASE_SEMANTICS_CHANGED", [d.code for d in c.panorama_option_checks(source)]
        )

    def test_cli_correct_conversion_and_rejected_mixed_has_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = c.canonical_system_path(Path(directory).absolute())
            source = root / "source.rules"
            for extra in ([], ["--allow-unverified"]):
                source.write_text(
                    rule(
                        'content:"/admin"; http_uri; content:"Host"; http_header; content:"anchor";'
                    ).raw
                )
                output = root / ("loose.rules" if extra else "strict.rules")
                status, _, err = self.cli(
                    [
                        "convert",
                        str(source),
                        "--target",
                        "snort3",
                        "--source-dialect",
                        "suricata",
                        "--output",
                        str(output),
                        *extra,
                    ]
                )
                self.assertEqual(status, 0, err)
                self.assertIn('pkt_data; content:"anchor";', output.read_text())
                mixed = root / ("mixed-loose.rules" if extra else "mixed-strict.rules")
                source.write_text(rule('http.uri; content:"first"; http_header;').raw)
                status, _, err = self.cli(
                    [
                        "convert",
                        str(source),
                        "--target",
                        "snort3",
                        "--source-dialect",
                        "suricata",
                        "--output",
                        str(mixed),
                        *extra,
                    ]
                )
                self.assertEqual(status, c.EXIT_FINDINGS)
                self.assertFalse(mixed.exists())
                self.assertIn("MIXED_SURICATA_BUFFER_FORMS", err)

    def test_panorama_publication_rejects_nocase_file_and_accepts_case_sensitive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = c.canonical_system_path(Path(directory).absolute())
            source = root / "source.rules"
            for nocase in (True, False):
                source.write_text(
                    rule('file_data; content:"payload"; ' + ("nocase;" if nocase else "")).raw
                )
                output = root / ("rejected" if nocase else "accepted")
                status, _, err = self.cli(
                    ["panorama-preflight", str(source), "--output-dir", str(output)]
                )
                self.assertEqual(status, c.EXIT_FINDINGS if nocase else 0, err)
                batches = list(output.glob("panorama_batch_*.rules"))
                self.assertEqual(len(batches), 0 if nocase else 1)
                if nocase:
                    self.assertIn("payload", (output / "panorama_rejected.rules").read_text())
                else:
                    self.assertIn("payload", batches[0].read_text())
                manifest = json.loads((output / "panorama_manifest.json").read_text())
                self.assertIsInstance(manifest, dict)

    def test_cli_auto_mixed_publishes_only_rejected_panorama_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = c.canonical_system_path(Path(directory).absolute())
            source = root / "source.rules"
            for selector in ("http_protocol", "http_header_names", "dns_query", "sip_header"):
                source.write_text(
                    rule(
                        f'{selector}; flow:to_server; content:"first"; http_header; content:"second"; nocase;'
                    ).raw
                )
                for target in ("snort2", "snort3"):
                    for extra in ([], ["--allow-unverified"]):
                        output = root / f"{selector}-{target}-{bool(extra)}.rules"
                        status, _, err = self.cli(
                            [
                                "convert",
                                str(source),
                                "--target",
                                target,
                                "--output",
                                str(output),
                                *extra,
                            ]
                        )
                        self.assertEqual(status, c.EXIT_FINDINGS)
                        self.assertFalse(output.exists())
                        self.assertIn("AMBIGUOUS_SOURCE_DIALECT", err)
                output = root / (selector + "-panorama")
                status, _, err = self.cli(
                    ["panorama-preflight", str(source), "--output-dir", str(output)]
                )
                self.assertEqual(status, c.EXIT_FINDINGS, err)
                self.assertFalse(list(output.glob("panorama_batch_*.rules")))
                self.assertIn(selector, (output / "panorama_rejected.rules").read_text())
                self.assertTrue((output / "panorama_manifest.json").is_file())

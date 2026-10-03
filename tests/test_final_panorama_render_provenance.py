"""Alias parity and complete-parse admission at public output boundaries."""

import copy
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import snort_suricata_rule_converter as app

RULE = 'alert tcp any any -> any any (msg:"boundary"; content:"marker"; sid:1001;)'


class PanoramaRenderProvenance(unittest.TestCase):
    def test_all_buffer_alias_pairs_have_identical_panorama_disposition(self):
        for legacy, dotted in app.LEGACY_TO_DOTTED_BUFFER.items():
            dispositions = []
            for spelling in (legacy, dotted, legacy.upper(), dotted.upper()):
                parsed = app.RuleParser().parse_text(
                    RULE.replace("content:", spelling + "; content:")
                )
                self.assertFalse(parsed.errors)
                report, accepted, rejected, diagnostics = app.build_panorama_report(parsed)
                dispositions.append(
                    (len(accepted), len(rejected), [(x.severity, x.code) for x in diagnostics])
                )
                with self.subTest(spelling=spelling):
                    if "raw" in legacy:
                        self.assertFalse(accepted)
                        self.assertEqual(len(rejected), 1)
                        self.assertIn("PANORAMA_MODIFIER_UNSUPPORTED", str(report))
            with self.subTest(legacy=legacy, dotted=dotted):
                self.assertTrue(all(x == dispositions[0] for x in dispositions))

    def test_supported_normalized_http_buffers_remain_accepted(self):
        for key in ("http_uri", "http.uri", "http_header", "http.header"):
            text = (
                RULE.replace("content:", key + "; content:")
                .replace('content:"marker";', 'content:"marker"; nocase;')
                .replace('msg:"boundary";', 'msg:"boundary"; flow:to_server;')
            )
            parsed = app.RuleParser().parse_text(text)
            _, accepted, rejected, _ = app.build_panorama_report(parsed)
            with self.subTest(key=key):
                self.assertEqual(len(accepted), 1)
                self.assertFalse(rejected)

    def test_direct_outputs_refuse_prefix_from_malformed_suffix(self):
        for suffix in (
            "\nalert tcp any any -> any any (",
            "\nalert tcp any any -> any any (sid:garbage;)",
        ):
            parsed = app.RuleParser().parse_text(RULE + suffix)
            self.assertTrue(parsed.errors)
            self.assertEqual(len(parsed.rules), 1)
            for rule in (
                parsed.rules[0],
                copy.copy(parsed.rules[0]),
                copy.deepcopy(parsed.rules[0]),
            ):
                for ack in (False, True):
                    for target in ("snort2", "snort3", "suricata", "ambiguous"):
                        with (
                            self.subTest(suffix=suffix, target=target, ack=ack),
                            self.assertRaisesRegex(app.ConverterError, "Complete parse"),
                        ):
                            app.render_rule(rule, target, allow_detached_rules=ack)
                    with self.assertRaisesRegex(app.ConverterError, "Complete parse"):
                        app.rule_to_dict(rule, allow_detached_rules=ack)

    def test_clearing_public_diagnostics_never_permits_prefix_output(self):
        parsed = app.RuleParser().parse_text(RULE + "\nalert tcp any any -> any any (")
        parsed.diagnostics.clear()
        self.assertFalse(parsed.errors)
        with self.assertRaises(app.ConverterError):
            app.render_rule(parsed.rules[0], "suricata")
        with self.assertRaises(app.ConverterError):
            app.rule_to_dict(parsed.rules[0])
        report, accepted, rejected, diagnostics = app.build_panorama_report(parsed)
        self.assertFalse(accepted)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(report["accepted_rules"], 0)
        self.assertTrue(any(x.severity == "error" for x in diagnostics))
        self.assertIn("INCOMPLETE_PARSE", str(report))

    def test_valid_complete_parse_direct_and_batch_outputs_still_work(self):
        parsed = app.RuleParser().parse_text(RULE)
        for target in ("snort2", "snort3", "suricata"):
            text = app.render_rule(parsed.rules[0], target, "snort3")
            result = app.convert_rules(parsed, target, source_dialect="snort3")
            with self.subTest(target=target):
                self.assertFalse(result.errors)
                self.assertEqual(result.rules, [text])
        self.assertIn('content:"marker";', app.rule_to_dict(parsed.rules[0])["canonical_rule"])

    def test_manual_direct_and_batch_outputs_require_same_explicit_acknowledgement(self):
        manual = replace(app.RuleParser().parse_text(RULE).rules[0])
        self.assertIsNone(manual._parse_diagnostics)
        with self.assertRaises(app.ConverterError):
            app.render_rule(manual, "suricata", "snort3")
        with self.assertRaises(app.ConverterError):
            app.rule_to_dict(manual)
        text = app.render_rule(manual, "suricata", "snort3", allow_detached_rules=True)
        result = app.convert_rules(
            [manual], "suricata", source_dialect="snort3", allow_detached_rules=True
        )
        self.assertEqual(result.rules, [text])
        self.assertEqual(len(result.diagnostics), 1)
        self.assertEqual(result.diagnostics[0].severity, "warning")
        self.assertIn(
            "marker", app.rule_to_dict(manual, allow_detached_rules=True)["canonical_rule"]
        )
        manual.options.append(app.RuleOption("service", "unsupported-service", "service"))
        with self.assertRaises(app.ConverterError):
            app.render_rule(manual, "suricata", "snort3", allow_detached_rules=True)

    def test_ambiguous_canonical_serialization_still_preserves_source(self):
        parsed = app.RuleParser().parse_text(
            RULE.replace('content:"marker";', 'content:"first"; http_header; content:"second";')
        )
        self.assertEqual(app.infer_dialect(parsed.rules[0]), "ambiguous")
        self.assertIn("http_header;", app.rule_to_dict(parsed.rules[0])["canonical_rule"])
        parsed = app.RuleParser().parse_text(
            parsed.rules[0].raw + "\nalert tcp any any -> any any ("
        )
        with self.assertRaises(app.ConverterError):
            app.rule_to_dict(parsed.rules[0])

    def test_diagnostic_budget_applies_before_any_direct_serialization(self):
        parsed = app.RuleParser().parse_text(RULE.replace('msg:"boundary"; ', ""))
        self.assertTrue(parsed.diagnostics)
        with patch.object(app, "MAX_DIAGNOSTICS", 0):
            with self.assertRaisesRegex(app.ConverterError, "Diagnostic budget"):
                app.render_rule(parsed.rules[0], "suricata")
            with self.assertRaisesRegex(app.ConverterError, "Diagnostic budget"):
                app.rule_to_dict(parsed.rules[0])
            with self.assertRaisesRegex(app.ConverterError, "Diagnostic budget"):
                app.build_panorama_report(parsed)

    def test_complete_context_diagnostic_work_is_linear_for_batch_and_direct_json(self):
        original_hash = app.Diagnostic.__hash__
        for operation in ("batch", "direct_json"):
            counts = []
            for size in (80, 160):
                text = "\n".join(
                    ["var LOCAL_PORTS 80"] * size
                    + [RULE.replace("1001", str(sid)) for sid in range(1, size + 1)]
                )
                hash_calls = 0

                def counted(diagnostic):
                    nonlocal hash_calls
                    hash_calls += 1
                    return original_hash(diagnostic)

                with patch.object(app.Diagnostic, "__hash__", counted):
                    parsed = app.RuleParser().parse_text(text)
                    self.assertFalse(parsed.errors)
                    self.assertEqual(len(parsed.diagnostics), size)
                    if operation == "batch":
                        result = app.convert_rules(parsed, "suricata", source_dialect="snort3")
                        self.assertFalse(result.errors)
                        self.assertEqual(len(result.rules), size)
                    else:
                        result = [app.rule_to_dict(rule) for rule in parsed.rules]
                        self.assertEqual(len(result), size)
                with self.subTest(operation=operation, size=size):
                    # Count actual diagnostic hashing, including parser summary creation.
                    # The old per-rule scan required 2*size**2 + 3*size hashes.
                    self.assertLessEqual(hash_calls, 5 * size)
                counts.append(hash_calls)
            self.assertEqual(counts[1], 2 * counts[0])

    def test_shared_parse_summary_is_immutable_and_copy_safe(self):
        from dataclasses import FrozenInstanceError

        parsed = app.RuleParser().parse_text(RULE + "\nalert tcp any any -> any any (")
        context = parsed.rules[0]._parse_context
        self.assertIs(context, parsed._parse_context)
        self.assertTrue(context.has_errors)
        with self.assertRaises(FrozenInstanceError):
            context.has_errors = False
        with self.assertRaises(FrozenInstanceError):
            context.diagnostics = ()
        for rule in (copy.copy(parsed.rules[0]), copy.deepcopy(parsed.rules[0])):
            with self.assertRaises(app.ConverterError):
                app.rule_to_dict(rule, allow_detached_rules=True)

    def test_actual_panorama_cli_never_emits_dotted_raw_selector_in_accepted_batch(self):
        for legacy, dotted in app.LEGACY_TO_DOTTED_BUFFER.items():
            if "raw" not in legacy:
                continue
            for spelling in (legacy, dotted):
                with self.subTest(spelling=spelling), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / "input.rules"
                    source.write_text(RULE.replace("content:", spelling + "; content:"))
                    dest = root / "reports"
                    code = app.main(["panorama-preflight", str(source), "--output-dir", str(dest)])
                    self.assertEqual(code, 2)
                    self.assertFalse(list(dest.glob("panorama_batch_*.rules")))
                    rejected = dest / "panorama_rejected.rules"
                    self.assertTrue(rejected.exists())
                    self.assertIn(spelling, rejected.read_text())

    def test_actual_panorama_cli_mixed_batch_contains_only_supported_rule(self):
        good = RULE.replace("content:", "http.uri; content:").replace(
            'content:"marker";', 'content:"marker"; nocase;'
        )
        rules = [good]
        for sid, key in enumerate(("http.header.raw", "http.host.raw", "http.uri.raw"), 1002):
            rules.append(RULE.replace("content:", key + "; content:").replace("1001", str(sid)))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.rules"
            source.write_text("\n".join(rules))
            dest = root / "reports"
            self.assertEqual(
                app.main(["panorama-preflight", str(source), "--output-dir", str(dest)]), 2
            )
            batches = list(dest.glob("panorama_batch_*.rules"))
            self.assertEqual(len(batches), 1)
            self.assertEqual(batches[0].read_text().strip(), good)
            self.assertNotIn(".raw;", batches[0].read_text())


if __name__ == "__main__":
    unittest.main()

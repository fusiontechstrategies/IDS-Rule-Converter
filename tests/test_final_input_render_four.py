"""Safe functional admission and format controls, with no reproduction demonstrations."""

import ctypes
import hashlib
import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import snort_suricata_rule_converter as app

RULE = 'alert tcp any any -> any any (msg:"ordinary"; content:"abcdef"; sid:1001;)'


class InputRenderFour(unittest.TestCase):
    def test_ordinary_file_keeps_lexical_path_and_exact_byte_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / "ordinary.rules"
            raw = b"\xef\xbb\xbf" + RULE.encode()
            source.write_bytes(raw)
            with patch.object(Path, "resolve", side_effect=AssertionError("Unpinned lookup")):
                parsed = app.RuleParser().parse_file(source)
            self.assertEqual(parsed.input_identity.path, source)
            self.assertEqual(parsed.source_sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(parsed.byte_count, len(raw))
            self.assertEqual(parsed.rules[0].sid, 1001)
            self.assertEqual(app.read_utf8(source), (RULE, len(raw)))

    def test_ordinary_file_all_commands_preserve_valid_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "ordinary.rules"
            source.write_text(RULE, encoding="utf-8")
            self.assertEqual(app.main(["validate", str(source)]), app.EXIT_OK)
            self.assertEqual(
                app.main(["analyze", str(source), "--output", str(root / "analysis.json")]),
                app.EXIT_OK,
            )
            self.assertEqual(
                app.main(
                    [
                        "convert",
                        str(source),
                        "--target",
                        "suricata",
                        "--output",
                        str(root / "converted.rules"),
                    ]
                ),
                app.EXIT_OK,
            )
            self.assertEqual(
                app.main(
                    [
                        "convert",
                        str(source),
                        "--target",
                        "json",
                        "--output",
                        str(root / "rules.json"),
                    ]
                ),
                app.EXIT_OK,
            )
            document = json.loads((root / "rules.json").read_text())
            self.assertEqual(document["source_sha256"], hashlib.sha256(RULE.encode()).hexdigest())

    def test_parent_traversal_and_directory_input_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "ordinary.rules"
            source.write_text(RULE, encoding="utf-8")
            for path in (root, root / "unused" / ".." / source.name):
                with self.subTest(path=path), self.assertRaises(app.ConverterError):
                    app.RuleParser().parse_file(path)

    @unittest.skipUnless(os.name == "nt", "Native Windows short names")
    def test_actual_short_path_is_a_valid_retained_input(self):
        with tempfile.TemporaryDirectory(prefix="ids-ordinary-long-input-") as directory:
            source = Path(directory).resolve() / "ordinary-long-input.rules"
            source.write_text(RULE, encoding="utf-8")
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetShortPathNameW.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_uint32,
            ]
            kernel.GetShortPathNameW.restype = ctypes.c_uint32
            buffer = ctypes.create_unicode_buffer(32768)
            result = kernel.GetShortPathNameW(str(source), buffer, len(buffer))
            if not result or result >= len(buffer) or buffer.value == str(source):
                self.skipTest("8.3 alias unavailable; no host settings changed")
            alias = Path(buffer.value)
            parsed = app.RuleParser().parse_file(alias)
            self.assertEqual(parsed.input_identity.path, alias)
            self.assertEqual(parsed.rules[0].sid, 1001)
            self.assertTrue(os.path.samefile(alias, source))

    def test_auto_and_default_dialects_have_identical_disposition(self):
        parser = app.RuleParser()
        ordinary = parser.parse_text(RULE).rules[0]
        ambiguous = parser.parse_text(
            RULE.replace('content:"abcdef";', 'content:"one"; http_uri; content:"two";')
        ).rules[0]
        for target in ("snort2", "snort3", "suricata"):
            self.assertEqual(
                app.render_rule(ordinary, target), app.render_rule(ordinary, target, "auto")
            )
            for dialect in (None, "auto", " AUTO "):
                with (
                    self.subTest(target=target, dialect=dialect),
                    self.assertRaises(app.ConverterError),
                ):
                    app.render_rule(ambiguous, target, dialect)
            self.assertTrue(app.convert_rules([ambiguous], target, source_dialect="auto").errors)
            for dialect in ("snort2", "snort3"):
                output = app.convert_rules([ambiguous], target, source_dialect=dialect)
                self.assertFalse(output.errors)
                self.assertEqual(app.render_rule(ambiguous, target, dialect), output.rules[0])
        self.assertEqual(app.rule_to_dict(ambiguous)["dialect_hint"], "ambiguous")

    def test_unknown_source_dialects_refuse_before_transformation(self):
        parsed = app.RuleParser().parse_text(RULE)
        for dialect in ("unknown", "", "ambiguous", 0):
            for method in (
                lambda dialect=dialect: app.render_rule(parsed.rules[0], "suricata", dialect),
                lambda dialect=dialect: app.convert_rules(
                    parsed, "suricata", source_dialect=dialect
                ),
                lambda dialect=dialect: app.compatibility_diagnostics(
                    parsed.rules[0], "suricata", False, dialect
                ),
                lambda dialect=dialect: app.transform_to_suricata(
                    parsed.rules[0].options, dialect, "tcp"
                ),
                lambda dialect=dialect: app.transform_to_snort3(parsed.rules[0].options, dialect),
                lambda dialect=dialect: app.transform_sticky_to_snort2(
                    parsed.rules[0].options, dialect
                ),
                lambda dialect=dialect: app.normalized_fast_pattern_options(
                    parsed.rules[0].options, dialect
                ),
            ):
                with self.subTest(dialect=dialect), self.assertRaises(app.ConverterError):
                    method()

    def test_full_and_pair_only_fast_pattern_groups_emit_one_marker_and_round_trip(self):
        for marker in ("fast_pattern,", ""):
            text = RULE.replace(
                'content:"abcdef";',
                f'content:"abcdef",{marker}fast_pattern_offset 1,fast_pattern_length 4;',
            )
            parsed = app.RuleParser().parse_text(text)
            self.assertFalse(parsed.errors)
            result = app.convert_rules(parsed, "suricata", source_dialect="snort3")
            self.assertFalse(result.errors)
            output = result.rules[0]
            self.assertEqual(output.count("fast_pattern"), 1)
            self.assertIn("fast_pattern:1,4;", output)
            self.assertEqual(output, app.render_rule(parsed.rules[0], "suricata", "snort3"))
            target = app.RuleParser().parse_text(output)
            returned = app.convert_rules(target, "snort3", source_dialect="suricata")
            self.assertFalse(returned.errors)
            self.assertIn("fast_pattern_offset 1,fast_pattern_length 4;", returned.rules[0])
            self.assertEqual(
                app.convert_rules(
                    app.RuleParser().parse_text(returned.rules[0]),
                    "suricata",
                    source_dialect="snort3",
                ).rules,
                [output],
            )

    def test_invalid_fast_pattern_groups_and_bounds_refuse(self):
        invalid = [
            "fast_pattern_offset:1; fast_pattern_length:4;",
            'content:"abcdef"; fast_pattern_offset:1;',
            'content:"abcdef"; fast_pattern_length:4;',
            'content:"abcdef"; fast_pattern; fast_pattern; fast_pattern_offset:1; fast_pattern_length:4;',
            'content:"abcdef"; fast_pattern:only; fast_pattern_offset:1; fast_pattern_length:4;',
            'content:"abcdef"; fast_pattern_offset:1; fast_pattern_length:0;',
            'content:"abcdef"; fast_pattern_offset:65536; fast_pattern_length:1;',
            'content:"abcdef"; fast_pattern_offset:0; fast_pattern_length:65536;',
            'content:"abcdef"; fast_pattern_offset:5; fast_pattern_length:2;',
            'content:"abcdef"; fast_pattern_offset:1; nocase; fast_pattern_length:2;',
        ]
        for options in invalid:
            parsed = app.RuleParser().parse_text(
                f"alert tcp any any -> any any ({options} sid:1001;)"
            )
            self.assertFalse(parsed.errors)
            with self.subTest(options=options):
                self.assertTrue(
                    app.convert_rules(parsed, "suricata", source_dialect="snort3").errors
                )
                with self.assertRaises(app.ConverterError):
                    app.render_rule(parsed.rules[0], "suricata", "snort3")

    def test_hex_content_and_small_boundaries_are_valid(self):
        text = RULE.replace(
            'content:"abcdef";',
            'content:"a|62 63|def",fast_pattern_offset 0,fast_pattern_length 6;',
        )
        self.assertIn(
            "fast_pattern:0,6;",
            app.render_rule(app.RuleParser().parse_text(text).rules[0], "suricata", "snort3"),
        )

    def test_text_NUL_admission_is_before_hashing_and_manual_outputs_refuse(self):
        for text in (
            RULE.replace("tcp", "t\x00cp"),
            RULE.replace("abcdef", "ab\x00cd"),
            RULE.replace("ordinary", "ord\x00inary"),
            "# comment\x00\n" + RULE,
        ):
            with (
                patch.object(
                    app.hashlib, "sha256", side_effect=AssertionError("Hash before admission")
                ),
                self.assertRaises(app.ConverterError),
            ):
                app.RuleParser().parse_text(text)
        manual = replace(
            app.RuleParser().parse_text(RULE).rules[0],
            options=[app.RuleOption("content", '"a\x00b"', "manual")],
        )
        for method in (
            lambda: app.render_rule(manual, "suricata", allow_detached_rules=True),
            lambda: app.rule_to_dict(manual, allow_detached_rules=True),
            lambda: app.convert_rules([manual], "suricata", allow_detached_rules=True),
            lambda: app.panorama_option_checks(manual),
            lambda: manual.options[0].rendered(),
        ):
            with self.assertRaises(app.ConverterError):
                method()
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(app.ConverterError):
            app.atomic_write_text(Path(directory) / "output.rules", "text\x00")

    def test_external_byte_count_cannot_weaken_UTF8_budget(self):
        with patch.object(app, "MAX_INPUT_BYTES", 4), self.assertRaises(app.ConverterError):
            app.RuleParser().parse_text("ééé", byte_count=1)

    def test_hex_NUL_and_unicode_text_are_ordinary_valid_rule_syntax(self):
        text = RULE.replace("abcdef", "|00|a").replace("ordinary", "ordinaryé")
        parsed = app.RuleParser().parse_text(text)
        self.assertFalse(parsed.errors)
        self.assertIn('content:"|00|a";', app.render_rule(parsed.rules[0], "suricata"))
        self.assertNotIn("\x00", app.rule_to_dict(parsed.rules[0])["canonical_rule"])

    def test_stream_construction_failure_closes_actual_leaf_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / "ordinary.rules"
            source.write_text(RULE, encoding="utf-8")
            opened = []
            real_open = app._open_input_leaf

            def tracked(path, parent):
                descriptor = real_open(path, parent)
                opened.append(descriptor)
                return descriptor

            with (
                patch.object(app, "_open_input_leaf", tracked),
                patch.object(os, "fdopen", side_effect=OSError("Fixture constructor refused")),
                self.assertRaises(app.ConverterError),
            ):
                app.read_input(source)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])

    def test_stream_processing_failure_closes_actual_descriptor_exactly_once(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / "ordinary.rules"
            source.write_text(RULE, encoding="utf-8")
            real_close = os.close
            with app.input_parent_namespace(source) as (requested, parent):
                with patch.object(os, "close", wraps=real_close) as close:
                    opened = []

                    def processing_failure():
                        with app._input_binary_stream(requested, parent) as stream:
                            opened.append(stream.fileno())
                            self.assertEqual(stream.read(), RULE.encode())
                            raise RuntimeError("Fixture processing refused")

                    self.assertRaisesRegex(
                        RuntimeError, "Fixture processing refused", processing_failure
                    )
                    self.assertEqual(len(opened), 1)
                    descriptor = opened[0]
                    close.assert_called_once_with(descriptor)
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    @unittest.skipIf(os.name == "nt", "POSIX descriptors; native Windows leaf cases execute")
    def test_byte_budget_refusal_closes_all_actual_retained_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / "ordinary.rules"
            source.write_text(RULE, encoding="utf-8")
            retained = []
            original = app._input_directory_descriptor

            @contextmanager
            def tracked(*args, **kwargs):
                with original(*args, **kwargs) as owner:
                    retained.append(owner.fileno())
                    yield owner

            with (
                patch.object(app, "_input_directory_descriptor", tracked),
                self.assertRaises(app.ConverterError),
            ):
                app.read_input(source, max_bytes=1)
            self.assertGreaterEqual(len(retained), 2)
            for descriptor in retained:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    @unittest.skipIf(os.name == "nt", "POSIX retained directory capability")
    def test_directory_capability_refuses_after_close_and_closes_exactly_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            real_close = os.close
            with patch.object(os, "close", wraps=real_close) as close:
                with app._input_directory_descriptor(str(root), flags) as owner:
                    descriptor = owner.fileno()
                    self.assertTrue(app.stat.S_ISDIR(os.fstat(descriptor).st_mode))
                    owner.close()
                    with self.assertRaises(app.ConverterError):
                        owner.fileno()
                close.assert_called_once_with(descriptor)
            with self.assertRaises(OSError):
                os.fstat(descriptor)


if __name__ == "__main__":
    unittest.main()

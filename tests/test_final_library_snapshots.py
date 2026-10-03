"""Public library failure paths, actual Windows sharing and retained input provenance."""

import copy
import hashlib
import io
import json
import mmap
import os
import tarfile
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import snort_suricata_rule_converter as app

RULE = 'alert tcp any any -> any any (msg:"snapshot"; content:"marker"; sid:1001; rev:1;)'


class LibrarySnapshots(unittest.TestCase):
    def test_direct_mapping_never_drops_unmapped_constraints(self):
        cases = [
            ("service", None),
            ("service", "unknown-service"),
            ("service", "http,ftp"),
            ("stream_size", None),
            ("stream_size", "1<>3"),
            ("tag", None),
            ("tag", "session,garbage"),
            ("fast_pattern_offset", None),
            ("fast_pattern_offset", "1"),
            ("fast_pattern_length", "2"),
        ]
        for dialect in ("snort2", "snort3"):
            for key, value in cases:
                with self.subTest(dialect=dialect, key=key, value=value):
                    option = app.RuleOption(key, value, key)
                    with self.assertRaises(app.ConverterError):
                        app.transform_to_suricata([option], dialect, "tcp")

    def test_direct_mapper_positive_controls_preserve_constraints(self):
        options = [
            app.RuleOption(k, v, k)
            for k, v in (
                ("service", "http"),
                ("stream_size", ">3,to_server"),
                ("tag", "session,packets 2"),
                ("fast_pattern_offset", "1"),
                ("fast_pattern_length", "2"),
            )
        ]
        result = app.transform_to_suricata(options, "snort3", "tcp")
        self.assertEqual(
            [(x.key, x.value) for x in result],
            [
                ("app-layer-protocol", "http"),
                ("stream_size", "client,>,3"),
                ("tag", "session,2,packets"),
                ("fast_pattern", "1,2"),
            ],
        )

    def test_invalid_fast_pattern_pair_refuses_direct_mapping(self):
        for first, second in (("x", "2"), ("1", "-2"), ("1", "Â²"), ("1", None)):
            with self.subTest(first=first, second=second), self.assertRaises(app.ConverterError):
                app.transform_to_suricata(
                    [
                        app.RuleOption("fast_pattern_offset", first, "offset"),
                        app.RuleOption("fast_pattern_length", second, "length"),
                    ],
                    "snort3",
                    "tcp",
                )

    def test_complete_parse_context_survives_every_common_library_composition(self):
        bad = app.RuleParser().parse_text(
            RULE + '\nalert tcp any any -> any any (content:"unfinished";'
        )
        self.assertEqual(len(bad.rules), 1)
        self.assertTrue(bad.errors)
        for source in (
            bad,
            bad.rules,
            bad.rules[:],
            tuple(bad.rules),
            [copy.copy(bad.rules[0])],
            copy.deepcopy(bad.rules),
        ):
            for target in ("snort2", "snort3", "suricata"):
                for strict in (True, False):
                    with self.subTest(source=type(source).__name__, target=target, strict=strict):
                        result = app.convert_rules(source, target, strict, "snort3")
                        self.assertFalse(result.rules)
                        self.assertTrue(result.errors)
                        self.assertEqual(result.rejected_rule_indexes, [1])

    def test_known_parse_failure_cannot_be_acknowledged_or_cleared_away(self):
        parsed = app.RuleParser().parse_text(
            RULE + '\nalert tcp any any -> any any (content:"unfinished";'
        )
        parsed.diagnostics.clear()
        for source in (parsed, parsed.rules):
            result = app.convert_rules(source, "suricata", allow_detached_rules=True)
            self.assertTrue(result.errors)
            self.assertFalse(result.rules)

    def test_mixed_parse_origins_refuse_entire_batch_on_one_failed_origin(self):
        good = app.RuleParser().parse_text(RULE)
        bad = app.RuleParser().parse_text(
            RULE.replace("1001", "1002") + "\nalert tcp any any -> any any ("
        )
        result = app.convert_rules(good.rules + bad.rules, "suricata", source_dialect="snort3")
        self.assertFalse(result.rules)
        self.assertTrue(result.errors)

    def test_manual_rule_requires_explicit_acknowledgement_and_still_checks_semantics(self):
        parsed = app.RuleParser().parse_text(RULE)
        manual = replace(parsed.rules[0])
        refused = app.convert_rules([manual], "suricata", source_dialect="snort3")
        self.assertFalse(refused.rules)
        self.assertEqual(refused.errors[0].code, "DETACHED_RULE_PROVENANCE")
        accepted = app.convert_rules(
            [manual], "suricata", source_dialect="snort3", allow_detached_rules=True
        )
        self.assertEqual(len(accepted.rules), 1)
        self.assertFalse(accepted.errors)
        self.assertEqual(accepted.diagnostics[0].severity, "warning")
        manual.options.append(app.RuleOption("service", "unknown-service", "service"))
        rejected = app.convert_rules(
            [manual], "suricata", strict=False, source_dialect="snort3", allow_detached_rules=True
        )
        self.assertFalse(rejected.rules)
        self.assertTrue(rejected.errors)

    def test_no_rule_parse_failure_and_unproven_parse_result_are_refused(self):
        for text in ('alert tcp any any -> any any (content:"unfinished";', "/* unfinished"):
            failed = app.RuleParser().parse_text(text)
            self.assertTrue(failed.errors)
            failed.diagnostics.clear()
            for source in (failed, copy.deepcopy(failed), failed.rules[:], tuple(failed.rules)):
                for allow_detached in (False, True):
                    with self.subTest(text=text, source=type(source).__name__, ack=allow_detached):
                        result = app.convert_rules(
                            source, "suricata", allow_detached_rules=allow_detached
                        )
                        self.assertTrue(result.errors)
                        self.assertFalse(result.rules)
        for text in ("", "# no rules\n"):
            parsed = app.RuleParser().parse_text(text)
            self.assertFalse(app.convert_rules(parsed, "suricata").errors)
        for source in ([], (), app.ParseResult("manual")):
            self.assertTrue(app.convert_rules(source, "suricata", allow_detached_rules=True).errors)
        good = app.RuleParser().parse_text(RULE)
        unproven = app.ParseResult("manual", rules=[replace(good.rules[0])])
        self.assertTrue(app.convert_rules(unproven, "suricata").errors)

    def test_permissive_whole_parse_preserves_unknown_options_without_crashing(self):
        parsed = app.RuleParser().parse_text(
            RULE.replace("sid:1001;", "custom_option:1; sid:1001;")
        )
        for source in (parsed, parsed.rules, tuple(parsed.rules)):
            with self.subTest(source=type(source).__name__):
                result = app.convert_rules(
                    source, "suricata", strict=False, source_dialect="snort3"
                )
                self.assertFalse(result.errors)
                self.assertEqual(len(result.rules), 1)
                self.assertIn("custom_option:1;", result.rules[0])
                warnings = [
                    d for d in result.diagnostics if d.code == "UNVERIFIED_KEYWORDS_PRESERVED"
                ]
                self.assertEqual(len(warnings), 1)
                self.assertEqual(warnings[0].source, parsed.source)
                self.assertTrue(app.convert_rules(source, "suricata", strict=True).errors)

    def test_public_permissive_cli_writes_output_and_strict_cli_refuses_unknown_option(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.rules"
            source.write_text(RULE.replace("sid:1001;", "custom_option:1; sid:1001;"))
            args = ["convert", str(source), "--target", "suricata", "--source-dialect", "snort3"]
            output = root / "permissive.rules"
            report = root / "permissive.json"
            self.assertEqual(
                app.main(
                    [*args, "--allow-unverified", "--output", str(output), "--report", str(report)]
                ),
                app.EXIT_OK,
            )
            self.assertIn("custom_option:1;", output.read_text())
            document = json.loads(report.read_text())
            self.assertEqual(
                [d["code"] for d in document["diagnostics"]].count("UNVERIFIED_KEYWORDS_PRESERVED"),
                1,
            )
            refused = root / "strict.rules"
            self.assertNotEqual(app.main([*args, "--output", str(refused)]), app.EXIT_OK)
            self.assertFalse(refused.exists())

    def test_parse_diagnostics_retained_once_and_limited_before_conversion(self):
        parsed = app.RuleParser().parse_text(RULE.replace('msg:"snapshot"; ', ""))
        result = app.convert_rules(parsed, "suricata", source_dialect="snort3")
        self.assertEqual(len(result.diagnostics), len(parsed.diagnostics))
        self.assertEqual(len(result.rules), 1)
        with patch.object(app, "MAX_DIAGNOSTICS", 0), self.assertRaises(app.ConverterError):
            app.convert_rules(parsed, "suricata")

    def test_raw_file_digest_includes_bom_and_original_line_endings(self):
        raw = b"\xef\xbb\xbf" + (RULE + "\r\n").encode()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.rules"
            source.write_bytes(raw)
            parsed = app.RuleParser().parse_file(source)
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(parsed.source_sha256, digest)
            self.assertEqual(parsed.input_identity.sha256, digest)
            self.assertEqual(parsed.byte_count, len(raw))
            self.assertEqual(parsed.rules[0].sid, 1001)
            self.assertEqual(app.ruleset_analysis(parsed)["source_sha256"], digest)
            self.assertEqual(
                app.sarif_report(parsed)["runs"][0]["artifacts"][0]["hashes"]["sha-256"], digest
            )
            report, _, _, _ = app.build_panorama_report(parsed)
            self.assertEqual(report["source_sha256"], digest)
            self.assertIn(digest, app.report_as_text(report))
            self.assertEqual(app.ruleset_diff(parsed, parsed)["before_sha256"], digest)

    def test_public_cli_reports_and_conversion_bind_consumed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.rules"
            raw = (
                b"\xef\xbb\xbf"
                + (RULE.replace('content:"marker";', 'content:"marker"; nocase;') + "\r\n").encode()
            )
            source.write_bytes(raw)
            expected = hashlib.sha256(raw).hexdigest()
            cases = [
                ["validate", str(source), "--json", str(root / "validate.json")],
                ["convert", str(source), "--target", "json", "--output", str(root / "export.json")],
                [
                    "convert",
                    str(source),
                    "--target",
                    "suricata",
                    "--source-dialect",
                    "snort3",
                    "--output",
                    str(root / "converted.rules"),
                    "--report",
                    str(root / "convert.json"),
                ],
                [
                    "panorama-preflight",
                    str(source),
                    "--output-dir",
                    str(root / "panorama"),
                ],
            ]
            for args in cases:
                with self.subTest(command=args[0]):
                    self.assertEqual(app.main(args), app.EXIT_OK)
            for name in (
                "validate.json",
                "export.json",
                "convert.json",
                "panorama/panorama_manifest.json",
                "panorama/panorama_preflight.json",
            ):
                document = json.loads((root / name).read_text())
                self.assertEqual(document["source_sha256"], expected)
                self.assertEqual(document["source_bytes"], len(raw))
            self.assertIn(expected, (root / "converted.rules").read_text())
            source.write_text(RULE.replace("1001", "9999"))
            self.assertEqual(
                json.loads((root / "convert.json").read_text())["source_sha256"], expected
            )

    @unittest.skipUnless(os.name == "nt", "Actual Windows file sharing")
    def test_windows_existing_writer_and_writable_mapping_refuse_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.rules"
            source.write_text(RULE)
            with (
                source.open("r+b"),
                self.assertRaisesRegex(app.ConverterError, "Cannot read input"),
            ):
                app.RuleParser().parse_file(source)
            writer = source.open("r+b")
            mapping = mmap.mmap(writer.fileno(), 0, access=mmap.ACCESS_WRITE)
            writer.close()
            try:
                with self.assertRaisesRegex(app.ConverterError, "Cannot read input"):
                    app.RuleParser().parse_file(source)
            finally:
                mapping.close()
            self.assertEqual(app.RuleParser().parse_file(source).rules[0].sid, 1001)

    @unittest.skipUnless(os.name == "nt", "Actual Windows file sharing")
    def test_windows_retained_read_excludes_new_writer_and_delete_then_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.rules"
            source.write_text(RULE)
            descriptor = app.open_input_descriptor(source)
            try:
                with self.assertRaises(OSError):
                    source.open("r+b")
                with self.assertRaises(OSError):
                    source.unlink()
                with source.open("rb") as other_reader:
                    self.assertEqual(other_reader.read(), RULE.encode())
            finally:
                os.close(descriptor)
            with source.open("r+b") as writer:
                self.assertEqual(writer.read(), RULE.encode())
            source.unlink()

    def test_compressed_input_limit_precedes_all_parser_and_filesystem_work(self):
        oversized = b"\x1f\x8b" + b"x" * 31
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "not-created"
            for operation in (
                lambda: app.validate_tar_archive(oversized),
                lambda: app.validate_zip_archive(oversized),
                lambda: app.extract_archive(oversized, "tar.gz", root, False),
            ):
                with (
                    patch.object(app, "MAX_DOWNLOAD_BYTES", 32),
                    patch.object(app.gzip, "GzipFile") as gzip_parser,
                    patch.object(app.tarfile, "open") as tar_parser,
                    patch.object(app.zipfile, "ZipFile") as zip_parser,
                    self.assertRaisesRegex(app.ConverterError, "download byte limit"),
                ):
                    operation()
                gzip_parser.assert_not_called()
                tar_parser.assert_not_called()
                zip_parser.assert_not_called()
                self.assertFalse(root.exists())

    def test_tar_exact_compressed_limit_passes_but_one_less_refuses(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            member = tarfile.TarInfo("input.rules")
            member.size = len(RULE)
            archive.addfile(member, io.BytesIO(RULE.encode()))
        data = output.getvalue()
        with patch.object(app, "MAX_DOWNLOAD_BYTES", len(data)):
            self.assertEqual(app.validate_tar_archive(data)[0].name, "input.rules")
        with (
            patch.object(app, "MAX_DOWNLOAD_BYTES", len(data) - 1),
            self.assertRaises(app.ConverterError),
        ):
            app.validate_tar_archive(data)

    def test_feed_target_digest_retains_params_query_order_and_encoding_without_secrets(self):
        targets = [
            "https://example.test/rules;version=A?token=SYNTHETIC_A&x=1#one",
            "https://example.test/rules;version=B?token=SYNTHETIC_A&x=1#one",
            "https://example.test/rules;version=A?token=SYNTHETIC_B&x=1#one",
            "https://example.test/rules;version=A?x=1&token=SYNTHETIC_A#one",
            "https://example.test/rules;version=A?token=SYNTHETIC_%41&x=1#one",
        ]
        hashes = []
        for url in targets:
            display, digest = app.feed_url_provenance(url)
            self.assertNotIn("SYNTHETIC", display)
            self.assertNotIn("version=A", display)
            self.assertEqual(digest, hashlib.sha256(url.split("#")[0].encode()).hexdigest())
            hashes.append(digest)
        self.assertEqual(len(set(hashes)), len(targets))
        self.assertEqual(
            app.feed_url_provenance(targets[0]),
            app.feed_url_provenance(targets[0].replace("#one", "#two")),
        )
        plain = "https://example.test/rules"
        self.assertEqual(app.feed_url_provenance(plain)[0], plain)

    def test_feed_digest_retains_empty_delimiters_used_in_actual_request_selectors(self):
        base = "https://example.test/rules"
        targets = [base, base + "?", base + ";", base + ";?", base + "?x=", base + ";?x="]
        selectors = [app.urllib.request.Request(url).selector for url in targets]
        self.assertEqual(len(set(selectors)), len(targets))
        hashes = []
        for url in targets:
            _, digest = app.feed_url_provenance(url)
            self.assertEqual(digest, hashlib.sha256(url.encode()).hexdigest())
            hashes.append(digest)
            for fragment in ("#", "#one", "#two?other"):
                self.assertEqual(app.feed_url_provenance(url + fragment)[1], digest)
        self.assertEqual(len(set(hashes)), len(targets))

    def test_actual_feed_composition_records_redacted_source_and_final_target_digests(self):
        class Response(io.BytesIO):
            def __init__(self, value=b""):
                super().__init__(value)
                self.headers = {"Content-Length": "7"}

            def geturl(self):
                return "https://example.test/rules;version=A?token=SYNTHETIC_FINAL#fragment"

        class Opener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response(b"fixture")

        source = "https://example.test/rules;version=B?token=SYNTHETIC_SOURCE"
        opener = Opener()
        with (
            patch.dict(
                app.FEEDS,
                {"fixture": {"url": source, "hosts": ["example.test"], "description": "offline"}},
            ),
            patch.object(app.urllib.request, "build_opener", return_value=opener),
        ):
            data, metadata = app.download_feed("fixture")
        self.assertEqual(data, b"fixture")
        self.assertEqual(opener.request.full_url, source)
        self.assertNotIn("SYNTHETIC", json.dumps(metadata))
        self.assertEqual(metadata["source_url_sha256"], app.feed_url_provenance(source)[1])
        self.assertEqual(
            metadata["resolved_url_sha256"], app.feed_url_provenance(Response().geturl())[1]
        )


if __name__ == "__main__":
    unittest.main()

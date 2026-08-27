from __future__ import annotations

import io
import json
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import snort_suricata_rule_converter as converter  # noqa: E402


def parse(text: str) -> converter.ParseResult:
    return converter.RuleParser().parse_text(text, "fixture.rules")


class ParserTests(unittest.TestCase):
    def test_parses_multiline_snort3_rule_and_inline_modifiers(self) -> None:
        result = parse(
            """
            alert tcp any any -> any 80
            (
                msg:"Example";
                http_uri;
                content:"/admin,a",fast_pattern,nocase,depth 10;
                sid:1001;
                rev:2;
            )
            """
        )
        self.assertEqual(1, len(result.rules))
        self.assertFalse(result.errors)
        self.assertEqual(
            [
                "msg",
                "http_uri",
                "content",
                "fast_pattern",
                "nocase",
                "depth",
                "sid",
                "rev",
            ],
            [option.key for option in result.rules[0].options],
        )
        self.assertEqual('"/admin,a"', result.rules[0].first_value("content"))
        self.assertEqual("content-inline", result.rules[0].options[3].origin)

    def test_hash_fragment_inside_reference_is_not_a_comment(self) -> None:
        result = parse(
            'alert tcp any any -> any any (msg:"URL"; reference:url,example.test/#/file/abc; sid:1002;)\n'
        )
        self.assertFalse(result.errors)
        self.assertEqual("url,example.test/#/file/abc", result.rules[0].first_value("reference"))

    def test_disabled_hash_rule_is_ignored(self) -> None:
        result = parse(
            '# alert tcp any any -> any any (msg:"Disabled"; sid:1;)\n'
            'alert tcp any any -> any any (msg:"Enabled"; sid:2;)\n'
        )
        self.assertEqual([2], [rule.sid for rule in result.rules])

    def test_non_rule_text_is_disclosed(self) -> None:
        result = parse('var HOME_NET any\nalert tcp any any -> any any (msg:"x"; sid:12;)\n')
        self.assertEqual(1, result.ignored_directives)
        self.assertIn("IGNORED_NON_RULE_TEXT", {item.code for item in result.diagnostics})

    def test_c_style_comments_are_removed_outside_quotes_only(self) -> None:
        result = parse(
            '/* lead */ alert tcp any any -> any any (msg:"keep /* text */"; /* middle */ content:"x"; sid:3;)'
        )
        self.assertFalse(result.errors)
        self.assertEqual("keep /* text */", result.rules[0].message)

    def test_semicolon_and_parentheses_inside_strings_are_preserved(self) -> None:
        result = parse('alert tcp any any -> any any (msg:"a; (b)"; pcre:"/x;y\\)/"; sid:4;)')
        self.assertFalse(result.errors)
        self.assertEqual('"a; (b)"', result.rules[0].first_value("msg"))
        self.assertEqual('"/x;y\\)/"', result.rules[0].first_value("pcre"))

    def test_multiple_rules_on_one_line(self) -> None:
        result = parse(
            'alert tcp any any -> any any (msg:"one"; sid:5;) '
            'alert udp any any -> any any (msg:"two"; sid:6;)'
        )
        self.assertEqual([5, 6], [rule.sid for rule in result.rules])

    def test_header_address_list_with_spaces(self) -> None:
        result = parse('alert tcp [10.0.0.0/8, 192.168.0.0/16] any -> any 443 (msg:"list"; sid:7;)')
        self.assertFalse(result.errors)
        self.assertEqual("[10.0.0.0/8, 192.168.0.0/16]", result.rules[0].source_address)

    def test_headerless_snort3_file_rule(self) -> None:
        result = parse('alert file (msg:"file"; file_data; content:"MZ"; sid:8;)')
        self.assertFalse(result.errors)
        self.assertTrue(result.rules[0].headerless)

    def test_snort3_file_identification_rule(self) -> None:
        result = parse(
            'file_id (msg:"PDF file"; file_meta:type PDF,id 282; file_data; content:"%PDF"; sid:13;)'
        )
        self.assertFalse(result.errors)
        self.assertEqual("file_id", result.rules[0].action)
        self.assertEqual(
            "file_id",
            converter.render_rule(result.rules[0], "snort3", "snort3").split(" (")[0],
        )

    def test_unterminated_rule_is_reported(self) -> None:
        result = parse('alert tcp any any -> any any (msg:"broken"; sid:9;')
        self.assertEqual("UNTERMINATED_RULE", result.errors[0].code)

    def test_missing_semicolon_is_reported(self) -> None:
        result = parse('alert tcp any any -> any any (msg:"broken"; sid:10)')
        self.assertIn("MISSING_OPTION_TERMINATOR", {item.code for item in result.errors})

    def test_invalid_sid_rule_is_not_accepted(self) -> None:
        result = parse('alert tcp any any -> any any (msg:"bad"; sid:abc;)')
        self.assertFalse(result.rules)
        self.assertIn("INVALID_SID", {item.code for item in result.errors})

    def test_missing_message_warning_is_preserved(self) -> None:
        result = parse('alert tcp any any -> any any (content:"x"; sid:11;)')
        self.assertEqual(1, len(result.rules))
        self.assertIn("MISSING_MSG", {item.code for item in result.diagnostics})

    def test_strict_utf8_rejects_invalid_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.rules"
            path.write_bytes(b"\xff\xfe")
            with self.assertRaises(converter.ConverterError):
                converter.RuleParser().parse_file(path)

    def test_nul_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.rules"
            path.write_bytes(b"alert\x00tcp")
            with self.assertRaises(converter.ConverterError):
                converter.RuleParser().parse_file(path)


class ConversionTests(unittest.TestCase):
    def test_snort3_sticky_buffer_maps_to_suricata(self) -> None:
        rule = parse(
            'alert tcp any any -> any 80 (msg:"x"; http_uri; content:"/x",nocase; sid:20;)'
        ).rules[0]
        output = converter.convert_rules([rule], "suricata", source_dialect="snort3")
        self.assertFalse(output.errors)
        self.assertIn('http.uri; content:"/x"; nocase;', output.rules[0])

    def test_suricata_sticky_buffer_maps_to_snort3(self) -> None:
        rule = parse(
            'alert tcp any any -> any 80 (msg:"x"; http.uri; content:"/x"; nocase; sid:21;)'
        ).rules[0]
        output = converter.convert_rules([rule], "snort3", source_dialect="suricata")
        self.assertFalse(output.errors)
        self.assertIn('http_uri; content:"/x",nocase;', output.rules[0])

    def test_snort2_modifier_moves_before_content_and_resets_buffer(self) -> None:
        rule = parse(
            'alert tcp any any -> any 80 (msg:"x"; content:"/x"; nocase; http_uri; content:"packet"; sid:22;)'
        ).rules[0]
        output = converter.convert_rules([rule], "snort3", source_dialect="snort2")
        self.assertFalse(output.errors)
        self.assertIn(
            'http_uri; content:"/x",nocase; pkt_data; content:"packet";',
            output.rules[0],
        )

    def test_sticky_buffer_downgrade_applies_modifier_to_each_content(self) -> None:
        rule = parse(
            'alert tcp any any -> any 80 (msg:"x"; http.uri; content:"one"; nocase; content:"two"; sid:23;)'
        ).rules[0]
        output = converter.convert_rules([rule], "snort2", source_dialect="suricata")
        self.assertFalse(output.errors)
        self.assertIn('content:"one"; http_uri; nocase; content:"two"; http_uri;', output.rules[0])

    def test_pcre_under_sticky_buffer_is_not_unsafely_downgraded(self) -> None:
        rule = parse('alert tcp any any -> any 80 (msg:"x"; http.uri; pcre:"/x/"; sid:24;)').rules[
            0
        ]
        output = converter.convert_rules([rule], "snort2", source_dialect="suricata")
        self.assertTrue(output.errors)
        self.assertEqual([], output.rules)
        self.assertIn("UNSAFE_STICKY_BUFFER_DOWNGRADE", {item.code for item in output.errors})

    def test_snort_specific_option_is_rejected_for_suricata(self) -> None:
        rule = parse(
            'alert tcp any any -> any any (msg:"x"; protected_content:"abc"; sid:25;)'
        ).rules[0]
        output = converter.convert_rules([rule], "suricata")
        self.assertIn("UNSUPPORTED_TARGET_OPTION", {item.code for item in output.errors})

    def test_unknown_option_is_preserved_and_disclosed(self) -> None:
        rule = parse('alert tcp any any -> any any (msg:"x"; future_keyword:yes; sid:26;)').rules[0]
        output = converter.convert_rules([rule], "suricata", strict=False)
        self.assertFalse(output.errors)
        self.assertIn("future_keyword:yes;", output.rules[0])
        self.assertEqual(1, output.unverified_keywords["future_keyword"])

    def test_strict_mode_rejects_unknown_option(self) -> None:
        rule = parse('alert tcp any any -> any any (msg:"x"; future_keyword:yes; sid:27;)').rules[0]
        output = converter.convert_rules([rule], "suricata")
        self.assertTrue(output.errors)
        self.assertFalse(output.rules)

    def test_snort3_same_dialect_round_trip_fingerprint(self) -> None:
        original = parse(
            'alert tcp any any -> any 80 (msg:"x"; http_uri; content:"/x",fast_pattern,nocase,depth 8; sid:28; rev:2;)'
        ).rules[0]
        rendered = converter.render_rule(original, "snort3", "snort3")
        reparsed = parse(rendered).rules[0]
        self.assertEqual(
            converter.semantic_fingerprint(original),
            converter.semantic_fingerprint(reparsed),
        )

    def test_snort3_fast_pattern_arguments_remain_inline(self) -> None:
        original = parse(
            'alert tcp any any -> any any (msg:"x"; content:"abcdef",fast_pattern,fast_pattern_offset 1,fast_pattern_length 4; sid:35;)'
        ).rules[0]
        rendered = converter.render_rule(original, "snort3", "snort3")
        self.assertIn(
            'content:"abcdef",fast_pattern,fast_pattern_offset 1,fast_pattern_length 4;',
            rendered,
        )

    def test_matching_service_is_not_redundantly_emitted(self) -> None:
        rule = parse(
            'alert tcp any any -> any 80 (msg:"x"; http_uri; content:"/x"; service:http; sid:29;)'
        ).rules[0]
        output = converter.convert_rules([rule], "suricata", source_dialect="snort3")
        self.assertFalse(output.errors)
        self.assertNotIn("app-layer-protocol", output.rules[0])
        self.assertIn("http.uri;", output.rules[0])

    def test_service_without_sticky_buffer_maps_to_app_protocol(self) -> None:
        rule = parse(
            'alert tcp any any -> any any (msg:"x"; content:"GET"; service:http; sid:30;)'
        ).rules[0]
        output = converter.convert_rules([rule], "suricata", source_dialect="snort3")
        self.assertFalse(output.errors)
        self.assertIn("app-layer-protocol:http;", output.rules[0])

    def test_http_header_field_user_agent_maps_safely(self) -> None:
        rule = parse(
            'alert http (msg:"x"; http_header:field user-agent; content:"Agent"; sid:31;)'
        ).rules[0]
        output = converter.convert_rules([rule], "suricata", source_dialect="snort3")
        self.assertFalse(output.errors)
        self.assertIn("http.user_agent;", output.rules[0])
        self.assertNotIn("field user-agent", output.rules[0])

    def test_snort_ber_options_are_rejected_for_suricata(self) -> None:
        rule = parse(
            'alert tcp any any -> any any (msg:"x"; ber_skip:0x01,optional; ber_data:0x04; sid:32;)'
        ).rules[0]
        output = converter.convert_rules([rule], "suricata", source_dialect="snort3")
        self.assertIn("UNSUPPORTED_TARGET_OPTION", {item.code for item in output.errors})

    def test_packet_and_app_layer_match_conflict_is_rejected(self) -> None:
        rule = parse(
            'alert tcp any any -> any 80 (msg:"x"; flags:S; http_uri; content:"/x"; sid:33;)'
        ).rules[0]
        output = converter.convert_rules([rule], "suricata", source_dialect="snort3")
        self.assertIn("PACKET_APP_LAYER_CONFLICT", {item.code for item in output.errors})

    def test_snort_stream_size_maps_direction_and_comparison(self) -> None:
        rule = parse(
            'alert tcp any any -> any any (msg:"x"; stream_size:1,to_client; sid:34;)'
        ).rules[0]
        output = converter.convert_rules([rule], "suricata", source_dialect="snort3")
        self.assertFalse(output.errors)
        self.assertIn("stream_size:server,=,1;", output.rules[0])

    def test_snort2_http_modifier_becomes_suricata_sticky_buffer(self) -> None:
        rule = parse(
            'alert tcp any any -> any 80 (msg:"x"; content:"/admin"; http_uri; nocase; sid:36;)'
        ).rules[0]
        output = converter.convert_rules([rule], "suricata", source_dialect="snort2")
        self.assertFalse(output.errors)
        self.assertIn('http.uri; content:"/admin"; nocase;', output.rules[0])

    def test_target_specific_action_is_rejected(self) -> None:
        rule = parse('block tcp any any -> any any (msg:"x"; content:"x"; sid:37;)').rules[0]
        output = converter.convert_rules([rule], "suricata", source_dialect="snort3")
        self.assertIn("UNSUPPORTED_TARGET_ACTION", {item.code for item in output.errors})

    def test_json_canonical_rule_uses_source_dialect(self) -> None:
        rule = parse('alert tcp any any -> any any (msg:"x"; service:sunrpc; sid:38;)').rules[0]
        exported = converter.rule_to_dict(rule)
        self.assertIn("service:sunrpc;", exported["canonical_rule"])


class AnalysisAndPanoramaTests(unittest.TestCase):
    def test_duplicate_and_conflicting_sids_are_separate(self) -> None:
        result = parse(
            'alert tcp any any -> any any (msg:"same"; content:"x"; sid:30;)\n'
            'alert tcp any any -> any any (msg:"same"; content:"x"; sid:30;)\n'
            'alert tcp any any -> any any (msg:"different"; content:"y"; sid:31;)\n'
            'alert udp any any -> any any (msg:"different"; content:"z"; sid:31;)\n'
        )
        report = converter.ruleset_analysis(result)
        self.assertEqual(1, len(report["duplicate_sid_groups"]))
        self.assertEqual(1, len(report["conflicting_sid_groups"]))

    def test_diff_detects_added_removed_and_changed(self) -> None:
        before = parse(
            'alert tcp any any -> any any (msg:"a"; sid:40; rev:1;)\n'
            'alert tcp any any -> any any (msg:"remove"; sid:41;)'
        )
        after = parse(
            'alert tcp any any -> any any (msg:"b"; sid:40; rev:2;)\n'
            'alert tcp any any -> any any (msg:"add"; sid:42;)'
        )
        summary = converter.ruleset_diff(before, after)["summary"]
        self.assertEqual(
            {"added": 1, "removed": 1, "changed": 1, "unchanged": 0, "conflicts": 0},
            summary,
        )

    def test_panorama_rejects_ignored_detection_semantics(self) -> None:
        rule = parse('alert tcp any any -> any any (msg:"x"; flags:S; content:"x"; sid:50;)').rules[
            0
        ]
        findings = converter.panorama_option_checks(rule)
        self.assertIn("PANORAMA_IGNORES_DETECTION_OPTION", {item.code for item in findings})

    def test_panorama_rejects_unsupported_pcre_features(self) -> None:
        rule = parse(
            'alert tcp any any -> any any (msg:"x"; pcre:"/(?>a)(?=b)\\1/"; sid:51;)'
        ).rules[0]
        codes = {item.code for item in converter.panorama_option_checks(rule)}
        self.assertIn("PANORAMA_PCRE_UNSUPPORTED", codes)
        self.assertIn("PANORAMA_PCRE_BACKREFERENCE", codes)

    def test_panorama_threshold_limits(self) -> None:
        rule = parse(
            'alert tcp any any -> any any (msg:"x"; content:"x"; threshold:type both, track by_src, count 256, seconds 3601; sid:52;)'
        ).rules[0]
        codes = [item.code for item in converter.panorama_option_checks(rule)]
        self.assertEqual(2, codes.count("PANORAMA_THRESHOLD_OUT_OF_RANGE"))

    def test_panorama_only_negated_content_is_rejected(self) -> None:
        rule = parse('alert tcp any any -> any any (msg:"x"; content:!"safe"; sid:53;)').rules[0]
        codes = {item.code for item in converter.panorama_option_checks(rule)}
        self.assertIn("PANORAMA_ONLY_NEGATED_CONDITIONS", codes)

    def test_sarif_has_locations_and_rule_metadata(self) -> None:
        result = parse('alert tcp any any -> any any (content:"x"; sid:54;)')
        sarif = converter.sarif_report(result)
        self.assertEqual("2.1.0", sarif["version"])
        self.assertEqual("MISSING_MSG", sarif["runs"][0]["results"][0]["ruleId"])


class FileAndArchiveSafetyTests(unittest.TestCase):
    def test_atomic_write_refuses_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "output.txt"
            converter.atomic_write_text(path, "one")
            with self.assertRaises(converter.ConverterError):
                converter.atomic_write_text(path, "two")
            converter.atomic_write_text(path, "two", force=True)
            self.assertEqual("two", path.read_text(encoding="utf-8"))

    def test_atomic_write_does_not_clobber_a_racing_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "output.txt"

            def create_competing_file(_source: str, destination: str) -> None:
                Path(destination).write_text("competitor", encoding="utf-8")
                raise FileExistsError

            with (
                unittest.mock.patch.object(converter.os, "link", side_effect=create_competing_file),
                self.assertRaises(converter.ConverterError),
            ):
                converter.atomic_write_text(path, "tool output")

            self.assertEqual("competitor", path.read_text(encoding="utf-8"))
            self.assertEqual([path], list(Path(directory).iterdir()))

    def test_tar_path_traversal_is_rejected(self) -> None:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo("../escape.rules")
            payload = b"x"
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        with self.assertRaises(converter.ConverterError):
            converter.validate_tar_archive(stream.getvalue())

    def test_tar_symlink_is_rejected(self) -> None:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo("rules/link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../outside"
            archive.addfile(info)
        with self.assertRaises(converter.ConverterError):
            converter.validate_tar_archive(stream.getvalue())

    def test_zip_path_traversal_is_rejected(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, mode="w") as archive:
            archive.writestr("../escape.rules", "x")
        with self.assertRaises(converter.ConverterError):
            converter.validate_zip_archive(stream.getvalue())

    def test_safe_tar_is_extracted(self) -> None:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo("rules/community.rules")
            payload = b'alert tcp any any -> any any (msg:"x"; sid:60;)\n'
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as directory:
            written = converter.extract_archive(
                stream.getvalue(), "tar.gz", Path(directory), force=False
            )
            self.assertEqual(1, len(written))
            self.assertTrue((Path(directory) / "rules" / "community.rules").is_file())

    def test_windows_drive_archive_name_is_rejected(self) -> None:
        with self.assertRaises(converter.ConverterError):
            converter.safe_archive_name("C:/Windows/win.ini")

    def test_windows_device_archive_name_is_rejected(self) -> None:
        with self.assertRaises(converter.ConverterError):
            converter.safe_archive_name("rules/CON.txt")

    def test_duplicate_zip_paths_are_rejected_case_insensitively(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, mode="w") as archive:
            archive.writestr("rules/one.rules", "x")
            archive.writestr("RULES/ONE.RULES", "y")
        with self.assertRaises(converter.ConverterError):
            converter.validate_zip_archive(stream.getvalue())

    def test_zip_symlink_is_rejected(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, mode="w") as archive:
            info = zipfile.ZipInfo("rules/link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "../outside")
        with self.assertRaises(converter.ConverterError):
            converter.validate_zip_archive(stream.getvalue())

    def test_insecure_redirect_is_rejected(self) -> None:
        handler = converter.RestrictedRedirectHandler({"example.test"})
        request = converter.urllib.request.Request("https://example.test/start")
        with self.assertRaises(converter.ConverterError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://example.test/file")

    def test_allowlisted_https_url_rejects_credentials_and_nonstandard_ports(self) -> None:
        hosts = {"example.test"}
        self.assertTrue(converter.is_allowed_https_url("https://example.test/file", hosts))
        self.assertTrue(converter.is_allowed_https_url("https://example.test:443/file", hosts))
        for url in (
            "https://user@example.test/file",
            "https://example.test:444/file",
            "https://example.test:not-a-port/file",
        ):
            with self.subTest(url=url):
                self.assertFalse(converter.is_allowed_https_url(url, hosts))


class CliTests(unittest.TestCase):
    def test_json_export_and_output_overwrite_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.rules"
            output_path = Path(directory) / "output.json"
            input_path.write_text(
                'alert tcp any any -> any any (msg:"x"; sid:70;)\n', encoding="utf-8"
            )
            first = converter.main(
                [
                    "convert",
                    str(input_path),
                    "--target",
                    "json",
                    "--output",
                    str(output_path),
                ]
            )
            second = converter.main(
                [
                    "convert",
                    str(input_path),
                    "--target",
                    "json",
                    "--output",
                    str(output_path),
                ]
            )
            self.assertEqual(converter.EXIT_OK, first)
            self.assertEqual(converter.EXIT_OPERATIONAL_ERROR, second)
            self.assertEqual(
                70,
                json.loads(output_path.read_text(encoding="utf-8"))["rules"][0]["sid"],
            )

    def test_force_cannot_replace_input_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.rules"
            original = 'alert tcp any any -> any any (msg:"x"; sid:71;)\n'
            input_path.write_text(original, encoding="utf-8")
            result = converter.main(
                [
                    "convert",
                    str(input_path),
                    "--target",
                    "snort3",
                    "--source-dialect",
                    "snort3",
                    "--output",
                    str(input_path),
                    "--force",
                ]
            )
            self.assertEqual(converter.EXIT_OPERATIONAL_ERROR, result)
            self.assertEqual(original, input_path.read_text(encoding="utf-8"))

    def test_partial_mode_requires_report_and_rejection_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.rules"
            output_path = Path(directory) / "output.rules"
            input_path.write_text(
                'alert tcp any any -> any any (msg:"x"; sid:72;)\n', encoding="utf-8"
            )
            result = converter.main(
                [
                    "convert",
                    str(input_path),
                    "--target",
                    "suricata",
                    "--output",
                    str(output_path),
                    "--allow-partial",
                ]
            )
            self.assertEqual(converter.EXIT_OPERATIONAL_ERROR, result)
            self.assertFalse(output_path.exists())


class LocalCorpusTests(unittest.TestCase):
    def test_bundled_local_corpus_parses_and_round_trips_without_loss(self) -> None:
        corpus = (
            PROJECT_ROOT
            / ".local-reference"
            / "corpus"
            / "Snort3 Community Rules"
            / "snort3-community.rules"
        )
        if not corpus.exists():
            self.skipTest("The third-party local corpus is intentionally not stored in Git")
        parsed = converter.RuleParser().parse_file(corpus)
        self.assertEqual(4017, len(parsed.rules))
        self.assertFalse(parsed.errors)
        converted = converter.convert_rules(parsed.rules, "snort3", source_dialect="snort3")
        self.assertFalse(converted.errors)
        reparsed = converter.RuleParser().parse_text("\n".join(converted.rules), "roundtrip.rules")
        self.assertFalse(reparsed.errors)
        self.assertEqual(
            [converter.semantic_fingerprint(rule) for rule in parsed.rules],
            [converter.semantic_fingerprint(rule) for rule in reparsed.rules],
        )


if __name__ == "__main__":
    unittest.main()

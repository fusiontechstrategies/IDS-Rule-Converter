"""Security semantics, source snapshots and canonical producer representation."""

import copy
import gzip
import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import test_security_regressions as fixtures

import snort_suricata_rule_converter as app
from scripts import normalize_sdist, normalize_wheel, prepare_release, verify_release_handoff

ROOT = Path(__file__).resolve().parents[1]
VERSION, COMMIT, EPOCH = "4.0.2", "a" * 40, 1767225600
RULE = 'alert tcp any any -> any any (content:"marker"; sid:1001;)'


class ConversionBoundaries(unittest.TestCase):
    def test_sip_generated_match_restores_packet_and_prior_file_buffers(self):
        for shorthand in ("sip_method:INVITE;", "sip_stat_code:200;", "sip_stat_code:2;"):
            for selector, expected in (
                ("", "pkt_data;"),
                ("file_data;", "file.data;"),
                ("base64_data;", "base64_data;"),
            ):
                for later in ('content:"marker";', 'pcre:"/marker/";', "byte_test:1,=,1,0;"):
                    with self.subTest(shorthand=shorthand, selector=selector, later=later):
                        parsed = app.RuleParser().parse_text(
                            f"alert tcp any any -> any any ({selector}{shorthand}{later} sid:1001;)"
                        )
                        result = app.convert_rules(
                            parsed.rules, "suricata", source_dialect="snort3"
                        )
                        self.assertFalse(result.errors)
                        self.assertEqual(len(result.rules), 1)
                        self.assertIn(expected + " " + later, result.rules[0])

    def test_sip_relative_cursor_is_rejected_even_without_strict_unknown_gate(self):
        for relative in (
            'content:"x"; distance:0;',
            'pcre:"/x/R";',
            "byte_test:1,=,1,0, relative;",
            "isdataat:1,relative;",
            "base64_decode:bytes 8, offset 0, relative;",
            "asn1:oversize_length 500,relative_offset 0;",
            "nocase;",
            "depth:4;",
        ):
            parsed = app.RuleParser().parse_text(
                "alert tcp any any -> any any (sip_method:INVITE; " + relative + " sid:1001;)"
            )
            for strict in (True, False):
                result = app.convert_rules(
                    parsed.rules, "suricata", strict=strict, source_dialect="snort3"
                )
                self.assertEqual(result.rules, [])
                self.assertIn("SIP_RELATIVE_CURSOR_UNSAFE", {d.code for d in result.errors})
            with self.assertRaisesRegex(app.ConverterError, "relative payload cursor"):
                app.render_rule(parsed.rules[0], "suricata", source_dialect="snort3")

    def test_snort2_sticky_payload_context_survives_sip_and_legacy_modifiers(self):
        for selector, expected in (
            ("file_data;", "file.data;"),
            ("base64_decode; base64_data;", "base64_data;"),
        ):
            for shorthand in ("sip_method:INVITE;", "sip_stat_code:200;"):
                parsed = app.RuleParser().parse_text(
                    f'alert tcp any any -> any any ({selector}{shorthand}content:"marker"; sid:1001;)'
                )
                for dialect in ("auto", "snort2", "snort3"):
                    for strict in (True, False):
                        with self.subTest(
                            selector=selector, shorthand=shorthand, dialect=dialect, strict=strict
                        ):
                            result = app.convert_rules(
                                parsed.rules, "suricata", strict=strict, source_dialect=dialect
                            )
                            self.assertFalse(result.errors)
                            self.assertIn(expected + ' content:"marker";', result.rules[0])
                            self.assertNotIn(
                                expected + ' pkt_data; content:"marker";', result.rules[0]
                            )
                    rendered = app.render_rule(
                        parsed.rules[0],
                        "suricata",
                        source_dialect=None if dialect == "auto" else dialect,
                    )
                    self.assertIn(expected + ' content:"marker";', rendered)
        parsed = app.RuleParser().parse_text(
            'alert tcp any any -> any any (file_data; content:"request"; http_uri; content:"decoded"; sid:1001;)'
        )
        rendered = app.render_rule(parsed.rules[0], "suricata", source_dialect="snort2")
        self.assertIn('http.uri; content:"request"; file.data; content:"decoded";', rendered)

    def test_snort2_one_shot_modifier_restores_before_actual_payload_operations(self):
        for selector, expected in (("file_data;", "file.data;"), ("", "pkt_data;")):
            for operation, rendered in (
                (
                    "base64_decode:bytes 8, offset 0; base64_data;",
                    "base64_decode:bytes 8, offset 0;",
                ),
                ("bufferlen:10;", "bsize:10;"),
                ("isdataat:1;", "isdataat:1;"),
                ("byte_test:1,=,1,0;", "byte_test:1,=,1,0;"),
            ):
                parsed = app.RuleParser().parse_text(
                    f'alert tcp any any -> any any ({selector}content:"request"; http_uri; {operation} sid:1001;)'
                )
                for strict in (True, False):
                    result = app.convert_rules(
                        parsed.rules, "suricata", strict=strict, source_dialect="snort2"
                    )
                    self.assertFalse(result.errors)
                    self.assertIn(expected + " " + rendered, result.rules[0])
                direct = app.render_rule(parsed.rules[0], "suricata", source_dialect="snort2")
                self.assertIn(expected + " " + rendered, direct)
        for operation in (
            'pcre:"/x/R";',
            "byte_test:1,=,1,0,relative;",
            "base64_decode:bytes 8,relative;",
            "isdataat:1,relative;",
        ):
            parsed = app.RuleParser().parse_text(
                f'alert tcp any any -> any any (file_data; content:"request"; http_uri; {operation} sid:1001;)'
            )
            for strict in (True, False):
                result = app.convert_rules(
                    parsed.rules, "suricata", strict=strict, source_dialect="snort2"
                )
                self.assertEqual(result.rules, [])
                self.assertTrue(result.errors)
            with self.assertRaisesRegex(app.ConverterError, "cannot preserve its cursor"):
                app.render_rule(parsed.rules[0], "suricata", source_dialect="snort2")

    def test_replace_is_rejected_only_when_sip_displaces_its_source_pattern(self):
        for shorthand in ("sip_method:INFO;", "sip_stat_code:200;"):
            for dialect in ("auto", "snort2", "snort3"):
                parsed = app.RuleParser().parse_text(
                    f'alert tcp any any -> any any (content:"ABCD"; {shorthand} replace:"EFGH"; sid:1001;)'
                )
                for strict in (True, False):
                    result = app.convert_rules(
                        parsed.rules, "suricata", strict=strict, source_dialect=dialect
                    )
                    self.assertEqual(result.rules, [])
                    self.assertIn("SIP_RELATIVE_CURSOR_UNSAFE", {d.code for d in result.errors})
                with self.assertRaisesRegex(app.ConverterError, "displaced pattern modifier"):
                    app.render_rule(
                        parsed.rules[0],
                        "suricata",
                        source_dialect=None if dialect == "auto" else dialect,
                    )
                for body in (
                    f'content:"ABCD"; replace:"EFGH"; {shorthand}',
                    f'{shorthand} content:"ABCD"; replace:"EFGH";',
                ):
                    valid = app.RuleParser().parse_text(
                        f"alert tcp any any -> any any ({body} sid:1001;)"
                    )
                    result = app.convert_rules(valid.rules, "suricata", source_dialect=dialect)
                    self.assertFalse(result.errors)
                    self.assertIn('content:"ABCD"; replace:"EFGH";', result.rules[0])

    def test_nested_semicolons_cannot_hide_options_but_quoted_payload_remains_intact(self):
        for hidden in (
            "metadata:[ok; flow:to_server; noalert]",
            "metadata:(ok; flow:to_server; noalert)",
        ):
            parsed = app.RuleParser().parse_text(
                "alert tcp any any -> any any (" + hidden + "; sid:1001;)"
            )
            self.assertTrue(parsed.errors)
        parsed = app.RuleParser().parse_text(RULE.replace('"marker"', '"[ok; noalert;]"'))
        self.assertFalse(parsed.errors)
        self.assertEqual([o.key for o in parsed.rules[0].options], ["content", "sid"])
        self.assertIn('content:"[ok; noalert;]";', app.render_rule(parsed.rules[0], "suricata"))

    def test_malformed_panorama_source_writes_no_subset_or_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "input", Path(directory) / "output"
            source.write_text(RULE + '\nalert tcp any any -> any any (content:"unterminated";')
            output.mkdir()
            sentinel = output / "unrelated"
            sentinel.write_text("keep")
            result = app.main(
                ["panorama-preflight", str(source), "--output-dir", str(output), "--force"]
            )
            self.assertEqual(result, app.EXIT_FINDINGS)
            self.assertEqual(list(output.iterdir()), [sentinel])

    def test_opened_source_identity_refuses_raced_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_text(RULE)
            source = source.resolve()
            original = app.os.open
            raced = []

            def raced_open(path, flags, *args, **kwargs):
                if Path(path) == source:
                    raced.append(True)
                    source.rename(source.with_name("original"))
                    source.write_text(RULE.replace("1001", "9999"))
                return original(path, flags, *args, **kwargs)

            with (
                patch.object(app.os, "open", side_effect=raced_open),
                self.assertRaisesRegex(app.ConverterError, "identity changed"),
            ):
                app.RuleParser().parse_file(source)
            self.assertEqual(raced, [True])

    def test_actual_hardlink_and_case_alias_cannot_replace_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.rules"
            source.write_text(RULE)
            parsed = app.RuleParser().parse_file(source)
            linked = source.with_name("hardlink.rules")
            os.link(source, linked)
            for destination in (linked, source.with_name("INPUT.RULES")):
                with self.assertRaises(app.ConverterError):
                    app.atomic_write_text(
                        destination,
                        "replacement",
                        force=True,
                        protected_inputs=app.input_snapshots(parsed),
                    )
            self.assertEqual(source.read_text(), RULE)

    @unittest.skipIf(os.name == "nt", "POSIX symlink fixture")
    def test_retargeted_input_alias_cannot_change_provenance_or_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            first, second, alias = (root / name for name in ("first", "second", "alias"))
            first.write_text(RULE)
            second.write_text(RULE.replace("1001", "9999"))
            alias.symlink_to(first)
            parsed = app.RuleParser().parse_file(alias)
            alias.unlink()
            alias.symlink_to(second)
            self.assertEqual(parsed.source, str(first))
            self.assertEqual(parsed.rules[0].sid, 1001)
            with self.assertRaises(app.ConverterError):
                app.ensure_outputs_do_not_replace_inputs((first,), app.input_snapshots(parsed))

    def test_input_identity_is_checked_again_at_force_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "input", Path(directory) / "output"
            source.write_text(RULE)
            output.write_text("previous output")
            parsed = app.RuleParser().parse_file(source)
            original = app.write_output_payload

            def replace_leaf(handle, data, expected_size):
                original(handle, data, expected_size)
                output.unlink()
                os.link(source, output)

            with (
                patch.object(app, "write_output_payload", side_effect=replace_leaf),
                self.assertRaisesRegex(app.ConverterError, "file identity"),
            ):
                app.atomic_write_text(
                    output, "replacement", force=True, protected_inputs=app.input_snapshots(parsed)
                )
            self.assertEqual(source.read_text(), RULE)
            self.assertEqual(output.read_text(), RULE)


class CanonicalHandoff(unittest.TestCase):
    def candidate(self, root):
        dist = root / "dist"
        dist.mkdir()
        wheel, sdist = fixtures.SecurityRegressions().fixture_distributions(dist)
        normalize_wheel.normalize_wheel(wheel, EPOCH)
        normalize_sdist.normalize_sdist(sdist, EPOCH)
        return dist, wheel, sdist

    def test_logically_valid_noncanonical_wheel_is_rejected_after_producer_rehash(self):
        for mutation in ("comment", "order", "timestamp", "extra", "mode", "compression"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                dist, wheel, _ = self.candidate(root)
                with zipfile.ZipFile(wheel) as archive:
                    entries = [(copy.copy(info), archive.read(info)) for info in archive.infolist()]
                if mutation == "order":
                    entries.reverse()
                if mutation == "timestamp":
                    entries[0][0].date_time = (2020, 1, 1, 0, 0, 0)
                if mutation == "extra":
                    entries[0][0].extra = b"\xff\xff\x04\x00bait"
                if mutation == "mode":
                    entries[0][0].external_attr = 0o100777 << 16
                if mutation == "compression":
                    entries[0][0].compress_type = zipfile.ZIP_DEFLATED
                with zipfile.ZipFile(wheel, "w") as archive:
                    if mutation == "comment":
                        archive.comment = b"unreviewed producer metadata"
                    for info, data in entries:
                        archive.writestr(info, data)
                assets = root / "assets"
                prepare_release.prepare_release(ROOT, assets, VERSION, COMMIT, dist)
                with self.assertRaisesRegex(ValueError, "not canonical"):
                    verify_release_handoff.verify_handoff(assets, ROOT, COMMIT, EPOCH)

    def test_logically_valid_noncanonical_sdist_is_rejected_after_producer_rehash(self):
        for mutation in ("gzip", "order", "owner", "mode", "timestamp", "pax"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                dist, _, sdist = self.candidate(root)
                with tarfile.open(sdist, "r:gz") as archive:
                    entries = [
                        (
                            copy.copy(member),
                            archive.extractfile(member).read() if member.isfile() else None,
                        )
                        for member in archive
                    ]
                if mutation == "order":
                    entries.reverse()
                if mutation == "owner":
                    entries[0][0].uid, entries[0][0].uname = 123, "unreviewed"
                if mutation == "mode":
                    entries[0][0].mode = 0o777
                if mutation == "timestamp":
                    entries[0][0].mtime = EPOCH + 1
                if mutation == "pax":
                    entries[0][0].pax_headers = {"comment": "unreviewed"}
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for info, data in entries:
                        archive.addfile(info, None if data is None else io.BytesIO(data))
                sdist.write_bytes(
                    gzip.compress(raw.getvalue(), mtime=EPOCH + 1)
                    if mutation == "gzip"
                    else normalize_sdist.build_stored_gzip(raw.getvalue(), EPOCH)
                )
                assets = root / "assets"
                prepare_release.prepare_release(ROOT, assets, VERSION, COMMIT, dist)
                with self.assertRaisesRegex(ValueError, "not canonical"):
                    verify_release_handoff.verify_handoff(assets, ROOT, COMMIT, EPOCH)

    def test_canonical_handoff_rejects_wrong_authenticated_epoch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist, _, _ = self.candidate(root)
            assets = root / "assets"
            prepare_release.prepare_release(ROOT, assets, VERSION, COMMIT, dist)
            with self.assertRaisesRegex(ValueError, "not canonical"):
                verify_release_handoff.verify_handoff(assets, ROOT, COMMIT, EPOCH + 2)

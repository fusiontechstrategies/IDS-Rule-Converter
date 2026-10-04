"""Actual public-boundary regressions from the fd8e508 final scan."""

from __future__ import annotations

import email.message
import io
import struct
import unittest
import urllib.parse
import urllib.request
import urllib.response
import zipfile
from pathlib import PurePosixPath, PureWindowsPath
from unittest.mock import MagicMock, patch

import snort_suricata_rule_converter as app


class FinalScanFive(unittest.TestCase):
    def rule(self, options):
        parsed = app.RuleParser().parse_text(
            f'alert tcp any any -> any any (msg:"probe"; {options} sid:918001;)'
        )
        self.assertFalse(parsed.errors)
        return parsed.rules[0]

    def test_snort2_payload_transition_does_not_inherit_http_modifier(self):
        for dialect, uri in (("suricata", "http.uri"), ("snort3", "http_uri")):
            for buffer in ("pkt_data", "raw_data", "file_data", "base64_data"):
                with self.subTest(dialect=dialect, buffer=buffer):
                    rule = self.rule(
                        f'base64_decode:bytes 32, offset 0; {uri}; content:"encoded"; '
                        f'{buffer}; content:"decoded";'
                    )
                    batch = app.convert_rules([rule], "snort2", source_dialect=dialect)
                    self.assertFalse(batch.errors)
                    text = app.render_rule(rule, "snort2", dialect)
                    self.assertIn('content:"encoded"; http_uri;', text)
                    self.assertIn(f'{buffer}; content:"decoded"; sid:', text)

    def test_snort2_rejects_unrecoverable_relative_content(self):
        for dialect, uri, header in (
            ("suricata", "http.uri", "http.header"),
            ("snort3", "http_uri", "http_header"),
        ):
            for modifier in ("distance:0;", "within:5;", "distance:0; within:5;"):
                for interposition in ("", "flow:to_server;", "metadata:test value;"):
                    with self.subTest(dialect=dialect, modifier=modifier, gap=interposition):
                        rule = self.rule(
                            f'{uri}; content:"a"; {header}; content:"h"; {interposition}'
                            f'{uri}; content:"b"; {modifier}'
                        )
                        for strict in (True, False):
                            batch = app.convert_rules(
                                [rule], "snort2", strict=strict, source_dialect=dialect
                            )
                            self.assertEqual(batch.rules, [])
                            self.assertTrue(batch.errors)
                        with self.assertRaises(app.ConverterError):
                            app.render_rule(rule, "snort2", dialect)

    def test_snort2_negative_match_cannot_establish_new_cursor(self):
        for prefix in ('http.uri; content:!"missing";', "http.uri;"):
            rule = self.rule(prefix + 'content:"b"; distance:0;')
            self.assertTrue(app.convert_rules([rule], "snort2", source_dialect="suricata").errors)
            with self.assertRaises(app.ConverterError):
                app.render_rule(rule, "snort2", "suricata")

    def test_snort2_valid_consecutive_and_fresh_pattern_controls(self):
        for options in (
            'http.uri; content:"a"; content:"b"; distance:0; within:5;',
            'http.uri; content:"a"; http.header; content:"h"; http.uri; '
            'content:"fresh"; content:"b"; distance:0;',
            'content:"a"; content:"b"; distance:0;',
            'file_data; content:"a"; content:"b"; distance:0;',
            'base64_decode:bytes 32, offset 0; base64_data; content:"a"; content:"b"; within:5;',
        ):
            with self.subTest(options=options):
                rule = self.rule(options)
                for strict in (True, False):
                    batch = app.convert_rules([rule], "snort2", strict, "suricata")
                    self.assertFalse(batch.errors)
                    self.assertEqual(len(batch.rules), 1)
                self.assertIn('content:"b";', app.render_rule(rule, "snort2", "suricata"))

    def test_snort2_buffer_selection_never_creates_a_match_cursor(self):
        for dialect, uri in (("suricata", "http.uri"), ("snort3", "http_uri")):
            for buffer in ("pkt_data", "raw_data", "file_data", "base64_data"):
                for prefix in ("", f'{uri}; content:"old";'):
                    options = prefix + f'{buffer}; content:"relative"; distance:0;'
                    with self.subTest(dialect=dialect, options=options):
                        rule = self.rule(options)
                        for strict in (True, False):
                            batch = app.convert_rules([rule], "snort2", strict, dialect)
                            self.assertEqual(batch.rules, [])
                            self.assertTrue(batch.errors)
                        with self.assertRaises(app.ConverterError):
                            app.render_rule(rule, "snort2", dialect)
        rule = self.rule('content:"relative"; distance:0;')
        with self.assertRaises(app.ConverterError):
            app.render_rule(rule, "snort2", "suricata")

    def test_dce_selection_clears_cursor_pattern_and_http_modifier(self):
        for dialect, uri in (("suricata", "http.uri"), ("snort3", "http_uri")):
            for options in (
                'content:"old"; dce_stub_data; content:"new"; distance:0;',
                'content:"old"; dce_stub_data; flow:to_server; distance:0;',
                f'{uri}; content:"old"; dce_stub_data; nocase;',
                'dce_stub_data; content:!"absent"; content:"new"; within:4;',
                'dce_stub_data; content:"old"; dce_stub_data; pcre:"/x/R";',
            ):
                with self.subTest(dialect=dialect, options=options):
                    rule = self.rule(options)
                    for strict in (True, False):
                        batch = app.convert_rules([rule], "snort2", strict, dialect)
                        self.assertEqual(batch.rules, [])
                        self.assertTrue(batch.errors)
                    with self.assertRaises(app.ConverterError):
                        app.render_rule(rule, "snort2", dialect)
            rule = self.rule(
                f'{uri}; content:"old"; dce_stub_data; content:"fresh"; content:"new"; distance:0;'
            )
            for strict in (True, False):
                self.assertFalse(app.convert_rules([rule], "snort2", strict, dialect).errors)
            output = app.render_rule(rule, "snort2", dialect)
            self.assertIn('dce_stub_data; content:"fresh"; content:"new"; distance:0;', output)

    def test_snort2_dce_payload_survives_backward_http_restoration(self):
        rule = self.rule('dce_stub_data; content:"http"; http_uri; content:"stub";')
        batch = app.convert_rules([rule], "snort3", source_dialect="snort2")
        self.assertFalse(batch.errors)
        output = app.render_rule(rule, "snort3", "snort2")
        self.assertIn('dce_stub_data; content:"stub";', output)
        # Public Suricata conversion still refuses conflicting app protocols.
        self.assertTrue(app.convert_rules([rule], "suricata", source_dialect="snort2").errors)

    def test_explicit_selector_arguments_cannot_bypass_direct_validation(self):
        for selector in app.EXPLICIT_PAYLOAD_SELECTORS:
            for dialect in ("suricata", "snort3"):
                rule = self.rule(f'{selector}:invalid; content:"fresh";')
                with self.subTest(selector=selector, dialect=dialect):
                    for strict in (True, False):
                        self.assertTrue(app.convert_rules([rule], "snort2", strict, dialect).errors)
                    with self.assertRaises(app.ConverterError):
                        app.render_rule(rule, "snort2", dialect)

    def test_ber_cursor_options_are_never_claimed_as_snort2_mappings(self):
        for option in ("ber_data:0x02;", "ber_skip:0x02;", "ber_skip:0x02,optional;"):
            rule = self.rule('content:"old"; ' + option + 'content:"next"; distance:0;')
            for strict in (True, False):
                batch = app.convert_rules([rule], "snort2", strict, "snort3")
                self.assertEqual(batch.rules, [])
                self.assertTrue(batch.errors)
            with self.assertRaises(app.ConverterError):
                app.render_rule(rule, "snort2", "snort3")
            self.assertFalse(app.convert_rules([rule], "snort3", source_dialect="snort3").errors)
            self.assertIn(option, app.render_rule(rule, "snort3", "snort3"))

    def test_neutral_options_never_hide_unproven_relative_content(self):
        for dialect, targets in (
            ("suricata", ("snort2",)),
            ("snort3", ("snort2",)),
            ("snort2", ("snort3", "suricata")),
        ):
            for selector in app.EXPLICIT_PAYLOAD_SELECTORS:
                for pattern in ('"first"', '!"absent"'):
                    for gap in ("flow:to_server;", "metadata:test value;"):
                        for modifier in ("distance:0;", "within:8;"):
                            options = f"{selector}; content:{pattern}; {gap}{modifier}"
                            rule = self.rule(options)
                            for target in targets:
                                with self.subTest(source=dialect, target=target, options=options):
                                    for strict in (True, False):
                                        batch = app.convert_rules([rule], target, strict, dialect)
                                        self.assertEqual(batch.rules, [])
                                        self.assertTrue(batch.errors)
                                    with self.assertRaises(app.ConverterError):
                                        app.render_rule(rule, target, dialect)

    def test_delayed_relative_modifiers_use_the_incoming_match_cursor(self):
        for dialect, targets in (
            ("suricata", ("snort2",)),
            ("snort3", ("snort2",)),
            ("snort2", ("snort3", "suricata")),
        ):
            for selector in ("pkt_data", "file_data", "dce_stub_data"):
                for pattern in ('"second"', '!"absent"'):
                    options = (
                        f'{selector}; content:"first"; content:{pattern}; '
                        "flow:to_server; metadata:test value; distance:0; within:8;"
                    )
                    rule = self.rule(options)
                    for target in targets:
                        with self.subTest(source=dialect, target=target, options=options):
                            for strict in (True, False):
                                self.assertFalse(
                                    app.convert_rules([rule], target, strict, dialect).errors
                                )
                            self.assertIn("distance:0;", app.render_rule(rule, target, dialect))

    def test_snort2_displaced_pattern_modifiers_are_refused_after_selectors(self):
        for dialect, uri, header in (
            ("suricata", "http.uri", "http.header"),
            ("snort3", "http_uri", "http_header"),
        ):
            for modifier in ("distance:0;", "within:5;", "depth:5;", "nocase;", 'replace:"x";'):
                for buffer in (header, uri, "pkt_data", "file_data"):
                    for gap in ("", "flow:to_server;", "metadata:test value;"):
                        options = f'{uri}; content:"old"; {buffer}; {gap}{modifier}'
                        with self.subTest(dialect=dialect, options=options):
                            rule = self.rule(options)
                            for strict in (True, False):
                                batch = app.convert_rules([rule], "snort2", strict, dialect)
                                self.assertEqual(batch.rules, [])
                                self.assertTrue(batch.errors)
                            with self.assertRaises(app.ConverterError):
                                app.render_rule(rule, "snort2", dialect)

    def test_snort2_sticky_noncontent_is_refused_in_direct_and_batch_paths(self):
        for operation in (
            'pcre:"/b/R";',
            "byte_test:1,=,1,0,relative;",
            "byte_extract:1,0,x,relative;",
            "byte_jump:1,0,relative;",
            "byte_math:bytes 1,offset 0,oper +,rvalue 1,result x,relative;",
            "isdataat:1,relative;",
            "base64_decode:bytes 32,relative;",
            "asn1:double_overflow, relative_offset 0;",
            "bufferlen:1,relative;",
        ):
            with self.subTest(operation=operation):
                rule = self.rule('http.uri; content:"a"; ' + operation)
                self.assertTrue(
                    app.convert_rules([rule], "snort2", source_dialect="suricata").errors
                )
                with self.assertRaises(app.ConverterError):
                    app.render_rule(rule, "snort2", "suricata")

    def test_sip_direct_batch_and_transform_share_value_validation(self):
        for key, invalid in (
            ("sip_method", ("", "!INVITE", "INVITE,ACK", "INV1TE", '"!INVITE"')),
            ("sip_stat_code", ("", "!200", "200,404", "0", "1000")),
        ):
            for value in invalid:
                with self.subTest(key=key, value=value):
                    rule = self.rule(f"{key}:{value};")
                    for strict in (True, False):
                        self.assertTrue(
                            app.convert_rules([rule], "suricata", strict, "snort3").errors
                        )
                    with self.assertRaises(app.ConverterError):
                        app.render_rule(rule, "suricata", "snort3")
                    with self.assertRaises(app.ConverterError):
                        app.transform_to_suricata(rule.options, "snort3", rule.protocol)

    def test_sip_valid_single_values_remain_supported(self):
        for key, value in (
            ("sip_method", "INVITE"),
            ("sip_method", '"ack"'),
            ("sip_stat_code", "2"),
            ("sip_stat_code", "200"),
        ):
            with self.subTest(key=key, value=value):
                rule = self.rule(f"{key}:{value};")
                self.assertFalse(
                    app.convert_rules([rule], "suricata", source_dialect="snort3").errors
                )
                self.assertIn("content:", app.render_rule(rule, "suricata", "snort3"))

    def test_sarif_paths_round_trip_without_uri_identity_collisions(self):
        paths = (
            PurePosixPath("/rules/a #?%\u00e9.rules"),
            PurePosixPath("/rules/a%23.rules"),
            PurePosixPath("/rules/a#.rules"),
            PurePosixPath("relative/space #?%\u00e9.rules"),
            PureWindowsPath("C:/rules/a #?%\u00e9.rules"),
            PureWindowsPath("//server/share/a #?%\u00e9.rules"),
        )
        uris = []
        for path in paths:
            with self.subTest(path=str(path)):
                diagnostic = app.Diagnostic("error", "PROBE", "test", str(path), 1, 1)
                report = app.sarif_report(app.ParseResult("<input>"), [diagnostic])
                uri = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                    "artifactLocation"
                ]["uri"]
                parsed = urllib.parse.urlsplit(uri)
                self.assertEqual(parsed.fragment, "")
                self.assertEqual(parsed.query, "")
                decoded = urllib.parse.unquote(parsed.path)
                if isinstance(path, PureWindowsPath):
                    if path.drive.startswith("\\\\"):
                        recovered = "//" + parsed.netloc + decoded
                    else:
                        recovered = decoded.lstrip("/")
                    self.assertEqual(PureWindowsPath(recovered), path)
                else:
                    self.assertEqual(PurePosixPath(decoded), path)
                uris.append(uri)
        self.assertEqual(len(set(uris)), len(paths))

    def redirect(self, handler, url="https://example.test/start", location="/final", code=302):
        request = urllib.request.Request(url)
        request.timeout = 30
        headers = email.message.Message()
        if location is not None:
            headers["Location"] = location
        fp = MagicMock()
        fp.read.side_effect = AssertionError("Redirect entity must not be drained")
        result = getattr(handler, f"http_error_{code}")(request, fp, code, "Redirect", headers)
        return result, fp

    def test_redirect_never_reads_intermediate_body_for_any_supported_status(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                handler = app.RestrictedRedirectHandler({"example.test"})
                handler.add_parent(MagicMock())
                _, fp = self.redirect(handler, code=status)
                fp.read.assert_not_called()
                fp.close.assert_called_once()
                next_request = handler.parent.open.call_args.args[0]
                self.assertEqual(next_request.full_url, "https://example.test/final")

    def test_308_preserves_read_methods_and_never_replays_post_body(self):
        for method in ("GET", "HEAD", "POST"):
            handler = app.RestrictedRedirectHandler({"example.test"})
            parent = MagicMock()
            handler.add_parent(parent)
            request = urllib.request.Request(
                "https://example.test/start",
                method=method,
                data=b"private" if method == "POST" else None,
            )
            request.timeout = 30
            headers = email.message.Message()
            headers["Location"] = "/final"
            fp = MagicMock()
            fp.read.side_effect = AssertionError("Redirect body must not be read")
            with self.subTest(method=method):
                if method == "POST":
                    with self.assertRaises(urllib.error.HTTPError) as rejected:
                        handler.http_error_308(request, fp, 308, "Redirect", headers)
                    self.assertEqual(rejected.exception.code, 308)
                    parent.open.assert_not_called()
                else:
                    handler.http_error_308(request, fp, 308, "Redirect", headers)
                    redirected = parent.open.call_args.args[0]
                    self.assertEqual(redirected.get_method(), method)
                    self.assertIsNone(redirected.data)
                fp.read.assert_not_called()
                fp.close.assert_called_once()

    def test_redirect_invalid_destination_missing_location_loop_and_deadline_fail_closed(self):
        for location in (
            "http://example.test/no",
            "https://evil.test/no",
            "https://user@example.test/no",
            None,
        ):
            with self.subTest(location=location):
                handler = app.RestrictedRedirectHandler({"example.test"})
                handler.add_parent(MagicMock())
                with self.assertRaises(app.ConverterError):
                    self.redirect(handler, location=location)
                handler.parent.open.assert_not_called()
        handler = app.RestrictedRedirectHandler({"example.test"})
        parent = MagicMock()
        handler.add_parent(parent)
        request = urllib.request.Request("https://example.test/start")
        request.timeout = 30
        headers = email.message.Message()
        headers["Location"] = "/loop"
        fp = MagicMock()
        for _ in range(handler.max_redirections):
            try:
                handler.http_error_302(request, fp, 302, "Redirect", headers)
            except app.ConverterError:
                break
            request = parent.open.call_args.args[0]
            request.timeout = 30
        else:
            self.fail("Redirect loop was not bounded")
        fp.read.assert_not_called()
        with (
            patch.object(app.time, "monotonic", return_value=handler.deadline + 1),
            self.assertRaises(app.ConverterError),
        ):
            self.redirect(handler)

    def test_actual_worker_opener_chain_closes_redirect_entities_without_reading(self):
        bodies = []

        class RedirectBody(io.BytesIO):
            def read(self, size=-1):
                raise AssertionError("The actual opener drained an intermediate response")

        class FixtureHTTPS(app.urllib.request.HTTPSHandler):
            def https_open(self, request):
                headers = email.message.Message()
                path = urllib.parse.urlsplit(request.full_url).path
                if path == "/fixture-final":
                    body, code = io.BytesIO(b"harmless"), 200
                    headers["Content-Length"] = "8"
                else:
                    body, code = RedirectBody(), 302
                    headers["Location"] = (
                        "/fixture-final" if path == "/fixture-hop" else "/fixture-hop"
                    )
                bodies.append((body, code))
                response = urllib.response.addinfourl(body, headers, request.full_url, code)
                response.msg = "OK" if code == 200 else "Found"
                return response

        with patch.object(app.urllib.request, "HTTPSHandler", FixtureHTTPS):
            result, metadata = app._download_feed_in_worker(next(iter(app.FEEDS)))
        self.assertEqual(result, b"harmless")
        self.assertEqual(metadata["bytes"], 8)
        self.assertEqual([code for _, code in bodies], [302, 302, 200])
        self.assertTrue(all(body.closed for body, _ in bodies))

    def test_worker_response_read_cannot_reset_download_deadline(self):
        response = MagicMock()
        response.__enter__.return_value = response
        source = next(iter(app.FEEDS))
        response.geturl.return_value = app.FEEDS[source]["url"]
        response.headers = {}
        response.read.return_value = b"late"
        opener = MagicMock()
        opener.open.return_value = response
        with (
            patch.object(app.urllib.request, "build_opener", return_value=opener),
            patch.object(app.time, "monotonic", side_effect=[0, 0, 31]),
            self.assertRaisesRegex(app.ConverterError, "deadline"),
        ):
            app._download_feed_in_worker(source)
        response.read.assert_called_once()

    @staticmethod
    def zip_bytes(count=1, comment=b"", force_zip64=False):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for i in range(count):
                with archive.open(f"rules/{i}.rules", "w", force_zip64=force_zip64) as entry:
                    entry.write(b"harmless")
            archive.comment = comment
        return stream.getvalue()

    def test_zip_many_entries_and_lied_count_refused_before_zipfile_allocation(self):
        payload = self.zip_bytes(5)
        lied = bytearray(payload)
        eocd = lied.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", lied, eocd + 8, 1, 1)
        for data in (payload, bytes(lied)):
            with (
                self.subTest(lied=data != payload),
                patch.object(app, "MAX_ARCHIVE_ENTRIES", 3),
                patch.object(app.zipfile, "ZipFile") as parser,
            ):
                with self.assertRaises(app.ConverterError):
                    app.validate_zip_archive(data)
                parser.assert_not_called()

    def test_zip_valid_comment_prefix_and_local_zip64_controls(self):
        for payload in (
            self.zip_bytes(),
            self.zip_bytes(comment=b"valid comment"),
            b"harmless stub" + self.zip_bytes(),
            self.zip_bytes(force_zip64=True),
        ):
            with self.subTest(size=len(payload)):
                members = app.validate_zip_archive(payload)
                self.assertEqual([x.filename for x in members], ["rules/0.rules"])

    def test_zip_false_prefix_and_malformed_local_headers_fail_before_extraction(self):
        payload = self.zip_bytes()
        eocd = payload.rfind(b"PK\x05\x06")
        directory = payload.find(b"PK\x01\x02")
        corruptions = []
        false_prefix = bytearray(payload)
        original_offset = struct.unpack_from("<L", payload, eocd + 16)[0]
        struct.pack_into("<L", false_prefix, eocd + 16, original_offset - 1)
        corruptions.append(bytes(false_prefix))
        for position, fmt, value in (
            (0, "<4s", b"BAD!"),
            (26, "<H", 65535),
            (28, "<H", 65535),
            (directory + 42, "<L", 1),
        ):
            changed = bytearray(payload)
            struct.pack_into(fmt, changed, position, value)
            corruptions.append(bytes(changed))
        changed = bytearray(payload)
        changed[30:43] = b"rules/9.rules"
        corruptions.append(bytes(changed))
        for data in corruptions:
            with (
                self.subTest(data=data[:30]),
                patch.object(
                    zipfile.ZipExtFile,
                    "read",
                    side_effect=AssertionError("Entity read during header validation"),
                ),
                self.assertRaises(app.ConverterError),
            ):
                app.validate_zip_archive(data)
        with patch.object(
            zipfile.ZipExtFile,
            "read",
            side_effect=AssertionError("Entity read during header validation"),
        ):
            self.assertEqual(app.validate_zip_archive(payload)[0].filename, "rules/0.rules")

    def test_zip_central_disk_start_is_refused_before_zipinfo_allocation(self):
        payload = self.zip_bytes()
        directory = payload.find(b"PK\x01\x02")
        for disk in (1, 65535):
            changed = bytearray(payload)
            struct.pack_into("<H", changed, directory + 34, disk)
            with self.subTest(disk=disk), patch.object(app.zipfile, "ZipFile") as parser:
                with self.assertRaisesRegex(app.ConverterError, "disk"):
                    app.validate_zip_archive(bytes(changed))
                parser.assert_not_called()

    def test_zip64_preflight_valid_and_adversarial_metadata(self):
        payload = self.zip_bytes()
        end = payload.rfind(b"PK\x05\x06")
        size, offset = struct.unpack_from("<LL", payload, end + 12)
        wide = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, size, offset)
        locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, end, 1)
        ordinary = struct.pack(
            "<4s4H2LH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0
        )
        valid = payload[:end] + wide + locator + ordinary
        self.assertEqual(app.validate_zip_archive(valid)[0].filename, "rules/0.rules")
        corruptions = []
        for position, fmt, value in (
            (24, "<QQ", (5, 5)),
            (40, "<Q", (2**40,)),
            (48, "<Q", (2**40,)),
            (4, "<Q", (100,)),
            (56 + 8, "<Q", (0,)),
            (16, "<L", (1,)),
        ):
            corrupted = bytearray(valid)
            struct.pack_into(fmt, corrupted, end + position, *value)
            corruptions.append(bytes(corrupted))
        for data in corruptions:
            with (
                self.subTest(data=data[end : end + 32]),
                patch.object(app, "MAX_ARCHIVE_ENTRIES", 3),
                patch.object(app.zipfile, "ZipFile") as parser,
            ):
                with self.assertRaises(app.ConverterError):
                    app.validate_zip_archive(data)
                parser.assert_not_called()

    def test_zip_directory_byte_budget_precedes_zipinfo_allocation(self):
        data = self.zip_bytes()
        with (
            patch.object(app, "MAX_ZIP_DIRECTORY_BYTES", 8),
            patch.object(app.zipfile, "ZipFile") as parser,
        ):
            with self.assertRaisesRegex(app.ConverterError, "metadata byte"):
                app.validate_zip_archive(data)
            parser.assert_not_called()

    def test_zip_directory_size_truncation_and_declared_count_mismatch_refused_before_parse(self):
        payload = self.zip_bytes()
        eocd = payload.rfind(b"PK\x05\x06")
        bad_size = bytearray(payload)
        struct.pack_into("<L", bad_size, eocd + 12, 0xFFFFFFFF)
        bad_count = bytearray(payload)
        struct.pack_into("<HH", bad_count, eocd + 8, 2, 2)
        for data in (bytes(bad_size), bytes(bad_count), payload[:-1], payload + b"trailing"):
            with self.subTest(size=len(data)), patch.object(app.zipfile, "ZipFile") as parser:
                with self.assertRaises(app.ConverterError):
                    app.validate_zip_archive(data)
                parser.assert_not_called()


if __name__ == "__main__":
    unittest.main()

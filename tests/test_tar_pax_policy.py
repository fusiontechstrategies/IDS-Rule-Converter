"""Ordinary valid PAX archives and deterministic metadata policy models."""

from __future__ import annotations

import gzip
import io
import tarfile
import tempfile
import unittest
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import snort_suricata_rule_converter as app


class TarPaxPolicyTests(unittest.TestCase):
    @staticmethod
    def ordinary_archive(*, global_fields=None):
        output = io.BytesIO()
        contents = {
            "rules/a.rules": b'alert tcp any any -> any any (msg:"a"; sid:1001;)\n',
            "rules/" + "ordinary_" * 15 + "résumé.rules": b"ordinary rule text\n",
        }
        with tarfile.open(
            fileobj=output,
            mode="w:gz",
            format=tarfile.PAX_FORMAT,
            pax_headers=global_fields,
        ) as archive:
            directory = tarfile.TarInfo("rules")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            for name, content in contents.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                member.mtime = 1234.5
                member.pax_headers = {"comment": "ordinary metadata", "ctime": "1234.25"}
                archive.addfile(member, io.BytesIO(content))
        return output.getvalue(), contents

    def test_valid_posix_long_path_and_fractional_metadata_return_minimal_records(self):
        data, contents = self.ordinary_archive(global_fields={"uname": "ordinary-owner"})
        admitted = app.validate_tar_archive(data)
        self.assertEqual({item.name for item in admitted if item.isfile()}, set(contents))
        self.assertTrue(admitted[0].isdir())
        self.assertEqual(
            [item.name for item in fields(app.AdmittedTarMember)], ["name", "type", "size"]
        )
        for member in admitted:
            self.assertIsInstance(member, app.AdmittedTarMember)
            self.assertFalse(hasattr(member, "pax_headers"))
            self.assertFalse(hasattr(member, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            admitted[0].name = "changed"

    def test_ordinary_pax_archive_decodes_into_complete_generation(self):
        data, contents = self.ordinary_archive(global_fields={"gname": "ordinary-group"})
        with tempfile.TemporaryDirectory() as directory:
            root = app.canonical_system_path(Path(directory).absolute())
            written = app.extract_archive(data, "tar.gz", root, False)
            self.assertEqual(len(written), len(contents))
            generations = list(root.glob("generation-*"))
            self.assertEqual(len(generations), 1)
            self.assertFalse(list(root.glob(".ids-stage-*")))
            for name, content in contents.items():
                self.assertEqual((generations[0] / name).read_bytes(), content)

    def test_independent_valid_decode_matches_admission_without_metadata_retention(self):
        data, contents = self.ordinary_archive(global_fields={"uid": "1001", "uname": "owner"})
        admitted = app.validate_tar_archive(data)
        decoded = {}
        index = 0
        with (
            gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed,
            tarfile.open(
                fileobj=app.DecompressionBudget(compressed), mode="r|", tarinfo=app.BoundedTarInfo
            ) as archive,
        ):
            while (member := app.next_tar_member(archive)) is not None:
                self.assertEqual(archive.members, [])
                self.assertEqual(member.pax_headers, {})
                expected = admitted[index]
                self.assertEqual(
                    (member.name, member.type, member.size),
                    (expected.name, expected.type, expected.size),
                )
                index += 1
                if member.isfile():
                    with archive.extractfile(member) as content:
                        decoded[member.name] = content.read(member.size + 1)
        self.assertEqual(index, len(admitted))
        self.assertEqual(decoded, contents)

    def test_effective_budget_refuses_before_standard_application(self):
        member = app.BoundedTarInfo("ordinary.rules")
        member._ids_archive = SimpleNamespace(_ids_pax_applications=1)
        with (
            patch.object(app, "MAX_TAR_PAX_APPLICATIONS", 1),
            patch.object(tarfile.TarInfo, "_apply_pax_info") as application,
            self.assertRaisesRegex(app.ConverterError, "effective application budget"),
        ):
            member._apply_pax_info({"uname": "owner"}, "utf-8", "strict")
        application.assert_not_called()

    def test_global_and_local_field_work_share_one_cumulative_budget(self):
        archive = SimpleNamespace()
        with patch.object(app, "MAX_TAR_PAX_APPLICATIONS", 2):
            app.charge_pax_application(archive, {"uname": "owner"})
            app.charge_pax_application(archive, {"mtime": "1234.5"})
            self.assertEqual(archive._ids_pax_applications, 2)
            with self.assertRaisesRegex(app.ConverterError, "effective application budget"):
                app.charge_pax_application(archive, {"comment": "ordinary"})
        self.assertEqual(archive._ids_pax_applications, 2)

    def test_field_counter_refuses_before_reading_a_second_valid_field(self):
        # This is metadata from a small valid two-field PAX record, not an
        # archive with dense metadata or a resource-exhaustion payload.
        raw = tarfile.TarInfo._create_pax_generic_header(
            {"uname": "owner", "gname": "group"}, tarfile.XHDTYPE, "utf-8"
        )
        member = app.BoundedTarInfo.frombuf(raw[:512], "utf-8", "strict")
        archive = SimpleNamespace(fileobj=io.BytesIO(raw[512:]), pax_headers={})
        with (
            patch.object(app, "MAX_TAR_PAX_FIELDS", 1),
            patch.object(app.BoundedTarInfo, "fromtarfile") as following_member,
            self.assertRaisesRegex(app.ConverterError, "object budget"),
        ):
            member._proc_pax(archive)
        following_member.assert_not_called()
        self.assertEqual(archive._ids_pax_fields, 1)

    def test_archive_field_counter_is_independent_of_current_header_counter(self):
        raw = tarfile.TarInfo._create_pax_generic_header(
            {"uname": "owner"}, tarfile.XHDTYPE, "utf-8"
        )
        member = app.BoundedTarInfo.frombuf(raw[:512], "utf-8", "strict")
        archive = SimpleNamespace(fileobj=io.BytesIO(raw[512:]), pax_headers={}, _ids_pax_fields=1)
        with (
            patch.object(app, "MAX_TAR_PAX_TOTAL_FIELDS", 1),
            patch.object(app.BoundedTarInfo, "fromtarfile") as following_member,
            self.assertRaisesRegex(app.ConverterError, "object budget"),
        ):
            member._proc_pax(archive)
        following_member.assert_not_called()

    def test_sparse_and_unsupported_fields_refuse_before_touching_values(self):
        class UndecodedValue:
            def __len__(self):
                raise AssertionError("A refused field's value was inspected")

            def decode(self, *args):
                raise AssertionError("A refused field's value was decoded")

        for keyword in (
            "GNU.sparse.size",
            "GNU.sparse.map",
            "GNU.sparse.major",
            "GNU.sparse.minor",
            "GNU.sparse.realsize",
            "GNU.sparse.name",
            "GNU.sparse.offset",
            "GNU.sparse.numbytes",
            "GNU.sparse.numblocks",
            "SCHILY.realsize",
            "unreviewed.vendor",
        ):
            with self.subTest(keyword=keyword), self.assertRaises(app.ConverterError):
                app.admitted_pax_value(keyword, UndecodedValue(), global_header=False)
        for keyword in ("path", "linkpath", "size"):
            with self.subTest(global_keyword=keyword), self.assertRaises(app.ConverterError):
                app.admitted_pax_value(keyword, UndecodedValue(), global_header=True)

    def test_value_length_refuses_before_decoding(self):
        class UnreadValue:
            def __len__(self):
                return app.MAX_TAR_PAX_VALUE_BYTES + 1

            def decode(self, *args):
                raise AssertionError("An over-budget value was decoded")

        with self.assertRaisesRegex(app.ConverterError, "value exceeds"):
            app.admitted_pax_value("comment", UnreadValue(), global_header=False)

    def test_bounded_posix_integer_timestamp_and_charset_policy(self):
        admitted = {
            "size": b"42",
            "uid": b"1001",
            "gid": b"1002",
            "mtime": b"1234.25",
            "atime": b"1234",
            "ctime": b"-1.5",
            "hdrcharset": b"ISO-IR 10646 2000 UTF-8",
        }
        for keyword, raw_value in admitted.items():
            with self.subTest(keyword=keyword):
                self.assertEqual(
                    app.admitted_pax_value(keyword, raw_value, global_header=False),
                    raw_value.decode("utf-8"),
                )
        for keyword, raw_value in (("size", b"-1"), ("mtime", b"nan"), ("hdrcharset", b"BINARY")):
            with self.subTest(refused=keyword), self.assertRaises(app.ConverterError):
                app.admitted_pax_value(keyword, raw_value, global_header=False)

    def test_global_dictionary_policy_refuses_before_a_dictionary_copy(self):
        class UnsupportedGlobalFields(dict):
            def copy(self):
                raise AssertionError("Unsupported global metadata was copied")

        member = app.BoundedTarInfo("ordinary-pax")
        member.type = tarfile.XHDTYPE
        member.size = 0
        archive = SimpleNamespace(
            fileobj=io.BytesIO(), pax_headers=UnsupportedGlobalFields({"path": "rules/a.rules"})
        )
        with self.assertRaisesRegex(app.ConverterError, "global PAX metadata"):
            member._proc_pax(archive)

    def test_streaming_next_releases_the_standard_cache(self):
        member = app.BoundedTarInfo("ordinary.rules")

        class CachedArchive:
            def __init__(self):
                self.members = [app.BoundedTarInfo("prior.rules")]

            def next(self):
                self.assert_empty_before = not self.members
                self.assert_reset_before = self._ids_extension_count == 0
                self.members.append(member)
                return member

        archive = CachedArchive()
        self.assertIs(app.next_tar_member(archive), member)
        self.assertTrue(archive.assert_empty_before)
        self.assertTrue(archive.assert_reset_before)
        self.assertEqual(archive.members, [])

    def test_streaming_next_releases_cache_when_parsing_refuses(self):
        class RefusingArchive:
            def __init__(self):
                self.members = []

            def next(self):
                self.members.append(app.BoundedTarInfo("ordinary.rules"))
                raise app.ConverterError("controlled refusal")

        archive = RefusingArchive()
        with self.assertRaisesRegex(app.ConverterError, "controlled refusal"):
            app.next_tar_member(archive)
        self.assertEqual(archive.members, [])

    def test_builtin_entry_count_refuses_before_member_application(self):
        member = app.BoundedTarInfo("ordinary.rules")
        archive = SimpleNamespace(_ids_member_count=1)
        with (
            patch.object(app, "MAX_ARCHIVE_ENTRIES", 1),
            patch.object(tarfile.TarInfo, "_proc_builtin") as application,
            self.assertRaisesRegex(app.ConverterError, "entry limit"),
        ):
            member._proc_builtin(archive)
        application.assert_not_called()

    def test_modern_pax_following_header_precedes_effective_local_path(self):
        # The following header is a typed protocol model. Only this small,
        # ordinary valid PAX path record is serialized or parsed.
        events = []

        class ModeledMember(app.BoundedTarInfo):
            def _apply_pax_info(self, metadata, encoding, errors):
                events.append(("application", self.type, self.name))
                return super()._apply_pax_info(metadata, encoding, errors)

        following = ModeledMember("fallback/")
        following.type = tarfile.AREGTYPE
        following.size = 1

        class ModernPaxInfo(app.BoundedTarInfo):
            @classmethod
            def _fromtarfile(cls, archive, *, dircheck=True):
                events.append(("following", dircheck))
                if dircheck:
                    following.type = tarfile.DIRTYPE
                following._ids_archive = archive
                return following

            @classmethod
            def fromtarfile(cls, archive):
                raise AssertionError("The modern public reader was used for a PAX follow")

        raw = tarfile.TarInfo._create_pax_generic_header(
            {"path": "rules/effective.rules"}, tarfile.XHDTYPE, "utf-8"
        )
        header = ModernPaxInfo.frombuf(raw[:512], "utf-8", "strict")
        archive = SimpleNamespace(
            fileobj=io.BytesIO(raw[512:]), pax_headers={}, encoding="utf-8", errors="strict"
        )
        member = header._proc_pax(archive)
        self.assertIs(member, following)
        self.assertEqual(
            events, [("following", False), ("application", tarfile.AREGTYPE, "fallback/")]
        )
        self.assertEqual(
            (member.name, member.type, member.size), ("rules/effective.rules", b"\0", 1)
        )
        self.assertEqual(member.pax_headers, {})
        self.assertEqual(archive._ids_pax_applications, 1)

    def test_older_pax_following_header_retains_public_protocol(self):
        calls = []
        member = SimpleNamespace(name="fallback/", type=tarfile.AREGTYPE)

        class OlderProtocol:
            def fromtarfile(self, archive):
                calls.append(archive)
                # Model the older parser's existing legacy inference without
                # serializing or executing an edge-case archive.
                if member.type == tarfile.AREGTYPE and member.name.endswith("/"):
                    member.type = tarfile.DIRTYPE
                    member.name = member.name.rstrip("/")
                return member

        archive = object()
        self.assertIs(app.read_pax_following_member(OlderProtocol(), archive), member)
        self.assertEqual(calls, [archive])
        self.assertEqual((member.name, member.type), ("fallback", tarfile.DIRTYPE))

    def test_modern_pax_reader_refusal_does_not_use_older_fallback(self):
        class RefusingModernProtocol:
            def _fromtarfile(self, archive, *, dircheck):
                self.dircheck = dircheck
                raise TypeError("controlled modern protocol refusal")

            def fromtarfile(self, archive):
                raise AssertionError("A modern protocol failure was silently retried")

        reader = RefusingModernProtocol()
        with self.assertRaisesRegex(TypeError, "controlled modern protocol refusal"):
            app.read_pax_following_member(reader, object())
        self.assertFalse(reader.dircheck)

    def test_raw_charset_range_admits_exact_bytes_at_bounded_offsets(self):
        value = app.TAR_PAX_UTF8_CHARSET
        buffer = b"prefix" + value + b"suffix"
        self.assertIsNone(app.require_pax_charset_range(buffer, 6, 6 + len(value)))

    def test_refused_raw_charset_range_never_slices_or_decodes(self):
        class RawRangeModel:
            def __init__(self):
                self.comparisons = []

            def startswith(self, expected, start, end):
                self.comparisons.append((expected, start, end))
                return False

            def __getitem__(self, key):
                raise AssertionError("A refused charset range was sliced")

            def decode(self, *args):
                raise AssertionError("A refused charset range was decoded")

        buffer = RawRangeModel()
        with self.assertRaisesRegex(app.ConverterError, "POSIX UTF-8"):
            app.require_pax_charset_range(buffer, 4, 4 + len(app.TAR_PAX_UTF8_CHARSET))
        self.assertEqual(
            buffer.comparisons, [(app.TAR_PAX_UTF8_CHARSET, 4, 4 + len(app.TAR_PAX_UTF8_CHARSET))]
        )
        buffer.comparisons.clear()
        with self.assertRaisesRegex(app.ConverterError, "POSIX UTF-8"):
            app.require_pax_charset_range(buffer, 0, len(b"BINARY"))
        self.assertEqual(buffer.comparisons, [])

    def test_charset_value_refuses_before_decode(self):
        class UndecodedCharset:
            def __init__(self, length):
                self.length = length
                self.comparisons = 0

            def __len__(self):
                return self.length

            def startswith(self, *args):
                self.comparisons += 1
                return False

            def decode(self, *args):
                raise AssertionError("An unsupported charset was decoded")

        for length, comparisons in ((len(b"BINARY"), 0), (len(app.TAR_PAX_UTF8_CHARSET), 1)):
            value = UndecodedCharset(length)
            with (
                self.subTest(length=length),
                self.assertRaisesRegex(app.ConverterError, "POSIX UTF-8"),
            ):
                app.admitted_pax_value("hdrcharset", value, global_header=False)
            self.assertEqual(value.comparisons, comparisons)

    def test_charset_length_refuses_before_comparison_or_decode(self):
        class OverBudgetCharset:
            def __len__(self):
                return app.MAX_TAR_PAX_VALUE_BYTES + 1

            def startswith(self, *args):
                raise AssertionError("An over-budget charset was compared")

            def decode(self, *args):
                raise AssertionError("An over-budget charset was decoded")

        with self.assertRaisesRegex(app.ConverterError, "value exceeds"):
            app.admitted_pax_value("hdrcharset", OverBudgetCharset(), global_header=False)

    def test_valid_charset_raw_admission_precedes_parser_value_slice(self):
        raw = tarfile.TarInfo._create_pax_generic_header(
            {"hdrcharset": app.TAR_PAX_UTF8_CHARSET.decode("ascii")}, tarfile.XHDTYPE, "utf-8"
        )
        header = app.BoundedTarInfo.frombuf(raw[:512], "utf-8", "strict")
        body = raw[512:]
        charset_range = slice(body.find(b"=") + 1, header.size - 1)
        events = []

        class GuardedValidBody:
            def __len__(self):
                return len(body)

            def find(self, *args):
                return body.find(*args)

            def startswith(self, expected, start, end):
                self.assert_range = (expected, start, end)
                events.append("raw_charset")
                return body.startswith(expected, start, end)

            def __getitem__(self, key):
                if key == charset_range:
                    if events != ["raw_charset"]:
                        raise AssertionError("The charset value was sliced before raw admission")
                    events.append("charset_slice")
                return body[key]

        guarded = GuardedValidBody()

        def read_valid_body(size):
            self.assertEqual(size, len(body))
            return guarded

        archive = SimpleNamespace(
            fileobj=SimpleNamespace(read=read_valid_body),
            pax_headers={},
            encoding="utf-8",
            errors="strict",
        )
        following = app.BoundedTarInfo("ordinary.rules")
        following._ids_archive = archive
        with patch.object(app, "read_pax_following_member", return_value=following):
            self.assertIs(header._proc_pax(archive), following)
        self.assertEqual(events, ["raw_charset", "charset_slice"])
        self.assertEqual(
            guarded.assert_range,
            (app.TAR_PAX_UTF8_CHARSET, charset_range.start, charset_range.stop),
        )
        self.assertEqual(following.pax_headers, {})


if __name__ == "__main__":
    unittest.main()

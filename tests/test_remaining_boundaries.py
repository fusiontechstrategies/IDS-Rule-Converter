"""Offline output ancestry, generation, service ambiguity and decoder regressions."""

import hashlib
import io
import json
import os
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import snort_suricata_rule_converter as app
from scripts import verify_distribution as verifier

RULE = 'alert tcp any any -> any any (msg:"test"; content:"test"; nocase; sid:1001;)'


class RemainingBoundaries(unittest.TestCase):
    def test_conflicting_service_protocols_are_rejected(self):
        parsed = app.RuleParser().parse_text(
            RULE.replace("sid:1001;", "service:http; service:dns; sid:1001;")
        )
        result = app.convert_rules(parsed.rules, "suricata")
        self.assertEqual(result.rules, [])
        self.assertTrue(result.rejected_rule_indexes)

    def test_identical_service_protocols_emit_once(self):
        parsed = app.RuleParser().parse_text(
            RULE.replace("sid:1001;", "service:http; service:http; sid:1001;")
        )
        result = app.convert_rules(parsed.rules, "suricata")
        self.assertEqual(len(result.rules), 1)
        self.assertEqual(result.rules[0].count("app-layer-protocol:http;"), 1)

    def test_zip_parameterized_decoder_rejected_before_extraction(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_LZMA) as archive:
            archive.writestr("rule.rules", RULE)
        with self.assertRaisesRegex(app.ConverterError, "decoder"):
            app.validate_zip_archive(stream.getvalue())

    def test_stream_declared_size_and_independent_budget(self):
        for content, declared in ((b"long", 3), (b"short", 8)):
            with self.subTest(declared=declared), self.assertRaises(app.ConverterError):
                app.write_output_payload(io.BytesIO(), io.BytesIO(content), declared)

    @unittest.skipIf(os.name == "nt", "POSIX directory authority")
    def test_private_leaf_under_unsafe_ancestor_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            unsafe = Path(directory) / "shared"
            unsafe.mkdir(mode=0o777)
            unsafe.chmod(0o777)
            leaf = unsafe / "private"
            leaf.mkdir(mode=0o700)
            try:
                with self.assertRaisesRegex(app.ConverterError, "ancestry"):
                    app.atomic_write_text(leaf / "result", "synthetic")
                self.assertEqual(list(leaf.iterdir()), [])
            finally:
                unsafe.chmod(0o700)

    def test_stale_panorama_generation_refused_even_with_force(self):
        for stale_name in ("panorama_batch_9999.rules", "panorama_rejected.rules"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, output = root / "input", root / "output"
                source.write_text(RULE)
                output.mkdir()
                stale = output / stale_name
                stale.write_text("prior generation")
                result = app.main(
                    ["panorama-preflight", str(source), "--output-dir", str(output), "--force"]
                )
                self.assertEqual(result, app.EXIT_OPERATIONAL_ERROR)
                self.assertEqual(stale.read_text(), "prior generation")
                self.assertEqual(list(output.iterdir()), [stale])

    def test_panorama_manifest_binds_current_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input", root / "output"
            source.write_text(RULE)
            self.assertEqual(
                app.main(["panorama-preflight", str(source), "--output-dir", str(output)]),
                app.EXIT_OK,
            )
            manifest = json.loads((output / "panorama_manifest.json").read_text())
            self.assertEqual(len(manifest["generation_id"]), 32)
            self.assertEqual(
                set(manifest["sha256"]),
                {p.name for p in output.iterdir()} - {"panorama_manifest.json"},
            )
            for name, digest in manifest["sha256"].items():
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)


@unittest.skipUnless(os.name == "nt", "Actual Windows pinned-handle ACL inspection")
class WindowsParentSecurity(unittest.TestCase):
    def test_actual_private_dacl_passes_and_second_sid_mutation_fails(self):
        import ctypes.wintypes

        wintypes = ctypes.wintypes
        sid = app.current_windows_sid()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        security = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        ]
        security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        security.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        security.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        security.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            ctypes.c_int,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        security.SetNamedSecurityInfoW.restype = wintypes.DWORD
        with tempfile.TemporaryDirectory() as directory:
            parent = app.windows_private_report_directory(Path(directory), sid)
            try:
                with app.windows_report_directory_lock(
                    parent, parent_sid=sid, require_user_owner=True
                ):
                    pass
                for mask, require_owner in ((0x40, True), (0x2, False), (0x100, False)):
                    descriptor = ctypes.c_void_p()
                    sddl = f"D:P(A;OICI;FA;;;{sid})(A;;0x{mask:x};;;S-1-5-21-111111111-222222222-333333333-1234)"
                    self.assertTrue(
                        security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                            sddl, 1, ctypes.byref(descriptor), None
                        )
                    )
                    try:
                        present, defaulted, dacl = (
                            wintypes.BOOL(),
                            wintypes.BOOL(),
                            ctypes.c_void_p(),
                        )
                        self.assertTrue(
                            security.GetSecurityDescriptorDacl(
                                descriptor,
                                ctypes.byref(present),
                                ctypes.byref(dacl),
                                ctypes.byref(defaulted),
                            )
                        )
                        self.assertEqual(
                            security.SetNamedSecurityInfoW(
                                str(parent), 1, 0x80000004, None, None, dacl, None
                            ),
                            0,
                        )
                    finally:
                        kernel.LocalFree(descriptor)
                    with (
                        self.subTest(mask=mask),
                        self.assertRaisesRegex(app.ConverterError, "another user"),
                        app.windows_report_directory_lock(
                            parent, parent_sid=sid, require_user_owner=require_owner
                        ),
                    ):
                        pass
            finally:
                parent.rmdir()


class ArchiveBudgetTests(unittest.TestCase):
    def test_zip64_legacy_zero_record_is_rejected_before_zipfile(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "test.whl"
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                for index in range(5000):
                    archive.writestr(str(index), b"x")
            raw = stream.getvalue()
            end = len(raw) - 22
            _, _, _, _, count, cd_bytes, cd_offset, _ = struct.unpack("<4s4H2LH", raw[end:])
            zip64 = struct.pack(
                "<4sQ2H2L4Q",
                b"PK\x06\x06",
                44,
                45,
                45,
                0,
                0,
                count,
                count,
                cd_bytes,
                cd_offset,
            )
            locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, end, 1)
            for comment_size in (0, 65516, 65535):
                legacy_zero = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, comment_size)
                crafted = raw[:end] + zip64 + locator + legacy_zero + b"x" * comment_size
                with zipfile.ZipFile(io.BytesIO(crafted)) as archive:
                    self.assertEqual(len(archive.infolist()), 5000)
                wheel.write_bytes(crafted)
                with (
                    self.subTest(comment_size=comment_size),
                    patch.object(
                        verifier.zipfile, "ZipFile", side_effect=AssertionError("too late")
                    ),
                    self.assertRaisesRegex(ValueError, "ZIP64"),
                    verifier.bounded_wheel(wheel),
                ):
                    pass

    def test_zip_member_decoder_size_and_count_budgets(self):
        for kind in ("decoder", "size", "count"):
            with tempfile.TemporaryDirectory() as directory:
                wheel = Path(directory) / "test.whl"
                compression = zipfile.ZIP_LZMA if kind == "decoder" else zipfile.ZIP_DEFLATED
                with zipfile.ZipFile(wheel, "w", compression=compression) as archive:
                    if kind == "count":
                        for index in range(verifier.MAX_ARCHIVE_MEMBERS + 1):
                            archive.writestr(str(index), b"x")
                    else:
                        archive.writestr(
                            "member",
                            b"x" * (verifier.MAX_MEMBER_BYTES + 1 if kind == "size" else 1),
                        )
                with self.assertRaises(ValueError), verifier.bounded_wheel(wheel):
                    pass

    def test_tar_declared_size_budget_precedes_contents_read(self):
        with tempfile.TemporaryDirectory() as directory:
            sdist = Path(directory) / "test.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                member = tarfile.TarInfo("member")
                member.size = verifier.MAX_MEMBER_BYTES + 1
                archive.addfile(member, io.BytesIO(b"x" * member.size))
            with self.assertRaises(ValueError), verifier.bounded_sdist(sdist):
                pass

    def test_invisible_pax_expansion_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            sdist = Path(directory) / "test.tar.gz"
            with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                member = tarfile.TarInfo("member")
                member.pax_headers = {"comment": "x" * (verifier.MAX_EXPANDED_BYTES + 1)}
                archive.addfile(member)
            with self.assertRaises(ValueError), verifier.bounded_sdist(sdist):
                pass


if __name__ == "__main__":
    unittest.main()

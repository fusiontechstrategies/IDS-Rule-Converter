from __future__ import annotations

import contextlib
import ctypes
import ctypes.wintypes
import hashlib
import io
import json
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import patch

import snort_suricata_rule_converter as app

RULE = 'alert tcp any any -> any 80 (msg:"ordinary"; content:"fixture"; sid:9001;)'


def canonical_tar() -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        member = tarfile.TarInfo("rules/ordinary.rules")
        member.size = len(RULE.encode())
        archive.addfile(member, io.BytesIO(RULE.encode()))
    return stream.getvalue()


def cli(arguments: list[str]) -> tuple[int, str]:
    errors = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
        result = app.main(arguments)
    return result, errors.getvalue()


class GzipCompletionModel:
    def __init__(self, values: list[bytes | Exception]):
        self.values = values
        self.reads: list[int] = []
        self.events: list[str] = []

    def __enter__(self):
        self.events.append("gzip-open")
        return self

    def __exit__(self, kind, error, traceback):
        self.events.append("gzip-close")
        return False

    def read(self, size: int) -> bytes:
        index = len(self.reads)
        self.reads.append(size)
        value = self.values[index]
        if isinstance(value, Exception):
            raise value
        return value


class TarEndModel:
    def __init__(self, events: list[str]):
        self.members = []
        self.events = events

    def __enter__(self):
        self.events.append("tar-open")
        return self

    def __exit__(self, kind, error, traceback):
        self.events.append("tar-close")
        return False

    def next(self):
        self.events.append("tar-end")
        return None


def modeled_preflight(data: bytes, stream: GzipCompletionModel) -> list[app.AdmittedTarMember]:
    with (
        patch.object(app.gzip, "GzipFile", return_value=stream),
        patch.object(app.tarfile, "open", return_value=TarEndModel(stream.events)) as opened,
    ):
        result = app.validate_tar_archive(data)
    self_bound = opened.call_args.kwargs["fileobj"]
    if not isinstance(self_bound, app.DecompressionBudget):
        raise AssertionError("TAR preflight did not retain its bounded reader")
    return result


class FetchRootModel:
    """Sequential ordinary identities and errors; no native path substitution."""

    def __init__(
        self,
        platform: str,
        *,
        changed=False,
        content=False,
        existing=False,
        unknown=False,
        inner_close=False,
        parent_close=False,
        acquisition=False,
    ):
        self.platform = platform
        self.changed, self.content, self.existing, self.unknown = (
            changed,
            content,
            existing,
            unknown,
        )
        self.inner_close, self.parent_close, self.acquisition = (
            inner_close,
            parent_close,
            acquisition,
        )
        self.events: list[str] = []
        self.stat_calls = 0
        self.open_calls = 0
        self.created = False
        self.removed = False
        self.primary = app.ConverterError("ordinary extraction model failure")
        self.original_cause = ValueError("ordinary source cause")
        self.primary.__cause__ = self.original_cause
        self.output = Path("C:/ordinary-model")

    @contextlib.contextmanager
    def parent(self, path, api):
        self.events.append("parent-open")
        if self.acquisition:
            raise OSError("ordinary parent acquisition failure")
        try:
            yield 101
        finally:
            self.events.append("parent-close")
            if self.parent_close:
                raise OSError("ordinary parent close failure")

    def mkdir(self, name, mode, *, dir_fd):
        self.events.append("mkdir")
        if self.existing:
            raise FileExistsError("ordinary preexisting root")
        self.created = True

    def info(self, changed=False):
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_dev=3, st_ino=5 if changed else 4)

    def named_stat(self, name, *, dir_fd, follow_symlinks):
        self.stat_calls += 1
        self.events.append("named-identity")
        if self.unknown and self.stat_calls == 1:
            raise OSError("ordinary creation identity read failure")
        return self.info(self.changed and self.stat_calls > 1)

    def fstat(self, descriptor):
        self.events.append("opened-identity")
        return self.info(self.changed and self.open_calls > 1)

    @contextlib.contextmanager
    def descriptor(self, *args, **kwargs):
        self.open_calls += 1
        creation = self.open_calls == 1
        self.events.append("root-open" if creation else "cleanup-open")
        try:
            yield SimpleNamespace(fileno=lambda: 102)
        finally:
            self.events.append("root-close" if creation else "cleanup-close")
            if creation and self.inner_close:
                raise OSError("ordinary root close failure")

    def rmdir(self, name, *, dir_fd):
        self.events.append("rmdir")
        if self.content:
            raise OSError("ordinary modeled nonempty root")
        self.removed = True

    @contextlib.contextmanager
    def object(
        self, parent, name, *, directory, create=False, delete=False, private=False, on_created=None
    ):
        role = "created" if create else "delete" if delete else "cleanup"
        self.events.append("object-" + role)
        if create:
            if self.existing:
                raise FileExistsError("ordinary preexisting root")
            self.created = True
        try:
            if create and on_created is not None:
                on_created(role)
            yield role
        finally:
            self.events.append("close-" + role)
            if create and self.inner_close:
                raise OSError("ordinary root close failure")

    def identity(self, handle):
        self.events.append("identity-" + handle)
        if handle == "created" and self.unknown:
            raise OSError("ordinary creation identity read failure")
        return 3, 5 if self.changed and handle != "created" else 4

    def dispose(self, handle):
        self.events.append("dispose")
        if self.content:
            raise OSError("ordinary modeled nonempty root")
        self.removed = True

    def run(self, fail=True):
        with (
            patch.object(app.os, "name", self.platform),
            patch.object(app.os, "O_DIRECTORY", 0x1000, create=True),
            patch.object(app.os, "O_NOFOLLOW", 0x2000, create=True),
            patch.object(app, "_archive_root_namespace", side_effect=self.parent),
            patch.object(app, "_WindowsArchiveApi", return_value=self),
            patch.object(app, "_input_directory_descriptor", side_effect=self.descriptor),
            patch.object(app.os, "mkdir", side_effect=self.mkdir),
            patch.object(app.os, "stat", side_effect=self.named_stat),
            patch.object(app.os, "fstat", side_effect=self.fstat),
            patch.object(app.os, "rmdir", side_effect=self.rmdir),
            app._fetch_extraction_root(self.output, "sample") as root,
        ):
            self.events.append("body")
            if fail:
                raise self.primary from self.original_cause
            self.events.append("committed")
        return root


class LineTailPolicy(unittest.TestCase):
    def test_lf_and_crlf_keep_comments_quotes_records_and_provenance(self):
        for boundary in ("\n", "\r\n"):
            with self.subTest(boundary=repr(boundary)):
                ordinary = [
                    "# ordinary heading",
                    RULE,
                    "/* ordinary comment */",
                    RULE.replace("9001", "9002"),
                ]
                text = boundary.join(ordinary) + boundary
                parsed = app.RuleParser().parse_text(text)
                self.assertFalse(parsed.errors)
                self.assertEqual([r.sid for r in parsed.rules], [9001, 9002])
                self.assertEqual(
                    [(r.start_line, r.end_line) for r in parsed.rules], [(2, 2), (4, 4)]
                )
                self.assertEqual(parsed.source_sha256, hashlib.sha256(text.encode()).hexdigest())
                self.assertEqual(parsed.byte_count, len(text.encode()))
                self.assertEqual(
                    len(app.convert_rules(parsed, "snort3", source_dialect="snort2").rules), 2
                )
        quoted = RULE.replace('"ordinary"', '"literal # and /* plus \\r"') + "\r\n"
        self.assertIn('"literal # and /* plus \\r"', app.strip_rule_comments(quoted))
        self.assertFalse(app.RuleParser().parse_text(quoted).errors)

    def test_lone_cr_is_a_complete_blocking_parse_not_partial_output(self):
        text = RULE + "\r" + RULE.replace("9001", "9002") + "\r"
        parsed = app.RuleParser().parse_text(text)
        self.assertEqual(parsed.rules, [])
        self.assertEqual([d.code for d in parsed.errors], ["UNSUPPORTED_LINE_BOUNDARY"])
        self.assertTrue(parsed._parse_context.has_errors)
        self.assertEqual(parsed.source_sha256, hashlib.sha256(text.encode()).hexdigest())
        for strict in (True, False):
            with self.subTest(strict=strict):
                converted = app.convert_rules(parsed, "snort3", strict, "snort2")
                self.assertTrue(converted.errors)
                self.assertEqual(converted.rules, [])
        parsed.diagnostics.clear()
        self.assertTrue(app.convert_rules(parsed, "snort3", False, "snort2").errors)
        self.assertTrue(
            app.convert_rules(parsed, "snort3", False, "snort2", allow_detached_rules=True).errors
        )

    def test_direct_comment_and_record_scanners_share_boundary_refusal(self):
        text = RULE + "\r"
        self.assertRaises(app.UnsupportedLineBoundary, app.strip_rule_comments, text)
        result = app.ParseResult(source="ordinary")
        records = app.RuleParser()._records(text, result)
        self.assertRaises(app.UnsupportedLineBoundary, next, records)
        self.assertEqual(result.rules, [])

    def test_other_text_line_separators_are_explicitly_unsupported(self):
        for boundary in "\v\f\x1c\x1d\x1e\x85\u2028\u2029":
            with self.subTest(boundary=repr(boundary)):
                parsed = app.RuleParser().parse_text(RULE + boundary)
                self.assertEqual([d.code for d in parsed.errors], ["UNSUPPORTED_LINE_BOUNDARY"])
                self.assertEqual(parsed.rules, [])
        quoted = RULE.replace('"ordinary"', '"ordinary\rtext"')
        self.assertEqual(
            [d.code for d in app.RuleParser().parse_text(quoted).errors],
            ["UNSUPPORTED_LINE_BOUNDARY"],
        )

    def test_accepted_file_snapshots_keep_exact_bom_and_line_bytes(self):
        for boundary in ("\n", "\r\n"):
            with self.subTest(boundary=repr(boundary)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "ordinary.rules"
                data = b"\xef\xbb\xbf" + (RULE + boundary).encode()
                path.write_bytes(data)
                parsed = app.RuleParser().parse_file(path)
                self.assertFalse(parsed.errors)
                self.assertEqual(parsed.byte_count, len(data))
                self.assertEqual(parsed.source_sha256, hashlib.sha256(data).hexdigest())
                self.assertEqual(parsed.input_identity.sha256, parsed.source_sha256)
                self.assertEqual(parsed.input_identity.byte_count, len(data))
                self.assertEqual(path.read_bytes(), data)

    def test_lone_cr_file_blocks_strict_non_strict_and_json_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ordinary.rules"
            data = (RULE + "\r").encode()
            path.write_bytes(data)
            parsed = app.RuleParser().parse_file(path)
            self.assertEqual(parsed.source_sha256, hashlib.sha256(data).hexdigest())
            self.assertEqual(parsed.input_identity.byte_count, len(data))
            for target, permissive in (("snort3", False), ("snort3", True), ("json", False)):
                with self.subTest(target=target, permissive=permissive):
                    output = Path(directory) / f"{target}-{permissive}.rules"
                    arguments = [
                        "convert",
                        str(path),
                        "--target",
                        target,
                        "--output",
                        str(output),
                        "--source-dialect",
                        "snort2",
                    ]
                    if permissive:
                        arguments.append("--allow-unverified")
                    status, errors = cli(arguments)
                    self.assertEqual(status, app.EXIT_FINDINGS)
                    self.assertIn("UNSUPPORTED_LINE_BOUNDARY", errors)
                    self.assertFalse(output.exists())
            self.assertEqual(path.read_bytes(), data)

    def test_preflight_drains_bounded_decoder_after_tar_end(self):
        stream = GzipCompletionModel([b"ordinary padding", b""])
        self.assertEqual(modeled_preflight(canonical_tar(), stream), [])
        self.assertEqual(stream.reads, [65536, 65536])
        self.assertEqual(
            stream.events, ["gzip-open", "tar-open", "tar-end", "tar-close", "gzip-close"]
        )

    def test_modeled_late_checksum_error_prevents_fetch_root_creation(self):
        data = canonical_tar()
        source = next(key for key, value in app.FEEDS.items() if value["archive"] == "tar.gz")
        failure = OSError("ordinary modeled checksum refusal")
        stream = GzipCompletionModel([b"ordinary padding", failure])
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                source=source, output_dir=Path(directory), force=False, extract=True
            )
            with (
                patch.object(
                    app,
                    "download_feed",
                    return_value=(data, {"sha256": hashlib.sha256(data).hexdigest()}),
                ),
                patch.object(app.gzip, "GzipFile", return_value=stream),
                patch.object(app.tarfile, "open", return_value=TarEndModel(stream.events)),
                patch.object(app, "_fetch_extraction_root") as created,
            ):
                self.assertRaisesRegex(
                    app.ConverterError, "checksum refusal", app.command_fetch, args
                )
                created.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(stream.reads, [65536, 65536])
        self.assertIn("gzip-close", stream.events)

    def test_drain_budget_bounds_every_request_before_stream_access(self):
        stream = GzipCompletionModel([b"ok", b""])
        bounded = app.DecompressionBudget(stream)
        bounded.limit = 8
        app.drain_bounded_archive_stream(bounded)
        self.assertEqual(stream.reads, [8, 6])
        self.assertEqual(bounded.count, 2)
        bounded.limit = bounded.count
        self.assertRaises(app.ConverterError, app.drain_bounded_archive_stream, bounded)
        self.assertEqual(stream.reads, [8, 6])

    def test_current_valid_tar_preflight_keeps_admitted_member_contract(self):
        members = app.validate_tar_archive(canonical_tar())
        self.assertEqual(
            [(m.name, m.size) for m in members], [("rules/ordinary.rules", len(RULE.encode()))]
        )
        self.assertTrue(members[0].isfile())
        self.assertEqual(type(members[0]), app.AdmittedTarMember)

    def test_empty_owned_fetch_root_is_removed_after_precommit_failure(self):
        for platform in ("posix", "nt"):
            with self.subTest(platform=platform):
                model = FetchRootModel(platform)
                with self.assertRaises(app.ConverterError) as caught:
                    model.run()
                self.assertIs(caught.exception, model.primary)
                self.assertIs(caught.exception.__cause__, model.original_cause)
                self.assertTrue(model.created)
                self.assertTrue(model.removed)
                self.assertNotIn("committed", model.events)

    def test_changed_root_identity_refuses_cleanup_and_preserves_primary(self):
        for platform in ("posix", "nt"):
            with self.subTest(platform=platform):
                model = FetchRootModel(platform, changed=True)
                with self.assertRaises(app.ConverterError) as caught:
                    model.run()
                self.assertIs(caught.exception, model.primary)
                self.assertFalse(model.removed)
                self.assertNotIn("rmdir", model.events)
                self.assertNotIn("dispose", model.events)
                self.assertEqual(model.primary.archive_cleanup_failure_count, 1)

    def test_unowned_remaining_content_refuses_empty_root_removal(self):
        for platform in ("posix", "nt"):
            with self.subTest(platform=platform):
                model = FetchRootModel(platform, content=True)
                with self.assertRaises(app.ConverterError) as caught:
                    model.run()
                self.assertIs(caught.exception, model.primary)
                self.assertFalse(model.removed)
                self.assertEqual(model.primary.archive_cleanup_failure_count, 1)
                self.assertIn("nonempty", model.primary.archive_cleanup_failures[0])

    def test_preexisting_fetch_root_never_becomes_cleanup_owned(self):
        for platform in ("posix", "nt"):
            with self.subTest(platform=platform):
                model = FetchRootModel(platform, existing=True)
                self.assertRaises(FileExistsError, model.run)
                self.assertFalse(model.created)
                self.assertFalse(model.removed)
                self.assertNotIn("rmdir", model.events)
                self.assertNotIn("dispose", model.events)

    def test_unknown_creation_identity_is_retained_for_owner_review(self):
        for platform in ("posix", "nt"):
            with self.subTest(platform=platform):
                model = FetchRootModel(platform, unknown=True)
                with self.assertRaises(OSError) as caught:
                    model.run()
                self.assertTrue(model.created)
                self.assertFalse(model.removed)
                self.assertIn("identity unavailable", caught.exception.archive_cleanup_failures[0])

    def test_committed_generation_is_preserved(self):
        for platform in ("posix", "nt"):
            with self.subTest(platform=platform):
                model = FetchRootModel(platform, content=True)
                root = model.run(fail=False)
                self.assertEqual(root, model.output / "sample")
                self.assertIn("committed", model.events)
                self.assertFalse(model.removed)

    def test_body_root_close_and_parent_close_keep_initial_exception_and_aggregate(self):
        for platform in ("posix", "nt"):
            with self.subTest(platform=platform):
                model = FetchRootModel(platform, inner_close=True, parent_close=True)
                with self.assertRaises(app.ConverterError) as caught:
                    model.run()
                self.assertIs(caught.exception, model.primary)
                self.assertIs(caught.exception.__cause__, model.original_cause)
                self.assertTrue(model.removed)
                self.assertEqual(model.primary.archive_cleanup_failure_count, 2)
                self.assertTrue(
                    any("root close" in item for item in model.primary.archive_cleanup_failures)
                )
                self.assertTrue(
                    any("parent close" in item for item in model.primary.archive_cleanup_failures)
                )

    def test_parent_close_after_commit_is_reported_without_deleting_generation(self):
        for platform in ("posix", "nt"):
            with self.subTest(platform=platform):
                model = FetchRootModel(platform, parent_close=True, content=True)
                self.assertRaisesRegex(OSError, "parent close", model.run, False)
                self.assertIn("committed", model.events)
                self.assertFalse(model.removed)

    def test_parent_acquisition_failure_creates_no_fetch_root(self):
        for platform in ("posix", "nt"):
            with self.subTest(platform=platform):
                model = FetchRootModel(platform, acquisition=True)
                self.assertRaisesRegex(OSError, "acquisition", model.run)
                self.assertEqual(model.events, ["parent-open"])
                self.assertFalse(model.created)

    def test_ordinary_failed_fetch_can_retry_same_source_with_valid_archive(self):
        data = canonical_tar()
        source = next(key for key, value in app.FEEDS.items() if value["archive"] == "tar.gz")
        metadata = {
            "source": source,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = ["fetch", "--source", source, "--output-dir", str(root), "--extract"]
            with (
                patch.object(app, "download_feed", return_value=(data, metadata)),
                patch.object(
                    app,
                    "extract_archive",
                    side_effect=app.ConverterError("ordinary modeled decode refusal"),
                ),
            ):
                status, _ = cli(arguments)
            self.assertEqual(status, app.EXIT_OPERATIONAL_ERROR)
            self.assertFalse((root / source).exists())
            self.assertEqual(list(root.iterdir()), [])
            with patch.object(app, "download_feed", return_value=(data, metadata)):
                status, errors = cli(arguments)
            self.assertEqual((status, errors), (app.EXIT_OK, ""))
            published = json.loads((root / (source + ".metadata.json")).read_text())
            self.assertEqual(len(published["extracted_files"]), 1)
            self.assertEqual((root / published["extracted_files"][0]).read_bytes(), RULE.encode())
            self.assertEqual(
                list((root / source).iterdir()),
                [root / source / published["extraction_generation"]],
            )


class NativeCallModel:
    """Callable native signature/status model; no native handle is acquired."""

    def __init__(self, action):
        self.action = action
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.action(*args)


class WindowsCloseModel:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.closed = []
        self.next_handle = 201
        self.kernel = SimpleNamespace(
            CloseHandle=NativeCallModel(self.close),
            LocalFree=NativeCallModel(lambda *args: None),
            GetFileInformationByHandle=NativeCallModel(self.identity),
            GetFileInformationByHandleEx=NativeCallModel(self.attributes),
            GetFileType=NativeCallModel(lambda handle: 1),
            CreateFileW=NativeCallModel(lambda *args: self.new_handle()),
            SetFileInformationByHandle=NativeCallModel(lambda *args: 1),
        )
        self.native = SimpleNamespace(
            NtCreateFile=NativeCallModel(self.create),
            NtSetInformationFile=NativeCallModel(lambda *args: 0),
            RtlNtStatusToDosError=NativeCallModel(lambda status: 6),
        )
        self.security = SimpleNamespace(
            ConvertStringSecurityDescriptorToSecurityDescriptorW=NativeCallModel(self.security_info)
        )

    def new_handle(self):
        self.next_handle += 1
        return self.next_handle

    def close(self, handle):
        self.closed.append(handle.value if hasattr(handle, "value") else handle)
        return self.statuses.pop(0)

    def create(self, handle, *args):
        handle._obj.value = self.new_handle()
        return 0

    def attributes(self, handle, kind, values, size):
        target = values._obj if hasattr(values, "_obj") else values
        target[0] = 0x10
        return 1

    def identity(self, handle, info):
        info._obj.volume, info._obj.index_low = 3, 4
        return 1

    def security_info(self, text, revision, pointer, size):
        pointer._obj.value = 101
        return 1

    def library(self, name, **kwargs):
        return {"kernel32": self.kernel, "ntdll": self.native, "advapi32": self.security}[name]

    @contextlib.contextmanager
    def environment(self):
        with (
            patch.object(ctypes, "WinDLL", side_effect=self.library, create=True),
            patch.object(ctypes, "get_last_error", return_value=6, create=True),
            patch.object(
                ctypes,
                "WinError",
                side_effect=lambda code: OSError(code, "modeled native close failure"),
                create=True,
            ),
            patch.object(app, "current_windows_sid", return_value="S-1-5-21-1000"),
            patch.object(app, "verify_windows_parent_security"),
        ):
            yield app._WindowsArchiveApi()

    def object_operation(self, *, failure=None, validation=None):
        with (
            self.environment() as api,
            patch.object(app, "validate_windows_input_component", side_effect=validation),
            api.object(101, "ordinary", directory=True),
        ):
            if failure is not None:
                raise failure from failure.__cause__

    def anchor_operation(self, *, failure=None, acquisition=None):
        path = PureWindowsPath("C:/ordinary-model")
        with (
            self.environment() as api,
            patch.object(app, "_require_windows_archive_child"),
            patch.object(api, "object", side_effect=acquisition)
            if acquisition is not None
            else contextlib.nullcontext(),
            app._archive_root_namespace(path, api),
        ):
            if failure is not None:
                raise failure from failure.__cause__

    def lock_operation(self, *, failure=None):
        with (
            self.environment(),
            patch.object(app.sys, "platform", "win32"),
            app.windows_report_directory_lock(PureWindowsPath("C:/ordinary-model")),
        ):
            if failure is not None:
                raise failure from failure.__cause__


class NestedGenerationModel:
    """Actual public extraction/generation with sequential owned-directory identities."""

    def __init__(self, *, fail=True, stage_close=False, cleanup_close=False, parent_close=False):
        self.failure = app.ConverterError("ordinary member writer failure")
        self.cause = ValueError("ordinary member source cause")
        self.failure.__cause__ = self.cause
        self.fail = fail
        self.stage_close, self.cleanup_close, self.parent_close = (
            stage_close,
            cleanup_close,
            parent_close,
        )
        self.events = []
        self.created = {}
        self.descriptors = {}
        self.opens = {}
        self.published = False
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            member = tarfile.TarInfo("ordinary.rules")
            member.size = len(RULE.encode())
            archive.addfile(member, io.BytesIO(RULE.encode()))
        self.data = stream.getvalue()
        self.output = Path("C:/ordinary-nested-model")
        self.parent_number = 0
        self.source = next(key for key, value in app.FEEDS.items() if value["archive"] == "tar.gz")

    @contextlib.contextmanager
    def parent(self, path, api):
        self.parent_number += 1
        number = self.parent_number
        self.events.append(f"parent-open-{number}")
        try:
            yield 101
        finally:
            self.events.append(f"parent-close-{number}")
            if self.parent_close:
                raise OSError(f"ordinary parent-close-{number}")

    def mkdir(self, name, mode, *, dir_fd):
        self.events.append("mkdir:" + name)
        self.created[name] = len(self.created) + 4

    def info(self, name):
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_dev=3, st_ino=self.created[name])

    def named_stat(self, name, *, dir_fd=None, follow_symlinks=True):
        if dir_fd is None:
            raise FileNotFoundError(2, "ordinary modeled absent public path")
        return self.info(name)

    def open(self, name, flags, *, dir_fd):
        self.opens[name] = self.opens.get(name, 0) + 1
        descriptor = len(self.descriptors) + 201
        self.descriptors[descriptor] = name, self.opens[name]
        self.events.append("open:" + name)
        return descriptor

    def fstat(self, descriptor):
        return self.info(self.descriptors[descriptor][0])

    def close(self, descriptor):
        name, occurrence = self.descriptors[descriptor]
        self.events.append("close:" + name)
        if name.startswith(".ids-stage-") and (
            (occurrence == 1 and self.stage_close) or (occurrence == 2 and self.cleanup_close)
        ):
            raise OSError(
                "ordinary stage close" if occurrence == 1 else "ordinary cleanup stage close"
            )

    def remove(self, name, *, dir_fd):
        self.events.append("remove:" + name)
        self.created.pop(name)

    def publish(self, parent, staging, final):
        self.events.append("publish:" + final)
        self.created[final] = self.created.pop(staging)
        self.published = True

    def write(self, path, data, **kwargs):
        self.events.append("write:" + path.name)
        if self.fail:
            raise self.failure from self.cause
        return path

    def execute(self, fetch=False):
        with (
            patch.object(app.os, "name", "posix"),
            patch.object(app.os, "O_DIRECTORY", 0x1000, create=True),
            patch.object(app.os, "O_NOFOLLOW", 0x2000, create=True),
            patch.object(app, "_archive_root_namespace", side_effect=self.parent),
            patch.object(app, "ensure_output_directory", side_effect=lambda path: path),
            patch.object(app, "canonical_system_path", side_effect=lambda path: path),
            patch.object(app, "ensure_outputs_available"),
            patch.object(app.os, "mkdir", side_effect=self.mkdir),
            patch.object(app.os, "stat", side_effect=self.named_stat),
            patch.object(app.os, "open", side_effect=self.open),
            patch.object(app.os, "fstat", side_effect=self.fstat),
            patch.object(app.os, "close", side_effect=self.close),
            patch.object(app.os, "rmdir", side_effect=self.remove),
            patch.object(app.os, "fpathconf", return_value=255, create=True),
            patch.object(app, "_publish_posix_generation", side_effect=self.publish),
            patch.object(app, "atomic_write_bytes", side_effect=self.write),
            patch.object(app, "atomic_write_text", side_effect=lambda *args, **kwargs: None),
            patch.object(
                app,
                "download_feed",
                return_value=(self.data, {"sha256": hashlib.sha256(self.data).hexdigest()}),
            ),
        ):
            if fetch:
                args = SimpleNamespace(
                    source=self.source, output_dir=self.output, force=False, extract=True
                )
                return app.command_fetch(args)
            return app.extract_archive(self.data, "tar.gz", self.output, False)


class LineTailCloseV2(unittest.TestCase):
    def test_component_admission_failure_checks_owned_bool_close_without_losing_cause(self):
        primary = app.ConverterError("ordinary component admission")
        cause = ValueError("ordinary component source cause")
        primary.__cause__ = cause
        model = WindowsCloseModel([0])
        with (
            model.environment(),
            patch.object(app, "validate_windows_input_component", side_effect=primary),
            self.assertRaises(app.ConverterError) as caught,
        ):
            app.open_windows_input_component(None, "C:\\", directory=True)
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertEqual(primary.archive_cleanup_failure_count, 1)
        self.assertEqual(model.closed, [202])

    def test_leaf_transfer_failure_checks_owned_bool_close_without_losing_cause(self):
        primary = OSError("ordinary descriptor transfer")
        cause = ValueError("ordinary descriptor source cause")
        primary.__cause__ = cause
        model = WindowsCloseModel([0])
        transfer = SimpleNamespace(
            open_osfhandle=NativeCallModel(lambda *args: self.transfer_error(primary))
        )
        with (
            model.environment(),
            patch.object(app.sys, "platform", "win32"),
            patch.dict(app.sys.modules, {"msvcrt": transfer}),
            patch.object(app.os, "O_BINARY", 0x8000, create=True),
            patch.object(app, "open_windows_input_component", return_value=301),
            self.assertRaises(OSError) as caught,
        ):
            app._open_input_leaf(PureWindowsPath("C:/ordinary/input.rules"), 101)
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertEqual(primary.archive_cleanup_failure_count, 1)
        self.assertEqual(model.closed, [301])
        self.assertEqual(len(transfer.open_osfhandle.calls), 1)

    @staticmethod
    def transfer_error(primary):
        raise primary from primary.__cause__

    def test_windows_publication_commits_before_failed_checked_publication_close(self):
        model = WindowsCloseModel([1, 0, 1, 1])

        def publish_generation():
            with (
                model.environment(),
                patch.object(app, "os", SimpleNamespace(name="nt")),
                patch.object(app, "_require_windows_archive_child"),
                app._archive_generation(PureWindowsPath("C:/ordinary-model"), {}),
            ):
                pass

        self.assertRaises(OSError, publish_generation)
        self.assertEqual(model.closed, [204, 205, 203, 202])
        self.assertEqual([call[-1] for call in model.native.NtSetInformationFile.calls], [10])
        self.assertEqual(model.statuses, [])

    def test_posix_partial_parent_acquisition_retains_cause_after_descriptor_close_error(self):
        primary = OSError("ordinary ancestry acquisition")
        cause = ValueError("ordinary ancestry source cause")
        primary.__cause__ = cause
        events = []

        class OrdinaryPath(PureWindowsPath):
            def absolute(self):
                return self

            def expanduser(self):
                return self

        def open_component(name, flags, *, dir_fd=None):
            events.append("open:" + name)
            if dir_fd is not None:
                raise primary from cause
            return 301

        def close_component(descriptor):
            events.append("close:" + str(descriptor))
            raise OSError("ordinary ancestry close")

        def acquire_namespace():
            with app.input_parent_namespace(OrdinaryPath("C:/ordinary/input.rules")):
                events.append("unexpected-body")

        with (
            patch.object(app.sys, "platform", "linux"),
            patch.object(app, "canonical_system_path", side_effect=lambda path: path),
            patch.object(app.os, "O_DIRECTORY", 0x1000, create=True),
            patch.object(app.os, "O_NOFOLLOW", 0x2000, create=True),
            patch.object(app.os, "open", side_effect=open_component) as opened,
            patch.object(app.os, "supports_dir_fd", {opened}),
            patch.object(app.os, "close", side_effect=close_component),
            patch.object(app.os, "geteuid", return_value=3, create=True),
            patch.object(
                app.os,
                "fstat",
                return_value=SimpleNamespace(st_uid=3, st_mode=stat.S_IFDIR | 0o700),
            ),
            self.assertRaises(OSError) as caught,
        ):
            acquire_namespace()
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertEqual(primary.archive_cleanup_failure_count, 1)
        self.assertEqual(events, ["open:C:\\", "open:ordinary", "close:301"])

    def test_checked_bool_close_succeeds_once_and_reports_false_with_last_error(self):
        model = WindowsCloseModel([1, 0])
        with model.environment():
            app._close_windows_handle(model.kernel, 101)
            with self.assertRaises(OSError) as caught:
                app._close_windows_handle(model.kernel, 102)
        self.assertEqual(caught.exception.errno, 6)
        self.assertEqual(model.closed, [101, 102])
        self.assertEqual(model.statuses, [])

    def test_actual_object_close_retains_body_identity_and_explicit_cause(self):
        primary = app.ConverterError("ordinary object body")
        cause = ValueError("ordinary explicit cause")
        primary.__cause__ = cause
        model = WindowsCloseModel([0])
        with self.assertRaises(app.ConverterError) as caught:
            model.object_operation(failure=primary)
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertEqual(primary.archive_cleanup_failure_count, 1)
        self.assertEqual(len(model.closed), 1)

    def test_actual_object_failed_close_cannot_return_success(self):
        model = WindowsCloseModel([0])
        self.assertRaises(OSError, model.object_operation)
        self.assertEqual(len(model.closed), 1)

    def test_object_validation_failure_retains_acquisition_error_and_cause(self):
        primary = app.ConverterError("ordinary object admission refusal")
        cause = ValueError("ordinary admission cause")
        primary.__cause__ = cause
        model = WindowsCloseModel([0])
        with self.assertRaises(app.ConverterError) as caught:
            model.object_operation(validation=primary)
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertEqual(primary.archive_cleanup_failure_count, 1)
        self.assertEqual(len(model.closed), 1)

    def test_actual_anchor_and_child_bool_failures_aggregate_without_primary_loss(self):
        primary = app.ConverterError("ordinary archive body")
        cause = ValueError("ordinary original cause")
        primary.__cause__ = cause
        model = WindowsCloseModel([0, 0])
        with self.assertRaises(app.ConverterError) as caught:
            model.anchor_operation(failure=primary)
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertEqual(primary.archive_cleanup_failure_count, 2)
        self.assertEqual(model.closed, [203, 202])

    def test_actual_anchor_failed_close_without_primary_is_operational_error(self):
        model = WindowsCloseModel([1, 0])
        self.assertRaises(OSError, model.anchor_operation)
        self.assertEqual(model.closed, [203, 202])

    def test_partial_parent_acquisition_failure_keeps_original_cause_after_bool_close(self):
        primary = OSError("ordinary parent acquisition")
        cause = ValueError("ordinary parent source cause")
        primary.__cause__ = cause
        model = WindowsCloseModel([0])
        with self.assertRaises(OSError) as caught:
            model.anchor_operation(acquisition=primary)
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertEqual(primary.archive_cleanup_failure_count, 1)
        self.assertEqual(model.closed, [202])

    def test_report_lock_checked_close_preserves_body_and_rejects_false_success(self):
        primary = app.ConverterError("ordinary report body")
        cause = ValueError("ordinary report cause")
        primary.__cause__ = cause
        model = WindowsCloseModel([0])
        with self.assertRaises(app.ConverterError) as caught:
            model.lock_operation(failure=primary)
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        self.assertEqual(primary.archive_cleanup_failure_count, 1)
        self.assertEqual(model.closed, [202])
        no_primary = WindowsCloseModel([0])
        self.assertRaises(OSError, no_primary.lock_operation)
        self.assertEqual(no_primary.closed, [202])

    def test_public_extraction_preserves_body_cause_through_stage_recovery_parent_close(self):
        model = NestedGenerationModel(stage_close=True, cleanup_close=True, parent_close=True)
        with self.assertRaises(app.ConverterError) as caught:
            model.execute()
        self.assertIs(caught.exception, model.failure)
        self.assertIs(model.failure.__cause__, model.cause)
        self.assertEqual(model.failure.archive_cleanup_failure_count, 3)
        self.assertFalse(model.created)
        self.assertFalse(model.published)
        self.assertTrue(any(event.startswith("remove:.ids-stage-") for event in model.events))

    def test_public_fetch_nested_generation_keeps_primary_and_cause_across_both_parents(self):
        model = NestedGenerationModel(stage_close=True, cleanup_close=True, parent_close=True)
        with self.assertRaises(app.ConverterError) as caught:
            model.execute(fetch=True)
        self.assertIs(caught.exception, model.failure)
        self.assertIs(model.failure.__cause__, model.cause)
        self.assertEqual(model.failure.archive_cleanup_failure_count, 4)
        self.assertFalse(model.created)
        self.assertFalse(model.published)
        self.assertIn("remove:" + model.source, model.events)

    def test_committed_public_generation_survives_parent_close_without_success(self):
        model = NestedGenerationModel(fail=False, parent_close=True)
        with self.assertRaises(app.ConverterError) as caught:
            model.execute()
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertTrue(model.published)
        self.assertEqual(len(model.created), 1)
        self.assertTrue(next(iter(model.created)).startswith("generation-"))
        self.assertFalse(any(event.startswith("remove:") for event in model.events))

    def test_normal_public_generation_returns_one_committed_result(self):
        model = NestedGenerationModel(fail=False)
        results = model.execute()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "ordinary.rules")
        self.assertTrue(model.published)
        self.assertEqual(len(model.created), 1)
        self.assertFalse(any(event.startswith("remove:") for event in model.events))


class AbsentJournalPosixModel:
    """Sequential absent temporary plus actual retained descriptor finalization."""

    def __init__(self, fail_closes):
        self.fail_closes = fail_closes
        self.identities = {"stage": 4, "rules": 5, "nested": 6}
        self.descriptors = {}
        self.events = []
        self.closed_ancestors = 0

    def information(self, name):
        return SimpleNamespace(st_dev=3, st_ino=self.identities[name], st_mode=stat.S_IFDIR | 0o700)

    def open(self, name, flags, *, dir_fd):
        descriptor = 202 + len(self.descriptors)
        self.descriptors[descriptor] = name
        self.events.append(("open", name))
        return descriptor

    def close(self, descriptor):
        name = self.descriptors[descriptor]
        self.events.append(("close", name))
        if name in {"rules", "nested"}:
            self.closed_ancestors += 1
            if self.closed_ancestors <= self.fail_closes:
                raise OSError("ordinary modeled " + name + " close failure")

    def stat(self, name, *, dir_fd, follow_symlinks):
        self.events.append(("stat", name))
        if name == ".writer.tmp":
            raise FileNotFoundError(2, "ordinary already removed temporary")
        return self.information(name)

    def remove(self, name, *, dir_fd):
        self.events.append(("remove", name))
        del self.identities[name]

    def execute(self):
        journal = app._ArchiveCreationJournal(Path("stage"), 202, None)
        journal.entries = [
            (("rules",), True, (3, 5)),
            (("rules", "nested"), True, (3, 6)),
            (("rules", "nested", ".writer.tmp"), False, (3, 7)),
        ]
        with (
            patch.object(app.os, "O_DIRECTORY", 0x1000, create=True),
            patch.object(app.os, "O_NOFOLLOW", 0x2000, create=True),
            patch.object(app.os, "open", side_effect=self.open),
            patch.object(app.os, "close", side_effect=self.close),
            patch.object(
                app.os, "fstat", side_effect=lambda fd: self.information(self.descriptors[fd])
            ),
            patch.object(app.os, "stat", side_effect=self.stat),
            patch.object(app.os, "rmdir", side_effect=self.remove),
            patch.object(app.os, "unlink") as unlink,
        ):
            app._cleanup_archive_generation(101, "stage", (3, 4), journal, None)
        return unlink.call_count


class AbsentJournalWindowsModel(WindowsCloseModel):
    """Actual native object/ancestor code with typed status and identity data."""

    def __init__(self, fail_closes):
        super().__init__([0 if index < fail_closes else 1 for index in range(7)])
        self.handles = {}
        self.events = []
        self.disposed = []
        self.native.NtSetInformationFile = NativeCallModel(self.set_information)
        self.native.RtlNtStatusToDosError = NativeCallModel(lambda status: 2)

    def create(self, handle, *args):
        name = args[1]._obj.name.contents.buffer
        self.events.append(("open", name))
        if name == ".writer.tmp":
            return -1
        handle._obj.value = self.new_handle()
        self.handles[handle._obj.value] = name
        return 0

    def identity(self, handle, info):
        name = self.handles[handle.value]
        info._obj.volume = 3
        info._obj.index_low = {"stage": 4, "rules": 5, "nested": 6}[name]
        return 1

    def close(self, handle):
        self.events.append(("close", self.handles[handle.value]))
        return super().close(handle)

    def set_information(self, handle, status, data, size, kind):
        self.events.append(("dispose", self.handles[handle.value]))
        self.disposed.append((self.handles[handle.value], kind))
        return 0

    def execute(self):
        with self.environment() as api:
            journal = app._ArchiveCreationJournal(PureWindowsPath("C:/stage"), 202, api)
            journal.entries = [
                (("rules",), True, (3, 0, 5)),
                (("rules", "nested"), True, (3, 0, 6)),
                (("rules", "nested", ".writer.tmp"), False, (3, 0, 7)),
            ]
            app._cleanup_archive_generation(101, "stage", (3, 0, 4), journal, api)


class LineTailAbsentCloseV3(unittest.TestCase):
    def test_absent_posix_temporary_keeps_only_attached_close_diagnostics(self):
        for failures in (0, 1, 2):
            with self.subTest(close_failures=failures):
                model = AbsentJournalPosixModel(failures)
                if failures:
                    with self.assertRaises(app._ArchiveCleanupError) as caught:
                        model.execute()
                    self.assertEqual(caught.exception.failure_count, failures)
                    expected = (
                        "ordinary modeled nested close failure",
                        "ordinary modeled rules close failure",
                    )[:failures]
                    self.assertEqual(caught.exception.failures, expected)
                    self.assertNotIn("removed temporary", str(caught.exception))
                else:
                    self.assertEqual(model.execute(), 0)
                self.assertEqual(
                    [name for event, name in model.events if event == "close"],
                    ["nested", "rules", "rules", "stage"],
                )
                self.assertEqual(
                    [name for event, name in model.events if event == "remove"],
                    ["nested", "rules", "stage"],
                )
                self.assertFalse(model.identities)
                self.assertIn(("stat", ".writer.tmp"), model.events)

    def test_absent_windows_temporary_keeps_false_bool_ancestor_close_diagnostics(self):
        for failures in (0, 1, 2):
            with self.subTest(close_failures=failures):
                model = AbsentJournalWindowsModel(failures)
                if failures:
                    with self.assertRaises(app._ArchiveCleanupError) as caught:
                        model.execute()
                    self.assertEqual(caught.exception.failure_count, failures)
                    self.assertEqual(
                        caught.exception.failures,
                        (str(OSError(6, "modeled native close failure")),) * failures,
                    )
                    self.assertNotIn("FileNotFoundError", str(caught.exception))
                else:
                    self.assertIsNone(model.execute())
                self.assertEqual(model.closed, [204, 203, 206, 205, 207, 202, 208])
                self.assertEqual(
                    [name for event, name in model.events if event == "close"],
                    ["nested", "rules", "nested", "rules", "rules", "stage", "stage"],
                )
                self.assertEqual(model.disposed, [("nested", 13), ("rules", 13), ("stage", 13)])
                self.assertEqual(model.statuses, [])
                self.assertIn(("open", ".writer.tmp"), model.events)


if __name__ == "__main__":
    unittest.main()

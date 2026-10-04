"""Inert installation policy and sequential owned-object cleanup controls."""

from __future__ import annotations

import copy
import io
import stat
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import test_security_regressions as fixtures

import snort_suricata_rule_converter as app
from scripts import normalize_sdist, normalize_wheel, prepare_release, verify_release_handoff
from scripts import verify_distribution as verifier

ROOT = Path(__file__).resolve().parents[1]


class InstallationContractTests(unittest.TestCase):
    def configuration(self):
        return copy.deepcopy(verifier.reviewed_project(ROOT))

    def test_current_static_contract_and_typed_empty_dependencies_are_approved(self):
        configuration = self.configuration()
        verifier.validate_installation_contract(configuration)
        configuration["project"].update(
            {"dependencies": [], "optional-dependencies": {}, "dynamic": []}
        )
        verifier.validate_installation_contract(configuration)
        self.assertEqual(configuration["project"]["scripts"], verifier.APPROVED_PROJECT["scripts"])
        self.assertEqual(
            configuration["build-system"]["requires"], ["setuptools==84.0.0", "wheel==0.48.0"]
        )

    def test_requirement_pin_spelling_duplicates_and_selectors_refuse_as_inert_data(self):
        variants = (
            ["setuptools==84.0.0", "wheel==0.48.0", "extra-package==1.0"],
            ["setuptools==84.0.0", "wheel==0.48.0", "wheel==0.48.0"],
            ["Setuptools==84.0.0", "wheel==0.48.0"],
            ["setuptools==84.0.0", "Wheel==0.48.0"],
            ["setuptools==84.0.1", "wheel==0.48.0"],
            ["setuptools==84.0.0; python_version>='3.10'", "wheel==0.48.0"],
            ["setuptools[extra]==84.0.0", "wheel==0.48.0"],
            ["setuptools @ https://example.invalid/package.whl", "wheel==0.48.0"],
        )
        for requirements in variants:
            with self.subTest(requirements=requirements):
                configuration = self.configuration()
                configuration["build-system"]["requires"] = requirements
                with self.assertRaisesRegex(ValueError, "build-system"):
                    verifier.validate_installation_contract(configuration)

    def test_backend_and_backend_path_refuse_without_backend_execution(self):
        for key, value in (("build-backend", "local_backend"), ("backend-path", ["."])):
            with self.subTest(key=key):
                configuration = self.configuration()
                configuration["build-system"][key] = value
                with self.assertRaisesRegex(ValueError, "build-system"):
                    verifier.validate_installation_contract(configuration)

    def test_dependency_and_dynamic_declarations_refuse_independently_of_producer_metadata(self):
        for key, value in (
            ("dependencies", ["extra-package==1.0"]),
            ("optional-dependencies", {"extra": ["extra-package==1.0"]}),
            ("dynamic", ["dependencies"]),
            ("dynamic", ["version"]),
            ("dependencies", {}),
            ("optional-dependencies", []),
            ("dynamic", ""),
        ):
            with self.subTest(key=key, value=value):
                configuration = self.configuration()
                configuration["project"][key] = value
                metadata = MagicMock()
                with self.assertRaisesRegex(ValueError, "dependency and dynamic"):
                    verifier.validate_descriptive_metadata(metadata, ROOT, configuration)
                metadata.get_all.assert_not_called()

    def test_entrypoints_package_discovery_and_identity_refuse_unreviewed_changes(self):
        for section, key, value in (
            ("project", "scripts", {"ids-rule-converter": "another_module:main"}),
            ("project", "entry-points", {"plugin": {"selected": "another_module:main"}}),
            ("project", "version", "4.0.3"),
            ("project", "requires-python", ">=3.10"),
            ("tool", "setuptools", {"py-modules": ["another_module"]}),
            (
                "tool",
                "setuptools",
                {"py-modules": ["snort_suricata_rule_converter"], "packages": {"find": {}}},
            ),
        ):
            with self.subTest(section=section, key=key):
                configuration = self.configuration()
                configuration[section][key] = value
                with self.assertRaises(ValueError):
                    verifier.validate_installation_contract(configuration)

    def test_invalid_pyproject_refuses_before_candidate_distribution_access(self):
        source, dist = MagicMock(), MagicMock()
        original = (ROOT / "pyproject.toml").read_bytes()
        source.__truediv__.return_value.open.return_value = io.BytesIO(
            original.replace(b'"wheel==0.48.0"', b'"wheel==0.48.0", "extra-package==1.0"')
        )
        with self.assertRaisesRegex(ValueError, "build-system"):
            verifier.verify_distribution(dist, source, "4.0.2")
        dist.iterdir.assert_not_called()

    def test_ordinary_distribution_metadata_and_trusted_handoff_remain_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / "dist"
            dist.mkdir()
            wheel, sdist = fixtures.SecurityRegressions().fixture_distributions(dist)
            self.assertEqual(verifier.verify_distribution(dist, ROOT, "4.0.2"), (wheel, sdist))
            epoch = 1767225600
            normalize_wheel.normalize_wheel(wheel, epoch)
            normalize_sdist.normalize_sdist(sdist, epoch)
            assets = root / "assets"
            prepare_release.prepare_release(ROOT, assets, "4.0.2", "a" * 40, dist)
            result = verify_release_handoff.verify_handoff(assets, ROOT, "a" * 40, epoch)
            self.assertEqual(result["tag"], "v4.0.2")
            self.assertEqual(len(result["manifest"]), 7)


class CleanupModel:
    """A sequential namespace; it performs no native filesystem operations."""

    def __init__(self, failures=(), changed=()):
        self.objects = {
            ("stage",): (True, "stage-identity"),
            ("stage", "rules"): (True, "directory-identity"),
            ("stage", "rules", "first.rules"): (False, "first-identity"),
            ("stage", "rules", ".writer.tmp"): (False, "temporary-identity"),
            ("stage", "rules", "last.rules"): (False, "last-identity"),
        }
        self.failures, self.changed = set(failures), set(changed)
        self.events = []

    @contextmanager
    def object(self, parent, name, *, directory, create=False, delete=False, private=False):
        key = (*parent, name)
        self.events.append((key, directory, delete, private))
        if key not in self.objects:
            raise FileNotFoundError(name)
        if self.objects[key][0] != directory:
            raise app.ConverterError("modeled type change")
        yield key

    def identity(self, key):
        return "changed" if key in self.changed else self.objects[key][1]

    def dispose(self, key):
        if key in self.failures:
            raise OSError("ordinary modeled disposal failure")
        if self.objects[key][0] and any(
            other[: len(key)] == key for other in self.objects if other != key
        ):
            raise OSError("ordinary modeled nonempty directory")
        del self.objects[key]


class ArchiveCleanupTests(unittest.TestCase):
    def journal(self, api):
        journal = app._ArchiveCreationJournal(Path("stage"), ("stage",), api)
        journal.entries = [
            (("rules",), True, "directory-identity"),
            (("rules", "first.rules"), False, "first-identity"),
            (("rules", ".writer.tmp"), False, "temporary-identity"),
            (("rules", "last.rules"), False, "last-identity"),
        ]
        return journal

    def test_portable_component_lengths_are_checked_as_strings_only(self):
        for name in ("a" * 255, "é" * 127, "😀" * 63):
            self.assertEqual(app.safe_archive_name("rules/" + name).parts, ("rules", name))
        for name in ("a" * 256, "é" * 128, "😀" * 64, "\ud800"):
            with self.subTest(length=len(name)), self.assertRaises(app.ConverterError):
                app.safe_archive_name("rules/" + name)

    def test_pinned_destination_limit_is_checked_before_stage_creation(self):
        graph = {("ordinary.rules",): False}

        @contextmanager
        def namespace(path, api):
            yield 10

        with (
            patch.object(app.os, "name", "posix"),
            patch.object(app, "_archive_root_namespace", side_effect=namespace),
            patch.object(app.os, "fpathconf", return_value=8, create=True) as limit,
            patch.object(app.os, "mkdir") as create,
            self.assertRaisesRegex(app.ConverterError, "filesystem name limit"),
            app._archive_generation(ROOT, graph),
        ):
            self.fail("Name refusal must precede stage creation")
        create.assert_not_called()
        limit.assert_called_once_with(10, "PC_NAME_MAX")

    def test_indeterminate_posix_name_limit_refuses_and_windows_keeps_portable_contract(self):
        for value in (-1, 0):
            with (
                patch.object(app.os, "fpathconf", return_value=value, create=True),
                self.assertRaisesRegex(app.ConverterError, "finite name limit"),
            ):
                app._admit_archive_destination({("ordinary",): False}, 10, None)
        with patch.object(app.os, "fpathconf", create=True) as limit:
            app._admit_archive_destination({("ordinary",): False}, 10, CleanupModel())
        limit.assert_not_called()

    def test_windows_model_removes_only_reverse_created_objects_and_stage(self):
        model = CleanupModel()
        journal = self.journal(model)
        app._cleanup_archive_generation((), "stage", "stage-identity", journal, model)
        self.assertFalse(model.objects)
        deletions = [event[0] for event in model.events if event[2]]
        self.assertEqual(
            deletions,
            [
                ("stage", "rules", "last.rules"),
                ("stage", "rules", ".writer.tmp"),
                ("stage", "rules", "first.rules"),
                ("stage", "rules"),
                ("stage",),
            ],
        )
        self.assertTrue(all(event[3] for event in model.events))

    def test_one_disposal_failure_does_not_stop_remaining_proven_objects(self):
        model = CleanupModel(failures=[("stage", "rules", "last.rules")])
        with self.assertRaises(app._ArchiveCleanupError) as caught:
            app._cleanup_archive_generation(
                (), "stage", "stage-identity", self.journal(model), model
            )
        self.assertEqual(caught.exception.failure_count, 3)
        self.assertNotIn(("stage", "rules", "first.rules"), model.objects)
        self.assertNotIn(("stage", "rules", ".writer.tmp"), model.objects)
        self.assertIn(("stage", "rules", "last.rules"), model.objects)
        self.assertEqual(model.events[-1][0], ("stage",))

    def test_changed_child_identity_refuses_that_delete_but_attempts_other_owned_objects(self):
        model = CleanupModel(changed=[("stage", "rules", "last.rules")])
        with self.assertRaisesRegex(app._ArchiveCleanupError, "identity changed"):
            app._cleanup_archive_generation(
                (), "stage", "stage-identity", self.journal(model), model
            )
        self.assertIn(("stage", "rules", "last.rules"), model.objects)
        self.assertNotIn(("stage", "rules", "first.rules"), model.objects)

    def test_changed_stage_identity_stops_all_child_deletes(self):
        model = CleanupModel(changed=[("stage",)])
        with self.assertRaisesRegex(app.ConverterError, "Staging identity changed"):
            app._cleanup_archive_generation(
                (), "stage", "stage-identity", self.journal(model), model
            )
        self.assertFalse(any(event[2] for event in model.events))

    def test_already_removed_temporary_objects_do_not_create_cleanup_failures(self):
        model = CleanupModel()
        del model.objects[("stage", "rules", ".writer.tmp")]
        app._cleanup_archive_generation((), "stage", "stage-identity", self.journal(model), model)
        self.assertFalse(model.objects)

    def test_unknown_created_identity_is_reported_without_expanding_deletion(self):
        model = CleanupModel()
        journal = self.journal(model)
        journal.entries[-1] = (("rules", "last.rules"), False, None)
        with self.assertRaisesRegex(app._ArchiveCleanupError, "identity is unavailable"):
            app._cleanup_archive_generation((), "stage", "stage-identity", journal, model)
        self.assertNotIn(("stage", "rules", "first.rules"), model.objects)
        self.assertIn(("stage", "rules", "last.rules"), model.objects)

    def test_primary_exception_is_retained_with_aggregate_cleanup_diagnostics(self):
        primary = OSError("ordinary initiating write error")
        cleanup = app._ArchiveCleanupError(["first cleanup error", "second cleanup error"], 2)
        app._retain_archive_cleanup_failure(primary, cleanup)
        self.assertEqual(primary.args, ("ordinary initiating write error",))
        self.assertEqual(primary.archive_cleanup_failure_count, 2)
        self.assertEqual(
            primary.archive_cleanup_failures, ("first cleanup error", "second cleanup error")
        )

    def test_partial_posix_atomic_writer_records_temporary_and_preserves_first_error(self):
        destination = ROOT / "modeled-stage" / "ordinary.rules"
        file = MagicMock()
        file.fileno.return_value = 11
        file.__enter__.return_value = file
        journal = MagicMock()
        journal.record_created.return_value = (1, 11)
        info = SimpleNamespace(st_dev=1, st_ino=11, st_uid=7, st_mode=stat.S_IFREG | 0o600)
        primary = OSError("ordinary payload failure")
        with (
            patch.object(app.os, "name", "posix"),
            patch.object(app.os, "O_NOFOLLOW", 0, create=True),
            patch.object(app.os, "geteuid", return_value=7, create=True),
            patch.object(app, "ensure_output_path", return_value=destination),
            patch.object(app, "ensure_outputs_do_not_replace_inputs"),
            patch.object(app, "open_posix_directory", return_value=10),
            patch.object(app.os, "fstat", return_value=info),
            patch.object(app.os, "stat", return_value=info),
            patch.object(app.os, "open", return_value=11),
            patch.object(app.os, "fdopen", return_value=file),
            patch.object(app, "write_output_payload", side_effect=primary),
            patch.object(
                app.os, "unlink", side_effect=OSError("ordinary temporary cleanup failure")
            ),
            patch.object(app.os, "close") as close,
            self.assertRaises(OSError) as caught,
        ):
            app.atomic_write_bytes(destination, b"ordinary", _archive_journal=journal)
        self.assertIs(caught.exception, primary)
        self.assertEqual(journal.record_created.call_count, 1)
        self.assertTrue(journal.record_created.call_args.args[0].name.startswith(".ids-"))
        self.assertFalse(journal.record_created.call_args.args[1])
        self.assertEqual(primary.archive_cleanup_failure_count, 1)
        close.assert_called_once_with(10)

    def test_windows_partial_writer_journals_private_directory_and_file_before_failure(self):
        destination = ROOT / "modeled-stage" / "ordinary.rules"
        file = MagicMock()
        file.__enter__.return_value = file
        journal = MagicMock()
        journal.record_created.return_value = (1, 2, 3)
        primary = OSError("ordinary Windows payload failure")

        def private_directory(parent, sid, *, on_created=None):
            path = parent / ".ordinary-private-writer"
            if on_created is not None:
                on_created(path)
            return path

        @contextmanager
        def lock(path, sid=None, remove_on_exit=False, **kwargs):
            try:
                yield
            finally:
                if remove_on_exit:
                    raise OSError("ordinary modeled writer-directory cleanup failure")

        with (
            patch.object(app.os, "name", "nt"),
            patch.object(app, "ensure_output_path", return_value=destination),
            patch.object(app, "ensure_outputs_do_not_replace_inputs"),
            patch.object(app, "current_windows_sid", return_value="modeled-owner"),
            patch.object(app, "windows_private_report_directory", side_effect=private_directory),
            patch.object(app, "windows_report_directory_lock", side_effect=lock),
            patch.object(Path, "open", return_value=file),
            patch.object(app, "write_output_payload", side_effect=primary),
            patch.object(Path, "unlink", side_effect=OSError("ordinary temporary removal failure")),
            self.assertRaises(OSError) as caught,
        ):
            app.atomic_write_bytes(destination, b"ordinary", _archive_journal=journal)
        self.assertIs(caught.exception, primary)
        self.assertEqual(
            [call.args[1] for call in journal.record_created.call_args_list], [True, False]
        )
        self.assertEqual(primary.archive_cleanup_failure_count, 2)

    def test_posix_model_checks_identities_and_continues_after_one_failed_unlink(self):
        entries = {
            ("rules",): (True, 2),
            ("rules", "first.rules"): (False, 3),
            ("rules", ".writer.tmp"): (False, 4),
            ("rules", "last.rules"): (False, 5),
        }
        attempted = []
        journal = app._ArchiveCreationJournal(ROOT, 10, None)
        journal.entries = [
            (parts, directory, (1, inode)) for parts, (directory, inode) in entries.items()
        ]

        @contextmanager
        def descriptor(*args, **kwargs):
            yield SimpleNamespace(fileno=lambda: 10)

        @contextmanager
        def parent(staging, parts, api):
            yield parts

        def information(name, *, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            if dir_fd == 0:
                return SimpleNamespace(st_dev=1, st_ino=1, st_mode=stat.S_IFDIR | 0o700)
            key = (*dir_fd, name)
            if key not in entries:
                raise FileNotFoundError(name)
            directory, inode = entries[key]
            return SimpleNamespace(
                st_dev=1, st_ino=inode, st_mode=stat.S_IFDIR if directory else stat.S_IFREG
            )

        def unlink(name, *, dir_fd):
            key = (*dir_fd, name)
            attempted.append(key)
            if name == "last.rules":
                raise OSError("ordinary modeled POSIX removal failure")
            del entries[key]

        def rmdir(name, *, dir_fd):
            attempted.append((name,) if dir_fd == 0 else (*dir_fd, name))
            raise OSError("ordinary modeled nonempty directory")

        with (
            patch.object(app.os, "O_DIRECTORY", 0, create=True),
            patch.object(app.os, "O_NOFOLLOW", 0, create=True),
            patch.object(app, "_input_directory_descriptor", side_effect=descriptor),
            patch.object(app, "_generation_parent", side_effect=parent),
            patch.object(app.os, "fstat", return_value=SimpleNamespace(st_dev=1, st_ino=1)),
            patch.object(app.os, "stat", side_effect=information),
            patch.object(app.os, "unlink", side_effect=unlink),
            patch.object(app.os, "rmdir", side_effect=rmdir),
            self.assertRaises(app._ArchiveCleanupError) as caught,
        ):
            app._cleanup_archive_generation(0, "stage", (1, 1), journal, None)
        self.assertEqual(caught.exception.failure_count, 3)
        self.assertEqual(
            attempted,
            [
                ("rules", "last.rules"),
                ("rules", ".writer.tmp"),
                ("rules", "first.rules"),
                ("rules",),
                ("stage",),
            ],
        )
        self.assertNotIn(("rules", "first.rules"), entries)

    def test_generation_cleanup_aggregation_preserves_the_original_exception(self):
        primary = app.ConverterError("ordinary initiating generation error")
        api = MagicMock()
        api.identity.return_value = "stage-identity"

        @contextmanager
        def namespace(path, supplied):
            yield 10

        @contextmanager
        def object_(parent, name, *, on_created=None, **kwargs):
            if on_created is not None:
                on_created(20)
            yield 20

        api.object.side_effect = object_
        with (
            patch.object(app.os, "name", "nt"),
            patch.object(app, "_WindowsArchiveApi", return_value=api),
            patch.object(app, "_archive_root_namespace", side_effect=namespace),
            patch.object(
                app,
                "_cleanup_archive_generation",
                side_effect=app._ArchiveCleanupError(["one", "two"], 2),
            ) as cleanup,
            self.assertRaises(app.ConverterError) as caught,
            app._archive_generation(ROOT, {}),
        ):
            raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.archive_cleanup_failure_count, 2)
        self.assertEqual(cleanup.call_args.args[2], "stage-identity")
        api.publish.assert_not_called()


class FinalCleanupResidualV2Tests(unittest.TestCase):
    def test_actual_internal_writer_registration_preserves_public_depth_boundary(self):
        stage = Path("stage")
        prefix = tuple(f"ordinary{number}" for number in range(31))
        destination = stage.joinpath(*prefix, "rules")
        private = stage.joinpath(*prefix, ".govhawk-private-" + "a" * 32)
        temporary = private / "report"
        self.assertEqual(len(app.safe_archive_name("/".join((*prefix, "rules"))).parts), 32)
        with self.assertRaisesRegex(app.ConverterError, "depth budget"):
            app.safe_archive_name("/".join(temporary.relative_to(stage).parts))
        model = CleanupModel()
        model.objects = {("stage",): (True, "stage-identity")}
        journal = app._ArchiveCreationJournal(stage, ("stage",), model)
        for size in range(1, len(prefix) + 1):
            parts = prefix[:size]
            identity = f"directory-{size}"
            model.objects[("stage", *parts)] = (True, identity)
            journal.record_created(stage.joinpath(*parts), True, identity=identity)
        for path, directory, identity in (
            (private, True, "private-identity"),
            (temporary, False, "temporary-identity"),
        ):
            model.objects[("stage", *path.relative_to(stage).parts)] = (directory, identity)
            self.assertEqual(
                journal.record_created(
                    path, directory, identity=identity, writer_destination=destination
                ),
                identity,
            )
        self.assertEqual(len(journal.entries[-1][0]), 33)
        self.assertEqual(journal.entries[-1][2], "temporary-identity")
        app._cleanup_archive_generation((), "stage", "stage-identity", journal, model)
        self.assertFalse(model.objects)
        self.assertEqual(model.events[-1][0], ("stage",))

    def test_registration_refusal_still_accounts_for_created_internal_objects(self):
        stage = Path("stage")
        private = stage / (".govhawk-private-" + "b" * 32)
        for path, directory, destination in (
            (private / "other", False, stage / "rules"),
            (private / "nested" / "report", False, stage / "rules"),
            (stage / "other" / private.name, True, stage / "rules"),
            (private / "report", False, stage.joinpath(*("ordinary" for _ in range(33)))),
        ):
            with self.subTest(parts=path.parts):
                journal = app._ArchiveCreationJournal(stage, ("stage",), CleanupModel())
                with self.assertRaises(app.ConverterError):
                    journal.record_created(
                        path, directory, identity="unaccepted", writer_destination=destination
                    )
                self.assertEqual(
                    journal.entries, [(path.relative_to(stage).parts, directory, None)]
                )
        journal = app._ArchiveCreationJournal(stage, 10, None)
        with self.assertRaisesRegex(app.ConverterError, "admitted destination"):
            journal.record_created(
                private, True, identity="unaccepted", writer_destination=stage / "rules"
            )
        self.assertEqual(journal.entries, [((private.name,), True, None)])

    def test_posix_payload_and_stream_close_failures_keep_body_error_with_or_without_journal(self):
        destination = ROOT / "modeled-stage" / "ordinary.rules"
        for tracked in (False, True):
            with self.subTest(tracked=tracked):
                file = MagicMock()
                file.fileno.return_value = 11
                file.__enter__.return_value = file
                primary = app.ConverterError("ordinary initiating POSIX payload failure")
                original_cause = ValueError("ordinary original POSIX cause")
                primary.__cause__ = original_cause
                closing = OSError("ordinary modeled stream close failure")
                file.__exit__.side_effect = closing
                journal = MagicMock() if tracked else None
                if journal is not None:
                    journal.record_created.return_value = (1, 11)
                info = SimpleNamespace(st_dev=1, st_ino=11, st_uid=7, st_mode=stat.S_IFREG | 0o600)
                with (
                    patch.object(app.os, "name", "posix"),
                    patch.object(app.os, "O_NOFOLLOW", 0, create=True),
                    patch.object(app.os, "geteuid", return_value=7, create=True),
                    patch.object(app, "ensure_output_path", return_value=destination),
                    patch.object(app, "ensure_outputs_do_not_replace_inputs"),
                    patch.object(app, "open_posix_directory", return_value=10),
                    patch.object(app.os, "fstat", return_value=info),
                    patch.object(app.os, "stat", return_value=info),
                    patch.object(app.os, "open", return_value=11),
                    patch.object(app.os, "fdopen", return_value=file),
                    patch.object(app, "write_output_payload", side_effect=primary),
                    patch.object(app.os, "unlink") as remove,
                    patch.object(app.os, "link") as publish,
                    patch.object(app.os, "close") as close,
                    self.assertRaises(app.ConverterError) as caught,
                ):
                    app.atomic_write_bytes(destination, b"ordinary", _archive_journal=journal)
                self.assertIs(caught.exception, primary)
                self.assertIs(primary.__cause__, original_cause)
                self.assertEqual(primary.args, ("ordinary initiating POSIX payload failure",))
                self.assertEqual(primary.archive_cleanup_failure_count, 1)
                self.assertIn("stream close", primary.archive_cleanup_failures[0])
                self.assertIs(file.__exit__.call_args.args[1], primary)
                remove.assert_called_once()
                close.assert_called_once_with(10)
                publish.assert_not_called()

    def test_windows_body_stream_and_directory_close_failures_keep_body_error(self):
        destination = ROOT / "modeled-stage" / "ordinary.rules"

        def private_directory(parent, sid, *, on_created=None):
            path = parent / (".govhawk-private-" + "c" * 32)
            if on_created is not None:
                on_created(path)
            return path

        @contextmanager
        def lock(path, sid=None, remove_on_exit=False, **kwargs):
            try:
                yield
            finally:
                if remove_on_exit:
                    raise OSError("ordinary modeled directory close failure")

        for tracked in (False, True):
            with self.subTest(tracked=tracked):
                file = MagicMock()
                file.__enter__.return_value = file
                primary = OSError("ordinary initiating Windows payload failure")
                original_cause = ValueError("ordinary original Windows cause")
                primary.__cause__ = original_cause
                file.__exit__.side_effect = OSError("ordinary modeled stream close failure")
                journal = MagicMock() if tracked else None
                if journal is not None:
                    journal.record_created.return_value = (1, 2, 3)
                with (
                    patch.object(app.os, "name", "nt"),
                    patch.object(app, "ensure_output_path", return_value=destination),
                    patch.object(app, "ensure_outputs_do_not_replace_inputs"),
                    patch.object(app, "current_windows_sid", return_value="modeled-owner"),
                    patch.object(
                        app, "windows_private_report_directory", side_effect=private_directory
                    ),
                    patch.object(app, "windows_report_directory_lock", side_effect=lock),
                    patch.object(Path, "open", return_value=file),
                    patch.object(app, "write_output_payload", side_effect=primary),
                    patch.object(Path, "unlink") as remove,
                    patch.object(app.os, "link") as publish,
                    self.assertRaises(OSError) as caught,
                ):
                    app.atomic_write_bytes(destination, b"ordinary", _archive_journal=journal)
                self.assertIs(caught.exception, primary)
                self.assertIs(primary.__cause__, original_cause)
                self.assertEqual(primary.args, ("ordinary initiating Windows payload failure",))
                self.assertEqual(primary.archive_cleanup_failure_count, 2)
                self.assertIn("stream close", primary.archive_cleanup_failures[0])
                self.assertIn("directory close", primary.archive_cleanup_failures[1])
                self.assertIs(file.__exit__.call_args.args[1], primary)
                if journal is not None:
                    self.assertEqual(journal.record_created.call_count, 2)
                    self.assertTrue(
                        all(
                            call.kwargs["writer_destination"] == destination
                            for call in journal.record_created.call_args_list
                        )
                    )
                remove.assert_called_once()
                publish.assert_not_called()

    def test_close_only_failure_remains_operational_and_cannot_suppress_body_failure(self):
        file = MagicMock()
        file.__enter__.return_value = file
        closing = OSError("ordinary close-only failure")
        file.__exit__.side_effect = closing
        with self.assertRaises(OSError) as caught, app._atomic_writer_stream(file):
            pass
        self.assertIs(caught.exception, closing)
        self.assertFalse(hasattr(closing, "archive_cleanup_failure_count"))
        file.__exit__.side_effect = None
        file.__exit__.return_value = True
        primary = app.ConverterError("ordinary body failure")
        with self.assertRaises(app.ConverterError) as caught, app._atomic_writer_stream(file):
            raise primary
        self.assertIs(caught.exception, primary)
        file.__exit__.side_effect = OSError("ordinary second close failure")
        primary = app.ConverterError("ordinary body without an original cause")
        with self.assertRaises(app.ConverterError) as caught, app._atomic_writer_stream(file):
            raise primary
        self.assertIs(caught.exception, primary)
        self.assertIsNone(primary.__cause__)
        self.assertEqual(primary.args, ("ordinary body without an original cause",))
        self.assertEqual(primary.archive_cleanup_failure_count, 1)
        self.assertIn("second close", primary.archive_cleanup_failures[0])

    def test_cli_preserves_first_error_and_prints_aggregate_cleanup_diagnostics(self):
        for error_type in (app.ConverterError, OSError):
            with self.subTest(error_type=error_type):
                primary = error_type("ordinary initiating CLI error")
                cause = ValueError("ordinary original cause")
                primary.__cause__ = cause
                app._retain_archive_cleanup_failure(
                    primary,
                    app._ArchiveCleanupError(
                        ["first cleanup failure", "second cleanup failure"], 2
                    ),
                )
                parser = MagicMock()
                parser.parse_args.return_value.handler.side_effect = primary
                output = io.StringIO()
                with (
                    patch.object(app, "build_argument_parser", return_value=parser),
                    patch.object(app.sys, "stderr", output),
                ):
                    self.assertEqual(app.main(["fetch"]), app.EXIT_OPERATIONAL_ERROR)
                self.assertEqual(
                    output.getvalue().splitlines(),
                    [
                        "ERROR: ordinary initiating CLI error",
                        "CLEANUP: Archive cleanup reported 2 failure(s): first cleanup failure; second cleanup failure",
                    ],
                )
                self.assertEqual(primary.args, ("ordinary initiating CLI error",))
                self.assertIs(primary.__cause__, cause)

    def test_cli_without_cleanup_diagnostics_keeps_existing_single_error_line(self):
        parser = MagicMock()
        parser.parse_args.return_value.handler.side_effect = app.ConverterError(
            "ordinary CLI failure"
        )
        output = io.StringIO()
        with (
            patch.object(app, "build_argument_parser", return_value=parser),
            patch.object(app.sys, "stderr", output),
        ):
            self.assertEqual(app.main(["fetch"]), app.EXIT_OPERATIONAL_ERROR)
        self.assertEqual(output.getvalue(), "ERROR: ordinary CLI failure\n")


if __name__ == "__main__":
    unittest.main()

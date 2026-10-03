"""Ordinary functional/refusal controls for complete IDS conversion generations."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path, PureWindowsPath
from unittest.mock import MagicMock, patch

import snort_suricata_rule_converter as app

RULE = 'alert tcp any any -> any 80 (msg:"ordinary"; content:"fixture"; sid:1001;)'
FILE_RULE = 'file_id (msg:"ordinary file"; file_meta:type TXT,id 1; file_data; content:"fixture"; gid:4; sid:1002;)'


class FinalFiveGeneration(unittest.TestCase):
    def cli(self, arguments):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return app.main(arguments)

    def test_canonical_file_id_and_other_action_headers_remain_supported(self):
        parsed = app.RuleParser().parse_text(FILE_RULE)
        self.assertFalse(parsed.errors)
        self.assertEqual(parsed.rules[0].canonical_header(), "file_id")
        self.assertTrue(app.render_rule(parsed.rules[0], "snort3").startswith("file_id ("))
        self.assertEqual(app.rule_to_dict(parsed.rules[0])["header"]["protocol"], "")
        for text in (RULE, 'alert http (msg:"ordinary service"; content:"fixture"; sid:1003;)'):
            parsed = app.RuleParser().parse_text(text)
            self.assertFalse(parsed.errors)
            self.assertTrue(app.render_rule(parsed.rules[0], "snort3").startswith("alert "))

    def test_noncanonical_file_id_is_a_parse_error_and_never_rendered(self):
        for header in ("file_id tcp", "file_id tcp any any -> any 80"):
            with self.subTest(header=header):
                parsed = app.RuleParser().parse_text(FILE_RULE.replace("file_id (", header + " ("))
                self.assertIn("INVALID_FILE_ID_HEADER", [item.code for item in parsed.errors])
                self.assertFalse(app.convert_rules(parsed, "snort3").rules)
                self.assertFalse(parsed.rules)

    def test_manual_file_id_fields_refuse_every_public_representation(self):
        for field, value in (
            ("protocol", "tcp"),
            ("source_address", "any"),
            ("source_port", "80"),
            ("direction", "->"),
            ("destination_address", "any"),
            ("destination_port", "80"),
        ):
            rule = app.RuleParser().parse_text(FILE_RULE).rules[0]
            rule._parse_context = None
            setattr(rule, field, value)
            for call in (
                rule.canonical_header,
                lambda r=rule: app.render_rule(r, "snort3", allow_detached_rules=True),
                lambda r=rule: app.compatibility_diagnostics(r, "snort3", True, "snort3"),
                lambda r=rule: app.rule_to_dict(r, allow_detached_rules=True),
            ):
                with self.subTest(field=field), self.assertRaises(app.ConverterError):
                    call()

    def test_file_id_cli_refusal_publishes_no_json_or_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = app.canonical_system_path(Path(directory).absolute())
            source = root / "ordinary-invalid-header.rules"
            source.write_text(FILE_RULE.replace("file_id (", "file_id tcp ("), encoding="utf-8")
            for target in ("snort3", "json"):
                output = root / (target + ".out")
                self.assertEqual(
                    self.cli(["convert", str(source), "--target", target, "--output", str(output)]),
                    app.EXIT_FINDINGS,
                )
                self.assertFalse(output.exists())

    def test_small_same_line_work_is_index_based_and_proportional(self):
        class CountedText(str):
            copied = 0
            searched = 0

            def __getitem__(self, key):
                value = super().__getitem__(key)
                if isinstance(key, slice):
                    self.copied += len(value)
                return value

            def find(self, needle, start=0, end=None):
                limit = len(self) if end is None else end
                self.searched += limit - start
                return super().find(needle, start, limit)

        for count in (4, 8, 12):
            text = CountedText(
                " ".join(RULE.replace("1001", str(1001 + index)) for index in range(count))
            )
            result = app.ParseResult(source="ordinary-counter")
            records = list(app.RuleParser()._records(text, result))
            self.assertEqual(len(records), count)
            self.assertLessEqual(text.copied + text.searched, len(text) * 3)
            parsed = app.RuleParser().parse_text(text)
            self.assertFalse(parsed.errors)
            self.assertEqual(len(parsed.rules), count)

    def test_rejected_artifact_zero_and_nonzero_generations_are_current(self):
        with tempfile.TemporaryDirectory() as directory:
            root = app.canonical_system_path(Path(directory).absolute())
            source, output, rejected, report = (
                root / name
                for name in ("input.rules", "output.rules", "rejected.rules", "report.json")
            )
            for text, count in (
                (RULE + "\n" + FILE_RULE, 1),
                (RULE, 0),
                (RULE + "\n" + FILE_RULE, 1),
                (RULE, 0),
            ):
                source.write_text(text, encoding="utf-8")
                status = self.cli(
                    [
                        "convert",
                        str(source),
                        "--target",
                        "suricata",
                        "--allow-partial",
                        "--output",
                        str(output),
                        "--report",
                        str(report),
                        "--rejected-output",
                        str(rejected),
                        "--force",
                    ]
                )
                self.assertEqual(status, app.EXIT_FINDINGS if count else app.EXIT_OK)
                metadata = json.loads(report.read_text(encoding="utf-8"))
                rejected_text = rejected.read_text(encoding="utf-8")
                for path in (output, rejected):
                    contents = path.read_text(encoding="utf-8")
                    self.assertIn("# Generation: " + metadata["generation_id"], contents)
                    self.assertIn("# Source SHA-256: " + metadata["source_sha256"], contents)
                self.assertIn(f"# Rejected input rules: {count}", rejected_text)
                self.assertEqual(metadata["rejected_rules"], count)
                self.assertEqual(
                    metadata["artifact_sha256"]["output"],
                    hashlib.sha256(output.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    metadata["artifact_sha256"]["rejected"],
                    hashlib.sha256(rejected.read_bytes()).hexdigest(),
                )
                if not count:
                    self.assertNotIn("file_id (", rejected_text)

    @staticmethod
    def worker_frame(source_name, data=b"ordinary"):
        source = app.FEEDS[source_name]
        metadata = {
            "source": source_name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "source_url_sha256": app.feed_url_provenance(source["url"])[1],
        }
        output, error = io.BytesIO(), io.BytesIO()
        with patch.object(app, "_download_feed_in_worker", return_value=(data, metadata)):
            status = app._feed_worker_main(source_name, output, error)
        if status != app.EXIT_OK:
            raise AssertionError(error.getvalue())
        return output.getvalue(), metadata

    @staticmethod
    def supervisor(frame=b"", *, alive=False):
        receiver, sender = MagicMock(), MagicMock()
        receiver.recv_bytes.return_value = b"\x00" + frame
        process = MagicMock(exitcode=0, pid=123)
        process.is_alive.return_value = alive
        context = MagicMock()
        context.Pipe.return_value = (receiver, sender)
        context.Process.return_value = process
        return context, process, receiver, sender

    def test_public_fetch_bounded_byte_frame_and_constant_spawn_target(self):
        source = next(iter(app.FEEDS))
        frame, metadata = self.worker_frame(source)
        context, process, receiver, sender = self.supervisor(frame)
        with patch.object(app.multiprocessing, "get_context", return_value=context) as launch:
            data, actual = app.download_feed(source)
        self.assertEqual(data, b"ordinary")
        self.assertEqual(actual, metadata)
        launch.assert_called_once_with("spawn")
        context.Pipe.assert_called_once_with(duplex=False)
        context.Process.assert_called_once_with(
            target=app._feed_process_worker, args=(source, sender)
        )
        receiver.recv_bytes.assert_called_once_with(
            app.MAX_DOWNLOAD_BYTES + app.MAX_FEED_METADATA_BYTES + 5
        )
        receiver.recv.assert_not_called()
        self.assertGreater(process.join.call_args_list[0].args[0], 0)
        process.kill.assert_not_called()
        receiver.close.assert_called_once_with()
        process.close.assert_called_once_with()

    def test_public_fetch_cancels_and_reaps_mocked_phase_timeout(self):
        source = next(iter(app.FEEDS))
        for phase in (
            "resolver",
            "connect",
            "TLS",
            "status",
            "headers",
            "redirect",
            "fixed body",
            "chunked body",
            "partial IPC",
        ):
            context, process, receiver, sender = self.supervisor(alive=True)
            completed, reader = MagicMock(), MagicMock()
            completed.wait.return_value = False
            with (
                self.subTest(phase=phase),
                patch.object(app.multiprocessing, "get_context", return_value=context),
                patch.object(app.threading, "Event", return_value=completed),
                patch.object(app.threading, "Thread", return_value=reader),
                self.assertRaisesRegex(app.ConverterError, "worker cancelled"),
            ):
                app.download_feed(source)
            self.assertGreater(completed.wait.call_args.args[0], 0)
            process.kill.assert_called_once_with()
            process.join.assert_called_once_with()
            reader.join.assert_called_once_with()
            receiver.close.assert_called_once_with()
            receiver.recv.assert_not_called()
            self.assertTrue(sender.close.called)

    def test_public_fetch_one_deadline_includes_start_join_and_validation(self):
        source = next(iter(app.FEEDS))
        frame, _ = self.worker_frame(source)
        for times, alive in (([0, 31], True), ([0, 1, 2, 31], False), ([0, 1, 2, 3, 31], False)):
            context, process, _, _ = self.supervisor(frame, alive=alive)
            with (
                patch.object(app.time, "monotonic", side_effect=times),
                patch.object(app.multiprocessing, "get_context", return_value=context),
                self.assertRaisesRegex(app.ConverterError, "deadline"),
            ):
                app.download_feed(source)
            self.assertEqual(process.kill.called, alive)
            self.assertEqual(process.join.call_args_list[-1].args, ())

    def test_public_fetch_worker_protocol_and_source_refusals(self):
        source = next(iter(app.FEEDS))
        for frame in (b"", b"bad frame", app.struct.pack(">I", app.MAX_FEED_METADATA_BYTES + 1)):
            context, _, _, _ = self.supervisor(frame)
            with (
                patch.object(app.multiprocessing, "get_context", return_value=context),
                self.assertRaises(app.ConverterError),
            ):
                app.download_feed(source)
        with (
            patch.object(app.multiprocessing, "get_context") as launch,
            self.assertRaises(app.ConverterError),
        ):
            app.download_feed("not-a-built-in-feed")
        launch.assert_not_called()

    def test_public_fetch_start_receive_and_interrupt_failures_close_owned_resources(self):
        source = next(iter(app.FEEDS))
        for failure in (
            OSError("ordinary start failure"),
            RuntimeError("ordinary guarded-start failure"),
            KeyboardInterrupt(),
        ):
            context, process, receiver, sender = self.supervisor(alive=True)
            process.start.side_effect = failure
            process.pid = None
            expected = (
                KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else app.ConverterError
            )
            with (
                patch.object(app.multiprocessing, "get_context", return_value=context),
                self.assertRaises(expected),
            ):
                app.download_feed(source)
            receiver.close.assert_called_once_with()
            sender.close.assert_called_once_with()
            process.join.assert_not_called()
            process.close.assert_called_once_with()
        context, process, receiver, _ = self.supervisor()
        receiver.recv_bytes.side_effect = EOFError()
        with (
            patch.object(app.multiprocessing, "get_context", return_value=context),
            self.assertRaisesRegex(app.ConverterError, "complete frame"),
        ):
            app.download_feed(source)
        process.join.assert_called()
        receiver.close.assert_called_once_with()

    def test_native_spawn_constant_worker_refuses_unknown_key_without_network(self):
        context = app.multiprocessing.get_context("spawn")
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(
            target=app._feed_process_worker, args=("ordinary-unknown-key", sender)
        )
        try:
            process.start()
            sender.close()
            self.assertTrue(receiver.poll(10))
            frame = receiver.recv_bytes(app.MAX_DOWNLOAD_BYTES + app.MAX_FEED_METADATA_BYTES + 5)
            process.join(10)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(frame[0], 1)
            self.assertIn(b"Unknown built-in feed", frame)
        finally:
            sender.close()
            if process.pid is not None:
                if process.is_alive():
                    process.kill()
                process.join()
            receiver.close()
            process.close()

    def test_mocked_sigint_is_delivered_after_process_and_reader_adoption(self):
        source = next(iter(app.FEEDS))
        for phase in ("process", "reader"):
            context, process, receiver, sender = self.supervisor(alive=True)
            reader, handlers = MagicMock(), {}
            previous = app.signal.default_int_handler

            def register(signum, handler, handlers=handlers, previous=previous):
                prior = handlers.get(signum, previous)
                handlers[signum] = handler
                return prior

            def start_process(phase=phase, process=process, handlers=handlers):
                process.pid = None
                if phase == "process":
                    handlers[app.signal.SIGINT](app.signal.SIGINT, None)
                process.pid = 123

            def start_reader(phase=phase, handlers=handlers):
                if phase == "reader":
                    handlers[app.signal.SIGINT](app.signal.SIGINT, None)

            process.start.side_effect = start_process
            reader.start.side_effect = start_reader
            with (
                self.subTest(phase=phase),
                patch.object(app.signal, "getsignal", return_value=previous),
                patch.object(app.signal, "signal", side_effect=register),
                patch.object(app.multiprocessing, "get_context", return_value=context),
                patch.object(app.threading, "Thread", return_value=reader),
                self.assertRaises(KeyboardInterrupt),
            ):
                app.download_feed(source)
            self.assertIs(handlers[app.signal.SIGINT], previous)
            process.kill.assert_called_once_with()
            process.join.assert_called_once_with()
            reader.join.assert_called_once_with()
            receiver.close.assert_called_once_with()
            self.assertTrue(sender.close.called)

    def test_mocked_returning_sigint_handler_is_restored_and_preserved(self):
        source = next(iter(app.FEEDS))
        frame, metadata = self.worker_frame(source)
        context, process, receiver, _ = self.supervisor(frame)
        handlers, delivered = {}, []

        def previous(signum, frame):
            delivered.append((signum, frame))

        def register(signum, handler):
            prior = handlers.get(signum, previous)
            handlers[signum] = handler
            return prior

        def start_reader(target, args, daemon):
            self.assertTrue(daemon)
            reader = MagicMock()

            def start():
                handlers[app.signal.SIGINT](app.signal.SIGINT, None)
                self.assertFalse(delivered)
                target(*args)

            reader.start.side_effect = start
            return reader

        with (
            patch.object(app.signal, "getsignal", return_value=previous),
            patch.object(app.signal, "signal", side_effect=register),
            patch.object(app.multiprocessing, "get_context", return_value=context),
            patch.object(app.threading, "Thread", side_effect=start_reader),
        ):
            data, actual = app.download_feed(source)
        self.assertEqual((data, actual), (b"ordinary", metadata))
        self.assertEqual(delivered, [(app.signal.SIGINT, None)])
        self.assertIs(handlers[app.signal.SIGINT], previous)
        process.kill.assert_not_called()
        receiver.close.assert_called_once_with()

    def test_startup_signal_guard_preserves_other_threads_and_os_dispositions(self):
        with (
            patch.object(app.threading, "current_thread", return_value=object()),
            patch.object(app.threading, "main_thread", return_value=object()),
            patch.object(app.signal, "getsignal") as inspect_handler,
            patch.object(app.signal, "signal") as register,
            app._feed_startup_interrupt_guard(),
        ):
            pass
        inspect_handler.assert_not_called()
        register.assert_not_called()
        for disposition in (app.signal.SIG_IGN, app.signal.SIG_DFL):
            with (
                self.subTest(disposition=disposition),
                patch.object(app.signal, "getsignal", return_value=disposition),
                patch.object(app.signal, "signal") as register,
                app._feed_startup_interrupt_guard(),
            ):
                pass
            register.assert_not_called()

    def test_typed_path_graph_accepts_normal_parents_and_refuses_inconsistent_shapes(self):
        graph = app.archive_path_graph(
            [("rules", True), ("rules/a.rules", False), ("rules/sub/b.rules", False)]
        )
        self.assertTrue(graph[("rules", "sub")])
        self.assertFalse(graph[("rules", "a.rules")])
        for entries in (
            [("rules", False), ("rules/a.rules", False)],
            [("rules/a.rules", False), ("rules", False)],
            [("Rules/a.rules", False), ("rules/b.rules", False)],
        ):
            with self.subTest(entries=entries), self.assertRaises(app.ConverterError):
                app.archive_path_graph(entries)

    def test_windows_drive_anchor_refuses_before_native_namespace_operations(self):
        api = MagicMock()
        with (
            patch.object(app, "current_windows_sid") as identity,
            self.assertRaisesRegex(app.ConverterError, "private child below the drive anchor"),
            app._archive_root_namespace(PureWindowsPath("C:/"), api),
        ):
            self.fail("A Windows drive anchor must not become an extraction root")
        identity.assert_not_called()
        api.object.assert_not_called()
        api.kernel.CloseHandle.assert_not_called()

    def test_public_drive_anchor_refuses_before_root_creation_or_native_setup(self):
        data, _ = self.archive("zip")
        root = MagicMock(spec=Path)
        root.absolute.return_value = PureWindowsPath("C:/")
        with (
            patch.object(app.os, "name", "nt"),
            patch.object(app, "ensure_output_directory") as create,
            patch.object(app, "_WindowsArchiveApi") as native,
            patch.object(app, "current_windows_sid") as identity,
            self.assertRaisesRegex(app.ConverterError, "private child below the drive anchor"),
        ):
            app.extract_archive(data, "zip", root, False)
        create.assert_not_called()
        native.assert_not_called()
        identity.assert_not_called()

    def test_valid_empty_zip_directory_entities_decode_before_publication(self):
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(compression=compression), tempfile.TemporaryDirectory() as directory:
                root = app.canonical_system_path(Path(directory).absolute())
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, "w", compression=compression) as archive:
                    archive.writestr("rules/", b"")
                    archive.writestr("rules/a.rules", RULE.encode())
                original = app._validate_zip_directory_entity

                def validate(data, member, root=root, original=original):
                    self.assertFalse(list(root.glob("generation-*")))
                    return original(data, member)

                with patch.object(
                    app, "_validate_zip_directory_entity", side_effect=validate
                ) as decode:
                    paths = app.extract_archive(stream.getvalue(), "zip", root, False)
                decode.assert_called_once()
                self.assertEqual(len(paths), 1)
                self.assertEqual(paths[0].read_bytes(), RULE.encode())

    def test_mocked_zip_directory_decoder_failure_cleans_only_owned_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = app.canonical_system_path(Path(directory).absolute())
            data, _ = self.archive("zip")
            user = root / "user.txt"
            user.write_text("preserve", encoding="utf-8")
            with (
                patch.object(
                    app,
                    "_validate_zip_directory_entity",
                    side_effect=app.zlib.error("ordinary mocked directory decoder failure"),
                ),
                self.assertRaisesRegex(app.ConverterError, "decoding"),
            ):
                app.extract_archive(data, "zip", root, True)
            self.assertEqual(list(root.iterdir()), [user])
            self.assertEqual(user.read_text(), "preserve")

    def test_valid_empty_and_nonempty_zip_file_entities_validate_before_publication(self):
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(compression=compression), tempfile.TemporaryDirectory() as directory:
                root = app.canonical_system_path(Path(directory).absolute())
                stream = io.BytesIO()
                payloads = {"empty.rules": b"", "ordinary.rules": RULE.encode()}
                with zipfile.ZipFile(stream, "w", compression=compression) as archive:
                    for name, payload in payloads.items():
                        archive.writestr(name, payload)
                original = app._validate_zip_file_entity

                def validate(data, member, root=root, original=original):
                    self.assertFalse(list(root.glob("generation-*")))
                    return original(data, member)

                with patch.object(app, "_validate_zip_file_entity", side_effect=validate) as decode:
                    paths = app.extract_archive(stream.getvalue(), "zip", root, False)
                self.assertEqual(decode.call_count, 2)
                self.assertEqual({path.name: path.read_bytes() for path in paths}, payloads)

    def test_valid_zip_file_entity_decoder_uses_bounded_chunks_without_flush(self):
        payload = bytes(range(256)) * 257
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("ordinary.bin", payload)
        data = stream.getvalue()
        member = app.validate_zip_archive(data)[0]
        original = app.zlib.decompressobj
        calls = []

        class ObservedDecoder:
            def __init__(self, *args):
                self.decoder = original(*args)

            def __getattr__(self, name):
                return getattr(self.decoder, name)

            def decompress(self, content, maximum):
                calls.append((len(content), maximum))
                return self.decoder.decompress(content, maximum)

            def flush(self, *args):
                raise AssertionError("Complete ZIP entity validation must not use flush")

        with patch.object(app.zlib, "decompressobj", side_effect=ObservedDecoder):
            app._validate_zip_file_entity(data, member)
        self.assertGreaterEqual(len(calls), 2)
        self.assertTrue(
            all(0 <= size <= 64 * 1024 and 1 <= cap <= 64 * 1024 for size, cap in calls)
        )

    def test_mocked_regular_zip_decoder_outcomes_must_complete_count_and_checksum(self):
        payload = RULE.encode()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("ordinary.rules", payload)
        data = stream.getvalue()
        member = app.validate_zip_archive(data)[0]
        outcomes = (
            (b"", True, b"", "size or checksum"),
            (b"x" * len(payload), True, b"", "size or checksum"),
            (b"", False, b"", "did not complete"),
            (payload, True, b"ordinary modeled remainder", "input beyond"),
        )
        for decoded, complete, unused, error in outcomes:
            decoder = MagicMock(eof=complete, unconsumed_tail=b"", unused_data=unused)
            decoder.decompress.return_value = decoded
            with (
                self.subTest(error=error, complete=complete),
                patch.object(app.zlib, "decompressobj", return_value=decoder),
                self.assertRaisesRegex(app.ConverterError, error),
            ):
                app._validate_zip_file_entity(data, member)
            decoder.flush.assert_not_called()

    def test_mocked_later_regular_zip_decoder_failure_preserves_prior_and_user_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = app.canonical_system_path(Path(directory).absolute())
            data, _ = self.archive("zip")
            earlier = app.extract_archive(data, "zip", root, False)
            prior = {path: path.read_bytes() for path in earlier}
            user = root / "user.txt"
            user.write_text("preserve", encoding="utf-8")
            original, calls = app._validate_zip_file_entity, []

            def validate(data, member):
                calls.append(member.filename)
                if len(calls) == 2:
                    raise app.zlib.error("ordinary mocked regular decoder failure")
                return original(data, member)

            with (
                patch.object(app, "_validate_zip_file_entity", side_effect=validate),
                self.assertRaisesRegex(app.ConverterError, "decoding"),
            ):
                app.extract_archive(data, "zip", root, True)
            self.assertEqual(len(calls), 2)
            self.assertEqual({path: path.read_bytes() for path in earlier}, prior)
            self.assertEqual(user.read_text(), "preserve")
            self.assertEqual(len(list(root.glob("generation-*"))), 1)
            self.assertFalse(list(root.glob(".ids-stage-*")))

    @staticmethod
    def archive(kind):
        stream = io.BytesIO()
        payloads = {
            "rules/a.rules": RULE.encode(),
            "rules/sub/b.rules": RULE.replace("1001", "1004").encode(),
        }
        if kind == "zip":
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("rules/", b"")
                for name, payload in payloads.items():
                    archive.writestr(name, payload)
        else:
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                directory = tarfile.TarInfo("rules")
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
                for name, payload in payloads.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
        return stream.getvalue(), payloads

    def test_ordinary_multifile_archives_publish_one_complete_generation(self):
        for kind in ("zip", "tar.gz"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = app.canonical_system_path(Path(directory).absolute())
                data, payloads = self.archive(kind)
                paths = app.extract_archive(data, kind, root, False)
                self.assertEqual(len(paths), 2)
                generations = list(root.glob("generation-*"))
                self.assertEqual(len(generations), 1)
                self.assertFalse(list(root.glob(".ids-stage-*")))
                for name, payload in payloads.items():
                    self.assertIn(generations[0] / name, paths)
                    self.assertEqual((generations[0] / name).read_bytes(), payload)
                    self.assertFalse(app.RuleParser().parse_file(generations[0] / name).errors)

    def test_forced_generation_retains_prior_and_user_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = app.canonical_system_path(Path(directory).absolute())
            user = root / "user.txt"
            user.write_text("ordinary user file", encoding="utf-8")
            data, _ = self.archive("zip")
            first = app.extract_archive(data, "zip", root, False)
            second = app.extract_archive(data, "zip", root, True)
            self.assertNotEqual(first[0], second[0])
            self.assertTrue(all(path.exists() for path in first + second))
            self.assertEqual(user.read_text(), "ordinary user file")
            self.assertEqual(len(list(root.glob("generation-*"))), 2)

    def test_mocked_late_writer_failure_exposes_no_generation_and_cleans_own_stage(self):
        for kind in ("zip", "tar.gz"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = app.canonical_system_path(Path(directory).absolute())
                data, _ = self.archive(kind)
                user = root / "user.txt"
                user.write_text("preserve", encoding="utf-8")
                original = app.atomic_write_bytes
                calls = 0

                def writer(*args, root=root, original=original, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise app.ConverterError("ordinary fixture writer failure")
                    self.assertFalse(list(root.glob("generation-*")))
                    return original(*args, **kwargs)

                with (
                    patch.object(app, "atomic_write_bytes", side_effect=writer),
                    self.assertRaises(app.ConverterError),
                ):
                    app.extract_archive(data, kind, root, True)
                self.assertEqual(list(root.iterdir()), [user])
                self.assertEqual(user.read_text(), "preserve")

    def test_existing_generation_collision_is_preserved_and_private_stage_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = app.canonical_system_path(Path(directory).absolute())
            fixed_uuid = app.uuid.UUID(int=1)
            existing = root / ("generation-" + fixed_uuid.hex)
            app.ensure_output_directory(existing, exclusive=True)
            user = existing / "user.txt"
            user.write_text("preserve ordinary prior generation", encoding="utf-8")
            data, _ = self.archive("zip")
            with (
                patch.object(app.uuid, "uuid4", return_value=fixed_uuid),
                self.assertRaisesRegex(app.ConverterError, "generation publication failed"),
            ):
                app.extract_archive(data, "zip", root, True)
            self.assertEqual(user.read_text(), "preserve ordinary prior generation")
            self.assertEqual(list(root.iterdir()), [existing])

    def test_public_fetch_local_fixture_publishes_complete_generation_before_metadata(self):
        source = next(name for name, value in app.FEEDS.items() if value["archive"] == "tar.gz")
        data, payloads = self.archive("tar.gz")
        metadata = {
            "source": source,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = app.canonical_system_path(Path(directory).absolute())
            with patch.object(app, "download_feed", return_value=(data, metadata)):
                self.assertEqual(
                    self.cli(["fetch", "--source", source, "--output-dir", str(root), "--extract"]),
                    app.EXIT_OK,
                )
            actual = json.loads((root / (source + ".metadata.json")).read_text())
            self.assertTrue(actual["extraction_generation"].startswith("generation-"))
            self.assertEqual(len(actual["extracted_files"]), len(payloads))
            for name in actual["extracted_files"]:
                self.assertTrue((root / name).is_file())
            self.assertEqual((root / (source + ".tar.gz")).read_bytes(), data)
            self.assertEqual(
                list((root / source).iterdir()), [root / source / actual["extraction_generation"]]
            )

    def test_public_fetch_local_extraction_failure_announces_no_artifacts(self):
        source = next(name for name, value in app.FEEDS.items() if value["archive"] == "tar.gz")
        data, _ = self.archive("tar.gz")
        metadata = {
            "source": source,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = app.canonical_system_path(Path(directory).absolute())
            with (
                patch.object(app, "download_feed", return_value=(data, metadata)),
                patch.object(
                    app,
                    "extract_archive",
                    side_effect=app.ConverterError("ordinary fixture decode failure"),
                ),
            ):
                self.assertEqual(
                    self.cli(["fetch", "--source", source, "--output-dir", str(root), "--extract"]),
                    app.EXIT_OPERATIONAL_ERROR,
                )
            self.assertFalse((root / (source + ".metadata.json")).exists())
            self.assertFalse((root / (source + ".tar.gz")).exists())
            self.assertFalse(list((root / source).iterdir()))

    def test_mocked_decoder_exception_cleans_its_ordinary_staging_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = app.canonical_system_path(Path(directory).absolute())
            data, _ = self.archive("zip")
            user = root / "user.txt"
            user.write_text("preserve", encoding="utf-8")
            with (
                patch.object(
                    app.zipfile.ZipExtFile,
                    "read",
                    side_effect=app.zipfile.BadZipFile("ordinary mocked decode failure"),
                ),
                self.assertRaisesRegex(app.ConverterError, "decoding"),
            ):
                app.extract_archive(data, "zip", root, True)
            self.assertEqual(list(root.iterdir()), [user])
            self.assertEqual(user.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()

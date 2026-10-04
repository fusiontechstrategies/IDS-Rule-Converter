from __future__ import annotations

import io
import sys
import unittest
import zipfile
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import snort_suricata_rule_converter as app


def option(name: str, value: str | None = None) -> app.RuleOption:
    return app.RuleOption(name, value, name, "model")


def manual_rule(options: list[app.RuleOption]) -> app.Rule:
    return app.Rule(
        source="typed-model",
        start_line=1,
        end_line=1,
        raw="typed-model",
        action="alert",
        protocol="tcp",
        source_address="any",
        source_port="any",
        direction="->",
        destination_address="any",
        destination_port="any",
        options=[option("sid", "9001"), *options],
        index=7,
    )


@dataclass(frozen=True)
class VirtualBlock:
    size: int
    start: int = 0

    def __len__(self) -> int:
        return self.size


class VirtualArchive:
    def __init__(self, compressed_size: int):
        self.size = 30 + compressed_size
        self.reads: list[tuple[int, int]] = []

    def __len__(self) -> int:
        return self.size

    def __getitem__(self, key: slice) -> VirtualBlock:
        if key.step is not None or not 30 <= key.start <= key.stop <= self.size:
            raise AssertionError("virtual model read outside admitted entity")
        self.reads.append((key.start, key.stop))
        return VirtualBlock(key.stop - key.start, key.start)


@dataclass(frozen=True)
class DecodeStep:
    input_size: int
    eof: bool = False
    tail: int = 0
    unused: bytes = b""
    output: bytes = b""


class DirectoryDecoderModel:
    def __init__(self, steps: list[DecodeStep]):
        self.steps = steps
        self.calls: list[tuple[int, int]] = []
        self.eof = False
        self.unconsumed_tail: bytes | VirtualBlock = b""
        self.unused_data = b""

    def decompress(self, data: VirtualBlock | bytes, output_limit: int) -> bytes:
        step = self.steps[len(self.calls)]
        self.calls.append((len(data), output_limit))
        if len(data) != step.input_size or output_limit != 1:
            raise AssertionError("decoder model received unexpected input/output admission")
        self.eof = step.eof
        self.unconsumed_tail = VirtualBlock(step.tail) if step.tail else b""
        self.unused_data = step.unused
        return step.output


class DirectoryRun:
    """No compressed bytes or resource pressure: only lengths and sequential states."""

    def __init__(self, size: int, steps: list[DecodeStep]):
        self.data = VirtualArchive(size)
        self.decoder = DirectoryDecoderModel(steps)
        self.member = zipfile.ZipInfo("rules/")
        self.member.compress_type = zipfile.ZIP_DEFLATED
        self.member.compress_size = size
        self.member.file_size = 0
        self.member.CRC = 0
        self.member.header_offset = 0
        self.header_reads: list[tuple[str, int]] = []

    def header(self, fmt: str, data: VirtualArchive, offset: int) -> tuple[int, int]:
        if data is not self.data or fmt != "<HH" or offset != 26:
            raise AssertionError("virtual model received an unexpected local-header read")
        self.header_reads.append((fmt, offset))
        return 0, 0

    def run(self) -> None:
        with (
            patch.object(app.struct, "unpack_from", side_effect=self.header),
            patch.object(app, "memoryview", side_effect=lambda data: data, create=True),
            patch.object(app.zlib, "decompressobj", return_value=self.decoder) as factory,
        ):
            app._validate_zip_directory_entity(self.data, self.member)
        factory.assert_called_once_with(-app.zlib.MAX_WBITS)


class ConversionZipTwo(unittest.TestCase):
    def test_valued_associated_buffers_refuse_before_suppression(self):
        for key, buffers in (("http_uri", None), ("model_selector", frozenset({"model_selector"}))):
            with self.subTest(key=key):
                options = [option("content", '"ordinary"'), option(key, "neutral-parameter")]
                before = tuple(options)
                self.assertRaisesRegex(
                    app.ConverterError,
                    "value-preserving snort2 to snort3",
                    app.transform_snort2_to_snort3,
                    options,
                    buffers,
                )
                self.assertEqual(tuple(options), before)
                self.assertEqual(options[1].value, "neutral-parameter")

    def test_original_source_admission_precedes_target_normalization(self):
        options = [option("http_uri", "neutral-parameter")]
        for source in ("snort2", "suricata"):
            with (
                self.subTest(source=source),
                patch.object(
                    app,
                    "normalized_fast_pattern_options",
                    wraps=app.normalized_fast_pattern_options,
                ) as normalize,
            ):
                self.assertRaisesRegex(
                    app.ConverterError,
                    f"{source} to suricata",
                    app.transform_to_suricata,
                    options,
                    source,
                    "tcp",
                )
                normalize.assert_not_called()
                self.assertRaisesRegex(
                    app.ConverterError,
                    f"{source} to snort3",
                    app.transform_to_snort3,
                    options,
                    source,
                )

    def test_user_agent_exception_requires_actual_snort3_source(self):
        selector = option("http_header", "field user-agent")
        for source in ("snort2", "suricata"):
            with self.subTest(source=source):
                error = app.legacy_buffer_argument_error(selector, source, "suricata")
                self.assertIsNotNone(error)
                self.assertIn(f"{source} to suricata", error)
        self.assertIsNone(app.legacy_buffer_argument_error(selector, "snort3", "suricata"))
        mapped = app.transform_to_suricata([selector], "snort3", "http")
        self.assertEqual([(item.key, item.value) for item in mapped], [("http.user_agent", None)])
        self.assertEqual(mapped[0].origin, selector.origin)

    def test_snort3_identity_retains_exact_valued_selector(self):
        selector = option("http_uri", "neutral-parameter")
        self.assertIsNone(app.legacy_buffer_argument_error(selector, "snort3", "snort3"))
        transformed = app.transform_to_snort3([selector], "snort3")
        self.assertEqual(transformed, [selector])
        self.assertIs(transformed[0], selector)

    def test_valueless_legacy_mapping_remains_available(self):
        options = [option("content", '"ordinary"'), option("http_uri")]
        for source in ("snort2", "suricata"):
            with self.subTest(source=source):
                converted = app.transform_to_snort3(options, source)
                self.assertEqual(
                    [(item.key, item.value) for item in converted],
                    [("http_uri", None), ("content", '"ordinary"')],
                )

    def test_strict_and_non_strict_batches_retained_semantic_refusal(self):
        rule = manual_rule(
            [option("content", '"ordinary"'), option("http_uri", "neutral-parameter")]
        )
        for source in ("snort2", "suricata"):
            for target in ("snort3", "suricata"):
                for strict in (False, True):
                    with self.subTest(source=source, target=target, strict=strict):
                        result = app.convert_rules(
                            [rule], target, strict, source, allow_detached_rules=True
                        )
                        errors = [
                            item
                            for item in result.errors
                            if item.code == "UNSUPPORTED_BUFFER_ARGUMENT"
                        ]
                        self.assertEqual(len(errors), 1)
                        self.assertIn(f"{source} to {target}", errors[0].message)
                        self.assertEqual(result.rules, [])
                        self.assertEqual(result.rejected_rule_indexes, [7])
        self.assertEqual(rule.options[-1].value, "neutral-parameter")

    def test_direct_renderer_and_diagnostics_keep_original_source(self):
        rule = manual_rule([option("http_uri", "neutral-parameter")])
        for source in ("snort2", "suricata"):
            with self.subTest(source=source):
                diagnostics, _ = app.compatibility_diagnostics(rule, "suricata", False, source)
                errors = [
                    item for item in diagnostics if item.code == "UNSUPPORTED_BUFFER_ARGUMENT"
                ]
                self.assertEqual(len(errors), 1)
                self.assertEqual(errors[0].severity, "error")
                self.assertIn(f"{source} to suricata", errors[0].message)
                self.assertRaises(
                    app.ConverterError,
                    app.render_rule,
                    rule,
                    "suricata",
                    source,
                    allow_detached_rules=True,
                )

    def test_each_fresh_directory_input_is_bounded_with_exact_end(self):
        run = DirectoryRun(65543, [DecodeStep(65536), DecodeStep(7, eof=True)])
        run.run()
        self.assertEqual(run.decoder.calls, [(65536, 1), (7, 1)])
        self.assertEqual(run.data.reads, [(30, 65566), (65566, 65573)])
        self.assertEqual(run.header_reads, [("<HH", 26)])
        self.assertEqual(run.data.reads[-1][1], len(run.data))
        self.assertTrue(run.decoder.eof)
        self.assertFalse(run.decoder.unconsumed_tail)
        self.assertFalse(run.decoder.unused_data)

    def test_pending_tail_shrinks_before_next_fresh_directory_input(self):
        run = DirectoryRun(
            65543, [DecodeStep(65536, tail=3), DecodeStep(3), DecodeStep(7, eof=True)]
        )
        run.run()
        self.assertEqual(run.decoder.calls, [(65536, 1), (3, 1), (7, 1)])
        self.assertEqual(run.data.reads, [(30, 65566), (65566, 65573)])
        self.assertEqual(run.data.reads[-1][1], len(run.data))
        self.assertTrue(run.decoder.eof)
        self.assertFalse(run.decoder.unconsumed_tail)
        self.assertFalse(run.decoder.unused_data)

    def test_directory_output_admission_refuses_any_decoded_byte(self):
        run = DirectoryRun(4, [DecodeStep(4, eof=True, output=b"x")])
        self.assertRaisesRegex(app.ConverterError, "empty content", run.run)
        self.assertEqual(run.decoder.calls, [(4, 1)])
        self.assertEqual(run.data.reads, [(30, 34)])

    def test_directory_eof_requires_no_pending_unused_or_fresh_input(self):
        models = (
            (4, DecodeStep(4, eof=True, tail=1)),
            (4, DecodeStep(4, eof=True, unused=b"x")),
            (65543, DecodeStep(65536, eof=True)),
        )
        for size, step in models:
            with self.subTest(size=size, step=step):
                run = DirectoryRun(size, [step])
                self.assertRaises(app.ConverterError, run.run)
                self.assertEqual(run.decoder.calls, [(step.input_size, 1)])
                self.assertEqual(len(run.data.reads), 1)
                self.assertTrue(run.decoder.eof)

    def test_directory_no_eof_and_non_progress_refuse(self):
        for step in (DecodeStep(4), DecodeStep(4, tail=4), DecodeStep(4, tail=5)):
            with self.subTest(step=step):
                run = DirectoryRun(4, [step])
                self.assertRaises(app.ConverterError, run.run)
                self.assertEqual(run.decoder.calls, [(4, 1)])
                self.assertEqual(run.data.reads, [(30, 34)])
                self.assertFalse(run.decoder.eof)

    def test_directory_unused_input_refuses_before_eof(self):
        run = DirectoryRun(4, [DecodeStep(4, tail=1, unused=b"x")])
        self.assertRaisesRegex(app.ConverterError, "empty content", run.run)
        self.assertEqual(run.decoder.calls, [(4, 1)])
        self.assertFalse(run.decoder.eof)

    def test_valid_canonical_empty_directory_entities_remain_supported(self):
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(compression=compression):
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, "w", compression=compression) as archive:
                    archive.writestr("rules/", b"")
                data = stream.getvalue()
                members = app.validate_zip_archive(data)
                self.assertEqual(len(members), 1)
                self.assertTrue(members[0].is_dir())
                self.assertEqual(members[0].file_size, 0)
                app._validate_zip_directory_entity(data, members[0])


if __name__ == "__main__":
    unittest.main()

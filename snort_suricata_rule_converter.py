#!/usr/bin/env python3
"""Secure, loss-aware Snort and Suricata rule conversion toolkit.

This module intentionally uses only the Python standard library. It parses rules
into an ordered representation so option placement, sticky buffers, and content
modifiers are not silently discarded during conversion.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import ssl
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

APP_NAME = "IDS Rule Converter"
VERSION = "4.0.0"
BUILD_DATE = "2026-08-12"

EXIT_OK = 0
EXIT_OPERATIONAL_ERROR = 1
EXIT_FINDINGS = 2

MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_RULE_CHARS = 1 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_FILE_BYTES = 128 * 1024 * 1024

PANORAMA_PROFILE = "2.0.4"
PANORAMA_MAX_UPLOAD_BYTES = 8 * 1024 * 1024
PANORAMA_MAX_RULES_PER_BATCH = 100
PANORAMA_MAX_CONDITIONS = 16
PANORAMA_MAX_PCRE_LENGTH = 127
PANORAMA_MAX_REFERENCE_LENGTH = 63
PANORAMA_MAX_THRESHOLD_SECONDS = 3600
PANORAMA_MAX_THRESHOLD_COUNT = 255
PANORAMA_ALLOWED_PROTOCOLS = {"tcp", "udp", "icmp", "smb", "http"}

RULE_ACTIONS = {
    "activate",
    "alert",
    "block",
    "config",
    "drop",
    "dynamic",
    "file_id",
    "log",
    "pass",
    "react",
    "reject",
    "rejectboth",
    "rejectdst",
    "rejectsrc",
    "rewrite",
    "sdrop",
}

TARGET_ACTIONS = {
    "snort2": {
        "activate",
        "alert",
        "drop",
        "dynamic",
        "log",
        "pass",
        "reject",
        "sdrop",
    },
    "snort3": {
        "alert",
        "block",
        "drop",
        "file_id",
        "log",
        "pass",
        "react",
        "reject",
        "rewrite",
    },
    "suricata": {
        "alert",
        "config",
        "drop",
        "pass",
        "reject",
        "rejectboth",
        "rejectdst",
        "rejectsrc",
    },
}

SNORT2_PROTOCOLS = {"icmp", "ip", "tcp", "udp"}

DIRECTIONS = {"->", "<>"}

SURICATA_APP_PROTOCOLS = {
    "bittorrent-dht",
    "dhcp",
    "dcerpc",
    "dns",
    "doh2",
    "ftp",
    "ftp-data",
    "http",
    "http2",
    "ike",
    "imap",
    "krb5",
    "ldap",
    "mdns",
    "mqtt",
    "nfs",
    "ntp",
    "pop3",
    "quic",
    "rdp",
    "rfb",
    "sip",
    "smb",
    "smtp",
    "snmp",
    "ssh",
    "telnet",
    "tftp",
    "tls",
    "websocket",
}

SNORT_SERVICE_TO_SURICATA = {
    "netbios-ssn": "smb",
    "ssl": "tls",
}

CONTENT_MODIFIERS = {
    "depth",
    "distance",
    "endian",
    "endswith",
    "fast_pattern",
    "fast_pattern_length",
    "fast_pattern_offset",
    "nocase",
    "offset",
    "rawbytes",
    "startswith",
    "width",
    "within",
}

LEGACY_TO_DOTTED_BUFFER = {
    "dns_query": "dns.query",
    "file_data": "file.data",
    "http_client_body": "http.request_body",
    "http_cookie": "http.cookie",
    "http_header": "http.header",
    "http_header_names": "http.header_names",
    "http_host": "http.host",
    "http_method": "http.method",
    "http_protocol": "http.protocol",
    "http_raw_header": "http.header.raw",
    "http_raw_host": "http.host.raw",
    "http_raw_uri": "http.uri.raw",
    "http_server_body": "http.response_body",
    "http_stat_code": "http.stat_code",
    "http_stat_msg": "http.stat_msg",
    "http_uri": "http.uri",
    "http_user_agent": "http.user_agent",
    "sip_header": "sip.header",
}
DOTTED_TO_LEGACY_BUFFER = {value: key for key, value in LEGACY_TO_DOTTED_BUFFER.items()}

SNORT_TO_SURICATA_OPTION = {
    "sip_method": "sip.method",
    "sip_stat_code": "sip.stat_code",
}

PANORAMA_SUPPORTED_OPTIONS = (
    {
        "content",
        "detection_filter",
        "distance",
        "flow",
        "metadata",
        "msg",
        "pcre",
        "reference",
        "service",
        "sid",
        "threshold",
        "within",
    }
    | CONTENT_MODIFIERS
    | set(LEGACY_TO_DOTTED_BUFFER)
    | set(DOTTED_TO_LEGACY_BUFFER)
)

PANORAMA_IGNORED_METADATA_OPTIONS = {"classtype", "gid", "priority", "rev"}
PANORAMA_IGNORED_DETECTION_OPTIONS = {
    "bufferlen",
    "depth",
    "dsize",
    "flags",
    "flowbits",
    "isdataat",
    "offset",
    "urilen",
}

# Options whose spelling is broadly shared. Unknown options are preserved and
# disclosed as unverified. They are never silently discarded.
COMMON_OPTIONS = (
    {
        "ack",
        "base64_data",
        "base64_decode",
        "ber_data",
        "ber_skip",
        "bufferlen",
        "bsize",
        "byte_extract",
        "byte_jump",
        "byte_math",
        "byte_test",
        "classtype",
        "content",
        "dce_iface",
        "dce_opnum",
        "dce_stub_data",
        "detection_filter",
        "dsize",
        "fast_pattern",
        "fast_pattern_length",
        "fast_pattern_offset",
        "file_data",
        "flags",
        "flow",
        "flowbits",
        "fragbits",
        "fragoffset",
        "gid",
        "icmp_id",
        "icmp_seq",
        "icode",
        "id",
        "ip_proto",
        "ipopts",
        "isdataat",
        "itype",
        "metadata",
        "msg",
        "noalert",
        "nocase",
        "offset",
        "pcre",
        "pkt_data",
        "priority",
        "raw_data",
        "reference",
        "replace",
        "rev",
        "rpc",
        "sameip",
        "seq",
        "service",
        "sip_method",
        "sip_stat_code",
        "sid",
        "ssl_state",
        "ssl_version",
        "stream_reassemble",
        "stream_size",
        "tag",
        "target",
        "threshold",
        "tos",
        "ttl",
        "urilen",
        "window",
    }
    | CONTENT_MODIFIERS
    | set(LEGACY_TO_DOTTED_BUFFER)
    | set(DOTTED_TO_LEGACY_BUFFER)
)

SNORT_ONLY_OPTIONS = {
    "cvs",
    "file_type",
    "js_data",
    "protected_content",
    "sd_pattern",
    "soid",
}

SURICATA_ONLY_OPTIONS = {
    "app-layer-protocol",
    "app-layer-event",
    "bsize",
    "bypass",
    "dataset",
    "lua",
    "prefilter",
    "requires",
    "xbits",
}

SURICATA_PACKET_ONLY_OPTIONS = {
    "ack",
    "dsize",
    "flags",
    "fragbits",
    "fragoffset",
    "icmp_id",
    "icmp_seq",
    "icode",
    "id",
    "ip_proto",
    "ipopts",
    "itype",
    "sameip",
    "seq",
    "tos",
    "ttl",
    "window",
}

FEEDS: dict[str, dict[str, Any]] = {
    "snort3-community": {
        "description": "Cisco Talos Snort 3 community rules",
        "url": "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz",
        "hosts": {
            "www.snort.org",
            "snort.org",
            "snort-org-site.s3.amazonaws.com",
        },
        "archive": "tar.gz",
    },
    "snort2-community": {
        "description": "Cisco Talos Snort 2 community rules",
        "url": "https://www.snort.org/downloads/community/community-rules.tar.gz",
        "hosts": {
            "www.snort.org",
            "snort.org",
            "snort-org-site.s3.amazonaws.com",
        },
        "archive": "tar.gz",
    },
}


class ConverterError(Exception):
    """Expected, user-facing operational failure."""


@dataclass(frozen=True)
class Diagnostic:
    severity: str
    code: str
    message: str
    source: str
    start_line: int | None = None
    end_line: int | None = None
    rule_index: int | None = None
    sid: int | None = None
    option: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(frozen=True)
class RuleOption:
    name: str
    value: str | None
    raw: str
    origin: str = "standalone"

    @property
    def key(self) -> str:
        return self.name.lower()

    def rendered(self, name: str | None = None) -> str:
        output_name = name or self.name
        if self.value is None:
            return f"{output_name};"
        return f"{output_name}:{self.value};"


@dataclass
class Rule:
    source: str
    start_line: int
    end_line: int
    raw: str
    action: str
    protocol: str
    source_address: str | None
    source_port: str | None
    direction: str | None
    destination_address: str | None
    destination_port: str | None
    options: list[RuleOption]
    index: int = 0

    @property
    def headerless(self) -> bool:
        return self.direction is None

    def values(self, name: str) -> list[str]:
        key = name.lower()
        return [
            option.value
            for option in self.options
            if option.key == key and option.value is not None
        ]

    def first_value(self, name: str) -> str | None:
        values = self.values(name)
        return values[0] if values else None

    def integer_value(self, name: str, default: int | None = None) -> int | None:
        value = self.first_value(name)
        if value is None:
            return default
        try:
            return int(value.strip(), 10)
        except ValueError:
            return default

    @property
    def sid(self) -> int | None:
        return self.integer_value("sid")

    @property
    def gid(self) -> int:
        value = self.integer_value("gid", 1)
        return value if value is not None else 1

    @property
    def rev(self) -> int:
        value = self.integer_value("rev", 1)
        return value if value is not None else 1

    @property
    def identity(self) -> tuple[int, int] | None:
        return (self.gid, self.sid) if self.sid is not None else None

    @property
    def message(self) -> str | None:
        value = self.first_value("msg")
        if value is None:
            return None
        return unquote(value)

    def canonical_header(self) -> str:
        if self.action == "file_id":
            return "file_id"
        if self.headerless:
            return f"{self.action} {self.protocol}"
        return " ".join(
            (
                self.action,
                self.protocol,
                self.source_address or "any",
                self.source_port or "any",
                self.direction or "->",
                self.destination_address or "any",
                self.destination_port or "any",
            )
        )


@dataclass
class ParseResult:
    source: str
    rules: list[Rule] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    ignored_directives: int = 0
    byte_count: int = 0

    @property
    def errors(self) -> list[Diagnostic]:
        return [item for item in self.diagnostics if item.severity == "error"]


@dataclass
class ConversionResult:
    target: str
    rules: list[str] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    unverified_keywords: Counter[str] = field(default_factory=Counter)
    rejected_rule_indexes: list[int] = field(default_factory=list)

    @property
    def errors(self) -> list[Diagnostic]:
        return [item for item in self.diagnostics if item.severity == "error"]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def unquote(value: str) -> str:
    value = value.strip()
    negated = value.startswith("!")
    if negated:
        value = value[1:].lstrip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
        value = value.replace(r"\"", '"').replace(r"\\", "\\")
    return ("!" if negated else "") + value


def read_utf8(path: Path, max_bytes: int = MAX_INPUT_BYTES) -> tuple[str, int]:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ConverterError(f"Cannot access input file '{path}': {exc}") from exc
    if not resolved.is_file():
        raise ConverterError(f"Input is not a regular file: {resolved}")
    size = resolved.stat().st_size
    if size > max_bytes:
        raise ConverterError(f"Input is {size:,} bytes; the limit is {max_bytes:,} bytes")
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise ConverterError(f"Cannot read input file '{resolved}': {exc}") from exc
    if b"\x00" in data:
        raise ConverterError(f"Input contains NUL bytes and is not a text ruleset: {resolved}")
    try:
        return data.decode("utf-8-sig"), size
    except UnicodeDecodeError as exc:
        raise ConverterError(
            f"Input is not valid UTF-8 at byte {exc.start}. Convert it to UTF-8 before processing."
        ) from exc


def ensure_output_path(path: Path, force: bool) -> Path:
    resolved_parent = path.expanduser().resolve().parent
    resolved_parent.mkdir(parents=True, exist_ok=True)
    resolved = resolved_parent / path.name
    if resolved.exists() and resolved.is_dir():
        raise ConverterError(f"Output path is a directory: {resolved}")
    if resolved.exists() and not force:
        raise ConverterError(f"Output already exists: {resolved}. Use --force to replace it.")
    return resolved


def ensure_outputs_available(paths: Iterable[Path], force: bool) -> None:
    seen: set[str] = set()
    for path in paths:
        resolved = path.expanduser().resolve()
        key = os.path.normcase(str(resolved))
        if key in seen:
            raise ConverterError(f"The same output path was requested more than once: {resolved}")
        seen.add(key)
        if resolved.exists() and resolved.is_dir():
            raise ConverterError(f"Output path is a directory: {resolved}")
        if resolved.exists() and not force:
            raise ConverterError(f"Output already exists: {resolved}. Use --force to replace it.")


def ensure_outputs_do_not_replace_inputs(outputs: Iterable[Path], inputs: Iterable[Path]) -> None:
    protected = {os.path.normcase(str(path.expanduser().resolve())) for path in inputs}
    for path in outputs:
        resolved = path.expanduser().resolve()
        if os.path.normcase(str(resolved)) in protected:
            raise ConverterError(f"Output path would replace an input file: {resolved}")


def atomic_write_bytes(path: Path, data: bytes, force: bool = False) -> Path:
    destination = ensure_output_path(path, force)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if destination.exists() and not force:
            raise ConverterError(f"Output already exists: {destination}")
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def atomic_write_text(path: Path, text: str, force: bool = False) -> Path:
    return atomic_write_bytes(path, text.encode("utf-8"), force=force)


def json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def strip_rule_comments(text: str) -> str:
    """Remove # and C-style comments while preserving strings and newlines."""
    output: list[str] = []
    quote = False
    escaped = False
    line_comment = False
    block_comment = False
    line_has_nonspace = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
                line_has_nonspace = False
                output.append("\n")
            else:
                output.append(" ")
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                output.extend((" ", " "))
                block_comment = False
                index += 2
                continue
            if char == "\n":
                line_has_nonspace = False
                output.append("\n")
            else:
                output.append(" ")
            index += 1
            continue
        if quote:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
            index += 1
            continue
        if char == '"':
            quote = True
            output.append(char)
            index += 1
            continue
        if char == "#" and not line_has_nonspace:
            line_comment = True
            output.append(" ")
            index += 1
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            output.extend((" ", " "))
            index += 2
            continue
        output.append(char)
        if char == "\n":
            line_has_nonspace = False
        elif not char.isspace():
            line_has_nonspace = True
        index += 1
    return "".join(output)


def split_top_level(text: str, delimiter: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quote = False
    escaped = False
    square = 0
    round_depth = 0
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
            continue
        if char == '"':
            quote = True
        elif char == "[":
            square += 1
        elif char == "]" and square:
            square -= 1
        elif char == "(":
            round_depth += 1
        elif char == ")" and round_depth:
            round_depth -= 1
        elif char == delimiter and square == 0 and round_depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def split_option(option_text: str) -> tuple[str, str | None]:
    quote = False
    escaped = False
    for index, char in enumerate(option_text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
            continue
        if char == '"':
            quote = True
        elif char == ":":
            return option_text[:index].strip(), option_text[index + 1 :].strip()
    return option_text.strip(), None


def split_header(header: str) -> list[str]:
    tokens: list[str] = []
    start: int | None = None
    square = 0
    quote = False
    escaped = False
    for index, char in enumerate(header):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
            continue
        if char == '"':
            quote = True
        elif char == "[":
            square += 1
        elif char == "]" and square:
            square -= 1
        if char.isspace() and square == 0 and not quote:
            if start is not None:
                tokens.append(header[start:index])
                start = None
        elif start is None:
            start = index
    if start is not None:
        tokens.append(header[start:])
    return tokens


def option_diagnostic(
    rule: Rule, severity: str, code: str, message: str, option: str | None = None
) -> Diagnostic:
    return Diagnostic(
        severity=severity,
        code=code,
        message=message,
        source=rule.source,
        start_line=rule.start_line,
        end_line=rule.end_line,
        rule_index=rule.index,
        sid=rule.sid,
        option=option,
    )


class RuleParser:
    def parse_file(self, path: Path) -> ParseResult:
        text, size = read_utf8(path)
        result = self.parse_text(text, str(path.resolve()))
        result.byte_count = size
        return result

    def parse_text(self, text: str, source: str = "<memory>") -> ParseResult:
        result = ParseResult(source=source, byte_count=len(text.encode("utf-8")))
        cleaned = strip_rule_comments(text)
        for record_index, (raw, start_line, end_line) in enumerate(
            self._records(cleaned, result), 1
        ):
            rule, diagnostics = self._parse_record(raw, source, start_line, end_line, record_index)
            result.diagnostics.extend(diagnostics)
            if rule is not None:
                result.rules.append(rule)
        return result

    def _records(self, text: str, result: ParseResult) -> Iterator[tuple[str, int, int]]:
        index = 0
        line = 1
        length = len(text)
        while index < length:
            while index < length and text[index].isspace():
                if text[index] == "\n":
                    line += 1
                index += 1
            if index >= length:
                break
            line_end = text.find("\n", index)
            if line_end == -1:
                line_end = length
            token_match = re.match(r"[A-Za-z_][A-Za-z0-9_-]*", text[index:line_end])
            token = token_match.group(0).lower() if token_match else ""
            if token not in RULE_ACTIONS:
                result.ignored_directives += 1
                preview = " ".join(text[index:line_end].strip().split())
                if preview:
                    if len(preview) > 120:
                        preview = preview[:117] + "..."
                    result.diagnostics.append(
                        Diagnostic(
                            "warning",
                            "IGNORED_NON_RULE_TEXT",
                            f"Ignored non-rule text: {preview}",
                            result.source,
                            line,
                            line,
                        )
                    )
                index = line_end
                continue
            start = index
            start_line = line
            quote = False
            escaped = False
            depth = 0
            opened = False
            while index < length:
                char = text[index]
                if char == "\n":
                    line += 1
                if quote:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == '"':
                        quote = False
                elif char == '"':
                    quote = True
                elif char == "(":
                    opened = True
                    depth += 1
                elif char == ")" and opened:
                    depth -= 1
                    if depth == 0:
                        index += 1
                        yield text[start:index].strip(), start_line, line
                        break
                    if depth < 0:
                        break
                if index - start > MAX_RULE_CHARS:
                    result.diagnostics.append(
                        Diagnostic(
                            "error",
                            "RULE_TOO_LARGE",
                            f"Rule exceeds the {MAX_RULE_CHARS:,} character safety limit",
                            result.source,
                            start_line,
                            line,
                        )
                    )
                    next_line = text.find("\n", index)
                    index = length if next_line == -1 else next_line
                    break
                index += 1
            else:
                result.diagnostics.append(
                    Diagnostic(
                        "error",
                        "UNTERMINATED_RULE",
                        "Rule is missing a balanced closing parenthesis",
                        result.source,
                        start_line,
                        line,
                    )
                )

    def _parse_record(
        self, raw: str, source: str, start_line: int, end_line: int, index: int
    ) -> tuple[Rule | None, list[Diagnostic]]:
        diagnostics: list[Diagnostic] = []
        opening = self._first_unquoted(raw, "(")
        closing = self._last_unquoted(raw, ")")
        if opening < 0 or closing < opening:
            return None, [
                Diagnostic(
                    "error",
                    "INVALID_STRUCTURE",
                    "Rule has no balanced option body",
                    source,
                    start_line,
                    end_line,
                )
            ]
        header_text = " ".join(raw[:opening].split())
        body = raw[opening + 1 : closing]
        header = split_header(header_text)
        if len(header) == 1 and header[0].lower() == "file_id":
            action, protocol = "file_id", ""
            source_address = source_port = direction = destination_address = destination_port = None
        elif len(header) == 2:
            action, protocol = header
            source_address = source_port = direction = destination_address = destination_port = None
        elif len(header) == 7:
            (
                action,
                protocol,
                source_address,
                source_port,
                direction,
                destination_address,
                destination_port,
            ) = header
            if direction not in DIRECTIONS:
                diagnostics.append(
                    Diagnostic(
                        "error",
                        "INVALID_DIRECTION",
                        f"Unsupported direction operator '{direction}'",
                        source,
                        start_line,
                        end_line,
                        index,
                    )
                )
        else:
            return None, [
                Diagnostic(
                    "error",
                    "INVALID_HEADER",
                    f"Expected a file_id header or 2 or 7 header fields, found {len(header)}",
                    source,
                    start_line,
                    end_line,
                    index,
                )
            ]
        if action.lower() not in RULE_ACTIONS:
            diagnostics.append(
                Diagnostic(
                    "error",
                    "INVALID_ACTION",
                    f"Unsupported action '{action}'",
                    source,
                    start_line,
                    end_line,
                    index,
                )
            )
        option_parts = split_top_level(body, ";")
        if body.strip() and option_parts[-1].strip():
            diagnostics.append(
                Diagnostic(
                    "error",
                    "MISSING_OPTION_TERMINATOR",
                    "The final rule option is missing a semicolon",
                    source,
                    start_line,
                    end_line,
                    index,
                )
            )
        options: list[RuleOption] = []
        for part in option_parts[:-1] if body.strip() else []:
            stripped = part.strip()
            if not stripped:
                continue
            name, value = split_option(stripped)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name):
                diagnostics.append(
                    Diagnostic(
                        "error",
                        "INVALID_OPTION_NAME",
                        f"Invalid option name '{name}'",
                        source,
                        start_line,
                        end_line,
                        index,
                    )
                )
                continue
            if name.lower() == "content" and value is not None:
                content_parts = [item.strip() for item in split_top_level(value, ",")]
                options.append(RuleOption(name=name, value=content_parts[0], raw=stripped))
                for modifier in content_parts[1:]:
                    if not modifier:
                        continue
                    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_.-]*)(?:\s+(.+))?", modifier)
                    if not match:
                        diagnostics.append(
                            Diagnostic(
                                "error",
                                "INVALID_INLINE_MODIFIER",
                                f"Cannot parse inline content modifier '{modifier}'",
                                source,
                                start_line,
                                end_line,
                                index,
                            )
                        )
                        continue
                    modifier_name, modifier_value = match.group(1), match.group(2)
                    options.append(
                        RuleOption(
                            name=modifier_name,
                            value=modifier_value.strip() if modifier_value else None,
                            raw=modifier,
                            origin="content-inline",
                        )
                    )
            else:
                options.append(RuleOption(name=name, value=value, raw=stripped))
        rule = Rule(
            source=source,
            start_line=start_line,
            end_line=end_line,
            raw=raw,
            action=action.lower(),
            protocol=protocol.lower(),
            source_address=source_address,
            source_port=source_port,
            direction=direction,
            destination_address=destination_address,
            destination_port=destination_port,
            options=options,
            index=index,
        )
        diagnostics.extend(self._validate_rule(rule))
        return (
            None if any(item.severity == "error" for item in diagnostics) else rule
        ), diagnostics

    @staticmethod
    def _first_unquoted(text: str, wanted: str) -> int:
        quote = False
        escaped = False
        for index, char in enumerate(text):
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quote = False
            elif char == '"':
                quote = True
            elif char == wanted:
                return index
        return -1

    @staticmethod
    def _last_unquoted(text: str, wanted: str) -> int:
        quote = False
        escaped = False
        found = -1
        for index, char in enumerate(text):
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quote = False
            elif char == '"':
                quote = True
            elif char == wanted:
                found = index
        return found

    @staticmethod
    def _validate_rule(rule: Rule) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        sid_values = rule.values("sid")
        if not sid_values:
            diagnostics.append(
                option_diagnostic(rule, "error", "MISSING_SID", "Rule has no sid option", "sid")
            )
        elif len(sid_values) > 1:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "DUPLICATE_SID_OPTION",
                    "Rule has multiple sid options",
                    "sid",
                )
            )
        elif not re.fullmatch(r"[1-9][0-9]*", sid_values[0].strip()):
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "INVALID_SID",
                    "sid must be a positive integer",
                    "sid",
                )
            )
        for name in ("gid", "rev"):
            values = rule.values(name)
            if len(values) > 1:
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        f"DUPLICATE_{name.upper()}_OPTION",
                        f"Rule has multiple {name} options",
                        name,
                    )
                )
            elif values and not re.fullmatch(r"[1-9][0-9]*", values[0].strip()):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        f"INVALID_{name.upper()}",
                        f"{name} must be a positive integer",
                        name,
                    )
                )
        if not rule.values("msg"):
            diagnostics.append(
                option_diagnostic(rule, "warning", "MISSING_MSG", "Rule has no msg option", "msg")
            )
        for option in rule.options:
            if option.key in {"depth", "distance", "offset", "within"} and option.value is None:
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "MISSING_MODIFIER_VALUE",
                        f"{option.name} requires a value",
                        option.name,
                    )
                )
        return diagnostics


def infer_dialect(rule: Rule) -> str:
    if rule.action in {"activate", "dynamic", "sdrop"}:
        return "snort2"
    if rule.action in {"block", "file_id", "react", "rewrite"}:
        return "snort3"
    if rule.action in {"config", "rejectboth", "rejectdst", "rejectsrc"}:
        return "suricata"
    if any(option.origin == "content-inline" for option in rule.options):
        return "snort3"
    if any("." in option.key for option in rule.options):
        return "suricata"
    first_content = next(
        (index for index, option in enumerate(rule.options) if option.key == "content"),
        None,
    )
    for index, option in enumerate(rule.options):
        if option.key not in LEGACY_TO_DOTTED_BUFFER or option.key == "file_data":
            continue
        if first_content is None or index < first_content:
            return "snort3"
        previous = index - 1
        while previous >= 0 and rule.options[previous].key in CONTENT_MODIFIERS:
            previous -= 1
        if previous >= 0 and rule.options[previous].key == "content":
            return "snort2"
    return "snort2"


def semantic_fingerprint(rule: Rule) -> str:
    normalized = {
        "header": rule.canonical_header().lower(),
        "options": [
            [
                option.key,
                " ".join(option.value.split()) if option.value is not None else None,
            ]
            for option in rule.options
            if option.key not in {"rev"}
        ],
    }
    return hashlib.sha256(
        json.dumps(normalized, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def snort2_content_buffer_indexes(options: Sequence[RuleOption]) -> dict[int, int]:
    associations: dict[int, int] = {}
    for index, option in enumerate(options):
        if option.key != "content":
            continue
        cursor = index + 1
        while cursor < len(options) and options[cursor].key in CONTENT_MODIFIERS:
            cursor += 1
        if (
            cursor < len(options)
            and options[cursor].key in LEGACY_TO_DOTTED_BUFFER
            and options[cursor].key != "file_data"
        ):
            associations[index] = cursor
    return associations


def transform_snort2_to_snort3(options: Sequence[RuleOption]) -> list[RuleOption]:
    associations = snort2_content_buffer_indexes(options)
    associated_buffers = set(associations.values())
    transformed: list[RuleOption] = []
    active_buffer = "pkt_data"
    for index, option in enumerate(options):
        if index in associated_buffers:
            continue
        if option.key == "content":
            buffer_index = associations.get(index)
            desired = options[buffer_index].key if buffer_index is not None else "pkt_data"
            if desired != active_buffer:
                transformed.append(RuleOption(desired, None, desired))
                active_buffer = desired
            transformed.append(option)
            continue
        if option.key in {"file_data", "pkt_data", "raw_data"}:
            transformed.append(option)
            active_buffer = option.key
            continue
        if option.key in {
            "pcre",
            "byte_extract",
            "byte_jump",
            "byte_math",
            "byte_test",
            "isdataat",
        } and active_buffer not in {"pkt_data", "raw_data", "file_data"}:
            transformed.append(RuleOption("pkt_data", None, "pkt_data"))
            active_buffer = "pkt_data"
        transformed.append(option)
    return transformed


def transform_sticky_to_snort2(
    options: Sequence[RuleOption], source_dialect: str
) -> list[RuleOption]:
    transformed: list[RuleOption] = []
    active_modifier: str | None = None
    for option in options:
        key = option.key
        is_sticky = key in DOTTED_TO_LEGACY_BUFFER or (
            source_dialect == "snort3" and key in LEGACY_TO_DOTTED_BUFFER
        )
        if is_sticky:
            legacy = DOTTED_TO_LEGACY_BUFFER.get(key, key)
            if legacy == "file_data":
                transformed.append(RuleOption("file_data", option.value, option.raw))
                active_modifier = None
            else:
                active_modifier = legacy
            continue
        if key in {"pkt_data", "raw_data"}:
            active_modifier = None
            transformed.append(option)
            continue
        transformed.append(option)
        if key == "content" and active_modifier is not None:
            transformed.append(RuleOption(active_modifier, None, active_modifier))
    return transformed


def mapped_suricata_service(value: str) -> str | None:
    services = [item.strip().lower() for item in unquote(value).split(",")]
    if len(services) != 1 or not services[0]:
        return None
    mapped = SNORT_SERVICE_TO_SURICATA.get(services[0], services[0])
    return mapped if mapped in SURICATA_APP_PROTOCOLS else None


def implied_suricata_protocols(options: Sequence[RuleOption], rule_protocol: str) -> set[str]:
    """Return application protocols already asserted by headers or keywords."""
    protocols: set[str] = set()
    header_protocol = SNORT_SERVICE_TO_SURICATA.get(rule_protocol, rule_protocol)
    if header_protocol in SURICATA_APP_PROTOCOLS:
        protocols.add(header_protocol)
    for option in options:
        key = option.key
        if key == "service":
            continue
        if key == "app-layer-protocol" and option.value is not None:
            value = unquote(option.value).strip().lower()
            if value in SURICATA_APP_PROTOCOLS:
                protocols.add(value)
        elif key.startswith("http.") or key.startswith("http_"):
            protocols.add("http")
        elif key.startswith("sip.") or key.startswith("sip_"):
            protocols.add("sip")
        elif key.startswith("dns.") or key == "dns_query":
            protocols.add("dns")
        elif key.startswith("tls.") or key in {"ssl_state", "ssl_version"}:
            protocols.add("tls")
        elif key.startswith("dce_"):
            protocols.add("dcerpc")
    return protocols


def mapped_suricata_tag(value: str) -> str | None:
    match = re.fullmatch(
        r"\s*(session|host_src|host_dst)\s*,\s*(packets|bytes|seconds)\s+([0-9]+)\s*",
        value,
        re.IGNORECASE,
    )
    if match is None:
        return None
    scope, metric, count = (part.lower() for part in match.groups())
    if scope == "session":
        return f"session,{count},{metric}"
    direction = "src" if scope == "host_src" else "dst"
    return f"host,{count},{metric},{direction}"


def mapped_suricata_stream_size(value: str) -> str | None:
    match = re.fullmatch(
        r"\s*(<=|>=|!=|[<>=!])?\s*([0-9]+)\s*(?:,\s*(either|to_server|to_client|both)\s*)?",
        value,
        re.IGNORECASE,
    )
    if match is None:
        return None
    operator, number, snort_direction = match.groups()
    directions = {
        None: "either",
        "either": "either",
        "to_server": "client",
        "to_client": "server",
        "both": "both",
    }
    suricata_operator = "!=" if operator == "!" else operator or "="
    return f"{directions[snort_direction.lower() if snort_direction else None]},{suricata_operator},{number}"


def transform_to_suricata(
    options: Sequence[RuleOption], source_dialect: str, rule_protocol: str
) -> list[RuleOption]:
    if source_dialect == "snort2":
        options = transform_snort2_to_snort3(options)
        source_dialect = "snort3"
    transformed: list[RuleOption] = []
    implied_protocols = implied_suricata_protocols(options, rule_protocol)
    index = 0
    while index < len(options):
        option = options[index]
        key = option.key
        if key == "service" and option.value is not None:
            service = mapped_suricata_service(option.value)
            if service is not None and service not in implied_protocols:
                transformed.append(
                    RuleOption("app-layer-protocol", service, option.raw, option.origin)
                )
        elif key == "bufferlen":
            transformed.append(RuleOption("bsize", option.value, option.raw, option.origin))
        elif key == "tag" and option.value is not None:
            value = mapped_suricata_tag(option.value)
            if value is not None:
                transformed.append(RuleOption("tag", value, option.raw, option.origin))
        elif (
            key == "stream_size"
            and option.value is not None
            and source_dialect in {"snort2", "snort3"}
        ):
            value = mapped_suricata_stream_size(option.value)
            if value is not None:
                transformed.append(RuleOption("stream_size", value, option.raw, option.origin))
        elif key == "fast_pattern_offset":
            if (
                option.value is not None
                and index + 1 < len(options)
                and options[index + 1].key == "fast_pattern_length"
                and options[index + 1].value is not None
            ):
                transformed.append(
                    RuleOption(
                        "fast_pattern",
                        f"{option.value.strip()},{options[index + 1].value.strip()}",
                        option.raw,
                    )
                )
                index += 1
        elif key == "fast_pattern_length":
            pass
        elif key in SNORT_TO_SURICATA_OPTION and option.value is not None:
            mapped = SNORT_TO_SURICATA_OPTION[key]
            transformed.append(RuleOption(mapped, None, option.raw, option.origin))
            value = unquote(option.value).upper()
            transformed.append(RuleOption("content", f'"{value}"', option.raw))
            if key == "sip_stat_code" and len(value) == 1:
                transformed.append(RuleOption("startswith", None, "startswith"))
        elif (
            source_dialect == "snort3"
            and key == "http_header"
            and option.value is not None
            and option.value.strip().lower() == "field user-agent"
        ):
            transformed.append(RuleOption("http.user_agent", None, option.raw, option.origin))
        else:
            mapped = LEGACY_TO_DOTTED_BUFFER.get(key) if source_dialect == "snort3" else None
            transformed.append(
                RuleOption(mapped, option.value, option.raw, option.origin)
                if mapped is not None
                else option
            )
        index += 1
    return transformed


def transform_to_snort3(options: Sequence[RuleOption], source_dialect: str) -> list[RuleOption]:
    if source_dialect == "snort2":
        return transform_snort2_to_snort3(options)
    transformed: list[RuleOption] = []
    for option in options:
        mapped = DOTTED_TO_LEGACY_BUFFER.get(option.key)
        if mapped is None:
            transformed.append(option)
        else:
            transformed.append(RuleOption(mapped, option.value, option.raw, option.origin))
    return transformed


def render_rule(rule: Rule, target: str, source_dialect: str | None = None) -> str:
    dialect = source_dialect or infer_dialect(rule)
    if target == "snort3":
        options = transform_to_snort3(rule.options, dialect)
        rendered: list[str] = []
        index = 0
        while index < len(options):
            option = options[index]
            if option.key == "content":
                pieces = [f"content:{option.value}" if option.value is not None else "content"]
                cursor = index + 1
                while cursor < len(options) and options[cursor].key in CONTENT_MODIFIERS:
                    modifier = options[cursor]
                    if modifier.value is None:
                        pieces.append(modifier.name)
                    else:
                        pieces.append(f"{modifier.name} {modifier.value}")
                    cursor += 1
                rendered.append(",".join(pieces) + ";")
                index = cursor
                continue
            rendered.append(option.rendered())
            index += 1
    elif target == "snort2":
        options = (
            list(rule.options)
            if dialect == "snort2"
            else transform_sticky_to_snort2(rule.options, dialect)
        )
        rendered = [option.rendered() for option in options]
    else:
        options = transform_to_suricata(rule.options, dialect, rule.protocol)
        rendered = [option.rendered() for option in options]
    header = rule.canonical_header()
    if target == "suricata":
        protocol = SNORT_SERVICE_TO_SURICATA.get(rule.protocol, rule.protocol)
        if rule.headerless:
            header = f"{rule.action} {protocol} any any -> any any"
        elif protocol != rule.protocol:
            header_parts = split_header(header)
            header_parts[1] = protocol
            header = " ".join(header_parts)
    return f"{header} ({' '.join(rendered)})"


def compatibility_diagnostics(
    rule: Rule, target: str, strict: bool, source_dialect: str
) -> tuple[list[Diagnostic], Counter[str]]:
    diagnostics: list[Diagnostic] = []
    unverified: Counter[str] = Counter()
    if rule.action not in TARGET_ACTIONS[target]:
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "UNSUPPORTED_TARGET_ACTION",
                f"Action '{rule.action}' has no verified {target} equivalent",
            )
        )
    if target == "snort2" and rule.headerless:
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "UNSUPPORTED_HEADERLESS_RULE",
                "Snort 3 service and file rule headers cannot be safely represented in Snort 2",
            )
        )
    if target == "snort2" and not rule.headerless and rule.protocol not in SNORT2_PROTOCOLS:
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "UNSUPPORTED_TARGET_PROTOCOL",
                f"Protocol '{rule.protocol}' is not supported in a Snort 2 rule header",
            )
        )
    if target == "suricata":
        mapped_protocol = SNORT_SERVICE_TO_SURICATA.get(rule.protocol, rule.protocol)
        allowed_protocols = {
            "icmp",
            "icmpv6",
            "ip",
            "tcp",
            "udp",
        } | SURICATA_APP_PROTOCOLS
        if mapped_protocol not in allowed_protocols:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "UNSUPPORTED_TARGET_PROTOCOL",
                    f"Protocol '{rule.protocol}' has no verified Suricata 8 mapping",
                )
            )
        if rule.headerless and mapped_protocol not in SURICATA_APP_PROTOCOLS:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "UNSUPPORTED_HEADERLESS_RULE",
                    f"Headerless Snort 3 protocol '{rule.protocol}' cannot be safely expanded for Suricata",
                )
            )
        implied_protocols = implied_suricata_protocols(rule.options, rule.protocol)
        if len(implied_protocols) > 1:
            protocols = ", ".join(sorted(implied_protocols))
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "CONFLICTING_APP_PROTOCOLS",
                    f"Rule asserts conflicting application protocols: {protocols}",
                )
            )
        packet_options = sorted(
            {option.key for option in rule.options} & SURICATA_PACKET_ONLY_OPTIONS
        )
        if implied_protocols and packet_options:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "PACKET_APP_LAYER_CONFLICT",
                    "Suricata 8 does not allow packet-only matches together with application-layer matching: "
                    + ", ".join(packet_options),
                )
            )
    for option_index, option in enumerate(rule.options):
        key = option.key
        if target == "suricata" and key == "service":
            mapped_service = (
                mapped_suricata_service(option.value) if option.value is not None else None
            )
            if mapped_service is None:
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "UNSUPPORTED_SERVICE_MAPPING",
                        "Suricata 8 conversion requires exactly one recognized service value",
                        option.name,
                    )
                )
            elif any(
                protocol != mapped_service
                for protocol in implied_suricata_protocols(rule.options, rule.protocol)
            ):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "CONFLICTING_SERVICE_MAPPING",
                        f"Service '{mapped_service}' conflicts with another application protocol asserted by the rule",
                        option.name,
                    )
                )
        elif (
            target == "suricata"
            and key in LEGACY_TO_DOTTED_BUFFER
            and option.value is not None
            and not (key == "http_header" and option.value.strip().lower() == "field user-agent")
        ):
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "UNSUPPORTED_BUFFER_ARGUMENT",
                    f"Option '{option.name}' has an argument that cannot be safely mapped to Suricata 8",
                    option.name,
                )
            )
        elif target == "suricata" and key == "bufferlen":
            value = option.value or ""
            if (
                not value
                or ",relative" in value.replace(" ", "").lower()
                or "<=>" in value
                or value.lstrip().startswith("!")
            ):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "UNSAFE_BUFFERLEN_MAPPING",
                        "bufferlen can map to Suricata bsize only without relative, inclusive-range, or negated semantics",
                        option.name,
                    )
                )
        elif target == "suricata" and key == "tag":
            if option.value is None or mapped_suricata_tag(option.value) is None:
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "UNSAFE_TAG_MAPPING",
                        "Snort tag syntax cannot be safely mapped to Suricata",
                        option.name,
                    )
                )
        elif (
            target == "suricata"
            and source_dialect in {"snort2", "snort3"}
            and key == "stream_size"
            and (option.value is None or mapped_suricata_stream_size(option.value) is None)
        ):
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "UNSAFE_STREAM_SIZE_MAPPING",
                    "Snort stream_size ranges or malformed arguments cannot be safely mapped to Suricata 8",
                    option.name,
                )
            )
        elif target == "suricata" and key in {
            "ber_data",
            "ber_skip",
            "dce_iface",
            "http_param",
            "raw_data",
            "sip_body",
            "sip_header",
        }:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "UNSUPPORTED_TARGET_OPTION",
                    f"Option '{option.name}' has no verified Suricata 8 mapping",
                    option.name,
                )
            )
        elif target == "suricata" and key == "sip_method":
            value = unquote(option.value or "")
            if not re.fullmatch(r"[A-Za-z]+", value) or value.startswith("!"):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "UNSAFE_SIP_METHOD_MAPPING",
                        "sip_method conversion supports one non-negated method per option",
                        option.name,
                    )
                )
        elif target == "suricata" and key == "sip_stat_code":
            value = unquote(option.value or "")
            if not re.fullmatch(r"(?:[1-9]|[1-9][0-9]{2})", value):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "UNSAFE_SIP_STATUS_MAPPING",
                        "sip_stat_code conversion supports one value from 1-9 or 100-999",
                        option.name,
                    )
                )
        elif target == "suricata" and key == "fast_pattern_offset":
            if (
                option.value is None
                or not option.value.strip().isdigit()
                or option_index + 1 >= len(rule.options)
                or rule.options[option_index + 1].key != "fast_pattern_length"
                or rule.options[option_index + 1].value is None
                or not rule.options[option_index + 1].value.strip().isdigit()
            ):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "UNSAFE_FAST_PATTERN_MAPPING",
                        "fast_pattern_offset requires an adjacent numeric fast_pattern_length for Suricata",
                        option.name,
                    )
                )
        elif target == "suricata" and key == "fast_pattern_length":
            if option_index == 0 or rule.options[option_index - 1].key != "fast_pattern_offset":
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "UNSAFE_FAST_PATTERN_MAPPING",
                        "fast_pattern_length requires an adjacent fast_pattern_offset for Suricata",
                        option.name,
                    )
                )
        elif target == "suricata" and key in SNORT_ONLY_OPTIONS:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "UNSUPPORTED_TARGET_OPTION",
                    f"Option '{option.name}' is Snort-specific and cannot be safely converted to Suricata",
                    option.name,
                )
            )
        elif target in {"snort2", "snort3"} and (
            key in SURICATA_ONLY_OPTIONS or ("." in key and key not in DOTTED_TO_LEGACY_BUFFER)
        ):
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "UNSUPPORTED_TARGET_OPTION",
                    f"Option '{option.name}' has no verified {target} mapping",
                    option.name,
                )
            )
        elif target == "snort2" and key in {"endswith", "startswith"}:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "UNSUPPORTED_TARGET_OPTION",
                    f"Option '{option.name}' is not safely representable in Snort 2",
                    option.name,
                )
            )
        elif key not in COMMON_OPTIONS and target != source_dialect:
            unverified[key] += 1
    if target == "snort2" and source_dialect in {"snort3", "suricata"}:
        active_buffer: str | None = None
        payload_noncontent = {
            "byte_extract",
            "byte_jump",
            "byte_math",
            "byte_test",
            "isdataat",
            "pcre",
        }
        for option in rule.options:
            key = option.key
            if key in DOTTED_TO_LEGACY_BUFFER or (
                source_dialect == "snort3" and key in LEGACY_TO_DOTTED_BUFFER
            ):
                active_buffer = DOTTED_TO_LEGACY_BUFFER.get(key, key)
            elif key in {"pkt_data", "raw_data", "file_data", "file.data"}:
                active_buffer = None
            elif active_buffer is not None and key in payload_noncontent:
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "UNSAFE_STICKY_BUFFER_DOWNGRADE",
                        f"Cannot safely express {option.name} under sticky buffer '{active_buffer}' in Snort 2",
                        option.name,
                    )
                )
    if target == "snort3" and source_dialect == "snort2":
        associated = set(snort2_content_buffer_indexes(rule.options).values())
        for index, option in enumerate(rule.options):
            if (
                option.key in LEGACY_TO_DOTTED_BUFFER
                and option.key != "file_data"
                and index not in associated
            ):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "AMBIGUOUS_LEGACY_BUFFER",
                        f"Cannot associate legacy buffer modifier '{option.name}' with a content option",
                        option.name,
                    )
                )
    if unverified and strict:
        sample = ", ".join(sorted(unverified)[:8])
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "UNVERIFIED_TARGET_OPTIONS",
                f"Target compatibility is not verified for: {sample}",
            )
        )
    return diagnostics, unverified


def convert_rules(
    rules: Sequence[Rule],
    target: str,
    strict: bool = True,
    source_dialect: str = "auto",
) -> ConversionResult:
    result = ConversionResult(target=target)
    for rule in rules:
        dialect = infer_dialect(rule) if source_dialect == "auto" else source_dialect
        diagnostics, unverified = compatibility_diagnostics(rule, target, strict, dialect)
        result.diagnostics.extend(diagnostics)
        result.unverified_keywords.update(unverified)
        if any(item.severity == "error" for item in diagnostics):
            result.rejected_rule_indexes.append(rule.index)
            continue
        result.rules.append(render_rule(rule, target, dialect))
    if result.unverified_keywords and not strict:
        result.diagnostics.append(
            Diagnostic(
                "warning",
                "UNVERIFIED_KEYWORDS_PRESERVED",
                "Some target keywords were preserved exactly but require validation in the target engine: "
                + ", ".join(sorted(result.unverified_keywords)),
                rules[0].source if rules else "<input>",
            )
        )
    return result


def rule_to_dict(rule: Rule) -> dict[str, Any]:
    dialect = infer_dialect(rule)
    return {
        "index": rule.index,
        "source": rule.source,
        "start_line": rule.start_line,
        "end_line": rule.end_line,
        "dialect_hint": dialect,
        "header": {
            "action": rule.action,
            "protocol": rule.protocol,
            "source_address": rule.source_address,
            "source_port": rule.source_port,
            "direction": rule.direction,
            "destination_address": rule.destination_address,
            "destination_port": rule.destination_port,
        },
        "gid": rule.gid,
        "sid": rule.sid,
        "rev": rule.rev,
        "message": rule.message,
        "fingerprint": semantic_fingerprint(rule),
        "options": [asdict(option) for option in rule.options],
        "canonical_rule": render_rule(rule, dialect, dialect),
    }


def diagnostic_counts(diagnostics: Iterable[Diagnostic]) -> dict[str, int]:
    counter = Counter(item.severity for item in diagnostics)
    return {name: counter.get(name, 0) for name in ("error", "warning", "info")}


def ruleset_analysis(parsed: ParseResult) -> dict[str, Any]:
    identities: dict[tuple[int, int], list[Rule]] = defaultdict(list)
    exact_fingerprints: dict[str, list[Rule]] = defaultdict(list)
    actions: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    keywords: Counter[str] = Counter()
    dialects: Counter[str] = Counter()
    missing_sid = 0
    for rule in parsed.rules:
        actions[rule.action] += 1
        protocols[rule.protocol] += 1
        dialects[infer_dialect(rule)] += 1
        keywords.update(option.key for option in rule.options)
        if rule.identity is None:
            missing_sid += 1
        else:
            identities[rule.identity].append(rule)
        exact_fingerprints[semantic_fingerprint(rule)].append(rule)
    duplicate_ids = []
    conflicting_ids = []
    for identity, group in sorted(identities.items()):
        if len(group) < 2:
            continue
        entry = {
            "gid": identity[0],
            "sid": identity[1],
            "rules": [
                {"index": item.index, "line": item.start_line, "rev": item.rev} for item in group
            ],
        }
        fingerprints = {semantic_fingerprint(item) for item in group}
        if len(fingerprints) == 1:
            duplicate_ids.append(entry)
        else:
            conflicting_ids.append(entry)
    exact_duplicates = [
        {
            "fingerprint": fingerprint,
            "rules": [
                {"index": item.index, "line": item.start_line, "sid": item.sid} for item in group
            ],
        }
        for fingerprint, group in exact_fingerprints.items()
        if len(group) > 1
    ]
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "tool": {"name": APP_NAME, "version": VERSION},
        "source": parsed.source,
        "bytes": parsed.byte_count,
        "rule_count": len(parsed.rules),
        "ignored_directive_lines": parsed.ignored_directives,
        "diagnostic_counts": diagnostic_counts(parsed.diagnostics),
        "missing_sid_count": missing_sid,
        "actions": dict(sorted(actions.items())),
        "protocols": dict(sorted(protocols.items())),
        "dialect_hints": dict(sorted(dialects.items())),
        "keywords": dict(sorted(keywords.items())),
        "duplicate_sid_groups": duplicate_ids,
        "conflicting_sid_groups": conflicting_ids,
        "exact_duplicate_groups": exact_duplicates,
        "diagnostics": [item.to_dict() for item in parsed.diagnostics],
    }


def sarif_report(parsed: ParseResult, extra: Sequence[Diagnostic] = ()) -> dict[str, Any]:
    diagnostics = list(parsed.diagnostics) + list(extra)
    rules: dict[str, dict[str, Any]] = {}
    results = []
    level_map = {"error": "error", "warning": "warning", "info": "note"}
    for item in diagnostics:
        rules.setdefault(
            item.code,
            {
                "id": item.code,
                "name": item.code,
                "shortDescription": {"text": item.message},
                "helpUri": "https://github.com/fusiontechstrategies/IDS-Rule-Converter",
            },
        )
        result: dict[str, Any] = {
            "ruleId": item.code,
            "level": level_map.get(item.severity, "note"),
            "message": {"text": item.message},
        }
        if item.start_line is not None and not item.source.startswith("<"):
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": Path(item.source).as_posix()},
                        "region": {
                            "startLine": item.start_line,
                            "endLine": item.end_line or item.start_line,
                        },
                    }
                }
            ]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": APP_NAME,
                        "version": VERSION,
                        "informationUri": "https://github.com/fusiontechstrategies/IDS-Rule-Converter",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }


def pcre_flags(value: str) -> str:
    text = unquote(value).lstrip("!")
    escaped = False
    closing = -1
    for index in range(len(text) - 1, -1, -1):
        char = text[index]
        if char == "/" and not escaped:
            closing = index
            break
        escaped = char == "\\" and not escaped
        if char != "\\":
            escaped = False
    return text[closing + 1 :] if closing >= 0 else ""


def pattern_contexts(rule: Rule) -> list[tuple[RuleOption, str, bool]]:
    """Return pattern, effective buffer, and case-insensitive intent."""
    dialect = infer_dialect(rule)
    results: list[tuple[RuleOption, str, bool]] = []
    if dialect == "snort2":
        buffer_indexes = snort2_content_buffer_indexes(rule.options)
        for index, option in enumerate(rule.options):
            if option.key == "content":
                modifier_index = buffer_indexes.get(index)
                context = (
                    rule.options[modifier_index].key if modifier_index is not None else "pkt_data"
                )
                cursor = index + 1
                modifiers: set[str] = set()
                while cursor < len(rule.options) and rule.options[cursor].key in CONTENT_MODIFIERS:
                    modifiers.add(rule.options[cursor].key)
                    cursor += 1
                results.append((option, context, "nocase" in modifiers))
            elif option.key == "pcre" and option.value is not None:
                flags = pcre_flags(option.value)
                contexts = {
                    "U": "http_uri",
                    "I": "http_raw_uri",
                    "P": "http_client_body",
                    "H": "http_header",
                    "D": "http_raw_header",
                    "M": "http_method",
                    "C": "http_cookie",
                    "S": "http_stat_code",
                    "Y": "http_stat_msg",
                }
                context = next((contexts[flag] for flag in flags if flag in contexts), "pkt_data")
                results.append((option, context, "i" in flags))
        return results

    active_context = "pkt_data"
    for index, option in enumerate(rule.options):
        key = option.key
        if key in DOTTED_TO_LEGACY_BUFFER:
            active_context = DOTTED_TO_LEGACY_BUFFER[key]
        elif (dialect == "snort3" and key in LEGACY_TO_DOTTED_BUFFER) or key in {
            "pkt_data",
            "raw_data",
            "file_data",
        }:
            active_context = key
        elif key == "content":
            cursor = index + 1
            modifiers: set[str] = set()
            while cursor < len(rule.options) and rule.options[cursor].key in CONTENT_MODIFIERS:
                modifiers.add(rule.options[cursor].key)
                cursor += 1
            results.append((option, active_context, "nocase" in modifiers))
        elif key == "pcre" and option.value is not None:
            results.append((option, active_context, "i" in pcre_flags(option.value)))
    return results


def panorama_case_checks(rule: Rule) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    flow = ",".join(rule.values("flow")).lower()
    for pattern, context, requested_nocase in pattern_contexts(rule):
        fixed_nocase: bool | None = None
        context_label = context
        if context in {"http_uri", "http_host", "http_user_agent"}:
            fixed_nocase = True
        elif context == "http_header":
            if "to_server" in flow:
                fixed_nocase = True
                context_label = "request HTTP header"
            elif "to_client" in flow:
                fixed_nocase = False
                context_label = "response HTTP header"
            else:
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "PANORAMA_HEADER_CASE_AMBIGUOUS",
                        "HTTP header case behavior cannot be verified without a flow direction",
                        pattern.name,
                    )
                )
                continue
        elif context in {"http_stat_code", "http_stat_msg", "file_data"}:
            fixed_nocase = False
        elif context in {"pkt_data", "raw_data"} and rule.protocol in {"tcp", "udp"}:
            fixed_nocase = True
            context_label = f"{rule.protocol}-context-free"
        if fixed_nocase is not None and fixed_nocase != requested_nocase:
            fixed_label = "case-insensitive" if fixed_nocase else "case-sensitive"
            requested_label = "case-insensitive" if requested_nocase else "case-sensitive"
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "PANORAMA_CASE_SEMANTICS_CHANGED",
                    f"The rule requests {requested_label} matching, but the plugin always uses {fixed_label} matching in {context_label}",
                    pattern.name,
                )
            )
    return diagnostics


def preceding_pattern(rule: Rule, option_index: int) -> RuleOption | None:
    for index in range(option_index - 1, -1, -1):
        candidate = rule.options[index]
        if candidate.key in {"content", "pcre"}:
            return candidate
        if candidate.key not in CONTENT_MODIFIERS:
            break
    return None


def panorama_option_checks(rule: Rule) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    allowed_actions = {"alert", "drop", "log", "pass", "reject", "sdrop"}
    if rule.action not in allowed_actions:
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "PANORAMA_ACTION_UNSUPPORTED",
                f"Action '{rule.action}' is not accepted by Panorama IPS Signature Converter {PANORAMA_PROFILE}",
            )
        )
    if rule.protocol not in PANORAMA_ALLOWED_PROTOCOLS:
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "PANORAMA_PROTOCOL_UNSUPPORTED",
                f"Protocol '{rule.protocol}' is not one of the plugin's five supported protocols: http, icmp, smb, tcp, udp",
            )
        )
    condition_count = sum(option.key in {"content", "pcre"} for option in rule.options)
    if condition_count > PANORAMA_MAX_CONDITIONS:
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "PANORAMA_TOO_MANY_CONDITIONS",
                f"Rule has {condition_count} detection conditions; the plugin limit is {PANORAMA_MAX_CONDITIONS}",
            )
        )
    raw_modifiers = {
        "http_raw_cookie",
        "http_raw_header",
        "http_raw_host",
        "http_raw_uri",
        "rawbytes",
    }
    for index, option in enumerate(rule.options):
        key = option.key
        if key in PANORAMA_IGNORED_DETECTION_OPTIONS:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "PANORAMA_IGNORES_DETECTION_OPTION",
                    f"The plugin ignores detection option '{option.name}', which would change rule behavior",
                    option.name,
                )
            )
        elif key in PANORAMA_IGNORED_METADATA_OPTIONS:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "info",
                    "PANORAMA_IGNORES_METADATA_OPTION",
                    f"The plugin ignores metadata option '{option.name}'",
                    option.name,
                )
            )
        elif key in raw_modifiers:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "PANORAMA_MODIFIER_UNSUPPORTED",
                    f"The plugin does not support modifier '{option.name}'",
                    option.name,
                )
            )
        elif key not in PANORAMA_SUPPORTED_OPTIONS:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "PANORAMA_OPTION_UNSUPPORTED",
                    f"Option '{option.name}' is neither supported nor safely ignored by the plugin",
                    option.name,
                )
            )
        if key in {"distance", "within"}:
            if option.value is None or not re.fullmatch(r"[0-9]+", option.value.strip()):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "PANORAMA_POSITION_NOT_INTEGER",
                        f"{option.name} must use an integer value",
                        option.name,
                    )
                )
            pattern = preceding_pattern(rule, index)
            if (
                pattern is None
                or pattern.key == "pcre"
                or (pattern.value is not None and pattern.value.lstrip().startswith("!"))
            ):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "PANORAMA_POSITION_SEMANTICS_IGNORED",
                        f"The plugin ignores {option.name} with PCRE or negated content",
                        option.name,
                    )
                )
            if (
                key == "within"
                and option.value is not None
                and option.value.strip().isdigit()
                and int(option.value.strip()) > 100
            ):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "PANORAMA_WITHIN_REDUCED",
                        "The plugin would reduce within to 100 and change rule behavior",
                        option.name,
                    )
                )
        if key == "pcre" and option.value is not None:
            diagnostics.extend(panorama_pcre_checks(rule, option))
        if (
            key == "reference"
            and option.value is not None
            and len(unquote(option.value)) > PANORAMA_MAX_REFERENCE_LENGTH
        ):
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "warning",
                    "PANORAMA_REFERENCE_IGNORED",
                    f"Reference exceeds the plugin's {PANORAMA_MAX_REFERENCE_LENGTH} character limit and will be ignored",
                    option.name,
                )
            )
        if key in {"threshold", "detection_filter"} and option.value is not None:
            diagnostics.extend(panorama_threshold_checks(rule, option))
    patterns = [
        option
        for option in rule.options
        if option.key in {"content", "pcre"} and option.value is not None
    ]
    if patterns and all(
        option.value is not None and option.value.lstrip().startswith("!") for option in patterns
    ):
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "PANORAMA_ONLY_NEGATED_CONDITIONS",
                "The plugin cannot convert a rule whose only detection conditions are negated",
                patterns[0].name,
            )
        )
    final_detection = patterns[-1] if patterns else None
    if (
        final_detection is not None
        and final_detection.value
        and final_detection.value.lstrip().startswith("!")
    ):
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "PANORAMA_FINAL_CONDITION_REORDERED",
                "The plugin would reorder a final negated condition and introduce false-positive risk",
                final_detection.name,
            )
        )
    pattern_details = pattern_contexts(rule)
    for pattern, context, _ in pattern_details:
        if pattern.key == "pcre" and context in {"pkt_data", "raw_data", "file_data"}:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "PANORAMA_PCRE_CONTEXT_UNSUPPORTED",
                    f"PCRE would map to unsupported plugin context '{context}'",
                    pattern.name,
                )
            )
    diagnostics.extend(panorama_case_checks(rule))
    return diagnostics


def panorama_pcre_checks(rule: Rule, option: RuleOption) -> list[Diagnostic]:
    value = unquote(option.value or "")
    diagnostics: list[Diagnostic] = []
    if len(value) > PANORAMA_MAX_PCRE_LENGTH:
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "PANORAMA_PCRE_TOO_LONG",
                f"PCRE is {len(value)} characters; the plugin limit is {PANORAMA_MAX_PCRE_LENGTH}",
                option.name,
            )
        )
    forbidden = {
        "(?>": "atomic grouping",
        "(?=": "positive lookahead",
        "(?!": "negative lookahead",
        "(?<=": "positive lookbehind",
        "(?<!": "negative lookbehind",
    }
    for token, label in forbidden.items():
        if token in value:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "PANORAMA_PCRE_UNSUPPORTED",
                    f"PCRE uses unsupported {label}",
                    option.name,
                )
            )
    if re.search(r"(?<!\\)\\[1-9]", value):
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "PANORAMA_PCRE_BACKREFERENCE",
                "PCRE uses an unsupported numeric backreference",
                option.name,
            )
        )
    if re.search(r"(?:[*+?]|\{\d+(?:,\d*)?\})\+", value):
        diagnostics.append(
            option_diagnostic(
                rule,
                "error",
                "PANORAMA_PCRE_POSSESSIVE_QUANTIFIER",
                "PCRE uses an unsupported possessive quantifier",
                option.name,
            )
        )
    return diagnostics


def panorama_threshold_checks(rule: Rule, option: RuleOption) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    value = option.value or ""
    seconds_match = re.search(r"(?:^|,)\s*seconds\s+([^,]+)", value, re.IGNORECASE)
    count_match = re.search(r"(?:^|,)\s*count\s+([^,]+)", value, re.IGNORECASE)
    for label, match, maximum in (
        ("seconds", seconds_match, PANORAMA_MAX_THRESHOLD_SECONDS),
        ("count", count_match, PANORAMA_MAX_THRESHOLD_COUNT),
    ):
        if match is None:
            continue
        try:
            number = int(match.group(1).strip())
        except ValueError:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "PANORAMA_THRESHOLD_NOT_INTEGER",
                    f"Threshold {label} must be an integer",
                    option.name,
                )
            )
            continue
        if number < 1 or number > maximum:
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "PANORAMA_THRESHOLD_OUT_OF_RANGE",
                    f"Threshold {label} must be between 1 and {maximum}",
                    option.name,
                )
            )
    return diagnostics


def build_panorama_report(
    parsed: ParseResult,
) -> tuple[dict[str, Any], list[Rule], list[Rule], list[Diagnostic]]:
    accepted: list[Rule] = []
    rejected: list[Rule] = []
    diagnostics = list(parsed.diagnostics)
    per_rule: list[dict[str, Any]] = []
    parse_error_lines = {item.start_line for item in parsed.errors}
    for rule in parsed.rules:
        findings = panorama_option_checks(rule)
        diagnostics.extend(findings)
        errors = [item for item in findings if item.severity == "error"]
        if errors:
            rejected.append(rule)
        else:
            accepted.append(rule)
        per_rule.append(
            {
                "index": rule.index,
                "line": rule.start_line,
                "gid": rule.gid,
                "sid": rule.sid,
                "accepted": not errors,
                "diagnostics": [item.to_dict() for item in findings],
            }
        )
    report = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "tool": {"name": APP_NAME, "version": VERSION},
        "profile": f"Panorama IPS Signature Converter Plugin {PANORAMA_PROFILE}",
        "source": parsed.source,
        "source_bytes": parsed.byte_count,
        "source_exceeds_plugin_upload_limit": parsed.byte_count > PANORAMA_MAX_UPLOAD_BYTES,
        "parsed_rules": len(parsed.rules),
        "accepted_rules": len(accepted),
        "rejected_rules": len(rejected),
        "unparsed_error_locations": sorted(line for line in parse_error_lines if line is not None),
        "batch_size": PANORAMA_MAX_RULES_PER_BATCH,
        "batch_count": (len(accepted) + PANORAMA_MAX_RULES_PER_BATCH - 1)
        // PANORAMA_MAX_RULES_PER_BATCH,
        "diagnostic_counts": diagnostic_counts(diagnostics),
        "rules": per_rule,
        "diagnostics": [item.to_dict() for item in diagnostics],
        "notice": (
            "This is an offline compatibility preflight. It does not replace validation in Panorama or a "
            "disposable firewall test environment. Generated batches contain source rules for the official plugin."
        ),
    }
    return report, accepted, rejected, diagnostics


def report_as_text(report: Mapping[str, Any]) -> str:
    lines = [
        f"{APP_NAME} Panorama Preflight",
        "=" * 48,
        f"Generated: {report['generated_at']}",
        f"Profile: {report['profile']}",
        f"Source: {report['source']}",
        f"Source bytes: {report['source_bytes']:,}",
        f"Parsed rules: {report['parsed_rules']:,}",
        f"Accepted rules: {report['accepted_rules']:,}",
        f"Rejected rules: {report['rejected_rules']:,}",
        f"Output batches: {report['batch_count']:,}",
        "",
        str(report["notice"]),
        "",
        "Diagnostics",
        "-" * 48,
    ]
    diagnostics = report.get("diagnostics", [])
    if not diagnostics:
        lines.append("No findings.")
    for item in diagnostics:
        location = f"line {item.get('start_line', '?')}"
        sid = f", SID {item['sid']}" if item.get("sid") is not None else ""
        lines.append(
            f"[{str(item['severity']).upper()}] {item['code']} ({location}{sid}): {item['message']}"
        )
    return "\n".join(lines) + "\n"


def ruleset_diff(before: ParseResult, after: ParseResult) -> dict[str, Any]:
    def index_rules(rules: Sequence[Rule]) -> dict[tuple[int, int], list[Rule]]:
        result: dict[tuple[int, int], list[Rule]] = defaultdict(list)
        for rule in rules:
            if rule.identity is not None:
                result[rule.identity].append(rule)
        return result

    old_index = index_rules(before.rules)
    new_index = index_rules(after.rules)
    all_ids = sorted(set(old_index) | set(new_index))
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unchanged = 0
    conflicts: list[dict[str, Any]] = []
    for identity in all_ids:
        old_group = old_index.get(identity, [])
        new_group = new_index.get(identity, [])
        if len(old_group) > 1 or len(new_group) > 1:
            conflicts.append(
                {
                    "gid": identity[0],
                    "sid": identity[1],
                    "before_count": len(old_group),
                    "after_count": len(new_group),
                }
            )
            continue
        if not old_group:
            added.append({"gid": identity[0], "sid": identity[1], "rev": new_group[0].rev})
        elif not new_group:
            removed.append({"gid": identity[0], "sid": identity[1], "rev": old_group[0].rev})
        else:
            old_rule, new_rule = old_group[0], new_group[0]
            if (
                semantic_fingerprint(old_rule) == semantic_fingerprint(new_rule)
                and old_rule.rev == new_rule.rev
            ):
                unchanged += 1
            else:
                changed.append(
                    {
                        "gid": identity[0],
                        "sid": identity[1],
                        "before_rev": old_rule.rev,
                        "after_rev": new_rule.rev,
                        "semantic_change": semantic_fingerprint(old_rule)
                        != semantic_fingerprint(new_rule),
                    }
                )
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "tool": {"name": APP_NAME, "version": VERSION},
        "before": before.source,
        "after": after.source,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": unchanged,
            "conflicts": len(conflicts),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "conflicts": conflicts,
        "parse_diagnostics": {
            "before": [item.to_dict() for item in before.diagnostics],
            "after": [item.to_dict() for item in after.diagnostics],
        },
    }


def safe_archive_name(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ConverterError(f"Archive contains an absolute path: {name!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ConverterError(f"Archive contains an unsafe path: {name!r}")
    reserved = (
        {"CON", "PRN", "AUX", "NUL"}
        | {f"COM{number}" for number in range(1, 10)}
        | {f"LPT{number}" for number in range(1, 10)}
    )
    for part in path.parts:
        stem = part.split(".", 1)[0].upper()
        if stem in reserved:
            raise ConverterError(f"Archive contains a Windows device path: {name!r}")
        if part.endswith((" ", ".")) or any(ord(char) < 32 or char in '<>:"|?*' for char in part):
            raise ConverterError(f"Archive contains a Windows-unsafe path: {name!r}")
    return path


def validate_tar_archive(data: bytes) -> list[tarfile.TarInfo]:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            members = archive.getmembers()
    except (tarfile.TarError, OSError) as exc:
        raise ConverterError(f"Downloaded file is not a valid tar archive: {exc}") from exc
    if len(members) > MAX_ARCHIVE_ENTRIES:
        raise ConverterError(
            f"Archive has {len(members):,} entries; limit is {MAX_ARCHIVE_ENTRIES:,}"
        )
    total = 0
    normalized_names: set[str] = set()
    for member in members:
        relative = safe_archive_name(member.name)
        normalized = "/".join(relative.parts).casefold()
        if normalized in normalized_names:
            raise ConverterError(f"Archive contains duplicate paths: {member.name!r}")
        normalized_names.add(normalized)
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise ConverterError(f"Archive contains a link or special file: {member.name!r}")
        if not (member.isfile() or member.isdir()):
            raise ConverterError(f"Archive contains an unsupported entry: {member.name!r}")
        if member.size < 0 or member.size > MAX_EXTRACTED_FILE_BYTES:
            raise ConverterError(f"Archive entry is too large: {member.name!r}")
        total += member.size
        if total > MAX_EXTRACTED_BYTES:
            raise ConverterError(f"Archive expands beyond the {MAX_EXTRACTED_BYTES:,} byte limit")
    return members


def validate_zip_archive(data: bytes) -> list[zipfile.ZipInfo]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        raise ConverterError(f"Downloaded file is not a valid zip archive: {exc}") from exc
    if len(members) > MAX_ARCHIVE_ENTRIES:
        raise ConverterError(
            f"Archive has {len(members):,} entries; limit is {MAX_ARCHIVE_ENTRIES:,}"
        )
    total = 0
    normalized_names: set[str] = set()
    for member in members:
        relative = safe_archive_name(member.filename.rstrip("/"))
        normalized = "/".join(relative.parts).casefold()
        if normalized in normalized_names:
            raise ConverterError(f"Archive contains duplicate paths: {member.filename!r}")
        normalized_names.add(normalized)
        if member.flag_bits & 0x1:
            raise ConverterError(f"Archive contains an encrypted entry: {member.filename!r}")
        unix_mode = (member.external_attr >> 16) & 0xFFFF
        if (unix_mode & 0o170000) == 0o120000:
            raise ConverterError(f"Archive contains a symbolic link: {member.filename!r}")
        if member.file_size < 0 or member.file_size > MAX_EXTRACTED_FILE_BYTES:
            raise ConverterError(f"Archive entry is too large: {member.filename!r}")
        total += member.file_size
        if total > MAX_EXTRACTED_BYTES:
            raise ConverterError(f"Archive expands beyond the {MAX_EXTRACTED_BYTES:,} byte limit")
    return members


def extract_archive(data: bytes, archive_type: str, output_dir: Path, force: bool) -> list[Path]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    def destination_for(name: str) -> Path:
        relative = safe_archive_name(name)
        destination = output_dir.joinpath(*relative.parts)
        if not destination.resolve(strict=False).is_relative_to(output_dir):
            raise ConverterError(f"Archive entry escapes the output directory: {name!r}")
        return destination

    if archive_type == "tar.gz":
        members = validate_tar_archive(data)
        ensure_outputs_available(
            (destination_for(member.name) for member in members if member.isfile()),
            force,
        )
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for member in members:
                destination = destination_for(member.name)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ConverterError(f"Cannot read archive entry: {member.name!r}")
                atomic_write_bytes(destination, extracted.read(), force=force)
                written.append(destination)
    elif archive_type == "zip":
        members = validate_zip_archive(data)
        ensure_outputs_available(
            (
                destination_for(member.filename.rstrip("/"))
                for member in members
                if not member.is_dir()
            ),
            force,
        )
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in members:
                destination = destination_for(member.filename.rstrip("/"))
                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                atomic_write_bytes(destination, archive.read(member), force=force)
                written.append(destination)
    else:
        raise ConverterError(f"Unsupported archive type: {archive_type}")
    return written


class RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]) -> None:
        super().__init__()
        self.allowed_hosts = {item.lower() for item in allowed_hosts}

    def redirect_request(
        self,
        request: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Any:
        parsed = urllib.parse.urlparse(newurl)
        if (
            parsed.scheme.lower() != "https"
            or (parsed.hostname or "").lower() not in self.allowed_hosts
        ):
            raise ConverterError(f"Refused redirect outside the HTTPS source allowlist: {newurl}")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def download_feed(source_name: str) -> tuple[bytes, dict[str, Any]]:
    source = FEEDS[source_name]
    url = str(source["url"])
    parsed = urllib.parse.urlparse(url)
    allowed_hosts = set(source["hosts"])
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in allowed_hosts:
        raise ConverterError("Built-in feed URL failed its HTTPS allowlist check")
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        RestrictedRedirectHandler(allowed_hosts),
    )
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"ids-rule-converter/{VERSION}",
            "Accept": "application/octet-stream",
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=30) as response:
            final_url = response.geturl()
            final = urllib.parse.urlparse(final_url)
            if final.scheme != "https" or (final.hostname or "").lower() not in allowed_hosts:
                raise ConverterError(
                    f"Download ended outside the HTTPS source allowlist: {final_url}"
                )
            length_header = response.headers.get("Content-Length")
            if length_header:
                try:
                    declared = int(length_header)
                except ValueError:
                    declared = 0
                if declared > MAX_DOWNLOAD_BYTES:
                    raise ConverterError(
                        f"Server declared {declared:,} bytes; limit is {MAX_DOWNLOAD_BYTES:,}"
                    )
            chunks: list[bytes] = []
            received = 0
            while True:
                chunk = response.read(min(1024 * 1024, MAX_DOWNLOAD_BYTES - received + 1))
                if not chunk:
                    break
                received += len(chunk)
                if received > MAX_DOWNLOAD_BYTES:
                    raise ConverterError(f"Download exceeded the {MAX_DOWNLOAD_BYTES:,} byte limit")
                chunks.append(chunk)
    except ConverterError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ConverterError(f"Feed download failed: {exc}") from exc
    data = b"".join(chunks)
    if not data:
        raise ConverterError("Feed download returned an empty file")
    metadata = {
        "source": source_name,
        "description": source["description"],
        "source_url": url,
        "resolved_url": urllib.parse.urlunparse(
            (final.scheme, final.netloc, final.path, "", "", "")
        ),
        "downloaded_at": utc_now(),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    return data, metadata


def print_diagnostics(diagnostics: Sequence[Diagnostic], limit: int = 25) -> None:
    for item in diagnostics[:limit]:
        location = (
            f"{item.source}:{item.start_line}" if item.start_line is not None else item.source
        )
        sid = f" SID {item.sid}" if item.sid is not None else ""
        print(
            f"{item.severity.upper()}: {item.code}: {location}{sid}: {item.message}",
            file=sys.stderr,
        )
    if len(diagnostics) > limit:
        print(
            f"... {len(diagnostics) - limit:,} additional diagnostics omitted from the console",
            file=sys.stderr,
        )


def command_validate(args: argparse.Namespace) -> int:
    parsed = RuleParser().parse_file(args.input)
    outputs = tuple(path for path in (args.json, args.sarif) if path is not None)
    ensure_outputs_do_not_replace_inputs(outputs, (args.input,))
    ensure_outputs_available(outputs, args.force)
    if args.json:
        payload = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "tool": {"name": APP_NAME, "version": VERSION},
            "source": parsed.source,
            "rule_count": len(parsed.rules),
            "diagnostic_counts": diagnostic_counts(parsed.diagnostics),
            "diagnostics": [item.to_dict() for item in parsed.diagnostics],
        }
        atomic_write_text(args.json, json_text(payload), force=args.force)
    if args.sarif:
        atomic_write_text(args.sarif, json_text(sarif_report(parsed)), force=args.force)
    print(
        f"Validated {len(parsed.rules):,} rules. "
        + ", ".join(f"{k}: {v}" for k, v in diagnostic_counts(parsed.diagnostics).items())
    )
    print_diagnostics(parsed.diagnostics)
    return EXIT_FINDINGS if parsed.errors else EXIT_OK


def command_analyze(args: argparse.Namespace) -> int:
    parsed = RuleParser().parse_file(args.input)
    report = ruleset_analysis(parsed)
    output = json_text(report)
    if args.output:
        ensure_outputs_do_not_replace_inputs((args.output,), (args.input,))
        destination = atomic_write_text(args.output, output, force=args.force)
        print(f"Wrote analysis to {destination}")
    else:
        print(output, end="")
    has_conflicts = bool(report["conflicting_sid_groups"])
    return EXIT_FINDINGS if parsed.errors or has_conflicts else EXIT_OK


def command_convert(args: argparse.Namespace) -> int:
    if args.target == "json" and (
        args.report or args.allow_partial or args.rejected_output or args.allow_unverified
    ):
        raise ConverterError(
            "JSON export does not use --report, --allow-partial, --rejected-output, or --allow-unverified"
        )
    if (
        args.target != "json"
        and args.allow_partial
        and (not args.report or not args.rejected_output)
    ):
        raise ConverterError(
            "--allow-partial requires --rejected-output and --report so every excluded rule remains reviewable"
        )
    if args.target != "json" and args.rejected_output and not args.allow_partial:
        raise ConverterError("--rejected-output requires --allow-partial")
    parsed = RuleParser().parse_file(args.input)
    requested_outputs = tuple(
        path for path in (args.output, args.report, args.rejected_output) if path is not None
    )
    ensure_outputs_do_not_replace_inputs(requested_outputs, (args.input,))
    if parsed.errors:
        print_diagnostics(parsed.diagnostics)
        print(
            "Conversion stopped because the input contains parse errors.",
            file=sys.stderr,
        )
        return EXIT_FINDINGS
    if args.target == "json":
        ensure_outputs_available(requested_outputs, args.force)
        payload = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "tool": {"name": APP_NAME, "version": VERSION},
            "source": parsed.source,
            "rules": [rule_to_dict(rule) for rule in parsed.rules],
            "diagnostics": [item.to_dict() for item in parsed.diagnostics],
        }
        atomic_write_text(args.output, json_text(payload), force=args.force)
        print(f"Exported {len(parsed.rules):,} rules to {args.output}")
        return EXIT_OK
    converted = convert_rules(
        parsed.rules,
        args.target,
        strict=not args.allow_unverified,
        source_dialect=args.source_dialect,
    )
    all_diagnostics = list(parsed.diagnostics) + converted.diagnostics
    output_lines = [
        f"# Generated by {APP_NAME} {VERSION}",
        f"# Source: {Path(parsed.source).name}",
        f"# Target dialect: {args.target}",
        f"# Rejected input rules: {len(converted.rejected_rule_indexes)}",
        "# Validate this ruleset with the target engine before deployment.",
        "",
        *converted.rules,
        "",
    ]
    if converted.rejected_rule_indexes and not args.allow_partial:
        print_diagnostics(all_diagnostics)
        print(
            f"Conversion stopped: {len(converted.rejected_rule_indexes):,} rules have unsafe target incompatibilities. "
            "No output was written.",
            file=sys.stderr,
        )
        return EXIT_FINDINGS
    if (
        args.allow_partial
        and converted.rejected_rule_indexes
        and (not args.rejected_output or not args.report)
    ):
        raise ConverterError(
            "--allow-partial requires --rejected-output and --report so every excluded rule remains reviewable"
        )
    rejected_text = ""
    if converted.rejected_rule_indexes:
        rejected_indexes = set(converted.rejected_rule_indexes)
        rejected_rules = [rule for rule in parsed.rules if rule.index in rejected_indexes]
        rejected_text = (
            f"# Rejected by {APP_NAME} {VERSION}\n"
            f"# Source: {Path(parsed.source).name}\n"
            "# See the JSON conversion report for incompatibility details.\n\n"
            + "\n".join(rule.raw.strip() for rule in rejected_rules)
            + "\n"
        )
    ensure_outputs_available(requested_outputs, args.force)
    atomic_write_text(args.output, "\n".join(output_lines), force=args.force)
    if args.rejected_output and converted.rejected_rule_indexes:
        atomic_write_text(args.rejected_output, rejected_text, force=args.force)
    if args.report:
        report = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "tool": {"name": APP_NAME, "version": VERSION},
            "source": parsed.source,
            "target": args.target,
            "source_dialect": args.source_dialect,
            "allow_unverified": args.allow_unverified,
            "input_rules": len(parsed.rules),
            "output_rules": len(converted.rules),
            "rejected_rules": len(converted.rejected_rule_indexes),
            "unverified_keywords": dict(sorted(converted.unverified_keywords.items())),
            "diagnostic_counts": diagnostic_counts(all_diagnostics),
            "diagnostics": [item.to_dict() for item in all_diagnostics],
        }
        atomic_write_text(args.report, json_text(report), force=args.force)
    print(f"Converted {len(converted.rules):,} rules to {args.target}: {args.output}")
    print_diagnostics(all_diagnostics)
    return EXIT_FINDINGS if converted.rejected_rule_indexes else EXIT_OK


def command_panorama(args: argparse.Namespace) -> int:
    parsed = RuleParser().parse_file(args.input)
    report, accepted, rejected, diagnostics = build_panorama_report(parsed)
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    files: list[tuple[Path, str]] = []
    for offset in range(0, len(accepted), PANORAMA_MAX_RULES_PER_BATCH):
        batch = accepted[offset : offset + PANORAMA_MAX_RULES_PER_BATCH]
        batch_number = offset // PANORAMA_MAX_RULES_PER_BATCH + 1
        text = "\n".join(rule.raw.strip() for rule in batch) + "\n"
        if len(text.encode("utf-8")) > PANORAMA_MAX_UPLOAD_BYTES:
            raise ConverterError(
                f"Generated batch {batch_number} exceeds the plugin's 8 MB upload limit"
            )
        files.append((output_dir / f"panorama_batch_{batch_number:04d}.rules", text))
    if rejected:
        files.append(
            (
                output_dir / "panorama_rejected.rules",
                "\n".join(rule.raw.strip() for rule in rejected) + "\n",
            )
        )
    files.extend(
        (
            (output_dir / "panorama_preflight.json", json_text(report)),
            (output_dir / "panorama_preflight.txt", report_as_text(report)),
        )
    )
    ensure_outputs_do_not_replace_inputs((path for path, _ in files), (args.input,))
    ensure_outputs_available((path for path, _ in files), args.force)
    for path, content in files:
        atomic_write_text(path, content, force=args.force)
    print(
        f"Panorama {PANORAMA_PROFILE} preflight: {len(accepted):,} accepted, {len(rejected):,} rejected, "
        f"{report['batch_count']:,} batches. Reports: {output_dir}"
    )
    print_diagnostics(diagnostics)
    return EXIT_FINDINGS if parsed.errors or rejected else EXIT_OK


def command_diff(args: argparse.Namespace) -> int:
    before = RuleParser().parse_file(args.before)
    after = RuleParser().parse_file(args.after)
    report = ruleset_diff(before, after)
    output = json_text(report)
    if args.output:
        ensure_outputs_do_not_replace_inputs((args.output,), (args.before, args.after))
        atomic_write_text(args.output, output, force=args.force)
        print(f"Wrote ruleset diff to {args.output}")
    else:
        print(output, end="")
    summary = report["summary"]
    return EXIT_FINDINGS if before.errors or after.errors or summary["conflicts"] else EXIT_OK


def command_list_sources(_args: argparse.Namespace) -> int:
    for name, source in FEEDS.items():
        print(f"{name}\n  {source['description']}\n  {source['url']}")
    return EXIT_OK


def command_fetch(args: argparse.Namespace) -> int:
    data, metadata = download_feed(args.source)
    source = FEEDS[args.source]
    extension = ".tar.gz" if source["archive"] == "tar.gz" else ".zip"
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"{args.source}{extension}"
    metadata_path = output_dir / f"{args.source}.metadata.json"
    ensure_outputs_available((archive_path, metadata_path), args.force)
    if args.extract:
        members = (
            validate_tar_archive(data)
            if source["archive"] == "tar.gz"
            else validate_zip_archive(data)
        )
        extraction_root = output_dir / args.source
        names = [
            member.name if isinstance(member, tarfile.TarInfo) else member.filename.rstrip("/")
            for member in members
            if not (isinstance(member, tarfile.TarInfo) and member.isdir())
            and not (isinstance(member, zipfile.ZipInfo) and member.is_dir())
        ]
        extraction_root_resolved = extraction_root.resolve()
        extraction_paths = []
        for name in names:
            relative = safe_archive_name(name)
            destination = extraction_root_resolved.joinpath(*relative.parts)
            if not destination.resolve(strict=False).is_relative_to(extraction_root_resolved):
                raise ConverterError(f"Archive entry escapes the output directory: {name!r}")
            extraction_paths.append(destination)
        ensure_outputs_available(extraction_paths, args.force)
    atomic_write_bytes(archive_path, data, force=args.force)
    atomic_write_text(metadata_path, json_text(metadata), force=args.force)
    if args.extract:
        extracted = extract_archive(
            data, str(source["archive"]), output_dir / args.source, force=args.force
        )
        print(
            f"Downloaded and safely extracted {len(extracted):,} files. SHA-256: {metadata['sha256']}"
        )
    else:
        print(f"Downloaded {len(data):,} bytes. SHA-256: {metadata['sha256']}")
    return EXIT_OK


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ids-rule-converter",
        description=(
            "Parse, validate, compare, and convert Snort and Suricata rules without silently dropping detection semantics."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION} ({BUILD_DATE})")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Validate rule syntax and identifiers")
    validate.add_argument("input", type=Path)
    validate.add_argument("--json", type=Path, help="Write a JSON validation report")
    validate.add_argument("--sarif", type=Path, help="Write a SARIF 2.1.0 validation report")
    validate.add_argument("--force", action="store_true", help="Replace output files")
    validate.set_defaults(handler=command_validate)

    analyze = subparsers.add_parser(
        "analyze", help="Inventory rules, keywords, duplicates, and SID conflicts"
    )
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--output", type=Path, help="Write JSON instead of printing it")
    analyze.add_argument("--force", action="store_true", help="Replace the output file")
    analyze.set_defaults(handler=command_analyze)

    convert = subparsers.add_parser("convert", help="Convert while preserving ordered rule options")
    convert.add_argument("input", type=Path)
    convert.add_argument(
        "--target", choices=("snort2", "snort3", "suricata", "json"), required=True
    )
    convert.add_argument(
        "--source-dialect",
        choices=("auto", "snort2", "snort3", "suricata"),
        default="auto",
        help="Declare the input dialect; auto infers it per rule",
    )
    convert.add_argument("--output", type=Path, required=True)
    convert.add_argument("--report", type=Path, help="Write a JSON conversion report")
    convert.add_argument(
        "--allow-partial",
        action="store_true",
        help="Write compatible rules even when some input rules are rejected",
    )
    convert.add_argument(
        "--rejected-output",
        type=Path,
        help="Write rules excluded by --allow-partial for manual review",
    )
    convert.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Preserve unverified target options instead of rejecting them",
    )
    convert.add_argument("--force", action="store_true", help="Replace output files")
    convert.set_defaults(handler=command_convert)

    panorama = subparsers.add_parser(
        "panorama-preflight",
        help=f"Validate and batch source rules for Panorama IPS Signature Converter {PANORAMA_PROFILE}",
    )
    panorama.add_argument("input", type=Path)
    panorama.add_argument("--output-dir", type=Path, required=True)
    panorama.add_argument("--force", action="store_true", help="Replace generated files")
    panorama.set_defaults(handler=command_panorama)

    difference = subparsers.add_parser("diff", help="Compare two rulesets by GID and SID")
    difference.add_argument("before", type=Path)
    difference.add_argument("after", type=Path)
    difference.add_argument("--output", type=Path, help="Write JSON instead of printing it")
    difference.add_argument("--force", action="store_true", help="Replace the output file")
    difference.set_defaults(handler=command_diff)

    sources = subparsers.add_parser("list-sources", help="List built-in HTTPS rule feeds")
    sources.set_defaults(handler=command_list_sources)

    fetch = subparsers.add_parser(
        "fetch", help="Download a built-in rule feed with archive safety checks"
    )
    fetch.add_argument("--source", choices=tuple(FEEDS), required=True)
    fetch.add_argument("--output-dir", type=Path, required=True)
    fetch.add_argument(
        "--extract", action="store_true", help="Safely extract the downloaded archive"
    )
    fetch.add_argument("--force", action="store_true", help="Replace generated files")
    fetch.set_defaults(handler=command_fetch)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except ConverterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

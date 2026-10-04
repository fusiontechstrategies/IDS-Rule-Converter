#!/usr/bin/env python3
"""Secure, loss-aware Snort and Suricata rule conversion toolkit.

This module intentionally uses only the Python standard library. It parses rules
into an ordered representation so option placement, sticky buffers, and content
modifiers are not silently discarded during conversion.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import multiprocessing
import os
import re
import signal
import ssl
import stat
import struct
import subprocess  # nosec B404
import sys
import tarfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import zlib
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, BinaryIO

APP_NAME = "IDS Rule Converter"
VERSION = "4.0.2"
BUILD_DATE = "2026-09-29"

EXIT_OK = 0
EXIT_OPERATIONAL_ERROR = 1
EXIT_FINDINGS = 2

MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_RULE_CHARS = 1 * 1024 * 1024
MAX_RULE_OPTIONS = 256
MAX_PARSED_RULES = 100_000
MAX_TOTAL_OPTIONS = 1_000_000
MAX_DIAGNOSTICS = 10_000
MAX_ARCHIVE_PATH_DEPTH = 32
MAX_ARCHIVE_COMPONENT_UTF8_BYTES = 255
MAX_ARCHIVE_COMPONENT_UTF16_UNITS = 255
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
FEED_DEADLINE_SECONDS = 30
MAX_FEED_METADATA_BYTES = 64 * 1024
MAX_ARCHIVE_ENTRIES = 20_000
MAX_TAR_PAX_FIELDS = 16
MAX_TAR_PAX_TOTAL_FIELDS = 4096
MAX_TAR_PAX_KEY_BYTES = 128
MAX_TAR_PAX_VALUE_BYTES = 4096
MAX_TAR_PAX_APPLICATIONS = 100_000
MAX_ZIP_DIRECTORY_BYTES = 8 * 1024 * 1024
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
RULE_TOKEN_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")

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

# This set is separate from inline content grammar: replace is a standalone
# post-match option, but generated SIP content can displace its source pattern.
DISPLACED_PATTERN_MODIFIERS = CONTENT_MODIFIERS | {"replace"}

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

# Suricata's underscore aliases are not all backward modifiers. Its documented
# HTTP content modifiers apply once to preceding content; file_data, DNS, SIP,
# http_protocol and http_header_names remain forward sticky selectors.
SURICATA_BACKWARD_BUFFERS = frozenset(
    {
        "http_client_body",
        "http_cookie",
        "http_header",
        "http_host",
        "http_method",
        "http_raw_header",
        "http_raw_host",
        "http_raw_uri",
        "http_server_body",
        "http_stat_code",
        "http_stat_msg",
        "http_uri",
        "http_user_agent",
    }
)
UNMAPPED_SNORT_BUFFERS = frozenset(
    {
        "dns_query",
        "http_header_names",
        "http_host",
        "http_protocol",
        "http_raw_host",
        "http_server_body",
        "http_user_agent",
    }
)

# Shared explicit selectors change the payload buffer independently of backward
# Snort 2 HTTP content modifiers. Keep all cursor and restoration paths aligned.
EXPLICIT_PAYLOAD_SELECTORS = frozenset(
    {"pkt_data", "raw_data", "file_data", "base64_data", "dce_stub_data"}
)
SNORT3_ONLY_OPTIONS = frozenset({"ber_data", "ber_skip"})

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


class UnterminatedBlockComment(ConverterError):
    def __init__(self, line: int):
        self.line = line
        super().__init__(f"UNTERMINATED_BLOCK_COMMENT at line {line}")


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
class _ParseContext:
    """Immutable evidence and admission summary created once for a complete parse."""

    diagnostics: tuple[Diagnostic, ...]
    has_errors: bool = field(init=False)
    unique_diagnostic_count: int = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "has_errors", any(d.severity == "error" for d in self.diagnostics))
        object.__setattr__(self, "unique_diagnostic_count", len(set(self.diagnostics)))


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
        require_text_without_nul(output_name, self.value)
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
    # Shared immutable context retains the entire parse, including a rejected suffix,
    # when callers copy or slice ParseResult.rules. None means unproven manual input.
    _parse_context: _ParseContext | None = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def _parse_diagnostics(self) -> tuple[Diagnostic, ...] | None:
        return self._parse_context.diagnostics if self._parse_context is not None else None

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
            return bounded_decimal(value)
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
        require_rule_header_shape(self)
        require_text_without_nul(
            self.action,
            self.protocol,
            self.source_address,
            self.source_port,
            self.direction,
            self.destination_address,
            self.destination_port,
        )
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


@dataclass(frozen=True)
class InputIdentity:
    path: Path
    device: int
    inode: int
    byte_count: int
    sha256: str | None = None


@dataclass
class ParseResult:
    source: str
    rules: list[Rule] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    ignored_directives: int = 0
    byte_count: int = 0
    input_identity: InputIdentity | None = None
    source_sha256: str | None = None
    _parse_context: _ParseContext | None = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def _parse_diagnostics(self) -> tuple[Diagnostic, ...] | None:
        return self._parse_context.diagnostics if self._parse_context is not None else None

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


def require_text_without_nul(*values: str | None) -> None:
    if any(value is not None and "\x00" in value for value in values):
        raise ConverterError("Input contains NUL characters and is not a text ruleset")


def validate_rule_text(rule: Rule) -> None:
    require_rule_header_shape(rule)
    require_text_without_nul(
        rule.raw,
        rule.source,
        rule.action,
        rule.protocol,
        rule.source_address,
        rule.source_port,
        rule.direction,
        rule.destination_address,
        rule.destination_port,
    )
    validate_options_text(rule.options)


def require_rule_header_shape(rule: Rule) -> None:
    """A file identification header has no protocol or network fields to discard."""
    if rule.action.casefold() == "file_id" and (
        rule.protocol != ""
        or any(
            value is not None
            for value in (
                rule.source_address,
                rule.source_port,
                rule.direction,
                rule.destination_address,
                rule.destination_port,
            )
        )
    ):
        raise ConverterError(
            "file_id requires its one-token header with no protocol/network fields"
        )


def validate_options_text(options: Sequence[RuleOption]) -> None:
    for option in options:
        require_text_without_nul(option.name, option.value, option.raw)


def open_windows_input_component(parent, name: str, *, directory: bool):
    """Open one existing component relative to its retained directory handle."""
    import ctypes.wintypes

    wintypes = ctypes.wintypes

    class UnicodeString(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.USHORT),
            ("maximum", wintypes.USHORT),
            ("buffer", wintypes.LPWSTR),
        ]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.ULONG),
            ("root", wintypes.HANDLE),
            ("name", ctypes.POINTER(UnicodeString)),
            ("attributes", wintypes.ULONG),
            ("security", ctypes.c_void_p),
            ("quality", ctypes.c_void_p),
        ]

    class IoStatusBlock(ctypes.Structure):
        _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    access = 0x120081 if directory else 0x120089
    if parent is None:
        kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel.CreateFileW.restype = wintypes.HANDLE
        handle = kernel.CreateFileW(name, access, 1, None, 3, 0x02200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        if name in {"", ".", ".."} or any(c in name for c in "\\/:"):
            raise ConverterError("Input component must be one local filesystem name")
        if name.endswith((" ", ".")):
            raise ConverterError("Input component cannot have ambiguous Windows suffixes")
        encoded = name.encode("utf-16-le")
        if len(encoded) > 65532:
            raise ConverterError("Input component exceeds its native name budget")
        buffer = ctypes.create_unicode_buffer(name)
        string = UnicodeString(len(encoded), len(encoded) + 2, ctypes.cast(buffer, wintypes.LPWSTR))
        attributes = ObjectAttributes(
            ctypes.sizeof(ObjectAttributes), parent, ctypes.pointer(string), 0x1040, None, None
        )
        status, handle = IoStatusBlock(), wintypes.HANDLE()
        native = ctypes.WinDLL("ntdll")
        native.NtCreateFile.argtypes = [
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            ctypes.POINTER(ObjectAttributes),
            ctypes.POINTER(IoStatusBlock),
            ctypes.c_void_p,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
            ctypes.c_void_p,
            wintypes.ULONG,
        ]
        native.NtCreateFile.restype = ctypes.c_int32
        native.RtlNtStatusToDosError.argtypes = [ctypes.c_int32]
        native.RtlNtStatusToDosError.restype = wintypes.ULONG
        result = native.NtCreateFile(
            ctypes.byref(handle),
            access,
            ctypes.byref(attributes),
            ctypes.byref(status),
            None,
            0,
            1,
            1,
            0x200020 | (1 if directory else 0x40),
            None,
            0,
        )
        if result < 0:
            raise ctypes.WinError(native.RtlNtStatusToDosError(result))
        handle = handle.value
    try:
        validate_windows_input_component(handle, directory=directory)
        return handle
    except BaseException:
        kernel.CloseHandle(handle)
        raise


def validate_windows_input_component(handle, *, directory: bool) -> None:
    import ctypes.wintypes

    wintypes = ctypes.wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    attributes = (wintypes.DWORD * 2)()
    if kernel.GetFileType(handle) != 1:
        raise ConverterError("Input handle is not a disk object")
    if not kernel.GetFileInformationByHandleEx(handle, 9, attributes, ctypes.sizeof(attributes)):
        raise ctypes.WinError(ctypes.get_last_error())
    if attributes[0] & 0x400 or bool(attributes[0] & 0x10) != directory:
        raise ConverterError("Input component is a link, reparse point, or unsupported object")


class _InputDirectoryDescriptor:
    """Own one retained directory descriptor; refuse use after ownership ends."""

    __slots__ = ("_descriptor",)

    def __init__(self, name: str, flags: int, *, parent: int | None = None):
        self._descriptor: int | None = os.open(name, flags, dir_fd=parent)

    def fileno(self) -> int:
        if self._descriptor is None:
            raise ConverterError("Input directory capability has already closed")
        return self._descriptor

    def close(self) -> None:
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is not None:
            os.close(descriptor)


@contextmanager
def _input_directory_descriptor(name: str, flags: int, *, parent: int | None = None):
    """Retain the owner, rather than transferring a bare descriptor to the stack."""
    owner = _InputDirectoryDescriptor(name, flags, parent=parent)
    try:
        yield owner
    finally:
        owner.close()


@contextmanager
def input_parent_namespace(path: Path):
    """Retain no-follow lexical ancestry for all admission and snapshot operations."""
    requested = canonical_system_path(path.expanduser().absolute())
    require_text_without_nul(str(requested))
    if ".." in requested.parts or not requested.name or requested == Path(requested.anchor):
        raise ConverterError("Input must select a file without parent traversal")
    with ExitStack() as stack:
        if sys.platform == "win32":
            import ctypes.wintypes

            if not re.fullmatch(r"[A-Za-z]:\\", requested.anchor):
                raise ConverterError("Input snapshots require a local Windows drive path")
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
            kernel.CloseHandle.restype = ctypes.wintypes.BOOL
            sid = current_windows_sid()
            parent = open_windows_input_component(None, requested.anchor, directory=True)
            stack.callback(kernel.CloseHandle, parent)
            verify_windows_parent_security(parent, sid)
            for part in requested.parent.parts[1:]:
                parent = open_windows_input_component(parent, part, directory=True)
                stack.callback(kernel.CloseHandle, parent)
                verify_windows_parent_security(parent, sid)
        else:
            if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
                raise ConverterError("Input snapshots require no-follow directory-relative opens")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            owner = stack.enter_context(_input_directory_descriptor(requested.anchor, flags))
            parent = owner.fileno()
            for part in requested.parent.parts[1:]:
                info = os.fstat(parent)
                if info.st_uid not in {0, os.geteuid()} or (
                    stat.S_IMODE(info.st_mode) & 0o022 and not info.st_mode & stat.S_ISVTX
                ):
                    raise ConverterError("Input ancestry can be replaced by another user")
                owner = stack.enter_context(_input_directory_descriptor(part, flags, parent=parent))
                parent = owner.fileno()
            info = os.fstat(parent)
            if info.st_uid not in {0, os.geteuid()} or (
                stat.S_IMODE(info.st_mode) & 0o022 and not info.st_mode & stat.S_ISVTX
            ):
                raise ConverterError("Input parent can be replaced by another user")
        yield requested, parent


def _open_input_leaf(path: Path, parent_descriptor) -> int:
    """Internal leaf open through the capability retained by input_parent_namespace."""
    if sys.platform != "win32":
        return os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
    import msvcrt

    handle = open_windows_input_component(parent_descriptor, path.name, directory=False)
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        import ctypes.wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        kernel.CloseHandle(handle)
        raise


def open_input_descriptor(path: Path) -> int:
    """Open a no-follow regular leaf through verified ancestry; exclude Windows writers."""
    with input_parent_namespace(path) as (requested, parent):
        return _open_input_leaf(requested, parent)


@contextmanager
def _input_binary_stream(path: Path, parent_descriptor):
    """Keep descriptor ownership through stream construction, use and close."""
    descriptor = _open_input_leaf(path, parent_descriptor)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            yield stream
    finally:
        os.close(descriptor)


def read_input(path: Path, max_bytes: int = MAX_INPUT_BYTES) -> tuple[str, InputIdentity]:
    if max_bytes < 0 or max_bytes > MAX_INPUT_BYTES:
        raise ConverterError("Input byte budget is outside its supported range")
    try:
        with input_parent_namespace(path) as (resolved, parent), ExitStack() as stack:
            expected = (
                None
                if sys.platform == "win32"
                else os.stat(resolved.name, dir_fd=parent, follow_symlinks=False)
            )
            if expected is not None and not stat.S_ISREG(expected.st_mode):
                raise ConverterError(f"Input is not a regular file: {resolved}")
            stream = stack.enter_context(_input_binary_stream(resolved, parent))
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ConverterError(f"Input is not a regular file: {resolved}")
            if expected is not None and (opened.st_dev, opened.st_ino) != (
                expected.st_dev,
                expected.st_ino,
            ):
                raise ConverterError("Input identity changed before reading")
            if opened.st_size > max_bytes:
                raise ConverterError(
                    f"Input is {opened.st_size:,} bytes; the limit is {max_bytes:,} bytes"
                )
            data = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
            if sys.platform == "win32":
                named_fd = _open_input_leaf(resolved, parent)
                try:
                    named = os.fstat(named_fd)
                finally:
                    os.close(named_fd)
            else:
                named = os.stat(resolved.name, dir_fd=parent, follow_symlinks=False)
            if (
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                    opened.st_ctime_ns,
                )
                or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
                or len(data) != opened.st_size
            ):
                raise ConverterError("Input changed during reading; no snapshot is safe")
        if len(data) > max_bytes:
            raise ConverterError(f"Input exceeds the {max_bytes:,} byte limit while reading")
    except OSError as exc:
        raise ConverterError(f"Cannot read input file '{path}': {exc}") from exc
    if b"\x00" in data:
        raise ConverterError(f"Input contains NUL bytes and is not a text ruleset: {resolved}")
    try:
        return data.decode("utf-8-sig"), InputIdentity(
            resolved, opened.st_dev, opened.st_ino, len(data), hashlib.sha256(data).hexdigest()
        )
    except UnicodeDecodeError as exc:
        raise ConverterError(
            f"Input is not valid UTF-8 at byte {exc.start}. Convert it to UTF-8 before processing."
        ) from exc


def read_utf8(path: Path, max_bytes: int = MAX_INPUT_BYTES) -> tuple[str, int]:
    text, identity = read_input(path, max_bytes)
    return text, identity.byte_count


def current_windows_sid():
    identity = subprocess.run(  # noqa: S603 # nosec B603
        [
            str(Path(os.environ["SYSTEMROOT"]) / "System32" / "whoami.exe"),
            "/user",
            "/fo",
            "csv",
            "/nh",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    sid = next(csv.reader([identity.stdout.strip()]))[1]
    if not re.fullmatch(r"S-1-[0-9-]+", sid):
        raise ConverterError("Cannot resolve current user SID")
    return sid


def verify_windows_parent_security(handle, sid, require_user_owner=False):
    """Read existing security by pinned handle. Never rewrite caller directories."""
    if sys.platform != "win32":
        raise OSError("Windows security APIs require Windows")
    import ctypes.wintypes

    wintypes = ctypes.wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.GetSecurityInfo.restype = wintypes.DWORD
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    security.ConvertSidToStringSidW.restype = wintypes.BOOL
    security.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    security.GetAclInformation.restype = wintypes.BOOL
    security.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    security.GetAce.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    canonical = ctypes.create_unicode_buffer(512)
    length = kernel.GetFinalPathNameByHandleW(handle, canonical, len(canonical), 1)
    volume_root = bool(
        0 < length < len(canonical)
        and re.fullmatch(r"\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}\\", canonical.value)
    )

    def sid_text(value):
        text = wintypes.LPWSTR()
        if not value or not security.ConvertSidToStringSidW(value, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            kernel.LocalFree(text)

    trusted = {
        sid,
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    error = security.GetSecurityInfo(
        handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)
    )
    if error:
        raise ctypes.WinError(error)
    try:
        actual_owner = sid_text(owner)
        if actual_owner not in trusted:
            raise ConverterError("Output directory has an untrusted owner")
        # OWNER RIGHTS denotes the owner whose SID was just validated, rather
        # than an independent principal. Python's private temp directories use it.
        trusted.add("S-1-3-4")
        if not dacl.value:
            raise ConverterError("Output directory has a NULL DACL")
        info = (wintypes.DWORD * 3)()
        if not security.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise ctypes.WinError(ctypes.get_last_error())
        if info[0] > 4096:
            raise ConverterError("Output directory ACL exceeds its inspection budget")
        # ADD_FILE or WRITE_ATTRIBUTES can authorize reparse-point retargeting
        # after our handles close, including on an intermediate directory.
        dangerous = 0x40 | 0x40000 | 0x80000
        if not volume_root:
            dangerous |= 0x2 | 0x100 | 0x10000
        if require_user_owner:
            dangerous |= 0x2 | 0x4 | 0x10 | 0x100
        for index in range(info[0]):
            ace = ctypes.c_void_p()
            if not security.GetAce(dacl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            address = ace.value
            if address is None:
                raise ConverterError("Missing output directory permission ACE")
            header = (ctypes.c_ubyte * 4).from_address(address)
            if header[1] & 0x08:  # INHERIT_ONLY cannot authorize mutation of this directory.
                continue
            if header[0] == 1:  # Ignoring denies conservatively refuses ambiguous grants.
                continue
            if header[0] != 0 or int.from_bytes(bytes(header[2:4]), "little") < 12:
                raise ConverterError("Unsupported output directory permission ACE")
            mask = ctypes.c_uint32.from_address(address + 4).value
            # Expand generic file rights before examining the specific mask.
            if mask & 0x10000000:
                mask |= 0x1F01FF
            if mask & 0x40000000:
                mask |= 0x120116
            if mask & dangerous and sid_text(address + 8) not in trusted:
                raise ConverterError("Output directory can be modified by another user")
    finally:
        kernel.LocalFree(descriptor)


@contextmanager
def windows_report_directory_lock(
    path, sid=None, remove_on_exit=False, *, parent_sid=None, require_user_owner=False
):
    """Hold a non-reparse directory against replacement; set its DACL by handle."""
    if sys.platform != "win32":
        raise OSError("Windows report directory handles are unavailable on this platform")
    if remove_on_exit and not sid:
        raise ValueError("Private directory removal requires a verified owner")
    import ctypes.wintypes

    wintypes = ctypes.wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    # LIST_DIRECTORY activates sharing checks; READ_ATTRIBUTES alone does not. Never share delete.
    handle = kernel.CreateFileW(
        str(path),
        0x81
        | (0x60000 if sid else 0)
        | (0x20000 if parent_sid else 0)
        | (0x10000 if remove_on_exit else 0),
        3,
        None,
        3,
        0x02200000,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    protected = False
    try:
        attributes = (wintypes.DWORD * 2)()
        if not kernel.GetFileInformationByHandleEx(
            handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not attributes[0] & 0x10 or attributes[0] & 0x400:
            raise PermissionError("Report directory must be a regular non-reparse directory")
        if parent_sid:
            verify_windows_parent_security(handle, parent_sid, require_user_owner)
        if sid:
            # A replaced staging pathname must not be adopted merely because
            # its DACL can be rewritten. Bind its owner before writing bytes.
            owner, owner_descriptor = ctypes.c_void_p(), ctypes.c_void_p()
            security.GetSecurityInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            security.GetSecurityInfo.restype = wintypes.DWORD
            security.ConvertSidToStringSidW.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(wintypes.LPWSTR),
            ]
            security.ConvertSidToStringSidW.restype = wintypes.BOOL
            error = security.GetSecurityInfo(
                handle, 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(owner_descriptor)
            )
            if error:
                raise ctypes.WinError(error)
            owner_text = wintypes.LPWSTR()
            try:
                if not security.ConvertSidToStringSidW(owner, ctypes.byref(owner_text)):
                    raise ctypes.WinError(ctypes.get_last_error())
                if owner_text.value != sid:
                    raise PermissionError("Report staging owner differs from its creator")
            finally:
                if owner_text:
                    kernel.LocalFree(owner_text)
                kernel.LocalFree(owner_descriptor)
            descriptor = ctypes.c_void_p()
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
            security.SetSecurityInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                wintypes.DWORD,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            security.SetSecurityInfo.restype = wintypes.DWORD
            if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                f"D:P(A;OICI;FA;;;{sid})", 1, ctypes.byref(descriptor), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
                if not security.GetSecurityDescriptorDacl(
                    descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
                if not present.value or not dacl.value:
                    raise PermissionError("Missing report protection DACL")
                error = security.SetSecurityInfo(handle, 1, 0x80000004, None, None, dacl, None)
                if error:
                    raise ctypes.WinError(error)
            finally:
                kernel.LocalFree(descriptor)
        protected = True
        yield
    finally:
        try:
            if remove_on_exit and protected:
                # The file cleanup runs while this handle and every ancestor are
                # still pinned. Delete this exact empty directory by handle.
                kernel.SetFileInformationByHandle.argtypes = [
                    wintypes.HANDLE,
                    ctypes.c_int,
                    ctypes.c_void_p,
                    wintypes.DWORD,
                ]
                kernel.SetFileInformationByHandle.restype = wintypes.BOOL
                disposition = wintypes.BOOL(True)
                if not kernel.SetFileInformationByHandle(
                    handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.CloseHandle(handle)


def windows_private_report_directory(parent, sid, *, on_created=None):
    """Create the directory with its protected owner DACL already in place."""
    if sys.platform != "win32":
        raise OSError("Windows security APIs require Windows")
    import ctypes.wintypes

    wintypes = ctypes.wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("descriptor", ctypes.c_void_p),
            ("inherit", wintypes.BOOL),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
    kernel.CreateDirectoryW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"O:{sid}D:P(A;OICI;FA;;;{sid})", 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        staging = parent / (".govhawk-private-" + os.urandom(16).hex())
        if not kernel.CreateDirectoryW(str(staging), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        if on_created is not None:
            on_created(staging)
        return staging
    finally:
        kernel.LocalFree(descriptor)


def reject_parent_links(path: Path) -> None:
    for parent in (path, *path.parents):
        if parent.is_symlink() or (
            parent.exists()
            and getattr(parent.lstat(), "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise ConverterError("Output parent contains a link or reparse point")


def canonical_system_path(path: Path) -> Path:
    """Expand only macOS root-owned system aliases, never user-created links."""
    if sys.platform == "darwin" and len(path.parts) > 1 and path.parts[1] in {"var", "tmp"}:
        alias = Path("/") / path.parts[1]
        expected = Path("/private") / path.parts[1]
        if alias.is_symlink() and alias.lstat().st_uid == 0 and alias.resolve() == expected:
            root = Path("/").stat()
            if root.st_uid == 0 and not stat.S_IMODE(root.st_mode) & 0o022:
                return expected.joinpath(*path.parts[2:])
    return path


def open_posix_directory(path: Path) -> int:
    """Walk from the root through no-follow descriptors and pin each component."""
    if sys.platform == "win32":
        raise ConverterError("POSIX output handles unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            ancestor = os.fstat(descriptor)
            if ancestor.st_uid not in {0, os.geteuid()} or (
                stat.S_IMODE(ancestor.st_mode) & 0o022 and not ancestor.st_mode & stat.S_ISVTX
            ):
                raise ConverterError("Output ancestry can be replaced by another user")
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def ensure_output_directory(path: Path, *, exclusive: bool = False) -> Path:
    """Create components while their actual parents are pinned, never through links."""
    requested = canonical_system_path(path.expanduser().absolute())
    if ".." in requested.parts:
        raise ConverterError("Output directory cannot contain parent traversal")
    reject_parent_links(requested)
    if os.name == "nt":
        sid = current_windows_sid()
        with ExitStack() as locks:
            current = Path(requested.anchor)
            locks.enter_context(
                windows_report_directory_lock(
                    current, parent_sid=sid, require_user_owner=current == requested
                )
            )
            for index, part in enumerate(requested.parts[1:], 1):
                current = current / part
                last = index == len(requested.parts) - 1
                if (exclusive and last) or not current.exists():
                    current.mkdir(mode=0o700)
                locks.enter_context(
                    windows_report_directory_lock(current, parent_sid=sid, require_user_owner=last)
                )
    else:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(requested.anchor, flags)
        try:
            for index, part in enumerate(requested.parts[1:], 1):
                ancestor = os.fstat(descriptor)
                if ancestor.st_uid not in {0, os.geteuid()} or (
                    stat.S_IMODE(ancestor.st_mode) & 0o022 and not ancestor.st_mode & stat.S_ISVTX
                ):
                    raise ConverterError("Output ancestry can be replaced by another user")
                last = index == len(requested.parts) - 1
                if exclusive and last:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
        finally:
            os.close(descriptor)
    return requested


def ensure_output_path(path: Path, force: bool) -> Path:
    requested = canonical_system_path(path.expanduser().absolute())
    resolved_parent = ensure_output_directory(requested.parent)
    resolved = resolved_parent / requested.name
    if resolved.is_symlink() or (
        resolved.exists()
        and getattr(resolved.lstat(), "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    ):
        raise ConverterError(f"Output leaf is a link or reparse point: {resolved}")
    if resolved.exists() and resolved.is_dir():
        raise ConverterError(f"Output path is a directory: {resolved}")
    if resolved.exists() and not force:
        raise ConverterError(f"Output already exists: {resolved}. Use --force to replace it.")
    return resolved


def ensure_outputs_available(paths: Iterable[Path], force: bool) -> None:
    seen: set[str] = set()
    for path in paths:
        resolved = ensure_output_path(path, force)
        key = portable_path_identity(resolved)
        if key in seen:
            raise ConverterError(f"The same output path was requested more than once: {resolved}")
        seen.add(key)
        if resolved.exists() and resolved.is_dir():
            raise ConverterError(f"Output path is a directory: {resolved}")
        if resolved.exists() and not force:
            raise ConverterError(f"Output already exists: {resolved}. Use --force to replace it.")


def portable_path_identity(path: Path) -> str:
    return unicodedata.normalize("NFC", str(path.expanduser().absolute())).casefold()


def ensure_outputs_do_not_replace_inputs(
    outputs: Iterable[Path], inputs: Iterable[InputIdentity | Path]
) -> None:
    identities = []
    for item in inputs:
        if isinstance(item, InputIdentity):
            identities.append(item)
        else:
            resolved = item.expanduser().resolve(strict=True)
            info = resolved.stat()
            identities.append(InputIdentity(resolved, info.st_dev, info.st_ino, info.st_size))
    for path in outputs:
        resolved = ensure_output_path(path, True)
        if any(
            portable_path_identity(resolved) == portable_path_identity(item.path)
            for item in identities
        ):
            raise ConverterError(f"Output path would replace an input file: {resolved}")
        try:
            leaf = resolved.stat()
        except FileNotFoundError:
            leaf = None
        refuse_input_leaf(leaf, identities)


def refuse_input_leaf(info: os.stat_result | None, inputs: Iterable[InputIdentity]) -> None:
    if info is not None and any(
        (info.st_dev, info.st_ino) == (item.device, item.inode) for item in inputs
    ):
        raise ConverterError("Output file identity would replace a file read as input")


def input_snapshots(*results: ParseResult) -> tuple[InputIdentity, ...]:
    identities = tuple(result.input_identity for result in results)
    if any(identity is None for identity in identities):
        raise ConverterError("File commands require verified input snapshots")
    return tuple(identity for identity in identities if identity is not None)


def write_output_payload(
    handle: BinaryIO, data: bytes | BinaryIO, expected_size: int | None
) -> None:
    """Stream decoded archive bytes under independent size and declaration checks."""
    if isinstance(data, bytes):
        if expected_size is not None and len(data) != expected_size:
            raise ConverterError("Archive entry length differs from its declaration")
        handle.write(data)
        return
    total = 0
    while chunk := data.read(64 * 1024):
        total += len(chunk)
        if total > MAX_EXTRACTED_FILE_BYTES or (
            expected_size is not None and total > expected_size
        ):
            raise ConverterError("Decoded archive entry exceeds its byte budget")
        handle.write(chunk)
    if expected_size is not None and total != expected_size:
        raise ConverterError("Archive entry length differs from its declaration")


@contextmanager
def _atomic_writer_stream(stream):
    """Keep a payload failure primary when buffered stream finalization fails."""
    initiating = []
    try:
        with stream as handle, _remember_archive_primary_error(initiating):
            yield handle
        if initiating:
            raise initiating[0]  # A stream must not suppress a failed payload.
    except BaseException as exc:
        if initiating and exc is not initiating[0]:
            _retain_archive_cleanup_failure(initiating[0], exc)
            raise initiating[0] from initiating[0].__cause__
        raise


def atomic_write_bytes(
    path: Path,
    data: bytes | BinaryIO,
    force: bool = False,
    *,
    expected_size: int | None = None,
    protected_inputs: Sequence[InputIdentity] = (),
    _archive_journal=None,
) -> Path:
    destination = ensure_output_path(path, force)
    ensure_outputs_do_not_replace_inputs((destination,), protected_inputs)
    if os.name != "nt":
        directory = open_posix_directory(destination.parent)
        temporary_name = f".ids-{uuid.uuid4().hex}.tmp"
        primary = None
        temporary_created = False
        temporary_identity = None
        try:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise ConverterError(
                    "Output parent must be owned by this user and not writable by others"
                )
            fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            temporary_created = True
            try:
                if _archive_journal is not None:
                    temporary_identity = _archive_journal.record_created(
                        destination.parent / temporary_name, False, descriptor=fd
                    )
                else:
                    info = os.fstat(fd)
                    temporary_identity = info.st_dev, info.st_ino
                handle = os.fdopen(fd, "wb")
            except BaseException:
                os.close(fd)
                raise
            with _atomic_writer_stream(handle) as handle:
                write_output_payload(handle, data, expected_size)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                leaf = os.stat(destination.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                leaf = None
            if leaf is not None and not stat.S_ISREG(leaf.st_mode):
                raise ConverterError("Output leaf must be a regular file")
            refuse_input_leaf(leaf, protected_inputs)
            if force:
                os.replace(
                    temporary_name, destination.name, src_dir_fd=directory, dst_dir_fd=directory
                )
            else:
                try:
                    os.link(
                        temporary_name,
                        destination.name,
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                        follow_symlinks=False,
                    )
                except FileExistsError as exc:
                    raise ConverterError(f"Output already exists: {destination}") from exc
            if _archive_journal is not None:
                _archive_journal.record_created(destination, False, identity=temporary_identity)
        except BaseException as exc:
            primary = exc
            raise
        finally:
            try:
                if temporary_created:
                    with suppress(FileNotFoundError):
                        info = os.stat(temporary_name, dir_fd=directory, follow_symlinks=False)
                        if (
                            not stat.S_ISREG(info.st_mode)
                            or (info.st_dev, info.st_ino) != temporary_identity
                        ):
                            raise ConverterError(
                                "Atomic writer temporary identity changed; cleanup refused"
                            )
                        os.unlink(temporary_name, dir_fd=directory)
            except (OSError, ConverterError) as cleanup:
                if primary is None:
                    raise
                _retain_archive_cleanup_failure(primary, cleanup)
            finally:
                try:
                    os.close(directory)
                except OSError as cleanup:
                    if primary is None:
                        raise
                    _retain_archive_cleanup_failure(primary, cleanup)
        return destination
    sid = current_windows_sid()
    with ExitStack() as locks:
        for parent in reversed((destination.parent, *destination.parent.parents)):
            locks.enter_context(
                windows_report_directory_lock(
                    parent, parent_sid=sid, require_user_owner=parent == destination.parent
                )
            )
        created = None
        if _archive_journal is not None:

            def created(path):
                _archive_journal.record_created(path, True, writer_destination=destination)

        staging = windows_private_report_directory(destination.parent, sid, on_created=created)
        primary = None
        try:
            with windows_report_directory_lock(staging, sid, remove_on_exit=True):
                temporary = staging / "report"
                temporary_created = False
                try:
                    with _atomic_writer_stream(temporary.open("xb")) as handle:
                        temporary_created = True
                        temporary_identity = None
                        if _archive_journal is not None:
                            temporary_identity = _archive_journal.record_created(
                                temporary, False, file=handle, writer_destination=destination
                            )
                        write_output_payload(handle, data, expected_size)
                        handle.flush()
                        os.fsync(handle.fileno())
                    if force:
                        try:
                            leaf = destination.stat()
                        except FileNotFoundError:
                            leaf = None
                        refuse_input_leaf(leaf, protected_inputs)
                        os.replace(temporary, destination)
                    else:
                        try:
                            os.link(temporary, destination)
                        except FileExistsError as exc:
                            raise ConverterError(f"Output already exists: {destination}") from exc
                    if _archive_journal is not None:
                        _archive_journal.record_created(
                            destination, False, identity=temporary_identity
                        )
                except BaseException as exc:
                    primary = exc
                    raise
                finally:
                    try:
                        if temporary_created:
                            temporary.unlink(missing_ok=True)
                    except OSError as cleanup:
                        if primary is None:
                            raise
                        _retain_archive_cleanup_failure(primary, cleanup)
        except BaseException as cleanup:
            if primary is not None and cleanup is not primary:
                _retain_archive_cleanup_failure(primary, cleanup)
                raise primary from primary.__cause__
            raise
    return destination


def atomic_write_text(
    path: Path, text: str, force: bool = False, *, protected_inputs: Sequence[InputIdentity] = ()
) -> Path:
    require_text_without_nul(text)
    return atomic_write_bytes(
        path, text.encode("utf-8"), force=force, protected_inputs=protected_inputs
    )


def json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def strip_rule_comments(text: str) -> str:
    """Remove # and C-style comments while preserving strings and newlines."""
    output = io.StringIO()
    quote = False
    escaped = False
    line_comment = False
    block_comment = False
    block_start_line = 1
    line = 1
    line_has_nonspace = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\n":
            line += 1
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
                line_has_nonspace = False
                output.write("\n")
            else:
                output.write(" ")
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                output.write("  ")
                block_comment = False
                index += 2
                continue
            if char == "\n":
                line_has_nonspace = False
                output.write("\n")
            else:
                output.write(" ")
            index += 1
            continue
        if quote:
            output.write(char)
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
            output.write(char)
            index += 1
            continue
        if char == "#" and not line_has_nonspace:
            line_comment = True
            output.write(" ")
            index += 1
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            block_start_line = line
            output.write("  ")
            index += 2
            continue
        output.write(char)
        if char == "\n":
            line_has_nonspace = False
        elif not char.isspace():
            line_has_nonspace = True
        index += 1
    if block_comment:
        raise UnterminatedBlockComment(block_start_line)
    return output.getvalue()


def split_top_level(
    text: str, delimiter: str, *, max_parts: int | None = None, respect_nesting: bool = True
) -> list[str]:
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
        elif char == delimiter and (not respect_nesting or (square == 0 and round_depth == 0)):
            parts.append(text[start:index])
            if max_parts is not None and len(parts) >= max_parts:
                raise ConverterError("Rule option budget exceeded; declare a smaller rule")
            start = index + 1
    parts.append(text[start:])
    if max_parts is not None and len(parts) > max_parts:
        raise ConverterError("Rule option budget exceeded; declare a smaller rule")
    return parts


def bounded_decimal(value: str, *, maximum: int = 4_294_967_295) -> int:
    text = value.strip()
    if not re.fullmatch(r"[0-9]{1,10}", text):
        raise ValueError("Expected a bounded unsigned decimal integer")
    number = int(text, 10)
    if number > maximum:
        raise ValueError("Decimal integer exceeds its supported range")
    return number


def valid_rule_identity(value: str) -> bool:
    try:
        return bounded_decimal(value) > 0
    except ValueError:
        return False


def extend_diagnostics(destination: list[Diagnostic], values: Sequence[Diagnostic]) -> None:
    if len(destination) + len(values) > MAX_DIAGNOSTICS:
        raise ConverterError("Diagnostic budget exceeded; no partial output is safe")
    destination.extend(values)


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
        text, identity = read_input(path)
        result = self.parse_text(text, str(identity.path), byte_count=identity.byte_count)
        result.input_identity = identity
        result.source_sha256 = identity.sha256
        return result

    def parse_text(
        self, text: str, source: str = "<memory>", *, byte_count: int | None = None
    ) -> ParseResult:
        require_text_without_nul(text, source)
        if len(text) > MAX_INPUT_BYTES:
            raise ConverterError("Input exceeds its character budget")
        actual_size = len(text.encode("utf-8"))
        size = actual_size if byte_count is None else byte_count
        if actual_size > MAX_INPUT_BYTES or size > MAX_INPUT_BYTES:
            raise ConverterError("Input exceeds its byte budget")
        if size < actual_size:
            raise ConverterError("Declared input byte count cannot understate its UTF-8 text")
        result = ParseResult(
            source=source,
            byte_count=size,
            source_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )
        try:
            cleaned = strip_rule_comments(text)
        except UnterminatedBlockComment as exc:
            result.diagnostics.append(
                Diagnostic(
                    "error", "UNTERMINATED_BLOCK_COMMENT", str(exc), source, exc.line, exc.line
                )
            )
            result._parse_context = _ParseContext(tuple(result.diagnostics))
            return result
        total_options = 0
        for record_index, (raw, start_line, end_line) in enumerate(
            self._records(cleaned, result), 1
        ):
            if record_index > MAX_PARSED_RULES:
                raise ConverterError("Parser rule count budget exceeded; no partial output is safe")
            rule, diagnostics = self._parse_record(raw, source, start_line, end_line, record_index)
            extend_diagnostics(result.diagnostics, diagnostics)
            if len(result.diagnostics) > MAX_DIAGNOSTICS:
                raise ConverterError("Parser diagnostic budget exceeded; no partial output is safe")
            if rule is not None:
                total_options += len(rule.options)
                if total_options > MAX_TOTAL_OPTIONS:
                    raise ConverterError(
                        "Parser total option budget exceeded; no partial output is safe"
                    )
                result.rules.append(rule)
        parse_context = _ParseContext(tuple(result.diagnostics))
        result._parse_context = parse_context
        for rule in result.rules:
            rule._parse_context = parse_context
        return result

    def _records(self, text: str, result: ParseResult) -> Iterator[tuple[str, int, int]]:
        index = 0
        line = 1
        length = len(text)
        line_end = -1
        # Do not expose a complete prefix until the remainder of its logical
        # line is accounted for. A directive is ignorable only at a line start.
        pending: list[tuple[str, int, int]] = []
        while index < length:
            if len(result.diagnostics) >= MAX_DIAGNOSTICS:
                raise ConverterError("Parser diagnostic budget exceeded; no partial output is safe")
            while index < length and text[index].isspace():
                if text[index] == "\n":
                    yield from pending
                    pending.clear()
                    line += 1
                index += 1
            if index >= length:
                yield from pending
                pending.clear()
                break
            if index >= line_end:
                line_end = text.find("\n", index)
                if line_end == -1:
                    line_end = length
            if line_end - index > MAX_RULE_CHARS:
                raise ConverterError("Input line exceeds the rule classification budget")
            token_match = RULE_TOKEN_PATTERN.match(text, index, line_end)
            token = token_match.group(0).lower() if token_match else ""
            looks_like_rule = token in RULE_ACTIONS
            if not looks_like_rule:
                # Inspect only this header, not each subsequent option body or record.
                opening = text.find("(", index, line_end)
                header_end = line_end if opening == -1 else opening
                looks_like_rule = (
                    text.find("->", index, header_end) != -1
                    or text.find("<>", index, header_end) != -1
                    or (opening != -1 and len(split_header(text[index:header_end])) == 2)
                )
                if not looks_like_rule:
                    following_index = line_end
                    following_limit = min(length, line_end + MAX_RULE_CHARS)
                    while following_index < following_limit and text[following_index].isspace():
                        following_index += 1
                    looks_like_rule = text.startswith(("(", "->", "<>"), following_index)
            if token not in RULE_ACTIONS and not looks_like_rule:
                if pending or text[index] == ")":
                    result.diagnostics.append(
                        Diagnostic(
                            "error",
                            "TRAILING_RULE_TEXT" if pending else "UNMATCHED_CLOSING_PARENTHESIS",
                            "Non-rule text follows a closed rule on the same logical line"
                            if pending
                            else "Unexpected closing parenthesis outside a rule",
                            result.source,
                            line,
                            line,
                        )
                    )
                    pending.clear()
                    index = line_end
                    continue
                result.ignored_directives += 1
                preview = " ".join(text[index : min(line_end, index + 160)].strip().split())
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
                        pending.append((text[start:index].strip(), start_line, line))
                        if len(pending) > MAX_PARSED_RULES:
                            raise ConverterError(
                                "Parser rule count budget exceeded; no partial output is safe"
                            )
                        break
                    if depth < 0:
                        break
                if index - start > MAX_RULE_CHARS:
                    pending.clear()
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
                pending.clear()
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
        yield from pending

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
        option_parts = split_top_level(
            body, ";", max_parts=MAX_RULE_OPTIONS + 1, respect_nesting=False
        )
        if len(option_parts) > MAX_RULE_OPTIONS + 1:
            raise ConverterError("Rule option budget exceeded; declare a smaller rule")
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
            if len(options) >= MAX_RULE_OPTIONS:
                raise ConverterError("Rule option budget exceeded; declare a smaller rule")
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
                content_parts = [
                    item.strip()
                    for item in split_top_level(
                        value, ",", max_parts=MAX_RULE_OPTIONS - len(options)
                    )
                ]
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
                    no_value = {"nocase", "rawbytes", "startswith", "endswith"}
                    optional_value = {"fast_pattern"}
                    if (
                        modifier_name.lower() not in CONTENT_MODIFIERS
                        or (modifier_name.lower() in no_value and modifier_value is not None)
                        or (
                            modifier_name.lower() not in no_value | optional_value
                            and modifier_value is None
                        )
                    ):
                        diagnostics.append(
                            Diagnostic(
                                "error",
                                "INVALID_INLINE_MODIFIER",
                                f"Invalid inline content modifier '{modifier_name}'",
                                source,
                                start_line,
                                end_line,
                                index,
                            )
                        )
                        continue
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
        try:
            require_rule_header_shape(rule)
        except ConverterError as exc:
            diagnostics.append(option_diagnostic(rule, "error", "INVALID_FILE_ID_HEADER", str(exc)))
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
        elif not valid_rule_identity(sid_values[0]):
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "INVALID_SID",
                    "sid must be a positive unsigned 32-bit integer",
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
            elif values and not valid_rule_identity(values[0]):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        f"INVALID_{name.upper()}",
                        f"{name} must be a positive unsigned 32-bit integer",
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
    if any(option.key in SNORT3_ONLY_OPTIONS for option in rule.options):
        return "snort3"
    if any(option.origin == "content-inline" for option in rule.options):
        return "snort3"
    if any("." in option.key for option in rule.options):
        return "suricata"
    # Some underscore aliases are forward selectors in Suricata too. A leading
    # one therefore cannot disambiguate a later backward-looking HTTP group.
    forward_aliases = frozenset(LEGACY_TO_DOTTED_BUFFER) - SURICATA_BACKWARD_BUFFERS - {"file_data"}
    if any(option.key in forward_aliases for option in rule.options) and (
        snort2_content_buffer_indexes(rule.options, SURICATA_BACKWARD_BUFFERS)
    ):
        return "ambiguous"
    first_content = next(
        (index for index, option in enumerate(rule.options) if option.key == "content"),
        None,
    )
    legacy_indexes = [
        index
        for index, option in enumerate(rule.options)
        if option.key in LEGACY_TO_DOTTED_BUFFER and option.key != "file_data"
    ]
    if legacy_indexes:
        if first_content is None or any(index < first_content for index in legacy_indexes):
            return "snort3"
        return "ambiguous"
    return "snort2"


def normalize_source_dialect(value: str | None) -> str:
    if value is None:
        return "auto"
    if not isinstance(value, str):
        raise ConverterError("Source dialect must be auto, snort2, snort3, or suricata")
    normalized = value.strip().lower()
    if normalized not in {"auto", "snort2", "snort3", "suricata"}:
        raise ConverterError(f"Unsupported source dialect: {value!r}")
    return normalized


def resolve_source_dialect(rule: Rule, value: str | None) -> str:
    normalized = normalize_source_dialect(value)
    return infer_dialect(rule) if normalized == "auto" else normalized


def concrete_source_dialect(value: str) -> str:
    normalized = normalize_source_dialect(value)
    if normalized == "auto":
        raise ConverterError("An option-only transformation requires an explicit source dialect")
    return normalized


def semantic_fingerprint(rule: Rule) -> str:
    normalized = {
        "header": rule.canonical_header(),
        "options": [
            [
                option.key,
                option.value,
            ]
            for option in rule.options
            if option.key not in {"rev"}
        ],
    }
    return hashlib.sha256(
        json.dumps(normalized, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def snort2_content_buffer_indexes(
    options: Sequence[RuleOption], backward_buffers: frozenset[str] | None = None
) -> dict[int, int]:
    if backward_buffers is None:
        backward_buffers = frozenset(LEGACY_TO_DOTTED_BUFFER) - {"file_data"}
    associations: dict[int, int] = {}
    for index, option in enumerate(options):
        if option.key != "content":
            continue
        cursor = index + 1
        while cursor < len(options) and options[cursor].key in CONTENT_MODIFIERS:
            cursor += 1
        if cursor < len(options) and options[cursor].key in backward_buffers:
            associations[index] = cursor
    return associations


def transform_snort2_to_snort3(
    options: Sequence[RuleOption], backward_buffers: frozenset[str] | None = None
) -> list[RuleOption]:
    validate_options_text(options)
    associations = snort2_content_buffer_indexes(options, backward_buffers)
    associated_buffers = set(associations.values())
    transformed: list[RuleOption] = []
    active_buffer = "pkt_data"
    payload_buffer = "pkt_data"
    # Generated selector restoration does not restore the source pattern cursor.
    # Keep its buffer provenance across flow, metadata and other neutral options.
    cursor_buffer = "pkt_data"
    cursor_preserved = False
    pattern_displaced = False
    pattern_incoming_cursor_preserved = False
    for index, option in enumerate(options):
        if index in associated_buffers:
            continue
        if option.key == "content":
            buffer_index = associations.get(index)
            desired = options[buffer_index].key if buffer_index is not None else payload_buffer
            pattern_incoming_cursor_preserved = (
                cursor_buffer == desired and active_buffer == desired and cursor_preserved
            )
            cursor = index + 1
            relative_pattern = False
            while cursor < len(options) and (
                options[cursor].key in CONTENT_MODIFIERS or cursor == buffer_index
            ):
                relative_pattern |= options[cursor].key in {"distance", "within"}
                cursor += 1
            if relative_pattern and not pattern_incoming_cursor_preserved:
                raise ConverterError(
                    "Relative content after a backward Snort 2 content modifier cannot preserve its cursor"
                )
            if desired != active_buffer:
                transformed.append(RuleOption(desired, None, desired))
                active_buffer = desired
                cursor_preserved = False
            transformed.append(option)
            pattern_displaced = False
            if option.value is not None and not option.value.lstrip().startswith("!"):
                cursor_buffer = desired
                cursor_preserved = True
            continue
        if option.key in EXPLICIT_PAYLOAD_SELECTORS:
            transformed.append(option)
            active_buffer = option.key
            payload_buffer = option.key
            cursor_buffer = option.key
            cursor_preserved = False
            pattern_displaced = True
            pattern_incoming_cursor_preserved = False
            continue
        if pattern_displaced and option.key in DISPLACED_PATTERN_MODIFIERS:
            raise ConverterError(
                "Displaced pattern modifier after a backward Snort 2 content group cannot preserve its pattern"
            )
        if option.key in {"distance", "within"} and not pattern_incoming_cursor_preserved:
            raise ConverterError(
                "Relative content after a backward Snort 2 content modifier cannot preserve its cursor"
            )
        # A backward modifier belongs only to its source content group. Restore
        # before any subsequent non-modifier instead of listing payload consumers.
        # Cursor-relative consumers cannot be moved safely between these buffers.
        if option.key not in DISPLACED_PATTERN_MODIFIERS:
            if (cursor_buffer != payload_buffer or not cursor_preserved) and (
                (
                    option.key == "pcre"
                    and option.value is not None
                    and "R" in pcre_flags(option.value)
                )
                or (
                    (
                        option.key.startswith("byte_")
                        or option.key in {"isdataat", "base64_decode", "asn1", "bufferlen"}
                    )
                    and option.value is not None
                    and re.search(r"\brelative(?:_offset)?\b", option.value.lower()) is not None
                )
            ):
                raise ConverterError(
                    "Relative payload operation after a backward Snort 2 content modifier cannot preserve its cursor"
                )
            if active_buffer != payload_buffer:
                transformed.append(RuleOption(payload_buffer, None, payload_buffer))
                active_buffer = payload_buffer
                cursor_preserved = False
                pattern_displaced = True
        transformed.append(option)
    return transformed


def transform_sticky_to_snort2(
    options: Sequence[RuleOption], source_dialect: str
) -> list[RuleOption]:
    source_dialect = concrete_source_dialect(source_dialect)
    validate_options_text(options)
    if source_dialect == "suricata":
        options = [
            RuleOption(LEGACY_TO_DOTTED_BUFFER[option.key], option.value, option.raw, option.origin)
            if option.key in LEGACY_TO_DOTTED_BUFFER and option.key not in SURICATA_BACKWARD_BUFFERS
            else option
            for option in options
        ]
    transformed: list[RuleOption] = []
    active_modifier: str | None = None
    selected_buffer = "pkt_data"
    cursor_buffer = "pkt_data"
    cursor_preserved = False
    pattern_preserved = False
    pattern_incoming_cursor_preserved = False
    payload_operations = {
        "pcre",
        "byte_extract",
        "byte_jump",
        "byte_math",
        "byte_test",
        "isdataat",
        "base64_decode",
        "asn1",
        "bufferlen",
    }
    for index, option in enumerate(options):
        key = option.key
        is_sticky = key in DOTTED_TO_LEGACY_BUFFER or (
            source_dialect == "snort3" and key in LEGACY_TO_DOTTED_BUFFER
        )
        if is_sticky:
            legacy = DOTTED_TO_LEGACY_BUFFER.get(key, key)
            if option.value is not None:
                raise ConverterError(
                    f"Sticky buffer '{option.name}' argument has no proven Snort 2 equivalent"
                )
            if legacy == "file_data":
                transformed.append(RuleOption("file_data", option.value, option.raw))
                active_modifier = None
                cursor_buffer = legacy
            else:
                active_modifier = legacy
            # Selection cannot create a match cursor or preserve modifiers of
            # a pattern selected before it, even when selecting the same buffer.
            cursor_preserved = False
            pattern_preserved = False
            pattern_incoming_cursor_preserved = False
            selected_buffer = legacy
            continue
        if key in EXPLICIT_PAYLOAD_SELECTORS:
            if option.value is not None:
                raise ConverterError(f"Payload selector '{option.name}' takes no arguments")
            active_modifier = None
            selected_buffer = key
            cursor_buffer = key
            cursor_preserved = False
            pattern_preserved = False
            pattern_incoming_cursor_preserved = False
            transformed.append(option)
            continue
        if key == "content":
            # A delayed modifier belongs to this pattern, not to the post-match
            # cursor this pattern may establish. Neutral options cannot hide it.
            pattern_incoming_cursor_preserved = (
                cursor_buffer == selected_buffer and cursor_preserved
            )
            cursor = index + 1
            relative = False
            while cursor < len(options) and options[cursor].key in CONTENT_MODIFIERS:
                relative |= options[cursor].key in {"distance", "within"}
                cursor += 1
            if relative and not pattern_incoming_cursor_preserved:
                raise ConverterError(
                    "Snort 2 downgrade cannot preserve relative content across buffer transitions"
                )
            if option.value is not None and not option.value.lstrip().startswith("!"):
                cursor_buffer = selected_buffer
                cursor_preserved = True
            pattern_preserved = True
        elif key in DISPLACED_PATTERN_MODIFIERS and not pattern_preserved:
            raise ConverterError(
                "Snort 2 downgrade cannot preserve a content modifier after a buffer transition"
            )
        elif key in {"distance", "within"} and not pattern_incoming_cursor_preserved:
            raise ConverterError(
                "Snort 2 downgrade cannot preserve the incoming cursor of relative content"
            )
        elif key in payload_operations:
            if active_modifier is not None:
                raise ConverterError(
                    f"Cannot safely express {option.name} under sticky buffer '{active_modifier}' in Snort 2"
                )
            relative = option.value is not None and (
                (key == "pcre" and "R" in pcre_flags(option.value))
                or re.search(r"\brelative(?:_offset)?\b", option.value.lower()) is not None
            )
            if relative and (cursor_buffer != selected_buffer or not cursor_preserved):
                raise ConverterError(
                    "Snort 2 downgrade cannot preserve the relative payload cursor"
                )
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


def implied_suricata_protocols(
    options: Sequence[RuleOption], rule_protocol: str, *, include_services: bool = True
) -> set[str]:
    """Return application protocols already asserted by headers or keywords."""
    protocols: set[str] = set()
    header_protocol = SNORT_SERVICE_TO_SURICATA.get(rule_protocol, rule_protocol)
    if header_protocol in SURICATA_APP_PROTOCOLS:
        protocols.add(header_protocol)
    for option in options:
        key = option.key
        if key == "service":
            if include_services and option.value is not None:
                mapped = mapped_suricata_service(option.value)
                if mapped is not None:
                    protocols.add(mapped)
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


def mapped_suricata_bufferlen(value: str | None) -> str | None:
    if value is None:
        return None
    # Accept the documented shared absolute numeric grammar only. This also
    # rejects relative qualifiers regardless of tabs, newlines or other spacing.
    match = re.fullmatch(r"\s*(<=|>=|[<>=])?\s*([0-9]+)\s*(?:<>\s*([0-9]+)\s*)?", value)
    if match is None:
        return None
    operator, first, second = match.groups()
    numbers = [number.lstrip("0") or "0" for number in (first, second) if number is not None]
    if any(len(number) > 5 or int(number) > 65535 for number in numbers):
        return None
    if second is not None:
        if operator is not None or int(numbers[0]) >= int(numbers[1]):
            return None
        return f"{int(numbers[0])}<>{int(numbers[1])}"
    return (operator or "") + str(int(numbers[0]))


def sip_relative_cursor_unsafe(options: Sequence[RuleOption]) -> bool:
    if not any(option.key in SNORT_TO_SURICATA_OPTION for option in options):
        return False
    if any(
        option.key in {"distance", "within"}
        or (option.key == "pcre" and option.value is not None and "R" in pcre_flags(option.value))
        or (
            (
                option.key.startswith("byte_")
                or option.key in {"isdataat", "base64_decode", "asn1", "bufferlen"}
            )
            and option.value is not None
            and re.search(r"\brelative(?:_offset)?\b", option.value.lower()) is not None
        )
        for option in options
    ):
        return True
    shorthand_since_pattern = False
    for option in options:
        if option.key in SNORT_TO_SURICATA_OPTION:
            shorthand_since_pattern = True
        elif option.key in {"content", "pcre"}:
            shorthand_since_pattern = False
        elif shorthand_since_pattern and option.key in DISPLACED_PATTERN_MODIFIERS:
            return True
    return False


def mapped_suricata_sip_value(option: RuleOption) -> str | None:
    value = unquote(option.value or "")
    grammar = r"[A-Za-z]+" if option.key == "sip_method" else r"(?:[1-9]|[1-9][0-9]{2})"
    return value.upper() if re.fullmatch(grammar, value) else None


def content_byte_length(value: str | None) -> int:
    """Count supported literal/hex content bytes without interpreting engine escapes."""
    if value is None or len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise ConverterError("Fast-pattern chopping requires non-negated quoted content")
    text = value[1:-1]
    count, index = 0, 0
    while index < len(text):
        if text[index] == "|":
            end = text.find("|", index + 1)
            if end < 0:
                raise ConverterError("Fast-pattern content has an unterminated hex segment")
            digits = "".join(text[index + 1 : end].split())
            if not digits or len(digits) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", digits):
                raise ConverterError("Fast-pattern content has an unsupported hex segment")
            count += len(digits) // 2
            index = end + 1
        elif text[index] == "\\":
            if index + 1 >= len(text) or text[index + 1] not in '\\";|:':
                raise ConverterError("Fast-pattern content escape has no proven byte length")
            count += 1
            index += 2
        else:
            count += len(text[index].encode("utf-8"))
            index += 1
    return count


def fast_pattern_pair(offset: str | None, length: str | None, content: RuleOption) -> str:
    try:
        first = bounded_decimal(offset or "", maximum=65535)
        size = bounded_decimal(length or "", maximum=65535)
    except ValueError as exc:
        raise ConverterError(
            "Fast-pattern offset/length require bounded unsigned integers"
        ) from exc
    if size < 1 or first + size > content_byte_length(content.value):
        raise ConverterError("Fast-pattern chop must be nonempty and fit its associated content")
    return f"{first},{size}"


def normalized_fast_pattern_options(
    options: Sequence[RuleOption], source_dialect: str
) -> list[RuleOption]:
    """Validate complete content groups and emit one marker for a supported chop."""
    source_dialect = concrete_source_dialect(source_dialect)
    validate_options_text(options)
    output: list[RuleOption] = []
    backwards = (
        frozenset(LEGACY_TO_DOTTED_BUFFER) - {"file_data"}
        if source_dialect == "snort2"
        else SURICATA_BACKWARD_BUFFERS
        if source_dialect == "suricata"
        else frozenset()
    )
    index, selected = 0, 0
    while index < len(options):
        content = options[index]
        if content.key != "content":
            if content.key in {"fast_pattern", "fast_pattern_offset", "fast_pattern_length"}:
                raise ConverterError("Fast-pattern modifiers require an associated content group")
            output.append(content)
            index += 1
            continue
        end = index + 1
        while end < len(options) and options[end].key in CONTENT_MODIFIERS | backwards:
            end += 1
        group = options[index + 1 : end]
        markers = [o for o in group if o.key == "fast_pattern"]
        offsets = [i for i, o in enumerate(group) if o.key == "fast_pattern_offset"]
        lengths = [i for i, o in enumerate(group) if o.key == "fast_pattern_length"]
        if len(markers) > 1:
            raise ConverterError("A content group cannot have competing fast-pattern markers")
        value: str | None = None
        has_pair = bool(offsets or lengths)
        if has_pair:
            if len(offsets) != 1 or len(lengths) != 1 or lengths[0] != offsets[0] + 1:
                raise ConverterError(
                    "Fast-pattern offset requires one adjacent length in its content group"
                )
            if markers and markers[0].value is not None:
                raise ConverterError(
                    "A valued fast-pattern marker cannot coexist with offset/length"
                )
            if any(o.key in {"width", "endian"} for o in group):
                raise ConverterError("Fast-pattern chopping of widened content is not supported")
            value = fast_pattern_pair(group[offsets[0]].value, group[lengths[0]].value, content)
        elif markers and markers[0].value is not None:
            if source_dialect == "snort3":
                raise ConverterError("Snort 3 requires a bare marker with separate chop modifiers")
            original = markers[0].value.strip()
            if original != "only":
                parts = original.split(",")
                if len(parts) != 2:
                    raise ConverterError("Unsupported fast-pattern marker value")
                value = fast_pattern_pair(parts[0], parts[1], content)
        if markers or has_pair:
            selected += 1
            if selected > 1:
                raise ConverterError("A rule cannot select multiple explicit fast-pattern contents")
        output.append(content)
        emitted = False
        for option in group:
            if value is not None and option.key in {
                "fast_pattern",
                "fast_pattern_offset",
                "fast_pattern_length",
            }:
                if not emitted:
                    output.append(RuleOption("fast_pattern", value, option.raw, option.origin))
                    emitted = True
            else:
                output.append(option)
        index = end
    return output


def transform_to_suricata(
    options: Sequence[RuleOption], source_dialect: str, rule_protocol: str
) -> list[RuleOption]:
    source_dialect = concrete_source_dialect(source_dialect)
    options = normalized_fast_pattern_options(options, source_dialect)
    if sip_relative_cursor_unsafe(options):
        raise ConverterError(
            "SIP shorthand cannot preserve a relative payload cursor or displaced pattern modifier"
        )
    if source_dialect == "snort2":
        options = transform_snort2_to_snort3(options)
        source_dialect = "snort3"
    transformed: list[RuleOption] = []
    if len(implied_suricata_protocols(options, rule_protocol)) > 1:
        raise ConverterError("Rule asserts conflicting application protocols")
    implied_protocols = implied_suricata_protocols(options, rule_protocol, include_services=False)
    emitted_services: set[str] = set()
    active_buffer = RuleOption("pkt_data", None, "pkt_data")
    index = 0
    while index < len(options):
        option = options[index]
        key = option.key
        if key == "service":
            service = mapped_suricata_service(option.value) if option.value is not None else None
            if service is None:
                raise ConverterError("service has no proven single-protocol Suricata mapping")
            if (
                service is not None
                and service not in implied_protocols
                and service not in emitted_services
            ):
                emitted_services.add(service)
                transformed.append(
                    RuleOption("app-layer-protocol", service, option.raw, option.origin)
                )
        elif key == "bufferlen":
            value = mapped_suricata_bufferlen(option.value)
            if value is None:
                raise ConverterError("bufferlen cannot safely map to Suricata bsize")
            transformed.append(RuleOption("bsize", value, option.raw, option.origin))
        elif key == "tag":
            value = mapped_suricata_tag(option.value) if option.value is not None else None
            if value is None:
                raise ConverterError("tag cannot safely map to Suricata")
            transformed.append(RuleOption("tag", value, option.raw, option.origin))
        elif key == "stream_size" and source_dialect in {"snort2", "snort3"}:
            value = mapped_suricata_stream_size(option.value) if option.value is not None else None
            if value is None:
                raise ConverterError("stream_size cannot safely map to Suricata")
            transformed.append(RuleOption("stream_size", value, option.raw, option.origin))
        elif key == "fast_pattern_offset":
            if (
                option.value is not None
                and re.fullmatch(r"[0-9]+", option.value.strip()) is not None
                and index + 1 < len(options)
                and options[index + 1].key == "fast_pattern_length"
                and options[index + 1].value is not None
                and re.fullmatch(r"[0-9]+", options[index + 1].value.strip()) is not None
            ):
                transformed.append(
                    RuleOption(
                        "fast_pattern",
                        f"{option.value.strip()},{options[index + 1].value.strip()}",
                        option.raw,
                    )
                )
                index += 1
            else:
                raise ConverterError(
                    "fast_pattern_offset requires adjacent numeric fast_pattern_length"
                )
        elif key == "fast_pattern_length":
            raise ConverterError("fast_pattern_length has no preceding fast_pattern_offset")
        elif key in SNORT_TO_SURICATA_OPTION:
            value = mapped_suricata_sip_value(option)
            if value is None:
                raise ConverterError(f"{option.name} has no safe single-value Suricata mapping")
            mapped = SNORT_TO_SURICATA_OPTION[key]
            transformed.append(RuleOption(mapped, None, option.raw, option.origin))
            transformed.append(RuleOption("content", f'"{value}"', option.raw))
            if key == "sip_stat_code" and len(value) == 1:
                transformed.append(RuleOption("startswith", None, "startswith"))
            transformed.append(active_buffer)
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
        if key not in SNORT_TO_SURICATA_OPTION and transformed:
            selected = transformed[-1]
            if (
                selected.key in DOTTED_TO_LEGACY_BUFFER
                or selected.key in EXPLICIT_PAYLOAD_SELECTORS
            ):
                active_buffer = selected
        index += 1
    return transformed


def transform_to_snort3(options: Sequence[RuleOption], source_dialect: str) -> list[RuleOption]:
    source_dialect = concrete_source_dialect(source_dialect)
    validate_options_text(options)
    if source_dialect == "snort2":
        options = transform_snort2_to_snort3(options)
    if source_dialect == "suricata" and any(
        option.key in SURICATA_BACKWARD_BUFFERS for option in options
    ):
        options = transform_snort2_to_snort3(options, SURICATA_BACKWARD_BUFFERS)
    transformed: list[RuleOption] = []
    for option in options:
        if source_dialect != "snort3" and option.key == "fast_pattern" and option.value is not None:
            parts = option.value.split(",")
            if len(parts) != 2:
                raise ConverterError(
                    "Snort 3 fast-pattern conversion requires a proven numeric chop"
                )
            transformed.extend(
                [
                    RuleOption("fast_pattern", None, option.raw, option.origin),
                    RuleOption("fast_pattern_offset", parts[0].strip(), option.raw, option.origin),
                    RuleOption("fast_pattern_length", parts[1].strip(), option.raw, option.origin),
                ]
            )
            continue
        mapped = DOTTED_TO_LEGACY_BUFFER.get(option.key)
        if mapped is None:
            transformed.append(option)
        else:
            transformed.append(RuleOption(mapped, option.value, option.raw, option.origin))
    return transformed


def complete_parse_diagnostics(
    source_rules: Sequence[Rule],
    parsed: ParseResult | None = None,
    *,
    allow_detached_rules: bool = False,
) -> list[Diagnostic]:
    """Collect bounded whole-parse evidence for every deployable output path."""
    if len(source_rules) > MAX_PARSED_RULES:
        raise ConverterError("Conversion rule count budget exceeded")
    diagnostics: list[Diagnostic] = []
    seen_contexts: set[int] = set()
    contexts: list[Sequence[Diagnostic]] = [parsed.diagnostics] if parsed is not None else []
    if parsed is not None and parsed._parse_diagnostics is not None:
        seen_contexts.add(id(parsed._parse_diagnostics))
        contexts.append(parsed._parse_diagnostics)
    if not source_rules and (parsed is None or parsed._parse_diagnostics is None):
        extend_diagnostics(
            diagnostics,
            [
                Diagnostic(
                    "error",
                    "DETACHED_RULE_PROVENANCE",
                    "An empty rule sequence has no complete-parse provenance; pass the parser-produced ParseResult",
                    parsed.source if parsed is not None else "<input>",
                )
            ],
        )
    unproven: list[Rule] = []
    for rule in source_rules:
        origin = rule._parse_diagnostics
        if origin is None:
            unproven.append(rule)
        elif id(origin) not in seen_contexts:
            seen_contexts.add(id(origin))
            contexts.append(origin)
    seen_diagnostics: set[Diagnostic] = set()
    for context in contexts:
        # ParseResult and its immutable Rule context usually describe the same
        # diagnostics. Deduplicate before counting, preserving every unique one.
        for diagnostic in context:
            if diagnostic not in seen_diagnostics:
                extend_diagnostics(diagnostics, [diagnostic])
                seen_diagnostics.add(diagnostic)
    if unproven:
        extend_diagnostics(
            diagnostics,
            [
                Diagnostic(
                    "warning" if allow_detached_rules else "error",
                    "DETACHED_RULE_PROVENANCE",
                    "Manual Rule objects have no complete-parse provenance; pass ParseResult or explicitly acknowledge allow_detached_rules=True",
                    unproven[0].source,
                )
            ],
        )
    return diagnostics


def render_rule(
    rule: Rule,
    target: str,
    source_dialect: str | None = None,
    *,
    allow_detached_rules: bool = False,
) -> str:
    validate_rule_text(rule)
    if MAX_PARSED_RULES < 1:
        raise ConverterError("Conversion rule count budget exceeded")
    # The parser computes this summary once over the immutable complete context.
    # Public per-rule and JSON calls must not rescan it for every rule in a batch.
    context = rule._parse_context
    if context is None:
        if MAX_DIAGNOSTICS < 1:
            raise ConverterError("Diagnostic budget exceeded; no partial output is safe")
        if not allow_detached_rules:
            raise ConverterError(
                "Complete parse provenance is required; no partial rule output is safe"
            )
    elif context.unique_diagnostic_count > MAX_DIAGNOSTICS:
        raise ConverterError("Diagnostic budget exceeded; no partial output is safe")
    elif context.has_errors:
        raise ConverterError(
            "Complete parse provenance is required; no partial rule output is safe"
        )
    dialect = resolve_source_dialect(rule, source_dialect)
    if dialect == "ambiguous":
        if target == "ambiguous":
            return f"{rule.canonical_header()} ({' '.join(option.rendered() for option in rule.options)})"
        raise ConverterError("Ambiguous buffer placement requires an explicit source dialect")
    if target not in TARGET_ACTIONS:
        raise ConverterError(f"Unsupported conversion target: {target}")
    # Preserve the documented non-strict unknown-keyword path, but never bypass
    # known hard compatibility failures through this importable renderer.
    diagnostics, _ = compatibility_diagnostics(rule, target, False, dialect)
    errors = [item.message for item in diagnostics if item.severity == "error"]
    if errors:
        raise ConverterError("; ".join(errors))
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
    validate_rule_text(rule)
    source_dialect = resolve_source_dialect(rule, source_dialect)
    if source_dialect == "ambiguous":
        raise ConverterError("Ambiguous buffer placement requires an explicit source dialect")
    diagnostics: list[Diagnostic] = []
    try:
        normalized_fast_pattern_options(rule.options, source_dialect)
    except ConverterError as exc:
        diagnostics.append(
            option_diagnostic(rule, "error", "UNSAFE_FAST_PATTERN_MAPPING", str(exc))
        )
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
        if sip_relative_cursor_unsafe(rule.options):
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "SIP_RELATIVE_CURSOR_UNSAFE",
                    "SIP shorthand conversion cannot preserve relative payload cursors or displaced pattern modifiers",
                )
            )
    for option_index, option in enumerate(rule.options):
        key = option.key
        if target in {"snort2", "snort3"} and (
            key in UNMAPPED_SNORT_BUFFERS
            or DOTTED_TO_LEGACY_BUFFER.get(key) in UNMAPPED_SNORT_BUFFERS
        ):
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "UNSUPPORTED_TARGET_BUFFER",
                    f"Buffer '{option.name}' has no proven {target} selector mapping",
                    option.name,
                )
            )
        elif target == "suricata" and key == "service":
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
            if mapped_suricata_bufferlen(option.value) is None:
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "UNSAFE_BUFFERLEN_MAPPING",
                        "bufferlen can map to Suricata bsize only for absolute 0..65535 comparisons or ascending exclusive ranges",
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
            if mapped_suricata_sip_value(option) is None:
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
            if mapped_suricata_sip_value(option) is None:
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
        elif target == "snort2" and key in {"endswith", "startswith"} | SNORT3_ONLY_OPTIONS:
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
    if target == "snort2" and (
        source_dialect in {"snort3", "suricata"}
        or any(option.value and option.key in LEGACY_TO_DOTTED_BUFFER for option in rule.options)
    ):
        for option in rule.options:
            key = option.key
            if (
                key in DOTTED_TO_LEGACY_BUFFER
                or (
                    (source_dialect == "snort3" or option.value is not None)
                    and key in LEGACY_TO_DOTTED_BUFFER
                )
            ) and option.value is not None:
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "UNSUPPORTED_BUFFER_ARGUMENT",
                        f"Sticky buffer '{option.name}' argument has no proven Snort 2 equivalent",
                        option.name,
                    )
                )
        try:
            transform_sticky_to_snort2(rule.options, source_dialect)
        except ConverterError as exc:
            diagnostics.append(
                option_diagnostic(rule, "error", "UNSAFE_STICKY_BUFFER_DOWNGRADE", str(exc))
            )
    backward_buffers = (
        SURICATA_BACKWARD_BUFFERS
        if source_dialect == "suricata"
        else frozenset(LEGACY_TO_DOTTED_BUFFER) - {"file_data"}
    )
    if (target in {"snort3", "suricata"} and source_dialect == "snort2") or (
        target in {"snort2", "snort3"} and source_dialect == "suricata"
    ):
        associated = set(snort2_content_buffer_indexes(rule.options, backward_buffers).values())
        for index, option in enumerate(rule.options):
            if option.key in backward_buffers and index not in associated:
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "AMBIGUOUS_LEGACY_BUFFER",
                        f"Cannot associate legacy buffer modifier '{option.name}' with a content option",
                        option.name,
                    )
                )
        if (
            source_dialect == "suricata"
            and any(option.key in backward_buffers for option in rule.options)
            and any(
                option.key in DOTTED_TO_LEGACY_BUFFER
                or (
                    option.key in LEGACY_TO_DOTTED_BUFFER
                    and option.key not in backward_buffers
                    and option.key != "file_data"
                )
                for option in rule.options
            )
        ):
            diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "MIXED_SURICATA_BUFFER_FORMS",
                    "Mixed Suricata sticky selectors and backward content modifiers cannot be safely converted",
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
    rules: ParseResult | Sequence[Rule],
    target: str,
    strict: bool = True,
    source_dialect: str = "auto",
    *,
    allow_detached_rules: bool = False,
) -> ConversionResult:
    """Convert a complete parse. Manual Rule objects require explicit provenance acknowledgement.

    That acknowledgement never overrides errors retained from a real parse. It
    does not relax dialect or semantic compatibility checks.
    """
    source_dialect = normalize_source_dialect(source_dialect)
    if target not in TARGET_ACTIONS:
        raise ConverterError(f"Unsupported conversion target: {target}")
    result = ConversionResult(target=target)
    parsed = rules if isinstance(rules, ParseResult) else None
    source_rules = parsed.rules if parsed is not None else rules
    if len(source_rules) > MAX_PARSED_RULES:
        raise ConverterError("Conversion rule count budget exceeded")
    extend_diagnostics(
        result.diagnostics,
        complete_parse_diagnostics(source_rules, parsed, allow_detached_rules=allow_detached_rules),
    )
    if result.errors:
        result.rejected_rule_indexes = [rule.index for rule in source_rules]
        return result
    for rule in source_rules:
        if len(result.diagnostics) >= MAX_DIAGNOSTICS:
            raise ConverterError("Diagnostic budget exceeded; no partial output is safe")
        dialect = resolve_source_dialect(rule, source_dialect)
        if dialect == "ambiguous":
            result.diagnostics.append(
                option_diagnostic(
                    rule,
                    "error",
                    "AMBIGUOUS_SOURCE_DIALECT",
                    "Legacy buffer placement has incompatible Snort 2 and Snort 3 meanings. Choose --source-dialect explicitly.",
                )
            )
            result.rejected_rule_indexes.append(rule.index)
            continue
        diagnostics, unverified = compatibility_diagnostics(rule, target, strict, dialect)
        extend_diagnostics(result.diagnostics, diagnostics)
        result.unverified_keywords.update(unverified)
        if any(item.severity == "error" for item in diagnostics):
            result.rejected_rule_indexes.append(rule.index)
            continue
        try:
            rendered = render_rule(rule, target, dialect, allow_detached_rules=allow_detached_rules)
        except ConverterError as error:
            extend_diagnostics(
                result.diagnostics,
                [option_diagnostic(rule, "error", "UNSAFE_RULE_TRANSFORMATION", str(error))],
            )
            result.rejected_rule_indexes.append(rule.index)
            continue
        result.rules.append(rendered)
    if result.unverified_keywords and not strict:
        if len(result.diagnostics) >= MAX_DIAGNOSTICS:
            raise ConverterError("Diagnostic budget exceeded; no partial output is safe")
        result.diagnostics.append(
            Diagnostic(
                "warning",
                "UNVERIFIED_KEYWORDS_PRESERVED",
                "Some target keywords were preserved exactly but require validation in the target engine: "
                + ", ".join(sorted(result.unverified_keywords)),
                source_rules[0].source if source_rules else "<input>",
            )
        )
    return result


def rule_to_dict(rule: Rule, *, allow_detached_rules: bool = False) -> dict[str, Any]:
    dialect = infer_dialect(rule)
    canonical_rule = render_rule(rule, dialect, allow_detached_rules=allow_detached_rules)
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
        "canonical_rule": canonical_rule,
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
        "source_sha256": parsed.source_sha256,
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


def sarif_artifact_uri(source: str) -> str:
    """Encode filesystem identity, including Windows drive/UNC paths on any host."""
    if re.match(r"^[A-Za-z]:[\\/]", source) or source.startswith("\\\\"):
        return PureWindowsPath(source).as_uri()
    path = PurePosixPath(source)
    if path.is_absolute():
        return path.as_uri()
    return urllib.parse.quote(path.as_posix(), safe="/")


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
                        "artifactLocation": {"uri": sarif_artifact_uri(item.source)},
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
                "artifacts": [
                    {
                        "location": {"uri": sarif_artifact_uri(parsed.source)},
                        "length": parsed.byte_count,
                        **(
                            {"hashes": {"sha-256": parsed.source_sha256}}
                            if parsed.source_sha256
                            else {}
                        ),
                    }
                ],
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
    backward_buffers = (
        frozenset(LEGACY_TO_DOTTED_BUFFER) - {"file_data"}
        if dialect == "snort2"
        else SURICATA_BACKWARD_BUFFERS
        if dialect == "suricata"
        else frozenset()
    )
    buffer_indexes = snort2_content_buffer_indexes(rule.options, backward_buffers)
    active_context = "pkt_data"
    for index, option in enumerate(rule.options):
        key = option.key
        if key in DOTTED_TO_LEGACY_BUFFER:
            active_context = DOTTED_TO_LEGACY_BUFFER[key]
        elif (
            key in LEGACY_TO_DOTTED_BUFFER and key not in backward_buffers
        ) or key in EXPLICIT_PAYLOAD_SELECTORS:
            active_context = key
        elif key == "content":
            modifier_index = buffer_indexes.get(index)
            context = (
                rule.options[modifier_index].key if modifier_index is not None else active_context
            )
            cursor = index + 1
            modifiers: set[str] = set()
            while cursor < len(rule.options) and (
                rule.options[cursor].key in CONTENT_MODIFIERS or cursor == modifier_index
            ):
                modifiers.add(rule.options[cursor].key)
                cursor += 1
            results.append((option, context, "nocase" in modifiers))
        elif key == "pcre" and option.value is not None:
            flags = pcre_flags(option.value)
            contexts = (
                {
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
                if dialect == "snort2"
                else {}
            )
            context = next((contexts[flag] for flag in flags if flag in contexts), active_context)
            results.append((option, context, "i" in flags))
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
    validate_rule_text(rule)
    diagnostics: list[Diagnostic] = []
    if infer_dialect(rule) == "ambiguous":
        return [
            option_diagnostic(
                rule,
                "error",
                "AMBIGUOUS_SOURCE_DIALECT",
                "Buffer placement has incompatible Snort 2 and Snort 3 meanings; Panorama preflight cannot verify it.",
            )
        ]
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
        # Equivalent legacy and dotted selectors must receive one policy decision.
        key = DOTTED_TO_LEGACY_BUFFER.get(option.key, option.key)
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
            if (
                option.value is None
                or len(option.value.strip()) > 10
                or not re.fullmatch(r"[0-9]+", option.value.strip())
            ):
                diagnostics.append(
                    option_diagnostic(
                        rule,
                        "error",
                        "PANORAMA_POSITION_NOT_INTEGER",
                        f"{option.name} must use a bounded unsigned integer value",
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
                and len(option.value.strip()) <= 10
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
            number = bounded_decimal(match.group(1))
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
    diagnostics = complete_parse_diagnostics(parsed.rules, parsed)
    incomplete_parse = any(item.severity == "error" for item in diagnostics)
    per_rule: list[dict[str, Any]] = []
    parse_error_lines = {item.start_line for item in diagnostics if item.severity == "error"}
    for rule in parsed.rules:
        findings = panorama_option_checks(rule)
        if incomplete_parse:
            findings.append(
                option_diagnostic(
                    rule,
                    "error",
                    "INCOMPLETE_PARSE",
                    "The complete parse has a failure; no prefix belongs in an accepted batch",
                )
            )
        extend_diagnostics(diagnostics, findings)
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
        "source_sha256": parsed.source_sha256,
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
        f"Source SHA-256: {report.get('source_sha256') or 'unavailable'}",
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
    return "\n".join(terminal_safe(line) for line in lines) + "\n"


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
        "before_sha256": before.source_sha256,
        "after_sha256": after.source_sha256,
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
    if len(path.parts) > MAX_ARCHIVE_PATH_DEPTH:
        raise ConverterError("Archive path exceeds its depth budget")
    for part in path.parts:
        try:
            utf8_bytes = len(part.encode("utf-8"))
            utf16_units = len(part.encode("utf-16-le")) // 2
        except UnicodeError as exc:
            raise ConverterError("Archive component is not portable Unicode") from exc
        if (
            utf8_bytes > MAX_ARCHIVE_COMPONENT_UTF8_BYTES
            or utf16_units > MAX_ARCHIVE_COMPONENT_UTF16_UNITS
        ):
            raise ConverterError("Archive component exceeds its portable name budget")
        stem = part.split(".", 1)[0].upper()
        if stem in reserved:
            raise ConverterError(f"Archive contains a Windows device path: {name!r}")
        if part.endswith((" ", ".")) or any(ord(char) < 32 or char in '<>:"|?*' for char in part):
            raise ConverterError(f"Archive contains a Windows-unsafe path: {name!r}")
    return path


TAR_PAX_FIELDS = frozenset(
    {
        "path",
        "linkpath",
        "size",
        "uid",
        "gid",
        "uname",
        "gname",
        "mtime",
        "atime",
        "ctime",
        "hdrcharset",
        "comment",
    }
)
TAR_GLOBAL_PAX_FIELDS = TAR_PAX_FIELDS - {"path", "linkpath", "size"}
TAR_PAX_UTF8_CHARSET = b"ISO-IR 10646 2000 UTF-8"


def require_pax_charset_range(buffer: bytes, start: int, end: int) -> None:
    """Admit the exact charset bytes without slicing or decoding their range."""
    if end - start != len(TAR_PAX_UTF8_CHARSET) or not buffer.startswith(
        TAR_PAX_UTF8_CHARSET, start, end
    ):
        raise ConverterError("Only the POSIX UTF-8 TAR PAX charset is supported")


def admitted_pax_value(keyword: str, raw_value: bytes, *, global_header: bool) -> str:
    """Admit a bounded POSIX field before decoding values or applying metadata."""
    if keyword.startswith("GNU.sparse."):
        raise ConverterError("Sparse TAR PAX metadata is not supported")
    allowed = TAR_GLOBAL_PAX_FIELDS if global_header else TAR_PAX_FIELDS
    if keyword not in allowed:
        raise ConverterError("TAR PAX field is not supported by the archive policy")
    if len(raw_value) > MAX_TAR_PAX_VALUE_BYTES:
        raise ConverterError("TAR PAX value exceeds its byte budget")
    if keyword == "hdrcharset":
        require_pax_charset_range(raw_value, 0, len(raw_value))
    try:
        value = raw_value.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ConverterError("TAR PAX metadata must be UTF-8") from exc
    if "\x00" in value:
        raise ConverterError("TAR PAX metadata contains a NUL")
    if keyword in {"size", "uid", "gid"}:
        pattern = r"[0-9]{1,20}" if keyword == "size" else r"-?[0-9]{1,20}"
        if re.fullmatch(pattern, value) is None:
            raise ConverterError("TAR PAX integer exceeds its supported numeric policy")
        if keyword == "size" and int(value) > MAX_EXTRACTED_FILE_BYTES:
            raise ConverterError("TAR PAX entry is too large")
    elif keyword in {"mtime", "atime", "ctime"}:
        if re.fullmatch(r"-?[0-9]{1,20}(?:\.[0-9]{1,20})?", value) is None:
            raise ConverterError("TAR PAX timestamp exceeds its supported numeric policy")
    return value


def charge_pax_application(archive, fields: Mapping[str, str]) -> None:
    """Bound cumulative effective field work, including repeated global metadata."""
    count = len(fields)
    if count > len(TAR_PAX_FIELDS) or any(key not in TAR_PAX_FIELDS for key in fields):
        raise ConverterError("TAR PAX application contains unsupported metadata")
    applications = getattr(archive, "_ids_pax_applications", 0) + count
    if applications > MAX_TAR_PAX_APPLICATIONS:
        raise ConverterError("TAR PAX metadata exceeds its effective application budget")
    archive._ids_pax_applications = applications


def read_pax_following_member(tarinfo, archive):
    """Follow an extension through the stdlib protocol available on this runtime."""
    following = getattr(tarinfo, "_fromtarfile", None)
    if following is not None:
        # Modern stdlib PAX parsing suppresses legacy AREGTYPE trailing-slash
        # inference for an extension's following header.
        return following(archive, dircheck=False)
    # Older stdlib has only this public reader and retains its legacy inference.
    return tarinfo.fromtarfile(archive)


class BoundedTarInfo(tarfile.TarInfo):
    """Bound extension bytes, PAX objects and work before standard member handling."""

    def _proc_member(self, archive):
        self._ids_archive = archive
        return super()._proc_member(archive)

    def _proc_builtin(self, archive):
        count = getattr(archive, "_ids_member_count", 0) + 1
        if count > MAX_ARCHIVE_ENTRIES:
            raise ConverterError("TAR archive exceeds its entry limit")
        archive._ids_member_count = count
        return super()._proc_builtin(archive)

    def _apply_pax_info(self, pax_headers, encoding, errors):
        charge_pax_application(self._ids_archive, pax_headers)
        super()._apply_pax_info(pax_headers, encoding, errors)
        # Extraction uses only the effective name/type/size. Keep extension
        # dictionaries transient even while this one TarInfo is in use.
        self.pax_headers = {}

    def _metadata_budget(self, archive):
        archive._ids_metadata_bytes = getattr(archive, "_ids_metadata_bytes", 0) + self.size
        archive._ids_extension_count = getattr(archive, "_ids_extension_count", 0) + 1
        if (
            self.size < 0
            or self.size > 1024 * 1024
            or archive._ids_metadata_bytes > 8 * 1024 * 1024
            or archive._ids_extension_count > 32
        ):
            raise ConverterError("TAR extension metadata exceeds its budget")

    def _proc_pax(self, archive):
        self._metadata_budget(archive)
        block_size = self._block(self.size)
        buffer = archive.fileobj.read(block_size)
        if len(buffer) != block_size:
            raise ConverterError("TAR PAX metadata is truncated")
        global_header = self.type == tarfile.XGLTYPE
        # The only retained global fields are the small supported set below.
        # No raw_headers list or GNU sparse-map parser is ever constructed.
        if len(archive.pax_headers) > len(TAR_GLOBAL_PAX_FIELDS) or any(
            key not in TAR_GLOBAL_PAX_FIELDS for key in archive.pax_headers
        ):
            raise ConverterError("TAR global PAX metadata exceeds its supported object policy")
        fields = archive.pax_headers.copy()
        position = 0
        field_count = 0
        while position < self.size:
            field_count += 1
            total = getattr(archive, "_ids_pax_fields", 0) + 1
            if field_count > MAX_TAR_PAX_FIELDS or total > MAX_TAR_PAX_TOTAL_FIELDS:
                raise ConverterError("TAR PAX fields exceed their object budget")
            archive._ids_pax_fields = total
            space = buffer.find(b" ", position, min(self.size, position + 9))
            if space < 0 or not buffer[position:space].isdigit():
                raise ConverterError("TAR PAX metadata has invalid record framing")
            length = int(buffer[position:space])
            end = position + length
            if length < 5 or end > self.size or buffer[end - 1] != 0x0A:
                raise ConverterError("TAR PAX metadata has invalid record framing")
            start = space + 1
            equals = buffer.find(b"=", start, min(end - 1, start + MAX_TAR_PAX_KEY_BYTES + 1))
            if equals <= start:
                raise ConverterError("TAR PAX keyword exceeds its supported framing or byte budget")
            try:
                keyword = buffer[start:equals].decode("ascii", "strict")
            except UnicodeDecodeError as exc:
                raise ConverterError("TAR PAX keywords must be ASCII") from exc
            # Decide sparse/unknown/global policy before slicing or decoding the
            # value. All GNU sparse PAX versions therefore refuse at this point.
            if keyword.startswith("GNU.sparse."):
                raise ConverterError("Sparse TAR PAX metadata is not supported")
            allowed = TAR_GLOBAL_PAX_FIELDS if global_header else TAR_PAX_FIELDS
            if keyword not in allowed:
                raise ConverterError("TAR PAX field is not supported by the archive policy")
            if end - equals - 2 > MAX_TAR_PAX_VALUE_BYTES:
                raise ConverterError("TAR PAX value exceeds its byte budget")
            if keyword == "hdrcharset":
                require_pax_charset_range(buffer, equals + 1, end - 1)
            value = admitted_pax_value(
                keyword, buffer[equals + 1 : end - 1], global_header=global_header
            )
            fields[keyword] = value
            position = end
        if global_header:
            archive.pax_headers = fields
        try:
            member = read_pax_following_member(self, archive)
        except tarfile.HeaderError as exc:
            raise tarfile.SubsequentHeaderError(str(exc)) from None
        if not global_header:
            member._apply_pax_info(fields, archive.encoding, archive.errors)
            member.offset = self.offset
            if "size" in fields:
                offset = member.offset_data
                if member.isreg() or member.type not in tarfile.SUPPORTED_TYPES:
                    offset += member._block(member.size)
                archive.offset = offset
        return member

    def _proc_gnulong(self, archive):
        self._metadata_budget(archive)
        return super()._proc_gnulong(archive)

    def _proc_sparse(self, archive):
        raise ConverterError("Sparse TAR members are not supported")


@dataclass(frozen=True, slots=True)
class AdmittedTarMember:
    """The complete TAR admission data needed by the independent decode pass."""

    name: str
    type: bytes
    size: int

    def isfile(self) -> bool:
        return self.type in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.CONTTYPE}

    def isdir(self) -> bool:
        return self.type == tarfile.DIRTYPE


def next_tar_member(archive):
    """Stream one member without tarfile retaining an accumulating TarInfo cache."""
    archive.members.clear()
    archive._ids_extension_count = 0
    try:
        return archive.next()
    finally:
        archive.members.clear()


class DecompressionBudget:
    def __init__(self, stream):
        self.stream = stream
        self.count = 0
        self.limit = MAX_EXTRACTED_BYTES + MAX_ARCHIVE_ENTRIES * 1024 + 8 * 1024 * 1024

    def read(self, size):
        if size < 0 or self.count + size > self.limit:
            raise ConverterError("TAR decompression exceeds its byte budget")
        value = self.stream.read(size)
        self.count += len(value)
        return value


def check_archive_object_budget(names: Iterable[str]) -> None:
    objects: set[tuple[str, ...]] = set()
    for name in names:
        parts = tuple(part.casefold() for part in safe_archive_name(name).parts)
        for depth in range(1, len(parts) + 1):
            objects.add(parts[:depth])
            if len(objects) > MAX_ARCHIVE_ENTRIES:
                raise ConverterError("Archive exceeds its total filesystem object budget")


def archive_path_graph(entries: Iterable[tuple[str, bool]]) -> dict[tuple[str, ...], bool]:
    """Admit one portable spelling and file/directory type for every path node."""
    nodes: dict[tuple[str, ...], tuple[tuple[str, ...], bool]] = {}
    for name, directory in entries:
        parts = safe_archive_name(name).parts
        for depth in range(1, len(parts) + 1):
            spelling = parts[:depth]
            key = tuple(unicodedata.normalize("NFC", part).casefold() for part in spelling)
            kind = directory if depth == len(parts) else True
            previous = nodes.get(key)
            if previous is not None and previous != (spelling, kind):
                raise ConverterError("Archive paths have conflicting types or portable spellings")
            nodes[key] = (spelling, kind)
            if len(nodes) > MAX_ARCHIVE_ENTRIES:
                raise ConverterError("Archive exceeds its total filesystem object budget")
    return dict(nodes.values())


def preflight_archive_input(data: bytes) -> None:
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ConverterError("Archive input exceeds the download byte limit")


def validate_tar_archive(data: bytes) -> list[AdmittedTarMember]:
    preflight_archive_input(data)
    if not data.startswith(b"\x1f\x8b"):
        raise ConverterError("Expected a gzip-compressed TAR archive")
    members = []
    total = 0
    normalized_names: set[str] = set()
    try:
        with (
            gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed,
            tarfile.open(
                fileobj=DecompressionBudget(compressed), mode="r|", tarinfo=BoundedTarInfo
            ) as archive,
        ):
            while True:
                member = next_tar_member(archive)
                if member is None:
                    break
                if len(members) >= MAX_ARCHIVE_ENTRIES:
                    raise ConverterError("TAR archive exceeds its entry limit")
                relative = safe_archive_name(member.name)
                normalized = "/".join(relative.parts).casefold()
                if normalized in normalized_names:
                    raise ConverterError(f"Archive contains duplicate paths: {member.name!r}")
                normalized_names.add(normalized)
                if not (member.isfile() or member.isdir()) or member.sparse is not None:
                    raise ConverterError(
                        f"Archive contains a link or special file: {member.name!r}"
                    )
                if member.isdir() and member.size != 0:
                    raise ConverterError("Archive directory carries an unexpected payload")
                if member.size < 0 or member.size > MAX_EXTRACTED_FILE_BYTES:
                    raise ConverterError(f"Archive entry is too large: {member.name!r}")
                total += member.size
                if total > MAX_EXTRACTED_BYTES:
                    raise ConverterError("TAR archive exceeds its extracted byte limit")
                members.append(AdmittedTarMember(member.name, member.type, member.size))
    except (tarfile.TarError, OSError, EOFError, RecursionError) as exc:
        raise ConverterError(f"Downloaded file is not a valid bounded TAR archive: {exc}") from exc
    check_archive_object_budget(member.name for member in members)
    archive_path_graph((member.name, member.isdir()) for member in members)
    return members


def preflight_zip_directory(data: bytes) -> tuple[int, int]:
    """Bound and count directory records before ZipFile allocates any ZipInfo."""
    preflight_archive_input(data)
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise ConverterError("ZIP has no complete end-of-directory record")
    _, disk, directory_disk, disk_count, count, size, offset, comment = struct.unpack_from(
        "<4s4H2LH", data, end
    )
    if end + 22 + comment != len(data):
        raise ConverterError("ZIP has a truncated comment or trailing data")
    if disk != 0 or directory_disk != 0 or disk_count != count:
        raise ConverterError("Multi-disk ZIP archives are not supported")
    directory_end = end
    zip64_position = None
    zip64_offset = None
    if end >= 20 and data[end - 20 : end - 16] == b"PK\x06\x07":
        _, locator_disk, zip64_offset, disks = struct.unpack_from("<4sLQL", data, end - 20)
        zip64_position = end - 20 - 56
        if locator_disk != 0 or disks != 1 or zip64_position < 0:
            raise ConverterError("Invalid or multi-disk ZIP64 locator")
        values = struct.unpack_from("<4sQ2H2L4Q", data, zip64_position)
        signature, record_size, _, _, z_disk, z_start, z_disk_count, z_count, z_size, z_offset = (
            values
        )
        if signature != b"PK\x06\x06" or record_size != 44:
            raise ConverterError(
                "Only fixed-size single-disk ZIP64 directory records are supported"
            )
        if z_disk != 0 or z_start != 0 or z_disk_count != z_count:
            raise ConverterError("Multi-disk ZIP64 archives are not supported")
        for ordinary, wide, sentinel in (
            (count, z_count, 0xFFFF),
            (size, z_size, 0xFFFFFFFF),
            (offset, z_offset, 0xFFFFFFFF),
        ):
            if ordinary != sentinel and ordinary != wide:
                raise ConverterError("ZIP and ZIP64 directory metadata disagree")
        count, size, offset = z_count, z_size, z_offset
        directory_end = zip64_position
    elif count == 0xFFFF or size == 0xFFFFFFFF or offset == 0xFFFFFFFF:
        raise ConverterError("ZIP64 directory metadata is missing")
    if count > MAX_ARCHIVE_ENTRIES:
        raise ConverterError(f"Archive has {count:,} entries; limit is {MAX_ARCHIVE_ENTRIES:,}")
    if size > MAX_ZIP_DIRECTORY_BYTES:
        raise ConverterError("ZIP central directory exceeds its metadata byte limit")
    start = directory_end - size
    prefix_size = start - offset
    if start < 0 or prefix_size < 0:
        raise ConverterError("ZIP central-directory offsets are invalid")
    if zip64_position is not None and zip64_offset != zip64_position - prefix_size:
        raise ConverterError("ZIP64 locator does not identify its directory record")
    position = start
    actual = 0
    while position < directory_end:
        if actual >= MAX_ARCHIVE_ENTRIES:
            raise ConverterError("ZIP actual entry count exceeds its entry limit")
        if position + 46 > directory_end or data[position : position + 4] != b"PK\x01\x02":
            raise ConverterError("ZIP central directory has an invalid or truncated record")
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", data, position + 28)
        if struct.unpack_from("<H", data, position + 34)[0] != 0:
            raise ConverterError("Multi-disk or extended-disk ZIP members are not supported")
        position += 46 + name_size + extra_size + comment_size
        if position > directory_end:
            raise ConverterError("ZIP central-directory record exceeds its declared bounds")
        actual += 1
    if actual != count:
        raise ConverterError("ZIP actual entry count differs from its directory metadata")
    return actual, start


def validate_zip_archive(data: bytes) -> list[zipfile.ZipInfo]:
    count, directory_start = preflight_zip_directory(data)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) != count or archive.start_dir != directory_start:
                raise ConverterError("ZIP parser disagrees with the bounded directory preflight")
            for member in members:
                if member.volume != 0:
                    raise ConverterError("Multi-disk ZIP members are not supported")
                offset = member.header_offset
                if (
                    offset < 0
                    or offset + 30 > directory_start
                    or data[offset : offset + 4] != b"PK\x03\x04"
                ):
                    raise ConverterError("ZIP entry does not identify a bounded local-file header")
                flags, compression = struct.unpack_from("<HH", data, offset + 6)
                name_size, extra_size = struct.unpack_from("<HH", data, offset + 26)
                entity_start = offset + 30 + name_size + extra_size
                if (
                    entity_start > directory_start
                    or member.compress_size < 0
                    or entity_start + member.compress_size > directory_start
                    or flags != member.flag_bits
                    or compression != member.compress_type
                ):
                    raise ConverterError("ZIP local-file metadata disagrees or exceeds its bounds")
                if member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise ConverterError("ZIP entry uses an unsupported parameterized decoder")
                if member.flag_bits & 0x1:
                    raise ConverterError(
                        f"Archive contains an encrypted entry: {member.filename!r}"
                    )
                # Validate the standard reader's name/overlap checks and close
                # immediately. No compressed entity is read or extracted here.
                with archive.open(member):
                    pass
    except (zipfile.BadZipFile, OSError, NotImplementedError, RuntimeError) as exc:
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
        if member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise ConverterError("ZIP entry uses an unsupported parameterized decoder")
        if member.flag_bits & 0x1:
            raise ConverterError(f"Archive contains an encrypted entry: {member.filename!r}")
        unix_mode = (member.external_attr >> 16) & 0xFFFF
        if (unix_mode & 0o170000) == 0o120000:
            raise ConverterError(f"Archive contains a symbolic link: {member.filename!r}")
        expected_kind = stat.S_IFDIR if member.is_dir() else stat.S_IFREG
        if stat.S_IFMT(unix_mode) not in {0, expected_kind} or (
            not member.is_dir() and member.external_attr & 0x10
        ):
            raise ConverterError("ZIP member type disagrees with its path")
        if member.is_dir() and member.file_size != 0:
            raise ConverterError("Archive directory carries an unexpected payload")
        if member.file_size < 0 or member.file_size > MAX_EXTRACTED_FILE_BYTES:
            raise ConverterError(f"Archive entry is too large: {member.filename!r}")
        total += member.file_size
        if total > MAX_EXTRACTED_BYTES:
            raise ConverterError(f"Archive expands beyond the {MAX_EXTRACTED_BYTES:,} byte limit")
    check_archive_object_budget(member.filename.rstrip("/") for member in members)
    archive_path_graph((member.filename.rstrip("/"), member.is_dir()) for member in members)
    return members


def _validate_zip_directory_entity(data: bytes, member: zipfile.ZipInfo) -> None:
    """Validate an empty directory's complete bounded stored/deflate entity."""
    if not member.is_dir() or member.file_size != 0 or member.CRC != 0:
        raise ConverterError("ZIP directory entity does not describe empty content")
    offset = member.header_offset
    if offset < 0 or offset + 30 > len(data):
        raise ConverterError("ZIP directory entity has invalid local bounds")
    name_size, extra_size = struct.unpack_from("<HH", data, offset + 26)
    start = offset + 30 + name_size + extra_size
    end = start + member.compress_size
    if member.compress_size < 0 or end > len(data):
        raise ConverterError("ZIP directory entity exceeds its admitted bounds")
    if member.compress_type == zipfile.ZIP_STORED:
        if member.compress_size != 0:
            raise ConverterError("Stored ZIP directory carries an unexpected entity")
        return
    if member.compress_type != zipfile.ZIP_DEFLATED:
        raise ConverterError("ZIP directory uses an unsupported decoder")
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    decoded = decoder.decompress(memoryview(data)[start:end], 1)
    if decoded or not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
        raise ConverterError("ZIP directory entity did not decode as complete empty content")


def _validate_zip_file_entity(data: bytes, member: zipfile.ZipInfo) -> None:
    """Count and checksum a complete entity independently of ZipExtFile's size clipping."""
    if member.is_dir() or not 0 <= member.file_size <= MAX_EXTRACTED_FILE_BYTES:
        raise ConverterError("ZIP file entity has an invalid admitted size")
    offset = member.header_offset
    if offset < 0 or offset + 30 > len(data):
        raise ConverterError("ZIP file entity has invalid local bounds")
    name_size, extra_size = struct.unpack_from("<HH", data, offset + 26)
    start = offset + 30 + name_size + extra_size
    end = start + member.compress_size
    if member.compress_size < 0 or end > len(data):
        raise ConverterError("ZIP file entity exceeds its admitted bounds")
    count, checksum = 0, 0
    if member.compress_type == zipfile.ZIP_STORED:
        if member.compress_size != member.file_size:
            raise ConverterError("Stored ZIP entity length differs from its admitted size")
        for position in range(start, end, 64 * 1024):
            block = memoryview(data)[position : min(position + 64 * 1024, end)]
            count += len(block)
            checksum = zlib.crc32(block, checksum)
    elif member.compress_type == zipfile.ZIP_DEFLATED:
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        position, pending = start, b""
        while True:
            if not pending and position < end:
                next_position = min(position + 64 * 1024, end)
                pending = memoryview(data)[position:next_position]
                position = next_position
            input_size = len(pending)
            block = decoder.decompress(pending, min(64 * 1024, member.file_size - count + 1))
            pending = decoder.unconsumed_tail
            count += len(block)
            if count > member.file_size:
                raise ConverterError("ZIP entity decodes beyond its admitted size")
            checksum = zlib.crc32(block, checksum)
            if decoder.eof:
                if pending or decoder.unused_data or position != end:
                    raise ConverterError("ZIP entity has input beyond its complete stream")
                break
            if not block and ((not pending and position == end) or len(pending) == input_size):
                raise ConverterError("ZIP entity decoder did not complete or make progress")
    else:
        raise ConverterError("ZIP file uses an unsupported decoder")
    if count != member.file_size or checksum != member.CRC:
        raise ConverterError("ZIP entity decoded size or checksum differs from its admission")


def _require_windows_archive_child(path) -> None:
    if not path.drive or path.drive.startswith("\\") or ".." in path.parts:
        raise ConverterError("Archive generations require a local drive-letter namespace")
    if not path.name:
        raise ConverterError(
            "Windows archive generations require a private child below the drive anchor"
        )


class _WindowsArchiveApi:
    """Native one-component creation, disposal and no-replace directory publication."""

    def __init__(self):
        import ctypes.wintypes

        self.ctypes, self.wintypes = ctypes, ctypes.wintypes
        self.sid = current_windows_sid()
        w = self.wintypes

        class UnicodeString(ctypes.Structure):
            _fields_ = [("length", w.USHORT), ("maximum", w.USHORT), ("buffer", w.LPWSTR)]

        class ObjectAttributes(ctypes.Structure):
            _fields_ = [
                ("length", w.ULONG),
                ("root", w.HANDLE),
                ("name", ctypes.POINTER(UnicodeString)),
                ("attributes", w.ULONG),
                ("security", ctypes.c_void_p),
                ("quality", ctypes.c_void_p),
            ]

        class IoStatusBlock(ctypes.Structure):
            _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]

        class FileInformation(ctypes.Structure):
            _fields_ = [
                ("attributes", w.DWORD),
                ("created", w.FILETIME),
                ("accessed", w.FILETIME),
                ("written", w.FILETIME),
                ("volume", w.DWORD),
                ("size_high", w.DWORD),
                ("size_low", w.DWORD),
                ("links", w.DWORD),
                ("index_high", w.DWORD),
                ("index_low", w.DWORD),
            ]

        self.UnicodeString, self.ObjectAttributes = UnicodeString, ObjectAttributes
        self.IoStatusBlock, self.FileInformation = IoStatusBlock, FileInformation
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.native = ctypes.WinDLL("ntdll")
        self.security = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel.CloseHandle.argtypes, self.kernel.CloseHandle.restype = [w.HANDLE], w.BOOL
        self.kernel.LocalFree.argtypes, self.kernel.LocalFree.restype = (
            [ctypes.c_void_p],
            ctypes.c_void_p,
        )
        self.kernel.GetFileInformationByHandle.argtypes = [
            w.HANDLE,
            ctypes.POINTER(FileInformation),
        ]
        self.kernel.GetFileInformationByHandle.restype = w.BOOL
        self.native.NtCreateFile.argtypes = [
            ctypes.POINTER(w.HANDLE),
            w.DWORD,
            ctypes.POINTER(ObjectAttributes),
            ctypes.POINTER(IoStatusBlock),
            ctypes.c_void_p,
            w.ULONG,
            w.ULONG,
            w.ULONG,
            w.ULONG,
            ctypes.c_void_p,
            w.ULONG,
        ]
        self.native.NtCreateFile.restype = ctypes.c_int32
        self.native.NtSetInformationFile.argtypes = [
            w.HANDLE,
            ctypes.POINTER(IoStatusBlock),
            ctypes.c_void_p,
            w.ULONG,
            ctypes.c_int,
        ]
        self.native.NtSetInformationFile.restype = ctypes.c_int32
        self.native.RtlNtStatusToDosError.argtypes = [ctypes.c_int32]
        self.native.RtlNtStatusToDosError.restype = w.ULONG
        self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            w.LPCWSTR,
            w.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        ]
        self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL

    def check(self, status):
        if status < 0:
            raise self.ctypes.WinError(self.native.RtlNtStatusToDosError(status))

    def identity(self, handle):
        info = self.FileInformation()
        if not self.kernel.GetFileInformationByHandle(handle, self.ctypes.byref(info)):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        return info.volume, info.index_high, info.index_low

    @contextmanager
    def object(
        self, parent, name, *, directory, create=False, delete=False, private=False, on_created=None
    ):
        c, w = self.ctypes, self.wintypes
        if safe_archive_name(name).parts != (name,):
            raise ConverterError("Native archive operations require one path component")
        encoded = name.encode("utf-16-le")
        if len(encoded) > 65532:
            raise ConverterError("Archive component exceeds its native name budget")
        buffer = c.create_unicode_buffer(name)
        string = self.UnicodeString(len(encoded), len(encoded) + 2, c.cast(buffer, w.LPWSTR))
        descriptor = c.c_void_p()
        if create and not self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"O:{self.sid}D:P(A;OICI;FA;;;{self.sid})",
            1,
            c.byref(descriptor),
            None,
        ):
            raise c.WinError(c.get_last_error())
        try:
            attributes = self.ObjectAttributes(
                c.sizeof(self.ObjectAttributes), parent, c.pointer(string), 0x1040, descriptor, None
            )
            status, handle = self.IoStatusBlock(), w.HANDLE()
            access = 0x120080 | (1 if directory else 0) | (0x10000 if delete else 0)
            self.check(
                self.native.NtCreateFile(
                    c.byref(handle),
                    access,
                    c.byref(attributes),
                    c.byref(status),
                    None,
                    0x10 if directory else 0x80,
                    3,
                    2 if create else 1,
                    0x200020 | (1 if directory else 0x40),
                    None,
                    0,
                )
            )
        finally:
            if descriptor:
                self.kernel.LocalFree(descriptor)
        try:
            if create and on_created is not None:
                on_created(handle)
            validate_windows_input_component(handle, directory=directory)
            if private and directory:
                verify_windows_parent_security(handle, self.sid, True)
            yield handle
        finally:
            self.kernel.CloseHandle(handle)

    def dispose(self, handle):
        c = self.ctypes
        disposition, status = c.c_ubyte(1), self.IoStatusBlock()
        self.check(
            self.native.NtSetInformationFile(
                handle, c.byref(status), c.byref(disposition), c.sizeof(disposition), 13
            )
        )

    def publish(self, handle, parent, name):
        c, w = self.ctypes, self.wintypes
        if safe_archive_name(name).parts != (name,):
            raise ConverterError("Generation publication requires one path component")

        class RenameInformation(c.Structure):
            _fields_ = (
                ("replace", c.c_ubyte),
                ("root", w.HANDLE),
                ("length", w.ULONG),
                ("name", w.WCHAR * 1),
            )

        encoded = name.encode("utf-16-le")
        buffer = c.create_string_buffer(c.sizeof(RenameInformation) + len(encoded))
        info = RenameInformation.from_buffer(buffer)
        info.replace, info.root, info.length = 0, parent, len(encoded)
        c.memmove(c.addressof(buffer) + RenameInformation.name.offset, encoded, len(encoded))
        status = self.IoStatusBlock()
        self.check(
            self.native.NtSetInformationFile(handle, c.byref(status), buffer, len(buffer), 10)
        )


@contextmanager
def _archive_root_namespace(path: Path, api):
    if api is None:
        with input_parent_namespace(path / ".ids-generation-anchor") as (_, parent):
            info = os.fstat(parent)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise ConverterError("Archive root must be private and owned by this user")
            yield parent
        return
    _require_windows_archive_child(path)
    sid = current_windows_sid()
    with ExitStack() as stack:
        parent = open_windows_input_component(None, path.anchor, directory=True)
        stack.callback(api.kernel.CloseHandle, parent)
        validate_windows_input_component(parent, directory=True)
        verify_windows_parent_security(parent, sid, path == Path(path.anchor))
        for index, part in enumerate(path.parts[1:], 1):
            parent = stack.enter_context(api.object(parent, part, directory=True))
            verify_windows_parent_security(parent, sid, index == len(path.parts) - 1)
        yield parent


@contextmanager
def _generation_parent(parent, parts, api):
    with ExitStack() as stack:
        for part in parts:
            if api is None:
                owner = stack.enter_context(
                    _input_directory_descriptor(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, parent=parent
                    )
                )
                parent = owner.fileno()
            else:
                parent = stack.enter_context(api.object(parent, part, directory=True, private=True))
        yield parent


def _publish_posix_generation(parent: int, staging: str, final: str) -> None:
    import ctypes

    library = ctypes.CDLL(None, use_errno=True)
    name, flag = ("renameatx_np", 4) if sys.platform == "darwin" else ("renameat2", 1)
    function = getattr(library, name, None)
    if function is None:
        raise ConverterError("Atomic no-replace directory generations are unsupported")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if function(parent, os.fsencode(staging), parent, os.fsencode(final), flag) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _retain_archive_cleanup_failure(primary, cleanup):
    """Keep the initiating exception and expose bounded cleanup diagnostics."""
    previous = getattr(primary, "archive_cleanup_failures", ())
    failures = getattr(cleanup, "failures", (str(cleanup)[:512],))
    primary.archive_cleanup_failure_count = getattr(primary, "archive_cleanup_failure_count", 0) + (
        getattr(cleanup, "failure_count", len(failures))
    )
    primary.archive_cleanup_failures = (previous + tuple(failures))[:100]
    summary = f"Archive cleanup reported {primary.archive_cleanup_failure_count} failure(s)"
    primary.archive_cleanup_summary = summary
    if hasattr(primary, "add_note"):
        primary.add_note(summary + ": " + "; ".join(primary.archive_cleanup_failures))


@contextmanager
def _remember_archive_primary_error(errors):
    """Capture the body failure before retained stage handles are released."""
    try:
        yield
    except BaseException as exc:
        errors.append(exc)
        raise


class _ArchiveCleanupError(ConverterError):
    def __init__(self, failures, failure_count):
        self.failures, self.failure_count = tuple(failures), failure_count
        super().__init__(
            f"Archive cleanup reported {failure_count} failure(s): " + "; ".join(failures)
        )


class _ArchiveCreationJournal:
    """Record only exclusive creations and published leaves in this owned stage."""

    def __init__(self, path, staging, api):
        self.path, self.staging, self.api = path, staging, api
        self.entries = []

    def record_created(
        self,
        path,
        directory,
        *,
        file=None,
        descriptor=None,
        identity=None,
        created_handle=None,
        writer_destination=None,
    ):
        parts = path.relative_to(self.path).parts
        if not parts:
            raise ConverterError("Created archive object is outside its private stage")
        # The successful creation is recorded even if obtaining its identity
        # or validating its internal spelling fails. Unknown identity requires
        # owner review and never authorizes guessed deletion.
        index = len(self.entries)
        self.entries.append((parts, directory, None))
        if writer_destination is None:
            if safe_archive_name("/".join(parts)).parts != parts:
                raise ConverterError("Created archive object is outside its private stage")
        else:
            destination_parts = writer_destination.relative_to(self.path).parts
            if (
                self.api is None
                or safe_archive_name("/".join(destination_parts)).parts != destination_parts
            ):
                raise ConverterError("Internal archive writer requires an admitted destination")
            # One private writer directory replaces the admitted final leaf;
            # its fixed report leaf adds exactly one internal component. This
            # does not increase the public archive path-depth admission.
            prefix = destination_parts[:-1]
            if (
                len(parts) != len(prefix) + (1 if directory else 2)
                or parts[: len(prefix)] != prefix
                or not re.fullmatch(r"\.govhawk-private-[0-9a-f]{32}", parts[len(prefix)])
                or (not directory and parts[-1] != "report")
                or any(safe_archive_name(part).parts != (part,) for part in parts)
            ):
                raise ConverterError("Internal archive writer spelling is not admitted")
        if identity is None:
            if created_handle is not None:
                identity = self.api.identity(created_handle)
            elif file is not None or descriptor is not None:
                descriptor = file.fileno() if file is not None else descriptor
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or directory:
                    raise ConverterError("Created archive writer is not a regular file")
                if self.api is None:
                    identity = info.st_dev, info.st_ino
                else:
                    import msvcrt

                    identity = self.api.identity(msvcrt.get_osfhandle(descriptor))
            else:
                with _generation_parent(self.staging, parts[:-1], self.api) as container:
                    if self.api is None:
                        info = os.stat(parts[-1], dir_fd=container, follow_symlinks=False)
                        if not (
                            stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
                        ):
                            raise ConverterError("Created archive object has an unexpected type")
                        identity = info.st_dev, info.st_ino
                    else:
                        with self.api.object(
                            container, parts[-1], directory=directory, private=True
                        ) as handle:
                            identity = self.api.identity(handle)
        self.entries[index] = (parts, directory, identity)
        return identity


def _admit_archive_destination(graph, parent, api):
    """Check the pinned destination filesystem before creating the stage."""
    if api is not None:
        return  # The shared UTF-8/UTF-16 contract precedes native Windows calls.
    try:
        limit = os.fpathconf(parent, "PC_NAME_MAX")
    except (AttributeError, OSError, ValueError) as exc:
        raise ConverterError("Cannot establish the pinned archive filesystem name limit") from exc
    if not isinstance(limit, int) or limit <= 0:
        raise ConverterError("Pinned archive filesystem has no supported finite name limit")
    for parts in graph:
        for part in parts:
            try:
                size = len(os.fsencode(part))
            except UnicodeError as exc:
                raise ConverterError(
                    "Archive component is not representable on this filesystem"
                ) from exc
            if size > limit:
                raise ConverterError("Archive component exceeds the pinned filesystem name limit")


def _cleanup_archive_generation(parent, name, identity, journal, api):
    """Remove only this created private generation, through its retained namespace."""
    with ExitStack() as stack:
        if api is None:
            owner = stack.enter_context(
                _input_directory_descriptor(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, parent=parent
                )
            )
            staging = owner.fileno()
            info = os.fstat(staging)
            actual = info.st_dev, info.st_ino
        else:
            staging = stack.enter_context(api.object(parent, name, directory=True, private=True))
            actual = api.identity(staging)
        if actual != identity:
            raise ConverterError("Staging identity changed; cleanup requires owner review")
        failures = []
        failure_count = 0

        def failed(exc):
            nonlocal failure_count
            failure_count += 1
            if len(failures) < 100:
                failures.append(f"{type(exc).__name__}: {str(exc)[:512]}")

        for parts, directory, expected in reversed(journal.entries):
            try:
                if expected is None:
                    raise ConverterError(
                        "Created staging object identity is unavailable; cleanup refused"
                    )
                with _generation_parent(staging, parts[:-1], api) as container:
                    if api is None:
                        info = os.stat(parts[-1], dir_fd=container, follow_symlinks=False)
                        if not (
                            stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
                        ):
                            raise ConverterError("Staging object type changed; cleanup refused")
                        if (info.st_dev, info.st_ino) != expected:
                            raise ConverterError("Staging object identity changed; cleanup refused")
                        if directory:
                            os.rmdir(parts[-1], dir_fd=container)
                        else:
                            os.unlink(parts[-1], dir_fd=container)
                    else:
                        with api.object(
                            container, parts[-1], directory=directory, delete=True, private=True
                        ) as entry:
                            if api.identity(entry) != expected:
                                raise ConverterError(
                                    "Staging object identity changed; cleanup refused"
                                )
                            api.dispose(entry)
            except FileNotFoundError:
                continue
            except (OSError, ConverterError) as exc:
                failed(exc)
    try:
        if api is None:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
                raise ConverterError("Staging identity changed; cleanup refused")
            os.rmdir(name, dir_fd=parent)
        else:
            with api.object(parent, name, directory=True, delete=True, private=True) as entry:
                if api.identity(entry) != identity:
                    raise ConverterError("Staging identity changed; cleanup refused")
                api.dispose(entry)
    except (OSError, ConverterError) as exc:
        failed(exc)
    if failure_count:
        raise _ArchiveCleanupError(failures, failure_count)


@contextmanager
def _archive_generation(output_dir: Path, graph):
    api = _WindowsArchiveApi() if os.name == "nt" else None
    token = uuid.uuid4().hex
    staging_name, final_name = ".ids-stage-" + token, "generation-" + token
    staging_path, final_path = output_dir / staging_name, output_dir / final_name
    with _archive_root_namespace(output_dir, api) as parent:
        identity = None
        journal = None
        stage_created = False
        initiating = []
        try:
            _admit_archive_destination(graph, parent, api)
            with ExitStack() as stack, _remember_archive_primary_error(initiating):
                if api is None:
                    os.mkdir(staging_name, 0o700, dir_fd=parent)
                    stage_created = True
                    info = os.stat(staging_name, dir_fd=parent, follow_symlinks=False)
                    identity = info.st_dev, info.st_ino
                    owner = stack.enter_context(
                        _input_directory_descriptor(
                            staging_name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            parent=parent,
                        )
                    )
                    staging = owner.fileno()
                    info = os.fstat(staging)
                    if (info.st_dev, info.st_ino) != identity:
                        raise ConverterError("Staging identity changed during creation")
                else:

                    def adopt_stage(handle):
                        nonlocal identity, stage_created
                        stage_created = True
                        identity = api.identity(handle)

                    staging = stack.enter_context(
                        api.object(
                            parent,
                            staging_name,
                            directory=True,
                            create=True,
                            private=True,
                            on_created=adopt_stage,
                        )
                    )
                journal = _ArchiveCreationJournal(staging_path, staging, api)
                for parts, directory in sorted(graph.items(), key=lambda item: len(item[0])):
                    if not directory:
                        continue
                    with _generation_parent(staging, parts[:-1], api) as container:
                        if api is None:
                            os.mkdir(parts[-1], 0o700, dir_fd=container)
                            journal.record_created(staging_path.joinpath(*parts), True)
                        else:

                            def adopt_directory(handle, parts=parts):
                                # Record before native post-creation validation.
                                journal.record_created(
                                    staging_path.joinpath(*parts),
                                    True,
                                    created_handle=handle,
                                )

                            with api.object(
                                container,
                                parts[-1],
                                directory=True,
                                create=True,
                                private=True,
                                on_created=adopt_directory,
                            ):
                                pass
                yield staging_path, final_path, journal
            if api is None:
                info = os.stat(staging_name, dir_fd=parent, follow_symlinks=False)
                if (info.st_dev, info.st_ino) != identity:
                    raise ConverterError("Staging identity changed; publication refused")
                _publish_posix_generation(parent, staging_name, final_name)
            else:
                with api.object(
                    parent, staging_name, directory=True, delete=True, private=True
                ) as entry:
                    if api.identity(entry) != identity:
                        raise ConverterError("Staging identity changed; publication refused")
                    api.publish(entry, parent, final_name)
        except BaseException as caught:
            primary = initiating[0] if initiating else caught
            if caught is not primary:
                _retain_archive_cleanup_failure(primary, caught)
            if identity is not None:
                try:
                    _cleanup_archive_generation(
                        parent,
                        staging_name,
                        identity,
                        journal or _ArchiveCreationJournal(staging_path, None, api),
                        api,
                    )
                except (OSError, ConverterError) as cleanup:
                    _retain_archive_cleanup_failure(primary, cleanup)
            elif stage_created:
                _retain_archive_cleanup_failure(
                    primary,
                    ConverterError("Created stage identity is unavailable; owner review required"),
                )
            if caught is primary:
                raise
            raise primary from caught


def extract_archive(data: bytes, archive_type: str, output_dir: Path, force: bool) -> list[Path]:
    """Return one complete immutable generation; never replace earlier/user files."""
    preflight_archive_input(data)
    if archive_type == "tar.gz":
        members = validate_tar_archive(data)
        entries = [(member.name, member.isdir()) for member in members]
    elif archive_type == "zip":
        members = validate_zip_archive(data)
        entries = [(member.filename.rstrip("/"), member.is_dir()) for member in members]
    else:
        raise ConverterError(f"Unsupported archive type: {archive_type}")
    graph = archive_path_graph(entries)
    if os.name == "nt":
        _require_windows_archive_child(output_dir.absolute())
    output_dir = ensure_output_directory(output_dir)
    written = []
    # force is retained for source compatibility; every call gets a fresh,
    # no-replace generation, so it never grants deletion of existing content.
    try:
        with _archive_generation(output_dir, graph) as (staging, final, journal):
            if archive_type == "tar.gz":
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
                    bounded = DecompressionBudget(compressed)
                    with tarfile.open(
                        fileobj=bounded, mode="r|", tarinfo=BoundedTarInfo
                    ) as archive:
                        member_index = 0
                        while True:
                            member = next_tar_member(archive)
                            if member is None:
                                break
                            if member_index >= len(members):
                                raise ConverterError(
                                    "Archive changed between admission and decoding"
                                )
                            admitted = members[member_index]
                            if (member.name, member.type, member.size) != (
                                admitted.name,
                                admitted.type,
                                admitted.size,
                            ):
                                raise ConverterError(
                                    "Archive changed between admission and decoding"
                                )
                            member_index += 1
                            if member.isdir():
                                continue
                            relative = safe_archive_name(member.name)
                            extracted = archive.extractfile(member)
                            if extracted is None:
                                raise ConverterError("Cannot read an admitted archive entry")
                            with extracted:
                                atomic_write_bytes(
                                    staging.joinpath(*relative.parts),
                                    extracted,
                                    expected_size=member.size,
                                    _archive_journal=journal,
                                )
                            written.append(final.joinpath(*relative.parts))
                        # Consume the bounded gzip tail as well, including its checksum.
                        if member_index != len(members):
                            raise ConverterError(
                                "Archive decoding did not complete its admitted members"
                            )
                        while True:
                            remaining = bounded.limit - bounded.count
                            if remaining <= 0:
                                raise ConverterError("TAR decompression exceeds its byte budget")
                            if not bounded.read(min(64 * 1024, remaining)):
                                break
            else:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    for member in members:
                        if member.is_dir():
                            _validate_zip_directory_entity(data, member)
                            continue
                        _validate_zip_file_entity(data, member)
                        relative = safe_archive_name(member.filename)
                        with archive.open(member) as content:
                            atomic_write_bytes(
                                staging.joinpath(*relative.parts),
                                content,
                                expected_size=member.file_size,
                                _archive_journal=journal,
                            )
                        written.append(final.joinpath(*relative.parts))
    except (
        zipfile.BadZipFile,
        tarfile.TarError,
        EOFError,
        OSError,
        RuntimeError,
        zlib.error,
    ) as exc:
        cleanup = getattr(exc, "archive_cleanup_summary", "")
        detail = f"; {cleanup}" if cleanup else ""
        error = ConverterError(f"Archive decoding or generation publication failed: {exc}{detail}")
        if cleanup:
            error.archive_cleanup_failures = exc.archive_cleanup_failures
            error.archive_cleanup_failure_count = exc.archive_cleanup_failure_count
        raise error from exc
    return written


def is_allowed_https_url(url: str, allowed_hosts: set[str]) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.lower() == "https"
        and (parsed.hostname or "").lower() in {item.lower() for item in allowed_hosts}
        and parsed.username is None
        and parsed.password is None
        and port in {None, 443}
    )


class RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str], deadline: float | None = None) -> None:
        super().__init__()
        self.allowed_hosts = {item.lower() for item in allowed_hosts}
        self.deadline = time.monotonic() + 30 if deadline is None else deadline

    def redirect_request(
        self,
        request: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Any:
        if not is_allowed_https_url(newurl, self.allowed_hosts):
            raise ConverterError(f"Refused redirect outside the HTTPS source allowlist: {newurl}")
        # Python 3.10 has no 308 adapter. For feed GET/HEAD requests, its 307
        # adapter has the same method-preserving behavior. Never replay a body.
        if code == 308 and request.get_method() not in {"GET", "HEAD"}:
            raise urllib.error.HTTPError(request.full_url, code, msg, headers, fp)
        delegated_code = 307 if code == 308 else code
        redirected = super().redirect_request(request, fp, delegated_code, msg, headers, newurl)
        if code == 308 and redirected is not None:
            redirected.method = request.get_method()
        return redirected

    def http_error_302(
        self, request: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any
    ) -> Any:
        try:
            location = headers.get("Location") or headers.get("URI")
            if not isinstance(location, str) or not location:
                raise ConverterError("Feed redirect has no destination")
            # Header bytes are decoded as Latin-1 by the HTTP client. Preserve
            # URI punctuation while encoding spaces and non-ASCII bytes.
            location = urllib.parse.quote(
                location, safe=":/?#[]@!$&'()*+,;=%", encoding="iso-8859-1"
            )
            newurl = urllib.parse.urljoin(request.full_url, location)
            redirected = self.redirect_request(request, fp, code, msg, headers, newurl)
            if redirected is None:
                raise ConverterError("Feed redirect cannot preserve the request method")
            visited = dict(getattr(request, "redirect_dict", {}))
            hops = getattr(request, "_feed_redirect_hops", 0)
            if visited.get(newurl, 0) >= self.max_repeats or hops >= self.max_redirections:
                raise ConverterError("Feed redirect loop or hop budget exceeded")
            visited[newurl] = visited.get(newurl, 0) + 1
            redirected.redirect_dict = visited
            redirected._feed_redirect_hops = hops + 1
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise ConverterError("Feed download deadline exceeded")
        finally:
            # Never drain redirect entities. Inherited HTTPRedirectHandler calls
            # fp.read() with no size argument before following the redirect.
            fp.close()
        return self.parent.open(redirected, timeout=min(request.timeout, remaining))

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


def feed_url_provenance(url: str) -> tuple[str, str]:
    """Redact parameters/query while hashing the complete effective target, without fragment."""
    parsed = urllib.parse.urlparse(url)
    # URL reconstruction drops empty '?' and ';' delimiters that urllib sends
    # as distinct request selectors. Hash the supplied target bytes instead.
    effective = url.partition("#")[0]
    display = parsed._replace(
        params="[redacted]" if parsed.params else "",
        query="[redacted]" if parsed.query else "",
        fragment="",
    ).geturl()
    return display, hashlib.sha256(effective.encode("utf-8")).hexdigest()


def _download_feed_in_worker(source_name: str) -> tuple[bytes, dict[str, Any]]:
    """Bounded HTTPS client; its entire lifetime is cancellable by the parent."""
    source = FEEDS[source_name]
    url = str(source["url"])
    allowed_hosts = set(source["hosts"])
    if not is_allowed_https_url(url, allowed_hosts):
        raise ConverterError("Built-in feed URL failed its HTTPS allowlist check")
    context = ssl.create_default_context()
    deadline = time.monotonic() + 30
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        RestrictedRedirectHandler(allowed_hosts, deadline=deadline),
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
            if not is_allowed_https_url(final_url, allowed_hosts):
                raise ConverterError("Download ended outside the HTTPS source allowlist")
            length_header = response.headers.get("Content-Length")
            if length_header:
                try:
                    declared = bounded_decimal(length_header)
                except ValueError as exc:
                    raise ConverterError(
                        "Server declared an invalid or unsupported Content-Length"
                    ) from exc
                if declared > MAX_DOWNLOAD_BYTES:
                    raise ConverterError(
                        f"Server declared {declared:,} bytes; limit is {MAX_DOWNLOAD_BYTES:,}"
                    )
            chunks: list[bytes] = []
            received = 0
            while True:
                if time.monotonic() >= deadline:
                    raise ConverterError("Feed download deadline exceeded")
                chunk = response.read(min(1024 * 1024, MAX_DOWNLOAD_BYTES - received + 1))
                if time.monotonic() >= deadline:
                    raise ConverterError("Feed download deadline exceeded")
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
    source_display, source_digest = feed_url_provenance(url)
    resolved_display, resolved_digest = feed_url_provenance(final_url)
    metadata = {
        "source": source_name,
        "description": source["description"],
        "source_url": source_display,
        "source_url_sha256": source_digest,
        "resolved_url": resolved_display,
        "resolved_url_sha256": resolved_digest,
        "downloaded_at": utc_now(),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    return data, metadata


def _feed_worker_main(source_name: str, output: BinaryIO, error: BinaryIO) -> int:
    """Emit one bounded frame; this worker never creates output artifacts."""
    try:
        if source_name not in FEEDS:
            raise ConverterError("Unknown built-in feed")
        data, metadata = _download_feed_in_worker(source_name)
        encoded = json.dumps(metadata, ensure_ascii=True).encode("utf-8")
        if len(encoded) > MAX_FEED_METADATA_BYTES or len(data) > MAX_DOWNLOAD_BYTES:
            raise ConverterError("Feed worker result exceeds its frame budget")
        output.write(struct.pack(">I", len(encoded)))
        output.write(encoded)
        output.write(data)
        output.flush()
        return EXIT_OK
    except ConverterError as exc:
        error.write(json.dumps({"error": str(exc)[:1024]}, ensure_ascii=True).encode("utf-8"))
        error.flush()
        return EXIT_OPERATIONAL_ERROR


def _feed_process_worker(source_name: str, connection) -> None:
    """Constant spawn target; network-derived IPC contains bounded bytes only."""
    try:
        output, error = io.BytesIO(), io.BytesIO()
        status = _feed_worker_main(source_name, output, error)
        payload = b"\x00" + output.getvalue() if status == EXIT_OK else b"\x01" + error.getvalue()
        if len(payload) > MAX_DOWNLOAD_BYTES + MAX_FEED_METADATA_BYTES + 5:
            raise ConverterError("Feed worker result exceeds its IPC budget")
        connection.send_bytes(payload)
    finally:
        connection.close()


def _receive_feed_frame(connection, result, completed) -> None:
    """Supervise receipt in a thread, including a partially delivered pipe frame."""
    try:
        result["payload"] = connection.recv_bytes(MAX_DOWNLOAD_BYTES + MAX_FEED_METADATA_BYTES + 5)
    except (OSError, EOFError) as exc:
        result["error"] = exc
    finally:
        completed.set()


def _validate_feed_frame(payload: bytes, source_name: str) -> tuple[bytes, dict[str, Any]]:
    source = FEEDS[source_name]
    if len(payload) < 4 or len(payload) > MAX_DOWNLOAD_BYTES + MAX_FEED_METADATA_BYTES + 4:
        raise ConverterError("Feed worker returned an invalid bounded frame")
    metadata_size = struct.unpack_from(">I", payload)[0]
    if metadata_size > MAX_FEED_METADATA_BYTES or metadata_size > len(payload) - 4:
        raise ConverterError("Feed worker returned invalid metadata bounds")
    try:
        metadata = json.loads(payload[4 : 4 + metadata_size])
    except (ValueError, UnicodeError) as exc:
        raise ConverterError("Feed worker metadata is invalid") from exc
    data = payload[4 + metadata_size :]
    if (
        not data
        or len(data) > MAX_DOWNLOAD_BYTES
        or not isinstance(metadata, dict)
        or metadata.get("source") != source_name
        or metadata.get("bytes") != len(data)
        or metadata.get("sha256") != hashlib.sha256(data).hexdigest()
        or metadata.get("source_url_sha256") != feed_url_provenance(str(source["url"]))[1]
    ):
        raise ConverterError("Feed worker data and provenance do not agree")
    return data, metadata


@contextmanager
def _feed_startup_interrupt_guard():
    """Defer a callable main-thread SIGINT handler until startup ownership is adopted."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.getsignal(signal.SIGINT)
    if not callable(previous):
        yield
        return
    pending = []

    def defer_interrupt(signum, frame):
        if not pending:
            pending.append((signum, frame))

    signal.signal(signal.SIGINT, defer_interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)
        if pending:
            previous(*pending.pop())


def download_feed(source_name: str) -> tuple[bytes, dict[str, Any]]:
    """Supervise every HTTPS phase and partial IPC under one cancellable deadline."""
    if source_name not in FEEDS:
        raise ConverterError("Unknown built-in feed")
    source = FEEDS[source_name]
    if not is_allowed_https_url(str(source["url"]), set(source["hosts"])):
        raise ConverterError("Built-in feed URL failed its HTTPS allowlist check")
    deadline = time.monotonic() + FEED_DEADLINE_SECONDS
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_feed_process_worker, args=(source_name, sender))
    reader = None
    reader_started = False
    result: dict[str, Any] = {}
    completed = threading.Event()
    try:
        with _feed_startup_interrupt_guard():
            try:
                process.start()
            except (OSError, RuntimeError, ValueError) as exc:
                raise ConverterError(f"Cannot start the bounded feed worker: {exc}") from exc
            # Close the parent's writer so cancelled/failed child exit gives EOF,
            # including while the receiver is waiting for the rest of a frame.
            sender.close()
            reader = threading.Thread(
                target=_receive_feed_frame, args=(receiver, result, completed), daemon=True
            )
            reader.start()
            reader_started = True
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not completed.wait(remaining):
            raise ConverterError("Feed download deadline exceeded; worker cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ConverterError("Feed download deadline exceeded; worker cancelled")
        process.join(remaining)
        if process.is_alive() or time.monotonic() >= deadline:
            raise ConverterError("Feed download deadline exceeded; worker cancelled")
        if process.exitcode != EXIT_OK or "error" in result:
            raise ConverterError("Feed download worker failed to return a complete frame")
        payload = result.get("payload", b"")
        if not payload or payload[0] not in {0, 1}:
            raise ConverterError("Feed worker returned an invalid IPC frame")
        if payload[0] == 1:
            detail = payload[1:8193].decode("utf-8", errors="replace")
            raise ConverterError(f"Feed download worker failed: {detail}")
        answer = _validate_feed_frame(payload[1:], source_name)
        if time.monotonic() >= deadline:
            raise ConverterError("Feed download deadline exceeded")
        return answer
    finally:
        sender.close()
        if process.pid is not None:
            if process.is_alive():
                process.kill()
            process.join()
        # Reaping the sole child writer ends a partial receive with EOF.
        if reader_started:
            reader.join()
        receiver.close()
        process.close()


def terminal_safe(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)[1:-1]


def print_diagnostics(diagnostics: Sequence[Diagnostic], limit: int = 25) -> None:
    for item in diagnostics[:limit]:
        location = (
            f"{item.source}:{item.start_line}" if item.start_line is not None else item.source
        )
        sid = f" SID {item.sid}" if item.sid is not None else ""
        print(
            terminal_safe(f"{item.severity.upper()}: {item.code}: {location}{sid}: {item.message}"),
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
    ensure_outputs_do_not_replace_inputs(outputs, input_snapshots(parsed))
    ensure_outputs_available(outputs, args.force)
    if args.json:
        payload = {
            "schema_version": 1,
            "generated_at": utc_now(),
            "tool": {"name": APP_NAME, "version": VERSION},
            "source": parsed.source,
            "source_sha256": parsed.source_sha256,
            "source_bytes": parsed.byte_count,
            "rule_count": len(parsed.rules),
            "diagnostic_counts": diagnostic_counts(parsed.diagnostics),
            "diagnostics": [item.to_dict() for item in parsed.diagnostics],
        }
        atomic_write_text(
            args.json,
            json_text(payload),
            force=args.force,
            protected_inputs=input_snapshots(parsed),
        )
    if args.sarif:
        atomic_write_text(
            args.sarif,
            json_text(sarif_report(parsed)),
            force=args.force,
            protected_inputs=input_snapshots(parsed),
        )
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
        ensure_outputs_do_not_replace_inputs((args.output,), input_snapshots(parsed))
        destination = atomic_write_text(
            args.output, output, force=args.force, protected_inputs=input_snapshots(parsed)
        )
        print(f"Wrote analysis to {terminal_safe(destination)}")
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
    ensure_outputs_do_not_replace_inputs(requested_outputs, input_snapshots(parsed))
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
            "source_sha256": parsed.source_sha256,
            "source_bytes": parsed.byte_count,
            "rules": [rule_to_dict(rule) for rule in parsed.rules],
            "diagnostics": [item.to_dict() for item in parsed.diagnostics],
        }
        atomic_write_text(
            args.output,
            json_text(payload),
            force=args.force,
            protected_inputs=input_snapshots(parsed),
        )
        print(f"Exported {len(parsed.rules):,} rules to {terminal_safe(args.output)}")
        return EXIT_OK
    converted = convert_rules(
        parsed,
        args.target,
        strict=not args.allow_unverified,
        source_dialect=args.source_dialect,
    )
    all_diagnostics = list(converted.diagnostics)
    generation_id = uuid.uuid4().hex
    output_lines = [
        f"# Generated by {APP_NAME} {VERSION}",
        f"# Generation: {generation_id}",
        f"# Source: {json.dumps(Path(parsed.source).name, ensure_ascii=True)}",
        f"# Source SHA-256: {parsed.source_sha256}",
        f"# Source bytes: {parsed.byte_count}",
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
    if args.rejected_output:
        rejected_indexes = set(converted.rejected_rule_indexes)
        rejected_rules = [rule for rule in parsed.rules if rule.index in rejected_indexes]
        rejected_text = (
            f"# Rejected by {APP_NAME} {VERSION}\n"
            f"# Generation: {generation_id}\n"
            f"# Source: {json.dumps(Path(parsed.source).name, ensure_ascii=True)}\n"
            f"# Source SHA-256: {parsed.source_sha256}\n"
            f"# Source bytes: {parsed.byte_count}\n"
            f"# Rejected input rules: {len(converted.rejected_rule_indexes)}\n"
            "# See the JSON conversion report for incompatibility details.\n\n"
            + "\n".join(rule.raw.strip() for rule in rejected_rules)
            + "\n"
        )
    ensure_outputs_available(requested_outputs, args.force)
    if args.rejected_output:
        atomic_write_text(
            args.rejected_output,
            rejected_text,
            force=args.force,
            protected_inputs=input_snapshots(parsed),
        )
    if args.report:
        report = {
            "schema_version": 1,
            "generation_id": generation_id,
            "generated_at": utc_now(),
            "tool": {"name": APP_NAME, "version": VERSION},
            "source": parsed.source,
            "source_sha256": parsed.source_sha256,
            "source_bytes": parsed.byte_count,
            "target": args.target,
            "source_dialect": args.source_dialect,
            "allow_unverified": args.allow_unverified,
            "input_rules": len(parsed.rules),
            "output_rules": len(converted.rules),
            "rejected_rules": len(converted.rejected_rule_indexes),
            "artifact_sha256": {
                "output": hashlib.sha256("\n".join(output_lines).encode("utf-8")).hexdigest(),
                "rejected": hashlib.sha256(rejected_text.encode("utf-8")).hexdigest()
                if args.rejected_output
                else None,
            },
            "unverified_keywords": dict(sorted(converted.unverified_keywords.items())),
            "diagnostic_counts": diagnostic_counts(all_diagnostics),
            "diagnostics": [item.to_dict() for item in all_diagnostics],
        }
        atomic_write_text(
            args.report,
            json_text(report),
            force=args.force,
            protected_inputs=input_snapshots(parsed),
        )
    atomic_write_text(
        args.output,
        "\n".join(output_lines),
        force=args.force,
        protected_inputs=input_snapshots(parsed),
    )
    print(
        f"Converted {len(converted.rules):,} rules to {args.target}: {terminal_safe(args.output)}"
    )
    print_diagnostics(all_diagnostics)
    return EXIT_FINDINGS if converted.rejected_rule_indexes else EXIT_OK


def command_panorama(args: argparse.Namespace) -> int:
    parsed = RuleParser().parse_file(args.input)
    report, accepted, rejected, diagnostics = build_panorama_report(parsed)
    if parsed.errors:
        print_diagnostics(diagnostics)
        print(
            "Panorama generation stopped because the input contains parse errors. No output was written.",
            file=sys.stderr,
        )
        return EXIT_FINDINGS
    output_dir = canonical_system_path(args.output_dir.expanduser().absolute())
    output_dir = ensure_output_directory(output_dir)
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
    manifest_path = output_dir / "panorama_manifest.json"
    manifest = {
        "generation_id": uuid.uuid4().hex,
        "source_sha256": parsed.source_sha256,
        "source_bytes": parsed.byte_count,
        "sha256": {
            path.name: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for path, content in files
        },
    }
    files.append((manifest_path, json_text(manifest)))
    expected_names = {path.name for path, _ in files}

    def check_existing_generation(names):
        for name in names:
            if (
                re.fullmatch(
                    r"panorama_(?:batch_[0-9]+\.rules|rejected\.rules|preflight\.(?:json|txt)|manifest\.json)",
                    name,
                )
                and name not in expected_names
            ):
                raise ConverterError(
                    "Output directory contains stale Panorama artifacts; choose a fresh directory"
                )

    if os.name == "nt":
        with windows_report_directory_lock(output_dir):
            check_existing_generation(path.name for path in output_dir.iterdir())
    else:
        directory = open_posix_directory(output_dir)
        try:
            check_existing_generation(os.listdir(directory))
        finally:
            os.close(directory)
    ensure_outputs_do_not_replace_inputs((path for path, _ in files), input_snapshots(parsed))
    ensure_outputs_available((path for path, _ in files), args.force)
    files.sort(
        key=lambda item: (
            item[0].name == "panorama_manifest.json",
            item[0].name.startswith("panorama_batch_"),
        )
    )
    for path, content in files:
        atomic_write_text(path, content, force=args.force, protected_inputs=input_snapshots(parsed))
    print(
        f"Panorama {PANORAMA_PROFILE} preflight: {len(accepted):,} accepted, {len(rejected):,} rejected, "
        f"{report['batch_count']:,} batches. Reports: {terminal_safe(output_dir)}"
    )
    print_diagnostics(diagnostics)
    return EXIT_FINDINGS if parsed.errors or rejected else EXIT_OK


def command_diff(args: argparse.Namespace) -> int:
    before = RuleParser().parse_file(args.before)
    after = RuleParser().parse_file(args.after)
    report = ruleset_diff(before, after)
    output = json_text(report)
    if args.output:
        ensure_outputs_do_not_replace_inputs((args.output,), input_snapshots(before, after))
        atomic_write_text(
            args.output, output, force=args.force, protected_inputs=input_snapshots(before, after)
        )
        print(f"Wrote ruleset diff to {terminal_safe(args.output)}")
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
    output_dir = canonical_system_path(args.output_dir.expanduser().absolute())
    output_dir = ensure_output_directory(output_dir)
    archive_path = output_dir / f"{args.source}{extension}"
    metadata_path = output_dir / f"{args.source}.metadata.json"
    ensure_outputs_available((archive_path, metadata_path), args.force)
    if args.extract:
        # Admit the complete typed graph before creating the private extraction
        # root. Member directories belong only to the staged generation.
        (
            validate_tar_archive(data)
            if source["archive"] == "tar.gz"
            else validate_zip_archive(data)
        )
        extraction_root = output_dir / args.source
        if extraction_root.exists() or extraction_root.is_symlink():
            raise ConverterError("Fetch extraction root must not already exist")
        ensure_output_directory(extraction_root, exclusive=True)
        extracted = extract_archive(data, str(source["archive"]), extraction_root, force=args.force)
        metadata = dict(metadata)
        metadata["extraction_generation"] = (
            str(extracted[0].relative_to(extraction_root).parts[0]) if extracted else None
        )
        metadata["extracted_files"] = [str(path.relative_to(output_dir)) for path in extracted]
    # Extraction must complete before its archive/provenance is announced.
    atomic_write_bytes(archive_path, data, force=args.force)
    atomic_write_text(metadata_path, json_text(metadata), force=args.force)
    if args.extract:
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
    except (ConverterError, OSError) as exc:
        print(f"ERROR: {terminal_safe(exc)}", file=sys.stderr)
        count = getattr(exc, "archive_cleanup_failure_count", 0)
        if count:
            summary = f"Archive cleanup reported {count} failure(s)"
            failures = getattr(exc, "archive_cleanup_failures", ())
            detail = ": " + "; ".join(failures) if failures else ""
            print(f"CLEANUP: {terminal_safe(summary + detail)}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

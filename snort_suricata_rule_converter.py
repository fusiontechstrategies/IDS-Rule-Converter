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
import os
import re
import ssl
import stat
import struct
import subprocess  # nosec B404
import sys
import tarfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
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
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000
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


@dataclass
class ParseResult:
    source: str
    rules: list[Rule] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    ignored_directives: int = 0
    byte_count: int = 0
    input_identity: InputIdentity | None = None

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


def read_input(path: Path, max_bytes: int = MAX_INPUT_BYTES) -> tuple[str, InputIdentity]:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ConverterError(f"Cannot access input file '{path}': {exc}") from exc
    try:
        expected = resolved.stat()
        if not stat.S_ISREG(expected.st_mode):
            raise ConverterError(f"Input is not a regular file: {resolved}")
        descriptor = os.open(
            resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ConverterError(f"Input is not a regular file: {resolved}")
            if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
                raise ConverterError("Input identity changed before reading")
            if opened.st_size > max_bytes:
                raise ConverterError(
                    f"Input is {opened.st_size:,} bytes; the limit is {max_bytes:,} bytes"
                )
            data = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
            named = resolved.stat()
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
        raise ConverterError(f"Cannot read input file '{resolved}': {exc}") from exc
    if b"\x00" in data:
        raise ConverterError(f"Input contains NUL bytes and is not a text ruleset: {resolved}")
    try:
        return data.decode("utf-8-sig"), InputIdentity(
            resolved, opened.st_dev, opened.st_ino, len(data)
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


def windows_private_report_directory(parent, sid):
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


def atomic_write_bytes(
    path: Path,
    data: bytes | BinaryIO,
    force: bool = False,
    *,
    expected_size: int | None = None,
    protected_inputs: Sequence[InputIdentity] = (),
) -> Path:
    destination = ensure_output_path(path, force)
    ensure_outputs_do_not_replace_inputs((destination,), protected_inputs)
    if os.name != "nt":
        directory = open_posix_directory(destination.parent)
        temporary_name = f".ids-{uuid.uuid4().hex}.tmp"
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
            with os.fdopen(fd, "wb") as handle:
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
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory)
            os.close(directory)
        return destination
    sid = current_windows_sid()
    with ExitStack() as locks:
        for parent in reversed((destination.parent, *destination.parent.parents)):
            locks.enter_context(
                windows_report_directory_lock(
                    parent, parent_sid=sid, require_user_owner=parent == destination.parent
                )
            )
        staging = windows_private_report_directory(destination.parent, sid)
        with windows_report_directory_lock(staging, sid, remove_on_exit=True):
            temporary = staging / "report"
            try:
                with temporary.open("xb") as handle:
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
            finally:
                temporary.unlink(missing_ok=True)
    return destination


def atomic_write_text(
    path: Path, text: str, force: bool = False, *, protected_inputs: Sequence[InputIdentity] = ()
) -> Path:
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
        return result

    def parse_text(
        self, text: str, source: str = "<memory>", *, byte_count: int | None = None
    ) -> ParseResult:
        if len(text) > MAX_INPUT_BYTES:
            raise ConverterError("Input exceeds its character budget")
        size = len(text.encode("utf-8")) if byte_count is None else byte_count
        if size > MAX_INPUT_BYTES:
            raise ConverterError("Input exceeds its byte budget")
        result = ParseResult(source=source, byte_count=size)
        try:
            cleaned = strip_rule_comments(text)
        except UnterminatedBlockComment as exc:
            result.diagnostics.append(
                Diagnostic(
                    "error", "UNTERMINATED_BLOCK_COMMENT", str(exc), source, exc.line, exc.line
                )
            )
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
        return result

    def _records(self, text: str, result: ParseResult) -> Iterator[tuple[str, int, int]]:
        index = 0
        line = 1
        length = len(text)
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
            line_end = text.find("\n", index)
            if line_end == -1:
                line_end = length
            token_match = re.match(r"[A-Za-z_][A-Za-z0-9_-]*", text[index:line_end])
            token = token_match.group(0).lower() if token_match else ""
            if line_end - index > MAX_RULE_CHARS:
                raise ConverterError("Input line exceeds the rule classification budget")
            header_preview = text[index:line_end]
            following_index = line_end
            following_limit = min(length, line_end + MAX_RULE_CHARS)
            while following_index < following_limit and text[following_index].isspace():
                following_index += 1
            looks_like_rule = (
                ("->" in header_preview or "<>" in header_preview)
                or (
                    "(" in header_preview
                    and len(split_header(header_preview.split("(", 1)[0])) == 2
                )
                or text.startswith(("(", "->", "<>"), following_index)
            )
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


def transform_to_suricata(
    options: Sequence[RuleOption], source_dialect: str, rule_protocol: str
) -> list[RuleOption]:
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
        if key == "service" and option.value is not None:
            service = mapped_suricata_service(option.value)
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
    if source_dialect == "snort2":
        return transform_snort2_to_snort3(options)
    if source_dialect == "suricata" and any(
        option.key in SURICATA_BACKWARD_BUFFERS for option in options
    ):
        return transform_snort2_to_snort3(options, SURICATA_BACKWARD_BUFFERS)
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
    rules: Sequence[Rule],
    target: str,
    strict: bool = True,
    source_dialect: str = "auto",
) -> ConversionResult:
    result = ConversionResult(target=target)
    for rule in rules:
        if len(result.diagnostics) >= MAX_DIAGNOSTICS:
            raise ConverterError("Diagnostic budget exceeded; no partial output is safe")
        dialect = infer_dialect(rule) if source_dialect == "auto" else source_dialect
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
            rendered = render_rule(rule, target, dialect)
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
    diagnostics = list(parsed.diagnostics)
    per_rule: list[dict[str, Any]] = []
    parse_error_lines = {item.start_line for item in parsed.errors}
    for rule in parsed.rules:
        findings = panorama_option_checks(rule)
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
        stem = part.split(".", 1)[0].upper()
        if stem in reserved:
            raise ConverterError(f"Archive contains a Windows device path: {name!r}")
        if part.endswith((" ", ".")) or any(ord(char) < 32 or char in '<>:"|?*' for char in part):
            raise ConverterError(f"Archive contains a Windows-unsafe path: {name!r}")
    return path


class BoundedTarInfo(tarfile.TarInfo):
    """Reject oversized extension metadata before tarfile reads or allocates it."""

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
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        self._metadata_budget(archive)
        return super()._proc_gnulong(archive)

    def _proc_sparse(self, archive):
        raise ConverterError("Sparse TAR members are not supported")


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


def validate_tar_archive(data: bytes) -> list[tarfile.TarInfo]:
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
                archive._ids_extension_count = 0
                member = archive.next()
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
                if member.size < 0 or member.size > MAX_EXTRACTED_FILE_BYTES:
                    raise ConverterError(f"Archive entry is too large: {member.name!r}")
                total += member.size
                if total > MAX_EXTRACTED_BYTES:
                    raise ConverterError("TAR archive exceeds its extracted byte limit")
                members.append(member)
    except (tarfile.TarError, OSError, EOFError, RecursionError) as exc:
        raise ConverterError(f"Downloaded file is not a valid bounded TAR archive: {exc}") from exc
    check_archive_object_budget(member.name for member in members)
    return members


def preflight_zip_directory(data: bytes) -> tuple[int, int]:
    """Bound and count directory records before ZipFile allocates any ZipInfo."""
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ConverterError("ZIP input exceeds the download byte limit")
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
        if member.file_size < 0 or member.file_size > MAX_EXTRACTED_FILE_BYTES:
            raise ConverterError(f"Archive entry is too large: {member.filename!r}")
        total += member.file_size
        if total > MAX_EXTRACTED_BYTES:
            raise ConverterError(f"Archive expands beyond the {MAX_EXTRACTED_BYTES:,} byte limit")
    check_archive_object_budget(member.filename.rstrip("/") for member in members)
    return members


def extract_archive(data: bytes, archive_type: str, output_dir: Path, force: bool) -> list[Path]:
    if output_dir.is_symlink() or (
        output_dir.exists()
        and getattr(output_dir.lstat(), "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    ):
        raise ConverterError("Extraction root cannot be a link or reparse point")
    output_dir = canonical_system_path(output_dir.expanduser().absolute())
    output_dir = ensure_output_directory(output_dir)
    written: list[Path] = []

    def destination_for(name: str) -> Path:
        relative = safe_archive_name(name)
        destination = output_dir.joinpath(*relative.parts)
        if not destination.absolute().is_relative_to(output_dir):
            raise ConverterError(f"Archive entry escapes the output directory: {name!r}")
        return destination

    if archive_type == "tar.gz":
        members = validate_tar_archive(data)
        ensure_outputs_available(
            (destination_for(member.name) for member in members if member.isfile()),
            force,
        )
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in members:
                destination = destination_for(member.name)
                if member.isdir():
                    ensure_output_directory(destination)
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ConverterError(f"Cannot read archive entry: {member.name!r}")
                with extracted:
                    atomic_write_bytes(
                        destination, extracted, force=force, expected_size=member.size
                    )
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
                    ensure_output_directory(destination)
                    continue
                with archive.open(member) as content:
                    atomic_write_bytes(
                        destination, content, force=force, expected_size=member.file_size
                    )
                written.append(destination)
    else:
        raise ConverterError(f"Unsupported archive type: {archive_type}")
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


def download_feed(source_name: str) -> tuple[bytes, dict[str, Any]]:
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
                raise ConverterError(
                    f"Download ended outside the HTTPS source allowlist: {final_url}"
                )
            final = urllib.parse.urlparse(final_url)
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
        parsed.rules,
        args.target,
        strict=not args.allow_unverified,
        source_dialect=args.source_dialect,
    )
    all_diagnostics = list(parsed.diagnostics)
    extend_diagnostics(all_diagnostics, converted.diagnostics)
    output_lines = [
        f"# Generated by {APP_NAME} {VERSION}",
        f"# Source: {json.dumps(Path(parsed.source).name, ensure_ascii=True)}",
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
            f"# Source: {json.dumps(Path(parsed.source).name, ensure_ascii=True)}\n"
            "# See the JSON conversion report for incompatibility details.\n\n"
            + "\n".join(rule.raw.strip() for rule in rejected_rules)
            + "\n"
        )
    ensure_outputs_available(requested_outputs, args.force)
    if args.rejected_output and converted.rejected_rule_indexes:
        atomic_write_text(
            args.rejected_output,
            rejected_text,
            force=args.force,
            protected_inputs=input_snapshots(parsed),
        )
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
        if extraction_root.exists() or extraction_root.is_symlink():
            raise ConverterError("Fetch extraction root must not already exist")
        ensure_output_directory(extraction_root, exclusive=True)
        extraction_root_resolved = extraction_root
        extraction_paths = []
        for name in names:
            relative = safe_archive_name(name)
            destination = extraction_root_resolved.joinpath(*relative.parts)
            if not destination.absolute().is_relative_to(extraction_root_resolved):
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
        print(f"ERROR: {terminal_safe(exc)}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR
    except OSError as exc:
        print(f"ERROR: {terminal_safe(exc)}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

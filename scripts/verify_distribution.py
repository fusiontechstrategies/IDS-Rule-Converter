"""Verify the installable IDS distributions against the reviewed source tree."""

from __future__ import annotations

import argparse
import base64
import csv
import email
import gzip
import hashlib
import io
import struct
import tarfile
import unicodedata
import zipfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

MODULE = "snort_suricata_rule_converter.py"
# Installation semantics come from this protected verifier, never the producer's
# generated metadata or a candidate backend. Pin/version evolution requires an
# explicit reviewed change here as well as in pyproject.toml.
APPROVED_BUILD_SYSTEM = {
    "requires": ["setuptools==84.0.0", "wheel==0.48.0"],
    "build-backend": "setuptools.build_meta",
}
APPROVED_PROJECT = {
    "name": "ids-rule-converter",
    "version": "4.0.2",
    "description": "Loss-aware Snort and Suricata rule conversion toolkit",
    "readme": "README.md",
    "requires-python": ">=3.10,<3.15",
    "license": "Apache-2.0",
    "license-files": ["LICENSE"],
    "authors": [{"name": "Fusion Technology Strategies"}],
    "classifiers": [
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: Security",
    ],
    "scripts": {"ids-rule-converter": "snort_suricata_rule_converter:main"},
    "urls": {
        "Repository": "https://github.com/fusiontechstrategies/IDS-Rule-Converter",
        "Issues": "https://github.com/fusiontechstrategies/IDS-Rule-Converter/issues",
    },
}
APPROVED_SETUPTOOLS = {"py-modules": ["snort_suricata_rule_converter"]}
APPROVED_ENTRY_POINTS = "[console_scripts]\nids-rule-converter = snort_suricata_rule_converter:main"
APPROVED_WHEEL_GENERATOR = "setuptools (84.0.0)"
BLOCKED_SUFFIXES = {".env", ".key", ".p12", ".pem", ".pfx", ".pyc"}
WINDOWS_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{index}" for prefix in ("COM", "LPT") for index in range(1, 10)
}


MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 1024 * 1024
MAX_EXPANDED_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256


class LimitedExpandedReader:
    """Bound the whole gzip stream, including invisible TAR/PAX headers."""

    def __init__(self, stream, compressed_bytes):
        self.stream = stream
        self.remaining = min(MAX_EXPANDED_BYTES, max(64 * 1024, 512 * compressed_bytes))

    def read(self, size=-1):
        request = self.remaining + 1 if size < 0 else min(size, self.remaining + 1)
        value = self.stream.read(request)
        if len(value) > self.remaining:
            raise ValueError("Archive expanded-byte budget exceeded")
        self.remaining -= len(value)
        return value


class CachedArchive:
    def __init__(self, members, values):
        self.members, self.values = members, values

    def namelist(self):
        return [member.filename for member in self.members]

    def getmembers(self):
        return self.members

    def read(self, name):
        return self.values[name]

    def extractfile(self, name):
        return io.BytesIO(self.values[name]) if name in self.values else None


def validate_archive_file(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("Archive file type or compressed-byte budget invalid")


@contextmanager
def bounded_wheel(path):
    validate_archive_file(path)
    # Reject inflated central-directory metadata before ZipFile materializes it.
    with path.open("rb") as stream:
        # Include the 20-byte ZIP64 locator even with the maximum EOCD comment.
        stream.seek(max(0, path.stat().st_size - (65557 + 20)))
        tail = stream.read(65557 + 20)
    start = tail.rfind(b"PK\x05\x06")
    if start < 0 or len(tail) - start < 22:
        raise ValueError("Missing ZIP end record")
    # ZipFile honors this locator even when the legacy end record advertises zero.
    # These small release wheels never require ZIP64 metadata.
    if start >= 20 and tail[start - 20 : start - 16] == b"PK\x06\x07":
        raise ValueError("ZIP64 archives are unsupported")
    _, disk, cd_disk, disk_count, count, cd_bytes, _, comment = struct.unpack(
        "<4s4H2LH", tail[start : start + 22]
    )
    if (
        disk
        or cd_disk
        or disk_count != count
        or count > MAX_ARCHIVE_MEMBERS
        or cd_bytes > 256 * 1024
        or start + 22 + comment != len(tail)
    ):
        raise ValueError("ZIP metadata budget exceeded or unsupported archive")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if (
            len(members) > MAX_ARCHIVE_MEMBERS
            or sum(member.file_size for member in members) > MAX_EXPANDED_BYTES
        ):
            raise ValueError("ZIP member or expanded-byte budget exceeded")
        values = {}
        for member in members:
            if (
                member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                or member.file_size > MAX_MEMBER_BYTES
                or member.file_size > 512 * max(1, member.compress_size)
            ):
                raise ValueError("ZIP member decoder, size or compression ratio invalid")
            with archive.open(member) as stream:
                data = stream.read(MAX_MEMBER_BYTES + 1)
            if len(data) > MAX_MEMBER_BYTES or len(data) != member.file_size:
                raise ValueError("ZIP member exceeded its expanded-byte budget")
            values[member.filename] = data
        yield CachedArchive(members, values)


@contextmanager
def bounded_sdist(path):
    validate_archive_file(path)
    members, values = [], {}
    total = 0
    with path.open("rb") as raw, gzip.GzipFile(fileobj=raw) as expanded:
        limited = LimitedExpandedReader(expanded, path.stat().st_size)
        with tarfile.open(fileobj=limited, mode="r|") as archive:
            for member in archive:
                members.append(member)
                if (
                    len(members) > MAX_ARCHIVE_MEMBERS
                    or member.size > MAX_MEMBER_BYTES
                    or member.size < 0
                    or not (member.isfile() or member.isdir())
                ):
                    raise ValueError("TAR member count, size or type invalid")
                total += member.size
                if total > MAX_EXPANDED_BYTES:
                    raise ValueError("TAR aggregate expanded-byte budget exceeded")
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError("TAR file contents unavailable")
                    with stream:
                        data = stream.read(MAX_MEMBER_BYTES + 1)
                    if len(data) > MAX_MEMBER_BYTES or len(data) != member.size:
                        raise ValueError("TAR member exceeded its expanded-byte budget")
                    values[member.name] = data
    yield CachedArchive(members, values)


def validate_record(values: dict[str, bytes], record: str) -> None:
    rows = list(csv.reader(io.StringIO(values[record].decode("utf-8"))))
    entries = {}
    for row in rows:
        if len(row) != 3 or row[0] not in values or row[0] in entries:
            raise ValueError("Wheel RECORD has an unreviewed, duplicate, or malformed entry")
        entries[row[0]] = row[1:]
    if set(entries) != set(values):
        raise ValueError("Wheel RECORD must cover the exact member set")
    for name, data in values.items():
        expected = (
            ["", ""]
            if name == record
            else [
                "sha256="
                + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode(),
                str(len(data)),
            ]
        )
        if entries[name] != expected:
            raise ValueError("Wheel RECORD identity differs from the verified member")


def validate_installation_contract(configuration: dict) -> None:
    """Authorize inert TOML without importing or running candidate build code."""
    if set(configuration) != {"build-system", "project", "tool"}:
        raise ValueError("Unreviewed top-level pyproject installation contract")
    if configuration["build-system"] != APPROVED_BUILD_SYSTEM:
        # Exact spellings also reject URLs, markers, extras, duplicate/case
        # variants, backend-path and additional requirements or backend keys.
        raise ValueError("Unreviewed pinned build-system installation contract")
    project = configuration["project"]
    if not isinstance(project, dict):
        raise ValueError("Project installation contract must be a table")
    permitted_empty = {"dependencies": [], "optional-dependencies": {}, "dynamic": []}
    if set(project) - set(APPROVED_PROJECT) - set(permitted_empty):
        raise ValueError("Unreviewed project installation fields")
    for key, empty in permitted_empty.items():
        if key in project and (type(project[key]) is not type(empty) or project[key] != empty):
            raise ValueError("The runtime contract forbids dependency and dynamic declarations")
    if {key: value for key, value in project.items() if key not in permitted_empty} != (
        APPROVED_PROJECT
    ):
        raise ValueError("Project differs from the protected reviewed installation contract")
    tool = configuration["tool"]
    if (
        not isinstance(tool, dict)
        or set(tool) != {"setuptools", "ruff"}
        or tool["setuptools"] != APPROVED_SETUPTOOLS
    ):
        raise ValueError("Unreviewed setuptools module or package installation contract")


def reviewed_project(source_root: Path) -> dict:
    # Release jobs run Python 3.12 in isolated mode. Python 3.10 test/build users
    # install the pinned tomli compatibility parser, never tagged import paths.
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib
    with (source_root / "pyproject.toml").open("rb") as stream:
        configuration = tomllib.load(stream)
    validate_installation_contract(configuration)
    return configuration


def validate_descriptive_metadata(metadata, source_root: Path, configuration: dict) -> None:
    validate_installation_contract(configuration)
    project = APPROVED_PROJECT
    authors = project["authors"]
    if any(set(author) != {"name"} for author in authors):
        raise ValueError("Reviewed author format is unsupported")
    expected = {
        "Summary": [project["description"]],
        "Author": [", ".join(author["name"] for author in authors)],
        "Project-URL": [f"{label}, {url}" for label, url in project["urls"].items()],
        "Classifier": project["classifiers"],
    }
    for header, values in expected.items():
        if Counter(metadata.get_all(header) or []) != Counter(values):
            raise ValueError(f"Package {header} differs from reviewed project metadata")
    if project["readme"] != "README.md":
        raise ValueError("Reviewed package description source is unsupported")
    description = metadata.get_payload(decode=True)
    if description is None or description.decode("utf-8").replace("\r\n", "\n") != (
        source_root / "README.md"
    ).read_text(encoding="utf-8"):
        raise ValueError("Package description differs from reviewed README")


def validate_metadata(metadata, source_root: Path, configuration: dict) -> None:
    allowed = {
        "Metadata-Version",
        "Name",
        "Version",
        "Summary",
        "Author",
        "License-Expression",
        "Project-URL",
        "Classifier",
        "Requires-Python",
        "Description-Content-Type",
        "License-File",
        "Dynamic",
    }
    if set(metadata.keys()) - allowed:
        raise ValueError("Package metadata contains unreviewed installation semantics")
    required = {
        "Metadata-Version": "2.4",
        "Requires-Python": "<3.15,>=3.10",
        "Description-Content-Type": "text/markdown",
        "License-Expression": "Apache-2.0",
        "License-File": "LICENSE",
    }
    for key, value in required.items():
        if metadata.get_all(key) != [value]:
            raise ValueError(f"Package metadata has unreviewed {key}")
    if metadata.get_all("Dynamic") not in (None, ["license-file"]):
        raise ValueError("Package metadata declares unreviewed dynamic fields")
    if len(metadata.get_all("Name") or []) != 1 or len(metadata.get_all("Version") or []) != 1:
        raise ValueError("Package metadata identity must be unique")
    validate_descriptive_metadata(metadata, source_root, configuration)


def safe_names(names: list[str]) -> None:
    seen: set[str] = set()
    for name in names:
        path = PurePosixPath(name)
        parts = name.removesuffix("/").split("/")
        if (
            name.startswith("/")
            or "\\" in name
            or not path.parts
            or any(part in {"", ".", ".."} for part in parts)
            or any(
                part.endswith((" ", "."))
                or part.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
                or any(ord(char) < 32 or ord(char) == 127 or char in '<>:"|?*' for char in part)
                for part in parts
            )
        ):
            raise ValueError(f"Unsafe archive path: {name}")
        portable = unicodedata.normalize("NFC", name.rstrip("/")).casefold()
        if portable in seen:
            raise ValueError(f"Duplicate archive path: {name}")
        seen.add(portable)
        if any(name.lower().endswith(suffix) for suffix in BLOCKED_SUFFIXES):
            raise ValueError(f"Blocked file type: {name}")
        if "__pycache__" in path.parts:
            raise ValueError(f"Python cache in archive: {name}")


def verify_distribution(dist_dir: Path, source_root: Path, version: str) -> tuple[Path, Path]:
    configuration = reviewed_project(source_root)
    if version != APPROVED_PROJECT["version"]:
        raise ValueError("Release version differs from the protected installation contract")
    wheel_name = f"ids_rule_converter-{version}-py3-none-any.whl"
    sdist_name = f"ids_rule_converter-{version}.tar.gz"
    if {path.name for path in dist_dir.iterdir()} != {wheel_name, sdist_name}:
        raise ValueError("Distribution directory must contain the exact wheel and source archive")
    wheel, sdist = dist_dir / wheel_name, dist_dir / sdist_name
    with bounded_wheel(wheel) as archive:
        names = archive.namelist()
        safe_names(names)
        prefix = f"ids_rule_converter-{version}.dist-info/"
        allowed = {MODULE} | {
            prefix + name
            for name in (
                "METADATA",
                "WHEEL",
                "RECORD",
                "entry_points.txt",
                "top_level.txt",
                "licenses/LICENSE",
            )
        }
        if set(names) != allowed:
            raise ValueError("Wheel contains missing or unreviewed installation members")
        values = {name: archive.read(name) for name in names}
        validate_record(values, prefix + "RECORD")
        wheel_metadata = email.message_from_bytes(values[prefix + "WHEEL"])
        for key, value in {
            "Wheel-Version": "1.0",
            "Root-Is-Purelib": "true",
            "Tag": "py3-none-any",
        }.items():
            if wheel_metadata.get_all(key) != [value]:
                raise ValueError(
                    "Wheel installation mode differs from reviewed pure-Python configuration"
                )
        if set(wheel_metadata.keys()) != {"Wheel-Version", "Generator", "Root-Is-Purelib", "Tag"}:
            raise ValueError("Wheel contains unreviewed installation headers")
        if wheel_metadata.get_all("Generator") != [APPROVED_WHEEL_GENERATOR]:
            raise ValueError("Wheel generator differs from reviewed build system")
        if values[prefix + "top_level.txt"].strip() != MODULE.removesuffix(".py").encode():
            raise ValueError("Wheel top-level module differs from reviewed source")
        if values[prefix + "licenses/LICENSE"] != (source_root / "LICENSE").read_bytes():
            raise ValueError("Wheel license differs from reviewed source")
        if [name for name in names if name.endswith(".py")] != [MODULE]:
            raise ValueError("Wheel must contain only the reviewed runtime module")
        if archive.read(MODULE) != (source_root / MODULE).read_bytes():
            raise ValueError("Wheel runtime differs from reviewed source")
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        entry_points = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        if len(metadata) != 1 or len(entry_points) != 1:
            raise ValueError("Wheel is missing unique package metadata or CLI entry point")
        details = email.message_from_bytes(archive.read(metadata[0]))
        validate_metadata(details, source_root, configuration)
        if details.get("Name") != "ids-rule-converter" or details.get("Version") != version:
            raise ValueError("Wheel package identity differs from release")
        if details.get_all("Requires-Dist"):
            raise ValueError("The standard-library runtime must have no install dependencies")
        if archive.read(entry_points[0]).decode("utf-8").strip() != APPROVED_ENTRY_POINTS:
            raise ValueError("Wheel CLI entry point differs from release")
    with bounded_sdist(sdist) as archive:
        members = archive.getmembers()
        safe_names([member.name for member in members])
        if any(not (member.isfile() or member.isdir()) for member in members):
            raise ValueError("Source archive contains links or special files")
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        if roots != {f"ids_rule_converter-{version}"}:
            raise ValueError("Source archive has an unexpected root")
        reviewed = {MODULE, "LICENSE", "README.md", "pyproject.toml"}
        reviewed.update(
            path.relative_to(source_root).as_posix()
            for path in (source_root / "tests").glob("test_*.py")
        )
        generated = {"PKG-INFO", "setup.cfg"} | {
            "ids_rule_converter.egg-info/" + name
            for name in (
                "PKG-INFO",
                "SOURCES.txt",
                "dependency_links.txt",
                "entry_points.txt",
                "top_level.txt",
            )
        }
        actual = {
            "/".join(PurePosixPath(member.name).parts[1:]) for member in members if member.isfile()
        }
        if actual != reviewed | generated:
            raise ValueError("Source archive contains missing or unreviewed installation members")
        allowed_directories = {f"ids_rule_converter-{version}"}
        for relative in reviewed | generated:
            path = PurePosixPath(f"ids_rule_converter-{version}/{relative}")
            allowed_directories.update(str(parent) for parent in path.parents if str(parent) != ".")
        if any(
            member.name.rstrip("/") not in allowed_directories
            for member in members
            if member.isdir()
        ):
            raise ValueError("Source archive contains unreviewed directories")
        prefix = f"ids_rule_converter-{version}/ids_rule_converter.egg-info/"
        sources = archive.extractfile(prefix + "SOURCES.txt").read().decode("utf-8").splitlines()
        if len(sources) != len(set(sources)) or set(sources) != reviewed | (
            generated - {"PKG-INFO", "setup.cfg"}
        ):
            raise ValueError("Source file manifest differs from the exact reviewed build inputs")
        if archive.extractfile(prefix + "dependency_links.txt").read().strip():
            raise ValueError("Source archive has unreviewed dependency links")
        if (
            archive.extractfile(prefix + "top_level.txt").read().strip()
            != MODULE.removesuffix(".py").encode()
        ):
            raise ValueError("Source archive top-level module differs from reviewed source")
        for relative in reviewed:
            contents = archive.extractfile(f"ids_rule_converter-{version}/{relative}").read()
            if contents != (source_root / relative).read_bytes():
                raise ValueError(f"Source archive differs from reviewed {relative}")
        config = archive.extractfile(f"ids_rule_converter-{version}/setup.cfg").read()
        if config.replace(b"\r\n", b"\n").strip() != b"[egg_info]\ntag_build = \ntag_date = 0":
            raise ValueError("Source archive contains unreviewed setup configuration")
        for relative in ("PKG-INFO", "ids_rule_converter.egg-info/PKG-INFO"):
            metadata = email.message_from_bytes(
                archive.extractfile(f"ids_rule_converter-{version}/{relative}").read()
            )
            validate_metadata(metadata, source_root, configuration)
            if (
                metadata.get("Name") != "ids-rule-converter"
                or metadata.get("Version") != version
                or metadata.get_all("Requires-Dist")
            ):
                raise ValueError("Source archive package metadata differs from release")
        entries = (
            archive.extractfile(
                f"ids_rule_converter-{version}/ids_rule_converter.egg-info/entry_points.txt"
            )
            .read()
            .decode("utf-8")
            .strip()
        )
        if entries != APPROVED_ENTRY_POINTS:
            raise ValueError("Source archive entry points differ from reviewed CLI")
        for relative in (MODULE, "LICENSE", "README.md", "pyproject.toml"):
            name = f"ids_rule_converter-{version}/{relative}"
            member = archive.extractfile(name)
            if member is None or member.read() != (source_root / relative).read_bytes():
                raise ValueError(f"Source archive differs from reviewed {relative}")
    return wheel, sdist


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist_dir", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-root", type=Path)
    arguments = parser.parse_args()
    root = (
        arguments.source_root.resolve()
        if arguments.source_root
        else Path(__file__).resolve().parents[1]
    )
    wheel, sdist = verify_distribution(arguments.dist_dir.resolve(), root, arguments.version)
    print(f"Verified {wheel.name} and {sdist.name}")


if __name__ == "__main__":
    main()

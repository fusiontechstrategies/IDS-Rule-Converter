"""Verify the installable IDS distributions against the reviewed source tree."""

from __future__ import annotations

import argparse
import base64
import csv
import email
import hashlib
import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MODULE = "snort_suricata_rule_converter.py"
BLOCKED_SUFFIXES = {".env", ".key", ".p12", ".pem", ".pfx", ".pyc"}


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


def validate_metadata(metadata) -> None:
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


def safe_names(names: list[str]) -> None:
    seen: set[str] = set()
    for name in names:
        path = PurePosixPath(name)
        if name.startswith("/") or "\\" in name or not path.parts or ".." in path.parts:
            raise ValueError(f"Unsafe archive path: {name}")
        portable = name.rstrip("/").casefold()
        if portable in seen:
            raise ValueError(f"Duplicate archive path: {name}")
        seen.add(portable)
        if any(name.lower().endswith(suffix) for suffix in BLOCKED_SUFFIXES):
            raise ValueError(f"Blocked file type: {name}")
        if "__pycache__" in path.parts:
            raise ValueError(f"Python cache in archive: {name}")


def verify_distribution(dist_dir: Path, source_root: Path, version: str) -> tuple[Path, Path]:
    wheel_name = f"ids_rule_converter-{version}-py3-none-any.whl"
    sdist_name = f"ids_rule_converter-{version}.tar.gz"
    if {path.name for path in dist_dir.iterdir()} != {wheel_name, sdist_name}:
        raise ValueError("Distribution directory must contain the exact wheel and source archive")
    wheel, sdist = dist_dir / wheel_name, dist_dir / sdist_name
    with zipfile.ZipFile(wheel) as archive:
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
        validate_metadata(details)
        if details.get("Name") != "ids-rule-converter" or details.get("Version") != version:
            raise ValueError("Wheel package identity differs from release")
        if details.get_all("Requires-Dist"):
            raise ValueError("The standard-library runtime must have no install dependencies")
        if (
            archive.read(entry_points[0]).decode("utf-8").strip()
            != "[console_scripts]\nids-rule-converter = snort_suricata_rule_converter:main"
        ):
            raise ValueError("Wheel CLI entry point differs from release")
    with tarfile.open(sdist, mode="r:gz") as archive:
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
            validate_metadata(metadata)
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
        if entries != "[console_scripts]\nids-rule-converter = snort_suricata_rule_converter:main":
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
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    wheel, sdist = verify_distribution(arguments.dist_dir.resolve(), root, arguments.version)
    print(f"Verified {wheel.name} and {sdist.name}")


if __name__ == "__main__":
    main()

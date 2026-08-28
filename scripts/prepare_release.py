#!/usr/bin/env python3
"""Build deterministic IDS Rule Converter release assets."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

PROJECT_NAME = "IDS Rule Converter"
PROJECT_SLUG = "IDS-Rule-Converter"
REPOSITORY_URL = "https://github.com/fusiontechstrategies/IDS-Rule-Converter"
RUNTIME_SOURCE = "snort_suricata_rule_converter.py"
STABLE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")
BUILD_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
ARCHIVE_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

PACKAGE_FILES = (
    "CHANGELOG.md",
    "LICENSE",
    "QUICK_REFERENCE.md",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "docs/TESTING.md",
    RUNTIME_SOURCE,
)


class ReleaseError(RuntimeError):
    """Raised when release input or output violates the release contract."""


@dataclass(frozen=True)
class RuntimeIdentity:
    version: str
    build_date: str


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_runtime_identity(path: Path) -> RuntimeIdentity:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise ReleaseError(f"Unable to parse runtime identity from {path}") from exc

    values: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in {"VERSION", "BUILD_DATE"}:
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            raise ReleaseError(f"{target.id} must be a string constant")
        values[target.id] = node.value.value

    if set(values) != {"VERSION", "BUILD_DATE"}:
        raise ReleaseError("Runtime must define one VERSION and one BUILD_DATE string")
    if not STABLE_VERSION.fullmatch(values["VERSION"]):
        raise ReleaseError("Runtime VERSION must be a stable semantic version")
    if not BUILD_DATE.fullmatch(values["BUILD_DATE"]):
        raise ReleaseError("Runtime BUILD_DATE must use YYYY-MM-DD")
    return RuntimeIdentity(values["VERSION"], values["BUILD_DATE"])


def expected_asset_names(version: str) -> tuple[str, ...]:
    stem = f"{PROJECT_SLUG}-v{version}"
    return (
        f"{stem}.py",
        f"{stem}.zip",
        f"{stem}.spdx.json",
        "SHA256SUMS.txt",
        "release-evidence.json",
    )


def write_exclusive(path: Path, data: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(data)
    except FileExistsError as exc:
        raise ReleaseError(f"Refusing to replace release output: {path}") from exc


def validate_package_files(project_root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for relative_name in PACKAGE_FILES:
        relative = PurePosixPath(relative_name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in relative_name:
            raise ReleaseError(f"Unsafe package path: {relative_name}")
        source = project_root.joinpath(*relative.parts)
        if not source.is_file() or source.is_symlink():
            raise ReleaseError(f"Required regular file is missing: {relative_name}")
        files[relative_name] = source.read_bytes()
    return files


def build_zip(path: Path, version: str, files: dict[str, bytes]) -> None:
    prefix = f"{PROJECT_SLUG}-v{version}"
    try:
        with zipfile.ZipFile(
            path,
            mode="x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for relative_name in sorted(files):
                member_name = f"{prefix}/{relative_name}"
                info = zipfile.ZipInfo(member_name, ARCHIVE_TIMESTAMP)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.flag_bits |= 0x800
                archive.writestr(info, files[relative_name])
    except FileExistsError as exc:
        raise ReleaseError(f"Refusing to replace release output: {path}") from exc


def spdx_id(index: int) -> str:
    return f"SPDXRef-File-{index:03d}"


def build_spdx(version: str, identity: RuntimeIdentity, files: dict[str, bytes]) -> bytes:
    file_records = []
    file_sha1_values = []
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package",
        }
    ]

    for index, relative_name in enumerate(sorted(files), start=1):
        data = files[relative_name]
        file_id = spdx_id(index)
        sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
        file_sha1_values.append(sha1)
        file_records.append(
            {
                "SPDXID": file_id,
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": sha1},
                    {"algorithm": "SHA256", "checksumValue": sha256_bytes(data)},
                ],
                "copyrightText": "NOASSERTION",
                "fileName": f"./{relative_name}",
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )

    verification_input = "".join(sorted(file_sha1_values)).encode("ascii")
    package_verification = hashlib.sha1(verification_input, usedforsecurity=False).hexdigest()
    runtime_digest = sha256_bytes(files[RUNTIME_SOURCE])
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": f"{identity.build_date}T00:00:00Z",
            "creators": [
                "Organization: Fusion Technology Strategies",
                "Tool: scripts/prepare_release.py",
            ],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"{REPOSITORY_URL}/releases/tag/v{version}#spdx-{runtime_digest}",
        "files": file_records,
        "name": f"{PROJECT_SLUG}-v{version}",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "copyrightText": "NOASSERTION",
                "downloadLocation": f"{REPOSITORY_URL}/releases/tag/v{version}",
                "filesAnalyzed": True,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "name": PROJECT_NAME,
                "packageVerificationCode": {"packageVerificationCodeValue": package_verification},
                "supplier": "Organization: Fusion Technology Strategies",
                "versionInfo": version,
            }
        ],
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def prepare_release(
    project_root: Path, output_dir: Path, version: str, source_commit: str
) -> tuple[Path, ...]:
    if not STABLE_VERSION.fullmatch(version):
        raise ReleaseError("Release version must be a stable semantic version")
    if not COMMIT_ID.fullmatch(source_commit):
        raise ReleaseError("Source commit must be a lowercase 40-character hexadecimal ID")

    runtime_path = project_root / RUNTIME_SOURCE
    identity = read_runtime_identity(runtime_path)
    if identity.version != version:
        raise ReleaseError(
            f"Requested version {version} does not match runtime version {identity.version}"
        )

    changelog = (project_root / "CHANGELOG.md").read_text(encoding="utf-8")
    expected_heading = f"## [{version}] - {identity.build_date}"
    if expected_heading not in changelog:
        raise ReleaseError(f"Changelog is missing exact release heading: {expected_heading}")

    notes_path = project_root / ".github" / "release-notes" / f"v{version}.md"
    if not notes_path.is_file() or notes_path.is_symlink():
        raise ReleaseError(f"Release notes are missing: {notes_path.relative_to(project_root)}")

    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ReleaseError(f"Release output directory must be empty: {output_dir}")

    files = validate_package_files(project_root)
    asset_names = expected_asset_names(version)
    runtime_asset = output_dir / asset_names[0]
    zip_asset = output_dir / asset_names[1]
    spdx_asset = output_dir / asset_names[2]
    checksums_asset = output_dir / asset_names[3]
    evidence_asset = output_dir / asset_names[4]

    write_exclusive(runtime_asset, files[RUNTIME_SOURCE])
    build_zip(zip_asset, version, files)
    write_exclusive(spdx_asset, build_spdx(version, identity, files))

    primary_assets = (runtime_asset, zip_asset, spdx_asset)
    checksum_lines = [f"{sha256_file(path)}  {path.name}" for path in primary_assets]
    write_exclusive(checksums_asset, ("\n".join(checksum_lines) + "\n").encode("ascii"))

    evidence_inputs = (*primary_assets, checksums_asset)
    evidence = {
        "artifacts": [
            {"bytes": path.stat().st_size, "name": path.name, "sha256": sha256_file(path)}
            for path in evidence_inputs
        ],
        "build_date": identity.build_date,
        "expected_release_assets": list(asset_names),
        "project": PROJECT_NAME,
        "repository": REPOSITORY_URL,
        "runtime_source_sha256": sha256_bytes(files[RUNTIME_SOURCE]),
        "schema_version": 1,
        "source_commit": source_commit,
        "version": version,
        "zip_members": [f"{PROJECT_SLUG}-v{version}/{name}" for name in sorted(files)],
    }
    write_exclusive(
        evidence_asset,
        (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )

    outputs = tuple(output_dir / name for name in asset_names)
    if tuple(path.name for path in outputs) != asset_names or not all(
        path.is_file() for path in outputs
    ):
        raise ReleaseError("Release output does not match the exact asset contract")
    return outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Stable version without the v prefix")
    parser.add_argument(
        "--source-commit", required=True, help="Exact lowercase 40-character commit"
    )
    parser.add_argument("--output-dir", type=Path, required=True, help="Empty output directory")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    project_root = Path(__file__).resolve().parents[1]
    try:
        outputs = prepare_release(
            project_root, args.output_dir.resolve(), args.version, args.source_commit
        )
    except (OSError, ReleaseError, UnicodeError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"Release preparation failed: {exc}") from exc
    for output in outputs:
        print(f"{sha256_file(output)}  {output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

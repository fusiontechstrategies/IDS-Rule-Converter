"""Distribution and protected publication tampering regressions."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import test_security_regressions as fixtures

from scripts import verify_distribution, verify_release_integrity


def rewrite_wheel(path: Path, replacements: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path) as archive:
        values = {name: archive.read(name) for name in archive.namelist()}
    values.update(replacements)
    record_name = next(name for name in values if name.endswith("/RECORD"))
    output = io.StringIO()
    writer = csv.writer(output)
    for name, data in values.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow(
            [name, "", ""] if name == record_name else [name, "sha256=" + digest, len(data)]
        )
    values[record_name] = output.getvalue().encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in values.items():
            archive.writestr(name, data)


class PublicationFollowups(unittest.TestCase):
    def test_rehashed_descriptive_wheel_tampering_is_rejected(self):
        for field in ("Summary", "Author", "Project-URL", "Classifier", "Generator", "description"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                wheel, _ = fixtures.SecurityRegressions().fixture_distributions(root)
                with zipfile.ZipFile(wheel) as archive:
                    name = next(
                        name
                        for name in archive.namelist()
                        if name.endswith("/WHEEL" if field == "Generator" else "/METADATA")
                    )
                    contents = archive.read(name).decode()
                if field == "description":
                    contents += "\nMalicious replacement instructions\n"
                else:
                    lines = contents.splitlines(keepends=True)
                    index = next(
                        index for index, line in enumerate(lines) if line.startswith(field + ":")
                    )
                    lines[index] = field + ": unreviewed value\n"
                    contents = "".join(lines)
                rewrite_wheel(wheel, {name: contents.encode()})
                with self.assertRaises(ValueError):
                    verify_distribution.verify_distribution(root, fixtures.ROOT, "4.0.2")

    def test_sdist_empty_unreviewed_and_nonportable_directories_rejected(self):
        for name in ("unreviewed", "NUL", "trailing.", "name ", "a:b"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, sdist = fixtures.SecurityRegressions().fixture_distributions(root)
                with tarfile.open(sdist, "r:gz") as archive:
                    members = [(member, archive.extractfile(member).read()) for member in archive]
                with tarfile.open(sdist, "w:gz") as archive:
                    for member, data in members:
                        archive.addfile(member, io.BytesIO(data))
                    extra = tarfile.TarInfo("ids_rule_converter-4.0.2/" + name)
                    extra.type = tarfile.DIRTYPE
                    archive.addfile(extra)
                with self.assertRaises(ValueError):
                    verify_distribution.verify_distribution(root, fixtures.ROOT, "4.0.2")

    def test_copied_dist_bytes_are_bound_to_original_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel, sdist = fixtures.SecurityRegressions().fixture_distributions(root)
            expected = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (wheel, sdist)}
            verify_release_integrity.verify_distributions(root, expected)
            wheel.write_bytes(b"synthetic replacement")
            with self.assertRaisesRegex(ValueError, "attested original"):
                verify_release_integrity.verify_distributions(root, expected)

    def test_publication_rechecks_changed_tag_release_and_main_after_approval(self):
        workflow = (fixtures.ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
        step = workflow.split(
            "- name: Recheck publication authorization after environment approval", 1
        )[1]
        inline = step.split("python -I - <<'PY'", 1)[1].split("\n          PY", 1)[0]
        code = "\n".join(
            line[10:] if line.startswith("          ") else line for line in inline.splitlines()
        )
        commit = "a" * 40
        environment = {
            "GH_REPO": "owner/repo",
            "RELEASE_TAG": "v4.0.2",
            "VERIFIED_COMMIT": commit,
            "VERIFIED_RELEASE_ID": "123",
        }
        for mutation in (None, "tag", "signature", "main", "release", "draft", "prerelease"):
            with self.subTest(mutation=mutation):

                def response(arguments, mutation=mutation, **kwargs):
                    self.assertEqual(arguments[:2], ["gh", "api"])
                    endpoint = arguments[2]
                    if "git/ref/" in endpoint:
                        value = {
                            "object": {
                                "type": "commit",
                                "sha": "b" * 40 if mutation == "tag" else commit,
                            }
                        }
                    elif "/commits/" in endpoint:
                        value = {"commit": {"verification": {"verified": mutation != "signature"}}}
                    elif "/compare/" in endpoint:
                        value = {"status": "diverged" if mutation == "main" else "ahead"}
                    else:
                        value = {
                            "id": 124 if mutation == "release" else 123,
                            "tag_name": "v4.0.2",
                            "draft": mutation == "draft",
                            "prerelease": mutation == "prerelease",
                        }
                    return json.dumps(value)

                with (
                    patch.dict(os.environ, environment),
                    patch.object(subprocess, "check_output", side_effect=response),
                ):
                    if mutation is None:
                        exec(compile(code, "publication-authorization", "exec"), {})  # noqa: S102
                    else:
                        with self.assertRaises(AssertionError):
                            exec(compile(code, "publication-authorization", "exec"), {})  # noqa: S102

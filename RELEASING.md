# Release process

IDS Rule Converter releases are built from a verified commit on protected `main`. The runtime remains a single standard-library Python file, while the release also carries the license, operator documentation, checksums, an SPDX SBOM, release evidence, and GitHub provenance.

## Release boundaries

- A pull request must pass the complete CI, native-engine, dependency, CodeQL, Semgrep, Trivy, and Gitleaks gates.
- The merge commit must be GitHub-verified and present on protected `main`.
- The runtime `VERSION`, `BUILD_DATE`, changelog heading, and versioned release-notes file must agree.
- Candidate builds must produce the exact seven-asset set documented below.
- A tag push builds a read-only candidate. A separate protected-main promotion workflow may create an approved draft. Neither publishes the release.
- Release publication requires a separate maintainer review in GitHub.
- Existing release assets are never replaced. A failed draft must be investigated and removed before a clean rerun.

## Exact asset contract

For version `X.Y.Z`, the release contains only:

1. `IDS-Rule-Converter-vX.Y.Z.py`
2. `IDS-Rule-Converter-vX.Y.Z.zip`
3. `ids_rule_converter-X.Y.Z-py3-none-any.whl`
4. `ids_rule_converter-X.Y.Z.tar.gz`
5. `IDS-Rule-Converter-vX.Y.Z.spdx.json`
6. `SHA256SUMS.txt`
7. `release-evidence.json`

The standalone asset is byte-identical to `snort_suricata_rule_converter.py` in the tagged commit. The ZIP is deterministic and contains the runtime, license, changelog, quick reference, README, security policy, support policy, and testing record under one versioned directory. All archive paths are fixed, relative, and portable.

`SHA256SUMS.txt` covers the standalone runtime, ZIP, wheel, source archive, and SBOM. `release-evidence.json` binds those files and the checksum file to the exact source commit. Every release asset receives a GitHub artifact-provenance attestation.

## Candidate verification

From the repository root, use an empty output directory:

```powershell
$commit = git rev-parse HEAD
$epoch = git show -s --format=%ct HEAD
$env:SOURCE_DATE_EPOCH = $epoch
python -m pip install -r requirements-build.txt
python -m build --no-isolation --wheel --sdist --outdir package-dist
python scripts/normalize_wheel.py --source-date-epoch $epoch package-dist/ids_rule_converter-4.0.2-py3-none-any.whl
python scripts/normalize_sdist.py --source-date-epoch $epoch package-dist/ids_rule_converter-4.0.2.tar.gz
python scripts/verify_distribution.py package-dist --version 4.0.2
python -m twine check package-dist/*
python scripts/prepare_release.py `
  --version 4.0.2 `
  --source-commit $commit `
  --dist-dir .\package-dist `
  --output-dir .\candidate
```

Run the command twice into separate empty directories and require identical bytes for all seven files. CI also builds the wheel and source archive twice and compares their normalized bytes on every pull request and protected-branch push.

Before tagging, require:

- 66 tests pass on the exact candidate tree (one optional third-party corpus test is skipped locally)
- the complete hosted platform matrix passes
- both native-engine fixture directions pass
- formatting, linting, Bandit, dependency audit, CodeQL, Semgrep, Trivy, and Gitleaks pass
- zero open code-scanning, Dependabot, or secret-scanning alerts
- the release notes and testing record remain accurate
- the release commit is verified and reachable from protected `main`

## Draft creation

Tag creation is a maintainer-controlled release action and requires explicit approval. The tag must be `vX.Y.Z` and must resolve to the approved protected-main commit.

Pushing the tag starts `.github/workflows/release.yml`. The read-only workflow:

1. Resolves the tag to its exact commit.
2. Confirms the commit is reachable from `main` and has a valid GitHub verification record.
3. Rebuilds the exact seven assets from source.
4. Verifies the candidate on another read-only runner and uploads the immutable seven-file handoff.

On successful completion, `.github/workflows/release-promotion.yml` executes
from protected `main`. It authenticates the producer API run and its exact
artifact ID, pins a signed protected-main verification commit, and reads tagged
source strictly as data. Trusted helpers independently verify the wheel/source
archive and reconstruct every release subject. Tagged helper code never runs
in jobs with OIDC, attestation or release-write permission.

The main-only `release` environment requires a maintainer reviewer for both
privileged jobs. Each repeats reconstruction before acting. Uploaded draft
assets are downloaded and compared against the verified manifest. An explicitly
authorized repository administrator can bypass environment approval;
administrators and protected-main reviewers remain trusted operators.

Attestations identify the protected-main promotion workflow and source ref.
Selected-tag source identity remains separately bound by the exact runtime,
distribution contents and reconstructed release evidence. The PyPI workflow
requires this promotion provenance and retains its protected-main verifier.

The workflow has no manual trigger and contains no publication command.

## Publication review

Before publishing the draft:

- confirm the tag and draft target the approved commit
- download all seven assets into a clean directory
- compare every digest with the workflow evidence
- verify the standalone file is byte-identical to the tagged runtime
- inspect the ZIP member list and extract it into a new directory
- install the wheel and source archive separately in clean environments and run the CLI smoke commands
- run `--version`, `--help`, a native `validate`, and a strict synthetic conversion from the downloaded runtime
- verify the GitHub attestations
- confirm the release notes state the current validation and residual limits accurately

Publish only after every check passes. After publication, repeat the download and verification against the public URLs, then record the metrics baseline without treating automated downloads as users.

## PyPI publication

The manually dispatched `.github/workflows/publish.yml` accepts an existing public, non-prerelease GitHub release tag. Its verification job checks the protected-main ancestry and GitHub commit verification, exact seven-asset release set, SHA-256 manifest, release evidence, distribution contents, runtime source match, and GitHub provenance for every asset. Only the verified wheel and source archive are transferred to the separate upload job.

The upload job uses a protected `pypi` environment and PyPI trusted publishing with a short-lived OpenID Connect credential. No PyPI API token belongs in repository secrets. Before the first upload, confirm that `ids-rule-converter` is available on PyPI, configure the exact `fusiontechstrategies/IDS-Rule-Converter` repository, `publish.yml` workflow, and `pypi` environment as a pending trusted publisher, and require maintainer approval for the GitHub environment. Review the verification job before approving the upload. After publication, compare PyPI wheel and source hashes with the GitHub assets and run the installed CLI from a clean environment.

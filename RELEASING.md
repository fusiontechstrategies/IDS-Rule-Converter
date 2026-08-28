# Release process

IDS Rule Converter releases are built from a verified commit on protected `main`. The runtime remains a single standard-library Python file, while the release also carries the license, operator documentation, checksums, an SPDX SBOM, release evidence, and GitHub provenance.

## Release boundaries

- A pull request must pass the complete CI, native-engine, dependency, CodeQL, Semgrep, Trivy, and Gitleaks gates.
- The merge commit must be GitHub-verified and present on protected `main`.
- The runtime `VERSION`, `BUILD_DATE`, changelog heading, and versioned release-notes file must agree.
- Candidate builds must produce the exact five-asset set documented below.
- A tag push may create a draft GitHub release. It cannot publish the release.
- Release publication requires a separate maintainer review in GitHub.
- Existing release assets are never replaced. A failed draft must be investigated and removed before a clean rerun.

## Exact asset contract

For version `X.Y.Z`, the release contains only:

1. `IDS-Rule-Converter-vX.Y.Z.py`
2. `IDS-Rule-Converter-vX.Y.Z.zip`
3. `IDS-Rule-Converter-vX.Y.Z.spdx.json`
4. `SHA256SUMS.txt`
5. `release-evidence.json`

The standalone asset is byte-identical to `snort_suricata_rule_converter.py` in the tagged commit. The ZIP is deterministic and contains the runtime, license, changelog, quick reference, README, security policy, support policy, and testing record under one versioned directory. All archive paths are fixed, relative, and portable.

`SHA256SUMS.txt` covers the standalone runtime, ZIP, and SBOM. `release-evidence.json` binds those files and the checksum file to the exact source commit. Every release asset receives a GitHub artifact-provenance attestation.

## Candidate verification

From the repository root, use an empty output directory:

```powershell
$commit = git rev-parse HEAD
python scripts/prepare_release.py `
  --version 4.0.1 `
  --source-commit $commit `
  --output-dir .\candidate
```

Run the command twice into separate empty directories and require identical bytes for all five files. CI performs that comparison on every pull request and protected-branch push.

Before tagging, require:

- 64 tests pass on the exact candidate tree
- the complete hosted platform matrix passes
- both native-engine fixture directions pass
- formatting, linting, Bandit, dependency audit, CodeQL, Semgrep, Trivy, and Gitleaks pass
- zero open code-scanning, Dependabot, or secret-scanning alerts
- the release notes and testing record remain accurate
- the release commit is verified and reachable from protected `main`

## Draft creation

Tag creation is a maintainer-controlled release action and requires explicit approval. The tag must be `vX.Y.Z` and must resolve to the approved protected-main commit.

Pushing the tag starts `.github/workflows/release.yml`. The workflow:

1. Resolves the tag to its exact commit.
2. Confirms the commit is reachable from `main` and has a valid GitHub verification record.
3. Rebuilds the exact five assets from source.
4. Creates GitHub provenance attestations for all five files.
5. Refuses to continue if a release with the same tag already exists.
6. Creates a draft GitHub release with the committed versioned notes.
7. Confirms the draft contains exactly the expected assets.

The workflow has no manual trigger and contains no publication command.

## Publication review

Before publishing the draft:

- confirm the tag and draft target the approved commit
- download all five assets into a clean directory
- compare every digest with the workflow evidence
- verify the standalone file is byte-identical to the tagged runtime
- inspect the ZIP member list and extract it into a new directory
- run `--version`, `--help`, a native `validate`, and a strict synthetic conversion from the downloaded runtime
- verify the GitHub attestations
- confirm the release notes state the current validation and residual limits accurately

Publish only after every check passes. After publication, repeat the download and verification against the public URLs, then record the metrics baseline without treating automated downloads as users.

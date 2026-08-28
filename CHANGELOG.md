# Changelog

All notable changes to this project are documented here.

The format follows Keep a Changelog, and versions follow Semantic Versioning.

## [Unreleased]

## [4.0.1] - 2026-08-28

### Changed

- Added scheduled CodeQL, Semgrep, Gitleaks, Trivy, Bandit, and dependency audits
- Added staggered Dependabot schedules and update cooldowns
- Added immutable checkout settings and weekly native-engine validation
- Added deterministic standalone, ZIP, SPDX 2.3 SBOM, checksum, and release-evidence assets
- Added a tag-only workflow that creates a draft GitHub release with provenance attestations

### Security

- Prevented a race from replacing a newly created output when `--force` is absent
- Rejected feed URLs and redirects containing credentials or nonstandard HTTPS ports
- Added regression tests for output races and stricter feed URL validation
- Required repeatable release artifacts bound to the exact source commit

## [4.0.0] - 2026-08-12

### Added

- Loss-aware ordered parser for Snort 2, Snort 3, and Suricata rules
- Strict, fail-safe conversion with explicit partial and unverified modes
- Verified buffer, service, protocol, SIP, fast-pattern, tag, and stream-size
  transformations
- JSON and SARIF validation output
- Ruleset inventory, duplicate detection, conflict detection, and semantic diff
- Panorama IPS Signature Converter 2.0.4 offline preflight and safe batching
- Allowlisted Cisco Talos feed retrieval with hardened TAR and ZIP extraction
- Atomic output, overwrite refusal, input replacement protection, and size limits
- Automated tests and native Snort 3.10.0.0 and Suricata 8.0.6 validation
- Repository security policy, contribution guidance, CI, and maintenance files

### Changed

- Rebuilt the runtime as a portable standard-library-only Python script
- Made unknown or unsafe target semantics blocking by default
- Replaced outdated text guidance with Markdown documentation

### Security

- Removed unsafe archive extraction behavior
- Restricted feed downloads and redirects to HTTPS allowlists
- Added traversal, link, special-file, duplicate-path, device-name, encryption,
  entry-count, file-size, and expanded-size defenses
- Prevented accidental replacement of source input files

[4.0.1]: https://github.com/fusiontechstrategies/IDS-Rule-Converter/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/fusiontechstrategies/IDS-Rule-Converter/releases/tag/v4.0.0
[Unreleased]: https://github.com/fusiontechstrategies/IDS-Rule-Converter/compare/v4.0.1...HEAD

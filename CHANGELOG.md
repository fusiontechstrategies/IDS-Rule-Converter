# Changelog

All notable changes to this project are documented here.

The format follows Keep a Changelog, and versions follow Semantic Versioning.

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

[4.0.0]: https://github.com/fusiontechstrategies/IDS-Rule-Converter/releases/tag/v4.0.0

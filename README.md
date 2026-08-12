# IDS Rule Converter

Stop guessing whether a converted IDS rule still means the same thing.

IDS Rule Converter is a secure, loss-aware, one-file Python toolkit for parsing,
validating, analyzing, comparing, and converting Snort and Suricata rules. It
defaults to refusing uncertain translations instead of silently dropping or
weakening detection logic.

The runtime has no third-party Python dependencies. Copy
`snort_suricata_rule_converter.py` to a system with Python 3.10 or newer and run
it directly.

## Why this tool is different

Rule conversion is not a keyword replacement problem. Sticky buffers, content
modifier placement, service declarations, application protocols, regular
expressions, and engine-specific actions all affect detection behavior.

IDS Rule Converter provides:

- Ordered parsing that preserves repeated options and content modifier context
- Strict, fail-safe conversion between Snort 2, Snort 3, and Suricata 8
- Explicit rejection files and machine-readable reports for unsafe rules
- Native JSON and SARIF output for automation and code scanning systems
- Duplicate SID, conflicting SID, keyword, protocol, and action analysis
- Semantic ruleset comparison by GID, SID, revision, and fingerprint
- Offline Panorama IPS Signature Converter 2.0.4 compatibility preflight
- Safe download support for allowlisted Cisco Talos community feeds
- Archive defenses against traversal, links, special files, duplicate paths,
  encrypted ZIP entries, Windows device names, and decompression abuse
- Atomic output writes, overwrite refusal, and input replacement protection
- No telemetry and no implicit network access

## Quick start

```text
python snort_suricata_rule_converter.py --help
python snort_suricata_rule_converter.py validate input.rules
python snort_suricata_rule_converter.py analyze input.rules --output analysis.json
```

Convert a Snort 3 ruleset to Suricata. Strict mode is the default, so no ruleset
is written if any rule has an unsafe or unverified mapping.

```text
python snort_suricata_rule_converter.py convert input.rules --source-dialect snort3 --target suricata --output converted.rules --report conversion.json
```

To export only the verified subset, preserve every rejected source rule, and
receive a detailed report:

```text
python snort_suricata_rule_converter.py convert input.rules --source-dialect snort3 --target suricata --output accepted.rules --allow-partial --rejected-output rejected.rules --report conversion.json
```

An intentional partial result exits with code 2 so automation cannot mistake it
for a complete conversion.

## Commands

| Command | Purpose |
| --- | --- |
| `validate` | Parse rules and report structural or identifier problems |
| `analyze` | Inventory rules, keywords, actions, protocols, duplicates, and conflicts |
| `convert` | Convert to Snort 2, Snort 3, Suricata, or structured JSON |
| `panorama-preflight` | Check and batch rules for Panorama plugin 2.0.4 |
| `diff` | Compare two rulesets by GID and SID |
| `list-sources` | Show built-in HTTPS feed definitions |
| `fetch` | Download and optionally extract an allowlisted rule feed safely |

See [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for copy-ready examples.

## Conversion safety model

The default behavior is intentionally conservative:

1. The complete input must parse successfully.
2. Each rule is checked against the declared target dialect.
3. Verified transformations preserve option order and buffer context.
4. A rule with an unsafe mapping is rejected, not approximated.
5. Strict conversion writes nothing when any rule is rejected.
6. Partial conversion requires both a rejection file and a JSON report.
7. Unknown target keywords require the explicit `--allow-unverified` opt-out.

Important verified transformations include Snort 3 and Suricata HTTP sticky
buffers, Snort 2 HTTP content modifiers, safe service mappings, TLS protocol
naming, selected SIP options, `bufferlen` to `bsize`, `stream_size` syntax,
fast-pattern offsets, and compatible tag syntax.

The converter rejects ambiguous multi-service rules, unsupported target actions,
conflicting application protocols, unsafe buffer arguments, packet and
application-layer conflicts, unsupported BER and DCE options, and other cases
where equivalence has not been established.

Always run the target engine's native configuration test before deployment.
Successful parsing proves that an engine accepts a rule. It does not prove that
every rule will detect identical traffic under every engine configuration.

## Panorama preflight

The Panorama command performs an offline compatibility review for IPS Signature
Converter plugin 2.0.4. It checks documented action, protocol, condition, PCRE,
threshold, reference, case-sensitivity, negation, and positional limits. Accepted
source rules are divided into batches of no more than 100 rules and 8 MB.

```text
python snort_suricata_rule_converter.py panorama-preflight input.rules --output-dir panorama-review
```

The tool never connects to Panorama and never uploads a rule.

## Safe feed retrieval

Network access occurs only when `fetch` is explicitly invoked. Built-in sources
use HTTPS and an exact hostname allowlist. Redirects outside that allowlist are
refused.

```text
python snort_suricata_rule_converter.py list-sources
python snort_suricata_rule_converter.py fetch --source snort3-community --output-dir downloads --extract
```

The downloaded archive, SHA-256 metadata, and extracted files are local outputs.
Rules remain subject to their provider's terms and are not part of this project's
Apache 2.0 license.

## Test evidence

Version 4.0.0 was validated on August 12, 2026 with:

- 56 automated tests covering parsing, conversion, reports, Panorama checks,
  overwrite controls, redirect policy, and malicious archive cases
- Python 3.12 and 3.13 on Windows, plus Python 3.14 in an isolated Linux container
- Snort 3.10.0.0 native configuration validation in an isolated container
- Suricata 8.0.6 native configuration validation in an isolated container
- A 4,017-rule Cisco Talos Snort 3 community corpus round trip accepted by Snort
  with zero warnings
- A fail-safe Suricata conversion that accepted 3,762 rules and rejected 255
  rules with recorded reasons
- Native Suricata validation of all 3,762 accepted rules with zero errors

The Suricata engine emitted 71 nonfatal duplicate-buffer warnings for source
patterns that intentionally revisit an earlier sticky buffer. Full commands,
container digests, and test scope are recorded in [docs/TESTING.md](docs/TESTING.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Operation completed without blocking findings |
| `1` | Operational failure, unsafe path, network failure, or invalid invocation |
| `2` | Validation findings, conflicts, rejected rules, or an intentional partial result |
| `130` | Interrupted by the operator |

## Development

```text
python -m pip install -r requirements-dev.txt
python -m ruff format --check .
python -m ruff check .
python -m bandit -q -r snort_suricata_rule_converter.py
python -m pip_audit -r requirements-dev.txt
python -m unittest discover -s tests -v
```

The production runtime remains one file. Tests, documentation, and repository
automation are separate so the executable itself stays portable.

## Security and privacy

- Rule files are processed locally.
- The tool contains no credentials, tokens, account IDs, or environment-specific
  resource names.
- Output files are UTF-8 and written atomically.
- Existing outputs are refused unless `--force` is supplied.
- `--force` cannot replace an input file.
- Report suspected vulnerabilities through the private process in
  [SECURITY.md](SECURITY.md).

## License

The converter, tests, and project documentation are licensed under the Apache
License 2.0. Third-party rules, vendor documents, and downloaded feeds are not
redistributed by this repository and retain their original terms.

Snort is a registered trademark of Cisco. Suricata is a registered trademark of
the Open Information Security Foundation. This project is independent and is not
endorsed by either organization.

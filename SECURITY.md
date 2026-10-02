# Security Policy

## Supported versions

Security fixes are applied to the current 4.x release line.

| Version | Supported |
| --- | --- |
| 4.x | Yes |
| Earlier versions | No |

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a regular issue, discussion, pull
request, or public message.

Use the repository's GitHub Security Advisory reporting feature:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.
4. Include the affected version, reproduction steps, impact, and any proposed
   mitigation.

If private vulnerability reporting is temporarily unavailable, email
jeff@fusiontsi.com and request a private reporting channel. Do not include
exploit details in that initial message.

Reports will be acknowledged as soon as practical. Confirmed issues will be
triaged based on exploitability, data exposure, integrity impact, and deployment
risk. Please allow time for a fix and coordinated disclosure before publishing
details.

## Security design

The runtime is standard-library only and has no telemetry. Network access occurs
only through the explicit `fetch` command. Feed hosts and HTTPS redirects are
allowlisted, downloads and extraction are bounded, archive paths are validated,
and outputs are written atomically.

Converted rules are untrusted configuration data. Validate them with the target
engine and review rejected or unverified mappings before deployment.

Malformed block comments and invalid inline content modifiers stop conversion.
Strict conversion rejects field-specific buffers when the target cannot preserve
their meaning. Source filenames are JSON-escaped inside generated comments.

Output leaf links and reparse points are rejected even with `--force`. POSIX
publication uses a pinned directory descriptor and requires an owner-controlled
parent. Extraction roots cannot be links; fetch uses an exclusively created
extraction directory. TAR parsing bounds entries, declared file sizes,
decompressed stream bytes, extension metadata, and extension chains before
materializing the full member list. Sparse archives are unsupported.

Release builds have read-only repository permissions and use fully hash-locked
build dependencies. A separate clean runner verifies exact wheel and source
archive installation manifests and correspondence with reviewed source. Only
verified immutable artifacts reach the attestation and draft-release job.
Privileged verification uses Python isolated mode. Source review and signed
commit validation remain necessary; releases stay drafts for explicit approval.

## Out of scope

- Vulnerabilities in Snort, Suricata, Panorama, Python, Docker, or GitHub
- Third-party rule content and vendor feeds
- Findings that require disabling documented safety controls
- Social engineering, denial of service against maintainers, or destructive
  testing

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
# Output and release boundaries

Reports and extracted rules require a trusted output path. On Windows, the converter reads the owner and DACL through retained directory handles and refuses other principals' mutation rights in the caller's directory or ancestry. It never rewrites existing caller directory permissions. SYSTEM, Administrators and TrustedInstaller are part of the local operating-system trust boundary. Unsupported permission ACEs are refused conservatively; a deny ACE does not cancel an otherwise unsafe allow in this inspection. Shared writable locations can therefore be rejected even when an individual output file has a private DACL.

POSIX output paths reject unsafe, non-sticky writable ancestors as well as unsafe leaves. Protected sticky temporary directories remain supported. ZIP rule feeds accept stored or deflated entries only, and extraction independently bounds streamed decoded bytes and their declared lengths.

Panorama runs refuse a reused directory with recognized artifacts outside the new generation, including old higher-numbered batches or a stale rejected-rules file. Choose a fresh output directory. The manifest is published last and binds every current report and rules batch with SHA-256; consumers must verify that manifest before using a generation.

Distribution verification limits compressed bytes, expanded bytes, member sizes, counts and metadata before materialization. ZIP64 wheels are refused, including locators preceding maximum-length end-record comments. PyPI publication uses a captured, signed protected-main verification revision and requires the protected-main deployment environment. Tag race closure additionally depends on the active GitHub rule preventing updates and deletion of version tags without bypass actors. Sequential API checks alone are not an atomic authorization boundary.

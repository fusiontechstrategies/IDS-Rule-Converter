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

## Out of scope

- Vulnerabilities in Snort, Suricata, Panorama, Python, Docker, or GitHub
- Third-party rule content and vendor feeds
- Findings that require disabling documented safety controls
- Social engineering, denial of service against maintainers, or destructive
  testing

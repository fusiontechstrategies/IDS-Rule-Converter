# Testing Record

This document records the release-readiness model for IDS Rule Converter 4.0.1
and preserves the separate large-corpus baseline completed for 4.0.0.

## Automated test suite

The standard-library `unittest` suite contains 64 tests covering:

- Multiline, multiple-rule, comment, quoted delimiter, and headerless parsing
- Strict UTF-8 input and NUL-byte rejection
- SID, GID, revision, and required option validation
- Snort 2, Snort 3, and Suricata buffer transformations
- Service, protocol, action, fast-pattern, tag, SIP, BER, and stream-size cases
- Strict rejection and explicit unverified-keyword behavior
- Semantic fingerprints, duplicate SID detection, SID conflicts, and ruleset diff
- JSON and SARIF output
- Panorama plugin 2.0.4 limits and behavior checks
- Atomic writes, overwrite refusal, and input replacement prevention
- TAR and ZIP traversal, links, duplicate paths, device paths, and safe extraction
- HTTPS redirect allowlisting
- Feed URL credential and port restrictions
- Repository punctuation policy
- Exact, deterministic release assets, checksums, SPDX metadata, and evidence

The candidate suite runs in hosted CI on Linux with Python 3.10 through 3.14 and
on Windows and macOS with Python 3.12. The optional local third-party corpus test
is skipped because its vendor-owned inputs are deliberately not stored in Git.

Python 3.14 image:

```text
python@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4
```

## 4.0.1 native fixture validation

Every pull request and protected-main push converts the committed Snort 3 fixture
to Suricata and the committed Suricata fixture to Snort 3. Both original fixtures
and both generated outputs must pass the applicable native configuration test.

The containers run without a network, with all Linux capabilities dropped, and
with the no-new-privileges security option. Suricata runs as its non-root
`suricata` user.

## 4.0.0 large-corpus Snort validation

Engine image:

```text
ciscotalos/snort3@sha256:f15f714fd61ade114b1039687dd43352cae26cd6401b89f2b03404e0d21e322f
```

Reported engine version: Snort 3.10.0.0.

The official Cisco Talos Snort 3 community file contained 4,017 source rules.
The converter parsed and rendered all 4,017 rules as Snort 3 without rejection.
The rendered corpus passed `snort -T` with zero warnings. The engine reported
4,236 total loaded rules because its standard configuration also loads built-in
file identification rules.

The test container used no network, dropped all Linux capabilities, and enabled
the no-new-privileges security option.

## 4.0.0 large-corpus Suricata validation

Engine image:

```text
jasonish/suricata@sha256:581dca6c8cc8a8a2fafd3fff33368573b547b7600a22b21a18866da05727508f
```

Reported engine version: Suricata 8.0.6.

Strict compatibility analysis of the same 4,017-rule source corpus produced:

- 3,762 accepted Suricata rules
- 255 rejected source rules
- Zero unverified keywords in the accepted set
- A rejection file containing every excluded source rule
- A JSON report containing the reason and source location for each finding

All 3,762 accepted rules passed Suricata's `-T` configuration test with zero
errors. Suricata emitted 71 nonfatal duplicate-buffer warnings where converted
rules intentionally returned to a previously used sticky buffer.

The stock Suricata configuration was supplied `SIP_SERVERS=any` for the native
test because that Snort variable is referenced by the source corpus and is not
defined by the stock Suricata image.

The test container used no network, dropped all Linux capabilities, enabled the
no-new-privileges security option, and ran as the image's `suricata` user.

## What the engine tests establish

The native configuration tests establish that the engines parse and accept the
rendered rules under the recorded versions and configuration. They do not claim
packet-by-packet behavioral equivalence across every engine configuration. A
converted ruleset must still be tested with the intended target configuration
before deployment.

Third-party test corpora and vendor documents are deliberately excluded from Git
and remain subject to their owners' terms.

## Release construction

The candidate builder runs twice from the exact source commit. All five outputs
must be byte-identical across both builds:

- exact standalone runtime
- deterministic documentation ZIP
- SPDX 2.3 SBOM
- SHA-256 checksum file
- machine-readable release evidence

The builder refuses a version mismatch, malformed commit identity, missing
package file, missing versioned release notes, changelog mismatch, nonempty output
directory, or attempted output replacement. Tests verify archive membership,
portable relative paths, fixed timestamps, source-byte identity, checksums, SPDX
identity, and evidence binding.

The tag-only release workflow also requires the tag commit to be reachable from
protected `main` and GitHub-verified. It creates provenance attestations and a
draft release, then verifies the exact five-asset set. Publication remains a
separate maintainer action.

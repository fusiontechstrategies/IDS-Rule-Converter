# Testing Record

This document records the validation performed for IDS Rule Converter 4.0.0 on
August 12, 2026.

## Automated test suite

The standard-library `unittest` suite contains 56 tests covering:

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

The suite passed on Windows with Python 3.12 and 3.13. It also passed in an
isolated Python 3.14 Linux container. The optional local third-party corpus test
was skipped in that Python 3.14 container because ignored local references were
not copied into it.

Python 3.14 image:

```text
python@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4
```

## Snort native validation

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

## Suricata native validation

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

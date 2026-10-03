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

Reports and extracted rules require a trusted output path. On Windows, the converter reads the owner and DACL through retained directory handles and refuses other principals' mutation rights in the caller's directory or ancestry. It never rewrites existing caller directory permissions. SYSTEM, Administrators and TrustedInstaller are part of the local operating-system trust boundary. OWNER RIGHTS is interpreted only after validating the actual owner. Canonical physical volume roots are recognized by their exact volume-GUID handle path and still refuse child-deletion and ACL/owner-control rights; ordinary ancestors retain full mutation checks. Subst aliases resolving to regular directories and UNC paths receive no volume-root exemption. Unsupported permission ACEs are refused conservatively; a deny ACE does not cancel an otherwise unsafe allow in this inspection. Shared writable locations can therefore be rejected even when an individual output file has a private DACL.

POSIX output paths reject unsafe, non-sticky writable ancestors as well as unsafe leaves. Protected sticky temporary directories remain supported. ZIP rule feeds accept stored or deflated entries only, and extraction independently bounds streamed decoded bytes and their declared lengths.

Panorama runs refuse a reused directory with recognized artifacts outside the new generation, including old higher-numbered batches or a stale rejected-rules file. Choose a fresh output directory. The manifest is published last and binds every current report and rules batch with SHA-256; consumers must verify that manifest before using a generation.

Distribution verification limits compressed bytes, expanded bytes, member sizes, counts and metadata before materialization. ZIP64 wheels are refused, including locators preceding maximum-length end-record comments. PyPI publication uses a captured, signed protected-main verification revision and requires the protected-main deployment environment. Tag race closure additionally depends on the active GitHub rule preventing updates and deletion of version tags without bypass actors. Sequential API checks alone are not an atomic authorization boundary.

Tag release builds are read-only. A default-branch promotion workflow authenticates
the producer run and immutable artifact ID, then independently verifies package
contents and reconstructs all seven subjects with protected-main helpers. Tagged
helpers are data and never run in attestation/write jobs. Each privileged job
requires the main-only release environment and repeats subject verification.
The required reviewer can be explicitly bypassed by an authorized administrator,
which remains part of the repository's trusted operator boundary.

SIP shorthand conversion restores the previous payload buffer after the generated
SIP match. Rules combining these shorthands with relative payload cursors are
refused because switching buffers cannot safely preserve that cursor, including
relative `isdataat`, Base64 decoding and ASN.1 offsets. A modifier separated from
its source pattern by SIP shorthand is also refused, including standalone `replace`.
Snort 2 sticky payload contexts remain independent from backward content modifiers,
including auto-detected `file_data` and the decoded Base64 buffer. Every
one-shot backward content group restores the source payload context before any
later non-modifier, including actual Base64 decoding and buffer-size tests.
Cursor provenance remains independent from buffer selection across flow, metadata
and other intervening options. Generated restoration cannot recover an earlier
pattern cursor. Relative consumers and relative content are refused until a real
positive content match or explicit source buffer selection establishes a safe
cursor; a negative match does not establish one. All refusals apply in strict,
non-strict and direct rendering paths. Direct rendering also refuses unsupported
relative, negated, empty or inclusive-range bufferlen mappings to bsize. Public
and direct paths share one bounded numeric mapping: absolute values from 0 to
65535, supported comparisons and ascending exclusive ranges. Tabs and newlines
cannot hide a relative qualifier. This follows the [Snort bufferlen grammar](https://docs.snort.org/rules/options/payload/bufferlen)
and [Suricata bsize grammar](https://docs.suricata.io/en/suricata-8.0.7/rules/payload-keywords.html#bsize).
Every
unquoted option semicolon is a delimiter, including inside brackets or parentheses.
Quoted content remains intact. Panorama writes no batches or completion manifest
when any input record fails parsing.

Modern-buffer downgrades to Snort 2 use the same checked buffer/cursor state in
batch and direct rendering. Decoded Base64, DCE stub, file, packet and raw payload selections
clear earlier HTTP content modifiers. A removed HTTP selector cannot restore an
earlier cursor. Relative content requires a preserved cursor in the same buffer;
a new positive absolute match establishes one, while a negative match does not.
For this downgrade, buffer selection alone never establishes a match cursor.
Content modifiers after an intervening selector are refused, including modifiers
separated from the selector by flow or metadata options. Shared explicit selectors
also retain their buffer identity when restoring payload after backward HTTP
modifiers or generated SIP matches. DCE selection resets the cursor to the stub
buffer start; it cannot inherit an earlier packet match. See the
[DCE buffer semantics](https://docs.snort.org/rules/options/payload/dce).
Snort 3 BER cursor operations have no verified Snort 2 mapping and are refused
in strict, non-strict and direct downgrades. Native Snort 3 use remains supported.
See the [BER option semantics](https://docs.snort.org/rules/options/payload/ber).
Relative content modifiers retain the cursor provenance that existed before their
own content match, including when flow or metadata intervenes. A modifier cannot
use a cursor created by the same content it modifies. Reverse Snort 2 restoration
applies the same check and refuses generated buffer switches that lose that cursor.
Non-content payload operations under a backward-only HTTP buffer are refused.
Valid consecutive content matches in one buffer remain supported. See the
[Snort HTTP buffer distinction](https://docs.snort.org/rules/options/payload/http/)
and [relative content semantics](https://docs.snort.org/rules/options/payload/oddw).
Direct rendering enforces all known hard compatibility errors. Non-strict unknown
keywords remain preserved for explicit native-engine review. SIP method/status
value validation is shared by direct transformation and batch conversion.

SARIF locations percent-encode filenames as URI identities, including spaces,
reserved characters, Unicode, Windows drive paths and UNC shares. Relative paths
remain relative, with literal percent signs encoded rather than reinterpreted.

Feed redirects never drain intermediate entities. Every hop must remain on an
allowlisted HTTPS host, within repeat/hop limits and the shared 30-second request
deadline. Final-response reads remain byte-bounded and check that same deadline
before and after each read; a blocking operation is also subject to its socket
timeout. ZIP helpers preflight the end record and actual central-directory records
before allocating member objects. Inputs are limited to 64 MiB, directory metadata
to 8 MiB and entries to 20,000. Counts, offsets and parser readback must agree.
Single-disk conventional ZIP and fixed-size ZIP64 end records are supported;
central member disk-start fields must be zero (extended disk-start fields are
unsupported). Multi-disk/extensible ZIP64, trailing data and malformed metadata
are refused. Each resolved member offset must identify a complete bounded local
header. Local/central flags, compression and names must agree, and the standard
reader's overlap check must pass. Header validation closes each member without
reading or decompressing its entity.
Existing extraction size, decoder, path and object-count limits still apply.

File parsing checks the actual opened descriptor against the named file, requires
a regular bounded stable snapshot, and retains its path and device/inode identity
for provenance and output protection. Output commands never resolve the original
input alias again. They reject hardlink, case and Unicode-normalization aliases and
recheck input identity immediately before forced replacement in a trusted output
directory. Case/Unicode spelling checks are deliberately conservative even on a
case-sensitive filesystem. Concurrent mutation by the same trusted user is outside
the output-directory isolation guarantee; detected changes fail closed.

Windows input admission uses GENERIC_READ with FILE_SHARE_READ only and rejects
reparse/directory/special leaves. Native sharing refuses existing data writers
and writable mappings and excludes new write/delete opens while the descriptor
is retained. Attribute-only writes are not excluded by these sharing flags;
metadata consistency checks remain in place. Every accepted file snapshot also
retains a SHA-256 of its exact raw bytes, propagated to machine reports and
generated provenance. POSIX retains descriptor/identity/size/timestamp checks;
the digest identifies the bytes consumed, but is not a cross-process lock or an
authenticity proof. Files may change after the read completes.

Library conversion accepts ParseResult and carries immutable complete-parse
diagnostics on parser-produced ParseResult and Rule objects. A later malformed record rejects
conversion of the whole batch even through a copied prefix list. Manual detached
Rule objects require explicit acknowledgement and remain subject to known
semantic checks. Python callers controlling the objects and private fields are
trusted application code; this is not isolation against arbitrary Python code.
Clearing public diagnostics does not remove the retained context. An empty
sequence is refused because it cannot distinguish a valid empty parse from a
failed one; a parser-produced empty ParseResult retains that distinction.
Unmappable service, stream-size, tag and fast-pattern constraints fail closed in
direct Suricata transformation as well as checked rendering.

Both TAR and ZIP admission reject compressed inputs over 64 MiB before constructing
the parser. Extraction applies that check before creating an output directory;
existing decoded-byte, entry, metadata and path limits are independent. Feed
provenance hashes the complete effective URL without its fragment, retaining
parameter/query distinctions (including empty delimiters) while redacting those
fields in display URLs. The digest uses the supplied URL before its first literal
fragment delimiter, rather than a reconstructed URL. This
digest binds the request target, not the remote server's identity or content;
HTTPS allowlists and the separate downloaded-byte digest remain required.

Protected promotion validates bounded distribution contents, then rebuilds wheel
and sdist containers with exact trusted sibling normalizers at the authenticated
source epoch. Original producer bytes must equal those canonical bytes, including
archive ordering, timestamps, modes, owners, comments, PAX data and gzip framing.
Recomputing producer checksums or evidence cannot authorize noncanonical metadata.

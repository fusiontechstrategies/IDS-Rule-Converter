# IDS Rule Converter Quick Reference

## Requirements

- Python 3.10 or newer
- No runtime package installation
- UTF-8 rule files

## Help and version

```text
python snort_suricata_rule_converter.py --help
python snort_suricata_rule_converter.py --version
```

## Validate

```text
python snort_suricata_rule_converter.py validate input.rules
python snort_suricata_rule_converter.py validate input.rules --json validation.json --sarif validation.sarif
```

## Analyze

```text
python snort_suricata_rule_converter.py analyze input.rules
python snort_suricata_rule_converter.py analyze input.rules --output analysis.json
```

## Strict conversion

No output is written if any rule cannot be converted safely.

```text
python snort_suricata_rule_converter.py convert input.rules --source-dialect snort3 --target suricata --output converted.rules --report conversion.json
```

Targets are `snort2`, `snort3`, `suricata`, and `json`.

## Reviewed partial conversion

```text
python snort_suricata_rule_converter.py convert input.rules --source-dialect snort3 --target suricata --output accepted.rules --allow-partial --rejected-output rejected.rules --report conversion.json
```

Review `rejected.rules` and `conversion.json`. Exit code 2 is expected when any
rule is rejected.

## Preserve unverified keywords

Use only when the target engine will immediately validate the result.

```text
python snort_suricata_rule_converter.py convert input.rules --source-dialect snort3 --target suricata --output converted.rules --allow-unverified --report conversion.json
```

## Compare rulesets

```text
python snort_suricata_rule_converter.py diff previous.rules current.rules --output changes.json
```

## Panorama plugin 2.0.4 preflight

```text
python snort_suricata_rule_converter.py panorama-preflight input.rules --output-dir panorama-review
```

Outputs include accepted batches, rejected source rules when present, a JSON
report, and a readable text report.

## Official community feeds

```text
python snort_suricata_rule_converter.py list-sources
python snort_suricata_rule_converter.py fetch --source snort3-community --output-dir downloads --extract
```

`fetch` is the only command that accesses the network.

## Exit codes

- `0`: success without blocking findings
- `1`: operational or safety failure
- `2`: findings, conflicts, rejected rules, or partial conversion
- `130`: interrupted

## Deployment rule

Run the target engine's native configuration test before placing converted rules
in any production IDS or IPS policy.

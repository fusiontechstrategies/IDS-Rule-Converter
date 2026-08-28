# Contributing

Thank you for helping improve IDS Rule Converter.

## Core principles

- Preserve detection meaning before maximizing conversion count.
- Reject uncertain mappings instead of silently dropping options.
- Keep the production runtime in one Python file.
- Use only the Python standard library at runtime.
- Keep inputs local unless the operator explicitly invokes `fetch`.
- Use ASCII punctuation and do not introduce em dashes.
- Do not commit third-party rule corpora, vendor documents, credentials, or
  environment-specific resource names.

## Development setup

```text
python -m venv .venv
python -m pip install -r requirements-dev.txt
```

Run all local checks before opening a pull request:

```text
python -m ruff format --check .
python -m ruff check .
python -m bandit -q -r snort_suricata_rule_converter.py scripts
python -m pip_audit -r requirements-dev.txt
python -m unittest discover -s tests -v
python -m compileall -q snort_suricata_rule_converter.py scripts tests
```

## Conversion changes

A new mapping should include:

1. Primary documentation for the source and target engines.
2. A statement of the source and target semantics.
3. Focused success and rejection tests.
4. Native target-engine validation when an engine image is available.
5. A clear diagnostic code for any unsafe or unsupported form.

Do not infer equivalence from similar keyword names alone. Ordering, active
buffers, negation, direction, normalization, protocol detection, and engine
configuration can change behavior.

## Tests and fixtures

Small original fixtures may be committed under `tests/fixtures`. Do not copy
vendor community rules into the repository. Local corpora belong under
`.local-reference`, which is ignored by Git.

Tests must be deterministic and must not require credentials, cloud resources,
live traffic, or privileged access. Network-dependent integration tests should
be isolated from the required unit-test workflow.

## Pull requests

- Keep the change focused.
- Explain the safety impact and any rejected edge cases.
- Update the README, quick reference, changelog, and tests when behavior changes.
- Confirm that generated files and local reference material are not included.
- Allow maintainers to edit the branch when practical.

By contributing, you agree that your contribution is licensed under the Apache
License 2.0.

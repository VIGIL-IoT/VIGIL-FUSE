# Contributing to FUSE

FUSE is a CLI-first [VIGIL Project](https://github.com/VIGIL-IoT) for defensive embedded and IoT security analysis. Contributions should keep findings evidence-based and disclose unsupported or partial coverage.

## Local setup

```powershell
git clone https://github.com/VIGIL-IoT/VIGIL-FUSE.git
cd VIGIL-FUSE
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

On POSIX shells, activate with `source .venv/bin/activate`.

## Before opening a change

```powershell
python -m pytest -q
python scripts/evaluate_rule_benchmark.py --check
python -m ruff check src tests scripts
python -m mypy
python scripts/validate_docs.py
python -m ruff format --check src tests scripts
python -m coverage run -m pytest
python -m coverage report -m --fail-under=70
```

The coverage report is a development signal, not a target to inflate. CI runs strict Mypy checks on the native rule package and checks Ruff formatting across the full source, test, and script trees. It also builds the wheel and source distribution, self-scans the repository, and runs the installed CLI smoke test in a clean virtual environment.

## Security rule changes

Follow the contract in [rule development](rule-development.md). Every rule change needs a vulnerable and secure fixture, negative and edge-case tests, bounded evidence, remediation, and a supported-scope statement. Do not add a finding merely because a regex can match it. Keep severity separate from confidence and applicability.

## General changes

- Do not execute project code, build scripts, compiler commands, or firmware during static analysis.
- Preserve schema compatibility and explicit coverage states.
- Treat paths, source text, XML, YAML, JSON, firmware, and analyzer output as untrusted.
- Keep tests deterministic and resource-bounded. Do not require network access in the default suite.
- Update documentation when behavior changes. Never describe regression data as a blind holdout.

Report FUSE vulnerabilities using the private disclosure process in [SECURITY.md](../SECURITY.md). Do not include live secrets or proprietary firmware in public issues.

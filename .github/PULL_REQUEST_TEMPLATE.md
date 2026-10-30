## Summary

<!-- Describe the implementation and user-visible behavior. -->

## Scope and evidence

- [ ] Documentation matches implemented behavior and coverage limits.
- [ ] No unsupported security or accuracy claims were added.
- [ ] License text and release metadata are unchanged, or the change has explicit owner approval.
- [ ] No credentials, private keys, proprietary scan targets, or unreviewed generated reports are included.

## Validation

- [ ] `python -m pytest -q`
- [ ] `python scripts/evaluate_rule_benchmark.py --check`
- [ ] `python -m ruff check src tests scripts`
- [ ] `python scripts/validate_docs.py`
- [ ] Package/build checks run when packaging files changed

## Rule changes

<!-- If applicable, list vulnerable and secure fixtures, expected findings, and false-positive cases. -->

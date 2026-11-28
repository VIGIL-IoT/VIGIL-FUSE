import json
import copy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vigil_fuse.attribution import scan_provenance_json
from vigil_fuse.baseline import _validate_report
from vigil_fuse.reasoning.context import load_report
from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan


def test_historical_schemas_and_current_report(tmp_path):
    root = Path(__file__).parent
    schemas = root.parent / "src/vigil_fuse/schemas"
    for version in ("1.13", "1.14"):
        report = json.loads((root / f"fixtures/report_schema/canonical-{version}.json").read_text())
        schema = json.loads((schemas / f"fuse-report-{version}.schema.json").read_text())
        Draft202012Validator(schema).validate(report)
        _validate_report(report)
        load_report(json.dumps(report).encode())

    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    result = scan(tmp_path)
    report = json.loads(to_json(result, include_evidence_graph=True))
    schema = json.loads((schemas / "fuse-report-1.15.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(report)
    assert isinstance(report["project_identity"]["domains"], dict)
    assert report["project_inventory"]["languages"] == {"Python": 1}
    assert report["evidence_graph"]
    assert json.loads(scan_provenance_json(result, {}))["report_schema_version"] == "1.15"
    for mutate in (
        lambda r: r.pop("project_inventory"),
        lambda r: r["project_inventory"].update(complete="yes"),
        lambda r: r["project_identity"].update(classifications=["invalid"]),
        lambda r: r.update(unexpected=True),
    ):
        bad = copy.deepcopy(report)
        mutate(bad)
        assert list(validator.iter_errors(bad))


def test_canonical_graph_report_is_accepted_and_branch_lineage_is_rejected(tmp_path):
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    report = json.loads(
        (Path(__file__).parent / "fixtures/report_schema/canonical-1.14.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["schema_version"] == "1.14"
    _validate_report(report)
    assert load_report(json.dumps(report).encode())["schema_version"] == "1.14"

    report["project_identity"]["domains"] = ["software"]
    for reader in (_validate_report, lambda value: load_report(json.dumps(value).encode())):
        with pytest.raises(ValueError, match="ambiguous"):
            reader(report)

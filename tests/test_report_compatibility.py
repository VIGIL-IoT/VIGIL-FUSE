import json

import pytest

from vigil_fuse.baseline import _validate_report
from vigil_fuse.reasoning.context import load_report
from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan


def test_canonical_graph_report_is_accepted_and_branch_lineage_is_rejected(tmp_path):
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    report = json.loads(to_json(scan(tmp_path), include_evidence_graph=True))
    assert report["schema_version"] == "1.14"
    _validate_report(report)
    assert load_report(json.dumps(report).encode())["schema_version"] == "1.14"

    report["project_identity"]["domains"] = ["software"]
    for reader in (_validate_report, lambda value: load_report(json.dumps(value).encode())):
        with pytest.raises(ValueError, match="ambiguous"):
            reader(report)

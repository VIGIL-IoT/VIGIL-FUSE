import json
from dataclasses import replace
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator
from vigil_fuse.reporting import to_json
from vigil_fuse.sarif import to_sarif
from vigil_fuse.scanner import scan
from vigil_fuse.software_codeql import parse_codeql, run_codeql


def location(path: str, line: int) -> dict:
    return {"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}


def document() -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "py/example",
                                "name": "Potential command execution",
                                "properties": {
                                    "tags": ["external/cwe/cwe-078"],
                                    "precision": "high",
                                },
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "py/example",
                        "level": "warning",
                        "locations": [location("app.py", 4)],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": location("app.py", 1),
                                                "kinds": ["source"],
                                            },
                                            {
                                                "location": location("app.py", 4),
                                                "kinds": ["sink"],
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_codeql_paths_survive_fuse_report_and_sarif(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    findings = parse_codeql(json.dumps(document()), tmp_path, "test")
    assert findings[0].cwe == ("CWE-78",)
    assert findings[0].engine_rule_id == "py/example"
    assert findings[0].engine_rule_name == "Potential command execution"
    assert [loc.line for loc in findings[0].code_flow[0]] == [1, 4]
    assert [loc.kinds for loc in findings[0].code_flow[0]] == [("source",), ("sink",)]
    result = replace(scan(tmp_path), findings=findings)
    report = json.loads(to_json(result))
    schema = json.loads(
        (
            Path(__file__).parents[1] / "src/vigil_fuse/schemas/fuse-report-1.15.schema.json"
        ).read_text()
    )
    Draft202012Validator(schema).validate(report)
    sarif = json.loads(to_sarif(result))
    steps = sarif["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(steps) == 2
    assert [step["kinds"] for step in steps] == [["source"], ["sink"]]
    assert sarif["runs"][0]["results"][0]["properties"]["engineRuleName"] == (
        "Potential command execution"
    )
    assert [loc["kinds"] for loc in report["findings"][0]["code_flow"][0]] == [
        ["source"],
        ["sink"],
    ]


def test_codeql_rejects_external_and_malformed_locations(tmp_path: Path) -> None:
    for bad in ("../secret.py", "https://example.com/a.py", "%2e%2e/secret.py"):
        doc = document()
        doc["runs"][0]["results"][0]["locations"] = [location(bad, 1)]
        with pytest.raises(ValueError):
            parse_codeql(json.dumps(doc), tmp_path, None)


def test_codeql_runner_uses_existing_database_and_local_queries(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    database = tmp_path / "database"
    database.mkdir()
    queries = tmp_path / "queries.qls"
    queries.write_text("- queries: .", encoding="utf-8")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[1:3] == ["database", "analyze"]
        assert "--no-download" in command
        assert "--no-sarif-add-snippets" in command
        output = Path(command[command.index("--output") + 1])
        output.write_text(json.dumps(document()), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch("vigil_fuse.software_codeql.shutil.which", return_value="codeql"),
        patch("vigil_fuse.software_codeql.inspect_tool_version", return_value="test"),
        patch("vigil_fuse.software_codeql.run_bounded_host_tool", side_effect=fake_run) as invoke,
    ):
        assert run_codeql(source, database, queries, no_network=True).status.status == "skipped"
        invoke.assert_not_called()
        result = run_codeql(source, database, queries, no_network=False)
        assert result.status.status == "partial"
        assert len(result.findings) == 1
        assert result.status.configuration_sha256 is not None
        inside = source / "database"
        inside.mkdir()
        assert run_codeql(source, inside, queries, no_network=False).status.status == "failed"


def test_unverified_uri_base_is_rejected(tmp_path: Path) -> None:
    doc = document()
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uriBaseId"
    ] = "%OTHER%"
    with pytest.raises(ValueError):
        parse_codeql(json.dumps(doc), tmp_path, None)

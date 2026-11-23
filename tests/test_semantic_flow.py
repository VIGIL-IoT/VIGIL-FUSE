from __future__ import annotations

import copy
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from vigil_fuse.analyzer_contract import (
    AnalyzerRequest,
    SandboxPolicy,
    container_command,
    run_analyzer,
)
from vigil_fuse.evidence_graph import EvidenceGraph
from vigil_fuse.semantic_flow import (
    normalize_sarif,
    normalize_joern,
    add_flows,
    validate_flow,
    FAMILIES,
)


def sarif(cwe: str = "78") -> dict:
    def point(line: int, function: str, kinds: list[str]) -> dict:
        return {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": "server.py"},
                    "region": {"startLine": line},
                },
                "logicalLocations": [{"fullyQualifiedName": function}],
            },
            "kinds": kinds,
        }

    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/command-line-injection",
                                "properties": {"tags": [f"external/cwe/cwe-{cwe}"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/command-line-injection",
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            point(1, "handler", []),
                                            point(2, "parse", ["call"]),
                                            point(3, "clean", ["sanitizer"]),
                                            point(4, "execute", []),
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


@pytest.mark.parametrize("cwe", FAMILIES)
def test_family_path_multifunction_sanitizer_and_graph(cwe: str) -> None:
    result = normalize_sarif(sarif(cwe), "python")
    flow = result["flows"][0]
    assert flow["source"]["line"] == 1 and flow["sink"]["line"] == 4
    assert flow["interprocedural"] is True and flow["path_feasibility"] == "unknown"
    assert len(flow["sanitizers"]) == 1
    assert flow["vulnerability_family"] == FAMILIES[cwe]
    g = EvidenceGraph("fixture")
    add_flows(g, result)
    assert {"calls", "flows_to", "sanitized_by"} <= {e["relation"] for e in g.edges.values()}
    assert EvidenceGraph.from_dict(g.to_dict()).to_dict() == g.to_dict()


def test_barrier_duplicates_and_joern_contract() -> None:
    doc = sarif()
    result = doc["runs"][0]["results"][0]
    result["codeFlows"][0]["threadFlows"][0]["locations"][2]["kinds"] = ["barrier"]
    doc["runs"][0]["results"].append(copy.deepcopy(result))
    row = normalize_sarif(doc, "python")
    assert len(row["flows"]) == 1 and len(row["flows"][0]["barriers"]) == 1
    flow = row["flows"][0]
    flow["engine"] = "Joern"
    joern = normalize_joern(
        {"schema_version": "fuse-joern-1.0", "status": "completed", "flows": [flow, flow]}
    )
    assert len(joern["flows"]) == 1
    flow["path_feasibility"] = "proven"
    with pytest.raises(ValueError):
        validate_flow(flow)


@pytest.mark.parametrize(
    "document", [{}, {"version": "2.1.0", "runs": [{}]}, {"version": "2.1.0", "runs": "wrong"}]
)
def test_malformed_and_unsupported(document: dict) -> None:
    with pytest.raises(ValueError):
        normalize_sarif(document, "python")
    assert normalize_sarif(document, "assembly")["status"] == "unsupported"


def test_execution_authorization_limits_isolation_and_failures(tmp_path: Path) -> None:
    request = AnalyzerRequest(
        "CodeQL", "fixture", "sha256:" + "a" * 64, ("python3", "-c", "print('{}')"), (tmp_path,)
    )
    with pytest.raises(ValueError):
        container_command(request, SandboxPolicy(), "fixture", "docker")
    from dataclasses import replace

    request = replace(request, authorized=True)
    command = container_command(request, SandboxPolicy(), "fixture", "docker")
    assert "--network=none" in command and "--read-only" in command
    assert any("readonly" in arg for arg in command)
    assert not any("docker.sock" in arg for arg in command)
    with pytest.raises(ValueError):
        container_command(request, SandboxPolicy(network="bridge"), "fixture", "docker")
    with patch("vigil_fuse.analyzer_contract.shutil.which", return_value=None):
        assert run_analyzer(request).status == "unavailable"
    with (
        patch("vigil_fuse.analyzer_contract.shutil.which", return_value="docker"),
        patch("vigil_fuse.analyzer_contract.subprocess.run"),
        patch(
            "vigil_fuse.analyzer_contract._run", side_effect=subprocess.TimeoutExpired("docker", 1)
        ),
    ):
        assert run_analyzer(request).status == "timeout"
    with (
        patch("vigil_fuse.analyzer_contract.shutil.which", return_value="docker"),
        patch("vigil_fuse.analyzer_contract.subprocess.run"),
        patch(
            "vigil_fuse.analyzer_contract._run",
            return_value=subprocess.CompletedProcess([], 0, "{}", ""),
        ),
    ):
        assert run_analyzer(request).stdout == "{}"

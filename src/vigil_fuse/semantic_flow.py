"""CodeQL SARIF and optional Joern normalized paths, never a FUSE compiler or CPG."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .analyzer_contract import AnalyzerRequest, AnalyzerResult, run_analyzer
from .evidence_graph import (
    EvidenceGraph,
    canonical,
    identity,
    object_fields,
    relative_path,
    strings,
    text,
)

FAMILIES = {
    "78": "command injection",
    "89": "SQL injection",
    "943": "NoSQL injection",
    "90": "LDAP injection",
    "1336": "template injection",
    "22": "path traversal",
    "918": "SSRF",
    "79": "XSS",
    "611": "XXE",
    "502": "unsafe deserialization",
    "601": "open redirect",
    "113": "header injection",
    "117": "log injection",
}
LANGUAGES = frozenset(
    "c cpp csharp go java javascript typescript kotlin python ruby rust swift".split()
)
MAX_PATHS = 2000
MAX_STEPS = 256


@dataclass(frozen=True)
class FlowEvidence:
    vulnerability_family: str
    source: dict[str, Any]
    steps: list[dict[str, Any]]
    sanitizers: list[dict[str, Any]]
    barriers: list[dict[str, Any]]
    sink: dict[str, Any]
    engine: str
    query: str
    interprocedural: bool | None
    path_feasibility: str = "unknown"
    limitations: tuple[str, ...] = (
        "An analyzer path does not establish runtime feasibility or exploitability.",
    )


def location(value: dict[str, Any]) -> dict[str, Any]:
    physical = value["physicalLocation"]
    uri = text(physical["artifactLocation"]["uri"])
    file = relative_path(unquote(uri))
    line = physical["region"]["startLine"]
    if type(line) is not int or not 1 <= line <= 100000000:
        raise ValueError("Invalid flow line")
    logical = value.get("logicalLocations", [])
    function = None
    if logical:
        function = text(logical[0].get("fullyQualifiedName") or logical[0]["name"])
    return {"file": file, "line": line, "function": function, "kind": "flow"}


def validate_flow(value: object) -> FlowEvidence:
    row = object_fields(
        value,
        {
            "vulnerability_family",
            "source",
            "steps",
            "sanitizers",
            "barriers",
            "sink",
            "engine",
            "query",
            "interprocedural",
            "path_feasibility",
            "limitations",
        },
    )
    if row["vulnerability_family"] not in FAMILIES.values() or row["engine"] not in {
        "CodeQL",
        "Joern",
        "Clang",
    }:
        raise ValueError("Unsupported semantic family or engine")
    if row["path_feasibility"] != "unknown" or (
        row["interprocedural"] is not None and type(row["interprocedural"]) is not bool
    ):
        raise ValueError("Unsupported feasibility claim")
    for name in ("steps", "sanitizers", "barriers"):
        if not isinstance(row[name], list) or len(row[name]) > MAX_STEPS:
            raise ValueError("Invalid flow steps")
    if not row["steps"] or row["source"] != row["steps"][0] or row["sink"] != row["steps"][-1]:
        raise ValueError("Inconsistent flow endpoints")
    for item in [*row["steps"], *row["sanitizers"], *row["barriers"]]:
        object_fields(item, {"file", "line", "function", "kind"})
        if item["kind"] not in {"flow", "call", "sanitizer", "barrier"}:
            raise ValueError("Invalid semantic step kind")
        relative_path(item["file"])
        if type(item["line"]) is not int or not 1 <= item["line"] <= 100000000:
            raise ValueError("Invalid semantic location")
        if item["function"] is not None:
            text(item["function"])
    text(row["query"])
    return FlowEvidence(**{**row, "limitations": tuple(strings(row["limitations"]))})


def _flow_dict(flow: FlowEvidence) -> dict[str, Any]:
    return dict(json.loads(canonical(asdict(flow))))


def _normalize_sarif(document: dict[str, Any], language: str) -> dict[str, Any]:
    if language not in LANGUAGES:
        return {
            "status": "unsupported",
            "flows": [],
            "limitations": ["Unsupported semantic language."],
        }
    if (
        document.get("version") != "2.1.0"
        or not isinstance(document.get("runs"), list)
        or len(document["runs"]) > 32
    ):
        raise ValueError("Expected bounded SARIF 2.1.0")
    flows: dict[str, dict[str, Any]] = {}
    partial = False
    for run in document["runs"]:
        driver = run["tool"]["driver"]
        if driver["name"] != "CodeQL":
            raise ValueError("Only CodeQL SARIF is accepted by this adapter")
        rules = {text(rule["id"]): rule for rule in driver.get("rules", [])}
        if not run.get("invocations"):
            partial = True
        for invocation in run.get("invocations", []):
            if invocation.get("executionSuccessful") is not True:
                partial = True
        results = run.get("results", [])
        if not isinstance(results, list) or len(results) > MAX_PATHS:
            raise ValueError("SARIF result limit exceeded")
        for result in results:
            query = text(result["ruleId"])
            rule = rules.get(query, {})
            tags = rule.get("properties", {}).get("tags", [])
            families = {
                FAMILIES[t.rsplit("-", 1)[-1].lstrip("0")]
                for t in tags
                if isinstance(t, str)
                and t.startswith("external/cwe/cwe-")
                and t.rsplit("-", 1)[-1].lstrip("0") in FAMILIES
            }
            if not families:
                partial = True
                continue
            for code_flow in result.get("codeFlows", []):
                for thread in code_flow["threadFlows"]:
                    steps, sanitizers, barriers = [], [], []
                    for item in thread["locations"]:
                        step = location(item["location"])
                        steps.append(step)
                        kinds = item.get("kinds", [])
                        for kind in ("barrier", "sanitizer", "call"):
                            if kind in kinds:
                                step["kind"] = kind
                                break
                        if "sanitizer" in kinds:
                            sanitizers.append(step)
                        if "barrier" in kinds:
                            barriers.append(step)
                    if not 2 <= len(steps) <= MAX_STEPS:
                        raise ValueError("Invalid semantic path length")
                    functions = {step["function"] for step in steps if step["function"] is not None}
                    for family in sorted(families):
                        flow = FlowEvidence(
                            family,
                            steps[0],
                            steps,
                            sanitizers,
                            barriers,
                            steps[-1],
                            "CodeQL",
                            query,
                            True if len(functions) > 1 else None,
                        )
                        row = _flow_dict(validate_flow(_flow_dict(flow)))
                        flows[identity("flow", row)] = row
                        if len(flows) > MAX_PATHS:
                            raise ValueError("Semantic path limit exceeded")
            if not result.get("codeFlows"):
                partial = True
    return {
        "status": "partial" if partial else "completed",
        "flows": [flows[k] for k in sorted(flows)],
        "limitations": ["No feasibility proof. Sanitizers absent from SARIF remain unknown."],
    }


def normalize_sarif(document: dict[str, Any], language: str) -> dict[str, Any]:
    try:
        return _normalize_sarif(document, language)
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("Malformed CodeQL SARIF") from exc


def normalize_joern(document: dict[str, Any]) -> dict[str, Any]:
    object_fields(document, {"schema_version", "flows", "status"})
    if document["schema_version"] != "fuse-joern-1.0" or document["status"] not in {
        "completed",
        "partial",
        "unsupported",
        "unavailable",
        "timeout",
        "failed",
    }:
        raise ValueError("Invalid Joern adapter envelope")
    if not isinstance(document["flows"], list) or len(document["flows"]) > MAX_PATHS:
        raise ValueError("Joern path limit exceeded")
    flows = [_flow_dict(validate_flow(row)) for row in document["flows"]]
    if any(row["engine"] != "Joern" for row in flows):
        raise ValueError("Joern producer mismatch")
    if document["status"] not in {"completed", "partial"} and flows:
        raise ValueError("Unavailable Joern run cannot emit paths")
    return {
        "status": document["status"],
        "flows": list({identity("flow", row): row for row in flows}.values()),
        "limitations": ["Experimental offline Joern contract; no FUSE-owned CPG."],
    }


def add_flows(graph: EvidenceGraph, evidence: dict[str, Any]) -> None:
    run = graph.run("semantic-flow", evidence["status"], artifact=identity("semantic", evidence))
    for value in evidence["flows"]:
        flow = validate_flow(value)
        path_id = graph.node("EvidenceArtifact", identity("flow", value), flow=value)
        nodes = [
            graph.node("Function", [flow.engine, step["file"], step["function"] or step["line"]])
            for step in flow.steps
        ]
        for index, (a, b) in enumerate(zip(nodes, nodes[1:]), start=1):
            relation = "calls" if flow.steps[index]["kind"] == "call" else "flows_to"
            graph.edge(
                a,
                b,
                relation,
                producer=run,
                method=flow.query,
                evidence_refs=[path_id],
                assertion="ASSERTED",
                limitations=list(flow.limitations),
            )
        for step in flow.sanitizers + flow.barriers:
            node = graph.node(
                "Function", [flow.engine, step["file"], step["function"] or step["line"]]
            )
            graph.edge(
                path_id,
                node,
                "sanitized_by",
                producer=run,
                method=flow.query,
                evidence_refs=[path_id],
                assertion="ASSERTED",
                limitations=[
                    "Barrier effectiveness is an analyzer assertion, not a runtime proof."
                ],
            )


_CODEQL_SCRIPT = """import json,os,shutil,subprocess,sys
shutil.copytree('/input0','/work/database',symlinks=True)
result=subprocess.run(['codeql','database','analyze','--format=sarifv2.1.0','--output=/work/flows.sarif','--threads=1','--ram=1024','--no-download','--no-database-extension-packs','--no-sarif-add-file-contents','--no-sarif-add-snippets','--','/work/database','/input1'],stdout=sys.stderr,stderr=sys.stderr,check=True,timeout=280)
with open('/work/flows.sarif','rb') as stream: payload=stream.read(8388609)
if len(payload)>8388608: raise ValueError('artifact limit')
sys.stdout.buffer.write(payload)
"""


def analyze_codeql(
    database: Path, queries: Path, *, image: str, version: str, authorized: bool = False
) -> AnalyzerResult:
    if not database.is_dir() or not (database / "codeql-database.yml").is_file():
        raise ValueError("An existing CodeQL database is required")
    return run_analyzer(
        AnalyzerRequest(
            "CodeQL",
            version,
            image,
            ("python3", "-c", _CODEQL_SCRIPT),
            (database, queries),
            authorized,
        )
    )

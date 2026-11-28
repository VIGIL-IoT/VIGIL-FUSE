from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

from vigil_fuse.dependency_analyzers import _software_components, read_sbom_components
from vigil_fuse.model import DependencyComponent, Finding, SoftwareComponent
from vigil_fuse.reporting import to_json, to_text
from vigil_fuse.sarif import to_sarif
from vigil_fuse.scanner import scan


def test_cyclonedx_inventory_normalizes_package_ecosystems_and_nested_entries() -> None:
    components, complete = _software_components(
        {
            "components": [
                {
                    "name": "demo",
                    "version": "1.2.0",
                    "purl": "pkg:npm/demo@1.2.0",
                    "components": [{"name": "lib", "version": "2", "purl": "pkg:pypi/lib@2"}],
                },
                {"name": "service", "version": "3", "purl": "pkg:maven/org.example/service@3"},
            ]
        }
    )

    assert complete
    assert {(item.name, item.ecosystem, item.version) for item in components} == {
        ("demo", "npm", "1.2.0"),
        ("lib", "Python", "2"),
        ("service", "Maven", "3"),
    }
    assert all(item.direct_dependency is None for item in components)


def test_cyclonedx_inventory_retains_additional_supported_ecosystems() -> None:
    components, complete = _software_components(
        {
            "components": [
                {"name": "app", "version": "1", "purl": "pkg:pub/app@1"},
                {"name": "app", "version": "1", "purl": "pkg:hex/app@1"},
                {"name": "app", "version": "1", "purl": "pkg:cran/app@1"},
                {"name": "app", "version": "1", "purl": "pkg:conan/app@1"},
            ]
        }
    )

    assert complete
    assert {item.ecosystem for item in components} == {"Dart", "Hex", "R", "Conan"}


def test_cyclonedx_inventory_marks_malformed_and_bounded_input_partial(monkeypatch) -> None:
    monkeypatch.setattr("vigil_fuse.dependency_analyzers._MAX_SOFTWARE_COMPONENTS", 1)
    components, complete = _software_components(
        {"components": [{"name": "a", "version": "1"}, {"name": "b", "version": "2"}]}
    )
    assert not complete
    assert len(components) == 1

    malformed, complete = _software_components({"components": [{"name": "x", "version": 1}]})
    assert not complete
    assert malformed == ()


def test_supplied_sbom_duplicate_keys_fail_closed(tmp_path: Path) -> None:
    sbom = tmp_path / "components.cdx.json"
    sbom.write_text('{"bomFormat":"CycloneDX","components":[],"components":[]}', encoding="utf-8")

    result = read_sbom_components(sbom)

    assert result.status.status == "failed"
    assert result.software_components == ()


def test_supplied_spdx_json_reports_packages_and_purl_ecosystems(tmp_path: Path) -> None:
    sbom = tmp_path / "software.spdx.json"
    sbom.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "demo",
                        "versionInfo": "1.2.0",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:npm/demo@1.2.0",
                            }
                        ],
                    }
                ],
                "relationships": [],
            }
        ),
        encoding="utf-8",
    )

    result = read_sbom_components(sbom)

    assert result.status.status == "completed"
    assert result.software_components[0].source == "supplied SPDX SBOM"
    assert result.software_components[0].ecosystem == "npm"
    assert result.software_components[0].purl == "pkg:npm/demo@1.2.0"


def test_spdx_unsupported_or_bounded_inventory_is_not_called_complete(tmp_path: Path) -> None:
    spdx = tmp_path / "software.spdx.json"
    spdx.write_text(
        json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "bad", "versionInfo": 1}]}),
        encoding="utf-8",
    )
    assert read_sbom_components(spdx).status.status == "partial"

    spdx.write_text(json.dumps({"spdxVersion": "SPDX-3.0", "packages": []}), encoding="utf-8")
    assert read_sbom_components(spdx).status.status == "unsupported"


def test_dependency_presence_advisories_and_unknown_reachability_are_reported(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    finding = Finding(
        id="OSV:GHSA-demo:demo@1.2.0:package-lock.json",
        fingerprint="a" * 64,
        rule_id="OSV-GHSA-demo",
        rule_version="fixture",
        analyzer="osv-scanner",
        title="Known vulnerable dependency: demo@1.2.0 (GHSA-demo)",
        severity="high",
        confidence="high",
        category="dependency-vulnerability",
        file="package-lock.json",
        start_line=None,
        end_line=None,
        evidence="npm package demo@1.2.0; advisory GHSA-demo",
        explanation="A package/version advisory match; reachability is unknown.",
        potential_impact="Depends on vulnerable behavior being reachable.",
        remediation="Review the advisory.",
        validation_method="advisory-match",
        component=DependencyComponent("demo", "1.2.0", "npm", "pkg:npm/demo@1.2.0"),
    )
    result = replace(
        scan(tmp_path),
        findings=(finding,),
        package_inventory_status="completed",
        software_components=(SoftwareComponent("demo", "1.2.0", "npm", "pkg:npm/demo@1.2.0"),),
    )
    report = json.loads(to_json(result))
    schema_path = Path(__file__).parents[1] / "src/vigil_fuse/schemas/fuse-report-1.15.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)

    assert report["software_security"]["dependency_inventory"]["components"][0]["name"] == "demo"
    inventory = report["software_security"]["dependency_inventory"]
    assert inventory["component_count"] == 1
    assert inventory["advisory_match_count"] == 1
    assert inventory["reachability"] == "unknown"
    assert "reachability unknown" in to_text(result)
    sarif = json.loads(to_sarif(result))
    assert sarif["runs"][0]["properties"]["softwareSecurity"]["dependency_inventory"] == inventory

from dataclasses import replace

from vigil_fuse.model import DependencyComponent, Finding
from vigil_fuse.software_correlation import correlate_findings


def finding(analyzer: str) -> Finding:
    return Finding(
        id=analyzer,
        fingerprint="a" * 64,
        rule_id=analyzer,
        rule_version="1",
        analyzer=analyzer,
        title="candidate",
        severity="medium",
        confidence="medium",
        category="software-source",
        file="app.py",
        start_line=5,
        end_line=5,
        evidence="redacted",
        explanation="static",
        potential_impact="unknown",
        remediation="review",
        cwe=("CWE-78",),
    )


def test_conservative_groups_retain_evidence_and_severity() -> None:
    first = finding("semgrep")
    second = finding("codeql")
    different = replace(second, id="other", start_line=6, end_line=6)
    grouped = correlate_findings((first, second, different))
    assert len(grouped) == 3
    assert grouped[0].correlation_group == grouped[1].correlation_group
    assert grouped[0].correlation_group is not None
    assert grouped[2].correlation_group is None
    assert grouped[0].severity == first.severity
    assert grouped[1].confidence == second.confidence
    assert correlate_findings((first, replace(first, id="duplicate")))[0].correlation_group is None


def test_secret_candidates_correlate_only_at_the_same_redacted_location() -> None:
    native = replace(finding("fuse-native"), rule_id="FUSE001", category="secrets", cwe=())
    history = replace(
        native,
        id="history",
        analyzer="gitleaks-history",
        rule_id="GITLEAKS:generic-api-key",
        category="historical-secret-exposure",
    )
    different_line = replace(history, id="other", start_line=6, end_line=6)
    private_key = replace(history, id="different-secret-kind", rule_id="GITLEAKS:private-key")

    grouped = correlate_findings((native, history, different_line, private_key))

    assert grouped[0].correlation_group == grouped[1].correlation_group
    assert grouped[2].correlation_group is None
    assert grouped[0].evidence == native.evidence
    assert grouped[1].evidence == history.evidence
    assert grouped[3].correlation_group is None


def test_trivy_secret_candidates_correlate_with_native_redacted_location() -> None:
    native = replace(finding("fuse-native"), rule_id="FUSE001", category="secrets", cwe=())
    trivy = replace(
        native,
        id="trivy-secret",
        analyzer="trivy-secrets",
        rule_id="TRIVY-SECRET:aws-access-key-id",
    )

    grouped = correlate_findings((native, trivy))

    assert grouped[0].correlation_group == grouped[1].correlation_group
    assert grouped[0].correlation_group is not None


def test_package_advisories_correlate_on_package_version_and_advisory() -> None:
    osv = replace(
        finding("osv-scanner"),
        category="dependency-vulnerability",
        rule_id="OSV-CVE-2026-1234",
        component=DependencyComponent("demo", "1.0", "npm"),
        start_line=None,
        end_line=None,
    )
    trivy = replace(
        osv,
        id="trivy",
        analyzer="trivy",
        rule_id="TRIVY-CVE-2026-1234",
        engine_rule_id="CVE-2026-1234",
    )
    different = replace(trivy, id="other", component=DependencyComponent("other", "1.0", "npm"))

    grouped = correlate_findings((osv, trivy, different))

    assert grouped[0].correlation_group == grouped[1].correlation_group
    assert grouped[2].correlation_group is None
    assert grouped[0].severity == grouped[1].severity

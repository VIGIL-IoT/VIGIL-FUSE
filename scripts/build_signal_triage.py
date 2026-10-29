from __future__ import annotations

import argparse
import csv
import json
import subprocess
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from vigil_fuse.model import SourceFile
from vigil_fuse.rules.registry import RULES


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "reports" / "pilot-validation" / "regression-2026-10-28" / "manifest.json"
DEFAULT_REPORT_ROOT = DEFAULT_MANIFEST.parent / "reports"
DEFAULT_CHECKOUTS_ROOT = ROOT.parent / "fuse-scan-targets"
DEFAULT_OUTPUT = DEFAULT_MANIFEST.parent / "manual-triage.csv"


def _git_head(checkout: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _source_text(path: Path) -> str:
    data = path.read_bytes()
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("iso-8859-1")


def _triage(rule_id: str, path: str, currently_reported: bool) -> tuple[str, str, str, str]:
    normalized = path.replace("\\", "/").casefold()
    if rule_id == "FUSE001" and not currently_reported:
        return (
            "filtered-placeholder",
            "example-placeholder",
            "The literal matches a narrow, fixture-backed tutorial-placeholder pattern. It is not treated as a usable credential.",
            "Keep the positive fixture for ordinary hard-coded values and the negative fixtures for these placeholders.",
        )
    if rule_id == "FUSE001" and "tinysrp/t_pwd.h" in normalized:
        return (
            "conditional-default-review",
            "shared-upstream-source",
            "A credential-named default constant is present in both the IoTGoat bundled OpenWrt snapshot and the standalone OpenWrt snapshot. Counts overlap across repositories.",
            "Check the constant's call sites and selected package/build configuration before judging product impact.",
        )
    if rule_id == "FUSE001" and "/berry/drivers/" in normalized:
        return (
            "conditional-default-review",
            "optional-runtime-driver",
            "A literal default occurs in an optional Berry network driver. The source match is real, while driver activation and product inclusion are unresolved.",
            "Check driver activation, configuration overrides, and whether the default can authenticate to a real service.",
        )
    if rule_id == "FUSE001" and "/examples/" in normalized:
        return (
            "conditional-example-review",
            "example",
            "A credential-like literal appears in a runnable example. Example status lowers product applicability, but the value may be copied into deployments.",
            "Keep the signal and verify whether the literal is a documented demo default or user-supplied setup value.",
        )
    if rule_id == "FUSE001":
        return (
            "conditional-default-review",
            "source-configuration",
            "A credential-named literal is present. Static analysis does not establish whether the value is accepted, enabled, or shipped.",
            "Trace use sites and selected build configuration; do not infer secret validity from the assignment alone.",
        )
    if rule_id == "FUSE002":
        return (
            "sample-key-review",
            "example-key-material",
            "A private-key boundary marker is present in a named example or sample-key location. Marker detection is accurate; distribution into a product image is unresolved.",
            "Confirm intended test use and whether packaging or firmware build rules include the file.",
        )
    if rule_id == "FUSE003" and "/examples/" in normalized:
        return (
            "conditional-insecure-example",
            "example",
            "The source explicitly invokes or configures a TLS verification bypass in an example. This is useful copy-paste guidance, not proof of product use.",
            "Keep the example signal and ensure the example clearly warns that verification is disabled.",
        )
    if rule_id == "FUSE003" and normalized.endswith("/httpclient.cpp"):
        return (
            "direct-library-fallback",
            "library-source",
            "The library calls the insecure TLS mode when its CA certificate input is absent. Whether callers supply a certificate is not resolved.",
            "Inspect call sites and API defaults; consider requiring an explicit insecure opt-in or a trusted certificate.",
        )
    if rule_id == "FUSE003" and (
        normalized.startswith("lib/libesp32/") or "/lib/libesp32/" in normalized
    ):
        return (
            "conditional-vendored-tls-review",
            "vendored-library",
            "A TLS verification-bypass indicator occurs in vendored mail-client code. Library selection and runtime call paths are unresolved.",
            "Check dependency version, selected component, and call sites in the target build.",
        )
    if rule_id == "FUSE003" and "powerwall.h" in normalized:
        return (
            "conditional-integration-review",
            "integration-source",
            "The integration source directly selects an insecure TLS client mode. Product use depends on whether this integration is enabled and reachable.",
            "Check feature selection and the connection path; replace the bypass with certificate validation where supported.",
        )
    if rule_id == "FUSE003" and "xdrv_10_scripter.ino" in normalized:
        return (
            "conditional-integration-review",
            "optional-scripting-driver",
            "The scripting driver creates a secure-client object and explicitly disables verification in a conditional driver path.",
            "Check whether this driver path is compiled and whether script-controlled endpoints can reach it.",
        )
    if rule_id == "FUSE003":
        return (
            "conditional-tls-review",
            "project-or-extension-source",
            "A TLS bypass indicator is present in project or extension source. The scan does not prove the path runs or ships.",
            "Trace callers, conditional compilation, and target selection.",
        )
    if rule_id == "FUSE004" and "pio-tools/" in normalized:
        return (
            "build-transport-review",
            "build-helper",
            "A build helper constructs an HTTP firmware-download URL. This is build-time transport evidence, not proof of device OTA behavior.",
            "Verify the download source and integrity mechanism; prefer authenticated HTTPS or a verified digest/signature.",
        )
    if rule_id == "FUSE004":
        return (
            "conditional-ota-transport-review",
            "optional-extension",
            "An optional extension contains a non-loopback HTTP endpoint. Whether the extension is enabled and how the endpoint is used are unresolved.",
            "Check feature activation and whether the update flow independently authenticates firmware.",
        )
    if rule_id == "FUSE-GHA-002":
        return (
            "valid-workflow-policy-signal",
            "github-actions-workflow",
            "The workflow references an action through a mutable branch rather than a full commit SHA. No workflow code was executed.",
            "Pin the action to a reviewed full commit SHA and update it through a controlled process.",
        )
    return (
        "unclassified-review",
        "unknown",
        "No rule-specific triage mapping exists for this signal.",
        "Review the source location manually.",
    )


def build_triage(
    manifest_path: Path,
    report_root: Path,
    checkouts_root: Path,
) -> list[dict[str, str]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report_root = report_root.resolve()
    rules = {rule.id: rule for rule in RULES}
    rows: list[dict[str, str]] = []
    for repository in manifest.get("repositories", []):
        checkout = (checkouts_root / repository["id"]).resolve()
        if not checkout.is_relative_to(checkouts_root.resolve()):
            raise ValueError(f"Checkout path escapes the checkout root: {repository['id']!r}")
        actual_commit = _git_head(checkout)
        if actual_commit != repository["commit"]:
            raise ValueError(
                f"Pinned checkout mismatch for {repository['name']}: "
                f"expected {repository['commit']}, got {actual_commit}"
            )
        current_rule_lines: dict[str, set[int]] = {}
        source_cache: dict[str, SourceFile] = {}
        for scan in repository.get("scans", []):
            report_path = (report_root / scan["id"] / "findings.json").resolve()
            if not report_path.is_relative_to(report_root):
                raise ValueError(f"Report path escapes the report root: {scan['id']!r}")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            for finding in report.get("findings", []):
                rule_id = str(finding.get("rule_id", "unknown"))
                location = finding.get("location", {})
                file_path = str(location.get("file", ""))
                line = location.get("start_line")
                if not isinstance(line, int):
                    line = 0
                if rule_id == "FUSE001" and file_path not in source_cache:
                    source_path = (checkout / Path(file_path)).resolve()
                    if not source_path.is_relative_to(checkout):
                        raise ValueError(f"Finding source path escapes the checkout: {file_path!r}")
                    if not source_path.is_file():
                        raise FileNotFoundError(f"Finding source path is missing: {file_path!r}")
                    source_cache[file_path] = SourceFile(
                        path=file_path,
                        text=_source_text(source_path),
                    )
                    rule = rules.get(rule_id)
                    current_rule_lines[file_path] = {
                        item.start_line or 0
                        for item in rule.scan(source_cache[file_path])
                    } if rule else set()
                currently_reported = (
                    line in current_rule_lines.get(file_path, set())
                    if rule_id == "FUSE001"
                    else True
                )
                disposition, source_role, rationale, next_check = _triage(
                    rule_id, file_path, currently_reported
                )
                commit_url = (
                    f"{repository['url'].rstrip('/')}/blob/{repository['commit']}/"
                    f"{quote(file_path, safe='/')}#L{line}"
                )
                rows.append(
                    {
                        "repository": repository["name"],
                        "scan_scope": scan["id"],
                        "commit": repository["commit"],
                        "finding_id": str(finding.get("id", "")),
                        "rule_id": rule_id,
                        "severity": str(finding.get("severity", "unknown")),
                        "confidence": str(finding.get("confidence", "unknown")),
                        "disposition": disposition,
                        "source_role": source_role,
                        "file": file_path,
                        "line": str(line) if line else "",
                        "rationale": rationale,
                        "next_check": next_check,
                        "source_url": commit_url,
                    }
                )
    return sorted(rows, key=lambda row: (row["repository"].casefold(), row["file"].casefold(), row["line"]))


def write_triage(rows: list[dict[str, str]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else []
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    counts = Counter(row["disposition"] for row in rows)
    summary_path = output.with_suffix(".md")
    summary = [
        "# Manual signal triage",
        "",
        f"Reviewed {len(rows)} raw signals at their pinned source locations.",
        "",
        "This is a static, source-context review. It does not confirm credential validity, release inclusion, reachability, or device behavior. Severity and confidence remain separate. The CSV contains no evidence values.",
        "",
        "| Disposition | Signals |",
        "| --- | ---: |",
    ]
    summary.extend(f"| `{name}` | {count} |" for name, count in sorted(counts.items()))
    summary.extend(
        [
            "",
            (
                "The `filtered-placeholder` rows are the matches now excluded by the fixture-backed FUSE001 refinement. Other example, library, integration, and workflow signals remain visible until target configuration or build evidence resolves applicability."
                if counts.get("filtered-placeholder", 0)
                else "No current finding rows were classified as filtered placeholders. Placeholder-only matches from the earlier baseline are retained in that baseline's triage ledger. Other example, library, integration, and workflow signals remain visible until target configuration or build evidence resolves applicability."
            ),
            "",
        ]
    )
    summary_path.write_text("\n".join(summary), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a value-redacted triage ledger for pinned FUSE findings.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    parser.add_argument("--checkouts-root", type=Path, default=DEFAULT_CHECKOUTS_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    rows = build_triage(args.manifest, args.report_root, args.checkouts_root)
    write_triage(rows, args.output)
    print(f"Wrote triage for {len(rows)} signals to {args.output}")


if __name__ == "__main__":
    main()

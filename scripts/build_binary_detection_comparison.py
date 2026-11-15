"""Build a separate comparison report for the 2026-11-15 Ghidra rerun."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("esp32", "esp32s3", "esp32c6")
OLD_EVIDENCE = ROOT / "reports/evaluation/2026-11-14/evidence"


def _load_real_record(path: Path) -> tuple[dict, dict]:
    summary = json.loads(path.read_text(encoding="utf-8"))
    records = [record for record in summary["records"] if "provenance" in record]
    if len(records) != 1:
        raise ValueError(f"Expected exactly one real firmware record in {path}")
    return summary, records[0]


def _old_inventory_status(record: dict) -> str:
    truncation = record.get("truncation")
    analysis = record.get("analysis")
    if (isinstance(truncation, dict) and any(value is True for value in truncation.values())) or (
        isinstance(analysis, dict) and analysis.get("status") == "partial"
    ):
        return "partial"
    return "complete"


def _safe_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def build(source: Path, output: Path) -> None:
    if any(
        (output / name).exists()
        for name in ("README.md", "comparison.json", "evidence", "evidence-hashes.json")
    ):
        raise FileExistsError("Refusing to overwrite a published binary detection comparison")
    source_records: dict[str, tuple[Path, dict, dict]] = {}
    for path in source.rglob("compatibility.json"):
        summary = json.loads(path.read_text(encoding="utf-8"))
        target = summary.get("target")
        if target in TARGETS:
            if target in source_records:
                raise ValueError(f"Duplicate current evidence for {target}")
            records = [record for record in summary["records"] if "provenance" in record]
            if len(records) != 1:
                raise ValueError(f"Expected one current firmware record for {target}")
            source_records[target] = (path.parent, summary, records[0])
    if set(source_records) != set(TARGETS):
        raise ValueError(f"Expected current evidence for {', '.join(TARGETS)}")

    prepared: dict[str, tuple[dict, dict, Path, dict, dict, bool]] = {}
    for target in TARGETS:
        old_summary, old = _load_real_record(OLD_EVIDENCE / target / "compatibility.json")
        artifact_root, current_summary, current = source_records[target]
        old_status = _old_inventory_status(old)
        new_inventory = current.get("inventory_status", "unsupported")
        new_security = current.get("security_evaluation_status", "unsupported")
        rules = current.get("security_rule_statuses", {})
        if new_inventory not in {"complete", "partial"}:
            raise ValueError(f"{target} has invalid inventory coverage status")
        if new_security not in {"complete", "partial", "unsupported"}:
            raise ValueError(f"{target} has invalid security evaluation status")
        if new_security != "complete" and current.get("status") == "completed":
            raise ValueError(f"{target} reports completed analysis with incomplete rule coverage")
        if new_security == "complete" and set(rules) != {"FUSE-BIN-001", "FUSE-BIN-002"}:
            raise ValueError(f"{target} has incomplete per-rule coverage metadata")
        old_provenance = old.get("provenance")
        current_provenance = current.get("provenance")
        identity_fields = ("repository", "commit", "image", "command")
        if (
            not isinstance(old_provenance, dict)
            or not isinstance(current_provenance, dict)
            or any(not old_provenance.get(field) for field in identity_fields)
            or old_provenance != current_provenance
        ):
            raise ValueError(f"Pinned build provenance changed for {target}")
        if old["input_bytes"] != current["input_bytes"]:
            raise ValueError(f"Input size changed for {target}; comparison requires investigation")
        prepared[target] = (
            old_summary,
            old,
            artifact_root,
            current_summary,
            current,
            current["input_sha256"] == old["input_sha256"],
        )

    output.mkdir(parents=True, exist_ok=True)
    targets: dict[str, dict] = {}
    hashes: dict[str, str] = {}
    lines = [
        "# FUSE binary detection completeness comparison",
        "",
        "A VIGIL Project",
        "",
        "This report compares the immutable November 14 ESP-IDF scan artifacts with the separately stored November 15 rebuild and rerun. The November 14 files were not modified. Old schema 1.0 artifacts did not record independent security traversal status, so their rule coverage is unsupported, not a clean negative.",
        "",
        "| Target | Old inventory | New inventory | Old rule evaluation | New rule evaluation | New findings | New truncation groups |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for target in TARGETS:
        old_summary, old, artifact_root, current_summary, current, sha256_matches = prepared[target]
        old_status = _old_inventory_status(old)
        new_inventory = current.get("inventory_status", "unsupported")
        new_security = current.get("security_evaluation_status", "unsupported")
        truncation = current.get("truncation") or {}
        groups = sorted(name for name, value in truncation.items() if value is True)
        rules = current.get("security_rule_statuses", {})

        targets[target] = {
            "input_comparison": {
                "basis": "same_pinned_source_rebuild",
                "pinned_provenance_matches": True,
                "input_bytes_match": True,
                "sha256_matches": sha256_matches,
            },
            "previous": {
                "fuse_commit": old_summary["fuse_commit"],
                "provenance": old["provenance"],
                "input_sha256": old["input_sha256"],
                "input_bytes": old["input_bytes"],
                "inventory_status": old_status,
                "security_evaluation_status": "unsupported",
                "rule_ids": old["rule_ids"],
                "truncation": old["truncation"],
                "elapsed_seconds": old["elapsed_seconds"],
                "peak_process_tree_rss_bytes": old["peak_process_tree_rss_bytes"],
                "artifact_bytes": old["artifact_bytes"],
                "ghidra_version": old["tool"]["version"],
            },
            "revised": {
                "fuse_commit": current_summary["fuse_commit"],
                "harness_commit": current_summary["harness_commit"],
                "provenance": current["provenance"],
                "input_sha256": current["input_sha256"],
                "input_bytes": current["input_bytes"],
                "inventory_status": new_inventory,
                "security_evaluation_status": new_security,
                "security_rule_statuses": rules,
                "rule_ids": current["rule_ids"],
                "truncation": current["truncation"],
                "elapsed_seconds": current["elapsed_seconds"],
                "peak_process_tree_rss_bytes": current["peak_process_tree_rss_bytes"],
                "artifact_bytes": current["artifact_bytes"],
                "ghidra_version": current["tool"]["version"],
                "security_counts": current["security_counts"],
            },
        }
        findings = ", ".join(current["rule_ids"]) if current["rule_ids"] else "none"
        lines.append(
            f"| {target} | {old_status} | {new_inventory} | unsupported | {new_security} | "
            f"{_safe_cell(findings)} | {_safe_cell(', '.join(groups) or 'none')} |"
        )
        target_dir = output / "evidence" / target
        target_dir.mkdir(parents=True, exist_ok=True)
        compatibility = artifact_root / "compatibility.json"
        shutil.copyfile(compatibility, target_dir / "compatibility.json")
        real_output = artifact_root / "outputs" / current["id"]
        if not real_output.is_dir():
            raise FileNotFoundError(f"Missing current Ghidra output for {target}")
        shutil.copytree(real_output, target_dir / "output")
        for copied in sorted(target_dir.rglob("*")):
            if copied.is_file():
                relative = copied.relative_to(output).as_posix()
                hashes[relative] = hashlib.sha256(copied.read_bytes()).hexdigest()

    lines += [
        "",
        "## Build input identity",
        "",
        "| Target | November 14 ELF SHA-256 | November 15 ELF SHA-256 | Bytes old to new | Pinned provenance |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for target in TARGETS:
        previous = targets[target]["previous"]
        revised = targets[target]["revised"]
        lines.append(
            f"| {target} | `{previous['input_sha256']}` | `{revised['input_sha256']}` | "
            f"{previous['input_bytes']} to {revised['input_bytes']} | "
            f"{'SHA-256 matches' if targets[target]['input_comparison']['sha256_matches'] else 'same pinned build provenance'} |"
        )
    mismatched_hashes = [
        target for target in TARGETS if not targets[target]["input_comparison"]["sha256_matches"]
    ]
    if mismatched_hashes:
        lines += [
            "",
            f"ELF SHA-256 differs for {', '.join(mismatched_hashes)}. For these targets, the pinned project commit, ESP-IDF image, build command, provenance, and byte count match, but the original November 14 ELF files were not archived. This compares scan outputs from separate rebuilds of the same pinned inputs, not scans of verified byte-identical binaries. The available artifacts do not establish why the ELF bytes differ.",
            "Full source, image, command, repository, and license provenance is preserved in `comparison.json` and the copied compatibility records.",
        ]
    else:
        lines += [
            "",
            "All compared ELF SHA-256 values match. This supports byte-identical input comparison for these targets.",
        ]
    lines += [
        "",
        "## Measured details",
        "",
        "| Target | Input SHA-256 match | Ghidra | Findings | Inventory groups truncated | Time old to new (seconds) | Sampled RSS old to new (bytes) | Artifact bytes old to new |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: |",
    ]
    for target in TARGETS:
        previous = targets[target]["previous"]
        revised = targets[target]["revised"]
        lines.append(
            f"| {target} | {'yes' if targets[target]['input_comparison']['sha256_matches'] else 'no'} | {revised['ghidra_version']} | "
            f"{_safe_cell(', '.join(revised['rule_ids']) or 'none')} | "
            f"{_safe_cell(', '.join(name for name, value in revised['truncation'].items() if value) or 'none')} | "
            f"{previous['elapsed_seconds']:.2f} to {revised['elapsed_seconds']:.2f} | "
            f"{previous['peak_process_tree_rss_bytes']} to {revised['peak_process_tree_rss_bytes']} | "
            f"{previous['artifact_bytes']} to {revised['artifact_bytes']} |"
        )
    lines += [
        "",
        "The artifact records include processor language, per-rule counts, reference visits, execution time, process-tree RSS samples, artifact size, and inventory truncation. RSS is sampled, not a hard memory ceiling. Security completion does not imply complete inventory or general firmware coverage.",
        "",
        "The new security traversal is validated on controlled binaries with more than 1,500 ordinary strings, secure HTTPS and MQTTS controls, unreferenced plaintext endpoints, optimization variants, and stripped binaries. Those controls are construction-based regressions, not independent accuracy evidence.",
        "",
        "See [the preregistered protocol](protocol.md), [pre-change manifest](prechange-manifest.json), [ESP-IDF configuration applicability review supplement](config-applicability/README.md), and [November 14 evaluation](../../2026-11-14/README.md).",
        "",
    ]
    (output / "comparison.json").write_text(
        json.dumps({"schema_version": "1.1", "targets": targets}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "evidence-hashes.json").write_text(
        json.dumps(hashes, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.source, args.output)


if __name__ == "__main__":
    main()

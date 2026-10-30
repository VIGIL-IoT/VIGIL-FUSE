from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any, TypedDict

from .model import ScanResult


class CapabilityDefinition(TypedDict):
    id: str
    label: str
    scope: str
    limitations: list[str]


class CapabilitySummary(TypedDict):
    capability_id: str
    label: str
    status: str
    scope: str
    limitations: list[str]


@lru_cache(maxsize=1)
def support_matrix() -> dict[str, Any]:
    resource = files("vigil_fuse").joinpath("support-matrix.json")
    document: object = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Bundled support matrix must be a JSON object")
    return document


def _capability(capability_id: str) -> CapabilityDefinition:
    for item in support_matrix()["capabilities"]:
        if not isinstance(item, dict) or item.get("id") != capability_id:
            continue
        label = item.get("label")
        scope = item.get("scope")
        limitations = item.get("limitations")
        if (
            not isinstance(label, str)
            or not isinstance(scope, str)
            or not isinstance(limitations, list)
            or not all(isinstance(limitation, str) for limitation in limitations)
        ):
            raise ValueError(f"Invalid FUSE support capability: {capability_id}")
        return {
            "id": capability_id,
            "label": label,
            "scope": scope,
            "limitations": limitations,
        }
    raise ValueError(f"Unknown FUSE support capability: {capability_id}")


def source_capability(profile: str) -> CapabilityDefinition:
    return _capability(f"source.{profile}")


def capability_for_scan(result: ScanResult) -> CapabilitySummary:
    capability: CapabilityDefinition
    if result.target_kind == "firmware-image":
        input_status = next(
            (item for item in result.analyzers if item.name == "firmware-input"), None
        )
        if input_status is not None:
            capability = {
                "id": "input.unsupported",
                "label": "unsupported",
                "scope": "The firmware image was rejected before hashing or signature identification.",
                "limitations": [
                    "Reduce the image size or raise scan.max_firmware_bytes within the configured maximum"
                ],
            }
            status = "unsupported"
        else:
            capability = _capability("firmware.signature-identification")
            analyzer = next((item for item in result.analyzers if item.name == "binwalk"), None)
            status = analyzer.status if analyzer else "skipped"
    elif result.target_kind == "sbom":
        input_status = next((item for item in result.analyzers if item.name == "sbom-input"), None)
        analyzer = next((item for item in result.analyzers if item.name == "osv-scanner"), None)
        if input_status is not None:
            capability = {
                "id": "input.unsupported",
                "label": "unsupported",
                "scope": "The SBOM exceeds the configured parse and hash limit.",
                "limitations": ["No SBOM parsing or advisory lookup was performed"],
            }
            status = "unsupported"
        elif analyzer is not None:
            capability = _capability("inventory.sbom-advisories")
            status = analyzer.status
        else:
            capability = _capability("inventory.sbom-detected")
            status = "detected"
    elif result.target_kind == "unsupported-file":
        capability = {
            "id": "input.unsupported",
            "label": "unsupported",
            "scope": "FUSE did not select a security analyzer for this target.",
            "limitations": ["No security analysis was performed"],
        }
        status = "unsupported"
    else:
        capability = source_capability(result.profile)
        native = next((item for item in result.analyzers if item.name == "fuse-native"), None)
        status = native.status if native else "skipped"
        if status == "skipped" and result.files_scanned == 0:
            status = "detected"

    return {
        "capability_id": capability["id"],
        "label": capability["label"],
        "status": status,
        "scope": capability["scope"],
        "limitations": capability["limitations"],
    }


def capability_for_plan(
    profile: str,
    *,
    sbom_input: bool,
    firmware: bool,
    oversized_sbom: bool,
    oversized_firmware: bool = False,
    unsupported_input: bool = False,
) -> CapabilitySummary:
    if oversized_firmware:
        return {
            "capability_id": "input.unsupported",
            "label": "unsupported",
            "status": "unsupported",
            "scope": "The firmware image exceeds the configured input size limit.",
            "limitations": ["No image hashing or signature identification will run"],
        }
    if oversized_sbom:
        return {
            "capability_id": "input.unsupported",
            "label": "unsupported",
            "status": "unsupported",
            "scope": "The SBOM exceeds the configured parse and hash limit.",
            "limitations": ["No SBOM parsing or advisory lookup will run"],
        }
    if firmware:
        capability = _capability("firmware.signature-identification")
        status = "planned"
    elif sbom_input:
        capability = _capability("inventory.sbom-detected")
        status = "detected"
    elif unsupported_input:
        capability = {
            "id": "input.unsupported",
            "label": "unsupported",
            "scope": "FUSE will not select a security analyzer for this target.",
            "limitations": ["No security analysis will be performed"],
        }
        status = "unsupported"
    else:
        capability = source_capability(profile)
        status = "planned"
    return {
        "capability_id": capability["id"],
        "label": capability["label"],
        "status": status,
        "scope": capability["scope"],
        "limitations": capability["limitations"],
    }

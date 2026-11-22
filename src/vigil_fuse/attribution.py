"""FUSE ownership metadata for generated scan bundles."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Mapping

from . import __version__
from .model import ScanResult

FUSE_NAME = "FUSE"
FUSE_FULL_NAME = "Firmware & Unified Security Engine"
FUSE_REPOSITORY = "https://github.com/VIGIL-IoT/VIGIL-FUSE"
REPORT_SCHEMA_VERSION = "1.13"


def generated_by_metadata() -> dict[str, str]:
    return {
        "name": FUSE_NAME,
        "full_name": FUSE_FULL_NAME,
        "project": "VIGIL",
        "repository": FUSE_REPOSITORY,
        "version": __version__,
    }


def citation_cff_text() -> str:
    template = files("vigil_fuse").joinpath("resources", "citation.cff").read_text(encoding="utf-8")
    return template.replace('version: "@VERSION@"', f'version: "{__version__}"')


def scan_provenance_json(result: ScanResult, report_artifacts: Mapping[str, bytes]) -> str:
    configuration = {
        "profile": result.profile,
        "target_kind": result.target_kind,
        "network_policy": result.network_policy,
        "rules_enabled": list(result.rules_enabled),
        "analyzers": [
            {"name": analyzer.name, "status": analyzer.status, "version": analyzer.version}
            for analyzer in result.analyzers
        ],
    }
    canonical_configuration = json.dumps(
        configuration, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    provenance = {
        "schema_version": "1.0",
        "generated_by": generated_by_metadata(),
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "scan": {
            "target_label": result.target_label,
            "profile": result.profile,
            "target_kind": result.target_kind,
            "network_policy": result.network_policy,
            "input_manifest_sha256": result.input_manifest_sha256,
            "configuration": configuration,
            "configuration_sha256": hashlib.sha256(canonical_configuration).hexdigest(),
            "project_identity": result.project_identity.to_dict(),
        },
        "artifacts": {
            name: {"sha256": hashlib.sha256(content).hexdigest()}
            for name, content in sorted(report_artifacts.items())
        },
    }
    return json.dumps(provenance, indent=2, ensure_ascii=False) + "\n"

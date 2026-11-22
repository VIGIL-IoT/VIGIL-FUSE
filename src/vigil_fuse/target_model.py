"""Versioned target identifiers for passive analysis planning."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal

TargetKind = Literal[
    "repository",
    "component",
    "web-service",
    "application",
    "container",
    "kubernetes-workload",
    "binary",
    "firmware",
    "embedded-device",
]


@dataclass(frozen=True)
class Target:
    target_id: str
    kind: TargetKind
    label: str
    source: str
    authorization: Literal["unknown", "authorized", "unauthorized"] = "unknown"
    revision: str | None = None
    sha256: str | None = None
    endpoint: str | None = None
    environment: str | None = None
    scope: tuple[str, ...] = ()
    provenance: str | None = None
    schema_version: str = "0.1"

    def __post_init__(self) -> None:
        if not self.target_id.strip() or not self.label.strip() or not self.source.strip():
            raise ValueError("target ID, label and source must be nonempty")
        if self.authorization not in {"unknown", "authorized", "unauthorized"}:
            raise ValueError("invalid authorization state")
        if self.kind not in {
            "repository",
            "component",
            "web-service",
            "application",
            "container",
            "kubernetes-workload",
            "binary",
            "firmware",
            "embedded-device",
        }:
            raise ValueError("invalid target type")
        if self.sha256 is not None and not re.fullmatch(r"[a-f0-9]{64}", self.sha256):
            raise ValueError("sha256 must be a lowercase SHA-256 digest")
        if self.schema_version != "0.1":
            raise ValueError("unsupported target schema version")

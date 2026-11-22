"""Explain conservative analysis recommendations without launching tools."""

from __future__ import annotations

from typing import Literal, TypedDict

from .repo_dna import RepoDNA


class Decision(TypedDict):
    stage: str
    status: Literal["selected", "skipped", "unsupported", "unavailable", "blocked_by_policy"]
    reason: str


def plan_analysis(dna: RepoDNA) -> list[Decision]:
    """Return advisory passive decisions; never invoke or enable analyzers."""
    stages: list[Decision] = [
        {"stage": "native", "status": "selected", "reason": "passive source analysis"},
        {
            "stage": "nikto",
            "status": "blocked_by_policy",
            "reason": "active target and authorization are required",
        },
        {
            "stage": "metasploit-check",
            "status": "blocked_by_policy",
            "reason": "explicit controlled validation is required",
        },
    ]
    if not dna["complete"]:
        stages.append(
            {
                "stage": "discovery",
                "status": "unsupported",
                "reason": "repository inspection is incomplete; recommendations are partial",
            }
        )
    return stages

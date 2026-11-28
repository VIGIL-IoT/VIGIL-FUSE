from __future__ import annotations

import json
from pathlib import Path

from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan


def test_hybrid_fixture_keeps_software_and_embedded_evidence_in_one_report() -> None:
    target = Path(__file__).parent / "fixtures" / "software-hybrid"

    result = scan(target)
    report = json.loads(to_json(result))

    identity = report["project_identity"]
    assert {"software", "embedded"} <= set(identity["classifications"])
    assert all(isinstance(score, float) for score in identity["domains"].values())
    assert identity["domains"]["firmware"] > 0
    assert identity["domains"]["hardware"] > 0
    assert identity["domains"]["rtl"] > 0
    assert any(item.rule_id == "FUSE-SW001" for item in result.findings)
    assert report["hardware_inventory"]["present"]
    assert result.hardware_inventory.rtl_analysis.status in {"parsed", "partial"}
    assert result.github_actions.status == "completed"

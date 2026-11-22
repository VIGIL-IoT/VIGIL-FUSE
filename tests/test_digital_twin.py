import json

import pytest

from vigil_fuse.digital_twin import synthesize_digital_twin
from vigil_fuse.model import HardwareBOMComponent, HardwareBOMInventory
from vigil_fuse.svd import parse_svd


SVD = b"""<device><name>CHIP1</name><peripherals><peripheral><name>UART2</name>
<baseAddress>0x40004400</baseAddress><registers><register><name>STATUS</name>
<addressOffset>0</addressOffset><resetValue>0xC0</resetValue>
</register></registers></peripheral></peripherals></device>"""


def test_twin_preserves_provenance_reset_and_candidate_bom_identity() -> None:
    svd = parse_svd(SVD, "local.svd")
    bom = HardwareBOMInventory(
        status="imported",
        source_path="bom.csv",
        sha256="abc",
        components=(HardwareBOMComponent("U1", "mcu", 1, part_number="CHIP1"),),
    )
    twin = synthesize_digital_twin(svd, ("UART2",), bom)
    result = json.loads(twin.to_json())
    assert result["status"] == "partial"
    assert result["svd_sha256"] == svd.device.sha256
    assert result["bom_identity_candidates"] == ["U1"]
    assert result["peripherals"][0]["registers"][0]["reset_value"] == 0xC0
    assert twin.to_json() == synthesize_digital_twin(svd, ("UART2",), bom).to_json()


def test_twin_rejects_missing_peripheral_and_oversized_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    svd = parse_svd(SVD, "local.svd")
    with pytest.raises(ValueError):
        synthesize_digital_twin(svd, ("missing",))
    twin = synthesize_digital_twin(svd)
    monkeypatch.setattr("vigil_fuse.digital_twin.MAX_TWIN_JSON_BYTES", 100)
    with pytest.raises(ValueError, match="size limit"):
        twin.to_json()

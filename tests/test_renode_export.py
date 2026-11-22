import pytest

from vigil_fuse.digital_twin import synthesize_digital_twin
from vigil_fuse.renode_export import export_renode
from vigil_fuse.svd import parse_svd


SVD = b"""<device><name>Chip</name><size>32</size><resetMask>0xffffffff</resetMask>
<peripherals><peripheral><name>UART2</name><baseAddress>0x40004400</baseAddress>
<registers><register><name>STATUS</name><addressOffset>0</addressOffset>
<resetValue>0xc0</resetValue></register></registers></peripheral></peripherals></device>"""


def test_renode_description_is_explicitly_synthetic() -> None:
    twin = synthesize_digital_twin(parse_svd(SVD, "local.svd"))
    result = export_renode(twin, {"UART2": 0x100}, {("UART2", "STATUS"): 1})
    assert result.status == "experimental"
    assert "Python.PythonPeripheral @ sysbus 0x40004400" in result.platform
    assert "{0: 193}" in result.platform
    assert any("Synthetic" in item for item in result.limitations)
    assert result == export_renode(twin, {"UART2": 0x100}, {("UART2", "STATUS"): 1})


def test_renode_refuses_unknown_resets_or_unmatched_overrides() -> None:
    twin = synthesize_digital_twin(parse_svd(SVD, "local.svd"))
    with pytest.raises(ValueError):
        export_renode(twin, {"UART2": 0x100}, {("UART2", "OTHER"): 1})
    incomplete = synthesize_digital_twin(
        parse_svd(SVD.replace(b"<resetMask>0xffffffff</resetMask>", b""), "x")
    )
    with pytest.raises(ValueError, match="fully known resets"):
        export_renode(incomplete, {"UART2": 0x100})
    with pytest.raises(ValueError):
        export_renode(twin, {"UART2": 3})


def test_untrusted_peripheral_names_do_not_become_platform_code() -> None:
    name = "UART2; injected"
    twin = synthesize_digital_twin(parse_svd(SVD.replace(b"UART2", name.encode()), "x"))
    output = export_renode(twin, {name: 0x100}).platform
    assert name not in output

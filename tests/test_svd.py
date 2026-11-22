from dataclasses import asdict
import hashlib
import json

from vigil_fuse.svd import MAX_SVD_BYTES, parse_svd


VALID = b"""<device><name>Example</name><version>1</version>
<access>read-write</access><resetValue>0xC0</resetValue>
<peripherals><peripheral><name>USART2</name><baseAddress>0x40004400</baseAddress>
<interrupt><name>USART2_IRQ</name><value>38</value></interrupt>
<registers><register><name>SR</name><addressOffset>0</addressOffset>
<fields><field><name>READY</name><bitOffset>7</bitOffset><bitWidth>1</bitWidth>
<enumeratedValues><usage>read</usage><enumeratedValue><name>Ready</name>
<value>1</value></enumeratedValue></enumeratedValues></field></fields>
</register></registers></peripheral></peripherals></device>"""


def test_svd_records_registers_fields_and_provenance() -> None:
    result = parse_svd(VALID, "board.svd")
    assert result.status == "partial"
    assert result.device is not None
    assert result.device.sha256 == hashlib.sha256(VALID).hexdigest()
    peripheral = result.device.peripherals[0]
    assert peripheral.base_address == 0x40004400
    assert peripheral.interrupts == (("USART2_IRQ", 38),)
    register = peripheral.registers[0]
    assert (register.offset, register.reset_value, register.access) == (0, 0xC0, "read-write")
    assert (register.fields[0].bit_offset, register.fields[0].bit_width) == (7, 1)
    assert register.fields[0].enumerated_values[0].usage == "read"
    assert json.dumps(asdict(result), sort_keys=True) == json.dumps(
        asdict(parse_svd(VALID, "board.svd")), sort_keys=True
    )


def test_svd_rejects_unsafe_invalid_and_duplicate_input() -> None:
    assert (
        parse_svd(b'<!DOCTYPE device [<!ENTITY x SYSTEM "file:///secret">]><device/>', "x").status
        == "invalid"
    )
    assert parse_svd(b"<device>", "x").status == "invalid"
    assert parse_svd(b"x" * (MAX_SVD_BYTES + 1), "x").status == "invalid"
    duplicate = VALID.replace(
        b"</peripherals>",
        b"<peripheral><name>USART2</name><baseAddress>0</baseAddress></peripheral></peripherals>",
    )
    assert parse_svd(duplicate, "x").status == "invalid"


def test_unsupported_derived_peripheral_is_omitted_and_partial() -> None:
    source = VALID.replace(
        b"</peripherals>",
        b'<peripheral derivedFrom="USART2"><name>USART3</name></peripheral></peripherals>',
    )
    result = parse_svd(source, "x")
    assert result.status == "partial"
    assert result.device is not None and len(result.device.peripherals) == 1
    assert any("Derived" in item for item in result.limitations)


def test_text_and_source_labels_are_bounded() -> None:
    assert parse_svd(VALID, "x" * 1025).status == "invalid"
    assert parse_svd(VALID.replace(b"Example", b"x" * 1025), "x").status == "invalid"

import pytest
from xml.parsers import expat

from vigil_fuse.xml_safety import XmlSafetyError, preflight_xml


@pytest.mark.parametrize(
    "encoding,bom",
    [
        ("utf-8", b""),
        ("utf-8", b"\xef\xbb\xbf"),
        ("utf-16-le", b"\xff\xfe"),
        ("utf-16-be", b"\xfe\xff"),
        ("utf-32-le", b"\xff\xfe\x00\x00"),
        ("utf-32-be", b"\x00\x00\xfe\xff"),
    ],
)
def test_preflight_rejects_dtd_and_entity_declarations_across_encodings(
    encoding: str, bom: bytes
) -> None:
    source = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x "value">]><root>&x;</root>'
    data = bom + source.encode(encoding)

    with pytest.raises((XmlSafetyError, expat.ExpatError)):
        preflight_xml(data, max_bytes=1024)


def test_preflight_accepts_utf8_bom_without_dtd() -> None:
    preflight_xml(b"\xef\xbb\xbf<root/>", max_bytes=1024)


def test_preflight_enforces_aggregate_attribute_and_text_quotas() -> None:
    with pytest.raises(XmlSafetyError, match="attribute count"):
        preflight_xml(b"<root a='1' b='2'/>", max_bytes=1024, max_attributes=1)

    with pytest.raises(XmlSafetyError, match="text exceeds"):
        preflight_xml(b"<root>four</root>", max_bytes=1024, max_text_chars=3)


def test_preflight_enforces_byte_element_and_depth_quotas() -> None:
    with pytest.raises(XmlSafetyError, match="byte limit"):
        preflight_xml(b"<root/>", max_bytes=4)

    with pytest.raises(XmlSafetyError, match="element count"):
        preflight_xml(b"<root><child/></root>", max_bytes=1024, max_elements=1)

    with pytest.raises(XmlSafetyError, match="nesting"):
        preflight_xml(b"<root><child/></root>", max_bytes=1024, max_depth=1)

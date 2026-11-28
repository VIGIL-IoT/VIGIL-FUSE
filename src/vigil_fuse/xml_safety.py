"""Encoding-aware, bounded XML preflight for untrusted project metadata."""

from __future__ import annotations

from xml.parsers import expat

MAX_XML_ELEMENTS = 100_000
MAX_XML_DEPTH = 128
MAX_XML_ATTRIBUTES = 200_000
MAX_XML_TEXT_CHARS = 5_000_000


class XmlSafetyError(ValueError):
    """Raised when XML violates a parser safety limit or contains a DTD."""


def preflight_xml(
    data: bytes,
    *,
    max_bytes: int,
    max_elements: int = MAX_XML_ELEMENTS,
    max_depth: int = MAX_XML_DEPTH,
    max_attributes: int = MAX_XML_ATTRIBUTES,
    max_text_chars: int = MAX_XML_TEXT_CHARS,
) -> None:
    """Parse bytes with Expat quotas before constructing an ElementTree."""
    if len(data) > max_bytes:
        raise XmlSafetyError(f"XML input exceeds the {max_bytes}-byte limit.")

    parser = expat.ParserCreate()
    depth = 0
    elements = 0
    attributes = 0
    text_chars = 0

    def start(_name: str, values: dict[str, str]) -> None:
        nonlocal depth, elements, attributes
        depth += 1
        elements += 1
        attributes += len(values)
        if depth > max_depth:
            raise XmlSafetyError(f"XML nesting exceeds the {max_depth}-element limit.")
        if elements > max_elements:
            raise XmlSafetyError(f"XML element count exceeds the {max_elements}-element limit.")
        if attributes > max_attributes:
            raise XmlSafetyError(
                f"XML attribute count exceeds the {max_attributes}-attribute limit."
            )

    def end(_name: str) -> None:
        nonlocal depth
        depth -= 1

    def text(value: str) -> None:
        nonlocal text_chars
        text_chars += len(value)
        if text_chars > max_text_chars:
            raise XmlSafetyError(f"XML text exceeds the {max_text_chars}-character limit.")

    def reject_doctype(*_args: object) -> None:
        raise XmlSafetyError("DTD and entity declarations are not accepted.")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    parser.StartDoctypeDeclHandler = reject_doctype
    parser.EntityDeclHandler = reject_doctype
    parser.ExternalEntityRefHandler = lambda *_args: 0
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.Parse(data, True)

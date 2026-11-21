from __future__ import annotations

import json
import math
import re
import unicodedata
from typing import Any

MAX_RESPONSE_BYTES = 24_000
MAX_ITEMS = 8


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("Non-finite JSON number")


def _float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Non-finite JSON number")
    return result


def strict_json(raw: bytes, limit: int = MAX_RESPONSE_BYTES) -> dict[str, Any]:
    if len(raw) > limit:
        raise ValueError("JSON exceeds byte limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_constant,
            parse_float=_float,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Invalid UTF-8 JSON object") from error
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError("Empty or oversized response string")
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        raise ValueError("Response contains control characters")
    return value


def _strings(value: Any, limit: int = 500) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError("Response array exceeds limit or has wrong type")
    return [_text(item, limit) for item in value]


# shortcut: lexical grounding cannot verify prose semantics, use human review for conclusions.
_IDENTIFIERS = re.compile(
    r"\b(?:FUSE(?:[-:][\w:./-]+|\d+(?::[\w:./-]+)?)|E\d+|(?:GPIO|UART|J|R|U|TP|C|D|L|Q|Y|X|K|SW|CN|P)\d+\b|CONFIG_[A-Z0-9_]+"
    r"|[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*|[a-zA-Z_]\w*_[a-zA-Z0-9_]+|[a-zA-Z_]\w*(?=\s*\())"
    r"|(?:[\w.-]+[/\\])+[\w.-]+"
    r"|\b[\w.-]+\.(?:c|h|cpp|hpp|py|rs|sv|v|toml|json|yaml|yml|elf|bin|kicad_sch|kicad_pcb|md|txt|ini|conf|dts|dtsi|s|sh|ps1|cmake)\b"
)


def identifiers(text: str) -> set[str]:
    return {match.group().rstrip(".,:;") for match in _IDENTIFIERS.finditer(text)}


def validate_response(raw: bytes, context: dict[str, Any]) -> dict[str, Any]:
    value = strict_json(raw)
    if set(value) != set(OUTPUT_SCHEMA["properties"]):
        raise ValueError("Response fields do not match reasoning_output_v1")
    prose = [_text(value["summary"], 600), _text(value["reasoning"], 1800)]
    for key in ("recommended_checks", "remediation", "limitations"):
        prose.extend(_strings(value[key]))
    missing = value["missing_evidence"]
    if not isinstance(missing, list) or len(missing) > MAX_ITEMS:
        raise ValueError("Invalid missing_evidence array")
    for item in missing:
        if not isinstance(item, dict) or set(item) != {"item", "importance"}:
            raise ValueError("Invalid missing_evidence fields")
        prose.append(_text(item["item"], 500))
        if item["importance"] not in ("high", "medium", "low"):
            raise ValueError("Invalid missing evidence importance")
    known_ids = {item["id"] for group in context["evidence"].values() for item in group}
    refs = _strings(value["evidence_ids"], 16)
    unknown = _strings(value["unknown_evidence_ids"], 16)
    expected_unknown = {item["id"] for item in context["evidence"]["unknown"]}
    if not refs or not set(refs) <= known_ids or len(set(refs)) != len(refs):
        raise ValueError("Ungrounded evidence IDs")
    if set(unknown) != expected_unknown or len(set(unknown)) != len(unknown):
        raise ValueError("Unknown evidence acknowledgements do not match context")
    if expected_unknown and (not missing or not value["limitations"]):
        raise ValueError("Unknown evidence requires missing evidence and limitations")

    # Only string values, not schema keys, form the grounding vocabulary.
    def strings(node: Any) -> list[str]:
        if isinstance(node, str):
            return [node]
        if isinstance(node, dict):
            return [text for child in node.values() for text in strings(child)]
        if isinstance(node, list):
            return [text for child in node for text in strings(child)]
        return []

    allowed = identifiers(" ".join(strings(context)))
    if identifiers(" ".join(prose)) - allowed:
        raise ValueError("Explanation references unsupported identifiers")
    return value


def _array(item: dict[str, Any]) -> dict[str, Any]:
    return {"type": "array", "items": item, "maxItems": MAX_ITEMS}


OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string", "minLength": 1, "maxLength": 600},
        "reasoning": {"type": "string", "minLength": 1, "maxLength": 1800},
        "missing_evidence": _array(
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "item": {"type": "string", "minLength": 1, "maxLength": 500},
                    "importance": {"enum": ["high", "medium", "low"]},
                },
                "required": ["item", "importance"],
            }
        ),
        **{
            key: _array({"type": "string", "minLength": 1, "maxLength": 500})
            for key in ("recommended_checks", "remediation", "limitations")
        },
        **{
            key: _array({"type": "string", "minLength": 1, "maxLength": 16})
            for key in ("evidence_ids", "unknown_evidence_ids")
        },
    },
}
OUTPUT_SCHEMA["required"] = list(OUTPUT_SCHEMA["properties"])

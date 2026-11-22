from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Sequence

from .analyzer_runtime import (
    AnalyzerOutputLimitError,
    analyzer_sandbox_active,
    inspect_tool_version,
    run_bounded_host_tool,
)
from .model import AnalyzerStatus, Finding, HardwareArtifact, RTLAnalysis, Severity, SourceFile
from .path_safety import resolve_inside_directory

RTL_SUFFIXES = frozenset({".v", ".vh", ".sv", ".svh"})
_RTL_MAX_FILES = 200
_RTL_MAX_FILE_BYTES = 2 * 1024 * 1024
_RTL_MAX_TOKENS = 200_000
_RTL_MAX_ITEMS = 100
_RTL_MAX_UNITS = 500
_RTL_MAX_EVIDENCE = 200
_VERIBLE_TIMEOUT_SECONDS = 5
_VERIBLE_OUTPUT_BYTES = 4 * 1024 * 1024
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_NUMBER = re.compile(r"^(?:\d[\d_]*(?:'[sS]?[bBoOdDhH][\da-fA-F_xXzZ?]+)?|'[01xXzZ])$")
_DEBUG_WORD = re.compile(
    r"(?:^|[_-])(?:debug|jtag|test|scan|bypass|unlock|maintenance)(?=$|[_-])",
    re.IGNORECASE,
)
_CONTROL_WORD = re.compile(
    r"(?:^|[_-])(?:debug|jtag|test|scan|bypass|unlock|maintenance|"
    r"(?:security|auth)_(?:disable|disabled|lock|locked|bypass|enable|enabled)|"
    r"disable_(?:security|auth))(?=$|[_-])",
    re.IGNORECASE,
)
_SECRET_WORD = re.compile(
    r"(?:^|[_-])(?:key|password|passwd|secret|token|credential)(?=$|[_-])|"
    r"(?:^|[_-])(?:auth|authentication|security)[_-](?:code|pin)(?=$|[_-])",
    re.IGNORECASE,
)
_UNLOCK_WORD = re.compile(r"(?:^|[_-])unlock(?=$|[_-])", re.IGNORECASE)
_UNLOCK_MATERIAL = re.compile(
    r"(?:^|[_-])(?:hardcoded|magic|value|constant|code|key|token|password|secret|word)(?=$|[_-])",
    re.IGNORECASE,
)
_SECURITY_WORD = re.compile(
    r"(?:^|[_-])(?:key|password|passwd|secret|token|credential|auth|authentication|"
    r"unlock|security|debug|bypass|scan)(?=$|[_-])",
    re.IGNORECASE,
)
_RESET_WORD = re.compile(r"reset|rst|por|preset|nrst|clear", re.IGNORECASE)
_CLOCK_WORD = re.compile(r"clock|clk", re.IGNORECASE)
_STATE_WORD = re.compile(r"state|mode", re.IGNORECASE)
_KEYWORDS = frozenset(
    "always always_comb always_ff always_latch and assign automatic begin buf case casez casex "
    "cell config deassign default defparam design disable edge else end endcase endfunction "
    "endgenerate endinterface endmodule endpackage endprogram endtask enum event for force "
    "foreach forever fork function generate genvar if initial inout input integer interface "
    "join localparam logic macromodule module nand negedge nmos nor not or output package "
    "parameter posedge primitive program pull0 pull1 real realtime reg release repeat return "
    "rnmos rpmos rtran rtranif0 rtranif1 signed small specparam static string supply0 supply1 "
    "table task time tran tranif0 tranif1 tri tri0 tri1 triand trior trireg unsigned use var "
    "wait wand weak0 weak1 while wire wor xnor xor".split()
)
_TYPE_WORDS = frozenset(
    "bit byte chandle integer int logic longint reg shortint signed string time tri unsigned "
    "var wire real".split()
)
_RULES = {
    "rtl-hardcoded-security-material": "FUSE-RTL-001",
    "rtl-debug-control": "FUSE-RTL-002",
    "rtl-permissive-control": "FUSE-RTL-003",
    "rtl-permissive-reset": "FUSE-RTL-004",
}


@dataclass(frozen=True)
class _Token:
    value: str
    line: int
    kind: str
    conditional: bool = False


def inspect_rtl_backend() -> tuple[str, str, str, str]:
    """Return availability, backend, version, and optional Verible state for doctor."""
    executable = shutil.which("verible-verilog-syntax")
    if executable is None:
        return (
            "AVAILABLE",
            "FUSE structural parser (Verible unavailable)",
            "builtin-1",
            "UNAVAILABLE",
        )
    version = inspect_tool_version(executable) or "version unavailable"
    return (
        "AVAILABLE",
        "Verible token parser + FUSE structural extraction",
        version,
        "AVAILABLE",
    )


def _kind(value: str) -> str:
    if value.startswith("`"):
        return "directive"
    if value.startswith(('"', "'")) and not _NUMBER.fullmatch(value):
        return "string"
    if _NUMBER.fullmatch(value) or value.isdecimal():
        return "number"
    if _IDENTIFIER.fullmatch(value):
        return "identifier"
    return "symbol"


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    index = 0
    line = 1
    operators = (
        "<<<",
        ">>>",
        "===",
        "!==",
        "<<",
        ">>",
        "<=",
        ">=",
        "==",
        "!=",
        "&&",
        "||",
        "::",
        "->",
        "=>",
        "++",
        "--",
        "**",
        "+:",
        "-:",
    )
    while index < len(text):
        char = text[index]
        if char in " \t\r\f\v":
            index += 1
            continue
        if char == "\n":
            line += 1
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            line += text.count("\n", index, end)
            index = end
            continue
        if char == '"':
            start, start_line = index, line
            index += 1
            escaped = False
            while index < len(text):
                current = text[index]
                if current == "\n":
                    line += 1
                if current == '"' and not escaped:
                    index += 1
                    break
                escaped = current == "\\" and not escaped
                if current != "\\":
                    escaped = False
                index += 1
            value = text[start:index]
            tokens.append(_Token(value, start_line, "string"))
            continue
        if (
            char == "`"
            and index + 1 < len(text)
            and (text[index + 1].isalpha() or text[index + 1] == "_")
        ):
            start = index
            index += 2
            while index < len(text) and (text[index].isalnum() or text[index] == "_"):
                index += 1
            value = text[start:index]
            tokens.append(_Token(value, line, "directive"))
            continue
        if char == "\\":
            start = index
            index += 1
            while index < len(text) and not text[index].isspace():
                index += 1
            value = text[start:index].lstrip("\\")
            tokens.append(_Token(value, line, "identifier"))
            continue
        if char.isalpha() or char in "_$":
            start = index
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in "_$"):
                index += 1
            value = text[start:index]
            tokens.append(_Token(value, line, _kind(value)))
            continue
        if char.isdigit() or (
            char == "'" and index + 1 < len(text) and text[index + 1] in "01xXzZ"
        ):
            start = index
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in "_?'"):
                index += 1
            value = text[start:index]
            tokens.append(_Token(value, line, "number"))
            continue
        operator = next((item for item in operators if text.startswith(item, index)), char)
        tokens.append(_Token(operator, line, "symbol"))
        index += len(operator)
        if len(tokens) >= _RTL_MAX_TOKENS:
            break
    return tokens


def _verible_tokens(
    executable: str, source_text: str, suffix: str, index: int, timeout_seconds: int
) -> tuple[list[_Token] | None, int, str | None]:
    try:
        with tempfile.TemporaryDirectory(prefix="fuse-rtl-") as temporary:
            path = Path(temporary) / f"input-{index}{suffix}"
            path.write_text(source_text, encoding="utf-8")
            result = run_bounded_host_tool(
                [
                    executable,
                    "--lang=auto",
                    "--export_json",
                    "--printtokens",
                    "--printtree",
                    str(path),
                ],
                timeout=max(1, min(_VERIBLE_TIMEOUT_SECONDS, timeout_seconds)),
                output_limit_bytes=_VERIBLE_OUTPUT_BYTES,
            )
    except (OSError, subprocess.TimeoutExpired, AnalyzerOutputLimitError) as error:
        return None, 0, type(error).__name__
    try:
        document = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return None, 0, "invalid-json"
    if not isinstance(document, dict):
        return None, 0, "invalid-json"
    parsed = document.get(str(path))
    if not isinstance(parsed, dict):
        parsed = next(
            (
                value
                for key, value in document.items()
                if Path(str(key)).name == path.name and isinstance(value, dict)
            ),
            None,
        )
    if not isinstance(parsed, dict) or not isinstance(parsed.get("tokens"), list):
        return None, 0, "tokens-unavailable"

    encoded = source_text.encode("utf-8")
    line_offsets = [0]
    line_offsets.extend(i + 1 for i, byte in enumerate(encoded) if byte == 10)
    tokens: list[_Token] = []
    for record in parsed["tokens"]:
        if not isinstance(record, dict):
            continue
        start = record.get("start")
        end = record.get("end")
        value = record.get("text")
        if not isinstance(value, str) and isinstance(start, int) and isinstance(end, int):
            value = encoded[start:end].decode("utf-8", errors="replace")
        if not isinstance(value, str) or not value:
            continue
        byte_offset = start if isinstance(start, int) else 0
        tag = record.get("tag")
        token_kind = (
            "directive" if isinstance(tag, str) and "directive" in tag.casefold() else _kind(value)
        )
        tokens.append(
            _Token(
                value=value,
                line=bisect_right(line_offsets, max(0, byte_offset)),
                kind=token_kind,
            )
        )
        if len(tokens) >= _RTL_MAX_TOKENS:
            break
    raw_errors = parsed.get("errors")
    error_count = len(raw_errors) if isinstance(raw_errors, list) else 0
    return tokens, error_count, "syntax-errors" if error_count or result.returncode else None


def _matching(tokens: Sequence[_Token], start: int, opening: str, closing: str) -> int | None:
    if start >= len(tokens) or tokens[start].value != opening:
        return None
    depth = 1
    for index in range(start + 1, len(tokens)):
        value = tokens[index].value
        if value == opening:
            depth += 1
        elif value == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _split(tokens: Sequence[_Token], separator: str) -> list[list[_Token]]:
    result: list[list[_Token]] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0}
    closes = {")": "(", "]": "[", "}": "{"}
    for index, token in enumerate(tokens):
        value = token.value
        if value in depths:
            depths[value] += 1
        elif value in closes:
            opener = closes[value]
            depths[opener] = max(0, depths[opener] - 1)
        elif value == separator and not any(depths.values()):
            result.append(list(tokens[start:index]))
            start = index + 1
    result.append(list(tokens[start:]))
    return result


def _identifier(token: _Token) -> bool:
    return token.kind == "identifier" and token.value.casefold() not in _KEYWORDS


def _end_at_semicolon(tokens: Sequence[_Token], start: int) -> int:
    depths = {"(": 0, "[": 0, "{": 0}
    closes = {")": "(", "]": "[", "}": "{"}
    for index in range(start, len(tokens)):
        value = tokens[index].value
        if value in depths:
            depths[value] += 1
        elif value in closes:
            opener = closes[value]
            depths[opener] = max(0, depths[opener] - 1)
        elif value == ";" and not any(depths.values()):
            return index
    return len(tokens)


def _truthy_literal(value: str) -> bool:
    normalized = value.casefold().replace("_", "")
    if normalized in {"1", "'1", "1'b1", "1'h1", "1'd1", "true"}:
        return True
    match = re.fullmatch(r"\d+'(?:s)?[bBoOdDhH]([0-9a-fA-F]+)", normalized)
    if match:
        digits = match.group(1)
        base = {"b": 2, "o": 8, "d": 10, "h": 16}[
            normalized[normalized.index("'") + 1 :].lstrip("s")[:1]
        ]
        try:
            return int(digits, base) != 0
        except ValueError:
            return False
    return False


def _false_literal(value: str) -> bool:
    normalized = value.casefold().replace("_", "")
    if normalized in {"0", "'0", "1'b0", "1'd0", "1'h0", "false"}:
        return True
    match = re.fullmatch(r"\d+'(?:s)?[bBoOdDhH]([0-9a-fA-F]+)", normalized)
    if not match:
        return False
    base = {"b": 2, "o": 8, "d": 10, "h": 16}[
        normalized[normalized.index("'") + 1 :].lstrip("s")[:1]
    ]
    try:
        return int(match.group(1), base) == 0
    except ValueError:
        return False


def _permissive(value: str) -> bool:
    normalized = value.casefold().replace("_", "")
    if _truthy_literal(normalized):
        return True
    if re.search(
        r"locked|disabled|denied|closed|false|unauthorized|restricted|inactive|off", normalized
    ):
        return False
    return bool(re.search(r"unlocked|open|enabled|authorized|privileged|bypass|allow", normalized))


def _permissive_control(signal: str, value: str) -> bool:
    if re.search(
        r"(?:^|[_-])(?:disable|disabled|lock|locked|deny|denied|closed|restricted|inactive|off)(?:$|[_-])",
        signal,
        re.IGNORECASE,
    ):
        return _false_literal(value)
    return _permissive(value)


def _secret_context(signal: str, *, comparison: bool = False) -> bool:
    return bool(
        _SECRET_WORD.search(signal)
        or (
            _UNLOCK_WORD.search(signal)
            and (
                _UNLOCK_MATERIAL.search(signal)
                or (comparison and signal.casefold().strip("_-") == "unlock")
            )
        )
    )


def _constant_expression(values: Sequence[_Token]) -> bool:
    return len(values) == 1 and values[0].kind in {"number", "string"}


def _assignments(tokens: Sequence[_Token]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    paren_depth = 0
    for index, token in enumerate(tokens):
        if token.value in {"(", "[", "{"}:
            paren_depth += 1
            continue
        if token.value in {")", "]", "}"}:
            paren_depth = max(0, paren_depth - 1)
            continue
        if (
            paren_depth
            or token.value not in {"=", "<="}
            or index == 0
            or not _identifier(tokens[index - 1])
        ):
            continue
        end = index + 1
        depths = {"(": 0, "[": 0, "{": 0}
        closes = {")": "(", "]": "[", "}": "{"}
        while end < len(tokens):
            value = tokens[end].value
            if value in depths:
                depths[value] += 1
            elif value in closes:
                opener = closes[value]
                depths[opener] = max(0, depths[opener] - 1)
            elif value in {";", ",", "end", "else", "endcase"} and not any(depths.values()):
                break
            end += 1
        expression = list(tokens[index + 1 : end])
        if not expression:
            continue
        result.append(
            {
                "signal": tokens[index - 1].value,
                "operator": token.value,
                "line": tokens[index - 1].line,
                "value_kind": "literal" if _constant_expression(expression) else "expression",
                "conditional": any(item.conditional for item in tokens[index - 1 : end]),
                "_rhs": expression,
            }
        )
    return result[:_RTL_MAX_ITEMS]


def _module_units(tokens: Sequence[_Token], limit: int) -> tuple[list[dict[str, object]], int]:
    units: list[dict[str, object]] = []
    omitted = 0
    terminators = {
        "module": "endmodule",
        "macromodule": "endmodule",
        "interface": "endinterface",
        "package": "endpackage",
        "program": "endprogram",
    }
    index = 0
    while index < len(tokens):
        kind = tokens[index].value.casefold()
        end_word = terminators.get(kind)
        if end_word is None:
            index += 1
            continue
        name_index = index + 1
        while name_index < len(tokens) and tokens[name_index].value in {"automatic", "static"}:
            name_index += 1
        if name_index >= len(tokens) or not _identifier(tokens[name_index]):
            index += 1
            continue
        end_index = name_index + 1
        while end_index < len(tokens) and tokens[end_index].value.casefold() != end_word:
            end_index += 1
        if end_index >= len(tokens):
            end_index = len(tokens)
        header_end = _end_at_semicolon(tokens, name_index + 1)
        header = list(tokens[name_index + 1 : header_end])
        body = list(tokens[header_end + 1 : end_index])
        if len(units) < limit:
            units.append(
                {
                    "kind": "module" if kind in {"module", "macromodule"} else kind,
                    "name": tokens[name_index].value,
                    "line": tokens[index].line,
                    "header": header,
                    "body": body,
                }
            )
        else:
            omitted += 1
        index = min(end_index + 1, len(tokens))
    return units, omitted


def _ports(header: Sequence[_Token], body: Sequence[_Token]) -> list[dict[str, str]]:
    port_open = None
    index = 0
    while index < len(header):
        if header[index].value == "(" and (index == 0 or header[index - 1].value != "#"):
            port_open = index
            break
        if header[index].value == "(" and index > 0 and header[index - 1].value == "#":
            closing = _matching(header, index, "(", ")")
            index = closing + 1 if closing is not None else len(header)
            continue
        index += 1
    ports: dict[str, str] = {}
    if port_open is not None:
        closing = _matching(header, port_open, "(", ")")
        if closing is not None:
            direction = "unknown"
            for piece in _split(header[port_open + 1 : closing], ","):
                found_direction = next(
                    (
                        token.value.casefold()
                        for token in piece
                        if token.value.casefold() in {"input", "output", "inout"}
                    ),
                    None,
                )
                if found_direction is not None:
                    direction = found_direction
                names = [
                    token.value
                    for token in piece
                    if _identifier(token) and token.value.casefold() not in _TYPE_WORDS
                ]
                if names:
                    ports[names[-1]] = direction

    index = 0
    while index < len(body):
        direction = body[index].value.casefold()
        if direction not in {"input", "output", "inout"}:
            index += 1
            continue
        end = _end_at_semicolon(body, index)
        for piece in _split(body[index + 1 : end], ","):
            names = [
                token.value
                for token in piece
                if _identifier(token) and token.value.casefold() not in _TYPE_WORDS
            ]
            if names:
                ports[names[-1]] = direction
        index = end + 1
    return [{"name": name, "direction": direction} for name, direction in sorted(ports.items())][
        :_RTL_MAX_ITEMS
    ]


def _parameters(tokens: Sequence[_Token]) -> list[str]:
    names: list[str] = []
    index = 0
    while index < len(tokens):
        if tokens[index].value.casefold() not in {"parameter", "localparam"}:
            index += 1
            continue
        end = index + 1
        while end < len(tokens) and tokens[end].value not in {";", ")"}:
            end += 1
        for piece in _split(tokens[index + 1 : end], ","):
            equal = next((i for i, token in enumerate(piece) if token.value == "="), len(piece))
            identifiers = [
                token.value
                for token in piece[:equal]
                if _identifier(token) and token.value.casefold() not in _TYPE_WORDS
            ]
            if identifiers and identifiers[-1] not in names:
                names.append(identifiers[-1])
        index = end + 1
    return names[:_RTL_MAX_ITEMS]


def _instances(
    tokens: Sequence[_Token], known_keywords: frozenset[str]
) -> tuple[list[dict[str, object]], set[str]]:
    instances: list[dict[str, object]] = []
    types: set[str] = set()
    index = 0
    while index < len(tokens) - 3:
        module_type = tokens[index]
        if not _identifier(module_type) or module_type.value.casefold() in known_keywords:
            index += 1
            continue
        name_index = index + 1
        if tokens[name_index].value == "#":
            if name_index + 1 >= len(tokens) or tokens[name_index + 1].value != "(":
                index += 1
                continue
            closing = _matching(tokens, name_index + 1, "(", ")")
            if closing is None:
                index += 1
                continue
            name_index = closing + 1
        if (
            name_index + 1 >= len(tokens)
            or not _identifier(tokens[name_index])
            or tokens[name_index + 1].value != "("
        ):
            index += 1
            continue
        closing = _matching(tokens, name_index + 1, "(", ")")
        if (
            closing is None
            or closing + 1 >= len(tokens)
            or tokens[closing + 1].value not in {";", ","}
        ):
            index += 1
            continue
        connections: list[dict[str, object]] = []
        for piece in _split(tokens[name_index + 2 : closing], ","):
            if (
                len(piece) >= 4
                and piece[0].value == "."
                and _identifier(piece[1])
                and piece[2].value == "("
            ):
                port_end = _matching(piece, 2, "(", ")")
                if port_end is not None:
                    connections.append(
                        {
                            "port": piece[1].value,
                            "signals": [
                                token.value for token in piece[3:port_end] if _identifier(token)
                            ],
                        }
                    )
        instances.append(
            {
                "type": module_type.value,
                "name": tokens[name_index].value,
                "line": module_type.line,
                "connections": connections[:_RTL_MAX_ITEMS],
            }
        )
        types.add(module_type.value)
        index = closing + 1
    return instances[:_RTL_MAX_ITEMS], types


def _always_blocks(tokens: Sequence[_Token]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    index = 0
    while index < len(tokens):
        kind = tokens[index].value.casefold()
        if kind not in {"always", "always_ff", "always_comb", "always_latch"}:
            index += 1
            continue
        sensitivity: list[dict[str, str]] = []
        event_index = index + 1
        while event_index < len(tokens) and tokens[event_index].value not in {"begin", ";"}:
            if tokens[event_index].value == "@":
                if event_index + 1 < len(tokens) and tokens[event_index + 1].value == "(":
                    closing = _matching(tokens, event_index + 1, "(", ")")
                    if closing is not None:
                        event_tokens = tokens[event_index + 2 : closing]
                        for edge_index, edge in enumerate(event_tokens[:-1]):
                            if edge.value.casefold() in {"posedge", "negedge"} and _identifier(
                                event_tokens[edge_index + 1]
                            ):
                                sensitivity.append(
                                    {
                                        "signal": event_tokens[edge_index + 1].value,
                                        "edge": edge.value.casefold(),
                                    }
                                )
                        event_index = closing + 1
                        continue
                elif event_index + 1 < len(tokens) and _identifier(tokens[event_index + 1]):
                    sensitivity.append({"signal": tokens[event_index + 1].value, "edge": "level"})
            event_index += 1
        clocks: list[str] = []
        resets: list[dict[str, str]] = []
        for item in sensitivity:
            signal = item["signal"]
            if _RESET_WORD.search(signal) or (len(sensitivity) > 1 and item["edge"] == "negedge"):
                resets.append(
                    {
                        "signal": signal,
                        "polarity": "active-low" if item["edge"] == "negedge" else "active-high",
                    }
                )
            elif item["edge"] == "posedge" or _CLOCK_WORD.search(signal):
                clocks.append(signal)
        body: list[_Token] = []
        body_start = None
        for position in range(index + 1, len(tokens)):
            if tokens[position].value == "begin":
                body_start = position
                break
            if tokens[position].value == ";" or tokens[position].value.casefold() in {
                "always",
                "always_ff",
                "always_comb",
                "always_latch",
            }:
                break
        end_index = index
        if body_start is not None:
            depth = 1
            end_index = body_start + 1
            while end_index < len(tokens) and depth:
                if tokens[end_index].value == "begin":
                    depth += 1
                elif tokens[end_index].value == "end":
                    depth -= 1
                end_index += 1
            body = list(tokens[body_start + 1 : max(body_start + 1, end_index - 1)])
        else:
            end_index = _end_at_semicolon(tokens, index + 1) + 1
            body = list(tokens[index + 1 : end_index])
        result.append(
            {
                "kind": kind,
                "line": tokens[index].line,
                "sensitivity": sensitivity,
                "clock_signals": sorted(set(clocks)),
                "reset_signals": resets,
                "_body": body,
            }
        )
        index = max(index + 1, end_index)
    return result[:_RTL_MAX_ITEMS]


def _reset_assignments(block: dict[str, object]) -> list[dict[str, object]]:
    body = block.get("_body")
    resets = block.get("reset_signals")
    if not isinstance(body, list) or not isinstance(resets, list) or not resets:
        return []
    reset_polarities = {
        item["signal"]: item["polarity"]
        for item in resets
        if isinstance(item, dict)
        and isinstance(item.get("signal"), str)
        and isinstance(item.get("polarity"), str)
    }
    tokens = [token for token in body if isinstance(token, _Token)]
    result: list[dict[str, object]] = []
    index = 0
    while index < len(tokens):
        if (
            tokens[index].value.casefold() != "if"
            or index + 1 >= len(tokens)
            or tokens[index + 1].value != "("
        ):
            index += 1
            continue
        closing = _matching(tokens, index + 1, "(", ")")
        if closing is None:
            index += 1
            continue
        condition = tokens[index + 2 : closing]
        reset = None
        for condition_index, token in enumerate(condition):
            polarity = reset_polarities.get(token.value)
            if polarity is None:
                continue
            inverted = condition_index > 0 and condition[condition_index - 1].value in {"!", "~"}
            if (
                condition_index + 2 < len(condition)
                and condition[condition_index + 1].value in {"==", "==="}
                and condition[condition_index + 2].kind == "number"
            ):
                inverted = not _truthy_literal(condition[condition_index + 2].value)
            if inverted == (polarity == "active-low"):
                reset = token.value
                break
        if reset is None:
            index = closing + 1
            continue
        branch_start = closing + 1
        if branch_start < len(tokens) and tokens[branch_start].value == "begin":
            branch_end = branch_start + 1
            depth = 1
            while branch_end < len(tokens) and depth:
                if tokens[branch_end].value == "begin":
                    depth += 1
                elif tokens[branch_end].value == "end":
                    depth -= 1
                branch_end += 1
            branch = tokens[branch_start + 1 : max(branch_start + 1, branch_end - 1)]
        else:
            branch_end = _end_at_semicolon(tokens, branch_start) + 1
            branch = tokens[branch_start:branch_end]
        for assignment in _assignments(branch):
            reset_item = next(
                item for item in resets if isinstance(item, dict) and item.get("signal") == reset
            )
            result.append(
                {
                    **assignment,
                    "reset_signal": reset,
                    "polarity": reset_item["polarity"],
                }
            )
        index = max(index + 1, branch_end)
    return result[:_RTL_MAX_ITEMS]


def _state_machines(tokens: Sequence[_Token]) -> list[dict[str, object]]:
    machines: list[dict[str, object]] = []
    index = 0
    while index < len(tokens):
        if (
            tokens[index].value.casefold() not in {"case", "casez", "casex"}
            or index + 1 >= len(tokens)
            or tokens[index + 1].value != "("
        ):
            index += 1
            continue
        closing = _matching(tokens, index + 1, "(", ")")
        if closing is None:
            index += 1
            continue
        expression = [token for token in tokens[index + 2 : closing] if _identifier(token)]
        state_signal = expression[-1].value if expression else ""
        if not _STATE_WORD.search(state_signal):
            index = closing + 1
            continue
        end = next(
            (
                position
                for position in range(closing + 1, len(tokens))
                if tokens[position].value.casefold() == "endcase"
            ),
            len(tokens),
        )
        case_body = tokens[closing + 1 : end]
        labels: list[str] = []
        transitions: list[dict[str, str]] = []
        cursor = 0
        while cursor < len(case_body):
            colon = next(
                (
                    position
                    for position in range(cursor, len(case_body))
                    if case_body[position].value == ":"
                ),
                None,
            )
            if colon is None:
                break
            label = next(
                (token.value for token in case_body[cursor:colon] if _identifier(token)), None
            )
            next_colon = next(
                (
                    position
                    for position in range(colon + 1, len(case_body))
                    if case_body[position].value == ":"
                ),
                len(case_body),
            )
            item_body = case_body[colon + 1 : next_colon]
            if label and label.casefold() != "default" and label not in labels:
                labels.append(label)
            for assignment in _assignments(item_body):
                if assignment["signal"] == state_signal and label and label.casefold() != "default":
                    rhs = assignment.get("_rhs")
                    target = (
                        next(
                            (
                                token.value
                                for token in rhs
                                if isinstance(token, _Token) and _identifier(token)
                            ),
                            None,
                        )
                        if isinstance(rhs, list)
                        else None
                    )
                    if target:
                        transitions.append({"from": label, "to": target})
            cursor = max(colon + 1, next_colon)
        if len(labels) >= 2 and transitions:
            machines.append(
                {
                    "signal": state_signal,
                    "line": tokens[index].line,
                    "states": labels[:_RTL_MAX_ITEMS],
                    "transitions": transitions[:_RTL_MAX_ITEMS],
                }
            )
        index = end + 1
    return machines[:_RTL_MAX_ITEMS]


def _include_paths(tokens: Sequence[_Token]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for index, token in enumerate(tokens[:-1]):
        if token.kind == "directive" and token.value.lstrip("`").casefold() == "include":
            following = tokens[index + 1]
            if following.kind == "string":
                result.append({"path": following.value.strip('"'), "line": token.line})
    return result[:_RTL_MAX_ITEMS]


def _conditional_tokens(tokens: Sequence[_Token]) -> tuple[list[_Token], list[str]]:
    depth = 0
    result: list[_Token] = []
    macros: list[str] = []
    for index, token in enumerate(tokens):
        directive = token.value.lstrip("`").casefold() if token.kind == "directive" else ""
        if directive == "endif":
            depth = max(0, depth - 1)
        result.append(_Token(token.value, token.line, token.kind, depth > 0))
        if directive in {"ifdef", "ifndef"}:
            depth += 1
        if directive in {"ifdef", "ifndef", "elsif"} and index + 1 < len(tokens):
            macro = tokens[index + 1].value
            if macro not in macros:
                macros.append(macro)
    return result, macros[:_RTL_MAX_ITEMS]


def _sensitive_constant_evidence(
    file_path: str,
    module_name: str,
    unit_tokens: Sequence[_Token],
    assignments: Sequence[dict[str, object]],
) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for assignment in assignments:
        signal = assignment.get("signal")
        rhs = assignment.get("_rhs")
        if (
            isinstance(signal, str)
            and _secret_context(signal)
            and isinstance(rhs, list)
            and _constant_expression(rhs)
        ):
            events.append(
                {
                    "kind": "rtl-hardcoded-security-material",
                    "module": module_name,
                    "signal": signal,
                    "file": file_path,
                    "line": assignment["line"],
                    "evidence": {
                        "source": "fixed_literal",
                        "value": "[REDACTED]",
                        "conditional": bool(assignment.get("conditional")),
                    },
                }
            )
    for index, token in enumerate(unit_tokens):
        if (
            token.value not in {"==", "===", "!=", "!=="}
            or index == 0
            or index + 1 >= len(unit_tokens)
        ):
            continue
        left, right = unit_tokens[index - 1], unit_tokens[index + 1]
        pair: tuple[_Token, _Token] | None = None
        if (
            _identifier(left)
            and right.kind in {"number", "string"}
            and _secret_context(left.value, comparison=True)
        ):
            pair = (left, right)
        elif (
            _identifier(right)
            and left.kind in {"number", "string"}
            and _secret_context(right.value, comparison=True)
        ):
            pair = (right, left)
        if pair is None:
            continue
        signal, literal = pair
        conditional = signal.conditional or literal.conditional
        events.append(
            {
                "kind": "rtl-hardcoded-security-material",
                "module": module_name,
                "signal": signal.value,
                "file": file_path,
                "line": token.line,
                "evidence": {
                    "source": "fixed_comparison",
                    "operator": token.value,
                    "value": "[REDACTED]",
                    "conditional": conditional,
                },
            }
        )
    return events[:_RTL_MAX_ITEMS]


def _parse_unit(
    raw: dict[str, object], file_path: str, language: str
) -> tuple[dict[str, object], set[str], list[dict[str, object]], list[dict[str, object]]]:
    name = str(raw["name"])
    kind = str(raw["kind"])
    raw_header = raw.get("header")
    raw_body = raw.get("body")
    header = (
        [item for item in raw_header if isinstance(item, _Token)]
        if isinstance(raw_header, list)
        else []
    )
    body = (
        [item for item in raw_body if isinstance(item, _Token)]
        if isinstance(raw_body, list)
        else []
    )
    tokens = [*header, *body]
    ports = _ports(header, body) if kind in {"module", "interface", "program"} else []
    parameters = _parameters(tokens)
    assignments = _assignments(tokens)
    always = _always_blocks(body) if kind == "module" else []
    instances, instance_types = _instances(body, _KEYWORDS | _TYPE_WORDS)
    state_machines = _state_machines(body) if kind == "module" else []
    is_testbench = bool(
        re.search(r"(^|[/_.-])(?:tb|testbench)([/_.-]|$)|(?:_tb)$", file_path.casefold())
        or re.search(r"(^|_)(?:tb|testbench)(_|$)", name.casefold())
        or (
            kind == "module"
            and any(token.value.casefold() == "initial" for token in body)
            and any(_DEBUG_WORD.search(token.value) for token in body)
        )
    )
    port_by_name = {str(item["name"]): str(item["direction"]) for item in ports}
    debug_names: dict[str, dict[str, object]] = {}
    for token in tokens:
        if _identifier(token) and _DEBUG_WORD.search(token.value):
            direction = port_by_name.get(token.value, "internal")
            debug_names.setdefault(
                token.value,
                {
                    "name": token.value,
                    "direction": direction,
                    "line": token.line,
                    "conditional": token.conditional,
                },
            )
    clock_signals: set[str] = set()
    reset_signals: dict[str, str] = {}
    for block in always:
        raw_clocks = block.get("clock_signals")
        if isinstance(raw_clocks, list):
            clock_signals.update(signal for signal in raw_clocks if isinstance(signal, str))
        raw_resets = block.get("reset_signals")
        if isinstance(raw_resets, list):
            for reset in raw_resets:
                if isinstance(reset, dict):
                    signal = reset.get("signal")
                    polarity = reset.get("polarity")
                    if isinstance(signal, str) and isinstance(polarity, str):
                        reset_signals[signal] = polarity
    clocks = sorted(clock_signals)

    evidence = _sensitive_constant_evidence(file_path, name, tokens, assignments)
    for item in debug_names.values():
        evidence.append(
            {
                "kind": "rtl-debug-signal",
                "module": name,
                "signal": item["name"],
                "file": file_path,
                "line": item["line"],
                "evidence": {
                    "source": "external_port"
                    if item["direction"] in {"input", "inout"}
                    else "internal_signal",
                    "direction": item["direction"],
                    "conditional": item["conditional"],
                },
            }
        )
    controls: dict[str, list[str]] = {}
    external_debug = {
        str(item["name"])
        for item in ports
        if item["direction"] in {"input", "inout"} and _DEBUG_WORD.search(str(item["name"]))
    }
    for assignment in assignments:
        rhs = assignment.get("_rhs")
        lhs = str(assignment["signal"])
        if isinstance(rhs, list) and not assignment.get("conditional") and _DEBUG_WORD.search(lhs):
            names = [
                token.value for token in rhs if isinstance(token, _Token) and _identifier(token)
            ]
            for external in external_debug.intersection(names):
                controls.setdefault(external, []).append(lhs)
    for signal, names in controls.items():
        evidence.append(
            {
                "kind": "rtl-debug-control",
                "module": name,
                "signal": signal,
                "file": file_path,
                "line": debug_names[signal]["line"],
                "evidence": {"source": "external_port", "controls": sorted(set(names))},
            }
        )
    for assignment in assignments:
        signal = str(assignment["signal"])
        rhs = assignment.get("_rhs")
        if isinstance(rhs, list) and _CONTROL_WORD.search(signal) and _constant_expression(rhs):
            evidence.append(
                {
                    "kind": "rtl-security-control-constant",
                    "module": name,
                    "signal": signal,
                    "file": file_path,
                    "line": assignment["line"],
                    "evidence": {
                        "source": "constant_assignment",
                        "value": "[REDACTED]",
                        "conditional": bool(assignment.get("conditional")),
                    },
                }
            )
        if (
            isinstance(rhs, list)
            and _CONTROL_WORD.search(signal)
            and not assignment.get("conditional")
            and _constant_expression(rhs)
            and _permissive_control(signal, rhs[0].value)
        ):
            evidence.append(
                {
                    "kind": "rtl-permissive-control",
                    "module": name,
                    "signal": signal,
                    "file": file_path,
                    "line": assignment["line"],
                    "evidence": {"source": "constant_assignment", "value": "[REDACTED]"},
                }
            )
    reset_evidence: list[dict[str, object]] = []
    for block in always:
        raw_resets = block.get("reset_signals")
        if not isinstance(raw_resets, list):
            continue
        for reset in raw_resets:
            if not isinstance(reset, dict):
                continue
            event = {
                "kind": "rtl-reset-signal",
                "module": name,
                "signal": reset.get("signal", "unknown"),
                "file": file_path,
                "line": block.get("line", 1),
                "evidence": {
                    "polarity": reset.get("polarity", "unknown"),
                    "source": "always sensitivity",
                },
            }
            reset_evidence.append(event)
        for assignment in _reset_assignments(block):
            signal = str(assignment["signal"])
            rhs = assignment.get("_rhs")
            if not _SECURITY_WORD.search(signal) or not isinstance(rhs, list) or not rhs:
                continue
            default_state = rhs[0].value
            event = {
                "kind": "rtl-reset-security-state",
                "module": name,
                "signal": signal,
                "file": file_path,
                "line": assignment["line"],
                "evidence": {
                    "reset_signal": assignment["reset_signal"],
                    "polarity": assignment["polarity"],
                    "default_state": "[REDACTED]"
                    if rhs[0].kind in {"number", "string"}
                    else default_state,
                    "value_kind": "literal" if _constant_expression(rhs) else "state",
                    "conditional": bool(assignment.get("conditional")),
                },
            }
            evidence.append(event)
            if not assignment.get("conditional") and _permissive_control(signal, default_state):
                evidence.append(
                    {
                        "kind": "rtl-permissive-reset",
                        "module": name,
                        "signal": signal,
                        "file": file_path,
                        "line": assignment["line"],
                        "evidence": {
                            "reset_signal": assignment["reset_signal"],
                            "polarity": assignment["polarity"],
                            "default_state": "[REDACTED]"
                            if rhs[0].kind in {"number", "string"}
                            else default_state,
                        },
                    }
                )
    evidence.extend(reset_evidence)
    for machine in state_machines:
        evidence.append(
            {
                "kind": "rtl-state-machine",
                "module": name,
                "signal": machine["signal"],
                "file": file_path,
                "line": machine["line"],
                "evidence": {"states": machine["states"], "transitions": machine["transitions"]},
            }
        )

    public_assignments: list[dict[str, object]] = []
    for assignment in assignments:
        public_assignments.append(
            {key: value for key, value in assignment.items() if key != "_rhs"}
        )
    public_always = [
        {key: value for key, value in block.items() if key != "_body"} for block in always
    ]
    unit = {
        "kind": kind,
        "name": name,
        "file": file_path,
        "line": raw["line"],
        "testbench_candidate": is_testbench,
        "top_candidate": False,
        "language": language,
        "ports": ports,
        "parameters": parameters,
        "always_blocks": public_always,
        "assignments": public_assignments,
        "instances": instances,
        "clock_signals": clocks,
        "reset_signals": [
            {"signal": signal, "polarity": polarity}
            for signal, polarity in sorted(reset_signals.items())
        ],
        "debug_test_signals": list(debug_names.values())[:_RTL_MAX_ITEMS],
        "security_sensitive_constants": [
            {
                "signal": item["signal"],
                "line": item["line"],
                "value": "[REDACTED]",
                "conditional": item_evidence.get("conditional", False),
            }
            for item in evidence
            if item["kind"] == "rtl-hardcoded-security-material"
            and isinstance((item_evidence := item.get("evidence")), dict)
        ][:_RTL_MAX_ITEMS],
        "state_machines": state_machines,
    }
    return unit, instance_types, evidence, reset_evidence


def _yosys_metadata(
    sources: Sequence[SourceFile], root: Path, rtl_paths: set[str]
) -> tuple[dict[str, list[dict[str, object]]], list[str], bool]:
    included: dict[str, list[dict[str, object]]] = {}
    declared_tops: list[str] = []
    unresolved = False
    for source in sources:
        if Path(source.path).suffix.casefold() != ".ys":
            continue
        for line_number, line in enumerate(source.text.splitlines(), start=1):
            for statement in line.split(";"):
                statement = statement.partition("#")[0].strip()
                if not statement:
                    continue
                try:
                    words = shlex.split(statement, comments=True, posix=True)
                except ValueError:
                    unresolved = True
                    continue
                if not words:
                    continue
                command = words[0].casefold()
                if command == "hierarchy" and "-top" in words:
                    top_index = words.index("-top") + 1
                    if top_index < len(words) and words[top_index] not in declared_tops:
                        declared_tops.append(words[top_index])
                if command != "read_verilog":
                    continue
                index = 1
                while index < len(words):
                    word = words[index]
                    if word in {"-D", "-I"}:
                        index += 2
                        continue
                    if word.startswith("-"):
                        index += 1
                        continue
                    if "$" in word or "`" in word or "*" in word or "?" in word:
                        unresolved = True
                        index += 1
                        continue
                    try:
                        resolved, _ = resolve_inside_directory(root, Path(word))
                    except (OSError, ValueError):
                        index += 1
                        continue
                    if not resolved.is_file():
                        index += 1
                        continue
                    try:
                        relative = resolved.relative_to(root.resolve()).as_posix()
                    except ValueError:
                        index += 1
                        continue
                    if relative in rtl_paths:
                        included.setdefault(relative, []).append(
                            {"script": source.path, "line": line_number}
                        )
                    index += 1
    return included, declared_tops, unresolved


def _finding(event: dict[str, object]) -> Finding | None:
    kind = str(event["kind"])
    rule_id = _RULES.get(kind)
    if rule_id is None:
        return None
    evidence_data = event.get("evidence")
    if not isinstance(evidence_data, dict) or evidence_data.get("conditional") is True:
        return None
    signal = str(event.get("signal", "RTL signal"))
    file_path = str(event["file"])
    raw_line = event.get("line")
    if not isinstance(raw_line, int):
        return None
    line = raw_line
    if kind == "rtl-hardcoded-security-material":
        title = "Fixed security material appears in RTL"
        explanation = "A security-named signal is assigned or compared with a fixed literal. The value is redacted; this is a static candidate, not proof the design is built or reachable."
        impact = "A fixed unlock or credential value could allow unintended access if this logic is included and active."
        remediation = "Review the intended trust boundary and use a build or device-provisioned secret instead of a source literal."
        severity: Severity = "low"
    elif kind == "rtl-debug-control":
        title = "External input controls a debug path"
        explanation = "A debug-named input port is used by logic that drives a debug-named signal. This records a control path candidate only."
        impact = "An externally controlled debug path may expose privileged logic if enabled in the selected design."
        remediation = "Review the selected build, authorization gate, lifecycle policy, and physical interface before deciding whether to disable or protect the path."
        severity = "medium"
    elif kind == "rtl-permissive-control":
        title = "Security-related RTL control is tied permissive"
        explanation = "A debug, bypass, or related control is assigned a constant that appears permissive. Static evidence does not prove synthesis inclusion or runtime reachability."
        impact = "The fixed control may leave a debug or bypass path active if the assignment is included in the selected design."
        remediation = "Review the control's intended polarity and require an authenticated, lifecycle-aware source for privileged enablement."
        severity = "medium"
    else:
        title = "Security state resets to a permissive value"
        explanation = "A security-related register is assigned a permissive value in a reset branch. The parser does not prove state-machine correctness."
        impact = "Reset may place the design in a debug-enabled or otherwise permissive state if this logic is active."
        remediation = "Review the reset polarity and initialize security state to a locked or unprivileged value."
        severity = "medium"
    fingerprint = hashlib.sha256(f"{rule_id}\0{file_path}\0{line}\0{signal}".encode()).hexdigest()
    return Finding(
        id=f"{rule_id}:{file_path}:{line}",
        fingerprint=fingerprint,
        rule_id=rule_id,
        rule_version="1.0",
        analyzer="fuse-rtl-structural",
        title=title,
        severity=severity,
        confidence="medium",
        category="rtl-security",
        file=file_path,
        start_line=line,
        end_line=line,
        evidence=f"{signal}: {kind}; literal values redacted",
        explanation=explanation,
        potential_impact=impact,
        remediation=remediation,
        applicability="unknown",
        validation_method="static",
        validation_status="not-validated",
    )


def analyze_rtl(
    sources: Sequence[SourceFile],
    present_artifacts: Sequence[HardwareArtifact],
    root: Path,
    *,
    deadline: float,
) -> tuple[RTLAnalysis, tuple[Finding, ...], AnalyzerStatus | None]:
    present_paths = sorted(
        {
            item.path
            for item in present_artifacts
            if Path(item.path).suffix.casefold() in RTL_SUFFIXES
        },
        key=str.casefold,
    )
    related_files = tuple(
        {
            "path": item.path,
            "format": item.format,
            "role": "constraints" if "constraint" in item.format.casefold() else "project-metadata",
        }
        for item in present_artifacts
        if Path(item.path).suffix.casefold()
        in {".xdc", ".sdc", ".qsf", ".qpf", ".pcf", ".lpf", ".xpr", ".ys"}
    )
    if not present_paths:
        return RTLAnalysis(related_files=related_files), (), None

    source_by_path = {
        source.path: source
        for source in sources
        if Path(source.path).suffix.casefold() in RTL_SUFFIXES
    }
    yosys_sources = [source for source in sources if Path(source.path).suffix.casefold() == ".ys"]
    included, declared_tops, unresolved_yosys = _yosys_metadata(
        yosys_sources, root, set(present_paths)
    )
    executable = shutil.which("verible-verilog-syntax")
    use_verible = executable is not None and not analyzer_sandbox_active()
    version = inspect_tool_version(executable) if use_verible and executable else None
    backend = (
        "Verible token parser + FUSE structural extraction"
        if use_verible
        else "FUSE structural parser (Verible unavailable or sandboxed)"
    )
    parser_version = version or "builtin-1"
    limitations = [
        "No formal verification.",
        "No gate-level proof.",
        "No timing analysis.",
        "No physical FPGA proof.",
        "No runtime validation.",
        "Includes and conditional macros are inventoried but not expanded; conditional code is observation-only.",
        "Only literal Yosys read_verilog paths and hierarchy -top values are recognized; scripts are never executed.",
        "PRESENT means no explicit Yosys inclusion was observed; it does not prove exclusion from another build.",
    ]
    if not use_verible:
        limitations.append(
            "The built-in parser is a bounded structural fallback, not a complete Verilog/SystemVerilog compiler."
        )
    if unresolved_yosys:
        limitations.append(
            "Some Yosys script paths or expressions were dynamic or unsupported and could not be resolved."
        )

    all_units: list[dict[str, object]] = []
    files: list[dict[str, object]] = []
    events: list[dict[str, object]] = []
    findings: list[Finding] = []
    module_names: set[str] = set()
    instantiated_types: set[str] = set()
    packages = 0
    testbenches = 0
    parsed_files = 0
    omitted_units = 0
    omitted_evidence = 0
    parser_partial = not use_verible or unresolved_yosys or len(present_paths) > _RTL_MAX_FILES
    omitted_files = max(0, len(present_paths) - _RTL_MAX_FILES)
    if omitted_files:
        limitations.append(f"RTL file analysis was capped at {_RTL_MAX_FILES} files.")

    for index, file_path in enumerate(present_paths[:_RTL_MAX_FILES]):
        source = source_by_path.get(file_path)
        file_record: dict[str, object] = {
            "path": file_path,
            "language": "SystemVerilog"
            if Path(file_path).suffix.casefold() in {".sv", ".svh"}
            else "Verilog",
            "presence": "PRESENT",
            "build_status": "BUILD_INCLUDED" if file_path in included else "PRESENT",
            "build_sources": included.get(file_path, []),
            "selected": source is not None,
            "parse_status": "not-selected",
            "includes": [],
            "conditional_macros": [],
            "units": [],
        }
        if source is None:
            parser_partial = True
            files.append(file_record)
            continue
        if time.monotonic() >= deadline:
            parser_partial = True
            file_record["parse_status"] = "time-limit"
            files.append(file_record)
            continue
        if (
            source.byte_size > _RTL_MAX_FILE_BYTES
            or len(source.text.encode("utf-8")) > _RTL_MAX_FILE_BYTES
        ):
            parser_partial = True
            file_record["parse_status"] = "too-large"
            files.append(file_record)
            continue
        suffix = Path(file_path).suffix.casefold()
        tokens: list[_Token] | None = None
        syntax_errors = 0
        parser_error: str | None = None
        if use_verible and executable:
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds >= 1.0:
                tokens, syntax_errors, parser_error = _verible_tokens(
                    executable, source.text, suffix, index, int(remaining_seconds)
                )
            else:
                file_record["parse_status"] = "time-limit"
                parser_partial = True
                files.append(file_record)
                continue
        if tokens is None:
            tokens = _tokenize(source.text)
            if use_verible:
                parser_partial = True
                parser_error = parser_error or "fallback"
        if time.monotonic() >= deadline:
            parser_partial = True
            file_record["parse_status"] = "time-limit"
            files.append(file_record)
            continue
        if len(tokens) >= _RTL_MAX_TOKENS:
            tokens = tokens[:_RTL_MAX_TOKENS]
            parser_partial = True
            limitations.append(
                f"Token analysis for {file_path} reached the {_RTL_MAX_TOKENS}-token cap."
            )
        tokens, macros = _conditional_tokens(tokens)
        includes = _include_paths(tokens)
        if macros:
            parser_partial = True
        if syntax_errors:
            parser_partial = True
        if parser_error:
            parser_partial = True
        file_record.update(
            {
                "parse_status": "verible"
                if use_verible and parser_error is None
                else "structural-fallback",
                "syntax_error_count": syntax_errors,
                "conditional_macros": macros,
                "includes": includes,
            }
        )
        units_raw, file_omitted_units = _module_units(
            tokens, min(_RTL_MAX_ITEMS, max(0, _RTL_MAX_UNITS - len(all_units)))
        )
        if file_omitted_units:
            omitted_units += file_omitted_units
            parser_partial = True
        file_units: list[dict[str, object]] = []
        for raw in units_raw:
            unit, instance_types, unit_events, _ = _parse_unit(
                raw, file_path, str(file_record["language"])
            )
            file_units.append(unit)
            all_units.append(unit)
            instantiated_types.update(instance_types)
            evidence_room = max(0, _RTL_MAX_EVIDENCE - len(events))
            events.extend(unit_events[:evidence_room])
            omitted_evidence += max(0, len(unit_events) - evidence_room)
            if unit["kind"] == "module":
                module_names.add(str(unit["name"]))
                if unit["testbench_candidate"]:
                    testbenches += 1
            elif unit["kind"] == "package":
                packages += 1
        file_record["units"] = file_units[:_RTL_MAX_ITEMS]
        files.append(file_record)
        parsed_files += 1

    inferred_tops = sorted(
        str(unit["name"])
        for unit in all_units
        if unit["kind"] == "module"
        and unit["name"] not in instantiated_types
        and not unit["testbench_candidate"]
    )
    for unit in all_units:
        if unit["kind"] == "module":
            unit["top_candidate"] = unit["name"] in inferred_tops
    for event in events:
        if len(findings) >= _RTL_MAX_EVIDENCE:
            break
        finding = _finding(event)
        if finding is not None:
            findings.append(finding)
    if omitted_evidence:
        parser_partial = True
        limitations.append(f"RTL evidence was capped at {_RTL_MAX_EVIDENCE} records.")
    if omitted_units:
        limitations.append(
            f"RTL unit analysis was capped at {_RTL_MAX_UNITS} modules, interfaces, packages, or programs."
        )
    status: Literal["partial", "completed"] = "partial" if parser_partial else "completed"
    analysis = RTLAnalysis(
        status=status,
        backend=backend,
        version=parser_version,
        file_count=len(present_paths),
        module_count=sum(1 for unit in all_units if unit["kind"] == "module"),
        package_count=packages,
        testbench_count=testbenches,
        top_module_candidates=tuple(inferred_tops),
        declared_top_modules=tuple(declared_tops[:_RTL_MAX_ITEMS]),
        files=tuple(files),
        related_files=related_files,
        evidence=tuple(events[:_RTL_MAX_EVIDENCE]),
        omitted_files=omitted_files,
        omitted_units=omitted_units,
        omitted_evidence=omitted_evidence,
        limitations=tuple(dict.fromkeys(limitations)),
    )
    analyzer = AnalyzerStatus(
        name="rtl-security-analysis",
        status=status,
        version=parser_version,
        detail=f"Analyzed {parsed_files} of {len(source_by_path)} selected RTL file(s) with {backend}; static candidates require build and design review.",
        findings=len(findings),
    )
    return analysis, tuple(findings), analyzer

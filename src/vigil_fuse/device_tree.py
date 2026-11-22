"""Bounded, non-preprocessing inspection of literal device-tree source."""

from __future__ import annotations

from dataclasses import dataclass
import re

MAX_DTS_BYTES = 2 * 1024 * 1024
MAX_DTS_NODES = 10_000
MAX_DTS_DEPTH = 128
MAX_DTS_STATEMENTS = 50_000


@dataclass(frozen=True)
class DeviceTreeNode:
    path: str
    label: str | None
    properties: tuple[tuple[str, str], ...]

    def property(self, name: str) -> str | None:
        return next((value for key, value in self.properties if key == name), None)


@dataclass(frozen=True)
class DeviceTreeResult:
    status: str
    nodes: tuple[DeviceTreeNode, ...] = ()
    limitations: tuple[str, ...] = ()


def parse_device_tree(data: bytes) -> DeviceTreeResult:
    """Read literals only; references, overlays and preprocessing are not resolved."""
    if len(data) > MAX_DTS_BYTES:
        return DeviceTreeResult("invalid", limitations=("DTS byte limit exceeded",))
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return DeviceTreeResult("invalid", limitations=("DTS is not UTF-8",))

    preprocessing = bool(
        re.search(
            r"(?m)^[ \t]*#[ \t]*(?:include|define|if|ifdef|ifndef|elif|else|endif|undef)\b",
            text,
        )
    )
    # Preprocessor directives are not DTS properties and cannot be expanded safely.
    text = re.sub(
        r"(?m)^[ \t]*#[ \t]*(?:include|define|if|ifdef|ifndef|elif|else|endif|undef)\b[^\n]*",
        "",
        text,
    )

    # The lexer keeps strings intact and discards comments without interpreting them.
    tokens: list[tuple[str, str]] = []
    pending: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = len(text) if end == -1 else end
            pending.append(" ")
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                return DeviceTreeResult("invalid", limitations=("Unterminated comment",))
            i = end + 2
            pending.append(" ")
        elif text[i] == '"':
            start = i
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            if i >= len(text):
                return DeviceTreeResult("invalid", limitations=("Unterminated string",))
            i += 1
            pending.append(text[start:i])
        elif text[i] in "{};":
            if len(tokens) // 2 >= MAX_DTS_STATEMENTS:
                return DeviceTreeResult("invalid", limitations=("DTS statement limit exceeded",))
            tokens.append(("".join(pending).strip(), text[i]))
            pending.clear()
            i += 1
        else:
            pending.append(text[i])
            i += 1
    if "".join(pending).strip():
        return DeviceTreeResult("invalid", limitations=("Incomplete statement",))

    stack: list[tuple[str, str | None, list[tuple[str, str]]]] = []
    nodes: list[DeviceTreeNode] = []
    limitations: set[str] = set()
    if preprocessing:
        limitations.add("Preprocessor includes and conditions were not resolved.")
    for statement, delimiter in tokens:
        if delimiter == "{":
            if len(stack) >= MAX_DTS_DEPTH or len(nodes) + len(stack) >= MAX_DTS_NODES:
                return DeviceTreeResult("invalid", limitations=("DTS structure limit exceeded",))
            match = re.fullmatch(r"(?:(\w+)\s*:\s*)?([\w,._+@/\-]+)", statement)
            if not match:
                return DeviceTreeResult("partial", tuple(nodes), ("Unsupported node syntax",))
            label, name = match.groups()
            parent = stack[-1][0] if stack else ""
            path = "/" if name == "/" else parent.rstrip("/") + "/" + name
            stack.append((path, label, []))
        elif delimiter == "}":
            if statement or not stack:
                return DeviceTreeResult("invalid", limitations=("Unbalanced node",))
            path, label, properties = stack.pop()
            nodes.append(DeviceTreeNode(path, label, tuple(properties)))
        elif statement and statement != "/dts-v1/":
            if not stack:
                limitations.add("Top-level statement was not interpreted.")
                continue
            name, separator, value = statement.partition("=")
            name = name.strip()
            if not re.fullmatch(r"[\w,._+?#\-]+", name):
                limitations.add("Unsupported property syntax.")
                continue
            if "&" in value:
                limitations.add("Phandle references were recorded as text but not resolved.")
            # Uppercase tokens outside strings commonly name macros or constants.
            unquoted = re.sub(r'"(?:\\.|[^"\\])*"', '""', value)
            if re.search(r"\b[A-Z_][A-Z_0-9]*\b", unquoted):
                limitations.add("Macro or symbolic property values were not resolved.")
            stack[-1][2].append((name, value.strip() if separator else ""))
    if stack:
        return DeviceTreeResult("invalid", limitations=("Unclosed node",))
    if not nodes:
        return DeviceTreeResult("invalid", limitations=("No literal nodes found",))
    return DeviceTreeResult(
        "partial" if limitations else "parsed",
        tuple(sorted(nodes, key=lambda n: n.path)),
        tuple(sorted(limitations)),
    )

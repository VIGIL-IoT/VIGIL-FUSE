"""Conservative, bounded observations of selected critical C state."""

from __future__ import annotations

from dataclasses import dataclass
import re

from .c_source import mask_c
from .text_safety import safe_report_text

MAX_SEU_BYTES = 2 * 1024 * 1024
MAX_SEU_STATES = 512
MAX_SEU_LINE = 4096
MAX_SEU_CHECKS = 20_000
_DECLARATION = re.compile(
    r"\b(?:bool|_Bool|unsigned|int|int\d+_t|uint\d+_t|[A-Za-z_]\w*_t)\s+"
    r"([A-Za-z_]\w*)\s*(?=[=;,\[])"
)
_CRITICAL = re.compile(
    r"(?:flight.?mode|flight.?state|(?:^|_)arm(?:ed|ing)?(?:_|$)|watchdog|de.?orbit|"
    r"actuator.?enable|thruster|heater|power.?state|reset.?count|mission.?timer)",
    re.IGNORECASE,
)
_IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")


@dataclass(frozen=True)
class CriticalState:
    name: str
    line: int
    status: str
    confidence: str
    indicators: tuple[str, ...]


@dataclass(frozen=True)
class SeuResult:
    status: str
    states: tuple[CriticalState, ...]
    limitations: tuple[str, ...]


def inspect_critical_state(data: bytes) -> SeuResult:
    """Observe a narrow C declaration and same-line defense-pattern subset."""
    if len(data) > MAX_SEU_BYTES:
        return SeuResult("partial", (), ("C source byte limit exceeded.",))
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return SeuResult("partial", (), ("C source is not UTF-8.",))
    masked, complete = mask_c(text)
    limitations = {
        "Static patterns do not prove radiation safety or the effectiveness of a protection.",
        "Preprocessing, control flow, types, cross-file handling and hardware defenses are unresolved.",
    }
    if not complete:
        limitations.add("An unterminated comment or literal prevented complete inspection.")
    declarations: dict[str, int] = {}
    ambiguous: set[str] = set()
    truncated = not complete
    lines = masked.splitlines()
    for number, line in enumerate(lines, 1):
        if len(line) > MAX_SEU_LINE:
            limitations.add("At least one oversized source line was skipped.")
            truncated = True
            continue
        if line.lstrip().startswith("#"):
            continue
        for match in _DECLARATION.finditer(line):
            name = match.group(1)
            if not _CRITICAL.search(name):
                continue
            if name in declarations:
                limitations.add("Repeated state names may represent distinct scopes.")
                ambiguous.add(name)
                continue
            if len(declarations) >= MAX_SEU_STATES:
                limitations.add(
                    "Critical-state limit reached; remaining declarations were omitted."
                )
                truncated = True
                break
            declarations[name] = number
    indicators: dict[str, set[str]] = {name: set() for name in declarations}
    checks = 0
    for line_number, line in enumerate(lines, 1):
        if len(line) > MAX_SEU_LINE or line.lstrip().startswith("#"):
            continue
        names = set(_IDENTIFIER.findall(line)) & declarations.keys()
        for name in names:
            checks += 1
            if checks > MAX_SEU_CHECKS:
                limitations.add("State-use inspection limit reached; later uses were omitted.")
                truncated = True
                break
            escaped = re.escape(name)
            excerpt = safe_report_text(line.strip(), limit=200) or "source line"
            if re.search(
                rf"\b\w*(?:crc|checksum|parity|ecc)\w*\s*\([^;]*\b{escaped}\b",
                line,
                re.IGNORECASE,
            ):
                indicators[name].add(f"line {line_number}: checksum/parity call: {excerpt}")
            if re.search(r"\bif\s*\(", line) and re.search(rf"\b{escaped}\s*(?:<|>|<=|>=)", line):
                indicators[name].add(f"line {line_number}: bound comparison: {excerpt}")
            redundant = r"[A-Za-z_]\w*(?:backup|copy|redundant)\w*"
            if re.search(r"\bif\s*\(", line) and re.search(
                rf"(?:\b{escaped}\s*(?:==|!=)\s*{redundant}\b|"
                rf"\b{redundant}\s*(?:==|!=)\s*{escaped}\b)",
                line,
                re.IGNORECASE,
            ):
                indicators[name].add(f"line {line_number}: redundant-state comparison: {excerpt}")
        if checks > MAX_SEU_CHECKS:
            break
    states = tuple(
        CriticalState(
            name,
            line,
            "UNKNOWN"
            if name in ambiguous
            else "PROTECTION_OBSERVED"
            if indicators[name]
            else "PARTIAL"
            if truncated
            else "NO_PROTECTION_OBSERVED",
            "low",
            tuple(sorted(indicators[name])),
        )
        for name, line in sorted(declarations.items(), key=lambda item: (item[1], item[0]))
    )
    return SeuResult("partial", states, tuple(sorted(limitations)))

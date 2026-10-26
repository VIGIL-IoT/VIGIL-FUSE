from __future__ import annotations

import re
from collections.abc import Iterable

from ..model import Finding, SourceFile
from .base import RuleDefinition, is_kconfig_input_path, is_test_path, iter_code_lines

_SKIP_VALIDATION = re.compile(
    r"^\s*CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP\s*=\s*y\s*(?:#.*)?$"
)


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    if is_test_path(source.path) or not is_kconfig_input_path(source.path):
        return
    for line_number, line in iter_code_lines(source.text, source.path):
        if not _SKIP_VALIDATION.fullmatch(line):
            continue
        yield rule.finding(
            source,
            line_number,
            "CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP=y",
        )


RULE = RuleDefinition(
    id="FUSE007",
    title="ESP-IDF skips app-image validation after deep sleep",
    severity="medium",
    confidence="high",
    category="boot-integrity",
    explanation=(
        "A scanned Kconfig-style input explicitly enables CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP. "
        "Espressif documents that this skips normal image checks, including checksum, SHA-256, and "
        "signature validation, when resuming from deep sleep. If the active OTA partition is changed "
        "before that resume, the new image may skip its first validation. This finding does not prove "
        "that the file is active or that the device follows that OTA/deep-sleep path."
    ),
    potential_impact=(
        "If the setting and OTA/deep-sleep sequence are both active, a modified app image may avoid "
        "the normal validation step on its first boot after the partition change."
    ),
    remediation=(
        "Keep image validation enabled when deep-sleep workflows can follow OTA partition changes. "
        "Review Secure Boot settings and verify the effective sdkconfig used for release builds."
    ),
    scanner=_scan,
    version="1.1.0",
    references=(
        "https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/kconfig-reference.html",
    ),
)

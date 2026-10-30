from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import replace
from pathlib import PurePosixPath

from ..model import Finding, SourceFile
from .base import RuleDefinition, is_kconfig_input_path, is_test_path, iter_code_lines

_SKIP_VALIDATION = re.compile(
    r"^\s*CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP\s*=\s*y\s*(?:#.*)?$"
)
_GENERATED_HEADER = re.compile(
    r"^\s*#\s*define\s+CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP\s+1\s*(?:/\*.*\*/)?$"
)


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    basename = PurePosixPath(source.path.replace("\\", "/")).name.casefold()
    if (
        basename == "sdkconfig.ci"
        or is_test_path(source.path)
        or not (is_kconfig_input_path(source.path) or source.generated_config)
    ):
        return
    for line_number, line in iter_code_lines(source.text, source.path):
        if not (
            _SKIP_VALIDATION.fullmatch(line)
            or (source.generated_config and _GENERATED_HEADER.fullmatch(line))
        ):
            continue
        finding = rule.finding(
            source,
            line_number,
            "CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP=y",
        )
        if basename.startswith("sdkconfig.defaults") and not source.generated_config:
            finding = replace(finding, applicability="candidate")
        yield finding


RULE = RuleDefinition(
    id="FUSE007",
    title="ESP-IDF skips app-image validation after deep sleep",
    severity="medium",
    confidence="high",
    category="boot-integrity",
    explanation=(
        "A scanned Kconfig-style input or selected generated configuration explicitly enables "
        "CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP. "
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
    version="1.2.0",
    references=(
        "https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/kconfig-reference.html",
    ),
    prefilter=lambda source: source.generated_config or is_kconfig_input_path(source.path),
)

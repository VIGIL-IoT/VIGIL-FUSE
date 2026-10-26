from __future__ import annotations

import re
from collections.abc import Iterable

from ..model import Finding, SourceFile
from .base import RuleDefinition, is_comment_line

_SKIP_VALIDATION = re.compile(
    r"^\s*CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS\s*=\s*y\s*(?:#.*)?$"
)


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    for line_number, line in enumerate(source.text.splitlines(), start=1):
        if is_comment_line(line) or not _SKIP_VALIDATION.fullmatch(line):
            continue
        yield rule.finding(source, line_number, "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS=y")


RULE = RuleDefinition(
    id="FUSE006",
    title="ESP-IDF bootloader image validation is disabled",
    severity="medium",
    confidence="high",
    category="boot-integrity",
    explanation=(
        "A scanned Kconfig-style input explicitly enables CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS. "
        "ESP-IDF documents that this prevents the bootloader from validating the app image before "
        "booting it. This finding does not establish that the file is the active build configuration "
        "or that a built image is deployed."
    ),
    potential_impact=(
        "If this setting is active in a deployed build, a corrupted or modified app image may reach "
        "execution without the bootloader's normal image-validation step."
    ),
    remediation=(
        "Unset CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS unless a reviewed boot-time requirement justifies it. "
        "Verify the effective sdkconfig and resulting bootloader configuration for the release build."
    ),
    scanner=_scan,
    references=(
        "https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/kconfig-reference.html",
    ),
)

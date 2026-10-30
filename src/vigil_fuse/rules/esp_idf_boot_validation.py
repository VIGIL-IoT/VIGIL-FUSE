from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import replace
from pathlib import PurePosixPath

from ..model import Finding, SourceFile
from .base import RuleDefinition, is_kconfig_input_path, is_test_path, iter_code_lines

_SKIP_VALIDATION = re.compile(r"^\s*CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS\s*=\s*y\s*(?:#.*)?$")
_GENERATED_HEADER = re.compile(
    r"^\s*#\s*define\s+CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS\s+1\s*(?:/\*.*\*/)?$"
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
            "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS=y",
        )
        if basename.startswith("sdkconfig.defaults") and not source.generated_config:
            finding = replace(finding, applicability="candidate")
        yield finding


RULE = RuleDefinition(
    id="FUSE006",
    title="ESP-IDF bootloader image validation is disabled",
    severity="medium",
    confidence="high",
    category="boot-integrity",
    explanation=(
        "A scanned Kconfig-style input or selected generated configuration explicitly enables "
        "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS. "
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
    version="1.2.0",
    references=(
        "https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/kconfig-reference.html",
    ),
    prefilter=lambda source: source.generated_config or is_kconfig_input_path(source.path),
)

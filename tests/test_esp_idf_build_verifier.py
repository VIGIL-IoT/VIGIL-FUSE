from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.verify_esp_idf_build_context import build_report


def _build_fixture(root: Path, *, target: str = "esp32s3", version: str = "v5.5.6") -> None:
    build = root / "build"
    generated = build / "config"
    generated.mkdir(parents=True)
    (root / "CMakeLists.txt").write_text(
        "include($ENV{IDF_PATH}/tools/cmake/project.cmake)\nproject(hello_world)\n",
        encoding="utf-8",
    )
    (root / "sdkconfig").write_text(
        "# CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS is not set\n"
        "# CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP is not set\n",
        encoding="utf-8",
    )
    (root / "sdkconfig.defaults").write_text("CONFIG_LOG_DEFAULT_LEVEL=3\n", encoding="utf-8")
    (generated / "sdkconfig.h").write_text(
        f'#define CONFIG_IDF_TARGET "{target}"\n', encoding="utf-8"
    )
    (build / "project_description.json").write_text(
        json.dumps({"target": target, "git_revision": version}), encoding="utf-8"
    )
    (build / "CMakeCache.txt").write_text(
        f"SDKCONFIG:FILEPATH={root / 'sdkconfig'}\n"
        "SDKCONFIG_DEFAULTS:STRING=sdkconfig.defaults\n"
        f"IDF_TARGET:STRING={target}\n",
        encoding="utf-8",
    )


class EspIdfBuildVerifierTests(unittest.TestCase):
    def test_report_verifies_selected_version_target_and_secure_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            _build_fixture(project)

            report = build_report(
                project,
                expected_target="esp32s3",
                expected_version="v5.5.6",
                idf_commit="880a203ae603d08a94d06aa01e0d6761958e5e9e",
                image_digest="sha256:bf72fe7a15c22849a9a94147301165a545fb8905d97c176cf748e3e4614cac84",
                source_project="examples/get-started/hello_world",
            )

        self.assertEqual("passed", report["verification_status"])
        build = report["build"]
        assert isinstance(build, dict)
        self.assertEqual("esp32s3", build["target_observed"])
        self.assertEqual("sdkconfig", build["selected_sdkconfig"])
        self.assertEqual("selected", build["configuration_origin_status"])
        scan = report["scan"]
        assert isinstance(scan, dict)
        self.assertEqual([], scan["boot_validation_findings"])
        self.assertNotIn(str(project), json.dumps(report))

    def test_report_fails_on_version_or_target_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            _build_fixture(project)

            report = build_report(
                project,
                expected_target="esp32",
                expected_version="v5.3.6",
                idf_commit="0" * 40,
                image_digest="sha256:" + "0" * 64,
                source_project="examples/get-started/hello_world",
            )

        self.assertEqual("failed", report["verification_status"])
        errors = report["verification_errors"]
        assert isinstance(errors, list)
        self.assertEqual(2, len(errors))

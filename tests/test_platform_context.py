from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from vigil_fuse.platform_context import (
    detect_project_frameworks,
    inspect_project_context,
    resolve_build_dir,
)
from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan
from vigil_fuse.esp_idf_lock import lock_parser_available


def _esp_idf_project(
    root: Path, *, version: str = "v5.2.1", lock_target: str | None = None
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "CMakeLists.txt").write_text(
        "include($ENV{IDF_PATH}/tools/cmake/project.cmake)\nproject(fixture)\n",
        encoding="utf-8",
    )
    build = root / "build"
    generated = build / "config"
    generated.mkdir(parents=True)
    (generated / "sdkconfig.h").write_text(
        '#define CONFIG_IDF_TARGET "esp32"\n'
        "#define CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS 1\n"
        "#define CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP 1\n",
        encoding="utf-8",
    )
    (build / "project_description.json").write_text(
        json.dumps({"target": "esp32", "idf_ver": version}),
        encoding="utf-8",
    )
    if lock_target is not None:
        (root / "dependencies.lock").write_text(
            "version: '1.0'\n"
            f"target: {lock_target}\n"
            f"manifest_hash: {'a' * 64}\n"
            "direct_dependencies: [vendor/component]\n"
            "dependencies:\n"
            "  vendor/component:\n"
            "    version: 2.1.0\n"
            "    source:\n"
            "      type: registry\n"
            "    targets: [esp32]\n"
            "    dependencies: {}\n",
            encoding="utf-8",
        )
    return build


def _zephyr_project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "CMakeLists.txt").write_text(
        "find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})\n",
        encoding="utf-8",
    )
    (root / "prj.conf").write_text("CONFIG_MAIN_STACK_SIZE=2048\n", encoding="utf-8")
    build = root / "build"
    generated = build / "zephyr"
    generated.mkdir(parents=True)
    (generated / ".config").write_text(
        'CONFIG_BOARD="native_sim"\nCONFIG_KERNELVERSION="4.5.0"\n',
        encoding="utf-8",
    )
    return build


class PlatformContextTests(unittest.TestCase):
    def test_esp_idf_generated_findings_keep_candidate_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            _esp_idf_project(root)
            result = scan(root, profile="esp-idf", build_dir="build")

        self.assertEqual("esp-idf", result.project_context.framework)
        self.assertEqual("generated-config-found", result.project_context.status)
        self.assertEqual("esp32", result.project_context.target)
        self.assertEqual("v5.2.1", result.project_context.framework_version)
        self.assertEqual({"FUSE006", "FUSE007"}, {finding.rule_id for finding in result.findings})
        for finding in result.findings:
            with self.subTest(rule=finding.rule_id):
                self.assertEqual("candidate", finding.applicability)
                self.assertEqual("generated-config", finding.validation_method)
                self.assertEqual("build/config/sdkconfig.h", finding.file)

    def test_esp_idf_project_detection_and_version_metadata_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            _esp_idf_project(root, version="v5.3.0")
            hints = detect_project_frameworks(root)
            context, sources, warnings, _ = inspect_project_context(root, "esp-idf", "build")

        self.assertEqual("esp-idf", hints[0][0])
        self.assertIn("ESP-IDF project build system", " ".join(hints[0][1]))
        self.assertEqual("v5.3.0", context.framework_version)
        self.assertEqual(1, len(sources))
        self.assertEqual((), warnings)
        self.assertTrue(
            all(not Path(artifact.path).is_absolute() for artifact in context.configuration_files)
        )

    def test_esp_idf_context_records_selected_sdkconfig_and_defaults_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            build = _esp_idf_project(root)
            (root / "config").mkdir()
            (root / "sdkconfig.release").write_text(
                "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS=y\n",
                encoding="utf-8",
            )
            (root / "sdkconfig.defaults").write_text(
                "CONFIG_LOG_DEFAULT_LEVEL=3\n", encoding="utf-8"
            )
            (root / "sdkconfig.defaults.esp32").write_text(
                "CONFIG_LOG_DEFAULT_LEVEL=4\n", encoding="utf-8"
            )
            (root / "config" / "release.defaults").write_text(
                "CONFIG_FREERTOS_HZ=1000\n", encoding="utf-8"
            )
            (root / "config" / "release.defaults.esp32").write_text(
                "CONFIG_FREERTOS_HZ=500\n", encoding="utf-8"
            )
            (build / "CMakeCache.txt").write_text(
                f"SDKCONFIG:FILEPATH={root / 'sdkconfig.release'}\n"
                "SDKCONFIG_DEFAULTS:STRING=sdkconfig.defaults;config/release.defaults\n"
                "IDF_TARGET:STRING=esp32\n",
                encoding="utf-8",
            )
            context, sources, warnings, _ = inspect_project_context(root, "esp-idf", "build")
            result = scan(root, profile="esp-idf", build_dir="build")
            report = json.loads(to_json(result))

        origin = context.configuration_origin
        self.assertEqual("selected", origin.status)
        self.assertEqual("sdkconfig.release", origin.selected_sdkconfig)
        self.assertEqual("cmake-cache", origin.selected_sdkconfig_source)
        self.assertEqual("cmake-cache", origin.defaults_source)
        self.assertTrue(origin.defaults_order_resolved)
        self.assertEqual(
            [
                (1, "sdkconfig.defaults", False),
                (2, "sdkconfig.defaults.esp32", True),
                (3, "config/release.defaults", False),
                (4, "config/release.defaults.esp32", True),
            ],
            [(item.order, item.path, item.target_specific) for item in origin.default_files],
        )
        self.assertTrue(
            all(item.state == "present" and item.sha256 for item in origin.default_files)
        )
        self.assertEqual("sdkconfig.release", sources[0].path)
        self.assertEqual((), warnings)
        finding = next(item for item in result.findings if item.rule_id == "FUSE006")
        self.assertEqual("sdkconfig.release", finding.file)
        self.assertEqual("candidate", finding.applicability)
        self.assertEqual(
            "sdkconfig.release",
            report["project_context"]["configuration_origin"]["selected_sdkconfig"],
        )
        self.assertEqual(
            [
                "sdkconfig.defaults",
                "sdkconfig.defaults.esp32",
                "config/release.defaults",
                "config/release.defaults.esp32",
            ],
            [
                item["path"]
                for item in report["project_context"]["configuration_origin"]["default_files"]
            ],
        )
        self.assertNotIn(str(root), to_json(result))

    def test_esp_idf_cache_path_accepts_an_os_alias_to_the_project(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "project"
            build = _esp_idf_project(root)
            (root / "sdkconfig.release").write_text(
                "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS=y\n",
                encoding="utf-8",
            )
            alias = parent / "parent-alias"
            try:
                alias.symlink_to(parent, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("directory symlinks are unavailable")
            aliased_sdkconfig = alias / root.name / "sdkconfig.release"
            (build / "CMakeCache.txt").write_text(
                f"SDKCONFIG:FILEPATH={aliased_sdkconfig}\nIDF_TARGET:STRING=esp32\n",
                encoding="utf-8",
            )

            context, sources, warnings, _ = inspect_project_context(root, "esp-idf", "build")

        origin = context.configuration_origin
        self.assertEqual("selected", origin.status)
        self.assertEqual("sdkconfig.release", origin.selected_sdkconfig)
        self.assertEqual(["sdkconfig.release"], [source.path for source in sources])
        self.assertEqual((), warnings)

    def test_esp_idf_external_sdkconfig_path_is_not_read_or_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "project"
            build = _esp_idf_project(root)
            external_config = parent / "private-sdkconfig"
            external_config.write_text(
                "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS=y\n",
                encoding="utf-8",
            )
            (build / "CMakeCache.txt").write_text(
                f"SDKCONFIG:FILEPATH={external_config}\nIDF_TARGET:STRING=esp32\n",
                encoding="utf-8",
            )
            context, _, _, _ = inspect_project_context(root, "esp-idf", "build")
            report = to_json(scan(root, profile="esp-idf", build_dir="build"))

        self.assertEqual("unresolved", context.configuration_origin.status)
        self.assertIsNone(context.configuration_origin.selected_sdkconfig)
        self.assertNotIn(str(external_config), report)

    def test_esp_idf_without_build_reports_defaults_as_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            (root / "sdkconfig.defaults").write_text(
                "CONFIG_LOG_DEFAULT_LEVEL=3\n", encoding="utf-8"
            )
            (root / "sdkconfig.defaults.esp32").write_text(
                "CONFIG_LOG_DEFAULT_LEVEL=4\n", encoding="utf-8"
            )
            context, _, _, _ = inspect_project_context(root, "esp-idf")
            (root / "sdkconfig.defaults.esp32").write_text(
                "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS=y\n",
                encoding="utf-8",
            )
            scan_result = scan(root, profile="esp-idf")

        origin = context.configuration_origin
        self.assertEqual("candidates-only", origin.status)
        self.assertIsNone(origin.selected_sdkconfig)
        self.assertFalse(origin.defaults_order_resolved)
        self.assertEqual(["sdkconfig.defaults"], [item.path for item in origin.default_files])
        self.assertTrue(any("candidate" in item for item in origin.limitations))
        finding = next(item for item in scan_result.findings if item.rule_id == "FUSE006")
        self.assertEqual("sdkconfig.defaults.esp32", finding.file)
        self.assertEqual("candidate", finding.applicability)

    def test_zephyr_build_metadata_reads_board_and_kernel_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            _zephyr_project(root)
            context, sources, warnings, _ = inspect_project_context(root, "zephyr", "build")

        self.assertTrue(context.project_detected)
        self.assertEqual("generated-config-found", context.status)
        self.assertEqual("native_sim", context.board)
        self.assertEqual("4.5.0", context.framework_version)
        self.assertEqual("build/zephyr/.config", context.configuration_files[0].path)
        self.assertEqual(1, len(sources))
        self.assertEqual((), warnings)

    def test_build_directory_must_stay_inside_project(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "project"
            root.mkdir()
            (root / "build").mkdir()
            outside = parent / "outside"
            outside.mkdir()

            resolved, relative = resolve_build_dir(root, "build")
            with self.assertRaisesRegex(ValueError, "inside the scan target"):
                resolve_build_dir(root, outside)
            resolved_is_dir = resolved.is_dir()

        self.assertEqual("build", relative)
        self.assertTrue(resolved_is_dir)

    def test_build_directory_cannot_pass_through_a_symbolic_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "project"
            root.mkdir()
            outside = parent / "outside"
            outside.mkdir()
            link = root / "linked-build"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("directory symlinks are unavailable")

            with self.assertRaisesRegex(ValueError, "symbolic link"):
                resolve_build_dir(root, link)

    def test_build_directory_accepts_a_parent_path_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "project"
            build = root / "build"
            build.mkdir(parents=True)
            alias = parent / "parent-alias"
            try:
                alias.symlink_to(parent, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("directory symlinks are unavailable")

            resolved, relative = resolve_build_dir(root, alias / root.name / "build")
            resolved_is_dir = resolved.is_dir()
            resolved_matches = resolved == (root / "build").resolve()

        self.assertEqual("build", relative)
        self.assertTrue(resolved_is_dir)
        self.assertTrue(resolved_matches)

    @unittest.skipUnless(lock_parser_available(), "PyYAML optional dependency is not installed")
    def test_esp_idf_lock_records_component_origin_and_target_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            _esp_idf_project(root, lock_target="esp32")
            context, _, warnings, status = inspect_project_context(root, "esp-idf", "build")

        lock = context.component_lock
        self.assertEqual("target-matches", lock.status)
        self.assertTrue(lock.selected_target_match)
        self.assertEqual("unverified", lock.manifest_freshness)
        self.assertEqual(("vendor/component",), lock.direct_dependencies)
        self.assertEqual("registry", lock.components[0].source_type)
        self.assertTrue(lock.components[0].direct)
        self.assertEqual("completed", status.status)
        self.assertEqual((), warnings)

    @unittest.skipUnless(lock_parser_available(), "PyYAML optional dependency is not installed")
    def test_esp_idf_lock_target_mismatch_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            _esp_idf_project(root, lock_target="esp32s3")
            context, _, warnings, status = inspect_project_context(root, "esp-idf", "build")

        self.assertEqual("target-mismatch", context.component_lock.status)
        self.assertFalse(context.component_lock.selected_target_match)
        self.assertEqual("partial", status.status)
        self.assertTrue(
            any("does not match" in warning for warning in context.component_lock.limitations)
        )

    @unittest.skipUnless(lock_parser_available(), "PyYAML optional dependency is not installed")
    def test_esp_idf_lock_rejects_duplicate_yaml_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "dependencies.lock").write_text(
                "version: '1.0'\nversion: '1.1'\ntarget: esp32\n",
                encoding="utf-8",
            )
            context, _, _, status = inspect_project_context(root, "esp-idf")

        self.assertEqual("invalid", context.component_lock.status)
        self.assertEqual("failed", status.status)
        self.assertIn("could not be parsed safely", status.detail)

    @unittest.skipUnless(lock_parser_available(), "PyYAML optional dependency is not installed")
    def test_esp_idf_lock_rejects_yaml_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "dependencies.lock").write_text(
                "version: '1.0'\ntarget: esp32\nbase: &base {}\ndependencies: *base\n",
                encoding="utf-8",
            )
            context, _, _, status = inspect_project_context(root, "esp-idf")

        self.assertEqual("invalid", context.component_lock.status)
        self.assertEqual("failed", status.status)
        self.assertIn("could not be parsed safely", status.detail)


if __name__ == "__main__":
    unittest.main()

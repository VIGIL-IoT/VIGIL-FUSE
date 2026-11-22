from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any
from urllib.error import URLError
from unittest.mock import MagicMock, patch

import pytest

from vigil_fuse.cli import main
from vigil_fuse.setup import manager


def _spec(tool_id: str = "syft") -> manager.ToolSpec:
    return next(spec for spec in manager.load_manifest() if spec.id == tool_id)


def test_manifest_has_only_the_four_dependency_categories_and_pinned_assets() -> None:
    specs = manager.load_manifest()
    assert {spec.category for spec in specs} <= {
        "CORE",
        "RECOMMENDED",
        "OPTIONAL_HEAVY",
        "RESEARCH",
    }
    assert len({spec.id for spec in specs}) == len(specs)
    windows = manager.assets_for_platform("Windows", "AMD64")
    assert tuple(asset.tool for asset in windows) == ("syft", "osv-scanner", "gitleaks")
    assert all(len(asset.sha256) == 64 for asset in windows)


def test_manifest_rejects_unknown_categories_and_unsupported_architectures(tmp_path: Path) -> None:
    manifest_path = Path(manager.__file__).with_name("tools.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["tools"][0]["category"] = "OPTIONAL"
    path = tmp_path / "malformed.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid category"):
        manager.load_manifest(path)
    with pytest.raises(ValueError, match="No pinned recommended-tool assets"):
        manager.assets_for_platform("Windows", "ARM64")
    manifest["tools"][0]["category"] = "RECOMMENDED"
    manifest["tools"][0]["assets"]["windows/x86_64"]["sha256"] = "not-a-digest"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid SHA-256"):
        manager.load_manifest(path)


def test_tool_detection_distinguishes_missing_available_wrong_and_broken() -> None:
    spec = _spec()
    missing = manager.inspect_tool(spec, system="Linux", machine="x86_64", which=lambda _: None)
    assert missing.status == "MISSING"
    with patch(
        "vigil_fuse.analyzer_runtime._run",
        return_value=subprocess.CompletedProcess([], 0, "syft 1.55.0", ""),
    ):
        available = manager.inspect_tool(
            spec, system="Linux", machine="x86_64", which=lambda _: "/tools/syft"
        )
    assert available.status == "AVAILABLE"
    assert available.version == "1.55.0"
    with patch(
        "vigil_fuse.analyzer_runtime._run",
        return_value=subprocess.CompletedProcess([], 0, "syft 0.9.0", ""),
    ):
        wrong = manager.inspect_tool(
            spec, system="Linux", machine="x86_64", which=lambda _: "/tools/syft"
        )
    assert wrong.status == "WRONG_VERSION"
    with patch(
        "vigil_fuse.analyzer_runtime._run",
        return_value=subprocess.CompletedProcess([], 2, "unknown output", ""),
    ):
        broken = manager.inspect_tool(
            spec, system="Linux", machine="x86_64", which=lambda _: "/tools/syft"
        )
    assert broken.status == "BROKEN"


def test_unsupported_platform_is_reported_without_running_a_tool() -> None:
    check = manager.inspect_tool(_spec(), system="Plan9", machine="x86_64", which=lambda _: None)
    assert check.status == "UNSUPPORTED"


def test_powershell_discovery_prefers_windows_powershell_then_pwsh() -> None:
    def powershell_first(name: str) -> str | None:
        return {"powershell": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"}.get(name)

    def pwsh_only(name: str) -> str | None:
        return "C:/Program Files/PowerShell/7/pwsh.exe" if name == "pwsh" else None

    assert manager.powershell_executable(system="Windows", which=powershell_first).endswith(
        "powershell.exe"
    )
    assert manager.powershell_executable(system="Windows", which=pwsh_only).endswith("pwsh.exe")
    assert manager.powershell_executable(system="Linux", which=pwsh_only) is None


def test_verified_installer_handles_paths_with_spaces_and_records_source(tmp_path: Path) -> None:
    directory = tmp_path / "I drive" / "Security Tools" / "FUSE tools"
    spec = _spec()
    asset = manager.ToolAsset(
        "syft",
        "https://github.com/anchore/syft/releases/download/v1.55.0/syft_windows_amd64.exe",
        "a" * 64,
        None,
        None,
        "syft.exe",
        "1.55.0",
    )
    with (
        patch(
            "vigil_fuse.setup.manager.download_verified",
            side_effect=lambda _asset, path: path.write_bytes(b"binary"),
        ),
        patch("vigil_fuse.setup.manager._probe_version", return_value=("1.55.0", None)),
    ):
        installed = manager.install_asset(directory, asset, spec)
    assert installed == directory / "syft.exe"
    assert installed.read_bytes() == b"binary"
    record = json.loads((directory / "install-record.json").read_text(encoding="utf-8"))
    assert record["tools"]["syft"]["source"] == asset.url
    assert record["tools"]["syft"]["version"] == "1.55.0"


def test_install_reuses_matching_copy_and_requires_explicit_upgrade_for_existing_copy(
    tmp_path: Path,
) -> None:
    spec = _spec()
    asset = spec.assets["windows/x86_64"]
    destination = tmp_path / asset.executable_name
    destination.write_bytes(b"already installed")
    with patch("vigil_fuse.setup.manager._probe_version", return_value=(asset.version, None)):
        assert manager.install_asset(tmp_path, asset, spec) == destination
    with patch("vigil_fuse.setup.manager._probe_version", return_value=("1.2.0", None)):
        with pytest.raises(ValueError, match="use --upgrade"):
            manager.install_asset(tmp_path, asset, spec)


def test_upgrade_never_downgrades_a_newer_managed_copy(tmp_path: Path) -> None:
    spec = _spec()
    asset = spec.assets["windows/x86_64"]
    destination = tmp_path / asset.executable_name
    destination.write_bytes(b"newer version")
    with (
        patch("vigil_fuse.setup.manager._probe_version", return_value=("1.56.0", None)),
        patch("vigil_fuse.setup.manager.download_verified") as download,
    ):
        assert manager.install_asset(tmp_path, asset, spec, upgrade=True) == destination
    assert destination.read_bytes() == b"newer version"
    download.assert_not_called()


def test_checksum_mismatch_and_offline_download_leave_no_partial_file(tmp_path: Path) -> None:
    payload = b"not the pinned bytes"
    response = MagicMock()
    response.headers = {}
    response.geturl.return_value = "https://github.com/anchore/syft/releases/download/v1.55.0/file"
    response.read.side_effect = [payload, b""]
    response.__enter__.return_value = response
    destination = tmp_path / "asset.release"
    asset = _spec().assets["windows/x86_64"]
    with patch("vigil_fuse.setup.manager.urlopen", return_value=response):
        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            manager.download_verified(asset, destination)
    assert not destination.exists()

    with patch("vigil_fuse.setup.manager.urlopen", side_effect=URLError("offline")):
        with pytest.raises(URLError):
            manager.download_verified(asset, destination)
    assert not destination.exists()


def test_download_rejects_redirect_outside_the_declared_release_hosts(tmp_path: Path) -> None:
    response = MagicMock()
    response.geturl.return_value = "https://downloads.example.invalid/release"
    response.__enter__.return_value = response
    destination = tmp_path / "asset.release"
    asset = _spec().assets["windows/x86_64"]
    with patch("vigil_fuse.setup.manager.urlopen", return_value=response):
        with pytest.raises(ValueError, match="Unexpected download publisher"):
            manager.download_verified(asset, destination)
    assert not destination.exists()


def test_setup_is_idempotent_when_recommended_tools_are_healthy(tmp_path: Path) -> None:
    def healthy(spec: manager.ToolSpec, **_: Any) -> manager.ToolCheck:
        return manager.ToolCheck(
            spec.id,
            spec.display_name,
            spec.category,
            "AVAILABLE",
            "1.55.0",
            str(tmp_path / f"{spec.id}.exe"),
        )

    with (
        patch("vigil_fuse.setup.manager.platform.system", return_value="Windows"),
        patch("vigil_fuse.setup.manager.platform.machine", return_value="AMD64"),
        patch("vigil_fuse.setup.manager.inspect_tool", side_effect=healthy),
        patch("vigil_fuse.setup.manager.install_asset") as install,
    ):
        results = manager.setup_tools("RECOMMENDED", directory=tmp_path)
    assert len(results) == 6
    assert all("reused" in result for _, result in results)
    install.assert_not_called()


def test_setup_reuses_present_tools_and_provisions_only_missing_tools(tmp_path: Path) -> None:
    def partial(spec: manager.ToolSpec, **_: Any) -> manager.ToolCheck:
        status = "AVAILABLE" if spec.id in {"syft", "git"} else "MISSING"
        executable = f"C:/tools/{spec.id}.exe" if status == "AVAILABLE" else None
        version = "1.55.0" if spec.id == "syft" else "2.51.2"
        return manager.ToolCheck(
            spec.id,
            spec.display_name,
            spec.category,
            status,
            version if status == "AVAILABLE" else None,
            executable,
        )

    with (
        patch("vigil_fuse.setup.manager.platform.system", return_value="Windows"),
        patch("vigil_fuse.setup.manager.platform.machine", return_value="AMD64"),
        patch("vigil_fuse.setup.manager.inspect_tool", side_effect=partial),
        patch(
            "vigil_fuse.setup.manager.install_asset", return_value=tmp_path / "tool.exe"
        ) as install,
    ):
        results = manager.setup_tools("RECOMMENDED", directory=tmp_path)
    outcomes = dict(results)
    assert "reused 1.55.0" in outcomes["Syft"]
    assert "installed 2.7.0" in outcomes["OSV-Scanner"]
    assert "installed 8.30.0" in outcomes["Gitleaks"]
    assert "reused 2.51.2" in outcomes["Git"]
    assert install.call_count == 2


def test_setup_reports_offline_failures_per_tool_and_continues(tmp_path: Path) -> None:
    def missing(spec: manager.ToolSpec, **_: Any) -> manager.ToolCheck:
        return manager.ToolCheck(spec.id, spec.display_name, spec.category, "MISSING")

    with (
        patch("vigil_fuse.setup.manager.platform.system", return_value="Windows"),
        patch("vigil_fuse.setup.manager.platform.machine", return_value="AMD64"),
        patch("vigil_fuse.setup.manager.inspect_tool", side_effect=missing),
        patch("vigil_fuse.setup.manager.install_asset", side_effect=URLError("offline")) as install,
    ):
        results = manager.setup_tools("RECOMMENDED", directory=tmp_path)
    assert install.call_count == 3
    failures = [result for _, result in results if result.startswith("failed:")]
    assert len(failures) == 3
    assert all(
        "offline" in result and "impact:" in result and "recovery:" in result for result in failures
    )


def test_setup_dry_run_and_missing_consent_never_install(tmp_path: Path) -> None:
    missing = tuple(
        manager.ToolCheck(
            spec.id, spec.display_name, spec.category, "MISSING", capability=spec.doctor_capability
        )
        for spec in manager.load_manifest()
        if spec.id != "ghidra"
    )
    with (
        patch("vigil_fuse.cli.inspect_environment", return_value=missing),
        patch("vigil_fuse.cli.setup_tools") as install,
        patch("vigil_fuse.cli.managed_tool_directory", return_value=tmp_path),
    ):
        assert main(["setup", "--recommended", "--dry-run"]) == 0
        install.assert_not_called()
        with patch("vigil_fuse.cli.sys.stdin") as stdin:
            stdin.isatty.return_value = False
            assert main(["setup", "--recommended"]) == 0
        install.assert_not_called()


def test_full_setup_includes_heavy_tools_only_in_the_full_mode(
    capsys: pytest.CaptureFixture[str],
) -> None:
    checks = tuple(
        manager.ToolCheck(
            spec.id,
            spec.display_name,
            spec.category,
            "MISSING" if spec.category == "RECOMMENDED" else "OPTIONAL",
            capability=spec.doctor_capability,
        )
        for spec in manager.load_manifest()
        if spec.id != "ghidra"
    )
    with (
        patch("vigil_fuse.cli.inspect_environment", return_value=checks),
        patch("vigil_fuse.cli.setup_tools", return_value=()) as setup,
    ):
        assert main(["setup", "--full", "--yes"]) == 0
    assert [call.args[0] for call in setup.call_args_list] == ["RECOMMENDED", "OPTIONAL_HEAVY"]
    output = capsys.readouterr().out
    assert "Docker" in output
    assert "Ghidra" in output
    assert "Heavy tools are not auto-installed" in output


def test_doctor_json_survives_missing_optional_python_capability(
    capsys: pytest.CaptureFixture[str],
) -> None:
    check = manager.ToolCheck("syft", "Syft", "RECOMMENDED", "MISSING")
    opa_check = manager.ToolCheck("opa", "OPA/Rego", "RECOMMENDED", "AVAILABLE", "1.22.4", "opa")
    verible_check = manager.ToolCheck(
        "verible-verilog-syntax", "Verible RTL parser", "RECOMMENDED", "MISSING"
    )
    ghidra = MagicMock(
        status="unavailable",
        version=None,
        launcher=None,
        java_version=None,
        java_executable=None,
        detail="not installed",
    )
    with (
        patch("vigil_fuse.cli.inspect_environment", return_value=(check, opa_check, verible_check)),
        patch("vigil_fuse.cli.inspect_ghidra", return_value=ghidra),
        patch(
            "vigil_fuse.cli.inspect_rtl_backend",
            return_value=("AVAILABLE", "FUSE structural parser", "builtin-1", "UNAVAILABLE"),
        ),
        patch(
            "vigil_fuse.cli.doctor_status", return_value={"available": False, "installed": False}
        ),
        patch("vigil_fuse.cli.lock_parser_available", return_value=False),
    ):
        assert main(["doctor", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["fuse"]["status"] == "AVAILABLE"
    assert report["core_python_dependencies"] == []
    assert report["clang_semantic"]["category"] == "OPTIONAL_HEAVY"
    assert report["optional_python_capabilities"]["esp_idf_yaml_parser"]["status"] == "OPTIONAL"
    tool_checks = {tool["id"]: tool for tool in report["tools"]}
    assert tool_checks["syft"]["status"] == "MISSING"
    assert tool_checks["opa"]["status"] == "AVAILABLE"
    assert tool_checks["verible-verilog-syntax"]["status"] == "MISSING"
    assert tool_checks["ghidra"]["status"] == "OPTIONAL"
    assert report["rtl_analyzer"]["status"] == "AVAILABLE"
    assert report["local_reasoning"]["status"] == "OPTIONAL"

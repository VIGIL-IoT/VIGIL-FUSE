from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from vigil_fuse.analyzer_runtime import (
    _container_configuration_isolated,
    _docker_rootless_limits_supported,
    _run_in_docker,
    analyzer_sandbox_context,
    analyzer_unavailable_detail,
    resolve_analyzer_executable,
)
from vigil_fuse.cli import main
from vigil_fuse.cli import _optional_analyzer_available
from vigil_fuse.analyzer_sandbox import (
    AnalyzerSandbox,
    build_create_command,
    container_user,
    parse_image_assignments,
    validate_image_reference,
)
from vigil_fuse.dependency_analyzers import generate_sbom, scan_vulnerabilities


_DIGEST = "a" * 64


class SandboxImageValidationTests(unittest.TestCase):
    def test_registry_reference_requires_an_immutable_digest(self) -> None:
        reference = f"ghcr.io/example/syft@sha256:{_DIGEST}"
        self.assertEqual(reference, validate_image_reference(reference))
        self.assertEqual(f"sha256:{_DIGEST}", validate_image_reference(f"sha256:{_DIGEST}"))

    def test_tags_and_malformed_image_assignments_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "immutable"):
            validate_image_reference("ghcr.io/example/syft:latest")
        with self.assertRaisesRegex(ValueError, "TOOL=IMAGE"):
            parse_image_assignments(["unknown=sha256:" + _DIGEST])
        with self.assertRaisesRegex(ValueError, "more than once"):
            parse_image_assignments([f"syft=sha256:{_DIGEST}", f"syft=sha256:{_DIGEST}"])


class SandboxCommandTests(unittest.TestCase):
    def test_create_command_uses_confinement_and_translates_mount_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "scan"
            output = root / "reports"
            config = root / "gitleaks-config"
            target.mkdir()
            output.mkdir()
            config.mkdir()
            (config / "gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
            sandbox = AnalyzerSandbox(
                runtime="docker",
                images={"syft": f"sha256:{_DIGEST}"},
                target=target,
            )
            command = build_create_command(
                sandbox,
                analyzer="syft",
                command=[
                    "syft",
                    "scan",
                    f"dir:{target}",
                    "--output",
                    "cyclonedx-json",
                ],
                container_name="vigil-fuse-analyzer-test",
            )

        joined = "\n".join(command)
        self.assertIn("--pull=never", command)
        self.assertIn("--network", command)
        self.assertEqual("none", command[command.index("--network") + 1])
        self.assertIn("--ipc=private", command)
        self.assertIn("--cgroupns=private", command)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--security-opt=no-new-privileges=true", command)
        self.assertIn("--pids-limit=64", command)
        self.assertIn("--memory=1g", command)
        self.assertIn("--cpus=1", command)
        self.assertIn("dir:/fuse/input", command)
        self.assertIn("cyclonedx-json", command)
        self.assertIn("SYFT_CHECK_FOR_APP_UPDATE=false", command)
        self.assertIn("target=/fuse/input,readonly", joined)
        self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777", command)
        self.assertIn("SYFT_CHECK_FOR_APP_UPDATE=false", command)
        self.assertNotIn("/fuse/output", joined)
        self.assertNotIn(str(output), joined)

    def test_osv_network_requires_explicit_configuration(self) -> None:
        sandbox = AnalyzerSandbox(
            runtime="docker",
            images={"osv-scanner": f"sha256:{_DIGEST}"},
            allow_osv_network=True,
        )
        command = build_create_command(
            sandbox,
            analyzer="osv-scanner",
            command=["osv-scanner", "--version"],
            container_name="vigil-fuse-analyzer-test",
        )
        self.assertEqual("bridge", command[command.index("--network") + 1])

    def test_host_paths_outside_declared_mounts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "scan"
            target.mkdir()
            sandbox = AnalyzerSandbox(
                runtime="docker",
                images={"binwalk": f"sha256:{_DIGEST}"},
                target=target,
            )
            with self.assertRaisesRegex(ValueError, "outside mounted inputs"):
                build_create_command(
                    sandbox,
                    analyzer="binwalk",
                    command=["binwalk", str(root / "private.bin")],
                    container_name="vigil-fuse-analyzer-test",
                )

    def test_nested_report_directory_is_hidden_by_bounded_tmpfs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "scan"
            reports = target / ".fuse-results"
            reports.mkdir(parents=True)
            (reports / "previous-report.json").write_text("{}", encoding="utf-8")
            sandbox = AnalyzerSandbox(
                runtime="docker",
                images={"syft": f"sha256:{_DIGEST}"},
                target=target,
                output_dir=reports,
            )
            command = build_create_command(
                sandbox,
                analyzer="syft",
                command=["syft", "scan", f"dir:{target}", "--output", "cyclonedx-json"],
                container_name="vigil-fuse-analyzer-test",
            )

        self.assertEqual(2, command.count("--tmpfs"))
        self.assertIn(
            "/fuse/input/.fuse-results:rw,noexec,nosuid,nodev,size=64m,mode=1777", command
        )
        self.assertNotIn(str(reports), "\n".join(command))

    def test_report_directory_cannot_replace_the_entire_scan_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "scan"
            target.mkdir()
            sandbox = AnalyzerSandbox(
                runtime="docker",
                images={"syft": f"sha256:{_DIGEST}"},
                target=target,
                output_dir=target,
            )
            with self.assertRaisesRegex(ValueError, "cannot use the target root"):
                build_create_command(
                    sandbox,
                    analyzer="syft",
                    command=["syft", "scan", f"dir:{target}", "--output", "cyclonedx-json"],
                    container_name="vigil-fuse-analyzer-test",
                )

    def test_explicit_sbom_is_mounted_as_a_single_readonly_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "scan"
            reports = target / ".fuse-results"
            reports.mkdir(parents=True)
            sbom = reports / "components.cdx.json"
            sbom.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
            sandbox = AnalyzerSandbox(
                runtime="docker",
                images={"osv-scanner": f"sha256:{_DIGEST}"},
                target=target,
            )
            command = build_create_command(
                sandbox,
                analyzer="osv-scanner",
                command=["osv-scanner", "scan", "source", "--format", "json", "-L", str(sbom)],
                container_name="vigil-fuse-analyzer-test",
                extra_readonly_mounts=(sbom,),
            )
            resolved_sbom = sbom.resolve()
            resolved_reports = reports.resolve()

        joined = "\n".join(command)
        self.assertIn("/fuse/readonly-0", command)
        readonly_sbom_mount = f"source={resolved_sbom},target=/fuse/readonly-0,readonly"
        self.assertIn(readonly_sbom_mount, joined)
        self.assertNotIn(str(resolved_reports), joined.replace(readonly_sbom_mount, ""))
        self.assertNotIn("/fuse/output", joined)


class SandboxResolutionTests(unittest.TestCase):
    def test_plan_checks_local_image_without_host_fallback_or_pull(self) -> None:
        missing = AnalyzerSandbox(runtime=None, images={"syft": f"sha256:{_DIGEST}"})
        with patch("vigil_fuse.cli.shutil.which") as host_lookup:
            self.assertFalse(_optional_analyzer_available("syft", missing))
            host_lookup.assert_not_called()

        configured = AnalyzerSandbox(
            runtime="docker",
            images={"syft": f"sha256:{_DIGEST}"},
        )
        with patch(
            "vigil_fuse.cli.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0),
        ) as image_inspect:
            self.assertTrue(_optional_analyzer_available("syft", configured))
        self.assertEqual("image", image_inspect.call_args.args[0][1])
        self.assertNotIn("pull", image_inspect.call_args.args[0])

    def test_docker_mode_uses_the_image_and_never_falls_back_to_host(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "scan"
            output = root / "reports"
            target.mkdir()
            output.mkdir()
            sandbox = AnalyzerSandbox(
                runtime="docker",
                images={"syft": f"sha256:{_DIGEST}"},
            )
            with analyzer_sandbox_context(sandbox, target=target):
                with patch(
                    "vigil_fuse.analyzer_runtime.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, stdout=f'sha256:{_DIGEST}|["/syft"]\n'
                    ),
                ) as docker_inspect:
                    host_lookup = unittest.mock.Mock(return_value="C:/host/syft.exe")
                    self.assertEqual(
                        "/syft", resolve_analyzer_executable("syft", host_lookup=host_lookup)
                    )
                    host_lookup.assert_not_called()
                    self.assertIn("Docker sandbox", analyzer_unavailable_detail("syft", "host"))
                    docker_inspect.assert_called_once()

    def test_missing_runtime_is_visible_and_does_not_use_host_tool(self) -> None:
        sandbox = AnalyzerSandbox(runtime=None, images={"syft": f"sha256:{_DIGEST}"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "scan"
            output = root / "reports"
            target.mkdir()
            output.mkdir()
            with analyzer_sandbox_context(sandbox, target=target):
                host_lookup = unittest.mock.Mock(return_value="C:/host/syft.exe")
                self.assertIsNone(resolve_analyzer_executable("syft", host_lookup=host_lookup))
                host_lookup.assert_not_called()
                self.assertIn(
                    "no host analyzer fallback", analyzer_unavailable_detail("syft", "host")
                )


class SandboxRuntimeValidationTests(unittest.TestCase):
    def test_syft_stdout_is_written_by_fuse_after_the_analyzer_returns(self) -> None:
        document = '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "scan"
            output = root / "reports"
            target.mkdir()
            with (
                patch(
                    "vigil_fuse.dependency_analyzers.resolve_analyzer_executable",
                    return_value="syft",
                ),
                patch("vigil_fuse.dependency_analyzers._tool_version", return_value="syft test"),
                patch("vigil_fuse.dependency_analyzers.analyzer_sandbox_active", return_value=True),
                patch(
                    "vigil_fuse.dependency_analyzers._run",
                    return_value=subprocess.CompletedProcess(
                        ["syft"], 0, stdout=document, stderr=""
                    ),
                ) as run,
            ):
                result = generate_sbom(target, output)
                artifact_path = output / "components.cdx.json"
                self.assertEqual("completed", result.status.status)
                self.assertEqual(document, artifact_path.read_text(encoding="utf-8"))
                self.assertEqual(50 * 1024 * 1024, run.call_args.kwargs["output_limit_bytes"])
                self.assertIn("cyclonedx-json", run.call_args.args[0])
                self.assertNotIn(str(output), " ".join(run.call_args.args[0]))

    def test_osv_mounts_only_the_generated_sbom_as_readonly_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "scan"
            output = root / "reports"
            target.mkdir()
            output.mkdir()
            sbom = output / "components.cdx.json"
            sbom.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
            with (
                patch(
                    "vigil_fuse.dependency_analyzers.resolve_analyzer_executable",
                    return_value="osv-scanner",
                ),
                patch(
                    "vigil_fuse.dependency_analyzers._tool_version", return_value="osv-scanner test"
                ),
                patch("vigil_fuse.dependency_analyzers.analyzer_sandbox_active", return_value=True),
                patch(
                    "vigil_fuse.dependency_analyzers._run",
                    return_value=subprocess.CompletedProcess(
                        ["osv-scanner"], 0, stdout='{"results":[]}', stderr=""
                    ),
                ) as run,
            ):
                result = scan_vulnerabilities(target, output, sbom_path=sbom)
                self.assertEqual("completed", result.status.status)
                self.assertEqual((sbom,), run.call_args.kwargs["readonly_mounts"])
                self.assertEqual(
                    '{"results":[]}\n',
                    (output / "osv-results.json").read_text(encoding="utf-8"),
                )

    def test_osv_network_opt_in_rejects_offline_modes(self) -> None:
        for offline_option in ("--offline-vulnerabilities", "--no-network"):
            with (
                self.subTest(offline_option=offline_option),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary) / "target"
                root.mkdir()
                stderr = StringIO()
                with redirect_stdout(StringIO()), redirect_stderr(stderr):
                    exit_code = main(
                        [
                            "scan",
                            str(root),
                            "--vulnerabilities",
                            "--analyzer-sandbox",
                            "docker",
                            "--sandbox-allow-osv-network",
                            offline_option,
                            "--output-dir",
                            str(Path(temporary) / "reports"),
                        ]
                    )
                self.assertEqual(2, exit_code)
                self.assertIn("requires online --vulnerabilities", stderr.getvalue())

    def test_rootless_runtime_requires_supported_cgroup_limits(self) -> None:
        sandbox = AnalyzerSandbox(runtime="docker", images={})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment: dict[str, str] = {}
            with patch(
                "vigil_fuse.analyzer_runtime.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [], 0, stdout='["name=rootless"]|2|systemd'
                ),
            ):
                self.assertTrue(_docker_rootless_limits_supported(sandbox, environment, root))
            with patch(
                "vigil_fuse.analyzer_runtime.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [], 0, stdout='["name=rootless"]|1|cgroupfs'
                ),
            ):
                self.assertFalse(_docker_rootless_limits_supported(sandbox, environment, root))
            with patch(
                "vigil_fuse.analyzer_runtime.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout="null|2|systemd"),
            ):
                self.assertFalse(_docker_rootless_limits_supported(sandbox, environment, root))

    def test_inspection_accepts_required_controls_and_rejects_unsafe_mounts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "scan"
            output = target / ".fuse-results"
            target.mkdir()
            output.mkdir()
            sandbox = AnalyzerSandbox(
                runtime="docker",
                images={"syft": f"sha256:{_DIGEST}"},
                target=target,
                output_dir=output,
            )
            details = {
                "HostConfig": {
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges=true"],
                    "PidsLimit": 64,
                    "Memory": 1024 * 1024 * 1024,
                    "MemorySwap": 1024 * 1024 * 1024,
                    "NanoCpus": 1_000_000_000,
                    "Privileged": False,
                    "PidMode": "",
                    "IpcMode": "private",
                    "CgroupnsMode": "private",
                    "Devices": [],
                    "DeviceRequests": [],
                    "Tmpfs": {
                        "/tmp": "rw,noexec,nosuid,nodev,size=64m,mode=1777",
                        "/fuse/input/.fuse-results": "rw,noexec,nosuid,nodev,size=64m,mode=1777",
                    },
                },
                "Config": {"User": container_user()},
                "Mounts": [
                    {"Destination": "/fuse/input", "RW": False},
                ],
            }

            def inspect(document: dict[str, object]) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess([], 0, stdout=json.dumps(document))

            with patch(
                "vigil_fuse.analyzer_runtime.subprocess.run",
                return_value=inspect(details),
            ):
                self.assertTrue(_container_configuration_isolated(sandbox, "syft", "test", ()))
            unsafe = json.loads(json.dumps(details))
            unsafe["Mounts"][0]["RW"] = True
            with patch(
                "vigil_fuse.analyzer_runtime.subprocess.run",
                return_value=inspect(unsafe),
            ):
                self.assertFalse(_container_configuration_isolated(sandbox, "syft", "test", ()))
            unconfined = json.loads(json.dumps(details))
            unconfined["HostConfig"]["SecurityOpt"].append("seccomp=unconfined")
            with patch(
                "vigil_fuse.analyzer_runtime.subprocess.run",
                return_value=inspect(unconfined),
            ):
                self.assertFalse(_container_configuration_isolated(sandbox, "syft", "test", ()))

    def test_timeout_forces_container_removal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "scan"
            target.mkdir()
            sandbox = AnalyzerSandbox(
                runtime="docker",
                images={"syft": f"sha256:{_DIGEST}"},
                target=target,
            )
            with (
                patch(
                    "vigil_fuse.analyzer_runtime.resolve_analyzer_executable", return_value="syft"
                ),
                patch(
                    "vigil_fuse.analyzer_runtime._docker_rootless_limits_supported",
                    return_value=True,
                ),
                patch(
                    "vigil_fuse.analyzer_runtime._container_configuration_isolated",
                    return_value=True,
                ),
                patch(
                    "vigil_fuse.analyzer_runtime.build_create_command",
                    return_value=["docker", "create"],
                ),
                patch(
                    "vigil_fuse.analyzer_runtime._run_with_environment",
                    side_effect=subprocess.TimeoutExpired(["docker", "start"], 180),
                ),
                patch(
                    "vigil_fuse.analyzer_runtime.subprocess.run",
                    side_effect=[
                        subprocess.CompletedProcess([], 0),
                        subprocess.CompletedProcess([], 0),
                    ],
                ) as docker_command,
            ):
                with self.assertRaises(subprocess.TimeoutExpired):
                    _run_in_docker(
                        ["syft", "scan"],
                        sandbox=sandbox,
                        environment={},
                        timeout=180,
                        temporary_root=root,
                        readonly_mounts=(),
                    )
            cleanup_command = docker_command.call_args_list[-1].args[0]
            self.assertEqual("rm", cleanup_command[1])
            self.assertIn("--force", cleanup_command)


if __name__ == "__main__":
    unittest.main()

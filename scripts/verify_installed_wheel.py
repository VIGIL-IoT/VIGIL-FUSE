"""Install one built wheel in a disposable environment and exercise it outside the checkout."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import venv


def run(command: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            check=True,
            text=True,
            timeout=600,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"Command failed ({error.returncode}): {command[0]}\n{error.stdout}\n{error.stderr}"
        ) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wheel", type=Path, help="wheel to install; defaults to the only dist/*.whl"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    wheels = [args.wheel.resolve()] if args.wheel else list((root / "dist").glob("*.whl"))
    if len(wheels) != 1 or not wheels[0].is_file():
        raise SystemExit("Expected exactly one built wheel. Pass --wheel to select it.")
    with tempfile.TemporaryDirectory(prefix="vigil fuse wheel smoke ") as temporary:
        outside = Path(temporary) / "outside source tree"
        outside.mkdir()
        environment_path = Path(temporary) / "fresh install environment"
        venv.EnvBuilder(with_pip=True).create(environment_path)
        scripts = environment_path / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        cli = scripts / ("vigil-fuse.exe" if os.name == "nt" else "vigil-fuse")
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        run([str(python), "-m", "pip", "install", str(wheels[0])], cwd=outside, env=environment)
        run([str(cli), "--version"], cwd=outside, env=environment)
        doctor = run([str(cli), "doctor", "--format", "json"], cwd=outside, env=environment)
        report = json.loads(doctor.stdout)
        assert report["fuse"]["status"] == "AVAILABLE"
        dry_run = run(
            [str(cli), "setup", "--recommended", "--dry-run"], cwd=outside, env=environment
        )
        assert "Dry run complete" in dry_run.stdout
        package_info = run(
            [
                str(python),
                "-c",
                "from importlib.metadata import metadata; "
                "from importlib.resources import files; "
                "m=metadata('vigil-fuse'); "
                "assert not [r for r in m.get_all('Requires-Dist', []) if '; extra' not in r]; "
                "assert files('vigil_fuse').joinpath('setup', 'tools.json').is_file(); "
                "print('package metadata and manifest OK')",
            ],
            cwd=outside,
            env=environment,
        )
        assert "manifest OK" in package_info.stdout
        target = outside / "sample project"
        target.mkdir()
        (target / "main.c").write_text(
            'const char *url = "http://device.local";\n', encoding="utf-8"
        )
        output = outside / "findings.json"
        run(
            [str(cli), "scan", str(target), "--format", "json", "--output", str(output)],
            cwd=outside,
            env=environment,
        )
        scan = json.loads(output.read_text(encoding="utf-8"))
        assert scan["tool"]["name"] == "FUSE"
        assert Path(
            run(
                [str(python), "-c", "import vigil_fuse; print(vigil_fuse.__file__)"],
                cwd=outside,
                env=environment,
            ).stdout.strip()
        ).is_relative_to(environment_path)
        run(
            [str(python), "-m", "pip", "install", f"{wheels[0]}[test]"],
            cwd=outside,
            env=environment,
        )
        test_environment = dict(environment)
        for name in tuple(test_environment):
            if name.startswith("GIT_CONFIG_"):
                test_environment.pop(name)
        test_environment["PYTHONPATH"] = str(root)
        test_result = run(
            [str(python), "-m", "pytest", "-q", str(root / "tests")],
            cwd=outside,
            env=test_environment,
        )
        print(test_result.stdout.strip())
    print(f"Installed and exercised {wheels[0].name} outside the source checkout.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

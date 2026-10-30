import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "repository-performance.yml"


class RepositoryPerformanceWorkflowTests(unittest.TestCase):
    def test_workflow_is_manual_and_runs_the_cohort_on_three_platforms(self) -> None:
        workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

        self.assertEqual({"workflow_dispatch": ""}, workflow["on"])
        self.assertEqual({}, workflow["permissions"])
        benchmark = workflow["jobs"]["benchmark"]
        self.assertEqual(
            ["ubuntu-latest", "windows-latest", "macos-latest"],
            benchmark["strategy"]["matrix"]["os"],
        )

    def test_workflow_actions_are_pinned_and_reports_are_retained_as_artifacts(self) -> None:
        workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["benchmark"]["steps"]
        action_steps = [step for step in steps if "uses" in step]

        self.assertEqual(3, len(action_steps))
        for step in action_steps:
            with self.subTest(action=step["uses"]):
                self.assertRegex(step["uses"], re.compile(r"^.+@[0-9a-f]{40}$"))

        upload = next(step for step in action_steps if "upload-artifact" in step["uses"])
        self.assertEqual("error", upload["with"]["if-no-files-found"])
        self.assertEqual("30", upload["with"]["retention-days"])

    def test_workflow_installs_fuse_before_running_the_benchmark(self) -> None:
        workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["benchmark"]["steps"]
        install_index = next(
            index for index, step in enumerate(steps) if step.get("name") == "Install FUSE package"
        )
        benchmark_index = next(
            index
            for index, step in enumerate(steps)
            if step.get("name") == "Measure pinned repository scopes"
        )

        self.assertEqual("python -m pip install -e .", steps[install_index]["run"])
        self.assertLess(install_index, benchmark_index)

    def test_workflow_installs_memory_sampler_and_validates_sampled_reports(self) -> None:
        workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["benchmark"]["steps"]
        dependency_step = next(
            step for step in steps if step.get("name") == "Install benchmark dependencies"
        )
        benchmark_step = next(
            step for step in steps if step.get("name") == "Measure pinned repository scopes"
        )
        validation_step = next(
            step for step in steps if step.get("name") == "Validate benchmark report schema"
        )

        self.assertIn('"psutil>=7.2,<8"', dependency_step["run"])
        self.assertIn("--sample-interval-ms 20", benchmark_step["run"])
        self.assertIn(
            'report["configuration"]["memory_sampling_enabled"] is True', validation_step["run"]
        )


if __name__ == "__main__":
    unittest.main()

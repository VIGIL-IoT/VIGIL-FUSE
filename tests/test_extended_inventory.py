from __future__ import annotations

import json
import random
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from vigil_fuse.build_context import inspect_platformio
from vigil_fuse.cli import main
from vigil_fuse.firmware_inventory import inspect_firmware_candidates
from vigil_fuse.github_actions import inspect_github_actions
from vigil_fuse.hardware_netlist import inspect_kicad_netlist
from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan


FIXTURES = Path(__file__).parent / "fixtures"


class PlatformIOIncludeTests(unittest.TestCase):
    def test_extra_configs_merge_environments_and_keep_source_filter_context(self) -> None:
        root = FIXTURES / "platformio"
        inventory = inspect_platformio(root, config_path="primary.ini")
        release = next(item for item in inventory.environments if item.name == "release")

        self.assertEqual("parsed", inventory.status)
        self.assertEqual(("release",), inventory.selected_environments)
        self.assertEqual("esp32-s3-devkitc-1", release.board)
        self.assertEqual("espressif32", release.platform)
        self.assertEqual("release", release.build_type)
        self.assertEqual("src", release.source_dir)
        self.assertEqual(("+<main.c>", "-<test.c>"), release.source_filter)
        self.assertEqual(3, len(inventory.configurations))
        self.assertEqual(
            ["primary.ini", "fragments/01-base.ini", "fragments/02-release.ini"],
            [item.path for item in inventory.configurations],
        )

    def test_missing_extra_config_is_partial_not_silent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "platformio.ini").write_text(
                "[platformio]\nextra_configs = missing.ini\n[env:board]\nboard = esp32dev\n",
                encoding="utf-8",
            )
            inventory = inspect_platformio(root)

        self.assertEqual("partial", inventory.status)
        self.assertEqual(("board",), tuple(item.name for item in inventory.environments))
        self.assertTrue(any("matched no files" in item for item in inventory.limitations))

    def test_extra_config_cannot_escape_scan_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            outside = Path(temporary) / "outside.ini"
            outside.write_text("[env:outside]\nboard = esp32dev\n", encoding="utf-8")
            (root / "platformio.ini").write_text(
                "[platformio]\nextra_configs = ../outside.ini\n", encoding="utf-8"
            )
            inventory = inspect_platformio(root)

        self.assertEqual("partial", inventory.status)
        self.assertFalse(inventory.environments)
        self.assertTrue(any("outside the scan target" in item for item in inventory.limitations))

    def test_include_cycle_and_unresolved_variable_are_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "platformio.ini").write_text(
                "[platformio]\nextra_configs = extra.ini\n[env:root]\nboard = esp32dev\n",
                encoding="utf-8",
            )
            (root / "extra.ini").write_text(
                "[platformio]\nextra_configs = ${sysenv.EXTRA_CONFIG}\n[env:extra]\nboard = esp32-s3-devkitc-1\n",
                encoding="utf-8",
            )
            inventory = inspect_platformio(root)

        self.assertEqual("partial", inventory.status)
        self.assertEqual({"root", "extra"}, {item.name for item in inventory.environments})
        self.assertTrue(
            any("unresolved extra_configs variable" in item for item in inventory.limitations)
        )

    def test_include_cycle_is_reported_without_recursing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "platformio.ini").write_text(
                "[platformio]\nextra_configs = extra.ini\n", encoding="utf-8"
            )
            (root / "extra.ini").write_text(
                "[platformio]\nextra_configs = platformio.ini\n[env:board]\nboard = esp32dev\n",
                encoding="utf-8",
            )
            inventory = inspect_platformio(root)

        self.assertEqual("partial", inventory.status)
        self.assertTrue(any("cycle" in item for item in inventory.limitations))

    def test_recursive_include_glob_is_left_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "platformio.ini").write_text(
                "[platformio]\nextra_configs = **/*.ini\n", encoding="utf-8"
            )
            inventory = inspect_platformio(root)

        self.assertEqual("partial", inventory.status)
        self.assertTrue(any("recursive glob syntax" in item for item in inventory.limitations))


class FirmwareCandidateTests(unittest.TestCase):
    def test_firmware_candidate_inventory_includes_common_build_outputs_without_reading(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_output = root / ".pio" / "build" / "release"
            source_output.mkdir(parents=True)
            (source_output / "firmware.bin").write_bytes(b"not an inspected firmware image")
            (source_output / "firmware.ota.gz").write_bytes(b"compressed candidate")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "ignored.bin").write_bytes(b"skip")
            inventory = inspect_firmware_candidates(
                root,
                deadline=10**20,
                max_paths=100,
                max_directories=100,
            )

        self.assertEqual("complete", inventory.status)
        self.assertEqual(2, inventory.candidate_count)
        self.assertEqual({".bin": 1, ".ota.gz": 1}, inventory.extension_counts)
        self.assertEqual(
            [".pio/build/release/firmware.bin", ".pio/build/release/firmware.ota.gz"],
            [item.path for item in inventory.candidates],
        )
        self.assertEqual(["bin", "ota.gz"], [item.format for item in inventory.candidates])


class GitHubActionsTests(unittest.TestCase):
    def test_static_workflow_checks_detect_only_explicit_conservative_signals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            for filename in ("vulnerable.yml", "secure.yml"):
                source = FIXTURES / "github-actions" / filename
                (workflows / filename).write_text(
                    source.read_text(encoding="utf-8"), encoding="utf-8"
                )
            inventory, findings = inspect_github_actions(root)

        self.assertEqual("completed", inventory.status)
        self.assertEqual(2, inventory.workflow_count)
        self.assertEqual(1, inventory.non_sha_action_reference_count)
        self.assertEqual(1, inventory.floating_branch_reference_count)
        self.assertEqual(2, len(findings))
        self.assertEqual({"FUSE-GHA-001", "FUSE-GHA-002"}, {item.rule_id for item in findings})
        self.assertTrue(all(item.applicability == "candidate" for item in findings))
        self.assertTrue(all(item.validation_status == "not-validated" for item in findings))
        self.assertTrue(all(item.file.endswith("vulnerable.yml") for item in findings))

    def test_scan_includes_workflow_findings_in_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "ci.yml").write_text(
                "permissions: write-all\nsteps:\n  - uses: vendor/check@main\n"
                "  - uses: vendor/versioned@v2\n",
                encoding="utf-8",
            )
            report = json.loads(to_json(scan(root)))

        self.assertEqual("completed", report["github_actions"]["status"])
        self.assertEqual(2, report["github_actions"]["non_sha_action_reference_count"])
        self.assertEqual(1, report["github_actions"]["floating_branch_reference_count"])
        self.assertEqual(2, report["github_actions"]["finding_count"])
        self.assertEqual(
            2, sum(item["rule_id"].startswith("FUSE-GHA-") for item in report["findings"])
        )

    def test_pull_request_target_and_commented_patterns_alone_are_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "review.yml").write_text(
                "# permissions: write-all\n"
                "on: pull_request_target\n"
                "permissions:\n  contents: read\n"
                "steps:\n  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n",
                encoding="utf-8",
            )
            inventory, findings = inspect_github_actions(root)

        self.assertEqual("completed", inventory.status)
        self.assertFalse(findings)


class KiCadNetlistTests(unittest.TestCase):
    def test_debug_net_candidate_is_reported_without_claiming_physical_exposure(self) -> None:
        root = FIXTURES / "hardware"
        inventory, findings = inspect_kicad_netlist(root, "debug-interface.net")

        self.assertEqual("parsed", inventory.status)
        self.assertEqual(2, inventory.component_count)
        self.assertEqual(2, inventory.net_count)
        self.assertEqual(1, len(inventory.debug_net_candidates))
        self.assertEqual(1, len(findings))
        self.assertEqual("FUSE-HW-001", findings[0].rule_id)
        self.assertEqual("info", findings[0].severity)
        self.assertEqual("candidate", findings[0].applicability)
        self.assertIn("does not establish PCB routing", findings[0].explanation)

    def test_secure_netlist_has_no_debug_candidate(self) -> None:
        root = FIXTURES / "hardware"
        inventory, findings = inspect_kicad_netlist(root, "secure.net")

        self.assertEqual("parsed", inventory.status)
        self.assertFalse(inventory.debug_net_candidates)
        self.assertFalse(findings)

    def test_internal_debug_net_without_connector_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "internal.net").write_text(
                "<export><components><comp ref='U1'><value>MCU</value></comp>"
                "<comp ref='U2'><value>bridge</value></comp></components><nets>"
                "<net code='1' name='/SWDIO'><node ref='U1' pin='1'/><node ref='U2' pin='2'/></net>"
                "</nets></export>",
                encoding="utf-8",
            )
            inventory, findings = inspect_kicad_netlist(root, "internal.net")

        self.assertEqual("parsed", inventory.status)
        self.assertFalse(inventory.debug_net_candidates)
        self.assertFalse(findings)

    def test_netlist_auto_selection_adds_read_only_inventory_to_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (root / "design.net").write_text(
                (FIXTURES / "hardware" / "debug-interface.net").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            report = json.loads(to_json(scan(root)))

        self.assertEqual("parsed", report["hardware_netlist"]["status"])
        self.assertEqual("design.net", report["hardware_netlist"]["path"])
        self.assertTrue(any(item["rule_id"] == "FUSE-HW-001" for item in report["findings"]))

    def test_cli_explicit_netlist_option_and_plan_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (root / "design.net").write_text(
                (FIXTURES / "hardware" / "debug-interface.net").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            output = StringIO()
            with redirect_stdout(output):
                plan_exit = main(["scan", str(root), "--plan", "--format", "json"])
            plan = json.loads(output.getvalue())
            output = StringIO()
            with redirect_stdout(output):
                scan_exit = main(
                    ["scan", str(root), "--hardware-netlist", "design.net", "--format", "json"]
                )
            report = json.loads(output.getvalue())

        stage_names = {item["name"] for item in plan["stages"]}
        self.assertEqual(0, plan_exit)
        self.assertIn("kicad-netlist-static", stage_names)
        self.assertEqual(0, scan_exit)
        self.assertEqual("parsed", report["hardware_netlist"]["status"])

    def test_netlist_with_entity_declaration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "unsafe.net").write_text(
                '<!DOCTYPE export [<!ENTITY x "JTAG">]><export>&x;</export>',
                encoding="utf-8",
            )
            inventory, findings = inspect_kicad_netlist(root, "unsafe.net")

        self.assertEqual("invalid", inventory.status)
        self.assertIn("DTD and entity", inventory.limitations[0])
        self.assertFalse(findings)

    def test_utf16_netlist_with_entity_declaration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsafe = (
                '<?xml version="1.0" encoding="UTF-16"?>'
                '<!DOCTYPE export [<!ENTITY x "JTAG">]>'
                '<export><components/><nets><net name="&x;"/></nets></export>'
            )
            (root / "unsafe.net").write_bytes(unsafe.encode("utf-16"))
            inventory, findings = inspect_kicad_netlist(root, "unsafe.net")

        self.assertEqual("invalid", inventory.status)
        self.assertIn("UTF-8", inventory.limitations[0])
        self.assertFalse(findings)

    def test_netlist_with_excessive_element_count_is_rejected_before_tree_parse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            net_elements = "<net/>" * 100_001
            (root / "large.net").write_text(
                f"<export><components/><nets>{net_elements}</nets></export>",
                encoding="utf-8",
            )
            inventory, findings = inspect_kicad_netlist(root, "large.net")

        self.assertEqual("invalid", inventory.status)
        self.assertIn("element", inventory.limitations[0])
        self.assertFalse(findings)

    def test_netlist_with_excessive_nesting_is_rejected_before_tree_parse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = "<node>" * 128 + "</node>" * 128
            (root / "deep.net").write_text(
                f"<export>{nested}</export>",
                encoding="utf-8",
            )
            inventory, findings = inspect_kicad_netlist(root, "deep.net")

        self.assertEqual("invalid", inventory.status)
        self.assertIn("nesting", inventory.limitations[0])
        self.assertFalse(findings)

    def test_seeded_malformed_xml_inputs_stay_inside_the_parser_boundary(self) -> None:
        rng = random.Random(20261029)
        alphabet = bytes(range(1, 128))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "fuzz.net"
            for _ in range(64):
                noise = bytes(rng.choice(alphabet) for _ in range(rng.randrange(1, 48)))
                path.write_bytes(b"<export><components/><nets>" + noise + b"</nets></export>")
                inventory, findings = inspect_kicad_netlist(root, path.name)

                self.assertIn(inventory.status, {"invalid", "parsed"})
                self.assertFalse(findings)


if __name__ == "__main__":
    unittest.main()

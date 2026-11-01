from __future__ import annotations

import ast
import importlib
import unittest
from pathlib import Path

from vigil_fuse.rules.registry import RULES

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "vigil_fuse"
PACKAGE_PREFIX = "vigil_fuse"


def _module_name(path: Path) -> str:
    parts = path.relative_to(PACKAGE_ROOT).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join((PACKAGE_PREFIX, *parts))


def _module_package(module_name: str, path: Path) -> str:
    if path.name == "__init__.py":
        return module_name
    return module_name.rpartition(".")[0]


def _internal_imports(module_name: str, path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = _module_package(module_name, path)
    imports: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(
                alias.name
                for alias in node.names
                if alias.name == PACKAGE_PREFIX or alias.name.startswith(f"{PACKAGE_PREFIX}.")
            )
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                package_parts = package.split(".")
                retained = max(0, len(package_parts) - node.level + 1)
                base_parts = package_parts[:retained]
            else:
                base_parts = []
            if node.module:
                base_parts.extend(node.module.split("."))
            target = ".".join(base_parts)

            if target == PACKAGE_PREFIX or target.startswith(f"{PACKAGE_PREFIX}."):
                if node.module is None:
                    imports.update(f"{target}.{alias.name}" for alias in node.names)
                else:
                    imports.add(target)

    return imports


def _module_graph() -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        name = _module_name(path)
        graph[name] = _internal_imports(name, path)
    return graph


class ArchitectureContractTests(unittest.TestCase):
    def test_internal_module_dependency_graph_is_acyclic(self) -> None:
        graph = _module_graph()
        active: list[str] = []
        complete: set[str] = set()

        def visit(module: str) -> None:
            if module in active:
                cycle = " -> ".join((*active[active.index(module) :], module))
                self.fail(f"internal import cycle detected: {cycle}")
            if module in complete:
                return
            active.append(module)
            for dependency in sorted(graph.get(module, ())):
                if dependency in graph:
                    visit(dependency)
            active.pop()
            complete.add(module)

        for module in sorted(graph):
            visit(module)

    def test_foundation_modules_remain_independent_of_application_layers(self) -> None:
        foundations = {
            "vigil_fuse.model",
            "vigil_fuse.input_types",
            "vigil_fuse.limits",
            "vigil_fuse.path_safety",
            "vigil_fuse.profiles",
            "vigil_fuse.target_labels",
            "vigil_fuse.text_safety",
        }
        graph = _module_graph()

        for module in sorted(foundations):
            with self.subTest(module=module):
                self.assertEqual(set(), graph[module])

    def test_rule_implementations_depend_only_on_the_shared_contract(self) -> None:
        graph = _module_graph()
        rule_directory = PACKAGE_ROOT / "rules"
        expected_rule_modules = {
            _module_name(path)
            for path in rule_directory.glob("*.py")
            if path.name not in {"__init__.py", "base.py", "registry.py"}
        }
        registered_rule_modules = {
            dependency
            for dependency in graph["vigil_fuse.rules.registry"]
            if dependency in expected_rule_modules
        }

        self.assertEqual(expected_rule_modules, registered_rule_modules)
        for module in sorted(expected_rule_modules):
            with self.subTest(module=module):
                self.assertLessEqual(
                    graph[module],
                    {"vigil_fuse.model", "vigil_fuse.rules.base"},
                )

        rule_ids = [rule.id for rule in RULES]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        expected_ids = {importlib.import_module(module).RULE.id for module in expected_rule_modules}
        self.assertEqual(expected_ids, set(rule_ids))

    def test_reporters_do_not_depend_on_scan_or_analyzer_orchestration(self) -> None:
        forbidden_prefixes = (
            "vigil_fuse.cli",
            "vigil_fuse.scanner",
            "vigil_fuse.rule_execution",
            "vigil_fuse.rule_worker",
            "vigil_fuse.rules",
            "vigil_fuse.analyzers",
            "vigil_fuse.dependency_analyzers",
            "vigil_fuse.firmware_analyzer",
            "vigil_fuse.history_analyzer",
        )
        graph = _module_graph()

        for module in ("vigil_fuse.reporting", "vigil_fuse.sarif"):
            forbidden = {
                dependency
                for dependency in graph[module]
                if any(
                    dependency == prefix or dependency.startswith(f"{prefix}.")
                    for prefix in forbidden_prefixes
                )
            }
            with self.subTest(module=module):
                self.assertEqual(set(), forbidden)


if __name__ == "__main__":
    unittest.main()

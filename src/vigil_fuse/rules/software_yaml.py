from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import PurePosixPath

from ..model import Finding, SourceFile
from .base import RuleDefinition


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    if PurePosixPath(source.path).suffix.casefold() != ".py":
        return
    try:
        tree = ast.parse(source.text)
    except (SyntaxError, ValueError, RecursionError):
        raise ValueError("Python source could not be parsed") from None
    imports: set[str] = set()
    rebound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "yaml":
                    imports.add(alias.asname or "yaml")
                else:
                    rebound.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            rebound.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            rebound.add(node.id)
        elif isinstance(node, ast.arg):
            rebound.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound.add(node.name)
    imports -= rebound
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in imports
            and node.func.attr == "unsafe_load"
        ):
            yield rule.finding(source, node.lineno, "PyYAML unsafe_load call")


RULE = RuleDefinition(
    id="FUSE-SW003",
    title="Python uses unsafe YAML deserialization",
    severity="medium",
    confidence="high",
    category="software-deserialization",
    explanation="An imported PyYAML module is called with unsafe_load. FUSE does not establish whether input is attacker controlled or this code runs.",
    potential_impact="If untrusted YAML reaches this loader, object construction can execute code.",
    remediation="Use yaml.safe_load for untrusted input and validate the resulting data.",
    scanner=_scan,
    references=("https://cwe.mitre.org/data/definitions/502.html",),
    prefilter=lambda source: (
        PurePosixPath(source.path).suffix.casefold() == ".py"
        and "yaml" in source.text
        and "unsafe_load" in source.text
    ),
)

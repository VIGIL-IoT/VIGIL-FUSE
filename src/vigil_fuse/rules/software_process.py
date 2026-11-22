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
                if alias.name == "subprocess":
                    imports.add(alias.asname or "subprocess")
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
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        receiver = node.func.value
        if not isinstance(receiver, ast.Name) or receiver.id not in imports:
            continue
        if node.func.attr not in {"run", "Popen", "call", "check_call", "check_output"}:
            continue
        if any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            yield rule.finding(source, node.lineno, "subprocess call with shell=True")


RULE = RuleDefinition(
    id="FUSE-SW001",
    title="Python subprocess invokes a shell",
    severity="medium",
    confidence="high",
    category="software-process-execution",
    explanation=(
        "A call to an imported subprocess module explicitly enables shell execution. "
        "FUSE does not track whether the command contains untrusted input or runs."
    ),
    potential_impact=(
        "If untrusted input reaches the command, shell interpretation can permit command injection."
    ),
    remediation="Avoid shell=True; pass a fixed executable and argument list without a shell.",
    scanner=_scan,
    references=("https://cwe.mitre.org/data/definitions/78.html",),
    prefilter=lambda source: (
        PurePosixPath(source.path).suffix.casefold() == ".py"
        and "shell" in source.text
        and "subprocess" in source.text
    ),
)

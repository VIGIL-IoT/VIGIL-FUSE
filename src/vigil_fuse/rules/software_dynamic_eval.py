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

    module_aliases: set[str] = set()
    function_aliases: set[str] = set()
    rebound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                if alias.name == "builtins":
                    module_aliases.add(name)
                else:
                    rebound.add(name)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "builtins":
                for alias in node.names:
                    name = alias.asname or alias.name
                    if alias.name in {"eval", "exec"}:
                        function_aliases.add(name)
                    else:
                        rebound.add(name)
            else:
                rebound.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            rebound.add(node.id)
        elif isinstance(node, ast.arg):
            rebound.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound.add(node.name)

    module_aliases -= rebound
    function_aliases -= rebound
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        direct_builtin = isinstance(function, ast.Name) and function.id in function_aliases
        module_builtin = (
            isinstance(function, ast.Attribute)
            and function.attr in {"eval", "exec"}
            and isinstance(function.value, ast.Name)
            and function.value.id in module_aliases
        )
        if direct_builtin or module_builtin:
            yield rule.finding(source, node.lineno, "explicit builtins eval/exec call")


RULE = RuleDefinition(
    id="FUSE-SW004",
    title="Python explicitly invokes dynamic code evaluation",
    severity="medium",
    confidence="high",
    category="software-dynamic-evaluation",
    explanation=(
        "A call resolves to the imported builtins eval or exec function. FUSE does not establish "
        "whether the argument is attacker controlled or the call executes."
    ),
    potential_impact=(
        "If untrusted input reaches dynamic evaluation, it may permit arbitrary code execution."
    ),
    remediation=(
        "Avoid eval and exec for data parsing; use a structured parser or ast.literal_eval when "
        "the accepted format is a Python literal."
    ),
    scanner=_scan,
    references=("https://cwe.mitre.org/data/definitions/95.html",),
    prefilter=lambda source: (
        PurePosixPath(source.path).suffix.casefold() == ".py"
        and "builtins" in source.text
        and ("eval" in source.text or "exec" in source.text)
    ),
)

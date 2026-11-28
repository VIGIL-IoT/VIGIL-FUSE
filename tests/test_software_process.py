from pathlib import Path

from vigil_fuse.model import SourceFile
from vigil_fuse.rules.software_process import RULE
from vigil_fuse.scanner import scan


def test_process_rule_boundaries() -> None:
    examples = [
        ("import subprocess as sp\nsp.run(cmd, shell=True)", 1),
        ("import subprocess\nsubprocess.run(cmd, shell=False)", 0),
        ("# subprocess.run(cmd, shell=True)", 0),
        ("import subprocess\ndef f(subprocess):\n subprocess.run(cmd, shell=True)", 0),
        ("import subprocess\nsubprocess.run(cmd, shell=flag)", 0),
    ]
    for text, expected in examples:
        assert len(list(RULE.scan(SourceFile(path="app.py", text=text)))) == expected


def test_process_rule_integrates_with_scan(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n")
    result = scan(tmp_path)
    finding = next(item for item in result.findings if item.rule_id == "FUSE-SW001")
    assert finding.applicability == "unknown"
    assert finding.validation_status == "not-validated"
    assert finding.evidence == "subprocess call with shell=True"

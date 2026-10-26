from pathlib import Path
import unittest

from vigil_fuse.model import SourceFile
from vigil_fuse.rules.registry import RULES

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures" / "rules"


class RuleFixtureTests(unittest.TestCase):
    def test_each_vulnerable_fixture_produces_expected_rule(self) -> None:
        for rule in RULES:
            with self.subTest(rule=rule.id):
                path = FIXTURES / f"{rule.id}-vulnerable.fixture"
                source = SourceFile(path=path.name, text=path.read_text(encoding="utf-8"))
                findings = list(rule.scan(source))
                self.assertTrue(findings, f"{rule.id} did not match its vulnerable fixture")
                self.assertEqual({rule.id}, {finding.rule_id for finding in findings})
                self.assertEqual("high", findings[0].confidence)

    def test_each_secure_fixture_has_no_finding(self) -> None:
        for rule in RULES:
            with self.subTest(rule=rule.id):
                path = FIXTURES / f"{rule.id}-secure.fixture"
                source = SourceFile(path=path.name, text=path.read_text(encoding="utf-8"))
                self.assertEqual([], list(rule.scan(source)))

    def test_credentials_are_redacted_from_evidence(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        path = FIXTURES / "FUSE001-vulnerable.fixture"
        source = SourceFile(path=path.name, text=path.read_text(encoding="utf-8"))
        finding = next(iter(rule.scan(source)))
        self.assertNotIn("S0me-realistic-secret", finding.evidence)
        self.assertIn("[REDACTED]", finding.evidence)

    def test_private_key_contents_are_not_in_evidence(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE002")
        path = FIXTURES / "FUSE002-vulnerable.fixture"
        source = SourceFile(path=path.name, text=path.read_text(encoding="utf-8"))
        finding = next(iter(rule.scan(source)))
        self.assertNotIn("ZmFrZS1maXh0dXJl", finding.evidence)

    def test_all_secret_values_on_a_matching_line_are_redacted(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        keys = ("pass" + "word", "api" + "_" + "token")
        text = (
            f'{keys[0]} = "first-secret-value"; '
            f'{keys[1]} = "second-secret-value"\n'
        )
        finding = next(iter(rule.scan(SourceFile(path="secrets.py", text=text))))
        self.assertNotIn("first-secret-value", finding.evidence)
        self.assertNotIn("second-secret-value", finding.evidence)
        self.assertEqual(2, finding.evidence.count("[REDACTED]"))

    def test_unquoted_env_secret_is_detected_and_redacted(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        source = SourceFile(path=".env", text="API_TOKEN=env-value-123456\n")
        finding = next(iter(rule.scan(source)))
        self.assertNotIn("env-value-123456", finding.evidence)
        self.assertIn("[REDACTED]", finding.evidence)

    def test_esp_idf_boot_validation_rule_requires_an_active_kconfig_assignment(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE006")
        key = "CONFIG_BOOTLOADER_" + "SKIP_VALIDATE_ALWAYS"
        text = f"# {key} is not set\n{key}=y\n"
        findings = list(rule.scan(SourceFile(path="sdkconfig", text=text)))

        self.assertEqual(1, len(findings))
        self.assertEqual(2, findings[0].start_line)
        self.assertEqual(f"{key}=y", findings[0].evidence)
        self.assertIn("does not establish that the file is the active build configuration", findings[0].explanation)

    def test_esp_idf_deep_sleep_rule_explains_its_ota_context(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE007")
        key = "CONFIG_BOOTLOADER_SKIP_VALIDATE_" + "IN_DEEP_SLEEP"
        finding = next(iter(rule.scan(SourceFile(path="sdkconfig", text=f"{key}=y\n"))))

        self.assertEqual("medium", finding.severity)
        self.assertIn("does not prove", finding.explanation)
        self.assertIn("active OTA partition", finding.explanation)
        self.assertEqual(1, len(finding.references))


if __name__ == "__main__":
    unittest.main()

from pathlib import Path
import unittest

from vigil_fuse.model import SourceFile
from vigil_fuse.rules.registry import RULES

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures" / "rules"


class RuleFixtureTests(unittest.TestCase):
    @staticmethod
    def fixture_source(rule_id: str, kind: str) -> SourceFile:
        path = FIXTURES / f"{rule_id}-{kind}.fixture"
        source_path = "sdkconfig" if rule_id in {"FUSE006", "FUSE007"} else path.name
        return SourceFile(path=source_path, text=path.read_text(encoding="utf-8"))

    def test_each_vulnerable_fixture_produces_expected_rule(self) -> None:
        for rule in RULES:
            with self.subTest(rule=rule.id):
                source = self.fixture_source(rule.id, "vulnerable")
                self.assertTrue(
                    rule.may_scan(source), f"{rule.id} prefilter rejected its vulnerable fixture"
                )
                findings = list(rule.scan(source))
                self.assertTrue(findings, f"{rule.id} did not match its vulnerable fixture")
                self.assertEqual({rule.id}, {finding.rule_id for finding in findings})
                self.assertEqual("high", findings[0].confidence)

    def test_each_secure_fixture_has_no_finding(self) -> None:
        for rule in RULES:
            with self.subTest(rule=rule.id):
                source = self.fixture_source(rule.id, "secure")
                self.assertEqual([], list(rule.scan(source)))

    def test_credentials_are_redacted_from_evidence(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        source = self.fixture_source("FUSE001", "vulnerable")
        finding = next(iter(rule.scan(source)))
        self.assertNotIn("S0me-realistic-secret", finding.evidence)
        self.assertIn("[REDACTED]", finding.evidence)

    def test_private_key_contents_are_not_in_evidence(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE002")
        source = self.fixture_source("FUSE002", "vulnerable")
        finding = next(iter(rule.scan(source)))
        self.assertNotIn("ZmFrZS1maXh0dXJl", finding.evidence)

    def test_all_secret_values_on_a_matching_line_are_redacted(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        keys = ("pass" + "word", "api" + "_" + "token")
        text = f'{keys[0]} = "first-secret-value"; {keys[1]} = "second-secret-value"\n'
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
        self.assertIn(
            "does not establish that the file is the active build configuration",
            findings[0].explanation,
        )

    def test_credentials_ignore_labels_locales_comments_and_test_source_but_scan_env_test(
        self,
    ) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        cases = (
            SourceFile("src/language/en.h", 'PASSWORD_LABEL = "Enter password"\n'),
            SourceFile(
                "src/core/language.h", '#define STR_PASSWORD_TOO_LONG "Password is too long"\n'
            ),
            SourceFile(
                "src/lcd/mks_ui/tft_Language_s_cn.h",
                '#define WIFI_SETTINGS_PASSWORD_CN "Password"\n',
            ),
            SourceFile("src/app.c", 'PASSWORD = "password is required"\n'),
            SourceFile("src/app.c", '// PASSWORD = "actual-secret-value"\n'),
            SourceFile("tests/test_config.py", 'password = "actual-secret-value"\n'),
        )
        for source in cases:
            with self.subTest(path=source.path):
                self.assertEqual([], list(rule.scan(source)))

        env_source = SourceFile(".env.test", "API_TOKEN=actual-secret-value\n")
        findings = list(rule.scan(env_source))
        self.assertEqual(1, len(findings))
        self.assertIn("[REDACTED]", findings[0].evidence)

    def test_credentials_ignore_common_embedded_tutorial_placeholders(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        placeholders = (
            "........",
            "yourpass",
            "yourpasswd",
            "yourPassword",
            "YourPSKHere",
            "wifi-password",
            "WiFi_Password",
            "write-api-key",
            "read_api_key",
        )
        for value in placeholders:
            with self.subTest(value=value):
                source = SourceFile(
                    "examples/wifi_config.cpp", f'const char *password = "{value}";\n'
                )
                self.assertEqual([], list(rule.scan(source)))

    def test_credentials_ignore_password_prompt_literals_inside_code_strings(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        source = SourceFile(
            "ports/cc3200/tools/update-wipy.py",
            'if b"Password:" in tn.read_until(b"Password:", timeout=5):\n',
        )
        self.assertEqual([], list(rule.scan(source)))

    def test_credentials_ignore_path_and_characteristic_constants_and_computed_values(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        text = (
            '#define PASSWD_FILE "/etc/passwd"\n'
            'const char *PASSWORD_CHARACTERISTIC = "7b8a0001-0000-0000-0000-000000000001";\n'
            'String realSASToken = "prefix" + createToken(deviceId);\n'
        )
        self.assertEqual([], list(rule.scan(SourceFile("src/config.cpp", text))))

        literal = SourceFile("src/config.cpp", 'const char *DEFAULT_PASSWORD = "device-default";\n')
        self.assertEqual(1, len(list(rule.scan(literal))))

    def test_credentials_ignore_filename_and_reserved_marker_constants(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        source = SourceFile(
            "src/security/EncryptedStorage.cpp",
            'const char *TOKEN_FILENAME = "unlock.token";\n'
            'const char *secretReserved = "reserved-marker-value";\n'
            'const char *access_token = "device-specific-auth-value";\n',
        )

        findings = list(rule.scan(source))

        self.assertEqual(1, len(findings))
        self.assertEqual(3, findings[0].start_line)
        self.assertEqual("FUSE001", findings[0].rule_id)

    def test_credentials_ignore_tinysrp_password_database_filename_only_in_its_header(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        filename_fixture = FIXTURES / "FUSE001-tinysrp-passwd-file-secure.fixture"
        credential_fixture = FIXTURES / "FUSE001-tinysrp-password-positive.fixture"
        source_path = "package/network/services/ead/src/tinysrp/t_pwd.h"
        filename_source = SourceFile(source_path, filename_fixture.read_text(encoding="utf-8"))
        credential_source = SourceFile(source_path, credential_fixture.read_text(encoding="utf-8"))
        unrelated_path_source = SourceFile(
            "src/auth/config.h", filename_fixture.read_text(encoding="utf-8")
        )

        self.assertEqual([], list(rule.scan(filename_source)))
        self.assertEqual(1, len(list(rule.scan(credential_source))))
        self.assertEqual(1, len(list(rule.scan(unrelated_path_source))))

    def test_credentials_ignore_hash_tutorial_inputs_and_build_expressions(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        hash_demo = SourceFile(
            "libraries/Hash/examples/MD5/MD5.ino",
            'String password = "Hello World";\n'
            'String passwordAsHex = "48656c6c6f20576f726c64";\n'
            "MD5Builder md;\nmd.add(password);\n",
        )
        make_expression = SourceFile(
            "package/skeleton-init-common.mk",
            'ROOT_PASSWORD = "`$(MKPASSWD) -m $(METHOD) $(ROOT_PASSWD)`"\n',
        )
        self.assertEqual([], list(rule.scan(hash_demo)))
        self.assertEqual([], list(rule.scan(make_expression)))

        ordinary_password = SourceFile("src/auth.cpp", 'const char *password = "Hello World";\n')
        self.assertEqual(1, len(list(rule.scan(ordinary_password))))

        ordinary_token = SourceFile("src/auth.cpp", 'const char *token = "auth-token-value";\n')
        self.assertEqual(1, len(list(rule.scan(ordinary_token))))

    def test_credentials_ignore_nmea_parser_sentence_tokens(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        parser_tokens = SourceFile(
            "src/gps_parser.c",
            "static ParserConfig parsers[] = {\n"
            '  {.token = "GPGSA", .parser = gpgsaParser},\n'
            '  {.token = "GPGGA", .parser = gpggaParser}\n'
            "};\n",
        )
        self.assertEqual([], list(rule.scan(parser_tokens)))

    def test_credentials_ignore_bitbake_metadata_and_disabled_xml_accounts(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE001")
        metadata = SourceFile(
            "recipes-connectivity/ppp/ppp.bb",
            'SUMMARY:${PN}-password = "Plugin to get passwords via a pipe"\n',
        )
        disabled_xml = SourceFile(
            "package/gerbera/config.xml",
            '<accounts enabled="no">\n'
            '  <account user="gerbera" password="gerbera" />\n'
            "</accounts>\n",
        )
        enabled_xml = SourceFile(
            "package/device/config.xml",
            '<accounts enabled="yes">\n'
            '  <account user="gerbera" password="device-default" />\n'
            "</accounts>\n",
        )
        self.assertEqual([], list(rule.scan(metadata)))
        self.assertEqual([], list(rule.scan(disabled_xml)))
        self.assertEqual(1, len(list(rule.scan(enabled_xml))))

    def test_private_key_rule_ignores_comments_and_test_material(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE002")
        sources = (
            SourceFile("src/keys.c", "// -----BEGIN PRIVATE KEY-----\n"),
            SourceFile("tests/test_key.pem", "-----BEGIN PRIVATE KEY-----\n"),
        )
        for source in sources:
            with self.subTest(path=source.path):
                self.assertEqual([], list(rule.scan(source)))

    def test_tls_rule_ignores_comments_strings_and_test_sources(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE003")
        sources = (
            SourceFile("src/tls.c", "// client.setInsecure()\n"),
            SourceFile("src/tls.c", 'const char *note = "client.setInsecure()";\n'),
            SourceFile("tests/test_tls.py", "session.verify = False\n"),
            SourceFile("src/menu_bed_tramming.cpp", "bool probe(const bool verify=false);\n"),
            SourceFile(
                "src/device.cpp", "// https://docs.example/tls\nbool probe(bool verify=false);\n"
            ),
        )
        for source in sources:
            with self.subTest(path=source.path, text=source.text):
                self.assertEqual([], list(rule.scan(source)))

    def test_tls_rule_keeps_generic_verify_false_when_https_context_is_present(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE003")
        source = SourceFile(
            "src/http_client.py",
            'requests.get("https://device.example", verify=False)\n',
        )
        self.assertEqual(1, len(list(rule.scan(source))))

    def test_tls_python_ast_detects_qualified_request_with_dynamic_endpoint(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE003")
        source = SourceFile(
            "src/client.py",
            "import requests\nresponse = requests.get(\n    endpoint,\n    verify=False,\n)\n",
        )

        findings = list(rule.scan(source))

        self.assertEqual(1, len(findings))
        self.assertEqual(4, findings[0].start_line)
        self.assertEqual("verify=False", findings[0].evidence)

    def test_tls_python_ast_detects_httpx_client_verification_bypass(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE003")
        source = SourceFile("src/client.py", "client = httpx.AsyncClient(verify=False)\n")

        findings = list(rule.scan(source))

        self.assertEqual(1, len(findings))
        self.assertEqual(1, findings[0].start_line)

    def test_tls_python_ast_does_not_flag_unrelated_verify_keyword(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE003")
        source = SourceFile(
            "src/client.py",
            "def configure(verify=False):\n    return verify\n\ncustom_builder(verify=False)\n",
        )

        self.assertEqual([], list(rule.scan(source)))

    def test_tls_rule_ignores_api_definition_but_keeps_bypass_call(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE003")
        definition = SourceFile(
            "libraries/NetworkClientSecure/src/NetworkClientSecure.cpp",
            "void NetworkClientSecure::setInsecure() {\n  _use_insecure = true;\n}\n",
        )
        call = SourceFile("src/client.cpp", "client.setInsecure();\n")
        self.assertEqual([], list(rule.scan(definition)))
        self.assertEqual(1, len(list(rule.scan(call))))

    def test_http_rule_requires_endpoint_context_and_ignores_comment_test_and_templates(
        self,
    ) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE004")
        sources = (
            SourceFile("src/http.c", 'const char *homepage = "http://docs.vendor.example";\n'),
            SourceFile("src/http.c", 'const char *url = "http://api.device.example";\n'),
            SourceFile("src/http.c", 'const char *url = "http://ip";\n'),
            SourceFile("src/http.c", 'const char *API_URL = "http://%HOST%/api";\n'),
            SourceFile("src/http.c", '/* API_URL = "http://api.device.example"; */\n'),
            SourceFile("tests/test_http.py", 'API_URL = "http://api.device.example"\n'),
        )
        for source in sources:
            with self.subTest(path=source.path, text=source.text):
                self.assertEqual([], list(rule.scan(source)))

        direct_call = SourceFile(
            "src/client.py", 'requests.get("http://api.device.local/status")\n'
        )
        self.assertEqual(1, len(list(rule.scan(direct_call))))

    def test_http_rule_ignores_reserved_test_domains_and_example_private_addresses(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE004")
        sources = (
            SourceFile("examples/client.ino", 'http.begin("http://example.com/index.html");\n'),
            SourceFile("examples/client.ino", 'http.begin("http://api.device.invalid/update");\n'),
            SourceFile("examples/client.ino", 'http.begin("http://192.168.1.12/status");\n'),
            SourceFile("meta/lib/oeqa/selftest/cases/spdx.py", 'url = "http://foo.bar/spdx"\n'),
        )
        for source in sources:
            with self.subTest(path=source.path, text=source.text):
                self.assertEqual([], list(rule.scan(source)))

        application_private_host = SourceFile(
            "src/client.ino", 'http.begin("http://192.168.1.12/status");\n'
        )
        self.assertEqual(1, len(list(rule.scan(application_private_host))))

    def test_http_rule_ignores_an_explicit_https_redirect_probe(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE004")
        source = SourceFile(
            "examples/WiFiMultiAdvanced.ino",
            'http.begin("http://www.vendor.com");\n'
            "int httpCode = http.GET();\n"
            "// We expect to get a 301 because the server redirects to HTTPS.\n"
            "if (httpCode == HTTP_CODE_MOVED_PERMANENTLY) return true;\n",
        )
        self.assertEqual([], list(rule.scan(source)))

    def test_http_rule_strips_multiline_comments_and_keeps_endpoint_assignments(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE004")
        text = '/* license comment\n API_URL = \\"http://api.device.local\\";\n*/\nAPI_URL = "http://api.device.local/v1"\n'
        findings = list(rule.scan(SourceFile("src/config.h", text)))
        self.assertEqual(1, len(findings))
        self.assertEqual(4, findings[0].start_line)

    def test_http_rule_keeps_http_ota_endpoint_in_safeboot_context(self) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE004")
        source = SourceFile(
            "berry/extensions/Partition_Wizard/partition_wizard.be",
            'static _default_safeboot_URL = "http://ota.device.local/release/%s.bin"\n',
        )
        self.assertEqual(1, len(list(rule.scan(source))))

    def test_mqtt_rule_requires_broker_context_and_ignores_comments_tests_and_loopback(
        self,
    ) -> None:
        rule = next(rule for rule in RULES if rule.id == "FUSE005")
        sources = (
            SourceFile("src/app.c", 'const char *uri = "mqtt://broker.device.example";\n'),
            SourceFile("src/app.c", '// broker_uri = "mqtt://broker.device.example"\n'),
            SourceFile("tests/test_mqtt.py", 'broker_uri = "mqtt://broker.device.example"\n'),
            SourceFile("src/app.c", 'broker_uri = "mqtt://127.0.0.1:1883"\n'),
            SourceFile("src/app.c", 'broker_uri = "mqtt://%BROKER%:1883"\n'),
        )
        for source in sources:
            with self.subTest(path=source.path, text=source.text):
                self.assertEqual([], list(rule.scan(source)))

        configured = SourceFile(
            "src/mqtt/client.c", 'broker_uri = "mqtt://broker.device.example:1883"\n'
        )
        self.assertEqual(1, len(list(rule.scan(configured))))

    def test_esp_idf_configuration_rules_are_scoped_to_kconfig_inputs(self) -> None:
        for rule_id, key in (
            ("FUSE006", "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS"),
            ("FUSE007", "CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP"),
        ):
            rule = next(rule for rule in RULES if rule.id == rule_id)
            with self.subTest(rule=rule_id):
                self.assertEqual([], list(rule.scan(SourceFile("README.md", f"{key}=y\n"))))
                self.assertEqual([], list(rule.scan(SourceFile("tests/sdkconfig", f"{key}=y\n"))))
                self.assertEqual([], list(rule.scan(SourceFile("sdkconfig", f"# {key}=y\n"))))
                findings = list(
                    rule.scan(SourceFile("sdkconfig.defaults", f"{key}=y # reviewed\n"))
                )
                self.assertEqual(1, len(findings))
                self.assertEqual("medium", findings[0].severity)
                self.assertEqual("high", findings[0].confidence)

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

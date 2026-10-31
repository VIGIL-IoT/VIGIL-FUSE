# Native rule development

Native rules are small, evidence-oriented checks over selected source or configuration text. They run in FUSE's killable worker process and return the common `Finding` model. A rule match is a static signal. It does not establish reachability, deployment, or exploitability.

## Current rule catalog

| ID | Platform | Severity | Confidence | Evidence |
| --- | --- | --- | --- | --- |
| FUSE001 | Generic embedded source and environment files | medium | high | Credential-like literal assigned or compared with a password-like input |
| FUSE002 | Generic text source | high | high | PEM private-key boundary marker |
| FUSE003 | Generic source | high | high | Explicit TLS bypass patterns, with Python AST support for qualified Requests and HTTPX calls |
| FUSE004 | Generic source and configuration | medium | high | Non-loopback plaintext HTTP endpoint in endpoint context |
| FUSE005 | Generic source and configuration | medium | high | Plaintext MQTT URI in broker or endpoint context |
| FUSE006 | ESP-IDF Kconfig inputs and selected generated config | medium | high | `CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS=y` |
| FUSE007 | ESP-IDF Kconfig inputs and selected generated config | medium | high | `CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP=y` |

### FUSE001: Credential-like literal in source

- **Category:** secrets
- **Evidence:** A credential-related identifier such as `password`, `secret`, `token`, or `api_key` is assigned a literal, or a password-like input is compared with a literal. Plain assignments are also checked in `.env` files. Evidence replaces matched values with `[REDACTED]`.
- **False-positive considerations:** UI labels, comments, tests, localization, placeholders, prompts, computed values, filename and reserved-marker constants, selected BitBake metadata, disabled XML accounts, and TinySRP's `DEFAULT_PASSWD` database filename are filtered using narrow context checks. Ordinary literals in examples remain review signals when they look credential-like.
- **Limitations:** FUSE cannot validate the credential, determine if it is used, or establish whether the file is built or deployed. It does not scan binary data for secrets.
- **Remediation:** Remove committed secrets, rotate any exposed value, and provision credentials through a protected deployment or device-provisioning process.
- **Reference:** [CWE-798](https://cwe.mitre.org/data/definitions/798.html)

### FUSE002: Private key PEM marker embedded in scanned file

- **Category:** secrets
- **Evidence:** A recognized PEM private-key boundary marker outside comments and test paths. Matched key contents are not included in evidence.
- **False-positive considerations:** Documentation, comments, and test material are excluded by path and lexical rules. A marker can still be an example or an incomplete key.
- **Limitations:** FUSE does not parse or validate the key, determine whether it is usable, or establish trust, packaging, or deployment.
- **Remediation:** Remove private key material from source and firmware, rotate or revoke affected keys, and provision unique keys securely.
- **Reference:** [CWE-321](https://cwe.mitre.org/data/definitions/321.html)

### FUSE003: TLS peer verification appears disabled

- **Category:** transport-security
- **Evidence:** Explicit patterns include `verify=false`, `check_hostname=false`, `CERT_NONE`, Go `InsecureSkipVerify: true`, `insecure_skip_verify=true`, and `.setInsecure()`. For syntactically valid Python, the standard-library AST also recognizes literal `verify=False` in qualified `requests` and `httpx` calls, even when the endpoint is dynamic. Generic lexical `verify=false` requires TLS-related context in the file or line.
- **False-positive considerations:** Comments, strings, test paths, C++ method definitions, and calls inside literal inactive C preprocessor branches are filtered. A TLS bypass in a test or unreachable branch may not affect a release.
- **Limitations:** The rule does not resolve variables, callbacks, function reachability, symbolic preprocessor conditions, trust stores, or build inclusion. The Python AST check requires qualified `requests` or `httpx` calls and does not track imported aliases or data flow. Syntax errors use the existing conservative lexical checks.
- **Remediation:** Enable certificate-chain and hostname verification, provision the right trust anchor, and prevent test overrides from entering production builds.
- **Reference:** [CWE-295](https://cwe.mitre.org/data/definitions/295.html)

### FUSE004: Non-loopback HTTP endpoint configured

- **Category:** transport-security
- **Evidence:** A plaintext `http://` endpoint in endpoint-like source context. Loopback and reserved example domains are excluded. Evidence does not copy unrelated credentials from the same line.
- **False-positive considerations:** Build-time downloads, redirect probes, documentation, test paths, templates, and reserved examples are filtered where context is clear. HTTP may be intentionally used behind a separate protected transport.
- **Limitations:** FUSE does not resolve redirects, prove the endpoint is contacted, identify the relevant network boundary, or infer product inclusion. A URL in a build helper is different from a device's runtime OTA endpoint.
- **Remediation:** Use an authenticated encrypted transport where supported, validate the server identity, and review any intentional local or provisioning-only HTTP use.
- **Reference:** [CWE-319](https://cwe.mitre.org/data/definitions/319.html)

### FUSE005: Plaintext MQTT broker URI configured

- **Category:** transport-security
- **Evidence:** A non-loopback `mqtt://` URI in broker or endpoint context. The URI scheme indicates plaintext MQTT.
- **False-positive considerations:** Comments, test paths, loopback values, placeholders, and non-endpoint strings are ignored. A transport may have protections outside the URI, so the finding remains a static indicator.
- **Limitations:** FUSE does not establish that a connection is made, whether a TLS tunnel or other protection is added, or whether the source is used in the selected build.
- **Remediation:** Use TLS-protected MQTT, verify the broker certificate, and keep broker credentials out of source.
- **Reference:** [CWE-319](https://cwe.mitre.org/data/definitions/319.html)

### FUSE006: ESP-IDF bootloader image validation is disabled

- **Category:** boot-integrity
- **Evidence:** The active assignment `CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS=y` in a recognized Kconfig input or selected generated configuration. Commented assignments do not match.
- **False-positive considerations:** `sdkconfig.defaults` is a candidate and might not be selected by the build. A checked-in `sdkconfig` is not proof of release configuration.
- **Limitations:** FUSE does not resolve Kconfig dependencies, choose between build variants, verify bootloader behavior, or establish deployment. Generated configuration findings are build candidates.
- **Remediation:** Keep image validation enabled unless a reviewed requirement justifies otherwise; verify the effective release `sdkconfig` and resulting bootloader.
- **Reference:** [ESP-IDF Kconfig reference](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/kconfig-reference.html)

### FUSE007: ESP-IDF skips app-image validation after deep sleep

- **Category:** boot-integrity
- **Evidence:** The active assignment `CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP=y` in a recognized Kconfig input or selected generated configuration.
- **False-positive considerations:** The option may be unused by the active build, and the OTA plus deep-sleep sequence described by its impact may not occur.
- **Limitations:** FUSE does not resolve Kconfig dependencies, inspect runtime control flow, identify the active OTA partition, or prove that a modified image can reach this path.
- **Remediation:** Keep validation enabled where OTA changes can be followed by deep sleep. Review the effective configuration, Secure Boot settings, and device lifecycle.
- **Reference:** [ESP-IDF Kconfig reference](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/kconfig-reference.html)

## Required rule change protocol

1. State the exact evidence and the supported input scope. Prefer a parser or configuration model when lexical matching cannot distinguish syntax reliably.
2. Add a vulnerable fixture and a secure fixture. Add negative cases for comments, strings, test paths, generated configuration, and common embedded examples where relevant.
3. Assert the expected rule ID, location, severity, confidence, and sanitized evidence. Keep severity, confidence, applicability, validation, and coverage separate.
4. Run `python -m pytest -q` and `python scripts/evaluate_rule_benchmark.py --check`.
5. Update the support matrix and documentation only when the implementation and tests support the claim.

The small fixture benchmark is a regression check only. Use `docs/detection-benchmark.md` for its limitations and the separate development, regression, and holdout corpora.

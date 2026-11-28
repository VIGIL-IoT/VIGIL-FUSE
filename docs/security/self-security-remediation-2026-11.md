# FUSE self-security remediation, November 2026

## Scope

This report records remediation of findings FUSE-SELF-001 through FUSE-SELF-006 from the local audit. The work is on `fix/self-security-remediation`, created from `origin/main` at `8c3ded9bb2840d7344076307365dbf0dd0068fe3`. `origin/main` later advanced to `e3937f308c997133ad872cb4713ab90698abd5ba` with unrelated language-composition changes. No merge to `main` was made. The source audit remains local and untracked.

## Findings

### FUSE-SELF-001: Build and publish shared PyPI OIDC privilege

- **Risk:** Compromised build code could run in a job able to request the PyPI publishing identity. Floating build tools could also change release output unexpectedly.
- **Fix:** Release construction and checks now run in a read-only build job without `id-token: write`. It uploads the wheel, sdist, and SHA-256 manifest. A separate protected publish job has OIDC permission, checks the exact expected artifact names and hashes, and publishes the downloaded distributions without checkout or rebuild. Release build tools and the build backend are pinned to `build==1.6.1`, `twine==7.0.0`, and `setuptools==84.2.1`. `docs/releasing.md` explains how to review and update the pins.
- **Tests:** `tests/test_pypi_publish_workflow.py`; isolated package build; `twine check` passed for wheel and sdist; fresh wheel installation and smoke verification passed.
- **Residual:** The hosted workflow and PyPI trusted-publisher settings were not inspected or executed. GitHub environment protection still needs to be confirmed in the repository settings.
- **Status:** Remediated in source; hosted release verification remains pending.

### FUSE-SELF-002: Report output followed hard-link aliases

- **Risk:** Truncating an existing hard-linked report could change a file outside the selected result directory.
- **Fix:** Writers use the shared `path_safety` API. It validates parent components and destination type, rejects hard links and aliases, writes a same-directory temporary file, flushes it, and atomically replaces the destination. The change covers JSON, text, SARIF, explicit output, policy, BOM/SBOM, provenance, citation, reasoning, firmware, Git history, Ghidra, and document outputs.
- **Tests:** Hard-link regression tests exercise report formats and shared writers with a sacrificial file outside the results directory. The outside bytes remain unchanged. `tests/test_output_safety.py` passed in the full suite.
- **Residual:** Atomic replacement behavior was exercised on this Windows host. Other supported operating systems are covered by CI configuration but their hosted runs were not available during this remediation.
- **Status:** Remediated.

### FUSE-SELF-003: Windows junctions bypassed symlink-only checks

- **Risk:** A junction or other reparse point could expand scan scope or redirect an output or managed install directory.
- **Fix:** Central path checks recognize `FILE_ATTRIBUTE_REPARSE_POINT` as well as symbolic links. Root selection, recursive discovery, project identity, repo DNA, output paths, setup locations, temporary boundaries, and analyzer inputs use the checks. Metadata paths are canonicalized only when they remain within the selected project; escaping aliases are rejected. Output and install destinations reject aliases in their parent chains.
- **Tests:** Windows junction tests cover a target root, a junction below the target, output and setup paths, identity inventory, and repo DNA. Junction creation and those tests ran on this Windows host. Full suite passed.
- **Residual:** No hosted Windows CI run or concurrent filesystem race test was available.
- **Status:** Remediated.

### FUSE-SELF-004: XML DTD rejection depended on encoding

- **Risk:** A UTF-16 DTD/entity declaration could bypass a byte-text check in an unmerged software-manifest parser and expose the process to unsafe XML or resource exhaustion.
- **Fix:** The canonical branch now has a shared Expat preflight that rejects DTD and entity declarations independent of encoding and bounds input bytes, element count, depth, attributes, and aggregate text. Both KiCad netlist entry points and SVD parsing use it before ElementTree construction. No network entity resolution is enabled.
- **Tests:** XML tests cover UTF-8, UTF-8 BOM, UTF-16 LE/BE, and UTF-32 LE/BE where supported, including DTD/entity rejection and size/structure limits. Full suite passed.
- **Residual:** The audit's additional `pom.xml` and `.csproj` parser was on the local, unmerged `feat/universal-software-security-engine-v2` worktree and is not present in this canonical branch. That separate parser was not modified. It must use the shared preflight when that feature is integrated.
- **Status:** Current canonical XML parsers remediated; the off-branch parser remains open for integration.

### FUSE-SELF-005: Host analyzers run with caller authority

- **Risk:** A vulnerable optional analyzer running on the host can access resources available to the invoking user.
- **Fix:** CLI help and scan plans explicitly say host analyzers are unsandboxed and run with the current user's permissions. Docker isolation remains opt-in, with no silent host fallback.
- **Tests:** Host-mode help and plan tests passed; Docker-unavailable behavior remains explicit.
- **Residual:** Host mode intentionally retains the caller's authority. For hostile inputs, use the documented digest-pinned Docker mode or a low-privilege disposable account.
- **Status:** Accepted residual, with warning strengthened and behavior documented.

### FUSE-SELF-006: Static site lacked defense-in-depth response headers

- **Risk:** Missing browser policy headers reduced protection against future content injection and framing mistakes.
- **Fix:** `vercel.json` now configures a restrictive CSP with reviewed script and style hashes, `frame-ancestors`, no `unsafe-eval` or script `unsafe-inline`, and `script-src-attr 'none'`. Existing inline script blocks are hash-allowlisted. Inline style attributes remain enabled for the two static diagram pages. It also sets `nosniff`, strict referrer policy, Permissions-Policy, same-origin framing, and HSTS. Its ignore command compares against Vercel's last successful branch deployment and forces a build when no previous deployment exists.
- **Tests:** `tests/test_site_security_headers.py` passed. The ignore command was exercised with Bash for first deployment, changed site content, and unchanged site content. Six Mermaid diagrams rendered with the pinned renderer.
- **Residual:** Vercel reported a successful status for the pushed commit, but its deployment detail redirected to login and the preview hostname could not be confirmed. A production HEAD request returned 200 but still lacked CSP, nosniff, Referrer-Policy, Permissions-Policy, and X-Frame-Options. It still sends `Access-Control-Allow-Origin: *`; the reviewed site is static and exposes no authenticated API. Production has not been promoted.
- **Status:** Header configuration is implemented. Deployed response verification remains blocked by unavailable Vercel deployment access.

## Validation

- Full suite with branch coverage at `72f58c5f5d7a9dc04fc16c233feac23a6e9cbb49`: **689 passed, 12 skipped, 225 subtests passed**. Total coverage was **79%**, above the 75% threshold.
- Focused path, CLI, and integration regressions: **76 passed, 23 subtests passed**.
- Ruff lint and format checks passed. Strict Mypy passed for 99 source files.
- Documentation links validated for 143 Markdown files in the local working tree, including the local untracked audit. All 25 JSON schemas validated. Six Mermaid diagrams rendered.
- Native rule fixture benchmark passed: 24 synthetic cases across seven rules; FUSE001 had 4 true positives, 0 false positives, and 0 false negatives.
- Isolated `pip-audit --local` found no known vulnerable dependencies. It could not audit the editable `vigil-fuse 0.4.1.dev0` package because that version is not published on PyPI.
- Fresh wheel and source distribution built with the pinned backend; Twine checks passed. The wheel was installed outside the source checkout and its CLI smoke checks and full test suite passed with 688 passed, 12 skipped, and 225 subtests before the Vercel ignore regression test was added. The final source suite passed with 689 tests.
- Self-scan completed over 690 files with complete discovery and native rules. It reported six findings, all from intentionally vulnerable RTL fixtures, and no high or critical findings. RTL analysis remains partial because Verible was unavailable.
- The isolated branch-history path audit passed for 1,282 tracked files and reachable Git history. The local source audit file remained untracked and was not included.
- GitHub Actions workflow runs and external analyzer integrations were not inspected. Vercel's status check succeeded, but deployed response verification remains incomplete because the preview host could not be confirmed and production still serves the old headers.

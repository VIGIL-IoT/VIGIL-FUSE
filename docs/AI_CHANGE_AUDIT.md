# AI change audit

**Audit date:** 2026-11-02
**Repository:** VIGIL-IoT/VIGIL-FUSE
**Purpose:** Record material automated changes and validation for the repository engineering pass requested with the Research-Grade Repository Architecture and Engineering Standard.

## Material changes

| Change | Reason | Evidence or implementation source |
| --- | --- | --- |
| Website visual restyle | Apply the user-provided NOEMA site's layout and interaction style while retaining FUSE identity, content, and red accent | Local NOEMA files were inspected at `web/src/App.tsx`, `web/src/index.css`, and `web/src/components/ui/morphic-navbar.tsx`. FUSE changes are in `site/index.html`, `site/styles.css`, and `site/script.js` |
| Report fragment card sizing | Give each report example card a shared heading height and equal card height across the horizontal gallery | `site/styles.css`; checked in the local browser across all five cards |
| Usage guide | Give operators a tested, CLI-first path covering planning, scanning, optional analyzers, hardware inputs, reports, and scope limits | `docs/usage.md` and its README link |
| Optional analyzer Docker mode | Add digest-pinned, local-image execution with read-only inputs, bounded stdout capture, isolated runtime settings, default no-network behavior, configuration inspection, and no host fallback | `src/vigil_fuse/analyzer_sandbox.py`, `src/vigil_fuse/analyzer_runtime.py`, CLI adapters, and sandbox tests |
| Rights review packet | Organize ownership, earlier license history, third-party notices, contribution policy, and distribution questions for owner and qualified legal review | `docs/governance/rights-review-packet.md`; no legal conclusion or license change |
| Independent evaluation protocol | Make the frozen holdout, dual-review, no-finding sample, comparator, and metrics process operational | `docs/research/independent-evaluation-protocol.md`; independent reviewers have not yet completed a review |
| Trust-boundary architecture figure | Show untrusted project input, the local FUSE path, and the distinct host and explicit Docker analyzer modes | `docs/diagrams/fuse-trust-boundaries.html`, exported to `docs/figures/fuse-trust-boundaries.svg` and linked from `README.md` and `docs/architecture.md` |
| Diagram punctuation cleanup | Honor the repository-wide instruction to avoid em dashes without changing embedded diagram behavior | Comment and descriptive text changes in `site/diagrams/fuse-scan.html` |
| Assumption register and failure-mode table | Make target authorization, static-evidence limits, analyzer trust, scan consistency, and operational recovery explicit | `docs/requirements.md` and `docs/threat-model.md` |
| Compatibility matrix | Separate tested OS and Python combinations from package metadata and unverified environments | `docs/compatibility.md` |
| Specialist tool registry and source ledger | Record which prompt-referenced skills are installed, used, not applicable, or unverified, and preserve research sources that informed documented decisions | `docs/AI_SKILLS_REFERENCE.md` and `docs/research-sources.md` |

## External research

The maturity closure research in `docs/research/maturity-100-closure-plan-2026-11-02.md` records official sources collected with Crawl4AI 0.9.5. For the website restyle, the supplied local NOEMA checkout was the reference. This pass did not crawl local code. Crawl4AI was used to check selected public skill repository pages; several requests timed out and are marked unverified in the skill registry.

## Validation performed

- `python -m coverage run -m pytest -q` and `python -m coverage report -m --fail-under=75`: 330 passed, 1 skipped, 150 subtests passed, 78% branch coverage, one environment warning. The skipped test requires the locally built Docker fixture and is run separately.
- Branch coverage measured 78%, above the 75% CI threshold.
- Ruff and formatting checks, strict Mypy across 56 source files, Markdown validation across 89 files, the 24-case native-rule fixture benchmark, and the path audit across 670 tracked files and Git history passed.
- Editable installation, `doctor`, scan help, and a JSON scan from the usage guide passed in a temporary Windows virtual environment.
- Wheel and source distribution builds, Twine metadata checks, and a clean temporary Windows virtual-environment install passed with current license metadata. The installed CLI completed `doctor`; a source self-scan covered 335 files with complete discovery and zero findings.
- The website dark and light themes were reviewed at desktop, tablet, and mobile widths in the prior visual pass.
- The Diagram Design HTML passed the installed skill self-check. Its exported SVG parsed as XML, and Playwright renders were inspected in light and dark themes. Figure claims were checked against `docs/threat-model.md`, `analyzer_sandbox.py`, and `analyzer_runtime.py`.
- Sandbox unit tests passed. A fixture-image integration test passed on Windows Docker Desktop Linux engine 28.5.1, verifying denied input writes, hidden prior reports, bounded report-path storage, CycloneDX output capture, and container cleanup. The official Syft v1.55.0 image at digest `sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a` also completed a FUSE SBOM scan with two components. A dedicated Linux CI integration job is defined in this increment; its hosted result is pending.

## Limits and unresolved work

- No physical hardware was available or needed for FUSE's software tests. This audit makes no hardware validation claim.
- Host execution remains the default for optional analyzers. Docker mode is opt-in. Local integration is verified on Windows Docker Desktop; the new Linux CI result is pending. Linux rootless, macOS, other daemon versions, and cleanup under daemon failure still need evidence.
- Local `pip-audit` could not reach its advisory service, and local Mermaid rendering could not pull its pinned GHCR image. Remote GitHub checks must be read from their workflow runs.
- Legal rights and distribution decisions require the owner and qualified counsel. This audit does not change the license or publish a package.
- Independent field-accuracy review still requires permission-cleared holdout data, two reviewers, and disagreement adjudication. Preparing a protocol does not supply that evidence.
- GitHub Actions and Vercel outcomes are external checks and must be reported from their actual run state, not inferred from local validation.

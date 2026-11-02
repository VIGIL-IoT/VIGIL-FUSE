# AI change audit

**Audit date:** 2026-11-02
**Repository:** VIGIL-IoT/VIGIL-FUSE
**Purpose:** Record material automated changes and validation for the repository engineering pass requested with the Research-Grade Repository Architecture and Engineering Standard.

## Material changes

| Change | Reason | Evidence or implementation source |
| --- | --- | --- |
| Website visual restyle | Apply the user-provided NOEMA site's layout and interaction style while retaining FUSE identity, content, and red accent | Local NOEMA files were inspected at `web/src/App.tsx`, `web/src/index.css`, and `web/src/components/ui/morphic-navbar.tsx`. FUSE changes are in `site/index.html`, `site/styles.css`, and `site/script.js` |
| Usage guide | Give operators a tested, CLI-first path covering planning, scanning, optional analyzers, hardware inputs, reports, and scope limits | `docs/usage.md` and its README link |
| Diagram punctuation cleanup | Honor the repository-wide instruction to avoid em dashes without changing embedded diagram behavior | Comment and descriptive text changes in `site/diagrams/fuse-scan.html` |
| Assumption register and failure-mode table | Make target authorization, static-evidence limits, analyzer trust, scan consistency, and operational recovery explicit | `docs/requirements.md` and `docs/threat-model.md` |
| Compatibility matrix | Separate tested OS and Python combinations from package metadata and unverified environments | `docs/compatibility.md` |
| Specialist tool registry and source ledger | Record which prompt-referenced skills are installed, used, not applicable, or unverified, and preserve research sources that informed documented decisions | `docs/AI_SKILLS_REFERENCE.md` and `docs/research-sources.md` |

## External research

The maturity closure research in `docs/research/maturity-100-closure-plan-2026-11-02.md` records official sources collected with Crawl4AI 0.9.5. For the website restyle, the supplied local NOEMA checkout was the reference. This pass did not crawl local code. Crawl4AI was used to check selected public skill repository pages; several requests timed out and are marked unverified in the skill registry.

## Validation performed

- `python -m pytest -q`: 313 passed, 148 subtests passed, one environment warning.
- Branch coverage measured 78%, above the 75% CI threshold.
- Ruff, strict Mypy, local Markdown and Mermaid-fence validation across 87 Markdown files, and the 24-case native-rule fixture benchmark passed.
- The repository path audit passed across tracked files and Git history.
- Editable installation, `doctor`, scan help, and a JSON scan from the usage guide passed in a temporary Windows virtual environment.
- Wheel and source distribution builds and `python -m twine check dist/*` passed with current license metadata. A FUSE self-scan completed on 332 files with zero high or critical findings and complete discovery.
- The website dark and light themes were reviewed at desktop, tablet, and mobile widths in the prior visual pass.
- A local Docker Desktop Linux-engine smoke check verified selected container flags for an Ubuntu image. FUSE does not invoke that container runtime, so this is runtime evidence only and does not establish analyzer sandboxing.

## Limits and unresolved work

- No physical hardware was available or needed for FUSE's software tests. This audit makes no hardware validation claim.
- No analyzer sandbox integration was added. Optional external analyzers still run as host processes, with the limitations in `docs/threat-model.md`.
- Local `pip-audit` could not reach its advisory service, and local Mermaid rendering could not pull its pinned GHCR image. Remote GitHub checks must be read from their workflow runs.
- Legal rights and distribution decisions require the owner and qualified counsel. This audit does not change the license or publish a package.
- Independent field-accuracy review requires permission-cleared holdout data and reviewers who were not available in this pass.
- GitHub Actions and Vercel outcomes are external checks and must be reported from their actual run state, not inferred from local validation.

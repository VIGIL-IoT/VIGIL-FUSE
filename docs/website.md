# FUSE project site

The static landing page lives in [site/](../site/) and uses plain HTML, CSS, and JavaScript. It has no build step, package dependencies, or environment variables. The root [Vercel configuration](../vercel.json) sets the output directory to `site`; the Python analyzer package remains independent.

## Deploy to Vercel

Import `VIGIL-IoT/VIGIL-FUSE` from GitHub and use these project settings:

| Setting | Value |
| --- | --- |
| Root Directory | `./` |
| Framework Preset | `Other` |
| Build Command | Leave blank |
| Output Directory | `site` |
| Environment Variables | None |

Keep the root directory at the repository root so Vercel can read `vercel.json`. Vercel serves the files in the configured output directory.

Vercel's `ignoreCommand` compares each commit with its parent and skips deployments when neither `site/` nor `vercel.json` changed. This avoids spending deployment attempts on Python package, test, documentation, and CI-only changes while ensuring site and deployment configuration changes still build.

Preview locally from the repository root with:

    py -m http.server 4173 --directory site

Then open http://localhost:4173. The install section points to the published [PyPI package](https://pypi.org/project/vigil-fuse/), provides pipx and virtual environment commands, and shows how to preview and run scans. The main repository [usage guide](usage.md) contains the full install, profile, optional analyzer, and report instructions.

The interactive finding panel uses vulnerable fixtures for FUSE001, FUSE003, and FUSE006. They are labelled as test examples. The repository scan section reads its pinned snapshot from `site/data/repository-scan-results.json`; full JSON, text, and SARIF reports are in `reports/repository-scans/`. Its counts are raw static indicators, not confirmed vulnerabilities or hardware results. The site links the current FUSE 0.3.0 transfer replay separately from the older 0.2.0 corpus. The site describes FUSE's current analysis scope and states that device testing is not part of the workflow.

After regenerating repository scan reports, run `py scripts\build_repository_scan_dashboard.py` from the repository root to refresh the scan summary, supported-input matrix, and SVG plots in `reports/repository-scans/plots/` and `site/assets/`.

The page uses no stock board imagery. The report-fragment row scrolls horizontally by design and includes arrow controls and a visible swipe hint. Its supported-input matrix is generated from `src/vigil_fuse/support-matrix.json`, so labels and scope descriptions stay aligned with the CLI support contract.

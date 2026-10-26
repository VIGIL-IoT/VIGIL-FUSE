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

Preview locally from the repository root with:

    py -m http.server 4173 --directory site

Then open http://localhost:4173. The website's command example installs the package from the repository and writes a scan's text, JSON, and SARIF reports to the `.fuse-results` folder.

The interactive finding panel uses vulnerable fixtures for FUSE001, FUSE003, and FUSE006. They are labelled as test examples. The repository scan section reads its pinned snapshot from `site/data/repository-scan-results.json`; full JSON, text, and SARIF reports are in `reports/repository-scans/`. Its counts are raw static indicators, not confirmed vulnerabilities or hardware results. FUSE 0.2.0's rule-context changes and remaining limitations are documented in the report directory. The SPECTRA-32 research loop remains planned work.

After regenerating repository scan reports, run `py scripts\build_repository_scan_dashboard.py` from the repository root to refresh the site data and SVG plots in `reports/repository-scans/plots/` and `site/assets/`.

The page uses no stock board imagery. The report-fragment row scrolls horizontally by design and includes arrow controls and a visible swipe hint.

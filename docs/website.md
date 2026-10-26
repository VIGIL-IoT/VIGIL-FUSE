# FUSE project site

The static landing page lives in [site/](../site/) and uses plain HTML, CSS, and JavaScript. It has no build step or JavaScript package dependencies. The root Vercel configuration points at the site output directory; the Python analyzer package remains independent.

Preview locally from the repository root with:

    py -m http.server 4173 --directory site

Then open http://localhost:4173. The website's command example installs the package from the repository and writes a scan's text, JSON, and SARIF reports to the .fuse-results folder.

The interactive finding panel is populated from the vulnerable fixtures for FUSE001, FUSE003, and FUSE006. Every example is labelled as a test fixture; it is not represented as a scan of a device or customer project. The scope and limits shown on the site reflect the current CLI implementation.

The physical-board image is credited in the website footer and kept unaltered. Downloaded source and licence metadata for the image search are recorded in site/assets/credits.json.

The page does not use video: FUSE is a CLI-first package and no genuine product footage exists yet. The interactive finding panel demonstrates real fixture content without implying that FUSE has already scanned a pictured board. The report-fragment row scrolls horizontally by design and includes arrow controls and a visible swipe hint.

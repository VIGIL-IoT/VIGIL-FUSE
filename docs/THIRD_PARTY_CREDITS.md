# Third-party credits

This file records external software that FUSE can invoke, vendors for figure generation, or embeds in static visual assets. It does not grant rights beyond the terms of each upstream project.

## Ghidra

- **Project:** Ghidra
- **Developer:** National Security Agency Research Directorate
- **Official repository:** <https://github.com/NationalSecurityAgency/ghidra>
- **License:** [Apache License 2.0](https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE)
- **Notice:** [Upstream NOTICE](https://github.com/NationalSecurityAgency/ghidra/blob/master/NOTICE)
- **Use in VIGIL-FUSE:** Optional external binary-analysis backend invoked through Ghidra Headless Analyzer.
- **Distribution:** VIGIL-FUSE does not bundle or redistribute the Ghidra application.

`FuseExport.java` is maintained by Shantanu and independently written against documented Ghidra APIs. It does not copy Ghidra source code or examples. Ghidra names and marks remain subject to upstream terms. The integration does not imply that the National Security Agency, Ghidra maintainers, or any government organization endorses, sponsors, or is affiliated with VIGIL-FUSE.

Because FUSE invokes an installation supplied by the user, the Ghidra binary and its notices remain with that installation. The FUSE wheel includes only the FUSE-owned adapter script and its schema.

## Archify

- **Project:** [Archify](https://github.com/tt-a1i/archify)
- **License:** Apache License 2.0, as stated in the generated diagram's embedded software notice.
- **Use in VIGIL-FUSE:** The generated standalone Ghidra workflow diagram in `site/diagrams/fuse-scan.html` includes Archify output and its embedded notice. The Archify application is not a FUSE runtime dependency.

## Anatomy kit

- **Project:** [Anatomy](https://github.com/wheresryan22/anatomy)
- **License and notice:** MIT, retained at `scripts/vendor/anatomy/LICENSE` and `scripts/vendor/anatomy/NOTICE.md`.
- **Use in VIGIL-FUSE:** The vendored `iso-kit.mjs` is used by the figure-generation script only. It is not a FUSE runtime dependency.

## JetBrains Mono

- **Project:** [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono)
- **License:** SIL Open Font License 1.1, embedded with the font data in `site/diagrams/fuse-scan.html`.
- **Use in VIGIL-FUSE:** The self-contained diagram embeds the font and its notice for browser rendering. It is not included in the Python package.

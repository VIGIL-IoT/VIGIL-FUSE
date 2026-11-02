# Third-party credits

This file records external software that FUSE can invoke or uses in validation. It does not grant rights beyond the terms of each upstream project.

## Ghidra

- **Project:** Ghidra
- **Developer:** National Security Agency Research Directorate
- **Official repository:** <https://github.com/NationalSecurityAgency/ghidra>
- **License:** [Apache License 2.0](https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE)
- **Notice:** [Upstream NOTICE](https://github.com/NationalSecurityAgency/ghidra/blob/master/NOTICE)
- **Use in VIGIL-FUSE:** Optional external binary-analysis backend invoked through Ghidra Headless Analyzer.
- **Distribution:** VIGIL-FUSE does not bundle or redistribute the Ghidra application.

`FuseExport.java` is maintained by VIGIL-IoT contributors and independently written against documented Ghidra APIs. It does not copy Ghidra source code or examples. Ghidra names and marks remain subject to upstream terms. The integration does not imply that the National Security Agency, Ghidra maintainers, or any government organization endorses, sponsors, or is affiliated with VIGIL-FUSE.

Because FUSE invokes an installation supplied by the user, the Ghidra binary and its notices remain with that installation. The FUSE wheel includes only the FUSE-owned adapter script and its schema.

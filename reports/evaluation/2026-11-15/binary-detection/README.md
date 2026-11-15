# FUSE binary detection completeness comparison

A VIGIL Project

This report compares the immutable November 14 ESP-IDF scan artifacts with the separately stored November 15 rebuild and rerun. The November 14 files were not modified. Old schema 1.0 artifacts did not record independent security traversal status, so their rule coverage is unsupported, not a clean negative.

| Target | Old inventory | New inventory | Old rule evaluation | New rule evaluation | New findings | New truncation groups |
| --- | --- | --- | --- | --- | --- | --- |
| esp32 | partial | partial | unsupported | complete | none | cross_references, exports, strings, symbols |
| esp32s3 | partial | partial | unsupported | complete | none | cross_references, exports, strings, symbols |
| esp32c6 | partial | partial | unsupported | complete | none | cross_references, exports, strings, symbols |

## Build input identity

| Target | November 14 ELF SHA-256 | November 15 ELF SHA-256 | Bytes old to new | Pinned provenance |
| --- | --- | --- | ---: | --- |
| esp32 | `230a0746f0e560e5582ce6a7a0de9e2846d4666ec56359dfe957a25959982a5f` | `433cfda174f40099354288da071a99994ce246878313cd1ddb9c700857265528` | 2392300 to 2392300 | same pinned build provenance |
| esp32s3 | `1315dc271837076a925df9a7cc942e0a08204097cba9526c2675fb109de35457` | `ccf9acff1a43c4d5b7149808a216178aa80da16aed1a2d75283380cba61f7156` | 3049700 to 3049700 | same pinned build provenance |
| esp32c6 | `ee11b7878d47b16c6fac132258cc453e8bec44994fab53fe9962c8965fcf2fae` | `4cfcfaaa9fe085b297e411354be2f60866ae82322a9a9eae21a5b031c10cf8a8` | 2866584 to 2866584 | same pinned build provenance |

ELF SHA-256 differs for esp32, esp32s3, esp32c6. For these targets, the pinned project commit, ESP-IDF image, build command, provenance, and byte count match, but the original November 14 ELF files were not archived. This compares scan outputs from separate rebuilds of the same pinned inputs, not scans of verified byte-identical binaries. The available artifacts do not establish why the ELF bytes differ.
Full source, image, command, repository, and license provenance is preserved in `comparison.json` and the copied compatibility records.

## Measured details

| Target | Input SHA-256 match | Ghidra | Findings | Inventory groups truncated | Time old to new (seconds) | Sampled RSS old to new (bytes) | Artifact bytes old to new |
| --- | --- | --- | --- | --- | ---: | ---: | ---: |
| esp32 | no | 12.2 | none | cross_references, exports, strings, symbols | 20.34 to 18.76 | 793468928 to 894160896 | 741081 to 741906 |
| esp32s3 | no | 12.2 | none | cross_references, exports, strings, symbols | 18.81 to 19.70 | 899727360 to 987693056 | 658811 to 659636 |
| esp32c6 | no | 12.2 | none | cross_references, exports, strings, symbols | 23.37 to 15.55 | 658567168 to 911683584 | 868237 to 869062 |

The artifact records include processor language, per-rule counts, reference visits, execution time, process-tree RSS samples, artifact size, and inventory truncation. RSS is sampled, not a hard memory ceiling. Security completion does not imply complete inventory or general firmware coverage.

The new security traversal is validated on controlled binaries with more than 1,500 ordinary strings, secure HTTPS and MQTTS controls, unreferenced plaintext endpoints, optimization variants, and stripped binaries. Those controls are construction-based regressions, not independent accuracy evidence.

See [the preregistered protocol](protocol.md), [pre-change manifest](prechange-manifest.json), [ESP-IDF configuration applicability review supplement](config-applicability/README.md), and [November 14 evaluation](../../2026-11-14/README.md).

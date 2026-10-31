# Credential comparison probe: NIST SARD case 2043

## Question

Does FUSE identify a hard-coded password when C++ compares a password-like variable directly with a string literal?

## Case provenance

NIST SARD case [2043, version 1.0.0](https://samate.nist.gov/SARD/test-cases/2043/versions/1.0.0) is an accepted bad C++ test case for CWE-259, Use of Hard-coded Password. It is part of [SARD test suite 59](https://samate.nist.gov/SARD/test-suites/59).

The downloaded suite archive SHA-256 was `0ae14c50fe29a920722a761f5fab49e0e39265a46d0908aa02720431cbbc50bf`. The single extracted source member, `src/hardcoded_pass_basic1.cpp`, had SHA-256 `5e880533a8f39d47f1ae036341147fd51fa0f7697a3a9d3dd2ec7f1947b719f69d` and was 961 bytes. The source stayed in a temporary directory and is not included in this repository. No redistribution or licensing claim is made for the upstream sample.

## Procedure

The sample was scanned as a single selected C++ source file. All seven native FUSE rules were enabled. Optional external analyzers, project builds, and execution of the sample were not part of the procedure. The reported path is relative to the temporary scan target.

| Run | FUSE source commit | FUSE001 version | Result |
| --- | --- | --- | --- |
| Baseline | `2c80283bbb71aae123df0b10682d864f8956f652` | 1.7.0 | 0 findings |
| Updated rule | `9f2e5a65ce29f4d86d89511c447990defe66e06a` | 1.8.0 | 1 FUSE001 finding at line 27 |

The updated finding was medium severity and high confidence. Its literal evidence was redacted in the JSON report.

## Interpretation and limits

This single case confirms that the previous rule missed a password-like variable compared directly with a hard-coded string, and that FUSE001 now reports this pattern. It does not establish whether the code is reachable in a product, whether a password is valid, or how often this pattern occurs in deployed firmware. One NIST C++ case cannot estimate FUSE precision, recall, or IoT-specific coverage. This supplemental probe is separate from the 24 synthetic fixture benchmark and does not change its reported scores.

NIST describes SARD as a collection of test material with varying origins and terms. The per-case source was not retained or redistributed here. See the [SARD manual](https://www.nist.gov/itl/csd/secure-systems-and-applications/software-assurance-reference-dataset-sard-manual) and NIST's [copyright and licensing notes](https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications).

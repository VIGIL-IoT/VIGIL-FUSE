# FUSE001 test-context regression from NVIDIA edk2-nvidia

- **Source:** NVIDIA/edk2-nvidia
- **Pinned source revision:** `cb638768ec174bb2041f87569409c53e4af4292e`
- **Record type:** manually adjudicated contextual regression
- **Regression purpose:** Recognize exact `UnitTest` directory variants so equivalent synthetic host-unit-test inputs do not surface as production credential candidates, while the same literal remains detectable in ordinary source.

## Historical result

The pinned scan produced one medium-severity FUSE001 lexical candidate with high confidence, unknown applicability, and no validation. Its source location was `Silicon/NVIDIA/Library/RedfishPlatformCredentialLib/UnitTest/CredentialBootstrapUnitTest.c`.

Manual review established that `USERNAME_STRING` and `PASSWORD_STRING` were repeated-character inputs used for mocked bootstrap credential responses. The source path was under `UnitTest`; `CredentialBootstrapUnitTest.inf` declared `MODULE_TYPE = HOST_APPLICATION`; and `Platform/NVIDIA/HostBasedTests/HostBasedTests.dsc` included the module. This supports a test-fixture, non-production interpretation of this candidate. It is not evidence that NVIDIA contains a vulnerability.

## Minimal synthetic regression

The checked-in fixture contains only the relevant macro structure and synthetic values. No NVIDIA source is copied into FUSE:

```c
#define USERNAME_STRING "AAAAAAAAAAAAAAAA"
#define PASSWORD_STRING "BBBBBBBBBBBBBBBB"
```

FUSE001 must emit no finding for this content at `vendor/Library/CredentialLib/UnitTest/CredentialBootstrapUnitTest.c`. The same content at `src/CredentialBootstrap.c` must emit one FUSE001 finding. This paired case checks that source context drives the result, not the repeated-character literal shape.

The shared path classifier recognizes exact directory names such as `unittest`, `unit-test`, `unit_test`, `unittests`, `unit-tests`, and `unit_tests`, case-insensitively. Near-matching names remain ordinary paths. `.env.test` remains scanned according to the existing FUSE001 policy.

This is contextual false-positive reduction. Recognizing a test-only source path does not prove that every file outside test directories is production-shipped, and it does not prove that every credential inside tests is harmless. FUSE does not determine build inclusion or deployment from this path check alone.

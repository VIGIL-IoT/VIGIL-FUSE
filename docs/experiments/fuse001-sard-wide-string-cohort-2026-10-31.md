# FUSE001 NIST SARD wide-string cohort

**Date:** 2026-10-31  
**FUSE revision:** `1aaccb4999b0ddf562302e5eba7ee7113a17aaf8`  
**Rule:** FUSE001 1.9.0  
**Result type:** supplemental known-case regression check

## Question

Does FUSE001 recognize credential literals written with C character-prefixed string syntax, including wide-character literals used in C and C++ code?

## Input selection

The sample contains ten NIST Software Assurance Reference Dataset (SARD) cases selected from the Juliet C/C++ suite. Each selected case is an accepted, mixed-state C case for CWE-259, Use of Hard-coded Password. The cases cover the listed Juliet flow variants and include narrow-character and wide-character examples. The [NIST SARD case page](https://samate.nist.gov/SARD/test-cases/93521/versions/1.0.0) shows the case metadata for case 93521. The [SARD dataset overview](https://samate.nist.gov/SARD/) and [suite catalogue](https://samate.nist.gov/SARD/test-suites) describe the broader dataset.

Archives were downloaded for this check, their SHA-256 digests were verified, and extraction was bounded and checked for unsafe paths. The sources and generated reports stayed in a temporary directory and are not redistributed here. The table records each archive digest so the inputs can be checked again.

| SARD case | Flow variant | NIST SARIF target | Archive SHA-256 | FUSE001 1.9.0 source hit |
| --- | ---: | --- | --- | --- |
| [93498](https://samate.nist.gov/SARD/test-cases/93498/versions/1.0.0) | 01 | `...w32_char_01.c:34` | `eb565270918c60192bb7c5a69e91381e0af1792edb2b41927167b1a520bd17b1` | `...w32_char_01.c:21` |
| [93521](https://samate.nist.gov/SARD/test-cases/93521/versions/1.0.0) | 34 | `...w32_char_34.c:41` | `40a76a13594f377c3e806137b6b56900d061eeaf8fb50d66bc3c99e313fc4b7d` | `...w32_char_34.c:21` |
| [93547](https://samate.nist.gov/SARD/test-cases/93547/versions/1.0.0) | 02 | `...w32_wchar_t_02.c:36` | `b8c1c3bd2971ec90a4b25bf78edf6c1ccc1211e51772c29390b6eb86a5dd7350` | `...w32_wchar_t_02.c:21` |
| [93553](https://samate.nist.gov/SARD/test-cases/93553/versions/1.0.0) | 08 | `...w32_wchar_t_08.c:50` | `e8fe04d77361ccf4e23a414cb369cf09260d6a0d2f73ec8e1342c9b9eb10f866` | `...w32_wchar_t_08.c:21` |
| [93562](https://samate.nist.gov/SARD/test-cases/93562/versions/1.0.0) | 17 | `...w32_wchar_t_17.c:37` | `3e7d55811890d27a2604eeb679c7f59c9dd1e510c57d723c8df1a1c7f4104156` | `...w32_wchar_t_17.c:21` |
| [93566](https://samate.nist.gov/SARD/test-cases/93566/versions/1.0.0) | 31 | `...w32_wchar_t_31.c:34` | `30aea80c628716fa710391f19eb6693a24ed6cfaddb7c8c15639359c74a4893e` | `...w32_wchar_t_31.c:21` |
| [93570](https://samate.nist.gov/SARD/test-cases/93570/versions/1.0.0) | 41 | `...w32_wchar_t_41.c:59` | `9532273951c12201553b61e26caa4ab7333abb8dc6f894fd4f86c53257fb062e` | `...w32_wchar_t_41.c:21` |
| [93573](https://samate.nist.gov/SARD/test-cases/93573/versions/1.0.0) | 44 | `...w32_wchar_t_44.c:61` | `cefcbd1f522886a751c321d99c223af1f9b983ad88ba1c1f5f71cb35bb251ffe` | `...w32_wchar_t_44.c:21` |
| [93579](https://samate.nist.gov/SARD/test-cases/93579/versions/1.0.0) | 61 | `...w32_wchar_t_61b.c:31` | `629a3fef228a2e4b96b7b33ab5a9efd7cfd0f385d02da4236b6177c0123cc1ac` | `...61a.c:21` and `...61b.c:21` |
| [93585](https://samate.nist.gov/SARD/test-cases/93585/versions/1.0.0) | 67 | `...w32_wchar_t_67a.c:43` | `16b4a66f253919052578fb134038519ed5f5a73cf87290047af143e69354e408` | `...67a.c:21` and `...67b.c:21` |

The abbreviated filenames in the table all share the `src/testcases/CWE259_Hard_Coded_Password/CWE259_Hard_Coded_Password__` prefix. FUSE scanned six files in each single-source case and seven files in each paired-source case. The findings were medium severity, high confidence static signals with redacted evidence and `not-validated` status.

## Procedure

The FUSE 1.8.0 baseline and FUSE 1.9.0 revision scanned the extracted case directories with the generic profile. Optional SBOM, vulnerability, firmware, and Git-history stages were disabled. No source was built or executed.

The command used for the FUSE 1.9.0 pass was:

```powershell
python -m vigil_fuse scan <case-source-directory> --profile generic --no-sbom --no-vulnerabilities --no-firmware --no-git-history --no-network --format json --output <report.json>
```

## Results

FUSE001 1.8.0 found the target source file in 2 of 10 cases. FUSE001 1.9.0 found the NIST target file in all 10 cases. It emitted 12 findings because cases 93579 and 93585 each include paired `a` and `b` source files, and both files matched. FUSE reports the credential literal source line, line 21 in these cases. The NIST SARIF targets point to later sink lines, so those line numbers are not expected to be identical.

The change in FUSE001 1.9.0 recognizes `u8`, `u`, `U`, and `L` string prefixes in assignments, macros, and password comparisons. Paired synthetic vulnerable and secure fixtures cover these forms in the regular native-rule regression benchmark.

## Limits

This is a deliberately selected, narrow regression set for C CWE-259 cases in Juliet. The cases are not a random sample of source repositories. SARD marks them `mixed`, meaning each case includes both bad and good paths. A match means FUSE recognized the hard-coded source literal; it does not mean the credential is active, reachable, deployed, exploitable, or confirmed in a product.

The result is not a precision, recall, field-accuracy, or general C/C++ compatibility estimate. It does not replace a larger independently labeled benchmark with representative positive and negative projects. NIST documentation also cautions that Juliet cases have design limitations, so this experiment does not treat the suite as ground truth for arbitrary software.

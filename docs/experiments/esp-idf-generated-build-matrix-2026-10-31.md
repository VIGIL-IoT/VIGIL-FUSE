# ESP-IDF generated build context matrix

## Result

GitHub Actions run [41155177181](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41155177181) passed nine generated-build checks. It built Espressif's `examples/get-started/hello_world` project with three ESP-IDF releases and three targets per release. FUSE CI run [41155177144](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41155177144) passed on the same FUSE revision, `ebe718e`.

| ESP-IDF release | Pinned source commit | Container image digest | `esp32` | `esp32s3` | `esp32c6` |
| --- | --- | --- | --- | --- | --- |
| v5.3.6 | `79e3454c68248bd7d881721c9b2e94561378a8ce` | `sha256:cee52f0c4fdaf088992a7a739f5993154e95cf1d3ab61c24f5b40e6d56a3a070` | [report](../../reports/esp-idf-build-context/2026-10-31/v5.3.6-esp32.json) | [report](../../reports/esp-idf-build-context/2026-10-31/v5.3.6-esp32s3.json) | [report](../../reports/esp-idf-build-context/2026-10-31/v5.3.6-esp32c6.json) |
| v5.5.6 | `880a203ae603d08a94d06aa01e0d6761958e5e9e` | `sha256:bf72fe7a15c22849a9a94147301165a545fb8905d97c176cf748e3e4614cac84` | [report](../../reports/esp-idf-build-context/2026-10-31/v5.5.6-esp32.json) | [report](../../reports/esp-idf-build-context/2026-10-31/v5.5.6-esp32s3.json) | [report](../../reports/esp-idf-build-context/2026-10-31/v5.5.6-esp32c6.json) |
| v6.1 | `fff9895c82d744c7237be8847347bdd1b07c6643` | `sha256:81893c71bb5e570088901f21def8684c25cd2a9020281bd01b843a7655edb18c` | [report](../../reports/esp-idf-build-context/2026-10-31/v6.1-esp32.json) | [report](../../reports/esp-idf-build-context/2026-10-31/v6.1-esp32s3.json) | [report](../../reports/esp-idf-build-context/2026-10-31/v6.1-esp32c6.json) |

## Method

Each job verifies that the checked out ESP-IDF source matches its pinned commit, copies the upstream example, selects the requested target with `idf.py set-target`, and runs `idf.py build`. It then scans the generated project with FUSE's ESP-IDF profile and selected `build` directory. The source and image are pinned in [the workflow](../../.github/workflows/esp-idf-build-matrix.yml).

All nine reports passed. Each observed the expected framework version and target, selected the project's generated `sdkconfig`, scanned six project files, and returned zero native findings, including no `FUSE006` or `FUSE007` findings. The individual JSON reports preserve the source commit, image digest, input manifest digest, selected configuration metadata, and finding counts.

ESP-IDF's generated [`project_description.json` template for v5.3.6](https://github.com/espressif/esp-idf/blob/v5.3.6/tools/cmake/project_description.json.in), [v5.5.6](https://github.com/espressif/esp-idf/blob/v5.5.6/tools/cmake/project_description.json.in), and [v6.1](https://github.com/espressif/esp-idf/blob/v6.1/tools/cmake/project_description.json.in) exposes the framework revision as `git_revision`. Commit `ebe718e` updates FUSE to read that field while retaining compatibility with `idf_ver` and `idf_version` metadata aliases.

## Limits

This verifies builds and FUSE's selected-build metadata handling for these nine release and target combinations. It does not flash or run a physical board, establish behavior of a shipped product, evaluate rule recall, or prove general compatibility with every ESP-IDF project. The report records conventional sdkconfig defaults as candidates when the selected build does not provide their order. The work does not change the repository's 91/100 maturity score because independent field-accuracy adjudication, hardware-in-the-loop validation, stronger process isolation for optional analyzers, and license review remain open.

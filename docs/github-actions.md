# GitHub Actions example

The FUSE repository also runs `.github/workflows/ci.yml`, which tests the supported Python matrix, validates the packaged report schema, builds the wheel and source distribution, and exercises the installed CLI. The workflow below is a separate template for scanning a repository that uses FUSE.

This workflow template keeps the scan job limited to repository read access, saves the canonical JSON, text, and SARIF reports as a workflow artifact, and uploads SARIF in a separate job with `security-events: write`. It restores the scan's nonzero status after report upload so findings and incomplete analysis still fail the workflow. External fork pull requests skip SARIF publication because they cannot write code-scanning results to the base repository.

Copy it into `.github/workflows/fuse.yml` after selecting the repository's intended default branch and confirming that code scanning is available for the repository.

```yaml
name: FUSE

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions: {}

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
    outputs:
      scan_outcome: ${{ steps.fuse_scan.outcome }}
      report_available: ${{ steps.report_check.outputs.available }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"

      - name: Install FUSE
        run: python -m pip install .

      - name: Scan repository
        id: fuse_scan
        continue-on-error: true
        run: vigil-fuse scan . --output-dir .fuse-results --fail-on high

      - name: Check reports
        id: report_check
        if: always()
        shell: bash
        run: |
          if [[ -f .fuse-results/findings.json && -f .fuse-results/findings.sarif ]]; then
            echo "available=true" >> "$GITHUB_OUTPUT"
          else
            echo "available=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Save FUSE reports
        if: always() && steps.report_check.outputs.available == 'true'
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: fuse-reports
          path: .fuse-results/
          include-hidden-files: true
          if-no-files-found: error

  publish_sarif:
    needs: scan
    if: >-
      always() &&
      needs.scan.outputs.report_available == 'true' &&
      (github.event_name != 'pull_request' ||
       github.event.pull_request.head.repo.full_name == github.repository)
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Download FUSE reports
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: fuse-reports
          path: .fuse-results

      - name: Upload SARIF to code scanning
        uses: github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0
        with:
          sarif_file: .fuse-results/findings.sarif
          category: vigil-fuse

  enforce-scan-result:
    needs: [scan, publish_sarif]
    if: always()
    runs-on: ubuntu-latest
    timeout-minutes: 2
    permissions: {}
    steps:
      - name: Enforce scan and publication status
        env:
          SCAN_JOB_RESULT: ${{ needs.scan.result }}
          SCAN_OUTCOME: ${{ needs.scan.outputs.scan_outcome }}
          REPORT_AVAILABLE: ${{ needs.scan.outputs.report_available }}
          PUBLISH_RESULT: ${{ needs.publish_sarif.result }}
        shell: bash
        run: |
          if [[ "$SCAN_JOB_RESULT" != "success" || "$SCAN_OUTCOME" != "success" || "$REPORT_AVAILABLE" != "true" ]]; then
            echo "FUSE scan failed, was incomplete, or did not produce reports."
            exit 1
          fi
          if [[ "$PUBLISH_RESULT" == "failure" ]]; then
            echo "SARIF publication failed."
            exit 1
          fi
```

The scan job uploads the full report folder as a workflow artifact. The SARIF job runs only for repository-owned events and has the write permission required by GitHub code scanning. The enforcement job has no token permissions and fails after publication if FUSE returned a finding threshold or incomplete-scan status.

Action versions are pinned to full commits from verified upstream releases: [checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1), [setup-python v7.0.0](https://github.com/actions/setup-python/releases/tag/v7.0.0), [upload-artifact v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2), [download-artifact v8.0.1](https://github.com/actions/download-artifact/releases/tag/v8.0.1), and [CodeQL Action v4.39.0](https://github.com/github/codeql-action/releases/tag/v4.39.0). Review and update pinned commits as part of routine dependency maintenance.

The scan step writes reports before returning a severity-based or incomplete-scan exit code, so the workflow can save and publish evidence first. FUSE scans selected source and configuration text by default. It does not build the project or validate findings on hardware.

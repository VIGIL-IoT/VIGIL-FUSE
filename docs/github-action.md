# FUSE GitHub Action

The Action runs this repository's FUSE Python core and writes the canonical JSON, text and SARIF reports. It does not run a separate scanner. Use a reviewed, immutable commit SHA in production; `@v1` is an eventual release interface, not a claim that the tag exists today. The checked-out target must be available before the Action runs.

```yaml
name: Security
on: [push, pull_request, workflow_dispatch]
permissions:
  contents: read
jobs:
  fuse:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - uses: VIGIL-IoT/VIGIL-FUSE@<reviewed-commit-sha>
        with:
          path: .
          fail-on: none
```

For a PR-only differential review set `baseline: 'true'` and `fail-on: high`. The checkout must contain the PR base commit (`fetch-depth: 0` above). FUSE scans a bounded extracted base tree and the current checkout with the same profile and target label, then uses its baseline identities and CLI. FUSE reports new, persistent, moved and resolved results; moved is not a proven semantic change and no independent `changed` identity is invented. Incomplete or incompatible comparisons are **unknown**, never clean. The base archive is limited to 512 MiB extracted; symlinks are skipped. The report includes `baseline-diff.json` when comparison succeeds.

`fail-on` accepts `none`, `info`, `low`, `medium`, `high`, or `critical`. Without a baseline it applies to all current findings; with one it applies to new findings. `none` reports without failing on findings. An unknown gate does not fail by default; set `require-complete: 'true'` when your policy requires complete analysis or a valid comparison. This does not turn an unavailable analyzer into a finding.

`profile` is `generic`, `esp-idf`, `zephyr`, `embedded-linux`, or `rtl`. `network` defaults to `offline`; `online` permits network-dependent advisory lookup only when `dependency-analysis: 'true'`. That option requests Syft and OSV-Scanner, which must already be installed in the runner. Missing or failed tools are reported as incomplete. No tools or databases are installed by FUSE. FUSE does not run target build scripts. Scan resources are subject to FUSE limits.

Reports are uploaded by default; set `artifact-upload: 'false'` to opt out. Artifacts can contain sensitive source evidence and should be handled using repository retention and access controls. Set `sarif-upload: 'true'` and grant `security-events: write` for Code Scanning, subject to repository availability and GitHub fork restrictions. The SARIF is FUSE's output, with its rule IDs, locations, fingerprints and supported metadata. A failed upload is a workflow failure, not evidence that a scan failed.

For one updated PR comment, provide `comment-token: ${{ github.token }}` and grant `pull-requests: write`. The token is supplied only to the post-scan comment step; the scan subprocess gets a restricted environment. Fork PRs normally receive a read-only token, so omit commenting and SARIF upload when permissions do not permit them. The job summary and report artifacts remain available subject to GitHub's permissions. Never use `pull_request_target` to check out and scan an untrusted PR: the adapter rejects that event. Use `pull_request`, a trusted pinned Action revision, no secrets, and no privileged follow-up that executes PR-controlled files. Do not use `uses: ./` from an untrusted PR checkout with write tokens. Third-party analyzers run with runner permissions when requested; run untrusted code on ephemeral isolated runners.

Example PR configuration, after checkout with full history:

```yaml
- uses: VIGIL-IoT/VIGIL-FUSE@<reviewed-commit-sha>
  with:
    baseline: 'true'
    fail-on: high
    network: offline
    sarif-upload: 'true'
    comment-token: ${{ github.token }}
```

Grant only the permissions needed for the selected features. For fork PRs, omit the last two inputs or use a separately designed trusted reporting workflow that consumes validated artifacts without executing PR code. Outputs `report-directory` and `gate` expose the local report path and `pass`, `fail`, or `unknown`. Exit status reflects policy, not proof of exploitability. FUSE's report records project context, analyzer status, coverage, and provenance; an absent finding does not establish complete inspection or runtime safety.

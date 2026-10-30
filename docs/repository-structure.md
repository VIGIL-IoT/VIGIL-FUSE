# Repository structure

The current tree follows the Python `src/` layout and keeps the CLI package, tests, research records, scan evidence, and static website separate. There is no FUSE-owned schematic, PCB, or physical hardware design in this repository. Hardware files encountered in target repositories are scan inputs stored as evidence under reports, not FUSE hardware implementation.

```text
VIGIL-FUSE/
├── .github/
│   ├── ISSUE_TEMPLATE/       issue forms
│   ├── workflows/            CI, tests, quality, package smoke checks
│   └── PULL_REQUEST_TEMPLATE.md
├── docs/
│   ├── decisions/            architecture decision records
│   ├── experiments/          repository evaluation protocol and interpretation
│   ├── research/              sourced research and feature strategy
│   └── *.md                   architecture, requirements, methods, limits, governance
├── reports/
│   ├── benchmark/             native-rule and scan-performance evidence plus schemas
│   ├── pilot-validation/      separately labelled pilot and holdout evidence
│   └── repository-scans/      pinned scan manifests, reports, plots, and triage
├── scripts/                   scan runners, report builders, validators, and scan benchmark
├── site/                      static project page and reviewed result snapshots
├── src/vigil_fuse/
│   ├── rules/                  native rule modules
│   ├── schemas/                packaged JSON report schemas
│   └── *.py                    CLI, scanner, models, platform and analyzer adapters
├── tests/
│   ├── fixtures/               vulnerable, secure, and parser input samples
│   └── test_*.py               unit, integration, CLI, reporting, and packaging tests
├── CHANGELOG.md
├── CITATION.cff
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
├── fuse.example.toml
├── pyproject.toml
└── vercel.json
```

`build/`, `dist/`, virtual environments, caches, coverage files, and `.fuse-results/` are generated or local artifacts and are ignored by Git. The top-level `site/` directory is a static informational page; it is not the FUSE analysis engine or a hosted report backend.

For module responsibility details see [architecture](architecture.md). For file capability boundaries see [hardware analysis](hardware-analysis.md) and [firmware analysis](firmware-analysis.md).

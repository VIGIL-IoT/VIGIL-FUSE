# Installation and setup

FUSE requires Python 3.11 or newer. The core Python package has no runtime dependencies. Optional analysis tools remain separate executables and are only used when requested.

## Install the current source

The adapted feature set is in this repository source. From the repository root:

~~~powershell
python -m pip install .
vigil-fuse --version
vigil-fuse doctor
~~~

For development, include the test, documentation, and interactive terminal tools:

~~~powershell
python -m pip install -e ".[dev,cliui]"
~~~

The optional esp-idf extra installs PyYAML for bounded dependencies.lock parsing. It is not required for core scanning. The research extra is for optional Python analysis scripts and does not enable R or Julia.

## Published package status

0.4.0 is the last published package and predates the adapted features described in this repository. PyPI publishing is paused. To install that historical release explicitly:

~~~powershell
python -m pip install vigil-fuse==0.4.0
~~~

Use the repository installation above for the current source. Do not interpret an existing package-index version or the release workflow as authorization to publish a new version.

## Interactive terminal

Run vigil-fuse from the project folder to open an interactive session without starting a scan. Type /help to list commands. /target [directory] displays or changes the current target; /profile [name] selects a profile; /scan, /plan, /findings, /baseline, and /doctor provide the main scan and review actions. The optional cliui extra enables command suggestions, editing, and in-memory command-name history. Paths and option values are not saved in that history.

After an interactive scan, FUSE can ask whether to create a PDF report. Rendering requires pdflatex; if it is missing or fails, the LaTeX source is retained and JSON, text, and SARIF outputs remain available.

## Optional setup command

vigil-fuse setup reports optional analyzers and can provision a bounded set of pinned tools after explicit consent. Use --dry-run to inspect the plan without downloading or changing the machine.

- --minimal checks the Python environment and does not install tools.
- --recommended checks Git, OPA, and Verible, and offers pinned Syft, OSV-Scanner, and Gitleaks releases for user-local installation.
- --full also reports manually managed tools such as Binwalk, Docker, Ollama, Ghidra, Java, and pdfLaTeX.
- --research reports Python extras and R, Julia, Rust, and Zig availability. It never installs language toolchains.

Setup does not download models, weights, GPU components, or toolchains. A missing optional tool leaves its analysis stage unavailable or partial; it does not prevent the core scanner from running. See [Windows setup](windows-setup.md) for the PowerShell helper and [dependency model](dependency-model.md) for pinned versions and hashes.

## Optional Clang adapter

The Clang LibTooling analyzer is a separate native executable. LLVM is not a Python package dependency. Build it using the [native instructions](../native/clang-analyzer/README.md), then follow the [semantic evidence guide](cpp-semantic-analysis.md). Its observations do not create security findings automatically. Host execution is not an OS sandbox; use an isolated environment for untrusted source.

## Package verification

See [local release validation](releasing.md) for wheel and source archive builds, metadata checks, fresh virtual environment installation, installed CLI smoke checks, and package-resource verification. This workflow stops before tagging or publishing.

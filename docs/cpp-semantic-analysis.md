# Compiler-semantic C/C++ evidence

The opt-in `native/clang-analyzer` stage uses real Clang LibTooling AST traversal.
Python owns findings, policy and coverage; Go owns scheduling; Java owns the
Ghidra bridge. C supplies controlled validation targets. Rust remains deferred.
This stage does not implement symbolic execution, taint tracking, complete data flow,
object-size inference, SDK validation or runtime reachability.

## Run

Build using the [native instructions](../native/clang-analyzer/README.md). Put the
trusted executable on PATH or pass its exact location:

```powershell
.\.venv\Scripts\python.exe -m vigil_fuse doctor
.\.venv\Scripts\python.exe -m vigil_fuse.clang_analyzer tests/fixtures/semantic_c tests/fixtures/semantic_c/compile_commands.json --executable C:/tools/fuse-clang-analyzer.exe
.\.venv\Scripts\python.exe -m pytest -q tests/test_clang_analyzer.py
```

`analyze(root, compilation_database, executable=..., present_sources=(...))` returns
`SemanticResult`: existing `AnalyzerStatus`, validated raw evidence, explicit coverage
records and normalized sensitive calls. No findings or severities are automatically
created. The separate module CLI prints that result and exits nonzero without evidence.
Ordinary scans and CLIUI behavior remain unchanged. LLVM is not a Python dependency.
Absence returns `unavailable`; invalid probes return `incompatible`. Doctor performs
a successful bounded JSON version probe before displaying version or database support.

On Windows, the LLVM build image produces a Linux executable, so run the adapter inside
that image. This PowerShell example mounts FUSE source, the selected project and the
executable read-only; it disables networking and limits the container. Replace the
target path with a project that has `compile_commands.json` at its root:

```powershell
$repoPath = (Resolve-Path .).Path
$targetPath = (Resolve-Path C:\work\firmware).Path
$binaryPath = (Resolve-Path native\clang-analyzer\build\fuse-clang-analyzer).Path
$dockerLimits = @('--rm', '--network', 'none', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--memory', '4g', '--cpus', '2', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--mount', "type=bind,source=$repoPath\src,target=/fuse-src,readonly", '--mount', "type=bind,source=$targetPath,target=/target,readonly", '--mount', "type=bind,source=$binaryPath,target=/usr/local/bin/fuse-clang-analyzer,readonly", '--env', 'PYTHONPATH=/fuse-src', '--env', 'PYTHONDONTWRITEBYTECODE=1', 'fuse-clang-build:llvm18')
docker run @dockerLimits python3 -m vigil_fuse doctor
docker run @dockerLimits python3 -m vigil_fuse.clang_analyzer /target /target/compile_commands.json
```

The same invocation was smoke-tested against the checked-in corpus and returned
`completed`, 30 selected API observations, and 12 `BUILD_INCLUDED` translation units.
Windows `doctor` stays `unavailable` because that Linux executable cannot run directly
on the Windows host.

## Compilation context and trust boundary

The bounded [JSON compilation database](https://clang.llvm.org/docs/JSONCompilationDatabase.html)
must contain explicit `arguments` arrays. `command` shell strings alone are rejected.
Each entry selects a C/C++ source under the root. Explicit sources can be analyzed by
creating a one-entry database with a known safe context; FUSE never infers unknown
toolchain settings or invokes a build to obtain them.

The producer discards the compiler executable, never executes it, and uses
[LibTooling](https://clang.llvm.org/docs/LibTooling.html) in process. Accepted compiler
arguments are joined `-DNAME=value`, `-UNAME`, `-std=...`, and joined `-Irelative/path`
inside the selected root. `-c` and the selected filename are consumed; `-o VALUE` is
discarded. Unknown arguments, plugins, response files, forced includes, target flags,
and split `-I path` are rejected. Real cross-compilation databases commonly need a
separately reviewed reduced context. Rejection is a failed stage, never a clean result.

Inputs and output are untrusted. Python rejects duplicate JSON keys, nonfinite values,
unknown/missing fields, wrong types, invalid paths, unselected TU observations and
contradictory completed states. Source/database digests are checked before and after
the run. This detects ordinary input changes, not adversarial change-and-restore races
or changes to transitive headers. Use an immutable snapshot for stronger provenance.

The host adapter is not an operating-system sandbox. Compiler includes can read files
outside the root through source directives or system headers. Analyze untrusted
projects in a no-network container with only a read-only input mount, restricted
permissions and memory/CPU limits. No target binary, project script, compiler plugin
or arbitrary build command is executed. The narrow API list is name based; it does
not establish SDK identity or prove that a same-named user function has SDK behavior.

## Contract and bounds

[clang-evidence.schema.json](../src/vigil_fuse/schemas/clang-evidence.schema.json)
defines the strict output shape. The Python validator additionally checks filesystem
containment, selected-build correspondence and consistency. Limits are:

| Resource | Bound |
| --- | --- |
| Selected compilation entries | 32 |
| Database and each selected source | 1 MiB |
| Compiler arguments per entry | 128, each at most 1024 bytes |
| Observations across selected TUs | 1024 |
| Arguments per observed call | 32 |
| Emitted warning/error diagnostic count | 64, saturated |
| Output, combined stdout/stderr in adapter | 1 MiB |
| Native wall time | 60 seconds watchdog |
| Adapter run / version probe | 65 / 5 seconds |
| Argument expression / name / enclosing function | 256 characters |

Diagnostics contain counts, not arbitrary compiler messages. Warnings, parse errors,
or dropped observations produce `partial`; oversized JSON is rejected. A diagnostic
count of 64 means at least 64, not an exact total. Included headers are compiler inputs,
not additional selected TUs; their total count/bytes are not separately limited.
Container memory limits are required for hostile workloads. The watchdog exit is a
failed native run; adapter deadline expiry reports `timeout`. Large source expressions
are clipped, mark the run partial, and must not be treated as complete expressions
in downstream policy. Empty expression text means Clang could not recover the source
spelling, for example at some macro boundaries.

Function declarations/definitions and calls are emitted only for main-source expansion
locations. Calls inside included headers are not inventoried. Macro spelling file/line
and expansion file/line/column are separate. An unresolved function pointer appears as
`<unresolved>`, with unknown target identity, and is not matched by name policy.
Completed means traversal completed within this scope, not that every callee resolved.

## Initial exact API names

Memory evidence: `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`, `scanf`, `fscanf`,
`sscanf`, `memcpy`, `memmove`. Scanf format expressions are preserved for later Python
policy; this stage does not label a format unsafe. Bounded copies are also observations.
Normalized records add argument count, destination expression and memcpy/memmove size
expression, plus per-argument literal/integer-constant flags.

Embedded/network evidence: `esp_tls_conn_new`, `esp_tls_conn_http_new`,
`esp_http_client_init`, `esp_mqtt_client_init`, `esp_https_ota`, `esp_ota_begin`,
`esp_ota_end`, `esp_secure_boot_verify_signature`, `mbedtls_ssl_conf_authmode`,
`mbedtls_ssl_set_hostname`, `mbedtls_ssl_get_verify_result`, `mbedtls_pk_parse_key`,
`esp_console_init`. These cover TLS, HTTP/MQTT, OTA/firmware checks, credential key
handling and console setup. Namespaced unrelated names and substring matches do not
match. Calls in both secure and unsafe specimens are expected evidence. Call order
does not prove validation dominates a write, or TLS verification is effective.

## Coverage and validation

`BUILD_INCLUDED` means a selected TU parsed, not that its functions execute.
Failed TU parsing is `UNKNOWN`. Explicit caller-supplied `present_sources` absent from
the database are `PRESENT`; the adapter does not silently crawl the repository or
equate absence from a selected database with exclusion from every possible build.

Text/static pattern findings, compiler-semantic observations, Ghidra binary evidence
and runtime/device measurements are separate evidence classes. This corpus contains
stand-in API declarations, not installed ESP-IDF/mbedTLS SDK builds or physical tests.
It covers paired memory/network/OTA examples, negative comments/names/wrappers/dead
branches, unresolved pointers, macro expansion, C++ namespace identity, all initial
security API names, alternate compile definitions, hostile flags, malformed code and
observation limits. Native tests skip explicitly when the optional executable is absent.

Run the benchmark in two fresh Linux processes:

```sh
PYTHONPATH=src python3 scripts/benchmark_clang_semantics.py --mode text --output text.json
PYTHONPATH=src python3 scripts/benchmark_clang_semantics.py --mode combined --executable /build/fuse-clang-analyzer --output combined.json
```

The benchmark records existing text findings, validated semantic call sites, false
positive/negative call sites, observations, build coverage, elapsed time and peak
individual process RSS. It does not call observed APIs vulnerabilities: new security
findings remain zero and vulnerability TP/FP metrics are unassessed. Existing text
rules lack most of these API policies, so the two counts are not interchangeable.
The controlled Ubuntu 24.04 / Python 3.12.3 / LLVM 18.1.3 run under Docker Desktop
WSL2 analyzed 12 C/C++ translation units. Text mode recorded 0 findings in 0.19 seconds
with 21,860 KiB peak individual process RSS. Combined mode recorded 79 AST observations
and 30 selected API call sites in 22.92 seconds with 75,780 KiB peak individual process
RSS. Those 30 API
sites matched the fixture call inventory (30/30; 0 unmatched and 0 missed sites).
This measures call recognition on a small synthetic corpus; it provides no vulnerability
precision, recall, general codebase accuracy or throughput claim. Full source hashes,
compiler hash, coverage and environment are in [text](experiments/clang-semantic-benchmark-text.json)
and [combined](experiments/clang-semantic-benchmark-combined.json) result files.

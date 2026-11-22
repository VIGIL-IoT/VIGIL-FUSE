# Optional local reasoning over deterministic FUSE evidence

FUSE establishes findings and evidence. One optional local Ollama model explains a
completed finding at a time. The default model is `qwen3.5:4b`. This layer does not
discover vulnerabilities, change severity, confidence, applicability, coverage or
policy, confirm unknowns, execute commands, apply patches or use tools. If the
model disappears, deterministic FUSE scans continue to work.

## Manual prerequisites

Install and start Ollama yourself. Model installation is also a separate, optional
manual action:

```powershell
ollama pull qwen3.5:4b
```

FUSE never runs that command. Package installation, setup, doctor and ordinary
scans never download weights, start Ollama or configure GPU software. Doctor only
lists installed models with `GET /api/tags`; it does not load a model. There are
no model weights, Ollama binaries, SDKs or new dependencies in the FUSE wheel.

## Usage

```powershell
vigil-fuse scan TARGET
vigil-fuse scan TARGET --reason
vigil-fuse reason .fuse-results/findings.json
vigil-fuse reason .fuse-results/findings.json --finding FUSE001
vigil-fuse reasoning-context .fuse-results/findings.json --finding FUSE001
vigil-fuse doctor
```

`--finding` accepts an exact instance ID, or a rule ID to select all its instances.
FUSE IDs normally include a rule, relative file and line. Copy the actual ID from
your report. Empty reports need no model request. `reasoning-context` requires no
Ollama and prints the exact packet objects used as model evidence, one per finding.
The chat request adds only stable system instructions, delimiters, the response
schema and configured runtime options.

Use `--config fuse.toml` on these commands to select one model and runtime settings:

```toml
[reasoning]
provider = "ollama"
model = "qwen3.5:4b"
endpoint = "http://127.0.0.1:11434"
context_tokens = 8192
temperature = 0.1
keep_alive = 0
connection_timeout = 2.0
generation_timeout = 120.0
```

These settings never enable reasoning implicitly. A scan must use `--reason`.
Only HTTP loopback origins (`127.0.0.1`, `localhost`, `::1`) are accepted. Localhost
is pinned to numeric loopback; proxies and redirects are not used. Cloud model
names and remote model metadata are rejected. There is no router or fallback.

## Reports and failure behavior

`scan --reason` completes deterministic analysis and writes the normal reports
first, then writes `reasoning.json` in the report directory. With `--output FILE`,
it writes `FILE` with its suffix replaced by `.reasoning.json`. For text/SARIF
single-file output, the hash identifies the canonical in-memory UTF-8 JSON and
`source_hash_basis` says `canonical-json-utf8`. Otherwise it identifies actual
canonical JSON report bytes, including the file's newline convention.

`reason findings.json` writes `findings.reasoning.json`. `reason --output PATH`
chooses another file. It refuses to overwrite the source report. Artifacts record
the report SHA-256, finding IDs and fingerprints, context hashes, schema versions,
provider, model, runtime options, latency, truncation, and validated output or a
failure. They do not store full prompts, raw invalid responses or hidden thinking.
No deterministic report fields are changed. Model output is nondeterministic.

An unavailable server, missing model, timeout, HTTP failure, empty/incomplete
message, invalid JSON, schema violation or unsupported identifier produces
`reasoning_status = failed`. The original scan remains valid and keeps its normal
exit status. Standalone `reason` returns 2 if any requested explanation fails.
For JSON/SARIF scan output, enrichment stays in its artifact so stdout remains
parseable. Text output presents `FUSE REASONING` as optional explanation.

Connection and generation deadlines are separate and bounded. Cancellation closes
the socket; after a failed generation FUSE attempts an empty unload request when
`keep_alive = 0`. The normal chat request also uses `keep_alive = 0` so Ollama can
unload immediately after completion. A positive value keeps the model resident
for that many seconds. Unloading after a crash/timeout is best effort and VRAM
usage is not guaranteed. FUSE does not stop other applications' Ollama sessions.

## Evidence and privacy boundary

Only canonical FUSE JSON versions 1.11 and 1.12 are accepted in V1. TXT, PDF, SARIF
and arbitrary context JSON are not inputs. No target source, firmware, compiler
commands, environment variables, or artifact files are reopened. The builder
allow-lists the selected finding, its report evidence, location, matching build
settings, matching hardware artifact metadata matching RTL metadata/observations and its VEX review, if present.
Unrelated inventory entries and findings are excluded. Source and inventories
remain untrusted data inside the system instruction boundary, even when they
contain forged delimiters or commands.

The current canonical finding schema has a single evidence string, without
per-observation truth states. V1 puts that string in `supported`; it does not
manufacture confirmed observations or parse prose into new authoritative facts.
It explicitly retains unknown applicability/validation and the absence of runtime,
population and accessibility evidence. `PRESENT`, `BUILD_INCLUDED`, `LINKED`,
`RUNTIME_EXECUTED`, `PHYSICALLY_POPULATED` and `EXTERNALLY_ACCESSIBLE` remain distinct.
Source presence, configuration and schematic routing do not establish later states.
Semantic observations remain unavailable. For schema 1.12, matching RTL file metadata
and observations at the finding line are bounded to 6 entries; presence, build
status, parse status and conditionality are preserved without claiming deployed logic.
Firmware evidence already normalized in a finding stays in its evidence string;
binary dumps and unrelated candidates are never attached.

Limits are deterministic: 8 source/evidence text lines, 700 characters per string,
8 evidence entries, 8 path segments, 6 build/hardware observations, 2 policy
entries and a total packet cap of `min(12000, context_tokens - 2300)` UTF-8 bytes.
Typical packets are a few thousand bytes. Byte size is conservative input
accounting, not a measured tokenizer count. The remaining context reserves space
for system instructions, schema and up to 1200 generated tokens. If an essential
packet cannot fit, reasoning fails rather than silently deleting its unknowns.
Omitted bounded fields set `context_truncated` and `truncated_categories`.

Existing report evidence is redacted by the scanner. The builder also filters
common secret assignments, private-key blocks, bearer tokens, long opaque values
and home/absolute paths, recording redacted categories. This is a conservative
filter, not a guarantee that arbitrary secrets in natural language are recognized.
Inspect `reasoning-context` before reasoning over sensitive input. Never include
unrelated secrets or credential files in canonical evidence.

## Validation and limits

The required `reasoning_output_v1` object contains `summary`, `reasoning` (a brief
user explanation), `missing_evidence` (item/importance), `recommended_checks`,
`remediation`, `limitations`, `evidence_ids` and `unknown_evidence_ids`. Unknown
acknowledgements must exactly match the supplied unknown IDs. Unknowns require
both missing evidence and limitations. The response is capped at 24000 bytes,
arrays at 8 items, summary at 600 characters, explanation at 1800, list strings
at 500, and evidence IDs at 16. Unknown/override fields, duplicate JSON keys,
non-finite numbers, invalid UTF-8 and control characters are rejected.

Grounding rejects unsupported lexical references such as relative file paths,
common source filenames, snake-case symbols, called symbols, `CONFIG_*`, GPIO,
component references, FUSE IDs and evidence IDs. It deliberately does not perform
full natural-language fact checking. A grounded, schema-valid sentence can still
be wrong; optional explanation remains lower trust than deterministic evidence
and requires human review. Unknown ID acknowledgement is a structural check,
not proof that every sentence preserves uncertainty. Suggested checks and
remediation are inert text and are never executed.

## Tests and manual evaluation

Normal tests use a mocked loopback HTTP server and require no Ollama or GPU:

```powershell
python -m pytest -q tests/test_reasoning.py
```

After manually installing and starting prerequisites, run either command:

```powershell
python scripts/test_local_reasoning.py --model qwen3.5:4b
python scripts/benchmark_reasoning_model.py --model qwen3.5:4b
```

Both share the same harness and controlled UART fixture. The smoke suite currently
has one case. Add `*.case.json` metadata in a directory and pass `--fixtures DIR`
to evaluate more cases. These scripts are never invoked by normal CI.
The fixture separates source/build/net routing support from unknown runtime
invocation, zero-ohm population, connector population and enclosure accessibility.
Metadata lists expected evidence IDs, unknown topics and forbidden claims;
expected prose is not prescribed.

The harness reports JSON validity, grounding, unknown-topic/ID acknowledgement,
expected evidence IDs, absence of fixture-specific forbidden phrases, latency,
context bytes, a conservative byte-based token upper bound, and response bytes.
Topic/phrase checks are coarse indicators for review, not semantic accuracy.
There is no combined accuracy percentage. Failed checks return 2. No model is
pulled, no service is started, and the configured unload policy applies.

The controlled canonical report and a valid response are in
[tests/fixtures/reasoning](../tests/fixtures/reasoning/). The response schema is
defined in [validation.py](../src/vigil_fuse/reasoning/validation.py).

## CLI consolidation boundary

Existing CLI integration files changed: `src/vigil_fuse/cli.py` and
`src/vigil_fuse/config.py`. The merge preserves the interactive result callback,
PDF prompt and Rego policy reporting/exit checks. Standalone `reason` and
`reasoning-context` are argparse commands; `/scan TARGET --reason` also works
through the existing interactive scan dispatcher. The main CLI only imports hooks, registers two
commands and `--reason`, dispatches the commands, adds doctor text, and calls
enrichment after reports are written. Reasoning-specific parsing, orchestration
and rendering live under `src/vigil_fuse/reasoning/`. Preserve that ordering and
the existing scan exit checks when integrating a parallel CLI branch.

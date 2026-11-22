# Polyglot foundation validation

Integration with main at `73060d7` (FUSE 0.5.1): the combined suite passed with 469 tests,
6 optional skips and 184 subtests. Ruff, formatting (160 files), strict mypy (78 source
files), documentation validation (121 Markdown files) and Go tests passed. Earlier
terminal failures were resolved by the main updates. Five local Git subprocess failures
were traced to an injected GIT_CONFIG_COUNT without its required value; clearing that
variable only for the test process restored valid Git invocation. Tests were not weakened.
The measurements below preserve the earlier implementation snapshot and its baseline.

Repository: `https://github.com/ShivuXD/FUSE`, separate checkout `FUSE-polyglot`.
Branch: `feat/polyglot-platform-foundation`. Starting commit:
`63fb424ab262d1dc99ea4c0d872b7c9fe9cfe533`.
The original VIGIL-IoT checkout and its cyber-physical branch were left intact.

## Implemented boundary

Python: versioned AnalysisPlan and EvidenceEnvelope schemas, strict standard-library
validation, explicit plan and result file handoff commands, deterministic identity probe,
and rejection tests. The scanner CLI, router and findings APIs were not changed.
Python uses no new runtime dependencies. The probe has no security interpretation.

Go: module `github.com/ShivuXD/FUSE/cluster/fuse-operator`, controller-runtime v0.25.3,
immutable FuseScan CRD, controller, bounded Job builder, namespace Role/RoleBinding,
ServiceAccount and deny ingress/egress NetworkPolicy. Isolation and operational failure
tests plus a fake-client policy rejection test are supplied. Separate Go CI is supplied.
The [upstream module](https://github.com/kubernetes-sigs/controller-runtime/blob/v0.25.3/go.mod)
requires Go 1.26.0, matching the supplied go.mod.

After explicit authorization, Go 1.27.4 and kind v0.33.0 were downloaded to an isolated
local tools folder and verified against upstream SHA-256 checksums. No global PATH
change was made. Go formatting, module resolution, four unit tests, vet and executable
build passed. Generated go.mod/go.sum lock the dependencies. The operator remains experimental.

## Observed commands

Commands used the checkout's `.venv/Scripts/python` unless noted.

| Command | Observed result |
| --- | --- |
| `python -m pip install -e ".[dev]"` | Installed successfully |
| Baseline `python -m pytest -q` | 386 passed, 8 failed, 1 skipped; 184 subtests passed |
| Core regression `python -m pytest -q` before opt-in test additions | 403 passed, same 8 failed, 1 skipped; 184 subtests passed |
| `python -m pytest tests/test_execution_contract.py -q` | 17 passed |
| `python -m ruff check src tests scripts` | Passed |
| `python -m mypy src/vigil_fuse/execution_contract.py src/vigil_fuse/execution_worker.py src/vigil_fuse/execution.py` | Passed |
| `python -m mypy` | 13 existing terminal.py errors in isolated environment |
| `python scripts/validate_docs.py` | Passed for 117 Markdown files |
| `vigil-fuse --help` | Passed |
| `vigil-fuse doctor` | Exited successfully |
| `vigil-fuse scan . --plan` | Exited successfully without Go/Kubernetes |
| Existing synthetic scan benchmark | Completed; see benchmark record |
| `git diff --check` | Passed |
| `python -m build --wheel` | Built successfully; execution modules and both schemas verified in wheel |
| YAML parse and live CRD installation | Passed |
| `go mod tidy`, `gofmt -w cmd internal` | Passed; lockfiles generated |
| `go test -v ./...` | Four tests passed |
| `go vet ./...`, `go build ./cmd/operator` | Passed; executable built |
| `python -m pytest tests/test_execution_docker.py tests/test_execution_contract.py -q` with explicit image | 21 passed |
| `python -m pytest tests/test_execution_kubernetes.py -q` with explicit cluster/binary/digest | Passed, including actual egress denial |
| Namespace-scoped ServiceAccount authorization checks | Job creation allowed locally; Secrets and other namespace denied |

The same eight tests failed before and after implementation: freeze repeatability,
tracked/untracked documentation discovery, repository cohort RSS, separate provenance
manifest, dirty-scanner refusal and three terminal banner tests. They were not weakened
or altered. Isolated mypy reports eight missing prompt_toolkit imports and five annotation
errors in terminal.py. The earlier system-wide environment reported six terminal errors.

## Integration limits

An authorized disposable kind v0.33.0 / Kubernetes v1.37.0 cluster was created, tested and
deleted. The image was built and run under Docker 28.5.1. Live tests verified Python plan
handoff through the controller to a restricted Job, envelope validation, immutable spec
rejection, Job owner cleanup and denied pod egress while an unselected baseline connected.
RBAC checks used ServiceAccount impersonation; the live controller ran locally with the
explicit test kubeconfig. In-cluster deployment packaging and authentication are unverified.

Initial image-import attempts observed ImagePullBackOff. kind loaded the image by tag
without its exact repository/digest alias. Inspecting containerd verified the original
content digest and adding that matching alias resolved it without changing pinning.
The first network diagnostic hit a server startup race; an explicit TCP readiness probe
fixed the fixture. The full integration test then passed. Live cluster OOM, killed workers,
deadline and inaccessible-cluster/CRD tests remain pending. Docker tests observed OOM exit
137, invalid input exit 2, and rejection of malformed output despite a successful process exit.
Captured envelopes reject invalid JSON, wrong schema, worker/plan mismatches and false
security coverage in Python tests. Partial execution remains an operational limitation.

The first deterministic cluster milestone passed. A real Syft worker remains a subsequent
milestone and is not implemented in this foundation. Evidence handoff currently uses
captured Job stdout and explicit Python validation. No automatic Kubernetes scan backend
is advertised.

Rust: `NO_RUST_NEEDED_YET`; the measured small synthetic workload does not isolate a hot
path. No C/C++ adapters or fixtures, Java exporter changes, or Julia/R experiments were
needed. No empty language showcase projects were created.

## Git and next commands

Main directly modified: NO. Automatic merge: NO. Force push: NO. Remote push: NO.
Local commits only. For the final commit IDs and clean-tree status use `git log -3 --oneline`
and `git status` in this checkout.

With Go 1.26+ installed, run from `cluster/fuse-operator`:

```powershell
go mod tidy
gofmt -w cmd internal
go test ./...
go vet ./...
```

Then review module/format changes and follow the [operator guide](../../cluster/fuse-operator/README.md)
on an explicitly authorized test cluster. Once the branch is reviewed, the optional
publication command is `git push -u origin feat/polyglot-platform-foundation`. It was not run.

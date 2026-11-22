# FUSE operator foundation

Experimental controller for immutable `FuseScan` plans. It schedules only the deterministic
`probe` worker. Python remains responsible for validating the plan, envelope and evidence.
Job `Completed` means process success, never security success.

Requires Go 1.26+, Kubernetes and a CNI that enforces NetworkPolicy. These are optional
for the Python package. Go tests, vet and build passed with Go 1.27.4. The probe roundtrip,
immutable plans, Job cleanup and actual egress denial passed on kind v0.33.0 / Kubernetes
v1.37.0. See the validation record for the remaining limits.

Run `go mod tidy`, `go test ./...`, `go vet ./...` and `gofmt -w cmd internal` here.
Dependencies are locked in go.mod and go.sum. CI checks formatting and module drift.

Use a dedicated namespace with restricted Pod Security admission and no untrusted resource
writers. Apply `config/crd.yaml` as a cluster administrator, then `config/rbac.yaml` within
that namespace. Build the probe image using `cluster/workers/native/Dockerfile`, publish
it explicitly, and obtain its digest. The controller rejects image tags without a digest.

Run with `FUSE_NAMESPACE` and `FUSE_WORKER_IMAGE` set, using the namespace-scoped
`fuse-operator` ServiceAccount (or equivalent local credentials). The image should be
`registry/image@sha256:<digest>`. The initial operator is run as a binary; deployment
packaging and automatic log ingestion remain follow-up work.

Create a resource with `apiVersion: fuse.vigil.dev/v1alpha1`, `kind: FuseScan` and a
Python-generated plan under `spec.plan`, with `execution_mode: kubernetes`. Observe
status and Jobs using `fuse.vigil.dev/scan` labels. Delete the FuseScan to garbage-collect
its owned Job, plan ConfigMap and NetworkPolicy. Completed Jobs remain for evidence retrieval.

The Job name and expected worker identifier are `fuse-<FuseScan UID>`. Retrieve stdout
from the owned Job's worker container, enforce the Python message byte limit, then call
`decode_message` and `validate_result(result, original_plan, expected_worker_id)`.
Evidence handoff currently requires this explicit caller step; no scanner CLI backend
or automatic log importer is advertised. ConfigMaps and stdout contain identity metadata
only. There is no target volume, secret volume or target analyzer in the probe.

Pending includes unavailable worker images and scheduling problems. Deadline/OOM/process
failure is Failed. Policy rejection is Blocked. A malformed or mismatched envelope is
rejected in Python even when Kubernetes reports Completed. None grants NOT_AFFECTED,
SAFE or NO_VULNERABILITY. Live cluster timeout, OOM and killed-worker checks remain pending;
container OOM and malformed output were tested with Docker. Namespace permissions and CNI policy enforcement
must be supplied by the cluster operator.

Opt-in tests from repository root:

```powershell
$env:FUSE_EXECUTION_WORKER_IMAGE = 'fuse-native-worker:dev'
python -m pytest tests/test_execution_docker.py -q
$env:FUSE_TEST_KUBECONFIG = '<disposable cluster kubeconfig>'
$env:FUSE_TEST_OPERATOR_BINARY = '<compiled operator executable>'
$env:FUSE_TEST_KUBERNETES_IMAGE = '<worker image pinned by digest>'
python -m pytest tests/test_execution_kubernetes.py -q
```

The Kubernetes test installs the CRD, creates a unique restricted namespace, runs the
operator locally with the supplied credentials, and cleans the namespace afterward.
Use only a disposable cluster. For locally loaded kind images, verify the target digest
with `ctr -n k8s.io images ls` inside the node. If the exact digest reference is missing,
tag that existing image with its matching `repository@sha256:<digest>` reference using
`ctr -n k8s.io images tag`. The alias must match the actual target digest. No registry
publication is needed. Initial tests observed ImagePullBackOff until this cache alias
was supplied; image authorization and pinning were preserved.

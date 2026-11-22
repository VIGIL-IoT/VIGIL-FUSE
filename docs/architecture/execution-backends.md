# Execution backends

Ordinary scanning continues to use the existing Python execution path. Its local and
optional Docker analyzer adapters are unchanged. No `scan --execution` flag is added.
The new probe contract is separate and uses `local`, `docker` or `kubernetes` metadata.
Declaring a backend does not launch it.

Create a probe plan with the explicit handoff command:

```powershell
python -m vigil_fuse.execution plan example firmware ('a' * 64) --backend local > plan.json
python -m vigil_fuse.execution_worker worker plan.json > result.json
python -m vigil_fuse.execution validate plan.json result.json worker
```

Use UTF-8 JSON files (PowerShell 7 output redirection uses UTF-8). The digest in this
example is synthetic. A production caller must derive and independently bind the digest
to an authorized target. The probe never reads target bytes and cannot verify that binding.

Plans contain schema version, plan and target identities, analyzer requests, backend,
explicit passive authorization, CPU/memory/time limits, deny networking, evidence
requirements and producer. The current version accepts only the probe analyzer. CPU is
integer millicores, memory is MiB and timeout is seconds. Defaults are 1000/512/300;
maximum accepted values are 4000/4096/3600. Local worker invocation does not enforce OS
CPU/memory/time isolation; Kubernetes enforces budgets through Job and Pod settings.

Envelopes contain version, plan identity, worker identity, operational status, artifacts,
findings, evidence, coverage and limitations. Probe artifacts/findings/coverage must be
empty. Evidence must bind to the expected target identity. Invalid JSON, duplicate keys,
nonfinite numbers, messages larger than 1 MiB, unsupported versions, unknown fields and
identity mismatches are rejected. File readers bound reads before decoding.

External envelopes are untrusted even when a Job exits successfully. Validate against the
original Python plan and independently obtained worker ID before using evidence. No
result changes existing security reports automatically. Partial, failed, blocked and
timeout envelopes require a limitation; errors never assert safety or non-applicability.

Docker can run the probe image with `--network none --memory 512m --cpus 1` and stdin.
Do not mount target directories for the identity probe. Kubernetes details are in the
[operator guide](../kubernetes-operator.md). A missing kubectl, absent cluster or missing
CRD prevents that explicit external handoff; ordinary Python scanning still works.

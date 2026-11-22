# Kubernetes operator

The experimental Go controller lives in [cluster/fuse-operator](../cluster/fuse-operator/README.md).
It accepts immutable namespaced FuseScan resources and creates owned ConfigMaps,
NetworkPolicies and disposable Jobs. The controller image setting is supplied by the
operator and must use a digest. Scan authors cannot choose worker commands or images.

The only enabled worker is the deterministic Python identity probe. A Job's completion
is an execution observation. Python must validate captured stdout against the original
plan and scheduled worker identity before accepting evidence. Network denial requires a
supporting CNI; creation of a NetworkPolicy alone is not proof of enforcement.

Worker security: UID 65532, non-root, no privilege escalation, read-only root filesystem,
all capabilities dropped, RuntimeDefault seccomp, no service-account token, no host
network, no host volumes, no secrets and bounded CPU/memory/time. Use a dedicated
namespace and restricted Pod Security admission. Namespace administrators remain trusted.

The supplied Role has namespaced access to FuseScans/status, Jobs, ConfigMaps and
NetworkPolicies. It has no Secret access. Apply CRDs separately with administrator
authorization. Deleting a FuseScan cancels execution through Kubernetes owner cleanup.
Pending, Running, Completed, Failed and Blocked are operational phases; Partial is
reserved for future evidence-aware workers. A worker log is the current evidence handoff,
so retrieve it before deleting the resource.

Go compilation, vet and four unit tests passed. A disposable kind v0.33.0 cluster with
Kubernetes v1.37.0 passed the probe roundtrip, immutable-plan rejection, Job cleanup and
actual egress-denial checks. Docker checks covered restricted execution, invalid input,
malformed output and OOM. Live cluster OOM, deadlines and killed-worker tests remain
pending. The operator remains experimental. See the operator README for opt-in tests.

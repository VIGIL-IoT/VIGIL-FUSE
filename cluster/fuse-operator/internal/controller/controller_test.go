package controller

import (
	"context"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"strings"
	"testing"
)

func TestReconcileSchedulesOnceWithDenyPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{batch.AddToScheme, core.AddToScheme, networking.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	scheme.AddKnownTypeWithName(GVK, scanObject())
	scan := scanObject()
	scan.SetName("test")
	scan.SetNamespace("test")
	scan.SetUID(types.UID("worker"))
	scan.Object["spec"] = map[string]interface{}{"plan": map[string]interface{}{
		"schema_version": "0.1", "execution_mode": "kubernetes", "network_policy": "deny",
		"plan_id": "test", "created_by": "vigil-fuse",
		"target":                map[string]interface{}{"target_id": "firmware", "sha256": strings.Repeat("a", 64)},
		"evidence_requirements": []interface{}{"target-identity"},
		"authorization":         map[string]interface{}{"passive_execution": true},
		"requested_analyzers":   []interface{}{"probe"},
		"limits":                map[string]interface{}{"cpu_millis": int64(1000), "memory_mb": int64(512), "timeout_seconds": int64(30)},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(scan).WithObjects(scan).Build()
	reconciler := &Reconciler{Client: c, Scheme: scheme, Image: "example@sha256:" + strings.Repeat("a", 64)}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"}}
	for i := 0; i < 2; i++ {
		if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	jobs := &batch.JobList{}
	if err := c.List(context.Background(), jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 1 {
		t.Fatalf("scheduled %d jobs", len(jobs.Items))
	}
	policy := &networking.NetworkPolicy{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "fuse-worker", Namespace: "test"}, policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.Spec.PolicyTypes) != 2 || len(policy.Spec.Ingress) != 0 || len(policy.Spec.Egress) != 0 {
		t.Fatal("worker networking must be denied")
	}
	config := &core.ConfigMap{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "fuse-worker", Namespace: "test"}, config); err != nil {
		t.Fatal(err)
	}
	if config.Immutable == nil || !*config.Immutable || config.Data["plan.json"] == "" {
		t.Fatal("missing immutable handoff")
	}
	job := &jobs.Items[0]
	job.Status.Conditions = []batch.JobCondition{{Type: batch.JobComplete, Status: core.ConditionTrue}}
	if err := c.Status().Update(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := c.List(context.Background(), jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 0 {
		t.Fatal("completed execution must not restart after its job is removed")
	}
}

func TestReconcileBlocksMissingPlan(t *testing.T) {
	scheme := runtime.NewScheme()
	scan := scanObject()
	scan.SetName("test")
	scan.SetNamespace("test")
	scheme.AddKnownTypeWithName(GVK, scanObject())
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(scan).WithObjects(scan).Build()
	reconciler := &Reconciler{Client: c, Scheme: scheme, Image: "example@sha256:digest"}
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	updated := scanObject()
	if err := c.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "test"}, updated); err != nil {
		t.Fatal(err)
	}
	status := updated.Object["status"].(map[string]interface{})
	if status["phase"] != "Blocked" {
		t.Fatal(status)
	}
}

func TestWorkerIsolation(t *testing.T) {
	job := BuildJob("probe", "test", "example@sha256:digest", 1000, 512, 30)
	pod := job.Spec.Template.Spec
	container := pod.Containers[0]
	if *pod.AutomountServiceAccountToken || !*pod.SecurityContext.RunAsNonRoot ||
		*container.SecurityContext.AllowPrivilegeEscalation || !*container.SecurityContext.ReadOnlyRootFilesystem ||
		container.SecurityContext.Capabilities.Drop[0] != "ALL" || *job.Spec.ActiveDeadlineSeconds != 30 ||
		len(container.Resources.Limits) != 2 || pod.HostNetwork || len(pod.Volumes) != 1 {
		t.Fatal("worker isolation regressed")
	}
}

func TestJobFailuresRemainOperational(t *testing.T) {
	for _, reason := range []string{"DeadlineExceeded", "OOMKilled", "PodFailurePolicy", "BackoffLimitExceeded"} {
		job := &batch.Job{Status: batch.JobStatus{Conditions: []batch.JobCondition{{
			Type: batch.JobFailed, Status: core.ConditionTrue, Reason: reason,
		}}}}
		phase, detail := JobPhase(job)
		if phase != "Failed" || detail != reason {
			t.Fatalf("%s: %s %s", reason, phase, detail)
		}
	}
	phase, _ := JobPhase(&batch.Job{})
	if phase != "Pending" {
		t.Fatal("missing image must not imply successful analysis")
	}
}

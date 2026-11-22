// Package controller schedules disposable workers. Job success is an operational state only.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var GVK = schema.GroupVersionKind{Group: "fuse.vigil.dev", Version: "v1alpha1", Kind: "FuseScan"}
var pinnedImage = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$`)

type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Image  string
}

func scanObject() *unstructured.Unstructured {
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(GVK)
	return object
}

func (r *Reconciler) Setup(manager ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(manager).For(scanObject()).Owns(&batch.Job{}).Complete(r)
}

func terminalPhase(phase string) bool {
	return phase == "Completed" || phase == "Failed" || phase == "Blocked"
}

func (r *Reconciler) phase(ctx context.Context, scan *unstructured.Unstructured, phase, reason string) (ctrl.Result, error) {
	if old, _, _ := unstructured.NestedString(scan.Object, "status", "phase"); old != phase {
		scan.Object["status"] = map[string]interface{}{"phase": phase, "reason": reason,
			"observedGeneration": scan.GetGeneration()}
		if err := r.Status().Update(ctx, scan); err != nil {
			return ctrl.Result{}, err
		}
	}
	if terminalPhase(phase) {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

func (r *Reconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	scan := scanObject()
	if err := r.Get(ctx, request.NamespacedName, scan); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !scan.GetDeletionTimestamp().IsZero() {
		return ctrl.Result{}, nil
	}
	if phase, _, _ := unstructured.NestedString(scan.Object, "status", "phase"); terminalPhase(phase) {
		return ctrl.Result{}, nil
	}
	plan, found, err := unstructured.NestedMap(scan.Object, "spec", "plan")
	if err != nil || !found {
		return r.phase(ctx, scan, "Blocked", "missing plan")
	}
	encoded, err := json.Marshal(plan)
	if err != nil || len(encoded) > 65536 {
		return r.phase(ctx, scan, "Blocked", "plan too large")
	}
	// Python validates semantics; the scheduler independently enforces its execution policy.
	limits, _ := plan["limits"].(map[string]interface{})
	number := func(key string, maximum int64) int64 {
		value, ok := limits[key].(int64)
		if !ok || value < 1 || value > maximum {
			return 0
		}
		return value
	}
	cpu, memory, timeout := number("cpu_millis", 4000), number("memory_mb", 4096), number("timeout_seconds", 3600)
	auth, _ := plan["authorization"].(map[string]interface{})
	analyzers, _ := plan["requested_analyzers"].([]interface{})
	if plan["schema_version"] != "0.1" || plan["execution_mode"] != "kubernetes" ||
		plan["network_policy"] != "deny" || auth["passive_execution"] != true ||
		len(analyzers) != 1 || analyzers[0] != "probe" || cpu == 0 || memory == 0 || timeout == 0 ||
		!pinnedImage.MatchString(r.Image) {
		return r.phase(ctx, scan, "Blocked", "execution policy rejected")
	}
	name := "fuse-" + string(scan.GetUID())
	key := types.NamespacedName{Namespace: scan.GetNamespace(), Name: name}
	job := &batch.Job{}
	if err := r.Get(ctx, key, job); err == nil {
		if !metav1.IsControlledBy(job, scan) {
			return r.phase(ctx, scan, "Blocked", "job identity collision")
		}
		phase, reason := JobPhase(job)
		return r.phase(ctx, scan, phase, reason)
	} else if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	labels := map[string]string{"fuse.vigil.dev/scan": name}
	policy := &networking.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: key.Namespace},
		Spec: networking.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: labels},
			PolicyTypes: []networking.PolicyType{networking.PolicyTypeIngress, networking.PolicyTypeEgress}}}
	config := &core.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: key.Namespace},
		Data: map[string]string{"plan.json": string(encoded)}, Immutable: ptr(true)}
	for _, object := range []client.Object{policy, config} {
		if err := ctrl.SetControllerReference(scan, object, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, object); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return ctrl.Result{}, err
			}
			existing := object.DeepCopyObject().(client.Object)
			if err := r.Get(ctx, key, existing); err != nil {
				return ctrl.Result{}, err
			}
			if !metav1.IsControlledBy(existing, scan) {
				return r.phase(ctx, scan, "Blocked", "resource identity collision")
			}
		}
	}
	job = BuildJob(name, key.Namespace, r.Image, cpu, memory, timeout)
	if err := ctrl.SetControllerReference(scan, job, r.Scheme); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return ctrl.Result{}, err
	}
	return r.phase(ctx, scan, "Pending", "worker scheduled")
}

func ptr[T any](value T) *T { return &value }

func BuildJob(name, namespace, image string, cpu, memory, timeout int64) *batch.Job {
	return &batch.Job{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Spec: batch.JobSpec{
		BackoffLimit: ptr(int32(0)), ActiveDeadlineSeconds: ptr(timeout),
		Template: core.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"fuse.vigil.dev/scan": name}},
			Spec: core.PodSpec{RestartPolicy: core.RestartPolicyNever, AutomountServiceAccountToken: ptr(false),
				SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr(true), RunAsUser: ptr(int64(65532)),
					SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
				Containers: []core.Container{{Name: "worker", Image: image,
					Command: []string{"python", "-m", "vigil_fuse.execution_worker", name, "/plan/plan.json"},
					SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr(false), ReadOnlyRootFilesystem: ptr(true),
						Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
					Resources: core.ResourceRequirements{Requests: core.ResourceList{
						core.ResourceCPU: resource.MustParse(fmt.Sprintf("%dm", cpu)), core.ResourceMemory: resource.MustParse(fmt.Sprintf("%dMi", memory))},
						Limits: core.ResourceList{core.ResourceCPU: resource.MustParse(fmt.Sprintf("%dm", cpu)), core.ResourceMemory: resource.MustParse(fmt.Sprintf("%dMi", memory))}},
					VolumeMounts: []core.VolumeMount{{Name: "plan", MountPath: "/plan", ReadOnly: true}},
					Env:          []core.EnvVar{{Name: "PYTHONDONTWRITEBYTECODE", Value: "1"}},
				}}, Volumes: []core.Volume{{Name: "plan", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{
					LocalObjectReference: core.LocalObjectReference{Name: name}}}}},
			}},
	}}
}

func JobPhase(job *batch.Job) (string, string) {
	for _, condition := range job.Status.Conditions {
		if condition.Status != core.ConditionTrue {
			continue
		}
		if condition.Type == batch.JobComplete {
			return "Completed", "worker exited successfully; evidence requires Python validation"
		}
		if condition.Type == batch.JobFailed {
			return "Failed", condition.Reason
		}
	}
	if job.Status.Active > 0 {
		return "Running", "worker active"
	}
	return "Pending", "worker pending (image or scheduling may be unavailable)"
}

package main

import (
	"os"

	"github.com/ShivuXD/FUSE/cluster/fuse-operator/internal/controller"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

func main() {
	namespace, image := os.Getenv("FUSE_NAMESPACE"), os.Getenv("FUSE_WORKER_IMAGE")
	if namespace == "" || image == "" {
		panic("FUSE_NAMESPACE and FUSE_WORKER_IMAGE required")
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{batch.AddToScheme, core.AddToScheme, networking.AddToScheme} {
		if err := add(scheme); err != nil {
			panic(err)
		}
	}
	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme, Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{namespace: {}}},
	})
	if err != nil {
		panic(err)
	}
	reconciler := &controller.Reconciler{Client: manager.GetClient(), Scheme: scheme, Image: image}
	if err := reconciler.Setup(manager); err != nil {
		panic(err)
	}
	if err := manager.Start(ctrl.SetupSignalHandler()); err != nil {
		panic(err)
	}
}

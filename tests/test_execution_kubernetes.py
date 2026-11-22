"""Opt-in integration against an explicitly selected disposable cluster."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

import pytest

from vigil_fuse.execution_contract import create_plan, decode_message, validate_result

CONFIG = os.environ.get("FUSE_TEST_KUBECONFIG")
BINARY = os.environ.get("FUSE_TEST_OPERATOR_BINARY")
IMAGE = os.environ.get("FUSE_TEST_KUBERNETES_IMAGE")
pytestmark = pytest.mark.skipif(
    not all((CONFIG, BINARY, IMAGE)),
    reason="explicit disposable cluster, operator and image required",
)


def kube(*arguments, value=None, check=True):
    return subprocess.run(
        ["kubectl", "--kubeconfig", CONFIG, *arguments],
        input=json.dumps(value) if value is not None else None,
        capture_output=True,
        text=True,
        timeout=45,
        check=check,
    )


def check_network_denial(namespace, worker_id):
    def pod(name, command, labels=None):
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": name, "namespace": namespace, "labels": labels or {}},
            "spec": {
                "restartPolicy": "Never",
                "automountServiceAccountToken": False,
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 65532,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [
                    {
                        "name": "check",
                        "image": IMAGE,
                        "command": command,
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}},
                    }
                ],
            },
        }

    server_pod = pod("network-server", ["python", "-m", "http.server", "8080", "--bind", "0.0.0.0"])
    server_pod["spec"]["containers"][0]["readinessProbe"] = {
        "tcpSocket": {"port": 8080},
        "periodSeconds": 1,
    }
    kube("create", "-f", "-", value=server_pod)
    kube("wait", "--for=condition=Ready", "pod/network-server", "-n", namespace, "--timeout=30s")
    server = json.loads(kube("get", "pod/network-server", "-n", namespace, "-o", "json").stdout)
    address = repr(server["status"]["podIP"])
    connection = f"s=socket.create_connection(({address},8080),3); s.close()"
    baseline = "import socket,time\ntime.sleep(1)\n" + connection
    denied = (
        "import socket,sys\ntry:\n " + connection + "\nexcept OSError:\n sys.exit(0)\nsys.exit(3)"
    )
    for name, program, labels in (
        ("network-baseline", baseline, {}),
        ("network-denied", denied, {"fuse.vigil.dev/scan": worker_id}),
    ):
        kube("create", "-f", "-", value=pod(name, ["python", "-c", program], labels))
        deadline = time.monotonic() + 30
        while True:
            status = json.loads(kube("get", "pod/" + name, "-n", namespace, "-o", "json").stdout)[
                "status"
            ]
            if status.get("phase") in ("Succeeded", "Failed"):
                if status["phase"] != "Succeeded":
                    details = kube(
                        "logs", "pod/" + name, "-n", namespace, "--limit-bytes=4096"
                    ).stdout
                    pytest.fail(f"{name}: network policy check failed: {details}")
                break
            assert time.monotonic() < deadline, f"{name}: network check timed out"
            time.sleep(1)


def test_cluster_probe_roundtrip_and_immutable_plan():
    namespace = "fuse-test-" + uuid.uuid4().hex[:12]
    root = Path(__file__).parents[1]
    plan = create_plan("cluster-probe", "firmware", "a" * 64, "kubernetes")
    process = None
    kube("apply", "-f", str(root / "cluster/fuse-operator/config/crd.yaml"))
    kube("wait", "--for=condition=Established", "crd/fusescans.fuse.vigil.dev", "--timeout=30s")
    kube(
        "create",
        "-f",
        "-",
        value={
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace,
                "labels": {"pod-security.kubernetes.io/enforce": "restricted"},
            },
        },
    )
    with tempfile.TemporaryFile() as output:
        try:
            kube(
                "apply", "-n", namespace, "-f", str(root / "cluster/fuse-operator/config/rbac.yaml")
            )
            environment = dict(
                os.environ, KUBECONFIG=CONFIG, FUSE_NAMESPACE=namespace, FUSE_WORKER_IMAGE=IMAGE
            )
            process = subprocess.Popen([BINARY], env=environment, stdout=output, stderr=output)
            document = {
                "apiVersion": "fuse.vigil.dev/v1alpha1",
                "kind": "FuseScan",
                "metadata": {"name": "probe", "namespace": namespace},
                "spec": {"plan": plan},
            }
            kube("create", "-f", "-", value=document)
            deadline = time.monotonic() + 180
            while True:
                assert process.poll() is None, "operator exited before completing probe"
                scan = json.loads(
                    kube("get", "fusescan", "probe", "-n", namespace, "-o", "json").stdout
                )
                phase = scan.get("status", {}).get("phase")
                assert phase not in ("Failed", "Blocked"), scan.get("status")
                if phase == "Completed":
                    break
                assert time.monotonic() < deadline, f"probe did not complete: {scan.get('status')}"
                time.sleep(1)
            worker_id = "fuse-" + scan["metadata"]["uid"]
            result = kube(
                "logs", "job/" + worker_id, "-n", namespace, "-c", "worker", "--limit-bytes=1048577"
            ).stdout.encode()
            assert validate_result(decode_message(result), plan, worker_id)["status"] == "completed"
            job = json.loads(kube("get", "job", worker_id, "-n", namespace, "-o", "json").stdout)
            pod = job["spec"]["template"]["spec"]
            assert pod["automountServiceAccountToken"] is False
            assert pod["securityContext"]["runAsNonRoot"] is True
            assert pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"] is True
            assert pod["containers"][0]["resources"]["limits"]["memory"] == "512Mi"
            policy = json.loads(
                kube("get", "networkpolicy", worker_id, "-n", namespace, "-o", "json").stdout
            )
            assert set(policy["spec"]["policyTypes"]) == {"Ingress", "Egress"}
            assert not policy["spec"].get("ingress") and not policy["spec"].get("egress")
            check_network_denial(namespace, worker_id)
            scan["spec"]["plan"]["target"]["target_id"] = "changed"
            assert kube("replace", "-f", "-", value=scan, check=False).returncode != 0
            kube("delete", "fusescan", "probe", "-n", namespace)
            kube("wait", "--for=delete", "job/" + worker_id, "-n", namespace, "--timeout=30s")
        finally:
            if process is not None:
                process.terminate()
                process.wait(timeout=15)
            kube("delete", "namespace", namespace, "--wait=false", check=False)

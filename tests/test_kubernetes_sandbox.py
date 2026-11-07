"""Contract tests for the Kubernetes sandbox provider."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from clearwing.sandbox.backend import (
    SandboxBackend,
    SandboxEnvironmentSpec,
    SandboxInstance,
    SandboxRunConfig,
)
from clearwing.sandbox.kubernetes import KubernetesSandbox, KubernetesSandboxBackend
from clearwing.sourcehunt.runner import SourceHuntRunner


def test_kubernetes_backend_implements_contract():
    backend = KubernetesSandboxBackend(image="registry.test/sandbox:1", namespace="jobs")
    assert isinstance(backend, SandboxBackend)
    environment = backend.ensure_environment(
        SandboxEnvironmentSpec(cache_key="a" * 64, profile="c-cpp")
    )
    sandbox = backend.create(environment.reference, SandboxRunConfig())
    assert isinstance(sandbox, SandboxInstance)
    assert environment.reference == "registry.test/sandbox:1"
    assert sandbox.namespace == "jobs"


def test_backend_selection(monkeypatch):
    from clearwing.sandbox.backend import sandbox_backend_from_env

    monkeypatch.delenv("CLEARWING_SANDBOX_ENDPOINT", raising=False)
    monkeypatch.setenv("CLEARWING_SANDBOX_BACKEND", "kubernetes")
    monkeypatch.setenv("CLEARWING_SANDBOX_IMAGE", "registry.test/sandbox:1")
    assert isinstance(sandbox_backend_from_env(), KubernetesSandboxBackend)


def test_host_mounts_are_rejected():
    backend = KubernetesSandboxBackend(image="sandbox:1")
    config = SandboxRunConfig(mounts=[("/host", "/workspace", "ro")])
    with pytest.raises(ValueError, match="host-path"):
        backend.create("sandbox:1", config)


def test_pod_lifecycle(monkeypatch):
    client = pytest.importorskip("kubernetes.client")
    api = MagicMock()
    api.read_namespaced_pod_status.return_value = SimpleNamespace(
        status=SimpleNamespace(phase="Running")
    )
    sandbox = KubernetesSandbox(
        "sandbox:1", SandboxRunConfig(), namespace="jobs", api_factory=lambda: api
    )
    monkeypatch.setattr(client, "V1Pod", MagicMock(side_effect=lambda **kw: kw))

    identity = sandbox.start()
    assert identity.startswith("clearwing-sandbox-")
    assert sandbox.is_running
    api.create_namespaced_pod.assert_called_once()

    sandbox.stop()
    api.delete_namespaced_pod.assert_called_once()
    assert sandbox.container_id is None


def _running_api():
    api = MagicMock()
    api.read_namespaced_pod_status.return_value = SimpleNamespace(
        status=SimpleNamespace(phase="Running")
    )
    return api


def test_pod_network_is_denied_before_the_pod_is_created(monkeypatch):
    client = pytest.importorskip("kubernetes.client")
    api = _running_api()
    networking = MagicMock()
    monkeypatch.setattr(client, "NetworkingV1Api", MagicMock(return_value=networking))
    order = MagicMock()
    order.attach_mock(networking.create_namespaced_network_policy, "policy")
    order.attach_mock(api.create_namespaced_pod, "pod")
    sandbox = KubernetesSandbox(
        "sandbox:1", SandboxRunConfig(), namespace="jobs", api_factory=lambda: api
    )

    sandbox.start()

    assert [name for name, _, _ in order.mock_calls] == ["policy", "pod"]
    namespace, policy = networking.create_namespaced_network_policy.call_args.args
    pod = api.create_namespaced_pod.call_args.args[1]
    assert namespace == "jobs"
    assert policy.spec.policy_types == ["Ingress", "Egress"]
    assert policy.spec.egress is None
    assert policy.spec.ingress is None
    assert policy.spec.pod_selector.match_labels.items() <= pod.metadata.labels.items()

    sandbox.stop()
    networking.delete_namespaced_network_policy.assert_not_called()


def test_existing_network_policy_is_replaced(monkeypatch):
    client = pytest.importorskip("kubernetes.client")
    api = _running_api()
    networking = MagicMock()
    networking.create_namespaced_network_policy.side_effect = client.ApiException(status=409)
    monkeypatch.setattr(client, "NetworkingV1Api", MagicMock(return_value=networking))
    sandbox = KubernetesSandbox(
        "sandbox:1", SandboxRunConfig(), namespace="jobs", api_factory=lambda: api
    )

    sandbox.start()

    name, namespace, policy = networking.replace_namespaced_network_policy.call_args.args
    assert (name, namespace) == (policy.metadata.name, "jobs")
    assert policy.spec.policy_types == ["Ingress", "Egress"]
    api.create_namespaced_pod.assert_called_once()


def test_pod_is_not_created_without_its_network_policy(monkeypatch):
    client = pytest.importorskip("kubernetes.client")
    api = _running_api()
    networking = MagicMock()
    networking.create_namespaced_network_policy.side_effect = RuntimeError("forbidden")
    monkeypatch.setattr(client, "NetworkingV1Api", MagicMock(return_value=networking))
    sandbox = KubernetesSandbox(
        "sandbox:1", SandboxRunConfig(), namespace="jobs", api_factory=lambda: api
    )

    with pytest.raises(RuntimeError, match="forbidden"):
        sandbox.start()
    api.create_namespaced_pod.assert_not_called()


def test_networked_config_is_rejected():
    backend = KubernetesSandboxBackend(image="sandbox:1")
    with pytest.raises(ValueError, match="network"):
        backend.create("sandbox:1", SandboxRunConfig(network_mode="bridge"))


@pytest.mark.parametrize(
    ("network_mode", "allowed"), [("none", True), ("bridge", False), (None, False)]
)
def test_runner_verification_guard_reads_network_mode(tmp_path, network_mode, allowed):
    config = (
        SimpleNamespace() if network_mode is None else SandboxRunConfig(network_mode=network_mode)
    )
    sandbox = KubernetesSandbox("sandbox:1", config, namespace="jobs", api_factory=MagicMock)
    sandbox.workspace_baseline_commit = "a" * 40
    runner = SourceHuntRunner(
        repo_url="test",
        output_dir=str(tmp_path),
        sandbox_factory=lambda **_: sandbox,
        enable_calibration=False,
        enable_mechanism_memory=False,
        enable_patch_oracle=False,
    )

    verification_sandbox, _, tools = runner._verification_resources(str(tmp_path))

    assert (verification_sandbox is sandbox) is allowed
    assert bool(tools) is allowed


def test_exit_code_parsing():
    response = MagicMock()
    response.read_channel.return_value = (
        '{"status":"Failure","details":{"causes":[{"reason":"ExitCode","message":"137"}]}}'
    )
    assert KubernetesSandbox._parse_exit_code(response) == 137

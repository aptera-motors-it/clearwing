"""Tests for Kali Docker tool (requires Docker daemon)."""

import shutil
from unittest.mock import MagicMock, patch

import pytest

from clearwing.agent.tooling import InterruptRequest
from clearwing.agent.tools.ops.kali_docker_tool import (
    CONTAINER_NAME,
    kali_cleanup,
    kali_execute,
    kali_install_tool,
    kali_setup,
)
from clearwing.mcp.server import _denied_tools

docker_available = shutil.which("docker") is not None

try:
    import docker as docker_lib

    client = docker_lib.from_env()
    client.ping()
    docker_running = True
except Exception:
    docker_lib = None
    docker_running = False

skip_no_docker = pytest.mark.skipif(
    not (docker_available and docker_running), reason="Docker daemon not available"
)


class TestKaliDockerSecurity:
    def test_execute_is_bound_to_managed_container(self):
        client = MagicMock()
        container = client.containers.get.return_value
        container.exec_run.return_value = (0, b"uid=0(root)")

        with (
            patch("docker.from_env", return_value=client),
            patch(
                "clearwing.agent.tools.ops.kali_docker_tool.interrupt",
                return_value=True,
            ) as approval,
        ):
            result = kali_execute.func(container_id="production-db", command="id")

        approval.assert_called_once_with(f"Approve running in Kali container {CONTAINER_NAME}: id")
        client.containers.get.assert_called_once_with(CONTAINER_NAME)
        assert result == {"exit_code": 0, "output": "uid=0(root)"}

    def test_default_mcp_denylist_blocks_kali_lifecycle_tools(self, monkeypatch):
        monkeypatch.delenv("CLEARWING_MCP_DENIED_TOOLS", raising=False)
        assert {"kali_setup", "kali_install_tool"} <= _denied_tools()

    def test_cleanup_requires_approval_and_is_bound_to_managed_container(self):
        client = MagicMock()

        with (
            patch("docker.from_env", return_value=client),
            patch(
                "clearwing.agent.tools.ops.kali_docker_tool.interrupt",
                return_value=False,
            ) as approval,
        ):
            denied = kali_cleanup.func(container_id="production-db")

        approval.assert_called_once_with(f"Approve removing Kali container {CONTAINER_NAME}?")
        client.containers.get.assert_not_called()
        assert denied == {
            "status": "denied",
            "message": "Kali cleanup denied by user",
        }

        with (
            patch("docker.from_env", return_value=client),
            patch(
                "clearwing.agent.tools.ops.kali_docker_tool.interrupt",
                return_value=True,
            ),
        ):
            removed = kali_cleanup.func(container_id="production-db")

        client.containers.get.assert_called_once_with(CONTAINER_NAME)
        assert removed["status"] == "removed"

    def test_install_requires_approval(self):
        client = MagicMock()
        client.containers.get.return_value.exec_run.return_value = (0, b"installed")

        with (
            patch("docker.from_env", return_value=client),
            patch(
                "clearwing.agent.tools.ops.kali_docker_tool.interrupt",
                return_value=False,
            ) as approval,
        ):
            result = kali_install_tool.func(
                container_id="production-db",
                package_name="nmap",
            )

        approval.assert_called_once_with(
            f"Approve installing package 'nmap' in Kali container {CONTAINER_NAME}?"
        )
        client.containers.get.assert_not_called()
        assert result == {"exit_code": -1, "output": "Installation denied by user"}

        client.reset_mock()
        with (
            patch("docker.from_env", return_value=client),
            patch(
                "clearwing.agent.tools.ops.kali_docker_tool.interrupt",
                return_value=True,
            ),
        ):
            installed = kali_install_tool.func(
                container_id="production-db",
                package_name="nmap",
            )

        client.containers.get.assert_called_once_with(CONTAINER_NAME)
        assert installed == {"exit_code": 0, "output": "installed"}

    def test_setup_requires_approval_before_docker_access(self):
        with (
            patch("docker.from_env") as from_env,
            patch("platform.system", return_value="Linux"),
            patch(
                "clearwing.agent.tools.ops.kali_docker_tool.interrupt",
                return_value=False,
            ) as approval,
        ):
            result = kali_setup.func()

        approval.assert_called_once_with(
            f"Approve setup of Kali container {CONTAINER_NAME} (network_mode=host)?"
        )
        from_env.assert_not_called()
        assert result == {
            "status": "denied",
            "message": "Kali setup denied by user",
        }

    def test_setup_fails_closed_without_resume_decision(self):
        with (
            patch("docker.from_env") as from_env,
            pytest.raises(InterruptRequest, match="clearwing-kali"),
        ):
            kali_setup.invoke({})

        from_env.assert_not_called()


@skip_no_docker
class TestKaliDocker:
    """Integration tests using alpine image for speed."""

    @pytest.fixture(autouse=True)
    def cleanup(self):
        """Cleanup any leftover test containers."""
        yield
        try:
            client = docker_lib.from_env()
            try:
                container = client.containers.get("clearwing-kali-test")
                container.stop(timeout=2)
                container.remove()
            except docker_lib.errors.NotFound:
                pass
        except Exception:
            pass

    def test_container_lifecycle(self):
        """Test start, execute, cleanup using alpine."""

        client = docker_lib.from_env()

        # Use alpine instead of kali for test speed
        container = client.containers.run(
            "alpine:latest",
            command="sleep 300",
            name="clearwing-kali-test",
            detach=True,
        )

        try:
            assert container.status in ("running", "created")

            # Execute a command
            exit_code, output = container.exec_run("echo hello")
            assert exit_code == 0
            assert b"hello" in output

            # Stop and remove
            container.stop(timeout=2)
            container.remove()

            # Verify removed
            with pytest.raises(docker_lib.errors.NotFound):
                client.containers.get("clearwing-kali-test")
        except Exception:
            # Cleanup on failure
            try:
                container.stop(timeout=2)
                container.remove()
            except Exception:
                pass
            raise

    def test_container_reuse(self):
        """Test that existing containers are reused."""
        client = docker_lib.from_env()

        container = client.containers.run(
            "alpine:latest",
            command="sleep 300",
            name="clearwing-kali-test",
            detach=True,
        )

        try:
            # Getting same container by name should return same ID
            same = client.containers.get("clearwing-kali-test")
            assert same.id == container.id
        finally:
            container.stop(timeout=2)
            container.remove()

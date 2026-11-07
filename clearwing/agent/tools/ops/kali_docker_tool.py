import platform

import docker

from clearwing.agent.tooling import interrupt, tool

CONTAINER_NAME = "clearwing-kali"


@tool
def kali_setup() -> dict:
    """Start a Kali Linux Docker container for specialized security tools.

    Pulls kalilinux/kali-rolling if not present, starts a container, and
    returns the container ID. Reuses existing container if one is already running.

    Returns:
        Dict with keys: container_id, status, message.
    """
    network_mode = "host" if platform.system() == "Linux" else "bridge"
    approval = interrupt(
        f"Approve setup of Kali container {CONTAINER_NAME} (network_mode={network_mode})?"
    )
    if not approval:
        return {"status": "denied", "message": "Kali setup denied by user"}

    client = docker.from_env()

    # Check for existing container
    try:
        existing = client.containers.get(CONTAINER_NAME)
        if existing.status == "running":
            return {
                "container_id": existing.id,
                "status": "reused",
                "message": f"Reusing existing Kali container {existing.short_id}",
            }
        existing.start()
        return {
            "container_id": existing.id,
            "status": "restarted",
            "message": f"Restarted existing Kali container {existing.short_id}",
        }
    except docker.errors.NotFound:
        pass

    # Pull image if needed
    try:
        client.images.get("kalilinux/kali-rolling")
    except docker.errors.ImageNotFound:
        client.images.pull("kalilinux/kali-rolling")

    container = client.containers.run(
        "kalilinux/kali-rolling",
        command="sleep infinity",
        name=CONTAINER_NAME,
        network_mode=network_mode,
        detach=True,
        tty=True,
    )

    return {
        "container_id": container.id,
        "status": "created",
        "message": f"Started new Kali container {container.short_id}",
    }


@tool
def kali_execute(container_id: str, command: str) -> dict:
    """Execute a command inside the Kali Docker container. REQUIRES HUMAN APPROVAL.

    Args:
        container_id: Retained for compatibility; execution is bound to clearwing-kali.
        command: Shell command to execute.

    Returns:
        Dict with keys: exit_code, output.
    """
    approval = interrupt(f"Approve running in Kali container {CONTAINER_NAME}: {command}")
    if not approval:
        return {"exit_code": -1, "output": "Command denied by user"}

    client = docker.from_env()
    container = client.containers.get(CONTAINER_NAME)
    exit_code, output = container.exec_run(command, tty=True)
    return {
        "exit_code": exit_code,
        "output": output.decode("utf-8", errors="replace"),
    }


@tool
def kali_install_tool(container_id: str, package_name: str) -> dict:
    """Install a package in the Kali Docker container via apt-get.

    Args:
        container_id: Retained for compatibility; installation is bound to clearwing-kali.
        package_name: Debian package name to install (e.g. 'nmap', 'nikto').

    Returns:
        Dict with keys: exit_code, output.
    """
    approval = interrupt(
        f"Approve installing package {package_name!r} in Kali container {CONTAINER_NAME}?"
    )
    if not approval:
        return {"exit_code": -1, "output": "Installation denied by user"}

    client = docker.from_env()
    container = client.containers.get(CONTAINER_NAME)
    exit_code, output = container.exec_run(
        f"apt-get update -qq && apt-get install -y -qq {package_name}", tty=True
    )
    return {
        "exit_code": exit_code,
        "output": output.decode("utf-8", errors="replace"),
    }


@tool
def kali_cleanup(container_id: str) -> dict:
    """Stop and remove the Kali Docker container.

    Args:
        container_id: Retained for compatibility; cleanup is bound to clearwing-kali.

    Returns:
        Dict with keys: status, message.
    """
    approval = interrupt(f"Approve removing Kali container {CONTAINER_NAME}?")
    if not approval:
        return {"status": "denied", "message": "Kali cleanup denied by user"}

    client = docker.from_env()
    try:
        container = client.containers.get(CONTAINER_NAME)
        container.stop(timeout=5)
        container.remove()
        return {"status": "removed", "message": f"Container {CONTAINER_NAME} removed"}
    except docker.errors.NotFound:
        return {"status": "not_found", "message": "Container not found"}

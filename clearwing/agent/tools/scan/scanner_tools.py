import ipaddress
from urllib.parse import urlparse

import clearwing.scanning as scanning
from clearwing.agent.tooling import _TOOL_ACTIVE, interrupt, tool
from clearwing.asm.scope import Scope
from clearwing.core.config import Config


def _configured_engagement_scopes() -> list[Scope]:
    asm_config = Config().get("asm", default={}) or {}
    return [
        Scope.from_config(name, asm_config)
        for name in (asm_config.get("scopes") or {})
    ]


def _target_host(target: str) -> str:
    candidate = target.strip()
    if "://" in candidate:
        return (urlparse(candidate).hostname or "").lower().rstrip(".")
    return candidate.lower().rstrip(".")


def _target_in_scope(target: str, scope: Scope) -> bool:
    host = _target_host(target)
    if not host:
        return False
    if any(host == excluded or host.endswith("." + excluded) for excluded in scope.exclusions):
        return False
    if scope.in_scope(host):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        for cidr in scope.cidrs:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    seed_hosts = {
        (urlparse(seed).hostname or "").lower().rstrip(".")
        for seed in scope.seed_urls
    }
    return host in seed_hosts


def _require_scan_access(action: str, target: str, details: str = "") -> None:
    if not _TOOL_ACTIVE.get():
        return
    if not any(_target_in_scope(target, scope) for scope in _configured_engagement_scopes()):
        raise PermissionError(f"Target {target} is outside configured engagement scope")
    suffix = f" ({details})" if details else ""
    if not interrupt(f"Approve {action} against target {target}{suffix}?"):
        raise PermissionError(f"User declined {action} against {target}")


@tool
async def scan_ports(
    target: str,
    ports: list[int] | None = None,
    scan_type: str = "syn",
    threads: int = 100,
) -> list[dict]:
    """Scan a target for open ports.

    Args:
        target: Target IP address.
        ports: List of ports to scan. Defaults to common ports if not provided.
        scan_type: Type of scan - 'syn' or 'connect'.
        threads: Number of concurrent threads.

    Returns:
        List of open port info dicts with keys: port, protocol, state, service.
    """
    port_scope = f"ports={ports or 'common'}, type={scan_type}, threads={threads}"
    _require_scan_access("port scan", target, port_scope)

    scanner = scanning.PortScanner()
    return await scanner.scan(target, ports or [], scan_type, threads)


@tool
async def detect_services(target: str, open_ports: list[dict]) -> list[dict]:
    """Detect services running on open ports via banner grabbing.

    Args:
        target: Target IP address.
        open_ports: List of open port dicts from scan_ports (must have 'port' key).

    Returns:
        List of service info dicts with keys: port, service, banner, version, protocol.
    """
    ports = [item.get("port") for item in open_ports]
    _require_scan_access("service detection", target, f"ports={ports}")

    scanner = scanning.ServiceScanner()
    return await scanner.detect(target, open_ports)


@tool
async def scan_vulnerabilities(target: str, services: list[dict]) -> list[dict]:
    """Scan detected services for known vulnerabilities using local DB and NVD.

    Args:
        target: Target IP address.
        services: List of service dicts from detect_services.

    Returns:
        List of vulnerability dicts with keys: cve, description, cvss, port, service.
    """
    service_scope = [
        {
            "port": item.get("port"),
            "service": item.get("service"),
            "version": item.get("version"),
        }
        for item in services
    ]
    _require_scan_access("vulnerability scan", target, f"services={service_scope}")

    scanner = scanning.VulnerabilityScanner()
    try:
        return await scanner.scan(target, services)
    finally:
        await scanner.close()


@tool
async def detect_os(target: str) -> str:
    """Detect the operating system of the target using TTL and TCP fingerprinting.

    Args:
        target: Target IP address.

    Returns:
        Detected OS string (e.g. 'Linux/Unix', 'Windows') or 'Unknown'.
    """
    _require_scan_access("OS detection", target)

    scanner = scanning.OSScanner()
    return await scanner.detect(target)


@tool
async def record_finding(
    description: str,
    port: int | None = None,
    service: str = "",
    version: str = "",
    severity: str = "info",
    cve: str = "",
    cvss: float = 0.0,
    url: str = "",
    request: str = "",
    response: str = "",
    evidence: str = "",
) -> dict:
    """Record a structured security finding for the run's final report.

    Use this to register a finding you identified from ANY source — Kali/nmap
    output via ``kali_execute``, manual analysis, or source review — that the
    automated ``scan_vulnerabilities`` tool did not capture. Kali/manual output is
    free text and never reaches the structured findings list on its own, so an
    Operator that relies on the Kali path must call this once per distinct finding
    (e.g. one per vulnerable service) before concluding, or the run reports zero
    findings despite a successful scan.

    Always attach the concrete detection evidence: the exact ``url`` you hit, the
    ``request`` you sent and the ``response`` you got back (for web/HTTP findings),
    or the raw tool output in ``evidence`` (for nmap/Kali). Without it the report
    and any DefectDojo export show a bare CVE with no proof of how it was found.

    Args:
        description: Human-readable description of the finding (required).
        port: Affected TCP/UDP port, if applicable.
        service: Affected service name (e.g. 'vsftpd', 'mysql').
        version: Detected service version, if known.
        severity: One of info, low, medium, high, critical (default: info).
        cve: Related CVE id, if known (e.g. 'CVE-2011-2523').
        cvss: CVSS base score, if known.
        url: The exact URL/endpoint where the issue was detected (web findings).
        request: The raw HTTP request (or command) that triggered detection.
        response: The raw HTTP response (or tool output) that proves the issue.
        evidence: Any other raw evidence (e.g. nmap/Kali output) when the
            request/response pair does not apply.

    Returns:
        The normalized finding dict that was recorded.
    """
    sev = str(severity).strip().lower()
    if sev not in ("info", "low", "medium", "high", "critical"):
        sev = "info"
    finding: dict = {
        "description": str(description).strip(),
        "severity": sev,
        "service": str(service).strip(),
        "version": str(version).strip(),
        "cve": str(cve).strip(),
        "cvss": float(cvss) if cvss else 0.0,
    }
    if port is not None:
        try:
            finding["port"] = int(port)
        except (TypeError, ValueError):
            finding["port"] = port
    # Detection evidence — carried through to the report and the DefectDojo
    # export so a finding is not a bare CVE without proof of how it was found.
    for key, value in (
        ("url", url),
        ("request", request),
        ("response", response),
        ("evidence", evidence),
    ):
        text_value = str(value).strip()
        if text_value:
            finding[key] = text_value
    return finding

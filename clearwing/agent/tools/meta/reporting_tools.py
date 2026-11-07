from pathlib import Path

from clearwing.agent.tooling import interrupt, tool
from clearwing.core.config import default_results_dir
from clearwing.core.engine import ScanResult
from clearwing.data.database import Database
from clearwing.reporting import ReportGenerator


@tool
def generate_report(format: str, scan_data: dict) -> str:
    """Generate a report from scan data collected by the agent.

    Args:
        format: Report format - 'text', 'json', 'html', or 'markdown'.
        scan_data: Dict with keys: target, open_ports, services, vulnerabilities,
                   exploits, os_info.

    Returns:
        Formatted report string.
    """
    result = ScanResult(target=scan_data.get("target", "unknown"))
    result.open_ports = scan_data.get("open_ports", [])
    result.services = scan_data.get("services", [])
    result.vulnerabilities = scan_data.get("vulnerabilities", [])
    result.exploits = scan_data.get("exploits", [])
    result.os_info = scan_data.get("os_info")

    generator = ReportGenerator()
    return generator.generate(result, format)


@tool
def save_report(filepath: str, format: str, scan_data: dict) -> str:
    """Save a report to a file.

    Args:
        filepath: Path to save the report file.
        format: Report format - 'text', 'json', 'html', or 'markdown'.
        scan_data: Dict with keys: target, open_ports, services, vulnerabilities,
                   exploits, os_info.

    Returns:
        Confirmation message with file path.
    """
    reports_dir = Path(default_results_dir("reports")).expanduser().resolve()
    requested_path = Path(filepath).expanduser()
    destination = (
        requested_path.resolve()
        if requested_path.is_absolute()
        else (reports_dir / requested_path).resolve()
    )
    if destination != reports_dir and reports_dir not in destination.parents:
        return f"Refusing path outside reports directory: {reports_dir}"
    if not interrupt(f"Approve saving {format} report to {destination}?"):
        return "Report save rejected by user."

    result = ScanResult(target=scan_data.get("target", "unknown"))
    result.open_ports = scan_data.get("open_ports", [])
    result.services = scan_data.get("services", [])
    result.vulnerabilities = scan_data.get("vulnerabilities", [])
    result.exploits = scan_data.get("exploits", [])
    result.os_info = scan_data.get("os_info")

    generator = ReportGenerator()
    generator.save(result, str(destination), format)
    return f"Report saved to {destination}"


@tool
def query_scan_history(target: str | None = None) -> list[dict]:
    """Query scan history from the database.

    Args:
        target: Optional target IP to filter. Returns all targets if not provided.

    Returns:
        List of scan history records.
    """
    db = Database()
    if target:
        return db.get_target_history(target)
    return db.get_all_targets()


@tool
def search_cves(pattern: str) -> list[dict]:
    """Search for CVEs in the scan database by pattern.

    Args:
        pattern: SQL LIKE pattern for CVE IDs (e.g. 'CVE-2017%').

    Returns:
        List of matching vulnerability records.
    """
    db = Database()
    return db.search_vulnerabilities(pattern)

from pathlib import Path
import sys
from urllib.parse import urlparse

# Make the parent directory (~) importable when Streamlit runs
# scanner.py from ~/vulnerability_scanner.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from lotm.pathways.guardian import guardian_scan
from lotm.pathways.savant import fingerprint


def _severity_for_guardian(finding):
    category = finding.get("category")
    status = finding.get("status")

    if category == "authorization" and status == "possible_bypass":
        return "High", 7.5

    if category == "authorization" and status == "review":
        return "Medium", 5.3

    if category == "cookie" and status == "missing":
        return "Medium", 5.3

    if category == "cors" and status == "wildcard":
        return "Medium", 5.3

    if category == "security_header" and status == "missing":
        return "Low", 3.1

    if category == "api_route" and status == "review":
        return "Low", 3.1

    return "Info", 0.0


def _target_service(target):
    parsed = urlparse(target)
    scheme = parsed.scheme.lower()

    if scheme == "https":
        service = "HTTPS"
        default_port = 443
    else:
        service = "HTTP"
        default_port = 80

    port = parsed.port or default_port
    return port, service


def _guardian_findings(result, port, service):
    rows = []

    for finding in result.get("findings", []):
        severity, cvss = _severity_for_guardian(finding)

        category = finding.get("category", "security")
        name = finding.get("name", category)
        status = finding.get("status", "observed")

        detail = finding.get("detail") or finding.get("cta") or ""

        rows.append({
            "Port": port,
            "Service": service,
            "Status": status.title(),
            "Finding": f"LOTM Guardian: {name}",
            "Severity": severity,
            "CVSS": cvss,
            "Evidence": (
                f"Category={category}; "
                f"Status={status}; "
                f"{detail}"
            ),
        })

    return rows


def _savant_findings(result, port, service):
    rows = []

    for technology in result.get("technologies", []):
        name = technology.get("technology", "Unknown")
        category = technology.get("category", "technology")
        confidence = technology.get("confidence", "unknown")
        evidence = technology.get("evidence", [])

        rows.append({
            "Port": port,
            "Service": service,
            "Status": "Detected",
            "Finding": f"LOTM Savant: {name}",
            "Severity": "Info",
            "CVSS": 0.0,
            "Evidence": (
                f"Category={category}; "
                f"Confidence={confidence}; "
                f"Evidence={'; '.join(map(str, evidence[:5]))}"
            ),
        })

    for version in result.get("versions", []):
        technology = version.get("technology", "Unknown")
        value = version.get("version", "Unknown")
        source = version.get("source", "public evidence")
        confidence = version.get("confidence", "unknown")
        evidence = version.get("evidence", [])

        rows.append({
            "Port": port,
            "Service": service,
            "Status": "Version Observed",
            "Finding": f"LOTM Savant: {technology} version evidence",
            "Severity": "Info",
            "CVSS": 0.0,
            "Evidence": (
                f"Version={value}; "
                f"Source={source}; "
                f"Confidence={confidence}; "
                f"Evidence={'; '.join(map(str, evidence[:5]))}"
            ),
        })

    return rows


def run_lotm_observation(target):
    """
    Run LOTM's passive Guardian and Savant pathways.

    No POST/PUT/PATCH/DELETE requests are performed here.
    Guardian's bounded rate-limit observation remains passive.
    """
    target = target.strip()

    if "://" not in target:
        target = "https://" + target

    port, service = _target_service(target)

    guardian = guardian_scan(target)
    savant = fingerprint(target)

    rows = []
    rows.extend(_guardian_findings(guardian, port, service))
    rows.extend(_savant_findings(savant, port, service))

    return rows, {
        "guardian": guardian,
        "savant": savant,
    }

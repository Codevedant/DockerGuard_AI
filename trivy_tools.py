import json
import subprocess

from langchain_core.tools import tool


@tool
def scan_docker_image(image: str):
    """
    Scan a Docker image with Trivy and return confirmed vulnerability
    findings. Trivy is the source of truth for CVEs and severity.
    """

    result = subprocess.run(
        [
            "trivy",
            "image",
            "--quiet",
            "--format",
            "json",
            "--severity",
            "CRITICAL,HIGH,MEDIUM,LOW",
            image,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return (
            "TRIVY_ERROR\n"
            + result.stderr.strip()
        )

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return "TRIVY_ERROR\nCould not parse Trivy JSON output."

    findings = []

    for target in report.get("Results", []):
        target_name = target.get("Target", "unknown")

        for vuln in target.get("Vulnerabilities") or []:
            findings.append(
                {
                    "target": target_name,
                    "vulnerability_id": vuln.get("VulnerabilityID"),
                    "severity": vuln.get("Severity"),
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "title": vuln.get("Title"),
                }
            )

    if not findings:
        return (
            "TRIVY_RESULT\n"
            "No CRITICAL, HIGH, MEDIUM, or LOW vulnerabilities found."
        )

    output = [
        "TRIVY_RESULT",
        f"Confirmed vulnerabilities: {len(findings)}",
        "",
    ]

    for i, finding in enumerate(findings[:30], 1):
        output.append(
            f"{i}. "
            f"{finding['vulnerability_id']} | "
            f"{finding['severity']} | "
            f"package={finding['package']} | "
            f"installed={finding['installed_version']} | "
            f"fixed={finding['fixed_version'] or 'not available'} | "
            f"target={finding['target']} | "
            f"title={finding['title'] or 'N/A'}"
        )

    if len(findings) > 30:
        output.append("")
        output.append(
            f"Only the first 30 of {len(findings)} findings are shown."
        )

    return "\n".join(output)

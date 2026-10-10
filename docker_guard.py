
"""
DockerGuard AI: read-only Dockerfile/image/container security auditor with Ollama summaries.

This tool gathers evidence using Docker CLI, Docker Scout, and Trivy, then asks a local
Ollama model to explain findings. It does not edit Dockerfiles, install packages in images,
stop/remove containers, or rebuild images.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:3b")
MAX_TEXT = 18000
TIMEOUT = 300


def run_cmd(args: list[str], timeout: int = TIMEOUT) -> dict[str, Any]:
    """Run a fixed, argument-list command; never invokes a shell."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "command": " ".join(args),
            "returncode": p.returncode,
            "stdout": p.stdout[-MAX_TEXT:],
            "stderr": p.stderr[-6000:],
        }
    except FileNotFoundError:
        return {"command": " ".join(args), "returncode": 127, "stdout": "", "stderr": f"Required command not found: {args[0]}"}
    except subprocess.TimeoutExpired as e:
        return {"command": " ".join(args), "returncode": 124, "stdout": str(e.stdout or "")[-MAX_TEXT:], "stderr": f"Timed out after {timeout}s"}


def command_available(name: str) -> bool:
    return shutil.which(name) is not None


def read_text(path: Path, limit: int = 14000) -> str:
    try:
        return path.read_text(errors="replace")[:limit]
    except (OSError, IsADirectoryError):
        return ""


def static_dockerfile_review(project_dir: Path, dockerfile_override: Path | None = None) -> dict[str, Any]:
    dockerfile = dockerfile_override.resolve() if dockerfile_override else project_dir / "Dockerfile"
    if not dockerfile.exists():
        # Use a Dockerfile only if one exists; don't silently choose an arbitrary one.
        return {
            "dockerfile": None,
            "error": "No file named Dockerfile found in the selected directory. Use --dockerfile PATH if needed.",
            "checks": [],
            "source": "",
            "dockerignore": read_text(project_dir / ".dockerignore"),
        }

    source = read_text(dockerfile, 24000)
    checks: list[dict[str, str]] = []

    def add(severity: str, category: str, line_no: int | None, finding: str, recommendation: str) -> None:
        checks.append({
            "severity": severity, "category": category,
            "line": str(line_no) if line_no is not None else "-",
            "finding": finding, "recommendation": recommendation
        })

    lines = source.splitlines()
    from_lines = [(i, line.strip()) for i, line in enumerate(lines, 1) if re.match(r"^\s*FROM\s+", line, re.I)]
    if not from_lines:
        add("HIGH", "Build configuration", None, "No FROM instruction detected.", "Check that this is the intended Dockerfile.")
    for i, line in from_lines:
        if re.search(r":latest\b", line, re.I) or not re.search(r"\S+:\S+", line.split("#", 1)[0]):
            add("MEDIUM", "Base image pinning", i, f"Base image may be unpinned: {line}", "Pin a tested tag or digest after compatibility testing; do not change it automatically.")
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        upper = stripped.upper()
        if re.match(r"^USER\s+root\b", stripped, re.I):
            add("HIGH", "Runtime privilege", i, "Explicit USER root.", "Use a non-root runtime user if the application and image support it.")
        if re.match(r"^ADD\s+", stripped, re.I):
            add("LOW", "Dockerfile instruction", i, "ADD is used.", "Prefer COPY unless ADD's archive/URL behavior is intentionally required.")
        if re.search(r"(curl|wget).*(\||&&).*(sh|bash)", stripped, re.I):
            add("HIGH", "Supply-chain execution", i, "Downloads and executes a script in one instruction.", "Pin and verify downloaded artifacts; avoid piping remote content directly to a shell.")
        if re.match(r"^(ENV|ARG)\s+.*(PASSWORD|TOKEN|SECRET|API_KEY|PRIVATE_KEY)\s*=", stripped, re.I):
            add("CRITICAL", "Potential secret exposure", i, "Potential secret assigned through ARG/ENV.", "Do not bake secrets into image layers; inject them at runtime via a secret manager.")
        if upper.startswith("RUN ") and ("apt-get install" in stripped or "apk add" in stripped) and not any(x in stripped for x in ("rm -rf /var/lib/apt/lists", "apk del", "--no-cache")):
            add("LOW", "Image size", i, "Package installation may leave package-index/cache files.", "Consider package-manager cache cleanup without removing required runtime packages.")
        if re.match(r"^COPY\s+\.\s+", stripped, re.I) and not (project_dir / ".dockerignore").exists():
            add("MEDIUM", "Build context", i, "COPY . is used but .dockerignore is missing.", "Add a reviewed .dockerignore to exclude .git, node_modules, logs, local secrets, and build output when appropriate.")
        if re.match(r"^HEALTHCHECK\s+NONE\b", stripped, re.I):
            add("LOW", "Runtime observability", i, "Health checks are explicitly disabled.", "Consider a suitable health check if the runtime/orchestrator needs one.")

    if not any(re.match(r"^\s*USER\s+", line, re.I) for line in lines):
        add("MEDIUM", "Runtime privilege", None, "No USER instruction detected; the image default user is not proven by this file.", "Inspect image config and use a non-root user when supported.")
    if len(from_lines) == 1:
        add("INFO", "Image size", None, "Single-stage Dockerfile detected.", "A multi-stage build may help if build tools/dev dependencies are not needed at runtime; preserve required runtime packages.")
    dockerignore_path = project_dir / ".dockerignore"
    dockerignore = read_text(dockerignore_path, 8000)
    if not dockerignore_path.exists():
        add("MEDIUM", "Build context", None, ".dockerignore is absent.", "Review whether unnecessary files or secrets are sent to the build context.")
    return {
        "dockerfile": str(dockerfile),
        "checks": checks,
        "source": source,
        "dockerignore": dockerignore,
        "dockerignore_exists": dockerignore_path.exists(),
        "from_instructions": [line for _, line in from_lines],
    }


def image_info(image: str) -> dict[str, Any]:
    inspect = run_cmd(["docker", "image", "inspect", image])
    history = run_cmd(["docker", "history", "--no-trunc", image])
    if inspect["returncode"] == 0:
        try:
            data = json.loads(inspect["stdout"])[0]
            config = data.get("Config") or {}
            info = {
                "id": data.get("Id"),
                "repo_tags": data.get("RepoTags"),
                "size_bytes": data.get("Size"),
                "size_mb": round((data.get("Size") or 0) / 1024 / 1024, 2),
                "created": data.get("Created"),
                "architecture": data.get("Architecture"),
                "os": data.get("Os"),
                "user": config.get("User") or "(empty/default; verify effective user)",
                "entrypoint": config.get("Entrypoint"),
                "cmd": config.get("Cmd"),
                "exposed_ports": config.get("ExposedPorts"),
                "environment_names": sorted({
                    item.split("=", 1)[0] for item in (config.get("Env") or [])
                    if "=" in item
                }),
                "history": history,
            }
        except (ValueError, IndexError, TypeError):
            info = {"inspect": inspect, "history": history}
    else:
        info = {"inspect": inspect, "history": history}
    return info


def scan_image(image: str, out_dir: Path) -> dict[str, Any]:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", image)
    result: dict[str, Any] = {"image": image, "info": image_info(image), "scanners": {}}

    if command_available("docker") and run_cmd(["docker", "scout", "version"], timeout=30)["returncode"] == 0:
        result["scanners"]["scout_quickview"] = run_cmd(["docker", "scout", "quickview", f"local://{image}"])
        result["scanners"]["scout_cves"] = run_cmd(["docker", "scout", "cves", f"local://{image}"])
        result["scanners"]["scout_recommendations"] = run_cmd(["docker", "scout", "recommendations", f"local://{image}"])
    else:
        result["scanners"]["scout"] = {"skipped": "Docker Scout CLI unavailable; install/authenticate it to use Scout."}

    if command_available("trivy"):
        trivy_path = out_dir / f"{safe_name}.trivy.json"
        result["scanners"]["trivy"] = run_cmd([
            "trivy", "image", "--format", "json", "--output", str(trivy_path), image
        ], timeout=900)
        result["scanners"]["trivy_json_path"] = str(trivy_path)
        if trivy_path.exists():
            try:
                trivy_json = json.loads(trivy_path.read_text(errors="replace"))
                counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
                findings = []
                for target in trivy_json.get("Results") or []:
                    for vuln in target.get("Vulnerabilities") or []:
                        sev = str(vuln.get("Severity", "UNKNOWN")).upper()
                        counts[sev if sev in counts else "UNKNOWN"] += 1
                        if len(findings) < 100:
                            findings.append({
                                "target": target.get("Target"),
                                "package": vuln.get("PkgName"),
                                "installed_version": vuln.get("InstalledVersion"),
                                "fixed_version": vuln.get("FixedVersion"),
                                "severity": sev,
                                "vulnerability_id": vuln.get("VulnerabilityID"),
                                "title": vuln.get("Title"),
                            })
                result["scanners"]["trivy_summary"] = {"counts": counts, "findings": findings}
            except (OSError, ValueError, TypeError):
                result["scanners"]["trivy_summary"] = {"error": "Could not parse Trivy JSON"}
    else:
        result["scanners"]["trivy"] = {"skipped": "Trivy unavailable; install it to add an independent scanner."}
    return result


def list_images() -> dict[str, Any]:
    return run_cmd(["docker", "image", "ls", "--no-trunc", "--format", "{{json .}}"])


def list_containers() -> dict[str, Any]:
    listed = run_cmd(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"])
    rows = []
    if listed["returncode"] == 0:
        for line in listed["stdout"].splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    results = []
    for row in rows:
        cid = row.get("ID")
        if not cid:
            continue
        inspect = run_cmd(["docker", "inspect", cid])
        item: dict[str, Any] = {"summary": row, "inspect_error": inspect["stderr"] if inspect["returncode"] else None}
        if inspect["returncode"] == 0:
            try:
                d = json.loads(inspect["stdout"])[0]
                host = d.get("HostConfig") or {}
                cfg = d.get("Config") or {}
                state = d.get("State") or {}
                mounts = d.get("Mounts") or []
                item["security_review"] = {
                    "name": d.get("Name", "").lstrip("/"),
                    "image": d.get("Config", {}).get("Image"),
                    "state": state.get("Status"),
                    "running": state.get("Running"),
                    "user": cfg.get("User") or "(image default)",
                    "privileged": host.get("Privileged", False),
                    "readonly_rootfs": host.get("ReadonlyRootfs", False),
                    "cap_add": host.get("CapAdd") or [],
                    "security_opt": host.get("SecurityOpt") or [],
                    "network_mode": host.get("NetworkMode"),
                    "published_ports": d.get("NetworkSettings", {}).get("Ports"),
                    "mounts": [
                        {"source": m.get("Source"), "destination": m.get("Destination"), "rw": m.get("RW"), "type": m.get("Type")}
                        for m in mounts
                    ],
                    "restart_policy": (host.get("RestartPolicy") or {}).get("Name"),
                }
            except (ValueError, IndexError, TypeError):
                pass
        results.append(item)
    return {"list_command": listed, "containers": results}


def summarize_with_ollama(evidence: dict[str, Any]) -> str:
    # Keep evidence bounded to avoid huge prompts/context usage.
    payload = json.dumps(evidence, ensure_ascii=False, indent=2)
    if len(payload) > 38000:
        payload = payload[:38000] + "\n...[evidence truncated]"
    prompt = f"""You are DockerGuard AI, a careful container security reviewer.
Analyze only the evidence below. Do not invent CVEs, package versions, or scan results.
Treat Docker Scout/Trivy output as scanner evidence; distinguish confirmed findings from heuristic Dockerfile warnings.
Prioritize Critical, High, Medium, Low, then Informational. Categorize issues as:
1) OS/package vulnerabilities, 2) application dependency vulnerabilities, 3) Dockerfile/build practices,
4) container runtime configuration, 5) image size/layers, 6) secrets/supply-chain.
For each issue, state evidence, severity, impact, and a practical recommendation.
The user wants to preserve required application packages and the original Dockerfile. Do not recommend deleting required packages or silently changing the original file.
Optimization recommendations should be non-destructive and identify trade-offs; explain that image size alone does not prove vulnerability.
If a scanner is unavailable or failed, say coverage is incomplete.
Finish with a short prioritized action plan and a clear statement that no files/containers/images were changed.

Evidence:
{payload}
"""
    request_data = json.dumps({
        "model": OLLAMA_MODEL,
        "stream": False,
        "messages": [
            {"role": "system", "content": "You are a precise Docker and container security auditor. Never claim a vulnerability without scanner evidence."},
            {"role": "user", "content": prompt}
        ],
        "options": {"temperature": 0.1}
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_URL.rstrip('/')}/api/chat",
        data=request_data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=900) as response:
            body = json.loads(response.read().decode("utf-8"))
        return body.get("message", {}).get("content", "(Ollama returned no message)")
    except urllib.error.URLError as exc:
        return (
            f"Ollama summary unavailable: {exc}. Evidence is still saved. "
            f"Check `ollama list`, `ollama serve`, OLLAMA_URL={OLLAMA_URL}, "
            f"and OLLAMA_MODEL={OLLAMA_MODEL}."
        )
    except (TimeoutError, ValueError, KeyError) as exc:
        return f"Ollama summary failed: {exc}. Review the raw JSON evidence."


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Dockerfile, image, and container audit with local Ollama explanations."
    )
    parser.add_argument("--path", default=".", help="Project directory containing Dockerfile (default: current directory)")
    parser.add_argument("--dockerfile", help="Optional Dockerfile path; static review only")
    parser.add_argument("--image", action="append", default=[], help="Image name/tag to scan; repeatable")
    parser.add_argument("--all-images", action="store_true", help="Scan all local images (can take a long time)")
    parser.add_argument("--containers", action="store_true", help="Inspect all containers, including stopped ones")
    parser.add_argument("--no-ollama", action="store_true", help="Collect evidence without LLM summary")
    parser.add_argument("--out", default="docker-guard-reports", help="Output directory")
    args = parser.parse_args()

    if not command_available("docker"):
        print("ERROR: docker CLI not found in PATH.", file=sys.stderr)
        return 2

    project_dir = Path(args.path).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    custom_dockerfile = Path(args.dockerfile).expanduser().resolve() if args.dockerfile else None
    dockerfile_result = static_dockerfile_review(project_dir, custom_dockerfile)

    evidence: dict[str, Any] = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "project_directory": str(project_dir),
        "dockerfile_review": dockerfile_result,
        "images": [],
        "containers": None,
        "tool_versions": {
            "docker": run_cmd(["docker", "--version"], timeout=15),
            "docker_scout": run_cmd(["docker", "scout", "version"], timeout=20) if command_available("docker") else None,
            "trivy": run_cmd(["trivy", "--version"], timeout=20) if command_available("trivy") else None,
            "ollama_model": OLLAMA_MODEL,
            "ollama_url": OLLAMA_URL,
        }
    }

    images = list(args.image)
    if args.all_images:
        image_list = list_images()
        evidence["local_image_list"] = image_list
        if image_list["returncode"] == 0:
            for line in image_list["stdout"].splitlines():
                try:
                    row = json.loads(line)
                    name = row.get("Repository")
                    tag = row.get("Tag")
                    if name and name != "<none>" and tag and tag != "<none>":
                        images.append(f"{name}:{tag}")
                except ValueError:
                    pass
    # Deduplicate while preserving order
    images = list(dict.fromkeys(images))
    for image in images:
        print(f"[+] Scanning image: {image}", flush=True)
        evidence["images"].append(scan_image(image, out_dir))

    if args.containers:
        print("[+] Inspecting containers (read-only)", flush=True)
        evidence["containers"] = list_containers()

    raw_path = out_dir / "evidence.json"
    raw_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False))
    print(f"[+] Raw evidence saved: {raw_path}", flush=True)

    if not args.no_ollama:
        print(f"[+] Asking local Ollama model {OLLAMA_MODEL} to interpret evidence...", flush=True)
        summary = summarize_with_ollama(evidence)
        report_path = out_dir / "report.md"
        report_path.write_text(
            "# DockerGuard AI Report\n\n"
            f"- Generated: {evidence['generated_at_utc']}\n"
            f"- Project: `{project_dir}`\n"
            f"- Model: `{OLLAMA_MODEL}`\n\n"
            "> This is an AI interpretation of scanner output and static heuristics, not a guarantee of security. "
            "No Dockerfile, image, or container was changed.\n\n"
            + summary + "\n"
        )
        print("\n" + "=" * 72 + "\nDOCKERGUARD AI REPORT\n" + "=" * 72)
        print(summary)
        print(f"\n[+] Markdown report saved: {report_path}", flush=True)
    else:
        print("[i] --no-ollama selected; raw evidence only.")

    print("\nCompleted. This tool did not build, modify, stop, remove, or push images/containers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

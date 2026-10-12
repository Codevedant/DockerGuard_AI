

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

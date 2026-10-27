# DockerGuard AI

A **read-only** Docker security audit agent for Ubuntu using:
- Docker CLI for image metadata, history, and container configuration
- Docker Scout for image CVE/SBOM-based analysis (when installed and authenticated)
- Trivy as an independent image vulnerability scanner (when installed)
- Ollama running locally for explanations, severity grouping, and optimization recommendations

It does **not** modify Dockerfiles, install/remove image packages, build images, or start/stop/remove containers.

## 1. Requirements

- Ubuntu with Docker Engine and permission to run `docker`
- Ollama running locally (`ollama serve`) and a model pulled
- Optional: Docker Scout CLI (Docker Hub login may be required)
- Optional: Trivy

The default model is `qwen2.5-coder:3b` to keep memory needs lower than a 30B model. You can select any model already available to Ollama.

## 2. Install tools

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip curl wget gnupg

# Ollama: skip installation if already installed
ollama list
```

If the default model is not installed:
```bash
ollama pull qwen2.5-coder:3b
```

If your installed model has a different name, set it:
```bash
export OLLAMA_MODEL="qwen3-coder:30b"
```

Ensure Ollama responds:
```bash
curl http://127.0.0.1:11434/api/tags
```

### Optional Trivy installation (official Ubuntu repository)

```bash
sudo apt-get install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy
trivy --version
```

### Optional Docker Scout

Check:
```bash
docker scout version
docker scout quickview local://devboard-fe:full
```

If Scout is installed but requests authentication, sign in using Docker's supported login flow. Scout's vulnerability analysis requires its backend/advisory data; it is not purely offline.

## 3. Run

Copy `docker_guard.py` onto the EC2 instance and:

```bash
chmod +x docker_guard.py
cd /home/ubuntu/devboard/frontend

# Review the Dockerfile and scan one image:
python3 /path/to/docker_guard.py --path . --image devboard-fe:full --containers

# Scan every local image too (can take a while):
python3 /path/to/docker_guard.py --path . --image devboard-fe:full --all-images --containers

# Static Dockerfile and container metadata only; skip image scanning:
python3 /path/to/docker_guard.py --path . --containers --no-ollama
```

To use a custom Dockerfile:
```bash
python3 /path/to/docker_guard.py --path . --dockerfile Dockerfile.dhi --image devboard-fe:dhi --containers
```

Reports are written to `docker-guard-reports/` (or the `--out` directory):
- `evidence.json`: raw scanner and Docker evidence
- `report.md`: Ollama explanation and prioritized recommendations

## 4. What it checks

### Dockerfile static heuristics
- Floating/unpinned base image tags
- Explicit root user or no USER instruction
- Potential secret values in ARG/ENV
- `curl`/`wget` piped to a shell
- `ADD` usage
- Potential package-manager cache left behind
- Missing `.dockerignore`
- Single-stage build opportunities

These are heuristics, not proof of a vulnerability. For example, a missing `USER` line does not prove the image runs as root; image metadata is also inspected.

### Images
- Image size, architecture, configured user, exposed ports, environment variable **names** (not values), entrypoint/CMD
- `docker history` for layers
- Docker Scout CVEs, quickview and base-image recommendations when available
- Trivy vulnerability report when available

### Containers
- Running/stopped state, configured user, privileged mode, read-only root filesystem, added capabilities, security options, network mode, published ports, mounts and restart policy

## 5. Important limitations

- A vulnerability scanner only reports issues it can identify in the image and its database. No findings is not a proof of zero risk.
- The LLM summarizes scanner output; it does not independently verify CVEs.
- A smaller image is not automatically safer.
- The agent deliberately does not delete packages or edit your Dockerfile. It gives recommendations only.
- Docker access is highly privileged. Run the agent only on systems you administer.
- The script uses Docker commands read-only, but vulnerability scanners may download/update their advisory databases.

from docker_tools import (
    list_docker_images,
    inspect_docker_image,
    docker_image_history,
    list_containers,
    inspect_container
    )
import subprocess
import requests


OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "qwen2.5-coder:3b"

DOCKERFILE_PATH = "/home/ubuntu/devboard/frontend/Dockerfile"
IMAGE_NAME = "devboard-fe:full"


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip()

    except Exception as e:
        return f"Command failed: {e}"


def limit_output(text, maximum=4000):
    if len(text) > maximum:
        return text[:maximum] + "\n...[TRUNCATED]..."
    return text


print("[1] Reading Dockerfile...", flush=True)

try:
    with open(DOCKERFILE_PATH, "r") as file:
        dockerfile = file.read()
except Exception as e:
    dockerfile = f"Unable to read Dockerfile: {e}"


print("[2] Inspecting Docker image...", flush=True)

image_info = run_command(
    f"docker image inspect {IMAGE_NAME}"
)

image_info = limit_output(image_info)


print("[3] Inspecting image layers...", flush=True)

image_history = run_command(
    f"docker history {IMAGE_NAME}"
)

image_history = limit_output(image_history)


print("[4] Finding Docker containers...", flush=True)

containers = run_command(
    "docker ps -a --format "
    "'ID={{.ID}} IMAGE={{.Image}} STATUS={{.Status}} "
    "PORTS={{.Ports}} NAME={{.Names}}'"
)

containers = limit_output(containers)


print("[5] Checking container security...", flush=True)

container_ids = run_command(
    "docker ps -aq"
).split()

container_security = []

for container_id in container_ids:

    info = run_command(
        "docker inspect --format "
        "'Name={{.Name}} "
        "User={{.Config.User}} "
        "Privileged={{.HostConfig.Privileged}} "
        "NetworkMode={{.HostConfig.NetworkMode}} "
        "ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} "
        "PidMode={{.HostConfig.PidMode}} "
        "IpcMode={{.HostConfig.IpcMode}}' "
        + container_id
    )

    container_security.append(info)


container_security = "\n".join(container_security)
container_security = limit_output(container_security)
print("[6] Running Trivy vulnerability scan...", flush=True)

trivy_command = (
    f"trivy image "
    f"--format json "
    f"{IMAGE_NAME}"
)

trivy_output = run_command(trivy_command)

trivy_output = limit_output(
    trivy_output,

    8000
)

prompt = f"""
You are DockerGuard AI.

Analyze this Docker project for security.

IMPORTANT RULES:
1. Do NOT invent CVEs.
2. Trivy findings are the vulnerability evidence.
3. Do NOT claim a vulnerability unless supported by Trivy.
4. Separate confirmed vulnerabilities from recommendations.
5. Do not recommend removing required application dependencies.

DOCKERFILE:
{dockerfile}

DOCKER IMAGE:
{image_info}

IMAGE HISTORY:
{image_history}

CONTAINERS:
{containers}

CONTAINER SECURITY:
{container_security}

TRIVY VULNERABILITY SCAN:
{trivy_output}
"""

print("[7] Preparing AI analysis...", flush=True)

prompt = f"""
You are DockerGuard AI.

Analyze this Docker project for security.

IMPORTANT RULES:

1. Do NOT invent CVEs.
2. Do NOT call normal Docker commands vulnerabilities.
3. Do NOT call a package vulnerable without evidence.
4. Separate confirmed security issues from recommendations.
5. Keep the answer concise.

DOCKERFILE:
{dockerfile}

DOCKER IMAGE:
{image_info}

IMAGE HISTORY:
{image_history}

CONTAINERS:
{containers}

CONTAINER SECURITY:
{container_security}

Analyze:

1. Dockerfile security
2. Docker image configuration
3. Container security
4. Image optimization

For each finding use:

SEVERITY:
FINDING:
EVIDENCE:
EXPLANATION:
RECOMMENDATION:

Severity must be:

CRITICAL
HIGH
MEDIUM
LOW
INFO

If there is no confirmed vulnerability, say:

No confirmed vulnerability found.

You may still provide recommendations, but clearly
label them as recommendations.
"""


print("[7] Sending information to Ollama...", flush=True)

try:

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 250
            }
        },
        timeout=180
    )

    response.raise_for_status()

except requests.exceptions.Timeout:

    print()
    print("ERROR: Ollama took too long to respond.")
    print("Check Ollama/model performance.")
    exit(1)


result = response.json()

print()
print("========================================")
print("          DOCKERGUARD AI")
print("========================================")
print()

print(result["response"])

print()
print("========================================")
print("             ANALYSIS END")
print("========================================")

import subprocess
import requests


OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "qwen2.5-coder:3b"

DOCKERFILE_PATH = "/home/ubuntu/devboard/frontend/Dockerfile"
IMAGE_NAME = "devboard-fe:full"


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip()

    except Exception as e:
        return f"Command failed: {e}"


def limit_output(text, maximum=4000):
    if len(text) > maximum:
        return text[:maximum] + "\n...[TRUNCATED]..."
    return text


print("[1] Reading Dockerfile...", flush=True)

try:
    with open(DOCKERFILE_PATH, "r") as file:
        dockerfile = file.read()
except Exception as e:
    dockerfile = f"Unable to read Dockerfile: {e}"


print("[2] Inspecting Docker image...", flush=True)

image_info = run_command(
    f"docker image inspect {IMAGE_NAME}"
)

image_info = limit_output(image_info)


print("[3] Inspecting image layers...", flush=True)

image_history = run_command(
    f"docker history {IMAGE_NAME}"
)

image_history = limit_output(image_history)


print("[4] Finding Docker containers...", flush=True)

containers = run_command(
    "docker ps -a --format "
    "'ID={{.ID}} IMAGE={{.Image}} STATUS={{.Status}} "
    "PORTS={{.Ports}} NAME={{.Names}}'"
)

containers = limit_output(containers)


print("[5] Checking container security...", flush=True)

container_ids = run_command(
    "docker ps -aq"
).split()

container_security = []

for container_id in container_ids:

    info = run_command(
        "docker inspect --format "
        "'Name={{.Name}} "
        "User={{.Config.User}} "
        "Privileged={{.HostConfig.Privileged}} "
        "NetworkMode={{.HostConfig.NetworkMode}} "
        "ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} "
        "PidMode={{.HostConfig.PidMode}} "
        "IpcMode={{.HostConfig.IpcMode}}' "
        + container_id
    )

    container_security.append(info)


container_security = "\n".join(container_security)
container_security = limit_output(container_security)


print("[6] Preparing AI analysis...", flush=True)

prompt = f"""
You are DockerGuard AI.

Analyze this Docker project for security.

IMPORTANT RULES:

1. Do NOT invent CVEs.
2. Do NOT call normal Docker commands vulnerabilities.
3. Do NOT call a package vulnerable without evidence.
4. Separate confirmed security issues from recommendations.
5. Keep the answer concise.

DOCKERFILE:
{dockerfile}

DOCKER IMAGE:
{image_info}

IMAGE HISTORY:
{image_history}

CONTAINERS:
{containers}

CONTAINER SECURITY:
{container_security}

Analyze:

1. Dockerfile security
2. Docker image configuration
3. Container security
4. Image optimization

For each finding use:

SEVERITY:
FINDING:
EVIDENCE:
EXPLANATION:
RECOMMENDATION:

Severity must be:

CRITICAL
HIGH
MEDIUM
LOW
INFO

If there is no confirmed vulnerability, say:

No confirmed vulnerability found.

You may still provide recommendations, but clearly
label them as recommendations.
"""


print("[7] Sending information to Ollama...", flush=True)

try:

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 250
            }
        },
        timeout=180
    )

    response.raise_for_status()

except requests.exceptions.Timeout:

    print()
    print("ERROR: Ollama took too long to respond.")
    print("Check Ollama/model performance.")
    exit(1)


result = response.json()

print()
print("========================================")
print("          DOCKERGUARD AI")
print("========================================")
print()

print(result["response"])

print()
print("========================================")
print("             ANALYSIS END")
print("========================================")


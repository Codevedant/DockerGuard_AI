import subprocess


def run_command(command):
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return f"ERROR: {result.stderr.strip()}"

    return result.stdout.strip()


def list_docker_images():
    """List all Docker images on the machine."""

    return run_command(
        'docker images --format '
        '"{{.Repository}}:{{.Tag}} | {{.ID}} | {{.Size}} | {{.CreatedSince}}"'
    )


def inspect_docker_image(image):
    """Inspect a Docker image."""

    return run_command(
        f'docker image inspect {image}'
    )


def docker_image_history(image):
    """Show Docker image layers/history."""

    return run_command(
        f'docker history {image}'
    )


def list_containers():
    """List Docker containers."""

    return run_command(
        'docker ps -a'
    )


def inspect_container(container):
    """Inspect a Docker container."""

    return run_command(
        f'docker inspect {container}'
    )

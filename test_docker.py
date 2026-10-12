import subprocess


def run_command(command):
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )

    return result.stdout


print("=== ALL DOCKER CONTAINERS ===")

containers = run_command("docker ps -a")

print(containers)

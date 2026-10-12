from langchain_ollama import ChatOllama
from langchain.agents import create_agent

from docker_tools import (
    list_docker_images,
    inspect_docker_image,
    docker_image_history,
    list_containers,
    inspect_container,
)

from trivy_tools import scan_docker_image


# ========================================
# Ollama model
# ========================================

llm = ChatOllama(
    model="qwen3:1.7b",
    temperature=0,
)


# ========================================
# DockerGuard AI rules
# ========================================

SYSTEM_PROMPT = """
You are DockerGuard AI, a Docker security and optimization assistant.

IMPORTANT SECURITY RULES:

1. Trivy is the authoritative source for Docker image vulnerabilities.
2. Never invent CVE IDs.
3. Never claim a vulnerability exists unless Trivy returned it.
4. Never change the severity reported by Trivy.
5. Never describe a normal Docker command or Dockerfile instruction as a CVE.
6. When the user asks for vulnerabilities, use the scan_docker_image tool.
7. Base vulnerability findings only on actual tool output.
8. If Trivy provides a fixed version, recommend upgrading to that version when appropriate.
9. If Trivy provides no fixed version, clearly state that no fixed version was reported.
10. Clearly distinguish confirmed vulnerabilities from general recommendations.

For every confirmed vulnerability, report:

- CVE ID
- Severity
- Package
- Installed version
- Fixed version
- Trivy evidence/title
- Explanation
- Recommended remediation

Do not fabricate technical details.

General Docker hardening recommendations must be clearly labeled as recommendations,
not as confirmed vulnerabilities.

Never modify the original Dockerfile automatically.
"""


# ========================================
# Tools
# ========================================

tools = [
    list_docker_images,
    inspect_docker_image,
    docker_image_history,
    list_containers,
    inspect_container,
    scan_docker_image,
]


# ========================================
# Agent
# ========================================

agent = create_agent(
    model=llm,
    tools=tools,
    system_prompt=SYSTEM_PROMPT,
)


# ========================================
# Interface
# ========================================

print()
print("========================================")
print("          DockerGuard AI")
print("========================================")
print("Model  : qwen3:1.7b")
print("Docker : ENABLED")
print("Trivy  : ENABLED")
print()
print("Examples:")
print("  Show me my Docker images")
print("  Show me my containers")
print("  Inspect devboard-fe:full")
print("  Show layers of devboard-fe:full")
print("  Scan devboard-fe:full for vulnerabilities")
print("  exit")
print("========================================")
print()


while True:

    try:
        user_input = input("You: ").strip()

    except (KeyboardInterrupt, EOFError):
        print("\nExiting DockerGuard AI...")
        break

    if not user_input:
        continue

    if user_input.lower() in ["exit", "quit"]:
        print("Exiting DockerGuard AI...")
        break

    print("\nDockerGuard AI is thinking...\n")

    try:

        result = agent.invoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": user_input,
                    }
                ]
            }
        )

        messages = result.get("messages", [])

        if messages:

            final_message = messages[-1]

            if hasattr(final_message, "content"):
                print(final_message.content)
            else:
                print(final_message)

        else:
            print("No response received.")

    except Exception as e:

        print("ERROR:")
        print(e)

    print()

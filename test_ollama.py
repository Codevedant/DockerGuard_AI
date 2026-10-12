import requests

dockerfile = open(
    "/home/ubuntu/devboard/frontend/Dockerfile"
).read()

prompt = f"""
Analyze this Dockerfile for security problems.

Dockerfile:

{dockerfile}

Give me:

1. Security problems
2. Severity
3. Explanation
4. Recommended fix

Do not invent CVEs.
"""

response = requests.post(
    "http://127.0.0.1:11434/api/generate",
    json={
        "model": "qwen3:1.7b",
        "prompt": prompt,
        "stream": False
    }
)

print(response.json()["response"])

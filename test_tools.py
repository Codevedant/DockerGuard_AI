from langchain_ollama import ChatOllama
from docker_tools import list_docker_images

llm = ChatOllama(
    model="qwen3:1.7b",
    temperature=0,
)

llm_with_tools = llm.bind_tools([list_docker_images])

# Ask the model what tool it wants to use
response = llm_with_tools.invoke(
    "Show me my Docker images. Use the Docker tool to get the actual list."
)

print("\n========== MODEL TOOL CALL ==========")
print(response.tool_calls)

# Execute the tool
if response.tool_calls:
    tool_call = response.tool_calls[0]

    print("\n========== EXECUTING TOOL ==========")

    result = list_docker_images()

    print(result)

else:
    print("\nNo tool call generated.")

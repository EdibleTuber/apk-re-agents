from pathlib import Path
from typing import TypeVar

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def call_ollama(
    prompt: str,
    output_schema: type[T],
    ollama_host: str = "http://localhost:11434",
    model: str = "qwen2.5-coder:7b",
    system_prompt: str | None = None,
) -> T:
    """Call Ollama and return a validated Pydantic model.

    Args:
        prompt: The user prompt to send.
        output_schema: Pydantic model class to validate the response against.
        ollama_host: Ollama server URL.
        model: Model name to use.
        system_prompt: Optional system prompt.
    """
    import ollama

    client = ollama.Client(host=ollama_host)

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    response = client.chat(
        model=model,
        messages=messages,
        format=output_schema.model_json_schema(),
    )

    return output_schema.model_validate_json(response["message"]["content"])


def create_agent_server(name: str, host: str = "0.0.0.0", port: int = 8080) -> FastMCP:
    server = FastMCP(name, host=host, port=port)

    @server.tool()
    def read_file(file_path: str, start_line: int = 0, max_lines: int = 200) -> str:
        """Read a file from the shared volume.

        Args:
            file_path: Path to the file (relative to /work or absolute).
            start_line: Line number to start reading from (0-indexed).
            max_lines: Maximum number of lines to return.
        """
        path = Path(file_path)
        if not path.is_absolute():
            path = Path("/work") / path
        if not path.exists():
            return f"Error: file not found: {path}"
        lines = path.read_text().splitlines()
        selected = lines[start_line : start_line + max_lines]
        return "\n".join(selected)

    return server

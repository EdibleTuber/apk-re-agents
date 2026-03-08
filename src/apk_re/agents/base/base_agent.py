from pathlib import Path

from mcp.server.fastmcp import FastMCP


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

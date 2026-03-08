import subprocess
from pathlib import Path

from apk_re.agents.base.base_agent import create_agent_server


def create_unpacker_server():
    server = create_agent_server("unpacker")

    @server.tool()
    def run_jadx(apk_path: str, output_dir: str = "/work/decompiled/jadx") -> str:
        """Decompile an APK using jadx.

        Args:
            apk_path: Path to the APK file.
            output_dir: Directory to write decompiled Java source.
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                ["jadx", "--deobf", "-d", output_dir, apk_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                return f"jadx error: {result.stderr}"
            return f"Decompiled to {output_dir}"
        except FileNotFoundError:
            return "Error: jadx not found in PATH"

    @server.tool()
    def run_apktool(apk_path: str, output_dir: str = "/work/decompiled/apktool") -> str:
        """Decode an APK using apktool (resources + manifest).

        Args:
            apk_path: Path to the APK file.
            output_dir: Directory to write decoded resources.
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                ["apktool", "d", "-f", "-o", output_dir, apk_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                return f"apktool error: {result.stderr}"
            return f"Decoded to {output_dir}"
        except FileNotFoundError:
            return "Error: apktool not found in PATH"

    return server


if __name__ == "__main__":
    server = create_unpacker_server()
    server.run(transport="sse")

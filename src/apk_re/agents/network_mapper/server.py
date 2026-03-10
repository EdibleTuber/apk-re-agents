import os
import re
from pathlib import Path

from pydantic import BaseModel, Field

from apk_re.agents.base.base_agent import create_agent_server, call_ollama
from apk_re.schemas import NetworkFinding

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.environ.get("MODEL_NAME", "qwen2.5-coder:7b")

SYSTEM_PROMPT = """You are an Android security analyst specializing in network behavior analysis.
Given Java source code from a decompiled Android app, identify all network-related behavior:

IMPORTANT field definitions:
- "endpoint": Must be a URL, hostname, IP address, or URL pattern. Examples: "https://api.example.com", "*.example.com", "10.0.0.1:8080". If the code handles network traffic but you cannot identify a specific endpoint, use "unknown".
- "source_class": The Java class where the network behavior was found. This is where the CLASS NAME goes.

Do NOT put class names or method names in the "endpoint" field.

For each network endpoint or connection found:
- Extract the endpoint URL or pattern
- Identify the protocol (http, https, wss, ws, tcp, udp)
- Note the source class where it was found
- Check if certificate pinning is implemented (CertificatePinner, TrustManager, X509TrustManager)
- Add relevant notes about the network behavior (e.g., "Uses OkHttp interceptor", "Custom TrustManager disables cert validation")

Focus on security-relevant findings:
- Hardcoded API endpoints
- Certificate pinning implementations (or lack thereof)
- Custom TrustManagers that may disable SSL validation
- WebSocket connections
- Raw socket usage"""

NETWORK_KEYWORDS = re.compile(
    r'(?:OkHttp|Retrofit|HttpURLConnection|HttpClient|WebSocket|'
    r'SSLContext|TrustManager|CertificatePinner|X509|'
    r'\.openConnection|\.getInputStream|Volley|'
    r'https?://|wss?://|Socket\(|ServerSocket|'
    r'NetworkSecurityConfig|cleartext)',
    re.IGNORECASE
)

MAX_FILES = 20
MAX_FILE_SIZE = 500 * 1024  # 500KB
MAX_CHARS_PER_FILE = 8000

LIBRARY_PATH_SEGMENTS = (
    "/io/netty/", "/okio/", "/okhttp3/", "/retrofit2/",
    "/dagger/", "/hilt_aggregated_deps/", "/androidx/",
    "/com/google/", "/com/android/", "/kotlin/", "/kotlinx/",
    "/org/apache/", "/io/reactivex/", "/com/squareup/",
    "/com/facebook/", "/com/crashlytics/", "/net/jodah/",
    "/com/braze/", "/com/airbnb/", "/exoplayer2/",
)


class NetworkAnalysisResult(BaseModel):
    findings: list[NetworkFinding] = Field(default_factory=list)


def _find_relevant_files(source_dir: Path) -> list[Path]:
    """Pre-filter .java files for network-related keywords."""
    relevant: list[tuple[int, Path]] = []
    for java_file in source_dir.rglob("*.java"):
        file_str = str(java_file)
        if any(seg in file_str for seg in LIBRARY_PATH_SEGMENTS):
            continue
        if java_file.stat().st_size > MAX_FILE_SIZE:
            continue
        try:
            content = java_file.read_text(errors="ignore")
        except OSError:
            continue
        matches = NETWORK_KEYWORDS.findall(content)
        if matches:
            relevant.append((len(matches), java_file))

    # Sort by number of matches descending, take top N
    relevant.sort(key=lambda x: x[0], reverse=True)
    return [path for _, path in relevant[:MAX_FILES]]


def create_network_mapper_server():
    server = create_agent_server("network_mapper")

    @server.tool()
    def map_network(source_dir: str) -> str:
        """Analyze decompiled Java source files for network-related behavior.

        Args:
            source_dir: Path to the decompiled source directory (e.g., /work/decompiled/jadx).
        """
        path = Path(source_dir)
        if not path.is_absolute():
            path = Path("/work") / path
        if not path.exists():
            return f"Error: directory not found: {path}"

        relevant_files = _find_relevant_files(path)
        if not relevant_files:
            return NetworkAnalysisResult(findings=[]).model_dump_json(indent=2)

        # Build prompt with file contents
        file_sections: list[str] = []
        for f in relevant_files:
            try:
                content = f.read_text(errors="ignore")
            except OSError:
                continue
            if len(content) > MAX_CHARS_PER_FILE:
                content = content[:MAX_CHARS_PER_FILE] + "\n... (truncated)"
            file_sections.append(
                f"--- {f.relative_to(path)} ---\n{content}"
            )

        prompt = (
            "Analyze the following Java source files for network-related behavior "
            "and extract all findings:\n\n"
            + "\n\n".join(file_sections)
        )

        result = call_ollama(
            prompt=prompt,
            output_schema=NetworkAnalysisResult,
            ollama_host=OLLAMA_HOST,
            model=MODEL_NAME,
            system_prompt=SYSTEM_PROMPT,
        )

        # Deduplicate findings by (endpoint, source_class)
        seen: set[tuple[str, str]] = set()
        deduped: list[NetworkFinding] = []
        for finding in result.findings:
            key = (finding.endpoint, finding.source_class)
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        result = NetworkAnalysisResult(findings=deduped)

        return result.model_dump_json(indent=2)

    return server


if __name__ == "__main__":
    server = create_network_mapper_server()
    server.run(transport="sse")

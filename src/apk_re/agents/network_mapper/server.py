import logging
import os
import re
from pathlib import Path

from pydantic import BaseModel, Field

from apk_re.agents.base.base_agent import create_agent_server, call_ollama, is_library_path
from apk_re.schemas import NetworkFinding

logger = logging.getLogger(__name__)

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

HARDCODED_URL = re.compile(r'"(https?://[^"]+)"')

_FP_URL_PREFIXES = (
    "http://schemas.android.com",
    "http://www.w3.org",
    "http://ns.adobe.com",
    "http://xmlpull.org",
    "https://www.googleapis.com/auth/",
    "http://schemas.xmlsoap.org",
    "http://www.apache.org",
    "https://developer.android.com",
)


def _is_fp_url(url: str) -> bool:
    return any(url.startswith(p) for p in _FP_URL_PREFIXES)

MAX_FILES = 20
MAX_FILE_SIZE = 500 * 1024  # 500KB
MAX_CHARS_PER_FILE = 8000



ENDPOINT_PATTERN = re.compile(
    r'^('
    r'https?://|wss?://|tcp://|udp://'  # URL schemes
    r'|\*\.'                              # wildcard hostnames
    r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # IP addresses
    r'|[a-z0-9][-a-z0-9]*\.[a-z]{2,}'   # hostnames (foo.example.com)
    r'|unknown'                           # explicit unknown
    r'|localhost'                          # localhost
    r')',
    re.IGNORECASE
)


class NetworkAnalysisResult(BaseModel):
    findings: list[NetworkFinding] = Field(default_factory=list)


def _find_relevant_files(source_dir: Path) -> list[Path]:
    """Pre-filter .java files for network-related keywords."""
    relevant: list[tuple[int, Path]] = []
    for java_file in source_dir.rglob("*.java"):
        file_str = str(java_file)
        if is_library_path(file_str):
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


def _extract_url_literals(files: list[Path], source_dir: Path) -> list[NetworkFinding]:
    """Extract hardcoded URLs from files without LLM."""
    findings = []
    for f in files:
        try:
            content = f.read_text(errors="ignore")
        except OSError:
            continue
        try:
            rel = str(f.relative_to(source_dir))
        except ValueError:
            rel = str(f)
        source_class = rel.replace("/", ".").replace(".java", "")
        if source_class.startswith("sources."):
            source_class = source_class[len("sources."):]
        for match in HARDCODED_URL.finditer(content):
            url = match.group(1)
            if _is_fp_url(url):
                continue
            findings.append(NetworkFinding(
                endpoint=url,
                protocol="https" if url.startswith("https") else "http",
                source_class=source_class,
                cert_pinning=False,
                notes="Hardcoded URL literal",
            ))
    return findings


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

        # Phase 1: Regex extraction of hardcoded URL literals
        all_findings = _extract_url_literals(relevant_files, path)

        # Phase 2: Per-file LLM calls
        for f in relevant_files:
            try:
                content = f.read_text(errors="ignore")
            except OSError:
                continue
            if len(content) > MAX_CHARS_PER_FILE:
                content = content[:MAX_CHARS_PER_FILE] + "\n... (truncated)"

            try:
                rel = str(f.relative_to(path))
            except ValueError:
                rel = str(f)

            prompt = (
                f"Analyze this single Java file for network behavior:\n\n"
                f"--- {rel} ---\n{content}"
            )

            # Compute source_class from file path for consistency with regex findings
            source_class = rel.replace("/", ".").replace(".java", "")
            if source_class.startswith("sources."):
                source_class = source_class[len("sources."):]

            try:
                result = call_ollama(
                    prompt=prompt,
                    output_schema=NetworkAnalysisResult,
                    ollama_host=OLLAMA_HOST,
                    model=MODEL_NAME,
                    system_prompt=SYSTEM_PROMPT,
                )
                # Override source_class so it matches regex findings for dedup
                for finding in result.findings:
                    finding.source_class = source_class
                all_findings.extend(result.findings)
            except Exception:
                logger.warning("LLM call failed for file %s", rel, exc_info=True)

        # Post-process: validate endpoint field
        for finding in all_findings:
            if not ENDPOINT_PATTERN.match(finding.endpoint):
                finding.endpoint = "unknown"

        # Deduplicate by (endpoint, source_class)
        seen: set[tuple[str, str]] = set()
        deduped: list[NetworkFinding] = []
        for finding in all_findings:
            key = (finding.endpoint, finding.source_class)
            if key not in seen:
                seen.add(key)
                deduped.append(finding)

        return NetworkAnalysisResult(findings=deduped).model_dump_json(indent=2)

    return server


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    server = create_network_mapper_server()
    server.run(transport="sse")

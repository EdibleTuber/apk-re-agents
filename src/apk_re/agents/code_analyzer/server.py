import os
import re
from pathlib import Path

from pydantic import BaseModel, Field

from apk_re.agents.base.base_agent import create_agent_server, call_ollama
from apk_re.schemas import CodeAnalysisSummary

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.environ.get("MODEL_NAME", "qwen2.5-coder:7b")

TRIAGE_PROMPT = """You are an Android security analyst performing triage on decompiled Java classes.
For each class, assess its security relevance on a scale of 0.0 to 1.0:
- 0.0-0.3: Benign (UI layouts, adapters, generated code)
- 0.3-0.6: Moderate (data models, utilities with some security surface)
- 0.6-0.8: Significant (network clients, auth handlers, data storage)
- 0.8-1.0: Critical (crypto implementations, certificate handling, secret management)

Scores MUST be decimal values between 0.0 and 1.0. Do NOT use percentages or integers. Examples: 0.3, 0.65, 0.9 — NOT 30, 65, 90.

For each class, provide:
- class_name: the fully qualified class name
- relevance_score: your assessment
- summary: one sentence describing what the class does from a security perspective
- flags: assign one or more flags from this list:
  - "network" — uses HTTP clients, sockets, URL connections, WebSocket, Retrofit, OkHttp
  - "crypto" — uses Cipher, MessageDigest, KeyStore, SecretKey, hashing, encryption
  - "storage" — uses SharedPreferences, SQLite, Room, file I/O, ContentProvider
  - "auth" — handles login, tokens, passwords, sessions, OAuth, credentials
  - "webview" — uses WebView, JavascriptInterface, WebViewClient
  - "ipc" — uses Intent, BroadcastReceiver, ContentProvider, AIDL, Binder

Every class MUST have at least one flag. Choose the most relevant category."""

ANALYSIS_PROMPT = """You are an Android security analyst performing deep analysis on a Java class.
Analyze the code thoroughly for security implications:
- Identify vulnerabilities (insecure crypto, hardcoded secrets, SQL injection, etc.)
- Note security-relevant patterns (cert pinning, encryption, auth flows)
- Flag any anti-patterns or risky behaviors
- Assess the overall security posture of this class

Provide a detailed summary and relevant flags."""

SECURITY_KEYWORDS = re.compile(
    r'(?:crypto|cipher|key|secret|password|token|auth|ssl|tls|certificate|'
    r'network|socket|http|database|sqlite|sharedpreferences|file|storage|'
    r'permission|intent|broadcast|content.?provider|webview|javascript)',
    re.IGNORECASE,
)

MAX_FILES = 30
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


class TriageResult(BaseModel):
    classes: list[CodeAnalysisSummary] = Field(default_factory=list)


def _find_relevant_files(source_dir: Path) -> list[Path]:
    """Pre-filter .java files for security-relevant keywords."""
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
        matches = SECURITY_KEYWORDS.findall(content)
        if matches:
            relevant.append((len(matches), java_file))

    # Sort by number of matches descending, take top N
    relevant.sort(key=lambda x: x[0], reverse=True)
    return [path for _, path in relevant[:MAX_FILES]]


def create_code_analyzer_server():
    server = create_agent_server("code_analyzer")

    @server.tool()
    def triage_classes(source_dir: str) -> str:
        """Triage decompiled Java classes by security relevance.

        Pre-filters files using regex for security-relevant keywords, then
        sends matching files to the LLM in batches for scoring.

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
            return TriageResult(classes=[]).model_dump_json(indent=2)

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
            "Triage the following decompiled Java classes for security relevance. "
            "Score each class and provide a summary and flags:\n\n"
            + "\n\n".join(file_sections)
        )

        result = call_ollama(
            prompt=prompt,
            output_schema=TriageResult,
            ollama_host=OLLAMA_HOST,
            model=MODEL_NAME,
            system_prompt=TRIAGE_PROMPT,
        )

        return result.model_dump_json(indent=2)

    @server.tool()
    def analyze_class(file_path: str) -> str:
        """Perform deep security analysis on a single Java class file.

        Args:
            file_path: Path to the Java file to analyze.
        """
        path = Path(file_path)
        if not path.is_absolute():
            path = Path("/work") / path
        if not path.exists():
            return f"Error: file not found: {path}"

        content = path.read_text(errors="ignore")

        prompt = (
            f"Perform a deep security analysis on this Java class:\n\n"
            f"--- {path.name} ---\n{content}"
        )

        result = call_ollama(
            prompt=prompt,
            output_schema=CodeAnalysisSummary,
            ollama_host=OLLAMA_HOST,
            model=MODEL_NAME,
            system_prompt=ANALYSIS_PROMPT,
        )

        return result.model_dump_json(indent=2)

    return server


if __name__ == "__main__":
    server = create_code_analyzer_server()
    server.run(transport="sse")

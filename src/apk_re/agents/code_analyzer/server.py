import logging
import os
import re
from pathlib import Path

import anyio

from pydantic import BaseModel, Field

from apk_re.agents.base.base_agent import create_agent_server, call_ollama, is_library_path
from apk_re.schemas import CodeAnalysisSummary

logger = logging.getLogger(__name__)

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

MAX_FILES = 75
MAX_FILE_SIZE = 500 * 1024  # 500KB
MAX_CHARS_PER_FILE = 8000
TRIAGE_BATCH_SIZE = 5



class TriageResult(BaseModel):
    classes: list[CodeAnalysisSummary] = Field(default_factory=list)


def _find_relevant_files(source_dir: Path) -> list[Path]:
    """Pre-filter .java files for security-relevant keywords."""
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
        matches = SECURITY_KEYWORDS.findall(content)
        if matches:
            relevant.append((len(matches), java_file))

    # Sort by number of matches descending, take top N
    relevant.sort(key=lambda x: x[0], reverse=True)
    return [path for _, path in relevant[:MAX_FILES]]


def _triage_classes_impl(source_dir: str) -> str:
    path = Path(source_dir)
    if not path.is_absolute():
        path = Path("/work") / path
    if not path.exists():
        return f"Error: directory not found: {path}"

    relevant_files = _find_relevant_files(path)
    if not relevant_files:
        return TriageResult(classes=[]).model_dump_json(indent=2)

    all_classes: list[CodeAnalysisSummary] = []
    for i in range(0, len(relevant_files), TRIAGE_BATCH_SIZE):
        batch = relevant_files[i:i + TRIAGE_BATCH_SIZE]
        file_sections: list[str] = []
        for f in batch:
            try:
                content = f.read_text(errors="ignore")
            except OSError:
                continue
            if len(content) > MAX_CHARS_PER_FILE:
                content = content[:MAX_CHARS_PER_FILE] + "\n... (truncated)"
            try:
                file_sections.append(f"--- {f.relative_to(path)} ---\n{content}")
            except ValueError:
                file_sections.append(f"--- {f.name} ---\n{content}")

        if not file_sections:
            continue

        prompt = (
            "Triage the following decompiled Java classes for security relevance. "
            "Score each class and provide a summary and flags:\n\n"
            + "\n\n".join(file_sections)
        )

        try:
            result = call_ollama(
                prompt=prompt,
                output_schema=TriageResult,
                ollama_host=OLLAMA_HOST,
                model=MODEL_NAME,
                system_prompt=TRIAGE_PROMPT,
            )
            all_classes.extend(result.classes)
        except Exception:
            logger.warning(
                "LLM triage batch failed (files %d-%d)",
                i, i + len(batch) - 1,
                exc_info=True,
            )

    sent_classes = set()
    for f in relevant_files:
        try:
            rel = str(f.relative_to(path))
        except ValueError:
            continue
        class_name = rel.replace("/", ".").replace(".java", "")
        if class_name.startswith("sources."):
            class_name = class_name[len("sources."):]
        sent_classes.add(class_name)

    validated = []
    for cls in all_classes:
        if cls.class_name not in sent_classes:
            continue
        if cls.relevance_score > 1.0:
            cls.relevance_score = min(cls.relevance_score / 100.0, 1.0)
        if not cls.flags:
            matching_files = [f for f in relevant_files if cls.class_name.replace(".", "/") in str(f)]
            if matching_files:
                try:
                    content = matching_files[0].read_text(errors="ignore")
                except OSError:
                    content = ""
                if any(kw in content for kw in ("Http", "Socket", "Url", "Retrofit", "OkHttp", "Volley")):
                    cls.flags = ["network"]
                elif any(kw in content for kw in ("Cipher", "KeyStore", "MessageDigest", "SecretKey")):
                    cls.flags = ["crypto"]
                elif any(kw in content for kw in ("SharedPreferences", "SQLite", "ContentProvider", "Room")):
                    cls.flags = ["storage"]
                elif any(kw in content for kw in ("login", "token", "password", "auth", "credential", "session")):
                    cls.flags = ["auth"]
                else:
                    cls.flags = ["other"]
            else:
                cls.flags = ["other"]
        validated.append(cls)

    return TriageResult(classes=validated).model_dump_json(indent=2)


def _analyze_class_impl(file_path: str) -> str:
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


def create_code_analyzer_server():
    server = create_agent_server("code_analyzer")

    @server.tool()
    async def triage_classes(source_dir: str) -> str:
        """Triage decompiled Java classes by security relevance.

        Pre-filters files using regex for security-relevant keywords, then
        sends matching files to the LLM in batches for scoring.

        Args:
            source_dir: Path to the decompiled source directory (e.g., /work/decompiled/jadx).
        """
        return await anyio.to_thread.run_sync(_triage_classes_impl, source_dir)

    @server.tool()
    async def analyze_class(file_path: str) -> str:
        """Perform deep security analysis on a single Java class file.

        Args:
            file_path: Path to the Java file to analyze.
        """
        return await anyio.to_thread.run_sync(_analyze_class_impl, file_path)

    return server


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    server = create_code_analyzer_server()
    server.run(transport="sse")

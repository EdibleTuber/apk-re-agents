import json
import math
import os
import re
from collections import Counter
from pathlib import Path

import anyio

from apk_re.agents.base.base_agent import create_agent_server, is_library_path
from apk_re.schemas import StringFinding

MAX_FINDINGS = 500
MAX_FILE_SIZE = 1_000_000  # 1 MB

# --- Regex patterns ---

URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')

API_KEY_PREFIXES = re.compile(
    r'(?:AIza[0-9A-Za-z_-]{35})'       # Google API key
    r'|(?:sk-[0-9A-Za-z]{32,})'         # OpenAI / Stripe secret key
    r'|(?:AKIA[0-9A-Z]{16})'            # AWS access key
    r'|(?:ghp_[0-9A-Za-z]{36})'         # GitHub personal access token
    r'|(?:glpat-[0-9A-Za-z_-]{20,})'    # GitLab personal access token
)

# Generic long hex/alphanumeric strings that look like keys (32+ chars, mixed case/digits)
GENERIC_KEY_PATTERN = re.compile(
    r'(?<![A-Za-z0-9_./])([A-Za-z0-9_-]{32,})(?![A-Za-z0-9_./])'
)

JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?')

BASE64_PATTERN = re.compile(
    r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])'
)

# --- False-positive filters ---

FALSE_POSITIVE_PREFIXES = (
    "http://schemas.android.com",
    "http://www.w3.org",
    "http://ns.adobe.com",
    "http://xmlpull.org",
    "https://www.googleapis.com/auth/",
    "http://schemas.xmlsoap.org",
    "http://www.apache.org",
    "https://developer.android.com",
)

FALSE_POSITIVE_URL_PATTERNS = re.compile(
    r'^https?://(schemas\.android\.com|www\.w3\.org|ns\.adobe\.com|xmlpull\.org'
    r'|www\.apache\.org|developer\.android\.com|schemas\.xmlsoap\.org)'
)

PACKAGE_NAME_PATTERN = re.compile(
    r'^com\.(android|google|sun|oracle|java|javax)\.[A-Za-z0-9_.]+$'
)

# Common Java/Android identifiers that match generic key patterns but aren't secrets
COMMON_JAVA_IDENTIFIERS = {
    "serialVersionUID",
    "CREATOR",
    "onActivityResult",
    "onRequestPermissionsResult",
    "getApplicationContext",
}

# Java/Android class name suffixes that indicate identifiers, not secrets
JAVA_SUFFIXES = (
    "Exception", "Error", "Handler", "Listener", "Callback", "Factory",
    "Provider", "Manager", "Service", "Module", "Component", "Activity",
    "Fragment", "Adapter", "Builder", "Helper", "Wrapper", "Delegate",
    "Interceptor", "Parameter", "Validator", "Processor", "Marker",
    "EntryPoint", "ViewModel", "Repository", "Receiver", "Connection",
    "Serializer",
)

# JVM internal type descriptor prefixes
JVM_DESCRIPTOR_PREFIXES = (
    "Ljava/", "Lokio/", "Landroid/", "Lkotlin/", "Lcom/",
)

CAMEL_CASE_RE = re.compile(r'^[a-z][a-zA-Z0-9]*$')
PASCAL_CASE_RE = re.compile(r'^[A-Z][a-zA-Z]*[a-z][a-zA-Z]*$')

# Kotlin name-mangled method patterns
# e.g., m5293surfaceColorAtElevationcq6XJ1M
KOTLIN_MANGLED_PREFIX = re.compile(r'^m\d{3,}[a-zA-Z]')
# e.g., createGuidelineFromAbsoluteRight-0680j_4
KOTLIN_HASH_SUFFIX = re.compile(r'^[a-zA-Z][a-zA-Z0-9]*-[A-Za-z0-9_]{4,10}$')
# Android resource styleable getters: getSTYLEABLE_VECTOR_DRAWABLE_*
STYLEABLE_PATTERN = re.compile(r'^(get|set)STYLEABLE_')
# Java class path strings: org/slf4j/impl/StaticLoggerBinder
JAVA_CLASS_PATH = re.compile(r'^[a-z][a-z0-9]*(/[a-zA-Z][a-zA-Z0-9]*)+$')
# Underscore resource/config identifiers: config_showMenuShortcutsWhenKeyboardPresent
UNDERSCORE_IDENTIFIER = re.compile(r'^[a-z][a-z0-9]*_[a-zA-Z0-9_]+$')
# Build config / Gradle module strings: src_kotlin_main_com_ergatta_device-build_cfg
BUILD_CONFIG_PATTERN = re.compile(r'^(src_|third_party_|layout/)')
# Data binding generated keys: viewModelStateRecommendationsDataOrNull...
DATA_BINDING_PATTERN = re.compile(r'^(viewModel|wrapUpModel|itemIs|boundView)[A-Z]')


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_false_positive_url(url: str) -> bool:
    return bool(FALSE_POSITIVE_URL_PATTERNS.match(url))


def _is_false_positive_string(value: str) -> bool:
    if PACKAGE_NAME_PATTERN.match(value):
        return True
    if value in COMMON_JAVA_IDENTIFIERS:
        return True
    # Skip strings that are all lowercase with underscores (likely variable/method names)
    if re.match(r'^[a-z][a-z0-9_]*$', value):
        return True
    # Skip strings that are all uppercase with underscores (likely constant names)
    if re.match(r'^[A-Z][A-Z0-9_]*$', value):
        return True
    # Skip camelCase identifiers (starts lowercase, has uppercase letters, pure letters)
    # Only filter if string is pure letters — real base64 contains digits
    if CAMEL_CASE_RE.match(value) and any(c.isupper() for c in value) and value.isalpha():
        return True
    # Skip PascalCase identifiers (starts uppercase, mixed case, no separators)
    if PASCAL_CASE_RE.match(value):
        return True
    # Skip strings ending with common Java class suffixes
    if any(value.endswith(suffix) for suffix in JAVA_SUFFIXES):
        return True
    # Skip JVM internal type descriptors (e.g. Ljava/lang/String;)
    if any(value.startswith(prefix) for prefix in JVM_DESCRIPTOR_PREFIXES):
        return True
    # Skip Kotlin name-mangled methods (m<digits><name> or name-<hash>)
    if KOTLIN_MANGLED_PREFIX.match(value):
        return True
    if KOTLIN_HASH_SUFFIX.match(value):
        return True
    # Skip Android STYLEABLE getter/setter names
    if STYLEABLE_PATTERN.match(value):
        return True
    # Skip Java class path strings (e.g., org/slf4j/impl/StaticLoggerBinder)
    if JAVA_CLASS_PATH.match(value):
        return True
    # Skip underscore-separated resource/config identifiers
    if UNDERSCORE_IDENTIFIER.match(value):
        return True
    # Skip build config / Gradle module strings and layout paths
    if BUILD_CONFIG_PATTERN.match(value):
        return True
    # Skip data binding generated keys
    if DATA_BINDING_PATTERN.match(value):
        return True
    return False


def _make_relative(path: Path) -> str:
    """Make a path relative to /work for readability."""
    try:
        return str(path.relative_to("/work"))
    except ValueError:
        return str(path)


def extract_strings_from_file(
    file_path: Path,
) -> list[StringFinding]:
    """Extract security-relevant strings from a single Java file."""
    findings: list[StringFinding] = []
    rel_path = _make_relative(file_path)

    try:
        content = file_path.read_text(errors="replace")
    except OSError:
        return findings

    for line_no, line in enumerate(content.splitlines(), start=1):
        # URLs
        for m in URL_PATTERN.finditer(line):
            url = m.group(0).rstrip(".,;)\"'")
            if _is_false_positive_url(url):
                continue
            findings.append(
                StringFinding(
                    value=url,
                    category="url",
                    source_file=rel_path,
                    line_number=line_no,
                    entropy=round(shannon_entropy(url), 2),
                )
            )

        # JWT tokens
        for m in JWT_PATTERN.finditer(line):
            findings.append(
                StringFinding(
                    value=m.group(0),
                    category="token",
                    source_file=rel_path,
                    line_number=line_no,
                    entropy=round(shannon_entropy(m.group(0)), 2),
                )
            )

        # API key prefixes
        for m in API_KEY_PREFIXES.finditer(line):
            findings.append(
                StringFinding(
                    value=m.group(0),
                    category="api_key",
                    source_file=rel_path,
                    line_number=line_no,
                    entropy=round(shannon_entropy(m.group(0)), 2),
                )
            )

        # Base64 encoded blobs
        for m in BASE64_PATTERN.finditer(line):
            val = m.group(1)
            if _is_false_positive_string(val):
                continue
            # Require at least one digit or base64 special char (+/=)
            # Pure-letter strings are identifiers, not encoded data
            if not re.search(r'[0-9+/=]', val):
                continue
            ent = shannon_entropy(val)
            if ent < 4.5:
                continue
            findings.append(
                StringFinding(
                    value=val,
                    category="encoded_blob",
                    source_file=rel_path,
                    line_number=line_no,
                    entropy=round(ent, 2),
                )
            )

        # Generic high-entropy keys (only from string literals)
        string_literals = re.findall(r'"([^"]{32,})"', line)
        for lit in string_literals:
            # Skip if already caught by other patterns
            if URL_PATTERN.match(lit) or JWT_PATTERN.match(lit) or API_KEY_PREFIXES.match(lit):
                continue
            if _is_false_positive_string(lit):
                continue
            ent = shannon_entropy(lit)
            if ent > 4.0 and re.match(r'^[A-Za-z0-9_+/=-]+$', lit):
                findings.append(
                    StringFinding(
                        value=lit,
                        category="api_key",
                        source_file=rel_path,
                        line_number=line_no,
                        entropy=round(ent, 2),
                    )
                )

    return findings


def create_string_extractor_server():
    server = create_agent_server("string_extractor")

    def _extract_strings_impl(source_dir: str) -> str:
        root = Path(source_dir)
        if not root.is_absolute():
            root = Path("/work") / root
        if not root.exists():
            return json.dumps({"error": f"Directory not found: {root}"})

        all_findings: list[StringFinding] = []
        seen_values: set[str] = set()

        for java_file in root.rglob("*.java"):
            if is_library_path(str(java_file)):
                continue
            if java_file.stat().st_size > MAX_FILE_SIZE:
                continue
            file_findings = extract_strings_from_file(java_file)
            for finding in file_findings:
                if finding.value in seen_values:
                    continue
                seen_values.add(finding.value)
                all_findings.append(finding)

        # Sort by entropy descending — highest-signal findings survive the trim.
        # Never break early: scan all files, trim at the end.
        all_findings.sort(key=lambda f: f.entropy or 0.0, reverse=True)
        all_findings = all_findings[:MAX_FINDINGS]

        return json.dumps([f.model_dump() for f in all_findings], indent=2)

    @server.tool()
    async def extract_strings(source_dir: str) -> str:
        """Scan decompiled Java source files for security-relevant strings.

        Finds API keys, URLs, tokens, and encoded blobs using regex patterns
        and Shannon entropy analysis.

        Args:
            source_dir: Path to decompiled source directory (e.g. /work/decompiled/jadx).
        """
        return await anyio.to_thread.run_sync(_extract_strings_impl, source_dir)

    return server


if __name__ == "__main__":
    server = create_string_extractor_server()
    server.run(transport="sse")

import logging
import os
import re
from pathlib import Path

import anyio

logger = logging.getLogger(__name__)

from pydantic import BaseModel, Field

from apk_re.agents.base.base_agent import create_agent_server, call_ollama, is_library_path
from apk_re.schemas import EndpointFinding

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.environ.get("MODEL_NAME", "qwen2.5-coder:7b")

MAX_FILE_SIZE = 500 * 1024  # 500KB
MAX_NON_RETROFIT_FILES = 15  # Cap Phase 4 to avoid unbounded LLM call chains

# --- Phase 1: Retrofit annotation regex ---
RETROFIT_ANNOTATION = re.compile(
    r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\s*\(\s*["\']([^"\']+)["\']\s*\)'
)

# --- Phase 2: Base URL discovery ---
BASE_URL_PATTERNS = re.compile(
    r'(?:baseUrl|BASE_URL|base_url|api_url|API_URL|server_url)\s*[=(]\s*["\']([^"\']+)["\']'
    r'|new\s+Retrofit\.Builder\(\)\s*\.baseUrl\s*\(\s*["\']?([^"\')\s]+)'
)
URL_LITERAL = re.compile(r'https?://[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}')

# --- Non-Retrofit fallback keywords ---
NON_RETROFIT_KEYWORDS = re.compile(
    r'(?:Request\.Builder|HttpURLConnection|\.newCall|Volley\.|'
    r'JsonObjectRequest|StringRequest|GraphQL)',
    re.IGNORECASE
)

# --- Post-filter for non-API URLs ---
NON_API_URL_PATTERNS = re.compile(
    r'(?:github\.com|gitlab\.com|bitbucket\.org|sources\.gett\.com'
    r'|stackoverflow\.com|developer\.android\.com|www\.w3\.org'
    r'|schemas\.android\.com|apache\.org|/commit/|/blob/|/tree/)'
)

# --- LLM enrichment prompt ---
ENRICHMENT_PROMPT = """You are an Android API analyst. Given a single Retrofit interface definition, extract the request and response field schemas for each endpoint.

For each endpoint method:
- method_name: the Java method name
- request_fields: parameter names and types from @Body, @Query, @Field, @Part annotations
- response_fields: field names and types from the return type (if visible)

Only extract what is explicitly visible in the code. Do NOT fabricate fields."""

# --- Fallback system prompt for non-Retrofit files ---
FALLBACK_SYSTEM_PROMPT = """You are an Android security analyst specializing in API endpoint extraction.
Given Java source code from a decompiled Android app, identify all runtime API endpoints.

For each endpoint found:
- Extract the URL or URL pattern (e.g., "/api/v1/users", "https://api.example.com/auth")
- Identify the HTTP method (GET, POST, PUT, DELETE, PATCH) if determinable
- Note the source class where it was defined
- Extract request fields/parameters (field name -> type) if visible
- Extract response fields (field name -> type) if visible from deserialization code

DO NOT extract:
- URLs from comments, license headers, or source code references
- Repository URLs (github.com, gitlab.com, bitbucket.org, sources.gett.com, etc.)
- Documentation or specification URLs

IMPORTANT: Only extract URLs that appear VERBATIM in the code. Do NOT fabricate, modify, or complete partial URLs."""

MAX_CHARS_PER_FILE = 8000


# --- Pydantic schemas for LLM enrichment ---

class EndpointSchema(BaseModel):
    method_name: str = ""
    request_fields: dict[str, str] = Field(default_factory=dict)
    response_fields: dict[str, str] = Field(default_factory=dict)


class FileEndpointSchemas(BaseModel):
    endpoints: list[EndpointSchema] = Field(default_factory=list)


class ApiAnalysisResult(BaseModel):
    endpoints: list[EndpointFinding] = Field(default_factory=list)
    base_urls: list[str] = Field(default_factory=list)


# --- Phase 1: Regex extraction ---

def _extract_retrofit_endpoints(source_dir: Path) -> dict[Path, list[tuple[str, str]]]:
    """Scan .java files that import retrofit2 and extract @GET/@POST etc. annotations.

    Returns a dict mapping file path -> list of (http_method, url_path) tuples.
    """
    results: dict[Path, list[tuple[str, str]]] = {}
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

        # Only process files that import retrofit2
        if "retrofit2" not in content:
            continue

        matches = RETROFIT_ANNOTATION.findall(content)
        if matches:
            results[java_file] = [(method, path) for method, path in matches]

    return results


# --- Phase 2: Base URL discovery ---

def _discover_base_urls(source_dir: Path) -> list[str]:
    """Find base URL configurations across the codebase."""
    base_urls: set[str] = set()
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

        for match in BASE_URL_PATTERNS.finditer(content):
            url = match.group(1) or match.group(2)
            if url and not NON_API_URL_PATTERNS.search(url):
                base_urls.add(url)

        # Also look for URL literals near baseUrl/Retrofit patterns
        if "baseUrl" in content or "BASE_URL" in content or "Retrofit" in content:
            for url_match in URL_LITERAL.finditer(content):
                url = url_match.group(0)
                if not NON_API_URL_PATTERNS.search(url):
                    base_urls.add(url)

    return sorted(base_urls)


# --- Phase 3: Per-file LLM enrichment ---

def _enrich_file_with_llm(
    file_path: Path,
    source_dir: Path,
    ollama_host: str,
    model: str,
) -> FileEndpointSchemas:
    """Send a single Retrofit interface file to the LLM for schema enrichment."""
    try:
        content = file_path.read_text(errors="ignore")
    except OSError:
        return FileEndpointSchemas()

    if len(content) > MAX_CHARS_PER_FILE:
        content = content[:MAX_CHARS_PER_FILE] + "\n... (truncated)"

    rel_path = file_path.relative_to(source_dir)
    prompt = f"--- {rel_path} ---\n{content}"

    try:
        result = call_ollama(
            prompt=prompt,
            output_schema=FileEndpointSchemas,
            ollama_host=ollama_host,
            model=model,
            system_prompt=ENRICHMENT_PROMPT,
        )
        return result
    except Exception as exc:
        logger.warning("LLM enrichment failed for %s: %s", file_path, exc)
        return FileEndpointSchemas()


# --- Phase 4: Combine results ---

def _build_source_class(file_path: Path, source_dir: Path) -> str:
    """Derive a source class name from the file path."""
    try:
        rel = file_path.relative_to(source_dir)
    except ValueError:
        return file_path.stem
    # Convert path like com/myapp/api/UserService.java -> com.myapp.api.UserService
    source_class = str(rel).replace("/", ".").replace(".java", "")
    # Strip JADX "sources/" directory prefix if present
    if source_class.startswith("sources."):
        source_class = source_class[len("sources."):]
    return source_class


# --- Fallback: non-Retrofit file discovery ---

def _find_non_retrofit_files(source_dir: Path, retrofit_files: set[Path]) -> list[Path]:
    """Find files using OkHttp/Volley/HttpURLConnection that aren't Retrofit interfaces.

    Returns up to MAX_NON_RETROFIT_FILES files, prioritised by keyword match density
    so the most API-heavy files are analysed first.
    """
    results: list[tuple[int, Path]] = []
    for java_file in source_dir.rglob("*.java"):
        if java_file in retrofit_files:
            continue
        file_str = str(java_file)
        if is_library_path(file_str):
            continue
        if java_file.stat().st_size > MAX_FILE_SIZE:
            continue
        try:
            content = java_file.read_text(errors="ignore")
        except OSError:
            continue

        matches = NON_RETROFIT_KEYWORDS.findall(content)
        if matches:
            results.append((len(matches), java_file))

    results.sort(key=lambda x: x[0], reverse=True)
    return [path for _, path in results[:MAX_NON_RETROFIT_FILES]]


def _process_non_retrofit_file(
    file_path: Path,
    source_dir: Path,
    ollama_host: str,
    model: str,
) -> list[EndpointFinding]:
    """Process a single non-Retrofit file with the LLM to extract endpoints."""
    try:
        content = file_path.read_text(errors="ignore")
    except OSError:
        return []

    if len(content) > MAX_CHARS_PER_FILE:
        content = content[:MAX_CHARS_PER_FILE] + "\n... (truncated)"

    try:
        rel_path = file_path.relative_to(source_dir)
    except ValueError:
        rel_path = file_path.name
    prompt = (
        f"Analyze this single Java source file for API endpoint definitions "
        f"and extract all endpoints:\n\n"
        f"--- {rel_path} ---\n{content}"
    )

    try:
        result = call_ollama(
            prompt=prompt,
            output_schema=ApiAnalysisResult,
            ollama_host=ollama_host,
            model=model,
            system_prompt=FALLBACK_SYSTEM_PROMPT,
        )
        # Post-filter non-API URLs
        return [
            ep for ep in result.endpoints
            if not NON_API_URL_PATTERNS.search(ep.url)
        ]
    except Exception as exc:
        logger.warning("LLM fallback analysis failed for %s: %s", file_path, exc)
        return []


def _extract_apis_impl(source_dir: str) -> str:
    path = Path(source_dir)
    if not path.is_absolute():
        path = Path("/work") / path
    if not path.exists():
        return f"Error: directory not found: {path}"

    all_endpoints: list[EndpointFinding] = []

    # Phase 1: Regex extraction of Retrofit annotations
    retrofit_files = _extract_retrofit_endpoints(path)
    logger.info("Phase 1: Found %d Retrofit files with annotations", len(retrofit_files))

    # Phase 2: Base URL discovery
    base_urls = _discover_base_urls(path)
    logger.info("Phase 2: Found %d base URLs", len(base_urls))

    # Phase 3: Per-file LLM enrichment for Retrofit files
    for i, (file_path, annotations) in enumerate(retrofit_files.items(), 1):
        logger.info("Phase 3: Enriching file %d/%d: %s", i, len(retrofit_files), file_path.name)
        source_class = _build_source_class(file_path, path)

        enrichment = _enrich_file_with_llm(file_path, path, OLLAMA_HOST, MODEL_NAME)

        # Create EndpointFinding for each regex-extracted annotation
        for http_method, url_path in annotations:
            req_fields: dict[str, str] = {}
            resp_fields: dict[str, str] = {}

            for ep_schema in enrichment.endpoints:
                if len(annotations) == 1 and len(enrichment.endpoints) == 1:
                    req_fields = ep_schema.request_fields
                    resp_fields = ep_schema.response_fields
                    break
                if ep_schema.method_name:
                    path_parts = url_path.strip("/").split("/")
                    last_part = path_parts[-1] if path_parts else ""
                    if last_part.lower().rstrip("s") in ep_schema.method_name.lower():
                        req_fields = ep_schema.request_fields
                        resp_fields = ep_schema.response_fields
                        break

            all_endpoints.append(EndpointFinding(
                url=url_path,
                http_method=http_method,
                source_class=source_class,
                request_fields=req_fields,
                response_fields=resp_fields,
            ))

    logger.info("Phase 3: Enrichment complete for %d Retrofit files", len(retrofit_files))

    # Phase 4: Fallback for non-Retrofit APIs
    non_retrofit_files = _find_non_retrofit_files(path, set(retrofit_files.keys()))
    logger.info("Phase 4: Found %d non-Retrofit HTTP files", len(non_retrofit_files))
    for i, file_path in enumerate(non_retrofit_files, 1):
        logger.info("Phase 4: Processing file %d/%d: %s", i, len(non_retrofit_files), file_path.name)
        endpoints = _process_non_retrofit_file(file_path, path, OLLAMA_HOST, MODEL_NAME)
        all_endpoints.extend(endpoints)

    logger.info("Phase 4: Complete. Total endpoints before filtering: %d", len(all_endpoints))

    all_endpoints = [
        ep for ep in all_endpoints
        if not NON_API_URL_PATTERNS.search(ep.url)
    ]

    return ApiAnalysisResult(endpoints=all_endpoints, base_urls=base_urls).model_dump_json(indent=2)


def create_api_extractor_server():
    server = create_agent_server("api_extractor")

    @server.tool()
    async def extract_apis(source_dir: str) -> str:
        """Analyze decompiled Java source files for API endpoint definitions.

        Uses a hybrid regex+LLM approach:
        1. Regex extraction of Retrofit annotations (deterministic)
        2. Base URL discovery via pattern matching
        3. Per-file LLM enrichment for request/response schemas
        4. Fallback LLM analysis for non-Retrofit HTTP libraries

        Args:
            source_dir: Path to the decompiled source directory (e.g., /work/decompiled/jadx).
        """
        return await anyio.to_thread.run_sync(_extract_apis_impl, source_dir)

    return server


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    server = create_api_extractor_server()
    server.run(transport="sse")

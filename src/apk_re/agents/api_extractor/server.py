import os
import re
from pathlib import Path

from pydantic import BaseModel, Field

from apk_re.agents.base.base_agent import create_agent_server, call_ollama, is_library_path
from apk_re.schemas import EndpointFinding

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.environ.get("MODEL_NAME", "qwen2.5-coder:7b")

SYSTEM_PROMPT = """You are an Android security analyst specializing in API endpoint extraction.
Given Java source code from a decompiled Android app, identify all runtime API endpoints.

For each endpoint found:
- Extract the URL or URL pattern (e.g., "/api/v1/users", "https://api.example.com/auth")
- Identify the HTTP method (GET, POST, PUT, DELETE, PATCH) if determinable
- Note the source class where it was defined
- Extract request fields/parameters (field name -> type) if visible
- Extract response fields (field name -> type) if visible from deserialization code

Look for:
- Retrofit interface definitions (@GET, @POST annotations with URL paths)
- OkHttp Request.Builder calls with URLs
- HttpURLConnection usage with endpoint URLs
- Volley request construction
- Any hardcoded API base URLs or path constants
- GraphQL endpoints and query definitions

DO NOT extract:
- URLs from comments, license headers, or source code references
- Repository URLs (github.com, gitlab.com, bitbucket.org, sources.gett.com, etc.)
- Documentation or specification URLs
- URLs that are not used for runtime HTTP requests

IMPORTANT: Only extract URLs that appear VERBATIM in the code. Do NOT fabricate, modify, or complete partial URLs. If you are not certain a URL appears exactly as shown in the code, do not include it.

Be precise with URLs. Include path parameters like {id} as-is."""


NON_API_URL_PATTERNS = re.compile(
    r'(?:github\.com|gitlab\.com|bitbucket\.org|sources\.gett\.com'
    r'|stackoverflow\.com|developer\.android\.com|www\.w3\.org'
    r'|schemas\.android\.com|apache\.org|/commit/|/blob/|/tree/)'
)

API_KEYWORDS = re.compile(
    r'(?:@GET|@POST|@PUT|@DELETE|@PATCH|@Headers|@Body|@Query|@Path|@Field|'
    r'@FormUrlEncoded|@Multipart|Request\.Builder|HttpURLConnection|'
    r'\.newCall|Volley\.|RequestQueue|JsonObjectRequest|StringRequest|'
    r'/api/|/v[0-9]+/|\.endpoint|baseUrl|BASE_URL)',
    re.IGNORECASE
)

MAX_FILES = 25
MAX_FILE_SIZE = 500 * 1024  # 500KB
MAX_CHARS_PER_FILE = 8000


class ApiAnalysisResult(BaseModel):
    endpoints: list[EndpointFinding] = Field(default_factory=list)


def _find_relevant_files(source_dir: Path) -> list[Path]:
    """Pre-filter .java files for API-related keywords."""
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
        matches = API_KEYWORDS.findall(content)
        if matches:
            relevant.append((len(matches), java_file))

    # Sort by number of matches descending, take top N
    relevant.sort(key=lambda x: x[0], reverse=True)
    return [path for _, path in relevant[:MAX_FILES]]


def create_api_extractor_server():
    server = create_agent_server("api_extractor")

    @server.tool()
    def extract_apis(source_dir: str) -> str:
        """Analyze decompiled Java source files for API endpoint definitions.

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
            return ApiAnalysisResult(endpoints=[]).model_dump_json(indent=2)

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
            "Analyze the following Java source files for API endpoint definitions "
            "and extract all endpoints:\n\n"
            + "\n\n".join(file_sections)
        )

        result = call_ollama(
            prompt=prompt,
            output_schema=ApiAnalysisResult,
            ollama_host=OLLAMA_HOST,
            model=MODEL_NAME,
            system_prompt=SYSTEM_PROMPT,
        )

        # Post-filter: remove non-API URLs (repo links, docs, etc.)
        result.endpoints = [
            ep for ep in result.endpoints
            if not NON_API_URL_PATTERNS.search(ep.url)
        ]

        return result.model_dump_json(indent=2)

    return server


if __name__ == "__main__":
    server = create_api_extractor_server()
    server.run(transport="sse")

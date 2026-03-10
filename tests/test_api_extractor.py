import json
import tempfile
from pathlib import Path
from unittest.mock import patch, call

from apk_re.agents.api_extractor.server import (
    create_api_extractor_server,
    ENRICHMENT_PROMPT,
    FALLBACK_SYSTEM_PROMPT,
    ApiAnalysisResult,
    NON_API_URL_PATTERNS,
    RETROFIT_ANNOTATION,
    BASE_URL_PATTERNS,
    URL_LITERAL,
    NON_RETROFIT_KEYWORDS,
    EndpointSchema,
    FileEndpointSchemas,
    _extract_retrofit_endpoints,
    _discover_base_urls,
    _find_non_retrofit_files,
    _build_source_class,
)
from apk_re.agents.base.base_agent import LIBRARY_PATH_SEGMENTS
from apk_re.schemas import EndpointFinding


def test_api_extractor_has_tools():
    server = create_api_extractor_server()
    tool_names = list(server._tool_manager._tools.keys())
    assert "read_file" in tool_names
    assert "extract_apis" in tool_names


# --- Phase 1: Retrofit regex tests ---

def test_retrofit_annotation_regex_matches():
    """The regex should match standard Retrofit annotations."""
    cases = [
        ('@GET("/api/v1/users")', "GET", "/api/v1/users"),
        ("@POST('/auth/login')", "POST", "/auth/login"),
        ('@DELETE("/items/{id}")', "DELETE", "/items/{id}"),
        ('@PUT( "/update" )', "PUT", "/update"),
        ('@PATCH("/data")', "PATCH", "/data"),
        ('@HEAD("/health")', "HEAD", "/health"),
        ('@OPTIONS("/cors")', "OPTIONS", "/cors"),
        ('@HTTP("/custom")', "HTTP", "/custom"),
    ]
    for text, expected_method, expected_path in cases:
        match = RETROFIT_ANNOTATION.search(text)
        assert match is not None, f"Should match: {text}"
        assert match.group(1) == expected_method
        assert match.group(2) == expected_path


def test_retrofit_annotation_regex_no_false_positives():
    """The regex should not match non-annotation text."""
    negatives = [
        ('String method = "GET";', "bare keyword assignment"),
        ('"@GET is a Retrofit annotation"', "English sentence mentioning annotation"),
        ('GET("/path")', "missing @ symbol"),
    ]
    for text, reason in negatives:
        match = RETROFIT_ANNOTATION.search(text)
        assert match is None, f"Should NOT match ({reason}): {text}"


def test_extract_retrofit_endpoints_basic():
    """Extract endpoints from a file that imports retrofit2."""
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "UserService.java"
        java_file.write_text(
            'import retrofit2.http.GET;\n'
            'import retrofit2.http.POST;\n'
            'public interface UserService {\n'
            '    @GET("/api/v1/users")\n'
            '    Call<List<User>> getUsers();\n'
            '    @POST("/api/v1/users")\n'
            '    Call<User> createUser(@Body User user);\n'
            '}\n'
        )

        results = _extract_retrofit_endpoints(Path(tmpdir))
        assert len(results) == 1
        endpoints = results[java_file]
        assert len(endpoints) == 2
        assert ("GET", "/api/v1/users") in endpoints
        assert ("POST", "/api/v1/users") in endpoints


def test_extract_retrofit_skips_non_retrofit_files():
    """Files without retrofit2 import should be skipped."""
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "OkHttpClient.java"
        java_file.write_text(
            'import okhttp3.OkHttpClient;\n'
            'public class ApiClient {\n'
            '    // @GET("/should/not/match")\n'
            '}\n'
        )

        results = _extract_retrofit_endpoints(Path(tmpdir))
        assert len(results) == 0


def test_extract_retrofit_skips_library_paths():
    """Files in library paths should be skipped."""
    with tempfile.TemporaryDirectory() as tmpdir:
        lib_dir = Path(tmpdir) / "com" / "google" / "api"
        lib_dir.mkdir(parents=True)
        java_file = lib_dir / "Service.java"
        java_file.write_text(
            'import retrofit2.http.GET;\n'
            'public interface Service {\n'
            '    @GET("/api/v1/data")\n'
            '    Call<Data> getData();\n'
            '}\n'
        )

        results = _extract_retrofit_endpoints(Path(tmpdir))
        assert len(results) == 0


# --- Phase 2: Base URL discovery tests ---

def test_base_url_patterns_regex():
    """The BASE_URL regex should match common patterns."""
    cases = [
        ('baseUrl("https://api.example.com")', "https://api.example.com"),
        ('BASE_URL = "https://backend.myapp.com/v1"', "https://backend.myapp.com/v1"),
        ('api_url = "https://api.test.io"', "https://api.test.io"),
    ]
    for text, expected_url in cases:
        match = BASE_URL_PATTERNS.search(text)
        assert match is not None, f"Should match: {text}"
        url = match.group(1) or match.group(2)
        assert url == expected_url


def test_url_literal_regex():
    """URL_LITERAL should match http/https URLs."""
    cases = [
        ("https://api.example.com", "https://api.example.com"),
        ("http://backend.test.io", "http://backend.test.io"),
    ]
    for text, expected in cases:
        match = URL_LITERAL.search(text)
        assert match is not None, f"Should match: {text}"
        assert match.group(0) == expected


def test_discover_base_urls():
    """Discover base URLs from source files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "ApiConfig.java"
        java_file.write_text(
            'public class ApiConfig {\n'
            '    private static final String BASE_URL = "https://api.ergatta.com/v2";\n'
            '}\n'
        )

        urls = _discover_base_urls(Path(tmpdir))
        assert "https://api.ergatta.com/v2" in urls


def test_discover_base_urls_filters_non_api():
    """Non-API URLs should be excluded from base URL results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "Config.java"
        java_file.write_text(
            'public class Config {\n'
            '    private static final String BASE_URL = "https://github.com/user/repo";\n'
            '}\n'
        )

        urls = _discover_base_urls(Path(tmpdir))
        assert len(urls) == 0


# --- Phase 3: LLM enrichment tests ---

@patch("apk_re.agents.api_extractor.server.call_ollama")
def test_extract_apis_retrofit_with_enrichment(mock_call_ollama):
    """Retrofit files: regex extracts endpoints, LLM enriches schemas."""
    mock_call_ollama.return_value = FileEndpointSchemas(
        endpoints=[
            EndpointSchema(
                method_name="getUsers",
                request_fields={},
                response_fields={"id": "int", "name": "String"},
            )
        ]
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "UserService.java"
        java_file.write_text(
            'import retrofit2.http.GET;\n'
            'public interface UserService {\n'
            '    @GET("/api/v1/users")\n'
            '    Call<List<User>> getUsers();\n'
            '}\n'
        )

        server = create_api_extractor_server()
        extract_fn = server._tool_manager._tools["extract_apis"].fn
        result_json = extract_fn(source_dir=tmpdir)
        result = json.loads(result_json)

    # LLM was called for enrichment
    mock_call_ollama.assert_called_once()
    call_kwargs = mock_call_ollama.call_args[1]
    assert call_kwargs["output_schema"] == FileEndpointSchemas
    assert call_kwargs["system_prompt"] == ENRICHMENT_PROMPT

    # Endpoint was extracted via regex
    assert len(result["endpoints"]) == 1
    ep = result["endpoints"][0]
    assert ep["url"] == "/api/v1/users"
    assert ep["http_method"] == "GET"
    assert "UserService" in ep["source_class"]


@patch("apk_re.agents.api_extractor.server.call_ollama")
def test_extract_apis_multiple_retrofit_files(mock_call_ollama):
    """Each Retrofit file gets its own LLM call."""
    mock_call_ollama.return_value = FileEndpointSchemas(endpoints=[])

    with tempfile.TemporaryDirectory() as tmpdir:
        for name, content in [
            ("UserApi.java",
             'import retrofit2.http.GET;\n'
             'public interface UserApi {\n'
             '    @GET("/users")\n'
             '    Call<List<User>> list();\n'
             '}\n'),
            ("ItemApi.java",
             'import retrofit2.http.POST;\n'
             'public interface ItemApi {\n'
             '    @POST("/items")\n'
             '    Call<Item> create(@Body Item item);\n'
             '}\n'),
        ]:
            (Path(tmpdir) / name).write_text(content)

        server = create_api_extractor_server()
        extract_fn = server._tool_manager._tools["extract_apis"].fn
        result_json = extract_fn(source_dir=tmpdir)
        result = json.loads(result_json)

    # One LLM call per file
    assert mock_call_ollama.call_count == 2

    # Both endpoints extracted
    urls = [ep["url"] for ep in result["endpoints"]]
    assert "/users" in urls
    assert "/items" in urls


# --- Phase 4: Non-Retrofit fallback tests ---

def test_non_retrofit_keywords_regex():
    """NON_RETROFIT_KEYWORDS should match OkHttp/Volley/etc patterns."""
    cases = [
        "new Request.Builder()",
        "HttpURLConnection conn",
        "client.newCall(request)",
        "Volley.newRequestQueue",
        "new JsonObjectRequest(",
        "new StringRequest(",
        "GraphQL query",
    ]
    for text in cases:
        assert NON_RETROFIT_KEYWORDS.search(text), f"Should match: {text}"


def test_find_non_retrofit_files():
    """Should find files using OkHttp etc but not Retrofit files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        retrofit_file = Path(tmpdir) / "RetrofitApi.java"
        retrofit_file.write_text(
            'import retrofit2.http.GET;\n'
            '@GET("/api") Call<Data> get();\n'
        )

        okhttp_file = Path(tmpdir) / "OkHttpClient.java"
        okhttp_file.write_text(
            'Request request = new Request.Builder()\n'
            '    .url("https://api.example.com/data")\n'
            '    .build();\n'
            'client.newCall(request).execute();\n'
        )

        plain_file = Path(tmpdir) / "Utils.java"
        plain_file.write_text('public class Utils { int add(int a, int b) { return a + b; } }')

        non_retrofit = _find_non_retrofit_files(Path(tmpdir), {retrofit_file})
        names = [f.name for f in non_retrofit]
        assert "OkHttpClient.java" in names
        assert "RetrofitApi.java" not in names
        assert "Utils.java" not in names


@patch("apk_re.agents.api_extractor.server.call_ollama")
def test_extract_apis_non_retrofit_fallback(mock_call_ollama):
    """Non-Retrofit files should be processed one-at-a-time with fallback prompt."""
    mock_call_ollama.return_value = ApiAnalysisResult(
        endpoints=[
            EndpointFinding(
                url="https://api.example.com/data",
                http_method="GET",
                source_class="OkHttpClient",
                request_fields={},
                response_fields={},
            )
        ]
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        okhttp_file = Path(tmpdir) / "OkHttpClient.java"
        okhttp_file.write_text(
            'Request request = new Request.Builder()\n'
            '    .url("https://api.example.com/data")\n'
            '    .build();\n'
            'client.newCall(request).execute();\n'
        )

        server = create_api_extractor_server()
        extract_fn = server._tool_manager._tools["extract_apis"].fn
        result_json = extract_fn(source_dir=tmpdir)
        result = json.loads(result_json)

    mock_call_ollama.assert_called_once()
    call_kwargs = mock_call_ollama.call_args[1]
    assert call_kwargs["output_schema"] == ApiAnalysisResult
    assert call_kwargs["system_prompt"] == FALLBACK_SYSTEM_PROMPT
    assert len(result["endpoints"]) == 1
    assert result["endpoints"][0]["url"] == "https://api.example.com/data"


# --- Post-filter tests (kept from original) ---

def test_post_filter_removes_repository_urls():
    """Non-API URLs like repo links should be filtered out."""
    for url in [
        "https://github.com/user/repo",
        "https://sources.gett.com/gettalent/getgolang/commit/abc123",
        "https://gitlab.com/org/project/blob/main/file.java",
        "https://stackoverflow.com/questions/12345",
        "https://developer.android.com/reference/foo",
        "https://www.w3.org/2001/XMLSchema",
    ]:
        assert NON_API_URL_PATTERNS.search(url), f"Should match non-API URL: {url}"

    # Real API endpoints should NOT be filtered
    for url in [
        "/api/v1/users",
        "https://api.example.com/auth/login",
        "https://backend.myapp.com/graphql",
    ]:
        assert not NON_API_URL_PATTERNS.search(url), f"Should not match API URL: {url}"


@patch("apk_re.agents.api_extractor.server.call_ollama")
def test_extract_apis_filters_repo_urls_from_fallback(mock_call_ollama):
    """Endpoints with repository URLs should be removed from non-Retrofit results."""
    mock_call_ollama.return_value = ApiAnalysisResult(
        endpoints=[
            EndpointFinding(
                url="https://sources.gett.com/gettalent/getgolang/commit/abc",
                http_method="GET",
                source_class="SomeClass",
                request_fields={},
                response_fields={},
            ),
            EndpointFinding(
                url="/api/v1/users",
                http_method="GET",
                source_class="UserService",
                request_fields={},
                response_fields={"id": "int"},
            ),
        ]
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "ApiClient.java"
        java_file.write_text(
            'Request request = new Request.Builder()\n'
            '    .url("/api/v1/users")\n'
            '    .build();\n'
            'client.newCall(request).execute();\n'
        )

        server = create_api_extractor_server()
        extract_fn = server._tool_manager._tools["extract_apis"].fn
        result_json = extract_fn(source_dir=tmpdir)

    assert "/api/v1/users" in result_json
    assert "sources.gett.com" not in result_json


# --- Library path filtering (kept from original) ---

def test_library_path_filtering():
    """Files in library paths should be skipped by both Retrofit and non-Retrofit scans."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # App file - should be found
        app_dir = Path(tmpdir) / "com" / "myapp" / "api"
        app_dir.mkdir(parents=True)
        app_file = app_dir / "MyApi.java"
        app_file.write_text(
            'import retrofit2.http.GET;\n'
            'public interface MyApi {\n'
            '    @GET("/api/v1/data")\n'
            '    Call<Data> getData();\n'
            '}\n'
        )

        # Library file - should be skipped
        lib_dir = Path(tmpdir) / "com" / "google" / "api"
        lib_dir.mkdir(parents=True)
        lib_file = lib_dir / "GoogleApi.java"
        lib_file.write_text(
            'import retrofit2.http.GET;\n'
            'public interface GoogleApi {\n'
            '    @GET("/api/v1/google")\n'
            '    Call<Data> getData();\n'
            '}\n'
        )

        results = _extract_retrofit_endpoints(Path(tmpdir))
        found_names = [f.name for f in results.keys()]
        assert "MyApi.java" in found_names
        assert "GoogleApi.java" not in found_names


# --- Edge cases ---

def test_extract_apis_empty_directory():
    """Empty directory should return empty results without error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        server = create_api_extractor_server()
        extract_fn = server._tool_manager._tools["extract_apis"].fn
        result_json = extract_fn(source_dir=tmpdir)
        result = json.loads(result_json)
        assert result["endpoints"] == []
        assert result["base_urls"] == []


def test_extract_apis_nonexistent_directory():
    """Nonexistent directory should return an error string."""
    server = create_api_extractor_server()
    extract_fn = server._tool_manager._tools["extract_apis"].fn
    result = extract_fn(source_dir="/nonexistent/path")
    assert "Error" in result


@patch("apk_re.agents.api_extractor.server.call_ollama")
def test_extract_apis_includes_base_urls(mock_call_ollama):
    """Discovered base URLs should appear in the extract_apis output."""
    mock_call_ollama.return_value = FileEndpointSchemas(endpoints=[])

    with tempfile.TemporaryDirectory() as tmpdir:
        # A Retrofit file so we get endpoints
        api_file = Path(tmpdir) / "UserApi.java"
        api_file.write_text(
            'import retrofit2.http.GET;\n'
            'public interface UserApi {\n'
            '    @GET("/users")\n'
            '    Call<List<User>> list();\n'
            '}\n'
        )
        # A config file with a base URL
        config_file = Path(tmpdir) / "ApiConfig.java"
        config_file.write_text(
            'public class ApiConfig {\n'
            '    private static final String BASE_URL = "https://api.ergatta.com/v2";\n'
            '}\n'
        )

        server = create_api_extractor_server()
        extract_fn = server._tool_manager._tools["extract_apis"].fn
        result_json = extract_fn(source_dir=tmpdir)
        result = json.loads(result_json)

    assert "https://api.ergatta.com/v2" in result["base_urls"]
    assert len(result["endpoints"]) == 1


def test_build_source_class():
    """Source class should be derived from file path."""
    source_dir = Path("/work/decompiled/jadx")
    file_path = Path("/work/decompiled/jadx/com/myapp/api/UserService.java")
    assert _build_source_class(file_path, source_dir) == "com.myapp.api.UserService"


@patch("apk_re.agents.api_extractor.server.call_ollama")
def test_enrichment_failure_graceful(mock_call_ollama):
    """If LLM enrichment fails, endpoints should still be returned (without schemas)."""
    mock_call_ollama.side_effect = Exception("LLM unavailable")

    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "Api.java"
        java_file.write_text(
            'import retrofit2.http.GET;\n'
            'public interface Api {\n'
            '    @GET("/health")\n'
            '    Call<Status> check();\n'
            '}\n'
        )

        server = create_api_extractor_server()
        extract_fn = server._tool_manager._tools["extract_apis"].fn
        result_json = extract_fn(source_dir=tmpdir)
        result = json.loads(result_json)

    # Endpoint still extracted via regex despite LLM failure
    assert len(result["endpoints"]) == 1
    assert result["endpoints"][0]["url"] == "/health"
    assert result["endpoints"][0]["http_method"] == "GET"


def test_enrichment_prompt_exists():
    """Enrichment prompt should contain key instructions."""
    assert "method_name" in ENRICHMENT_PROMPT
    assert "request_fields" in ENRICHMENT_PROMPT
    assert "Do NOT fabricate" in ENRICHMENT_PROMPT


def test_fallback_prompt_exists():
    """Fallback prompt should contain endpoint extraction instructions."""
    assert "DO NOT" in FALLBACK_SYSTEM_PROMPT
    assert "VERBATIM" in FALLBACK_SYSTEM_PROMPT

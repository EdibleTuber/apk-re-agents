import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from apk_re.agents.network_mapper.server import (
    create_network_mapper_server,
    SYSTEM_PROMPT,
    NETWORK_KEYWORDS,
    NetworkAnalysisResult,
    _find_relevant_files,
    _extract_url_literals,
    _FP_URL_PREFIXES,
    _is_fp_url,
    HARDCODED_URL,
)
from apk_re.agents.base.base_agent import LIBRARY_PATH_SEGMENTS
from apk_re.schemas import NetworkFinding


def test_network_mapper_has_tools():
    server = create_network_mapper_server()
    tool_names = list(server._tool_manager._tools.keys())
    assert "read_file" in tool_names
    assert "map_network" in tool_names


def test_system_prompt_exists():
    assert "network" in SYSTEM_PROMPT.lower()
    assert len(SYSTEM_PROMPT) > 50


def test_system_prompt_endpoint_field_guidance():
    assert "URL, hostname, IP address" in SYSTEM_PROMPT
    assert "Do NOT put class names" in SYSTEM_PROMPT


@patch("apk_re.agents.network_mapper.server.call_ollama")
def test_map_network_calls_ollama_per_file(mock_call_ollama):
    """LLM is called once per relevant file, not once for all files."""
    mock_result = NetworkAnalysisResult(
        findings=[
            NetworkFinding(
                endpoint="https://api.example.com/v1",
                protocol="https",
                source_class="ApiClient",
                cert_pinning=False,
                notes="Hardcoded endpoint",
            )
        ]
    )
    mock_call_ollama.return_value = mock_result

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create two relevant java files
        java_file1 = Path(tmpdir) / "ApiClient.java"
        java_file1.write_text(
            'public class ApiClient {\n'
            '    private static final String URL = "https://api.example.com/v1";\n'
            '    OkHttpClient client = new OkHttpClient();\n'
            '}\n'
        )
        java_file2 = Path(tmpdir) / "WebSocketHandler.java"
        java_file2.write_text(
            'public class WebSocketHandler {\n'
            '    WebSocket ws = new WebSocket("wss://stream.example.com");\n'
            '}\n'
        )

        server = create_network_mapper_server()
        map_fn = server._tool_manager._tools["map_network"].fn
        result = map_fn(source_dir=tmpdir)

    # Should be called once per file
    assert mock_call_ollama.call_count == 2
    # Each call should have a single-file prompt
    for call in mock_call_ollama.call_args_list:
        assert "Analyze this single Java file" in call[1]["prompt"]

    assert "https://api.example.com/v1" in result


def test_keyword_prefilter_identifies_relevant_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        # File with network keywords
        relevant = Path(tmpdir) / "NetworkHelper.java"
        relevant.write_text(
            'public class NetworkHelper {\n'
            '    OkHttpClient client;\n'
            '    String url = "https://example.com";\n'
            '}\n'
        )

        # File without network keywords
        irrelevant = Path(tmpdir) / "Utils.java"
        irrelevant.write_text(
            'public class Utils {\n'
            '    public static int add(int a, int b) { return a + b; }\n'
            '}\n'
        )

        # Non-java file with network keywords (should be ignored)
        non_java = Path(tmpdir) / "config.xml"
        non_java.write_text('<config url="https://example.com"/>\n')

        found = _find_relevant_files(Path(tmpdir))
        found_names = [f.name for f in found]
        assert "NetworkHelper.java" in found_names
        assert "Utils.java" not in found_names
        assert "config.xml" not in found_names


def test_library_path_filtering():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a file inside a library path
        lib_dir = Path(tmpdir) / "sources" / "io" / "netty" / "handler" / "ssl"
        lib_dir.mkdir(parents=True)
        lib_file = lib_dir / "SslHandler.java"
        lib_file.write_text(
            'public class SslHandler {\n'
            '    SSLContext ctx = SSLContext.getInstance("TLS");\n'
            '}\n'
        )

        # Create a file in app code (not a library path)
        app_dir = Path(tmpdir) / "sources" / "com" / "myapp" / "network"
        app_dir.mkdir(parents=True)
        app_file = app_dir / "AppClient.java"
        app_file.write_text(
            'public class AppClient {\n'
            '    String url = "https://myapp.com/api";\n'
            '}\n'
        )

        found = _find_relevant_files(Path(tmpdir))
        found_names = [f.name for f in found]
        assert "AppClient.java" in found_names
        assert "SslHandler.java" not in found_names


@patch("apk_re.agents.network_mapper.server.call_ollama")
def test_deduplication_of_findings(mock_call_ollama):
    """Duplicate findings (same endpoint + source_class) are deduplicated."""
    mock_result = NetworkAnalysisResult(
        findings=[
            NetworkFinding(
                endpoint="https://api.example.com",
                protocol="https",
                source_class="ApiClient",
                cert_pinning=False,
                notes="LLM found this",
            ),
        ]
    )
    mock_call_ollama.return_value = mock_result

    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "ApiClient.java"
        java_file.write_text(
            'public class ApiClient {\n'
            '    String url = "https://api.example.com";\n'
            '    OkHttpClient client = new OkHttpClient();\n'
            '}\n'
        )

        server = create_network_mapper_server()
        map_fn = server._tool_manager._tools["map_network"].fn
        result = map_fn(source_dir=tmpdir)

    parsed = json.loads(result)
    # Regex extraction finds "https://api.example.com" and LLM also returns it
    # They share the same (endpoint, source_class) key so should be deduped to 1
    endpoints = [f["endpoint"] for f in parsed["findings"]]
    assert endpoints.count("https://api.example.com") == 1


@patch("apk_re.agents.network_mapper.server.call_ollama")
def test_url_literal_extraction(mock_call_ollama):
    """Hardcoded URLs are extracted via regex without LLM."""
    mock_call_ollama.return_value = NetworkAnalysisResult(findings=[])

    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "Config.java"
        java_file.write_text(
            'public class Config {\n'
            '    String api = "https://api.myapp.com/v2";\n'
            '    String docs = "http://docs.myapp.com";\n'
            '    OkHttpClient client = new OkHttpClient();\n'
            '}\n'
        )

        server = create_network_mapper_server()
        map_fn = server._tool_manager._tools["map_network"].fn
        result = map_fn(source_dir=tmpdir)

    parsed = json.loads(result)
    endpoints = [f["endpoint"] for f in parsed["findings"]]
    assert "https://api.myapp.com/v2" in endpoints
    assert "http://docs.myapp.com" in endpoints
    # Check protocol is set correctly
    for f in parsed["findings"]:
        if f["endpoint"] == "https://api.myapp.com/v2":
            assert f["protocol"] == "https"
            assert f["notes"] == "Hardcoded URL literal"
        if f["endpoint"] == "http://docs.myapp.com":
            assert f["protocol"] == "http"


def test_extract_url_literals_skips_false_positives():
    """Schema URLs (w3.org, schemas.android.com, etc.) are filtered out."""
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "Layout.java"
        java_file.write_text(
            'public class Layout {\n'
            '    String ns = "http://schemas.android.com/apk/res/android";\n'
            '    String real = "https://api.real.com/data";\n'
            '    String auth = "https://www.googleapis.com/auth/fitness.activity.read";\n'
            '}\n'
        )

        findings = _extract_url_literals([java_file], Path(tmpdir))
        endpoints = [f.endpoint for f in findings]
        assert "https://api.real.com/data" in endpoints
        assert not any("schemas.android.com" in e for e in endpoints)
        assert not any("googleapis.com/auth/" in e for e in endpoints)


def test_is_fp_url():
    """_is_fp_url correctly identifies false positive URLs."""
    assert _is_fp_url("http://schemas.android.com/apk/res/android")
    assert _is_fp_url("http://www.w3.org/2001/XMLSchema")
    assert _is_fp_url("https://www.googleapis.com/auth/fitness")
    assert not _is_fp_url("https://api.example.com/v1")
    assert not _is_fp_url("https://www.googleapis.com/robot/v1")


def test_extract_url_literals_strips_sources_prefix():
    """source_class strips 'sources.' prefix from relative path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir) / "sources" / "com" / "myapp"
        src_dir.mkdir(parents=True)
        java_file = src_dir / "Client.java"
        java_file.write_text(
            'public class Client {\n'
            '    String url = "https://api.myapp.com";\n'
            '}\n'
        )

        findings = _extract_url_literals([java_file], Path(tmpdir))
        assert len(findings) == 1
        assert findings[0].source_class == "com.myapp.Client"


@patch("apk_re.agents.network_mapper.server.call_ollama")
def test_llm_failure_logged_not_raised(mock_call_ollama):
    """If LLM call fails for one file, processing continues."""
    mock_call_ollama.side_effect = RuntimeError("Ollama down")

    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "Client.java"
        java_file.write_text(
            'public class Client {\n'
            '    String url = "https://api.example.com";\n'
            '    OkHttpClient client = new OkHttpClient();\n'
            '}\n'
        )

        server = create_network_mapper_server()
        map_fn = server._tool_manager._tools["map_network"].fn
        result = map_fn(source_dir=tmpdir)

    # Should still return regex-extracted findings despite LLM failure
    parsed = json.loads(result)
    assert len(parsed["findings"]) >= 1
    assert parsed["findings"][0]["endpoint"] == "https://api.example.com"

import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from apk_re.agents.network_mapper.server import (
    create_network_mapper_server,
    SYSTEM_PROMPT,
    NETWORK_KEYWORDS,
    LIBRARY_PATH_SEGMENTS,
    NetworkAnalysisResult,
    _find_relevant_files,
)
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
def test_map_network_calls_ollama(mock_call_ollama):
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
        # Create a sample java file with network keywords
        java_file = Path(tmpdir) / "ApiClient.java"
        java_file.write_text(
            'public class ApiClient {\n'
            '    private static final String URL = "https://api.example.com/v1";\n'
            '    OkHttpClient client = new OkHttpClient();\n'
            '}\n'
        )

        server = create_network_mapper_server()
        map_fn = server._tool_manager._tools["map_network"].fn
        result = map_fn(source_dir=tmpdir)

    mock_call_ollama.assert_called_once()
    call_kwargs = mock_call_ollama.call_args[1]
    assert call_kwargs["output_schema"] == NetworkAnalysisResult
    assert "ApiClient" in call_kwargs["prompt"]
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
    mock_result = NetworkAnalysisResult(
        findings=[
            NetworkFinding(
                endpoint="https://api.example.com",
                protocol="https",
                source_class="ApiClient",
                cert_pinning=False,
                notes="First occurrence",
            ),
            NetworkFinding(
                endpoint="https://api.example.com",
                protocol="https",
                source_class="ApiClient",
                cert_pinning=False,
                notes="Duplicate occurrence",
            ),
            NetworkFinding(
                endpoint="https://other.example.com",
                protocol="https",
                source_class="OtherClient",
                cert_pinning=True,
                notes="Different endpoint",
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

    import json
    parsed = json.loads(result)
    assert len(parsed["findings"]) == 2
    assert parsed["findings"][0]["notes"] == "First occurrence"
    assert parsed["findings"][1]["endpoint"] == "https://other.example.com"

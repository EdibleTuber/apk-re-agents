import tempfile
from pathlib import Path
from unittest.mock import patch

from apk_re.agents.api_extractor.server import (
    create_api_extractor_server,
    SYSTEM_PROMPT,
    API_KEYWORDS,
    ApiAnalysisResult,
    _find_relevant_files,
)
from apk_re.schemas import EndpointFinding


def test_api_extractor_has_tools():
    server = create_api_extractor_server()
    tool_names = list(server._tool_manager._tools.keys())
    assert "read_file" in tool_names
    assert "extract_apis" in tool_names


def test_system_prompt_exists():
    prompt_lower = SYSTEM_PROMPT.lower()
    assert "api" in prompt_lower or "endpoint" in prompt_lower
    assert len(SYSTEM_PROMPT) > 50


@patch("apk_re.agents.api_extractor.server.call_ollama")
def test_extract_apis_calls_ollama(mock_call_ollama):
    mock_result = ApiAnalysisResult(
        endpoints=[
            EndpointFinding(
                url="/api/v1/users",
                http_method="GET",
                source_class="UserService",
                request_fields={},
                response_fields={"id": "int", "name": "String"},
            )
        ]
    )
    mock_call_ollama.return_value = mock_result

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a sample java file with API keywords
        java_file = Path(tmpdir) / "UserService.java"
        java_file.write_text(
            'public interface UserService {\n'
            '    @GET("/api/v1/users")\n'
            '    Call<List<User>> getUsers();\n'
            '}\n'
        )

        server = create_api_extractor_server()
        extract_fn = server._tool_manager._tools["extract_apis"].fn
        result = extract_fn(source_dir=tmpdir)

    mock_call_ollama.assert_called_once()
    call_kwargs = mock_call_ollama.call_args[1]
    assert call_kwargs["output_schema"] == ApiAnalysisResult
    assert "UserService" in call_kwargs["prompt"]
    assert "/api/v1/users" in result


def test_keyword_prefilter_identifies_relevant_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        # File with API keywords
        relevant = Path(tmpdir) / "ApiService.java"
        relevant.write_text(
            'public interface ApiService {\n'
            '    @GET("/api/v1/users")\n'
            '    Call<List<User>> getUsers();\n'
            '    @POST("/api/v1/users")\n'
            '    Call<User> createUser(@Body User user);\n'
            '}\n'
        )

        # File without API keywords
        irrelevant = Path(tmpdir) / "Utils.java"
        irrelevant.write_text(
            'public class Utils {\n'
            '    public static int add(int a, int b) { return a + b; }\n'
            '}\n'
        )

        # Non-java file with API keywords (should be ignored)
        non_java = Path(tmpdir) / "config.xml"
        non_java.write_text('<config url="/api/v1/health"/>\n')

        found = _find_relevant_files(Path(tmpdir))
        found_names = [f.name for f in found]
        assert "ApiService.java" in found_names
        assert "Utils.java" not in found_names
        assert "config.xml" not in found_names

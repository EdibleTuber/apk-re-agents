import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from apk_re.agents.code_analyzer.server import (
    create_code_analyzer_server,
    TRIAGE_PROMPT,
    ANALYSIS_PROMPT,
    SECURITY_KEYWORDS,
    TriageResult,
    _find_relevant_files,
)
from apk_re.schemas import CodeAnalysisSummary


def test_code_analyzer_has_tools():
    server = create_code_analyzer_server()
    tool_names = list(server._tool_manager._tools.keys())
    assert "read_file" in tool_names
    assert "triage_classes" in tool_names
    assert "analyze_class" in tool_names


def test_triage_prompt_exists():
    assert "security" in TRIAGE_PROMPT.lower()
    assert "relevance_score" in TRIAGE_PROMPT
    assert len(TRIAGE_PROMPT) > 50


def test_analysis_prompt_exists():
    assert "security" in ANALYSIS_PROMPT.lower()
    assert "vulnerabilities" in ANALYSIS_PROMPT.lower()
    assert len(ANALYSIS_PROMPT) > 50


@patch("apk_re.agents.code_analyzer.server.call_ollama")
def test_triage_classes_calls_ollama(mock_call_ollama):
    mock_result = TriageResult(
        classes=[
            CodeAnalysisSummary(
                class_name="com.example.CryptoHelper",
                relevance_score=0.9,
                summary="Implements AES encryption with hardcoded key",
                flags=["crypto"],
            )
        ]
    )
    mock_call_ollama.return_value = mock_result

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a sample java file with security keywords
        java_file = Path(tmpdir) / "CryptoHelper.java"
        java_file.write_text(
            'public class CryptoHelper {\n'
            '    private static final String SECRET_KEY = "hardcoded";\n'
            '    Cipher cipher = Cipher.getInstance("AES");\n'
            '}\n'
        )

        server = create_code_analyzer_server()
        triage_fn = server._tool_manager._tools["triage_classes"].fn
        result = triage_fn(source_dir=tmpdir)

    mock_call_ollama.assert_called_once()
    call_kwargs = mock_call_ollama.call_args[1]
    assert call_kwargs["output_schema"] == TriageResult
    assert "CryptoHelper" in call_kwargs["prompt"]
    assert "com.example.CryptoHelper" in result


@patch("apk_re.agents.code_analyzer.server.call_ollama")
def test_analyze_class_calls_ollama(mock_call_ollama):
    mock_result = CodeAnalysisSummary(
        class_name="com.example.AuthManager",
        relevance_score=0.85,
        summary="Handles OAuth2 token refresh with insecure storage",
        flags=["auth", "storage"],
    )
    mock_call_ollama.return_value = mock_result

    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "AuthManager.java"
        java_file.write_text(
            'public class AuthManager {\n'
            '    private String token;\n'
            '    SharedPreferences prefs;\n'
            '}\n'
        )

        server = create_code_analyzer_server()
        analyze_fn = server._tool_manager._tools["analyze_class"].fn
        result = analyze_fn(file_path=str(java_file))

    mock_call_ollama.assert_called_once()
    call_kwargs = mock_call_ollama.call_args[1]
    assert call_kwargs["output_schema"] == CodeAnalysisSummary
    assert "AuthManager" in call_kwargs["prompt"]
    assert "com.example.AuthManager" in result


def test_keyword_prefilter_identifies_relevant_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        # File with security keywords
        relevant = Path(tmpdir) / "CryptoUtil.java"
        relevant.write_text(
            'public class CryptoUtil {\n'
            '    Cipher cipher = Cipher.getInstance("AES");\n'
            '    SecretKey key = generateKey();\n'
            '}\n'
        )

        # File without security keywords
        irrelevant = Path(tmpdir) / "StringUtils.java"
        irrelevant.write_text(
            'public class StringUtils {\n'
            '    public static String capitalize(String s) { return s; }\n'
            '}\n'
        )

        # Non-java file with keywords (should be ignored)
        non_java = Path(tmpdir) / "config.xml"
        non_java.write_text('<config password="secret"/>\n')

        found = _find_relevant_files(Path(tmpdir))
        found_names = [f.name for f in found]
        assert "CryptoUtil.java" in found_names
        assert "StringUtils.java" not in found_names
        assert "config.xml" not in found_names

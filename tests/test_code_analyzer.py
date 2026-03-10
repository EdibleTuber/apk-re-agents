import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from apk_re.agents.code_analyzer.server import (
    create_code_analyzer_server,
    TRIAGE_PROMPT,
    ANALYSIS_PROMPT,
    SECURITY_KEYWORDS,
    TRIAGE_BATCH_SIZE,
    TriageResult,
    _find_relevant_files,
)
from apk_re.agents.base.base_agent import LIBRARY_PATH_SEGMENTS
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


def test_triage_prompt_scoring_scale():
    assert "0.0 and 1.0" in TRIAGE_PROMPT
    assert "NOT" in TRIAGE_PROMPT and "percentages" in TRIAGE_PROMPT


def test_triage_prompt_flag_examples():
    for flag in ("network", "crypto", "storage", "auth", "webview", "ipc"):
        assert f'"{flag}"' in TRIAGE_PROMPT


def test_analysis_prompt_exists():
    assert "security" in ANALYSIS_PROMPT.lower()
    assert "vulnerabilities" in ANALYSIS_PROMPT.lower()
    assert len(ANALYSIS_PROMPT) > 50


@patch("apk_re.agents.code_analyzer.server.call_ollama")
def test_triage_classes_calls_ollama(mock_call_ollama):
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a sample java file with security keywords in a package path
        pkg_dir = Path(tmpdir) / "com" / "example"
        pkg_dir.mkdir(parents=True)
        java_file = pkg_dir / "CryptoHelper.java"
        java_file.write_text(
            'public class CryptoHelper {\n'
            '    private static final String SECRET_KEY = "hardcoded";\n'
            '    Cipher cipher = Cipher.getInstance("AES");\n'
            '}\n'
        )

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


def test_library_path_filtering():
    """Files in known library packages should be skipped even if they contain keywords."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create files in library paths (should be skipped)
        for lib_path in ("com/google/crypto", "androidx/security", "exoplayer2/upstream"):
            lib_dir = Path(tmpdir) / lib_path
            lib_dir.mkdir(parents=True)
            (lib_dir / "LibClass.java").write_text(
                'public class LibClass { Cipher cipher; SecretKey key; }\n'
            )

        # Create a file in an app-specific path (should be kept)
        app_dir = Path(tmpdir) / "com" / "ifit" / "security"
        app_dir.mkdir(parents=True)
        (app_dir / "AppCrypto.java").write_text(
            'public class AppCrypto { Cipher cipher; SecretKey key; }\n'
        )

        found = _find_relevant_files(Path(tmpdir))
        found_names = [f.name for f in found]
        assert "AppCrypto.java" in found_names
        # Library files should be excluded
        assert len(found) == 1, f"Expected only app file, got: {[str(f) for f in found]}"


def test_triage_batch_size_is_five():
    """TRIAGE_BATCH_SIZE should be 5."""
    assert TRIAGE_BATCH_SIZE == 5


@patch("apk_re.agents.code_analyzer.server.call_ollama")
def test_triage_batches_multiple_calls(mock_call_ollama):
    """Triage with more files than TRIAGE_BATCH_SIZE makes multiple LLM calls."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create 7 files (should produce 2 batches: 5 + 2)
        class_names = []
        for i in range(7):
            pkg_dir = Path(tmpdir) / "com" / "example"
            pkg_dir.mkdir(parents=True, exist_ok=True)
            name = f"Security{i}.java"
            (pkg_dir / name).write_text(
                f'public class Security{i} {{\n'
                f'    Cipher cipher; SecretKey key; password token;\n'
                f'}}\n'
            )
            class_names.append(f"com.example.Security{i}")

        def make_result(call_args):
            # Return classes matching files in the prompt
            classes = []
            for cn in class_names:
                short = cn.split(".")[-1]
                if short in call_args[1]["prompt"]:
                    classes.append(CodeAnalysisSummary(
                        class_name=cn,
                        relevance_score=0.7,
                        summary=f"{short} handles crypto",
                        flags=["crypto"],
                    ))
            return TriageResult(classes=classes)

        mock_call_ollama.side_effect = lambda **kwargs: make_result((None, kwargs))

        server = create_code_analyzer_server()
        triage_fn = server._tool_manager._tools["triage_classes"].fn
        result = triage_fn(source_dir=tmpdir)

    # Should have been called twice (batch of 5 + batch of 2)
    assert mock_call_ollama.call_count == 2
    # All 7 classes should appear in result
    import json
    parsed = json.loads(result)
    assert len(parsed["classes"]) == 7


@patch("apk_re.agents.code_analyzer.server.call_ollama")
def test_triage_batch_failure_continues(mock_call_ollama):
    """If one batch fails, other batches still succeed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create 7 files (2 batches)
        for i in range(7):
            pkg_dir = Path(tmpdir) / "com" / "example"
            pkg_dir.mkdir(parents=True, exist_ok=True)
            (pkg_dir / f"Crypto{i}.java").write_text(
                f'public class Crypto{i} {{ Cipher cipher; SecretKey key; }}\n'
            )

        call_count = [0]

        def side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("LLM unavailable")
            # Second batch succeeds
            return TriageResult(classes=[
                CodeAnalysisSummary(
                    class_name="com.example.Crypto5",
                    relevance_score=0.8,
                    summary="Crypto class",
                    flags=["crypto"],
                ),
            ])

        mock_call_ollama.side_effect = side_effect

        server = create_code_analyzer_server()
        triage_fn = server._tool_manager._tools["triage_classes"].fn
        result = triage_fn(source_dir=tmpdir)

    import json
    parsed = json.loads(result)
    # First batch failed, second succeeded — should have results from second batch
    assert len(parsed["classes"]) >= 1
    assert mock_call_ollama.call_count == 2

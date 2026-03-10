import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from apk_re.agents.report_synthesizer.server import (
    create_report_synthesizer_server,
    SYSTEM_PROMPT,
    SecurityReport,
    _load_findings,
)


def test_report_synthesizer_has_tools():
    server = create_report_synthesizer_server()
    tool_names = list(server._tool_manager._tools.keys())
    assert "read_file" in tool_names
    assert "synthesize_report" in tool_names


def test_system_prompt_mentions_security_and_report():
    prompt_lower = SYSTEM_PROMPT.lower()
    assert "security" in prompt_lower
    assert "report" in prompt_lower
    assert len(SYSTEM_PROMPT) > 50


@patch("apk_re.agents.report_synthesizer.server.call_ollama")
def test_synthesize_report_calls_ollama(mock_call_ollama):
    mock_result = SecurityReport(
        app_name="com.example.testapp",
        risk_level="high",
        summary="The app has several critical security issues.",
        key_findings=["Hardcoded API key found", "No certificate pinning"],
        permissions_analysis="Requests dangerous permissions.",
        network_analysis="Communicates over HTTP.",
        secrets_analysis="Contains hardcoded AWS key.",
        code_analysis="Uses reflection to bypass security.",
        recommendations=["Remove hardcoded secrets", "Implement cert pinning"],
    )
    mock_call_ollama.return_value = mock_result

    with tempfile.TemporaryDirectory() as tmpdir:
        job_dir = Path(tmpdir) / "findings" / "test-job"
        job_dir.mkdir(parents=True)

        # Create sample findings files
        (job_dir / "manifest_analyzer.json").write_text(
            json.dumps({"permissions": ["INTERNET", "CAMERA"]})
        )
        (job_dir / "string_extractor.json").write_text(
            json.dumps({"secrets": ["AKIA1234567890"]})
        )
        (job_dir / "network_mapper.json").write_text(
            json.dumps({"endpoints": ["http://api.example.com"]})
        )

        server = create_report_synthesizer_server()
        synth_fn = server._tool_manager._tools["synthesize_report"].fn

        with patch(
            "apk_re.agents.report_synthesizer.server.Path"
        ) as mock_path_cls:
            # Make Path("/work/findings") / "test-job" resolve to our temp dir
            # Instead, directly call _load_findings and the function with patched path
            pass

        # Patch at a higher level: override the job_dir path construction
        with patch("apk_re.agents.report_synthesizer.server.Path") as MockPath:
            # When Path("/work/findings") is called, redirect to our tmpdir
            def path_side_effect(arg):
                if arg == "/work/findings":
                    return Path(tmpdir) / "findings"
                return Path(arg)

            MockPath.side_effect = path_side_effect

            result = synth_fn(job_id="test-job")

    mock_call_ollama.assert_called_once()
    call_kwargs = mock_call_ollama.call_args[1]
    assert call_kwargs["output_schema"] == SecurityReport
    assert "Manifest Analysis" in call_kwargs["prompt"]
    assert "com.example.testapp" in result


@patch("apk_re.agents.report_synthesizer.server.call_ollama")
def test_handles_missing_findings_gracefully(mock_call_ollama):
    mock_result = SecurityReport(
        app_name="com.example.partial",
        risk_level="medium",
        summary="Partial analysis completed.",
        key_findings=["Only manifest was available"],
    )
    mock_call_ollama.return_value = mock_result

    with tempfile.TemporaryDirectory() as tmpdir:
        job_dir = Path(tmpdir) / "findings" / "partial-job"
        job_dir.mkdir(parents=True)

        # Only create one findings file (the rest are missing)
        (job_dir / "manifest_analyzer.json").write_text(
            json.dumps({"permissions": ["INTERNET"]})
        )

        with patch("apk_re.agents.report_synthesizer.server.Path") as MockPath:
            def path_side_effect(arg):
                if arg == "/work/findings":
                    return Path(tmpdir) / "findings"
                return Path(arg)

            MockPath.side_effect = path_side_effect

            server = create_report_synthesizer_server()
            synth_fn = server._tool_manager._tools["synthesize_report"].fn
            result = synth_fn(job_id="partial-job")

    mock_call_ollama.assert_called_once()
    call_kwargs = mock_call_ollama.call_args[1]
    # Only manifest findings should be in prompt
    assert "Manifest Analysis" in call_kwargs["prompt"]
    assert "Network Mapping" not in call_kwargs["prompt"]


def test_load_findings_skips_missing_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        job_dir = Path(tmpdir)

        # Only create two findings files
        (job_dir / "manifest_analyzer.json").write_text('{"permissions": []}')
        (job_dir / "code_analyzer.json").write_text('{"issues": []}')

        result = _load_findings(job_dir)
        assert "Manifest Analysis" in result
        assert "Code Analysis" in result
        assert "String/Secrets Extraction" not in result
        assert "Network Mapping" not in result
        assert "API Extraction" not in result


def test_load_findings_truncates_large_content():
    with tempfile.TemporaryDirectory() as tmpdir:
        job_dir = Path(tmpdir)

        # Create a very large findings file
        large_content = "x" * 5000
        (job_dir / "manifest_analyzer.json").write_text(large_content)

        result = _load_findings(job_dir)
        assert "... (truncated)" in result
        # Should be truncated to ~3000 chars plus the header
        assert len(result) < 3200

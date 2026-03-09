import json
from unittest.mock import patch, MagicMock

from apk_re.agents.manifest_analyzer.server import create_manifest_analyzer_server, SYSTEM_PROMPT
from apk_re.schemas import ManifestFindings


def test_manifest_analyzer_has_tools():
    server = create_manifest_analyzer_server()
    tool_names = list(server._tool_manager._tools.keys())
    assert "read_file" in tool_names
    assert "analyze_manifest" in tool_names


def test_system_prompt_exists():
    assert "Android" in SYSTEM_PROMPT
    assert len(SYSTEM_PROMPT) > 50


@patch("apk_re.agents.manifest_analyzer.server.Path")
@patch("apk_re.agents.manifest_analyzer.server.call_ollama")
def test_analyze_manifest_calls_ollama(mock_call_ollama, mock_path_cls):
    mock_findings = ManifestFindings(
        permissions=[],
        activities=[],
        services=[],
        receivers=[],
    )
    mock_call_ollama.return_value = mock_findings

    # Mock the Path so the file appears to exist and has content
    mock_path = MagicMock()
    mock_path.is_absolute.return_value = True
    mock_path.exists.return_value = True
    mock_path.read_text.return_value = '<manifest package="com.example"/>'
    mock_path_cls.return_value = mock_path

    server = create_manifest_analyzer_server()
    # Get the analyze_manifest function from the tool manager
    analyze_fn = server._tool_manager._tools["analyze_manifest"].fn

    result = analyze_fn(manifest_path="/work/decompiled/apktool/AndroidManifest.xml")

    mock_call_ollama.assert_called_once()
    call_kwargs = mock_call_ollama.call_args[1]
    assert call_kwargs["output_schema"] == ManifestFindings
    assert "AndroidManifest" in call_kwargs["prompt"] or "manifest" in call_kwargs["prompt"].lower()

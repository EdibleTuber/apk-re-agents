import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apk_re.coordinator.pipeline import Pipeline, PipelineStage
from apk_re.schemas import JobRequest


def test_pipeline_stage_ordering():
    stages = [
        PipelineStage(name="unpack", agents=["unpacker"], parallel=False),
        PipelineStage(name="analyze", agents=["manifest_analyzer", "string_extractor", "network_mapper"], parallel=True),
        PipelineStage(name="code_triage", agents=["code_analyzer"], parallel=False),
    ]
    assert stages[0].name == "unpack"
    assert stages[1].parallel is True
    assert len(stages[1].agents) == 3


def test_pipeline_defines_default_stages():
    pipeline = Pipeline(shared_volume="/tmp/test")
    stage_names = [s.name for s in pipeline.stages]
    assert stage_names == ["unpack", "parallel_analysis", "code_triage", "code_deep", "api_extraction", "report"]


@pytest.mark.asyncio
async def test_pipeline_writes_job_status(tmp_path):
    pipeline = Pipeline(shared_volume=str(tmp_path))
    job = JobRequest(apk_path="/tmp/test.apk", job_id="test-123")

    # Mock the _run_stage method so we don't need real agents
    pipeline._run_stage = AsyncMock()

    await pipeline.run(job)

    status_file = tmp_path / "findings" / "test-123" / "status.json"
    assert status_file.exists()
    status = json.loads(status_file.read_text())
    assert status["job_id"] == "test-123"
    assert status["state"] == "completed"


@pytest.mark.asyncio
async def test_run_stage_passes_stage_name_to_call_agent():
    """_run_stage passes stage.name to _call_agent."""
    pipeline = Pipeline(shared_volume="/tmp/test")
    pipeline._call_agent = AsyncMock()

    stage = PipelineStage(name="code_deep", agents=["code_analyzer"], parallel=False)
    job = JobRequest(apk_path="/tmp/test.apk", job_id="test-1")
    await pipeline._run_stage(stage, job)

    pipeline._call_agent.assert_called_once_with("code_analyzer", job, "code_deep")


@pytest.mark.asyncio
async def test_run_stage_passes_stage_name_parallel():
    """_run_stage passes stage.name in parallel mode too."""
    pipeline = Pipeline(shared_volume="/tmp/test")
    pipeline._call_agent = AsyncMock()

    stage = PipelineStage(name="parallel_analysis", agents=["manifest_analyzer", "string_extractor"], parallel=True)
    job = JobRequest(apk_path="/tmp/test.apk", job_id="test-1")
    await pipeline._run_stage(stage, job)

    calls = pipeline._call_agent.call_args_list
    assert len(calls) == 2
    for call in calls:
        assert call.args[2] == "parallel_analysis"


@pytest.mark.asyncio
async def test_code_deep_saves_to_separate_file(tmp_path):
    """code_deep stage saves findings to code_analyzer_deep.json, not code_analyzer.json."""
    pipeline = Pipeline(shared_volume=str(tmp_path))
    job = JobRequest(apk_path="/tmp/test.apk", job_id="deep-test")

    # Pre-create triage results with one high-score class
    findings_dir = tmp_path / "findings" / "deep-test"
    findings_dir.mkdir(parents=True)
    triage_data = {
        "classes": [
            {"class_name": "com.example.HighScore", "relevance_score": 0.8},
            {"class_name": "com.example.LowScore", "relevance_score": 0.3},
        ]
    }
    (findings_dir / "code_analyzer.json").write_text(json.dumps(triage_data))

    # Mock the MCP session
    mock_session = AsyncMock()
    mock_tool_result = MagicMock()
    mock_tool_result.content = [SimpleNamespace(text='{"analysis": "deep result"}')]
    mock_session.call_tool.return_value = mock_tool_result
    mock_session.list_tools.return_value = SimpleNamespace(
        tools=[SimpleNamespace(name="analyze_class"), SimpleNamespace(name="triage_classes")]
    )
    mock_session.initialize = AsyncMock()

    # Patch sse_client to yield our mock session
    async def fake_sse_client(url):
        # sse_client is used as: async with sse_client(url) as (read, write)
        # Then: async with ClientSession(read, write) as session
        # We need to patch at _execute_agent_tools level instead
        pass

    # Directly test _call_agent by patching sse_client context manager
    with patch("apk_re.coordinator.pipeline.sse_client") as mock_sse, \
         patch("apk_re.coordinator.pipeline.ClientSession") as mock_cs:
        # Set up the nested async context managers
        mock_sse.return_value.__aenter__ = AsyncMock(return_value=(AsyncMock(), AsyncMock()))
        mock_sse.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_cs.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cs.return_value.__aexit__ = AsyncMock(return_value=False)

        await pipeline._call_agent("code_analyzer", job, "code_deep")

    # Should save to code_analyzer_deep.json
    deep_file = findings_dir / "code_analyzer_deep.json"
    assert deep_file.exists(), "code_deep should save to code_analyzer_deep.json"
    deep_data = json.loads(deep_file.read_text())
    assert "deep_analysis" in deep_data

    # Should NOT overwrite triage file
    triage_file = findings_dir / "code_analyzer.json"
    assert json.loads(triage_file.read_text()) == triage_data


@pytest.mark.asyncio
async def test_execute_agent_tools_code_deep_filters_by_score(tmp_path):
    """code_deep only calls analyze_class for classes with relevance_score >= 0.6."""
    pipeline = Pipeline(shared_volume=str(tmp_path))
    job = JobRequest(apk_path="/tmp/test.apk", job_id="filter-test")

    # Set up triage results
    findings_dir = tmp_path / "findings" / "filter-test"
    findings_dir.mkdir(parents=True)
    triage_data = {
        "classes": [
            {"class_name": "com.example.Important", "relevance_score": 0.9},
            {"class_name": "com.example.MediumHigh", "relevance_score": 0.6},
            {"class_name": "com.example.BelowThreshold", "relevance_score": 0.5},
            {"class_name": "com.example.Low", "relevance_score": 0.1},
        ]
    }
    (findings_dir / "code_analyzer.json").write_text(json.dumps(triage_data))

    # Mock session
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.content = [SimpleNamespace(text='{"methods": ["doStuff"]}')]
    mock_session.call_tool.return_value = mock_result

    result = await pipeline._execute_agent_tools(
        mock_session, "code_analyzer", ["analyze_class", "triage_classes"],
        job, stage_name="code_deep"
    )

    # Should only call analyze_class for the 2 classes at or above 0.6
    assert mock_session.call_tool.call_count == 2
    assert len(result["deep_analysis"]) == 2

    # Verify the file paths passed
    call_args = [c.kwargs["arguments"]["file_path"] for c in mock_session.call_tool.call_args_list]
    assert "/work/decompiled/jadx/sources/com/example/Important.java" in call_args
    assert "/work/decompiled/jadx/sources/com/example/MediumHigh.java" in call_args


@pytest.mark.asyncio
async def test_execute_agent_tools_code_deep_no_triage_file(tmp_path):
    """code_deep returns empty list when no triage file exists."""
    pipeline = Pipeline(shared_volume=str(tmp_path))
    job = JobRequest(apk_path="/tmp/test.apk", job_id="no-triage")

    # Don't create triage file
    findings_dir = tmp_path / "findings" / "no-triage"
    findings_dir.mkdir(parents=True)

    mock_session = AsyncMock()
    result = await pipeline._execute_agent_tools(
        mock_session, "code_analyzer", ["analyze_class", "triage_classes"],
        job, stage_name="code_deep"
    )

    assert result == {"deep_analysis": []}
    mock_session.call_tool.assert_not_called()


@pytest.mark.asyncio
async def test_execute_agent_tools_triage_stage_unchanged(tmp_path):
    """code_triage stage still calls triage_classes as before."""
    pipeline = Pipeline(shared_volume=str(tmp_path))
    job = JobRequest(apk_path="/tmp/test.apk", job_id="triage-test")

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.content = [SimpleNamespace(text='{"classes": []}')]
    mock_session.call_tool.return_value = mock_result

    result = await pipeline._execute_agent_tools(
        mock_session, "code_analyzer", ["triage_classes", "analyze_class"],
        job, stage_name="code_triage"
    )

    mock_session.call_tool.assert_called_once_with(
        "triage_classes", arguments={"source_dir": "/work/decompiled/jadx"}
    )
    assert result == {"classes": []}

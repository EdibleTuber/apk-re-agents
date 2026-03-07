import json
from unittest.mock import AsyncMock

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

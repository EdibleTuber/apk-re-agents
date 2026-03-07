import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from apk_re.coordinator.api import create_app


@pytest.fixture
def client():
    app = create_app(shared_volume="/tmp/test_shared")
    return TestClient(app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_submit_job(client):
    with patch("apk_re.coordinator.api.Pipeline") as MockPipeline:
        mock_pipeline = AsyncMock()
        MockPipeline.return_value = mock_pipeline

        response = client.post("/jobs", json={"apk_path": "/data/shared/input/test.apk"})
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["state"] == "pending"


def test_get_job_status(tmp_path):
    # Write a fake status file
    job_dir = tmp_path / "findings" / "test-job-123"
    job_dir.mkdir(parents=True)
    status = {"job_id": "test-job-123", "state": "running", "current_stage": "unpack", "results": None}
    (job_dir / "status.json").write_text(json.dumps(status))

    app = create_app(shared_volume=str(tmp_path))
    test_client = TestClient(app)
    response = test_client.get("/jobs/test-job-123")
    assert response.status_code == 200
    assert response.json()["state"] == "running"


def test_get_missing_job(client):
    response = client.get("/jobs/nonexistent-id")
    assert response.status_code == 404

from __future__ import annotations

import json
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException

from apk_re.coordinator.pipeline import Pipeline
from apk_re.schemas import JobRequest, JobStatus


def create_app(shared_volume: str = "/data/apk_re/shared", agent_urls: dict[str, str] | None = None) -> FastAPI:
    app = FastAPI(title="APK RE Coordinator")
    volume = Path(shared_volume)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/jobs", status_code=202)
    def submit_job(request: JobRequest, background_tasks: BackgroundTasks):
        status = JobStatus(job_id=request.job_id, state="pending")

        # Write initial status
        job_dir = volume / "findings" / request.job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        (job_dir / "status.json").write_text(status.model_dump_json(indent=2))

        # Run pipeline in background
        pipeline = Pipeline(shared_volume=shared_volume, agent_urls=agent_urls)
        background_tasks.add_task(_run_pipeline, pipeline, request)

        return status.model_dump()

    @app.get("/jobs/{job_id}")
    def get_job_status(job_id: str):
        status_file = volume / "findings" / job_id / "status.json"
        if not status_file.exists():
            raise HTTPException(status_code=404, detail="Job not found")
        return json.loads(status_file.read_text())

    return app


async def _run_pipeline(pipeline: Pipeline, job: JobRequest) -> None:
    await pipeline.run(job)

# APK RE Subagent Framework: Scaffolding & Coordinator Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the project scaffolding and coordinator that orchestrates APK reverse engineering subagents running in Docker containers, communicating via MCP over SSE, with Ollama as the inference backend.

**Architecture:** The coordinator runs on the inference server alongside Ollama and manages Docker containers (one per subagent). Each subagent is an MCP server exposing tools over SSE. The coordinator connects as an MCP client, routes tasks through the pipeline, and writes structured JSON results to a shared volume. A lightweight API lets the Pi 5 assistant submit jobs and fetch reports.

**Tech Stack:** Python 3.11+, `mcp` (MCP Python SDK), `ollama` (Ollama Python SDK), `docker` (Docker Python SDK), `pydantic` (structured schemas), `fastapi` + `uvicorn` (coordinator API), `pytest`

---

## Project Structure (Target)

```
apk_re_agents/
├── pyproject.toml
├── docker-compose.yml
├── docs/
│   └── plans/
├── src/
│   └── apk_re/
│       ├── __init__.py
│       ├── config.py              # Settings (Ollama host, paths, model names)
│       ├── schemas.py             # Pydantic models for all inter-agent data
│       ├── coordinator/
│       │   ├── __init__.py
│       │   ├── pipeline.py        # Pipeline orchestration logic
│       │   ├── agent_manager.py   # Docker container lifecycle
│       │   └── api.py             # FastAPI endpoints for Pi 5 client
│       └── agents/
│           ├── base/
│           │   ├── Dockerfile
│           │   ├── requirements.txt
│           │   └── base_agent.py  # Shared MCP server boilerplate
│           ├── unpacker/
│           │   ├── Dockerfile
│           │   ├── requirements.txt
│           │   └── server.py
│           ├── manifest_analyzer/
│           │   ├── Dockerfile
│           │   ├── requirements.txt
│           │   └── server.py
│           ├── string_extractor/
│           │   ├── Dockerfile
│           │   ├── requirements.txt
│           │   └── server.py
│           ├── network_mapper/
│           │   ├── Dockerfile
│           │   ├── requirements.txt
│           │   └── server.py
│           ├── code_analyzer/
│           │   ├── Dockerfile
│           │   ├── requirements.txt
│           │   └── server.py
│           ├── api_extractor/
│           │   ├── Dockerfile
│           │   ├── requirements.txt
│           │   └── server.py
│           └── report_synthesizer/
│               ├── Dockerfile
│               ├── requirements.txt
│               └── server.py
├── tests/
│   ├── conftest.py
│   ├── test_schemas.py
│   ├── test_config.py
│   ├── test_agent_manager.py
│   └── test_pipeline.py
└── shared_volume/                 # Runtime: mounted into containers
    ├── input/                     # APKs go here
    ├── decompiled/                # Unpacker writes here
    └── findings/                  # Each agent writes JSON here
```

---

## Task 1: Project Skeleton and Dependencies

**Files:**
- Create: `pyproject.toml`
- Create: `src/apk_re/__init__.py`
- Create: `src/apk_re/coordinator/__init__.py`

**Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "apk-re-agents"
version = "0.1.0"
description = "APK reverse engineering subagent framework"
requires-python = ">=3.11"
dependencies = [
    "mcp",
    "ollama",
    "docker",
    "pydantic>=2.0",
    "pydantic-settings>=2.0",
    "fastapi",
    "uvicorn[standard]",
]

[project.optional-dependencies]
dev = [
    "pytest",
    "pytest-asyncio",
    "httpx",
]

[project.scripts]
apk-re = "apk_re.main:main"

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

**Step 2: Create the package init files**

```python
# src/apk_re/__init__.py
```

```python
# src/apk_re/coordinator/__init__.py
```

Empty files, just mark the packages.

**Step 3: Create directory structure**

Run:
```bash
mkdir -p src/apk_re/coordinator src/apk_re/agents/base
mkdir -p src/apk_re/agents/{unpacker,manifest_analyzer,string_extractor,network_mapper,code_analyzer,api_extractor,report_synthesizer}
mkdir -p tests
mkdir -p shared_volume/{input,decompiled,findings}
touch src/apk_re/__init__.py src/apk_re/coordinator/__init__.py
touch shared_volume/input/.gitkeep shared_volume/decompiled/.gitkeep shared_volume/findings/.gitkeep
```

**Step 4: Install in dev mode**

Run: `pip install -e ".[dev]"`
Expected: Clean install, no errors.

**Step 5: Commit**

```bash
git init
git add pyproject.toml src/ tests/ shared_volume/ docs/
git commit -m "feat: initial project scaffolding with dependencies"
```

---

## Task 2: Configuration Module

**Files:**
- Create: `src/apk_re/config.py`
- Create: `tests/test_config.py`

**Step 1: Write the failing test**

```python
# tests/test_config.py
from apk_re.config import Settings


def test_default_settings():
    settings = Settings()
    assert settings.ollama_host == "http://localhost:11434"
    assert settings.small_model == "qwen2.5:7b"
    assert settings.large_model == "qwen2.5:32b"
    assert settings.shared_volume.is_absolute()


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://10.0.0.5:11434")
    monkeypatch.setenv("SMALL_MODEL", "mistral:7b")
    settings = Settings()
    assert settings.ollama_host == "http://10.0.0.5:11434"
    assert settings.small_model == "mistral:7b"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError` or `ImportError`

**Step 3: Write minimal implementation**

```python
# src/apk_re/config.py
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ollama_host: str = "http://localhost:11434"
    small_model: str = "qwen2.5:7b"
    large_model: str = "qwen2.5:32b"
    shared_volume: Path = Path("/data/apk_re/shared")
    coordinator_port: int = 8000
    agent_base_port: int = 9000
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_config.py -v`
Expected: PASS (2 tests)

**Step 5: Commit**

```bash
git add src/apk_re/config.py tests/test_config.py
git commit -m "feat: add configuration module with env var support"
```

---

## Task 3: Pydantic Schemas for Inter-Agent Communication

**Files:**
- Create: `src/apk_re/schemas.py`
- Create: `tests/test_schemas.py`

**Step 1: Write the failing tests**

```python
# tests/test_schemas.py
import json
from apk_re.schemas import (
    JobRequest,
    JobStatus,
    ManifestFindings,
    Permission,
    Component,
    StringFinding,
    EndpointFinding,
    CodeAnalysisSummary,
    NetworkFinding,
    AgentResult,
)


def test_job_request_roundtrip():
    job = JobRequest(apk_path="/data/shared/input/test.apk")
    data = job.model_dump_json()
    restored = JobRequest.model_validate_json(data)
    assert restored.apk_path == "/data/shared/input/test.apk"
    assert restored.job_id is not None


def test_manifest_findings_structure():
    findings = ManifestFindings(
        permissions=[Permission(name="android.permission.INTERNET", dangerous=False)],
        activities=[Component(name=".MainActivity", exported=True, intent_filters=["android.intent.action.MAIN"])],
        services=[],
        receivers=[],
    )
    data = json.loads(findings.model_dump_json())
    assert data["permissions"][0]["name"] == "android.permission.INTERNET"
    assert data["activities"][0]["exported"] is True


def test_string_finding():
    finding = StringFinding(
        value="AIzaSyD-example-key",
        category="api_key",
        source_file="com/example/Config.java",
        line_number=42,
        entropy=4.2,
    )
    assert finding.category == "api_key"


def test_endpoint_finding():
    finding = EndpointFinding(
        url="https://api.example.com/v1/users",
        http_method="POST",
        source_class="com.example.ApiClient",
        request_fields={"username": "string", "password": "string"},
        response_fields={"token": "string"},
    )
    assert finding.http_method == "POST"


def test_agent_result_serialization():
    result = AgentResult(
        agent_name="manifest_analyzer",
        job_id="abc-123",
        status="success",
        findings={"permissions_count": 5},
    )
    data = json.loads(result.model_dump_json())
    assert data["agent_name"] == "manifest_analyzer"
    assert data["status"] == "success"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_schemas.py -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

```python
# src/apk_re/schemas.py
from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field


# --- Job lifecycle ---

class JobRequest(BaseModel):
    apk_path: str
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class JobStatus(BaseModel):
    job_id: str
    state: str  # "pending", "running", "completed", "failed"
    current_stage: str | None = None
    results: dict[str, str] | None = None  # agent_name -> findings file path


# --- Manifest ---

class Permission(BaseModel):
    name: str
    dangerous: bool = False


class Component(BaseModel):
    name: str
    exported: bool = False
    intent_filters: list[str] = Field(default_factory=list)


class ManifestFindings(BaseModel):
    permissions: list[Permission] = Field(default_factory=list)
    activities: list[Component] = Field(default_factory=list)
    services: list[Component] = Field(default_factory=list)
    receivers: list[Component] = Field(default_factory=list)


# --- Strings & Secrets ---

class StringFinding(BaseModel):
    value: str
    category: str  # "api_key", "url", "token", "encoded_blob", "other"
    source_file: str
    line_number: int | None = None
    entropy: float | None = None


# --- API Endpoints ---

class EndpointFinding(BaseModel):
    url: str
    http_method: str | None = None
    source_class: str
    request_fields: dict[str, str] = Field(default_factory=dict)
    response_fields: dict[str, str] = Field(default_factory=dict)


# --- Code Analysis ---

class CodeAnalysisSummary(BaseModel):
    class_name: str
    relevance_score: float  # 0.0 to 1.0
    summary: str
    flags: list[str] = Field(default_factory=list)  # "network", "crypto", "storage", etc.


# --- Network ---

class NetworkFinding(BaseModel):
    endpoint: str
    protocol: str  # "https", "http", "wss", etc.
    source_class: str
    cert_pinning: bool = False
    notes: str | None = None


# --- Generic agent result wrapper ---

class AgentResult(BaseModel):
    agent_name: str
    job_id: str
    status: str  # "success", "error"
    error: str | None = None
    findings: dict[str, Any] = Field(default_factory=dict)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_schemas.py -v`
Expected: PASS (5 tests)

**Step 5: Commit**

```bash
git add src/apk_re/schemas.py tests/test_schemas.py
git commit -m "feat: add pydantic schemas for inter-agent communication"
```

---

## Task 4: Agent Manager (Docker Container Lifecycle)

**Files:**
- Create: `src/apk_re/coordinator/agent_manager.py`
- Create: `tests/test_agent_manager.py`

**Step 1: Write the failing tests**

```python
# tests/test_agent_manager.py
from unittest.mock import MagicMock, patch
from apk_re.coordinator.agent_manager import AgentManager, AgentInfo


def test_agent_info_port_assignment():
    info = AgentInfo(name="unpacker", image="agent-unpacker:latest", port=9000)
    assert info.mcp_url == "http://localhost:9000/sse"


def test_agent_manager_registers_agents():
    manager = AgentManager(base_port=9000, shared_volume="/tmp/test_shared")
    manager.register("unpacker", "agent-unpacker:latest")
    manager.register("manifest_analyzer", "agent-manifest:latest")
    assert len(manager.agents) == 2
    assert manager.agents["unpacker"].port == 9000
    assert manager.agents["manifest_analyzer"].port == 9001


@patch("apk_re.coordinator.agent_manager.docker")
def test_start_agent_runs_container(mock_docker):
    mock_client = MagicMock()
    mock_docker.from_env.return_value = mock_client
    mock_container = MagicMock()
    mock_client.containers.run.return_value = mock_container

    manager = AgentManager(base_port=9000, shared_volume="/tmp/test_shared")
    manager.register("unpacker", "agent-unpacker:latest")
    manager.start("unpacker")

    mock_client.containers.run.assert_called_once()
    call_kwargs = mock_client.containers.run.call_args[1]
    assert call_kwargs["detach"] is True
    assert "/tmp/test_shared" in str(call_kwargs["volumes"])


@patch("apk_re.coordinator.agent_manager.docker")
def test_stop_agent_removes_container(mock_docker):
    mock_client = MagicMock()
    mock_docker.from_env.return_value = mock_client
    mock_container = MagicMock()
    mock_client.containers.run.return_value = mock_container

    manager = AgentManager(base_port=9000, shared_volume="/tmp/test_shared")
    manager.register("unpacker", "agent-unpacker:latest")
    manager.start("unpacker")
    manager.stop("unpacker")

    mock_container.stop.assert_called_once()
    mock_container.remove.assert_called_once()
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_agent_manager.py -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

```python
# src/apk_re/coordinator/agent_manager.py
from __future__ import annotations

from dataclasses import dataclass

import docker


@dataclass
class AgentInfo:
    name: str
    image: str
    port: int
    container: object | None = None

    @property
    def mcp_url(self) -> str:
        return f"http://localhost:{self.port}/sse"


class AgentManager:
    def __init__(self, base_port: int = 9000, shared_volume: str = "/data/apk_re/shared"):
        self.base_port = base_port
        self.shared_volume = shared_volume
        self.agents: dict[str, AgentInfo] = {}
        self._next_port = base_port
        self._docker = docker.from_env()

    def register(self, name: str, image: str) -> AgentInfo:
        info = AgentInfo(name=name, image=image, port=self._next_port)
        self.agents[name] = info
        self._next_port += 1
        return info

    def start(self, name: str) -> None:
        agent = self.agents[name]
        container = self._docker.containers.run(
            agent.image,
            detach=True,
            name=f"apk-re-{agent.name}",
            ports={"8080/tcp": agent.port},
            volumes={
                self.shared_volume: {"bind": "/work", "mode": "rw"},
            },
            environment={
                "AGENT_NAME": agent.name,
            },
        )
        agent.container = container

    def stop(self, name: str) -> None:
        agent = self.agents[name]
        if agent.container:
            agent.container.stop(timeout=5)
            agent.container.remove()
            agent.container = None

    def stop_all(self) -> None:
        for name in list(self.agents):
            self.stop(name)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_agent_manager.py -v`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add src/apk_re/coordinator/agent_manager.py tests/test_agent_manager.py
git commit -m "feat: add agent manager for Docker container lifecycle"
```

---

## Task 5: Pipeline Orchestrator

**Files:**
- Create: `src/apk_re/coordinator/pipeline.py`
- Create: `tests/test_pipeline.py`

**Step 1: Write the failing tests**

```python
# tests/test_pipeline.py
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
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_pipeline.py -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

```python
# src/apk_re/coordinator/pipeline.py
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path

from mcp import ClientSession
from mcp.client.sse import sse_client

from apk_re.schemas import JobRequest, JobStatus


@dataclass
class PipelineStage:
    name: str
    agents: list[str]
    parallel: bool = False


class Pipeline:
    def __init__(self, shared_volume: str = "/data/apk_re/shared", agent_urls: dict[str, str] | None = None):
        self.shared_volume = Path(shared_volume)
        self.agent_urls = agent_urls or {}
        self.stages = self._default_stages()

    @staticmethod
    def _default_stages() -> list[PipelineStage]:
        return [
            PipelineStage(name="unpack", agents=["unpacker"], parallel=False),
            PipelineStage(
                name="parallel_analysis",
                agents=["manifest_analyzer", "string_extractor", "network_mapper"],
                parallel=True,
            ),
            PipelineStage(name="code_triage", agents=["code_analyzer"], parallel=False),
            PipelineStage(name="code_deep", agents=["code_analyzer"], parallel=False),
            PipelineStage(name="api_extraction", agents=["api_extractor"], parallel=False),
            PipelineStage(name="report", agents=["report_synthesizer"], parallel=False),
        ]

    async def run(self, job: JobRequest) -> JobStatus:
        job_dir = self.shared_volume / "findings" / job.job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        status = JobStatus(job_id=job.job_id, state="running")

        for stage in self.stages:
            status.current_stage = stage.name
            self._write_status(job_dir, status)
            await self._run_stage(stage, job)

        status.state = "completed"
        status.current_stage = None
        self._write_status(job_dir, status)
        return status

    async def _run_stage(self, stage: PipelineStage, job: JobRequest) -> None:
        if stage.parallel:
            await asyncio.gather(
                *[self._call_agent(agent, job) for agent in stage.agents]
            )
        else:
            for agent in stage.agents:
                await self._call_agent(agent, job)

    async def _call_agent(self, agent_name: str, job: JobRequest) -> None:
        url = self.agent_urls.get(agent_name)
        if not url:
            return

        async with sse_client(url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools = await session.list_tools()
                tool_names = [t.name for t in tools.tools]

                result = await self._execute_agent_tools(session, agent_name, tool_names, job)

                # Write result to shared volume
                findings_dir = self.shared_volume / "findings" / job.job_id
                findings_dir.mkdir(parents=True, exist_ok=True)
                findings_file = findings_dir / f"{agent_name}.json"
                findings_file.write_text(
                    json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
                )

    async def _execute_agent_tools(
        self, session: ClientSession, agent_name: str, tool_names: list[str], job: JobRequest
    ) -> dict:
        """Execute the appropriate tools for each agent type."""
        if agent_name == "unpacker":
            jadx_result = await session.call_tool("run_jadx", arguments={"apk_path": job.apk_path})
            apktool_result = await session.call_tool("run_apktool", arguments={"apk_path": job.apk_path})
            return {"jadx": str(jadx_result), "apktool": str(apktool_result)}
        elif "read_file" in tool_names:
            return {"status": "completed", "agent": agent_name}
        return {}

    def _write_status(self, job_dir: Path, status: JobStatus) -> None:
        status_file = job_dir / "status.json"
        status_file.write_text(status.model_dump_json(indent=2))
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_pipeline.py -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add src/apk_re/coordinator/pipeline.py tests/test_pipeline.py
git commit -m "feat: add pipeline orchestrator with stage execution and MCP client"
```

---

## Task 6: Coordinator API (FastAPI)

**Files:**
- Create: `src/apk_re/coordinator/api.py`
- Create: `tests/test_api.py`

**Step 1: Write the failing tests**

```python
# tests/test_api.py
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
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_api.py -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

```python
# src/apk_re/coordinator/api.py
from __future__ import annotations

import json
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException

from apk_re.coordinator.pipeline import Pipeline
from apk_re.schemas import JobRequest, JobStatus


def create_app(shared_volume: str = "/data/apk_re/shared") -> FastAPI:
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
        pipeline = Pipeline(shared_volume=shared_volume)
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
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_api.py -v`
Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add src/apk_re/coordinator/api.py tests/test_api.py
git commit -m "feat: add FastAPI coordinator API for job submission and status"
```

---

## Task 7: Base Agent MCP Server Template

**Files:**
- Create: `src/apk_re/agents/base/base_agent.py`
- Create: `src/apk_re/agents/base/requirements.txt`
- Create: `tests/test_base_agent.py`

**Step 1: Write the failing test**

```python
# tests/test_base_agent.py
from apk_re.agents.base.base_agent import create_agent_server


def test_create_agent_server_returns_mcp():
    server = create_agent_server("test_agent")
    assert server.name == "test_agent"


def test_agent_server_has_read_file_tool():
    server = create_agent_server("test_agent")
    # FastMCP registers tools internally -- check via the tools dict
    assert "read_file" in server._tool_manager._tools
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_base_agent.py -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

```python
# src/apk_re/agents/base/base_agent.py
from pathlib import Path

from mcp.server.fastmcp import FastMCP


def create_agent_server(name: str) -> FastMCP:
    server = FastMCP(name)

    @server.tool()
    def read_file(file_path: str, start_line: int = 0, max_lines: int = 200) -> str:
        """Read a file from the shared volume.

        Args:
            file_path: Path to the file (relative to /work or absolute).
            start_line: Line number to start reading from (0-indexed).
            max_lines: Maximum number of lines to return.
        """
        path = Path(file_path)
        if not path.is_absolute():
            path = Path("/work") / path
        if not path.exists():
            return f"Error: file not found: {path}"
        lines = path.read_text().splitlines()
        selected = lines[start_line : start_line + max_lines]
        return "\n".join(selected)

    return server
```

```
# src/apk_re/agents/base/requirements.txt
mcp
pydantic>=2.0
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_base_agent.py -v`
Expected: PASS (2 tests). If `_tool_manager._tools` is not the right attribute, check the FastMCP source and adjust accordingly.

**Step 5: Commit**

```bash
git add src/apk_re/agents/base/ tests/test_base_agent.py
git commit -m "feat: add base agent MCP server with read_file tool"
```

---

## Task 8: Unpacker Agent

**Files:**
- Create: `src/apk_re/agents/unpacker/server.py`
- Create: `src/apk_re/agents/unpacker/Dockerfile`
- Create: `src/apk_re/agents/unpacker/requirements.txt`
- Create: `tests/test_unpacker.py`

**Step 1: Write the failing test**

```python
# tests/test_unpacker.py
from apk_re.agents.unpacker.server import create_unpacker_server


def test_unpacker_has_tools():
    server = create_unpacker_server()
    tool_names = list(server._tool_manager._tools.keys())
    assert "read_file" in tool_names
    assert "run_jadx" in tool_names
    assert "run_apktool" in tool_names
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_unpacker.py -v`
Expected: FAIL with `ImportError`

**Step 3: Write minimal implementation**

```python
# src/apk_re/agents/unpacker/server.py
import subprocess
from pathlib import Path

from apk_re.agents.base.base_agent import create_agent_server


def create_unpacker_server():
    server = create_agent_server("unpacker")

    @server.tool()
    def run_jadx(apk_path: str, output_dir: str = "/work/decompiled/jadx") -> str:
        """Decompile an APK using jadx.

        Args:
            apk_path: Path to the APK file.
            output_dir: Directory to write decompiled Java source.
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                ["jadx", "--deobf", "-d", output_dir, apk_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                return f"jadx error: {result.stderr}"
            return f"Decompiled to {output_dir}"
        except FileNotFoundError:
            return "Error: jadx not found in PATH"

    @server.tool()
    def run_apktool(apk_path: str, output_dir: str = "/work/decompiled/apktool") -> str:
        """Decode an APK using apktool (resources + manifest).

        Args:
            apk_path: Path to the APK file.
            output_dir: Directory to write decoded resources.
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                ["apktool", "d", "-f", "-o", output_dir, apk_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                return f"apktool error: {result.stderr}"
            return f"Decoded to {output_dir}"
        except FileNotFoundError:
            return "Error: apktool not found in PATH"

    return server


if __name__ == "__main__":
    server = create_unpacker_server()
    server.run(transport="sse", host="0.0.0.0", port=8080)
```

```dockerfile
# src/apk_re/agents/unpacker/Dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jdk \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install jadx
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip -O /tmp/jadx.zip \
    && unzip /tmp/jadx.zip -d /opt/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip

# Install apktool
RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool \
    && wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O /usr/local/bin/apktool.jar

WORKDIR /app
COPY src/apk_re/agents/base/base_agent.py ./apk_re/agents/base/base_agent.py
COPY src/apk_re/agents/base/__init__.py ./apk_re/agents/base/__init__.py
COPY src/apk_re/agents/unpacker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/apk_re/agents/unpacker/server.py .

EXPOSE 8080
CMD ["python", "server.py"]
```

```
# src/apk_re/agents/unpacker/requirements.txt
mcp
pydantic>=2.0
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_unpacker.py -v`
Expected: PASS (1 test)

**Step 5: Commit**

```bash
git add src/apk_re/agents/unpacker/ tests/test_unpacker.py
git commit -m "feat: add unpacker agent with jadx and apktool tools"
```

---

## Task 9: Docker Compose for Multi-Container Setup

**Files:**
- Create: `docker-compose.yml`

**Step 1: Write docker-compose.yml**

```yaml
# docker-compose.yml
services:
  coordinator:
    build:
      context: .
      dockerfile: Dockerfile.coordinator
    ports:
      - "${COORDINATOR_PORT:-8000}:8000"
    volumes:
      - shared_data:/data/apk_re/shared
    environment:
      - OLLAMA_HOST=${OLLAMA_HOST:-http://host.docker.internal:11434}
      - SHARED_VOLUME=/data/apk_re/shared
    depends_on:
      - unpacker
      - manifest_analyzer
      - string_extractor
      - network_mapper
      - code_analyzer
      - api_extractor
      - report_synthesizer

  unpacker:
    build:
      context: .
      dockerfile: src/apk_re/agents/unpacker/Dockerfile
    ports:
      - "9000:8080"
    volumes:
      - shared_data:/work

  manifest_analyzer:
    build:
      context: .
      dockerfile: src/apk_re/agents/manifest_analyzer/Dockerfile
    ports:
      - "9001:8080"
    volumes:
      - shared_data:/work

  string_extractor:
    build:
      context: .
      dockerfile: src/apk_re/agents/string_extractor/Dockerfile
    ports:
      - "9002:8080"
    volumes:
      - shared_data:/work

  network_mapper:
    build:
      context: .
      dockerfile: src/apk_re/agents/network_mapper/Dockerfile
    ports:
      - "9003:8080"
    volumes:
      - shared_data:/work

  code_analyzer:
    build:
      context: .
      dockerfile: src/apk_re/agents/code_analyzer/Dockerfile
    ports:
      - "9004:8080"
    volumes:
      - shared_data:/work

  api_extractor:
    build:
      context: .
      dockerfile: src/apk_re/agents/api_extractor/Dockerfile
    ports:
      - "9005:8080"
    volumes:
      - shared_data:/work

  report_synthesizer:
    build:
      context: .
      dockerfile: src/apk_re/agents/report_synthesizer/Dockerfile
    ports:
      - "9006:8080"
    volumes:
      - shared_data:/work

volumes:
  shared_data:
```

**Step 2: Validate syntax**

Run: `docker compose config --quiet`
Expected: No errors (will warn about missing Dockerfiles for agents not yet created, that's fine)

**Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "feat: add docker-compose for multi-container agent setup"
```

---

## Task 10: Coordinator Entrypoint

**Files:**
- Create: `src/apk_re/main.py`

**Step 1: Write the entrypoint**

```python
# src/apk_re/main.py
import uvicorn

from apk_re.config import Settings
from apk_re.coordinator.api import create_app


def main():
    settings = Settings()
    app = create_app(shared_volume=str(settings.shared_volume))
    uvicorn.run(app, host="0.0.0.0", port=settings.coordinator_port)


if __name__ == "__main__":
    main()
```

**Step 2: Test it starts**

Run: `python -m apk_re.main &` then `curl http://localhost:8000/health` then kill the process.
Expected: `{"status":"ok"}`

**Step 3: Commit**

```bash
git add src/apk_re/main.py
git commit -m "feat: add coordinator entrypoint with uvicorn"
```

---

## Summary

| Task | What it builds | Tests |
|------|---------------|-------|
| 1 | Project skeleton, pyproject.toml, directories | - |
| 2 | Config module (Settings with env vars) | 2 |
| 3 | Pydantic schemas for all inter-agent data | 5 |
| 4 | Agent manager (Docker container lifecycle) | 4 |
| 5 | Pipeline orchestrator (stage execution + MCP client) | 3 |
| 6 | FastAPI coordinator API | 4 |
| 7 | Base agent MCP server template | 2 |
| 8 | Unpacker agent (jadx + apktool) | 1 |
| 9 | Docker Compose | - |
| 10 | Coordinator entrypoint | manual |

**Total: 10 tasks, ~21 tests**

After these tasks you'll have a working coordinator that accepts APK analysis jobs via HTTP, manages subagent Docker containers, communicates with them over MCP/SSE, and writes structured findings to a shared volume. The remaining agents (manifest_analyzer, string_extractor, network_mapper, code_analyzer, api_extractor, report_synthesizer) follow the same pattern as the unpacker and can be added incrementally.

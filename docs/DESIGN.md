# APK RE Agents -- Design Document

## What This Is

An automated APK reverse engineering pipeline. You submit an APK, it gets decompiled and analyzed by a team of specialized subagents, and you get back a structured report covering permissions, API endpoints, hardcoded secrets, network behavior, and code-level findings.

The system runs entirely on the inference server (colocated with Ollama). A lightweight API lets external clients (like pi-mono on the Pi 5) submit jobs and check results.

## System Architecture

```
                        Inference Server
 +---------------------------------------------------------+
 |                                                         |
 |   Coordinator (FastAPI, port 8000)                      |
 |     |                                                   |
 |     |-- POST /jobs       Submit APK for analysis        |
 |     |-- GET  /jobs/{id}  Check job status / get report  |
 |     |-- GET  /health     Health check                   |
 |     |                                                   |
 |     +-- Pipeline Orchestrator                           |
 |           |                                             |
 |           |  MCP/SSE connections                        |
 |           |                                             |
 |   +-------+-------+-------+-------+----+----+----+     |
 |   |       |       |       |       |    |    |    |     |
 |   v       v       v       v       v    v    v    v     |
 |  [unpack][manifest][string][network][code][api][report] |
 |   :9000   :9001    :9002   :9003   :9004 :9005 :9006   |
 |                                                         |
 |   Each agent = Docker container + MCP server            |
 |                                                         |
 |   Ollama (port 11434) <--- agents call for inference    |
 |                                                         |
 |   /data/apk_re/shared  <--- shared Docker volume       |
 |     /input/             APKs staged here                |
 |     /decompiled/        jadx + apktool output           |
 |     /findings/{job_id}/ Per-job JSON results            |
 |                                                         |
 +---------------------------------------------------------+
         ^
         |  HTTP (submit APK, poll status, get report)
         |
     Pi 5 (pi-mono)
```

## How a Job Runs

1. **Client submits an APK** via `POST /jobs` with `{"apk_path": "/data/apk_re/shared/input/some.apk"}`. Gets back a `job_id` immediately (HTTP 202).

2. **Pipeline runs in background** through 6 stages:

```
Stage 1: unpack (sequential)
  unpacker -> runs jadx + apktool, writes to /decompiled/

Stage 2: parallel_analysis (concurrent)
  manifest_analyzer  \
  string_extractor    }-- all run simultaneously
  network_mapper     /

Stage 3: code_triage (sequential)
  code_analyzer -> scores every class by relevance

Stage 4: code_deep (sequential)
  code_analyzer -> deep analysis on high-signal classes

Stage 5: api_extraction (sequential)
  api_extractor -> pulls endpoint URLs, methods, schemas

Stage 6: report (sequential)
  report_synthesizer -> combines all findings into final report
```

3. **Each stage writes findings** to `/data/apk_re/shared/findings/{job_id}/{agent_name}.json`.

4. **Client polls** `GET /jobs/{job_id}` to check progress. Status includes `state` (pending/running/completed/failed) and `current_stage`.

## Component Details

### Coordinator (`src/apk_re/coordinator/`)

**api.py** -- FastAPI application factory. Three endpoints:
- `GET /health` -- returns `{"status": "ok"}`
- `POST /jobs` -- accepts `JobRequest`, writes initial status, kicks off pipeline in background
- `GET /jobs/{job_id}` -- reads `status.json` from disk, returns current state

**pipeline.py** -- Orchestrates the 6-stage pipeline. Each stage has:
- A list of agents to invoke
- A `parallel` flag (if true, agents run concurrently via `asyncio.gather`)

The pipeline connects to each agent via MCP over SSE (`mcp.client.sse.sse_client`), discovers available tools, and calls the appropriate ones. Results get written to the shared volume as JSON.

**agent_manager.py** -- Manages Docker container lifecycle. Handles:
- Registering agents (name + image + auto-assigned port)
- Starting containers with shared volume mount
- Stopping and removing containers

### Agents (`src/apk_re/agents/`)

Each agent is a Docker container running an MCP server over SSE on port 8080 (mapped to host ports 9000-9006).

**Base agent** (`agents/base/base_agent.py`) -- Factory function `create_agent_server(name)` that returns a FastMCP instance with a `read_file` tool pre-registered. All agents inherit this.

**Unpacker** (`agents/unpacker/server.py`) -- Extends base agent with:
- `run_jadx` -- decompiles APK to Java source (with deobfuscation)
- `run_apktool` -- decodes APK resources and manifest

The remaining agents (manifest_analyzer, string_extractor, network_mapper, code_analyzer, api_extractor, report_synthesizer) are not yet implemented. They follow the same pattern: extend base agent, add task-specific tools.

### Configuration (`src/apk_re/config.py`)

All settings via environment variables (no hardcoded IPs):

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama inference endpoint |
| `SMALL_MODEL` | `qwen2.5:7b` | Model for execution agents |
| `LARGE_MODEL` | `qwen2.5:32b` | Model for report synthesis |
| `SHARED_VOLUME` | `/data/apk_re/shared` | Shared volume path |
| `COORDINATOR_PORT` | `8000` | Coordinator API port |
| `AGENT_BASE_PORT` | `9000` | First agent port (auto-increments) |

### Data Schemas (`src/apk_re/schemas.py`)

All inter-agent communication uses Pydantic models serialized as JSON:

- **JobRequest** -- `apk_path` + auto-generated `job_id`
- **JobStatus** -- `job_id`, `state`, `current_stage`, `results`
- **ManifestFindings** -- permissions, activities, services, receivers
- **StringFinding** -- value, category (api_key/url/token/encoded_blob), source file, entropy
- **EndpointFinding** -- URL, HTTP method, source class, request/response field shapes
- **CodeAnalysisSummary** -- class name, relevance score, summary, flags
- **NetworkFinding** -- endpoint, protocol, cert pinning, source class
- **AgentResult** -- generic wrapper (agent name, job ID, status, findings dict)

## Communication Flow

```
Coordinator                          Agent Container
    |                                      |
    |-- SSE connect to :port/sse --------->|
    |<--------- SSE session established ---|
    |                                      |
    |-- initialize() -------------------->|
    |<--------- capabilities --------------|
    |                                      |
    |-- list_tools() -------------------->|
    |<--------- [read_file, run_jadx, ...]-|
    |                                      |
    |-- call_tool("run_jadx", {args}) ---->|
    |<--------- result --------------------|
    |                                      |
    |-- (write result to shared volume)    |
    |-- (close SSE connection)             |
```

The coordinator is the MCP **client**. Each agent is an MCP **server**. The coordinator decides what tools to call and in what order -- agents don't make decisions, they just execute.

## Shared Volume Layout

```
/data/apk_re/shared/
  input/
    some-app.apk              # APK to analyze
  decompiled/
    jadx/                     # jadx Java output
      com/example/app/
        MainActivity.java
        ...
    apktool/                  # apktool decoded output
      AndroidManifest.xml
      res/
      smali/
  findings/
    {job_id}/
      status.json             # Pipeline progress
      unpacker.json           # Unpacker results
      manifest_analyzer.json  # Manifest analysis
      string_extractor.json   # Secrets/strings found
      network_mapper.json     # Network behavior
      code_analyzer.json      # Code analysis
      api_extractor.json      # API endpoints
      report_synthesizer.json # Final report
```

## Docker Setup

`docker-compose.yml` defines 8 services:
- 1 coordinator (port 8000)
- 7 agents (ports 9000-9006)
- All share a `shared_data` Docker volume mounted at `/work` (agents) or `/data/apk_re/shared` (coordinator)

Each agent has its own Dockerfile in `src/apk_re/agents/{name}/Dockerfile`. The unpacker's Dockerfile includes jadx 1.5.1 and apktool 2.9.3 with a JDK.

## Current State

**Implemented:**
- Coordinator (API + pipeline + agent manager)
- All data schemas
- Configuration with env vars
- Base agent MCP template
- Unpacker agent (with Dockerfile)
- Docker Compose topology
- 21 passing tests

**Not yet implemented:**
- 6 remaining agents (manifest_analyzer, string_extractor, network_mapper, code_analyzer, api_extractor, report_synthesizer)
- Ollama inference integration within agents
- Coordinator Dockerfile (`Dockerfile.coordinator`)
- Error handling / retry logic in pipeline
- Authentication on the coordinator API

## Running Locally (Minimal Test)

To test the coordinator + unpacker without Docker:

```bash
# Terminal 1: Start the unpacker agent
cd /path/to/apk_re_agents
.venv/bin/python -m apk_re.agents.unpacker.server

# Terminal 2: Start the coordinator
SHARED_VOLUME=/tmp/apk_re_test .venv/bin/python -m apk_re.main

# Terminal 3: Submit a job
curl -X POST http://localhost:8000/jobs \
  -H "Content-Type: application/json" \
  -d '{"apk_path": "/tmp/apk_re_test/input/test.apk"}'

# Check status
curl http://localhost:8000/jobs/{job_id}
```

## Running with Docker

```bash
# Set your Ollama host
export OLLAMA_HOST=http://localhost:11434

# Build and start (only unpacker works currently)
docker compose up --build unpacker

# Or start everything (agents without Dockerfiles will fail)
docker compose up --build
```

# APK RE Agents -- Design Document

## What This Is

An automated APK reverse engineering pipeline. You submit an APK, it gets decompiled and analyzed by a team of specialized subagents, and you get back a structured report covering permissions, API endpoints, hardcoded secrets, network behavior, and code-level findings.

The system runs entirely on the inference server (colocated with Ollama). A lightweight API lets external clients (like pi-mono on the Pi 5) submit jobs and check results.

## Core Hypothesis

Small local models (7B parameters) can handle targeted security extraction tasks when given narrow prompts and structured output schemas. The Manifest Analyzer proved this -- qwen2.5-coder:7b correctly extracts permissions, activities, services, and receivers from AndroidManifest.xml with Pydantic-enforced JSON output.

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
 |   /work  <--- shared Docker volume                      |
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

1. **Client submits an APK** via `POST /jobs` with `{"apk_path": "/work/input/some.apk"}`. Gets back a `job_id` immediately (HTTP 202).

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

3. **Each stage writes findings** to `/work/findings/{job_id}/{agent_name}.json`.

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

**Base agent** (`agents/base/base_agent.py`) -- Provides two building blocks:
- `create_agent_server(name)` -- factory that returns a FastMCP instance with a `read_file` tool pre-registered
- `call_ollama(prompt, output_schema, ...)` -- calls Ollama with a Pydantic JSON schema for structured output, returns a validated model instance

**Unpacker** (`agents/unpacker/server.py`) -- Pure tooling, no LLM. Extends base agent with:
- `run_jadx` -- decompiles APK to Java source (with deobfuscation)
- `run_apktool` -- decodes APK resources and manifest

**Manifest Analyzer** (`agents/manifest_analyzer/server.py`) -- LLM-powered (qwen2.5-coder:7b). Reads AndroidManifest.xml and uses Ollama to extract structured security findings:
- Permissions with dangerous/normal classification
- Activities, services, and receivers with exported status and intent filters
- Uses a baked-in system prompt with the full Android dangerous permissions list

**String Extractor** (`agents/string_extractor/server.py`) -- Pure regex, no LLM. Scans decompiled Java source for:
- URLs (filtering Android/W3C/Apache false positives)
- API keys with known prefixes (Google `AIza`, OpenAI `sk-`, AWS `AKIA`, GitHub `ghp_`, GitLab `glpat-`)
- JWT tokens (`eyJ...eyJ...` pattern)
- Base64 encoded blobs (20+ chars, entropy > 3.5)
- Generic high-entropy string literals (entropy > 4.0)
- Calculates Shannon entropy for each finding to help identify secrets
- Caps at 200 findings, skips files over 1MB

### Ollama Integration

Inference happens agent-side. Each agent container that needs LLM has its own Ollama client, connects directly to the Ollama server, and handles all reasoning internally. The coordinator only tells agents *what* to analyze, not *how*.

```
Coordinator                    Agent Container
    |                               |
    |-- call_tool("analyze_*") ---->|
    |                               |-- read file from /work
    |                               |-- build prompt (baked-in template)
    |                               |-- ollama.chat(model, prompt, format=schema)
    |                               |-- validate response with Pydantic
    |<---- structured JSON ---------│
```

Key constraints:
- One inference call per tool invocation (no multi-turn chatter)
- Prompt templates are constants baked into the agent code
- Structured output enforced via Pydantic JSON schema passed to Ollama
- Agent reads its own files -- coordinator does not pass file content over MCP

### Configuration (`src/apk_re/config.py`)

All settings via environment variables (no hardcoded IPs):

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama inference endpoint |
| `SMALL_MODEL` | `qwen2.5-coder:7b` | Model for extraction agents |
| `LARGE_MODEL` | `qwen2.5-coder:32b-instruct-q4_K_M` | Model for report synthesis |
| `SHARED_VOLUME` | `/data/apk_re/shared` | Shared volume path |
| `COORDINATOR_PORT` | `8000` | Coordinator API port |
| `AGENT_BASE_PORT` | `9000` | First agent port (auto-increments) |

In Docker, set `OLLAMA_HOST` via a `.env` file in the project root (gitignored). Docker Compose reads it automatically.

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
/work/
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

`docker-compose.yml` defines services sharing a `shared_data` Docker volume mounted at `/work` across all containers.

Each agent has its own Dockerfile in `src/apk_re/agents/{name}/Dockerfile`. The unpacker's Dockerfile includes jadx 1.5.1 and apktool 2.9.3 with a JDK. LLM-powered agents include the `ollama` Python SDK.

Containers that need to reach Ollama on the host use `extra_hosts: host.docker.internal:host-gateway` for Linux compatibility.

## Model Allocation

| Agent | Model | Rationale |
|-------|-------|-----------|
| Unpacker | none | Pure tooling (jadx + apktool) |
| Manifest Analyzer | qwen2.5-coder:7b | Structured extraction, small context |
| String Extractor | none | Pure regex + entropy |
| Network Mapper | qwen2.5-coder:7b | Pattern recognition in code |
| Code Analyzer | qwen2.5-coder:7b or 14b | May need more capacity for reasoning |
| API Extractor | qwen2.5-coder:7b | Structured extraction from code |
| Report Synthesizer | qwen2.5-coder:32b | Needs coherent long-form reasoning |

## Current State

**Implemented and tested (44 tests):**
- Coordinator (API + pipeline orchestrator + agent manager)
- All data schemas
- Configuration with env vars
- Base agent with MCP template + Ollama helper
- Unpacker agent (jadx + apktool, with Dockerfile)
- Manifest Analyzer agent (LLM-powered, with Dockerfile)
- String Extractor agent (regex-based, with Dockerfile)
- Docker Compose with coordinator + 3 active agents
- End-to-end pipeline tested with real APK on inference server

**Not yet implemented:**
- Network Mapper agent
- Code Analyzer agent
- API Extractor agent
- Report Synthesizer agent
- Error handling / retry logic in pipeline
- Authentication on the coordinator API

## Running with Docker

```bash
# Create .env with your Ollama host
echo "OLLAMA_HOST=http://192.168.1.14:11434" > .env

# Build and start
docker compose up --build

# Force full rebuild (no cache)
docker compose build --no-cache && docker compose up

# Submit a job
docker compose exec coordinator mkdir -p /work/input
docker compose cp some-app.apk coordinator:/work/input/
curl -X POST http://localhost:8000/jobs \
  -H "Content-Type: application/json" \
  -d '{"apk_path": "/work/input/some-app.apk"}'

# Check results
curl http://localhost:8000/jobs/{job_id}
```

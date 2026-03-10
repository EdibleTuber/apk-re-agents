# APK RE Agents -- Quick Reference

## Build & Run

```bash
# Build and start everything
docker compose up --build

# Build and start in background
docker compose up --build -d

# Force full rebuild (no cache)
docker compose build --no-cache && docker compose up

# Stop everything
docker compose down

# Rebuild a single service
docker compose up --build unpacker
```

## Submit & Monitor Jobs

```bash
# Health check
curl http://localhost:8000/health

# Submit a job
curl -X POST http://localhost:8000/jobs \
  -H "Content-Type: application/json" \
  -d '{"apk_path": "/work/input/some-app.apk"}'

# Check job status (replace JOB_ID)
curl http://localhost:8000/jobs/JOB_ID
```

## Copy APKs Into the Shared Volume

```bash
# From host into running coordinator container
docker compose exec coordinator mkdir -p /work/input
docker compose cp some-app.apk coordinator:/work/input/
```

## Inspect Shared Volume (Forensics)

```bash
# List decompiled output
docker compose exec coordinator ls /work/decompiled/
docker compose exec coordinator ls /work/decompiled/jadx/
docker compose exec coordinator ls /work/decompiled/apktool/

# Read unpacker findings
docker compose exec coordinator cat /work/findings/JOB_ID/unpacker.json

# Read manifest analyzer findings
docker compose exec coordinator cat /work/findings/JOB_ID/manifest_analyzer.json

# Read string extractor findings
docker compose exec coordinator cat /work/findings/JOB_ID/string_extractor.json

# Read network mapper findings
docker compose exec coordinator cat /work/findings/JOB_ID/network_mapper.json

# Read code analyzer findings
docker compose exec coordinator cat /work/findings/JOB_ID/code_analyzer.json

# Read API extractor findings
docker compose exec coordinator cat /work/findings/JOB_ID/api_extractor.json

# Read job status
docker compose exec coordinator cat /work/findings/JOB_ID/status.json

# List all findings for a job
docker compose exec coordinator ls /work/findings/JOB_ID/

# Browse the decompiled manifest
docker compose exec coordinator cat /work/decompiled/apktool/AndroidManifest.xml
```

## Container Debugging

```bash
# Check running containers
docker compose ps

# View logs (all services)
docker compose logs

# View logs (single service, follow)
docker compose logs -f unpacker
docker compose logs -f coordinator
docker compose logs -f manifest_analyzer
docker compose logs -f string_extractor
docker compose logs -f network_mapper
docker compose logs -f code_analyzer
docker compose logs -f api_extractor

# Shell into a container
docker compose exec coordinator bash
docker compose exec unpacker bash

# Check if agent MCP endpoint is responding (from inside coordinator)
docker compose exec coordinator curl http://unpacker:8080/sse
```

## Environment Setup

Create a `.env` file in the project root (gitignored):

```bash
# Point to your Ollama instance
echo "OLLAMA_HOST=http://192.168.1.14:11434" > .env
```

Docker Compose reads this automatically. If Ollama is on the same machine, `host.docker.internal:11434` works too.

## Run Tests (Local, No Docker)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

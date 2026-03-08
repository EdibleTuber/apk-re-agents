# APK Reverse Engineering Subagent Framework

## Architecture Overview

Coordinator runs on a Pi 5 via a custom API layer. Subagents run as micro Docker containers on a separate inference server. Inference via Ollama on a Tesla P40 (24GB VRAM). Two models loaded: one small fast model for execution subagents (Qwen2.5 7B or Mistral 7B), one larger model for synthesis.

Communication: coordinator talks to each subagent's MCP endpoint. Decompiled output lives on a shared volume -- subagents reference file paths, not raw source, to keep message payloads small.

---

## Subagent Definitions

### 1. Unpacker
Tools: `run_jadx`, `run_apktool`
Input: APK path
Output: decompiled file tree written to shared volume
Notes: jadx for Java output, apktool for resources and manifest reliability. Runs first, blocks all downstream agents.

### 2. Manifest Analyzer
Tools: `read_file`
Input: path to `AndroidManifest.xml`
Output: structured JSON -- permissions, activities, services, receivers, intent filters
Notes: low ambiguity task, small model handles cleanly.

### 3. Code Analyzer
Tools: `read_file`
Input: one class at a time from shared volume
Output: per-class relevance score + summary (triage mode), or deep analysis on high-signal classes
Notes: coordinator does first-pass index (file tree + class names + package structure) and prioritizes entry points, network/crypto/storage-touching classes, non-standard-library namespaces. Triage pass first, deep pass on flagged classes.

### 4. API Endpoint & Schema Extractor
Tools: `read_file`
Input: one class at a time
Output: structured findings per class -- endpoint, HTTP method, expected request/response payload shape
Notes: extraction not reasoning, small model handles well with tight prompt.

### 5. String & Secret Extractor
Tools: regex scan, entropy analysis
Input: decompiled source on shared volume
Output: flagged strings -- API keys, URLs, tokens, encoded blobs
Notes: may not need an LLM at all, could be pure tooling.

### 6. Network Traffic Mapper
Tools: `read_file`
Input: relevant classes from shared volume
Output: endpoint list, protocols, certificate pinning logic
Notes: runs in parallel with manifest analyzer and string extractor after unpack completes.

### 7. Report Synthesizer
Tools: `read_file`
Input: structured output files written by all prior subagents
Model: larger model (better reasoning for coherent narrative)
Output: final report
Notes: reads from shared volume, not passed data through coordinator.

---

## Execution Order

```
Unpacker
    |
    +---> Manifest Analyzer  \
    +---> String Extractor    +--> (parallel, no interdependency)
    +---> Network Mapper     /
    |
    +---> Code Analyzer (triage pass)
              |
              +---> Code Analyzer (deep pass, flagged classes)
                        |
                        +---> API Endpoint Extractor
                                    |
                              Report Synthesizer
```

---

## Design Principles

- Each subagent has 1-3 tools maximum, scoped to its task only.
- Coordinator handles decomposition, routing, and synthesis decisions -- not subagents.
- Subagents receive only the context slice relevant to their task, not full conversation history.
- Structured output (JSON) enforced at subagent boundaries where possible.
- Shared volume is working memory across the pipeline; coordinator reads findings files to decide next steps.
- No round-trip chatter -- batch what coordinator sends to reduce Pi-to-inference-server latency.

---

## Model Allocation

| Subagent | Model |
|---|---|
| Unpacker | small (tool use only) |
| Manifest Analyzer | small |
| String Extractor | none / small |
| Network Mapper | small |
| Code Analyzer (triage) | small |
| Code Analyzer (deep) | small |
| API Endpoint Extractor | small |
| Report Synthesizer | larger |

---

## Benchmark

Target APK has prior manual RE work as reference. Validation: diff pipeline output against manually identified logic, API endpoints, and JSON schemas. Measures signal coverage and false negative rate.

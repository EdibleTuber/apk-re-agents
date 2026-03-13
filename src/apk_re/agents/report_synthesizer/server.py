import json
import os
from pathlib import Path

import anyio

from pydantic import BaseModel, Field

from apk_re.agents.base.base_agent import create_agent_server, call_ollama

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.environ.get("MODEL_NAME", "qwen2.5-coder:7b")

SYSTEM_PROMPT = """You are a senior Android security analyst writing a final security assessment report.
You are given findings from multiple analysis tools that examined a decompiled Android APK.

Synthesize all findings into a coherent security report:

- app_name: The app's package name or display name if identifiable from the findings
- risk_level: Overall risk assessment (low/medium/high/critical) based on the severity of findings
- summary: 2-3 sentence executive summary of the security posture
- key_findings: Top 5-10 most important security findings, each as a clear statement
- permissions_analysis: Assessment of the app's permission usage and any dangerous permissions
- network_analysis: Assessment of network behavior, endpoints, cert pinning, and SSL/TLS usage
- secrets_analysis: Assessment of any hardcoded secrets, API keys, tokens found in the code
- code_analysis: Assessment of security-relevant code patterns and potential vulnerabilities
- recommendations: Actionable security recommendations based on findings

Be concise but thorough. Focus on security implications, not implementation details.
Prioritize findings by severity. Flag anything that could be exploited."""


class SecurityReport(BaseModel):
    app_name: str = ""
    risk_level: str = "unknown"  # "low", "medium", "high", "critical"
    summary: str = ""
    key_findings: list[str] = Field(default_factory=list)
    permissions_analysis: str = ""
    network_analysis: str = ""
    secrets_analysis: str = ""
    code_analysis: str = ""
    recommendations: list[str] = Field(default_factory=list)


# Per-section character budget for the synthesis prompt.
# Smart selection (not blind truncation) fills each slot.
_SECTION_BUDGETS = {
    "manifest_analyzer":  4000,   # small file, pass most of it
    "network_mapper":     4000,   # real endpoints only
    "code_analyzer":      5000,   # top classes by relevance_score
    "api_extractor":      8000,   # top endpoints, ergatta/first-party first
    "string_extractor":   4000,   # top findings by entropy
    "mobsf_analyzer":     4000,   # cert + apkid + niap + vuln libs
}


def _select_manifest(data: dict) -> dict:
    """Pass manifest through as-is — it's always small."""
    return data


def _select_network(data: dict) -> dict:
    """Real (non-unknown) endpoints first, unknown ones dropped."""
    findings = data.get("findings", [])
    real = [f for f in findings if f.get("endpoint", "unknown") != "unknown"]
    data["findings"] = real
    return data


def _select_code(data: dict) -> dict:
    """Sort classes by relevance_score descending, keep top 25."""
    classes = data.get("classes", [])
    classes.sort(key=lambda c: c.get("relevance_score", 0), reverse=True)
    data["classes"] = classes[:25]
    return data


def _select_apis(data: dict) -> dict:
    """Sort endpoints: resolved base_url first, then by header richness,
    then by source class depth. Keep top 60."""
    endpoints = data.get("endpoints", [])
    endpoints.sort(key=lambda e: (
        e.get("base_url") is not None,
        len(e.get("headers", {})) > 0,
        len(e.get("query_params", [])) + len(e.get("path_params", [])),
        e.get("source_class", "").count("."),
    ), reverse=True)
    data["endpoints"] = endpoints[:60]
    # base_urls is small, keep as-is
    return data


def _select_strings(data: list) -> list:
    """Sort by entropy descending, keep top 50."""
    data.sort(key=lambda f: f.get("entropy") or 0.0, reverse=True)
    return data[:50]


def _select_mobsf(data: dict) -> dict:
    """Keep only the fields that add value over our own agents:
    cert, apkid, niap, vulnerable_libraries, manifest_issues summary."""
    return {
        k: data[k] for k in (
            "app_name", "package_name", "version", "min_sdk", "target_sdk",
            "certificate", "apkid", "vulnerable_libraries",
            "niap_findings", "manifest_issues",
        ) if k in data
    }


_SELECTORS = {
    "manifest_analyzer": ("Manifest Analysis",    _select_manifest),
    "network_mapper":    ("Network Mapping",       _select_network),
    "code_analyzer":     ("Code Analysis",         _select_code),
    "api_extractor":     ("API Extraction",        _select_apis),
    "string_extractor":  ("String/Secrets",        _select_strings),
    "mobsf_analyzer":    ("MobSF Pre-scan",        _select_mobsf),
}


def _load_findings(job_dir: Path) -> str:
    sections: list[str] = []
    for agent_name, (label, selector) in _SELECTORS.items():
        filepath = job_dir / f"{agent_name}.json"
        if not filepath.exists():
            continue
        try:
            raw = filepath.read_text()
            data = json.loads(raw)
        except Exception:
            continue

        try:
            selected = selector(data)
            content = json.dumps(selected, indent=2)
        except Exception:
            content = raw

        budget = _SECTION_BUDGETS.get(agent_name, 3000)
        if len(content) > budget:
            content = content[:budget] + "\n... (truncated)"

        sections.append(f"## {label}\n{content}")

    return "\n\n".join(sections)


def create_report_synthesizer_server():
    server = create_agent_server("report_synthesizer")

    def _synthesize_report_impl(job_id: str) -> str:
        job_dir = Path("/work/findings") / job_id
        if not job_dir.exists():
            return f"Error: findings directory not found: {job_dir}"

        findings_text = _load_findings(job_dir)
        if not findings_text:
            return SecurityReport(
                summary="No findings available. All analysis agents either failed or produced no output.",
                risk_level="unknown",
            ).model_dump_json(indent=2)

        prompt = (
            "Synthesize the following analysis findings into a security report:\n\n"
            + findings_text
        )

        result = call_ollama(
            prompt=prompt,
            output_schema=SecurityReport,
            ollama_host=OLLAMA_HOST,
            model=MODEL_NAME,
            system_prompt=SYSTEM_PROMPT,
        )
        return result.model_dump_json(indent=2)

    @server.tool()
    async def synthesize_report(job_id: str) -> str:
        """Synthesize a security analysis report from all agent findings.

        Args:
            job_id: The job identifier used to locate findings under /work/findings/{job_id}/.
        """
        return await anyio.to_thread.run_sync(_synthesize_report_impl, job_id)

    return server


if __name__ == "__main__":
    server = create_report_synthesizer_server()
    server.run(transport="sse")

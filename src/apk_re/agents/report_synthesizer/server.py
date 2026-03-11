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

FINDINGS_FILES = [
    ("Manifest Analysis", "manifest_analyzer.json"),
    ("String/Secrets Extraction", "string_extractor.json"),
    ("Network Mapping", "network_mapper.json"),
    ("Code Analysis", "code_analyzer.json"),
    ("API Extraction", "api_extractor.json"),
]

MAX_SECTION_CHARS = 3000
MAX_TOTAL_CHARS = 12000


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


def _load_findings(job_dir: Path) -> str:
    sections = []
    for label, filename in FINDINGS_FILES:
        filepath = job_dir / filename
        if not filepath.exists():
            continue
        try:
            content = filepath.read_text()
            # Truncate very large findings
            if len(content) > MAX_SECTION_CHARS:
                content = content[:MAX_SECTION_CHARS] + "\n... (truncated)"
            sections.append(f"## {label}\n{content}")
        except Exception:
            continue
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

        if len(findings_text) > MAX_TOTAL_CHARS:
            findings_text = findings_text[:MAX_TOTAL_CHARS] + "\n... (truncated)"

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

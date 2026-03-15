from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from mcp import ClientSession
from mcp.client.sse import sse_client

from apk_re.schemas import JobRequest, JobStatus

logger = logging.getLogger(__name__)


@dataclass
class PipelineStage:
    name: str
    agents: list[str]
    parallel: bool = False


class Pipeline:
    # Default agent names that map to docker-compose service names
    AGENT_NAMES = [
        "unpacker", "manifest_analyzer", "string_extractor",
        "network_mapper", "code_analyzer", "api_extractor",
        "report_synthesizer", "mobsf_analyzer",
    ]

    def __init__(self, shared_volume: str = "/data/apk_re/shared", agent_urls: dict[str, str] | None = None):
        self.shared_volume = Path(shared_volume)
        if agent_urls is not None:
            self.agent_urls = agent_urls
        else:
            # Default: docker-compose networking (service_name:8080)
            self.agent_urls = {
                name: f"http://{name}:8080/sse" for name in self.AGENT_NAMES
            }
        self.stages = self._default_stages()

    @staticmethod
    def _default_stages() -> list[PipelineStage]:
        return [
            PipelineStage(name="unpack", agents=["unpacker"], parallel=False),
            PipelineStage(name="mobsf_pre_scan", agents=["mobsf_analyzer"], parallel=False),
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
            logger.info("Starting stage: %s", stage.name)
            self._write_status(job_dir, status)
            await self._run_stage(stage, job)
            # Digest MobSF output into per-agent snippet files before LLM stages start.
            # MobSF failure is non-fatal: _call_agent writes an error JSON and continues,
            # so downstream agents simply fall back to empty context strings.
            if stage.name == "mobsf_pre_scan":
                self._digest_mobsf_findings(job)
            logger.info("Completed stage: %s", stage.name)

        status.state = "completed"
        status.current_stage = None
        self._write_status(job_dir, status)
        return status

    async def _run_stage(self, stage: PipelineStage, job: JobRequest) -> None:
        if stage.parallel:
            await asyncio.gather(
                *[self._call_agent(agent, job, stage.name) for agent in stage.agents]
            )
        else:
            for agent in stage.agents:
                await self._call_agent(agent, job, stage.name)

    async def _call_agent(self, agent_name: str, job: JobRequest, stage_name: str = "") -> None:
        url = self.agent_urls.get(agent_name)
        if not url:
            return

        findings_dir = self.shared_volume / "findings" / job.job_id
        findings_dir.mkdir(parents=True, exist_ok=True)

        # Use stage-specific filename for code_deep to avoid overwriting triage
        if stage_name == "code_deep" and agent_name == "code_analyzer":
            findings_file = findings_dir / "code_analyzer_deep.json"
        else:
            findings_file = findings_dir / f"{agent_name}.json"

        logger.info("Calling agent: %s (stage: %s)", agent_name, stage_name)
        try:
            # Per-file LLM calls can take 30-60min total; default 5min timeout is too short
            async with sse_client(url, sse_read_timeout=60 * 60) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()

                    tools = await session.list_tools()
                    tool_names = [t.name for t in tools.tools]

                    result = await self._execute_agent_tools(
                        session, agent_name, tool_names, job, stage_name=stage_name
                    )

                    findings_file.write_text(
                        json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
                    )
            logger.info("Agent %s completed successfully", agent_name)
        except Exception as e:
            logger.exception("Agent %s failed", agent_name)
            error_result = {"status": "error", "agent": agent_name, "error": str(e)}
            findings_file.write_text(json.dumps(error_result, indent=2))

    async def _execute_agent_tools(
        self, session: ClientSession, agent_name: str, tool_names: list[str],
        job: JobRequest, stage_name: str = ""
    ) -> dict:
        """Execute the appropriate tools for each agent type."""
        if agent_name == "unpacker":
            # Translate coordinator path to agent mount path
            agent_apk_path = job.apk_path.replace(str(self.shared_volume), "/work")
            jadx_result = await session.call_tool("run_jadx", arguments={"apk_path": agent_apk_path})
            apktool_result = await session.call_tool("run_apktool", arguments={"apk_path": agent_apk_path})
            # Extract text from MCP CallToolResult
            jadx_text = jadx_result.content[0].text if jadx_result.content else str(jadx_result)
            apktool_text = apktool_result.content[0].text if apktool_result.content else str(apktool_result)
            return {"jadx": jadx_text, "apktool": apktool_text}
        elif agent_name == "manifest_analyzer":
            manifest_path = "/work/decompiled/apktool/AndroidManifest.xml"
            result = await session.call_tool("analyze_manifest", arguments={"manifest_path": manifest_path})
            result_text = result.content[0].text if result.content else str(result)
            # Parse the JSON string returned by the agent
            try:
                return json.loads(result_text)
            except json.JSONDecodeError:
                return {"raw_output": result_text}
        elif agent_name == "string_extractor":
            source_dir = "/work/decompiled/jadx"
            result = await session.call_tool("extract_strings", arguments={"source_dir": source_dir})
            result_text = result.content[0].text if result.content else str(result)
            try:
                return json.loads(result_text)
            except json.JSONDecodeError:
                return {"raw_output": result_text}
        elif agent_name == "network_mapper":
            source_dir = "/work/decompiled/jadx"
            result = await session.call_tool(
                "map_network",
                arguments={
                    "source_dir": source_dir,
                    "mobsf_context_path": self._snippet_path(job, "mobsf_network_context.txt"),
                },
            )
            result_text = result.content[0].text if result.content else str(result)
            try:
                return json.loads(result_text)
            except json.JSONDecodeError:
                return {"raw_output": result_text}
        elif agent_name == "code_analyzer":
            source_dir = "/work/decompiled/jadx"
            if stage_name == "code_deep":
                # Read triage results from previous stage
                findings_dir = self.shared_volume / "findings" / job.job_id
                triage_file = findings_dir / "code_analyzer.json"
                if triage_file.exists():
                    triage_data = json.loads(triage_file.read_text())
                    classes = triage_data.get("classes", [])
                    deep_results = []
                    for cls in classes:
                        if cls.get("relevance_score", 0) >= 0.6:
                            class_path = f"{source_dir}/sources/{cls['class_name'].replace('.', '/')}.java"
                            result = await session.call_tool(
                                "analyze_class", arguments={"file_path": class_path}
                            )
                            result_text = result.content[0].text if result.content else str(result)
                            try:
                                deep_results.append(json.loads(result_text))
                            except json.JSONDecodeError:
                                deep_results.append({"raw_output": result_text})
                    return {"deep_analysis": deep_results}
                return {"deep_analysis": []}
            elif "triage_classes" in tool_names:
                result = await session.call_tool(
                    "triage_classes",
                    arguments={
                        "source_dir": source_dir,
                        "mobsf_context_path": self._snippet_path(job, "mobsf_code_context.txt"),
                    },
                )
                result_text = result.content[0].text if result.content else str(result)
                try:
                    return json.loads(result_text)
                except json.JSONDecodeError:
                    return {"raw_output": result_text}
            return {"status": "completed", "agent": agent_name}
        elif agent_name == "api_extractor":
            source_dir = "/work/decompiled/jadx"
            result = await session.call_tool(
                "extract_apis",
                arguments={
                    "source_dir": source_dir,
                    "mobsf_flagged_path": self._snippet_path(job, "mobsf_api_flagged.txt"),
                },
            )
            result_text = result.content[0].text if result.content else str(result)
            try:
                return json.loads(result_text)
            except json.JSONDecodeError:
                return {"raw_output": result_text}
        elif agent_name == "report_synthesizer":
            result = await session.call_tool("synthesize_report", arguments={"job_id": job.job_id})
            result_text = result.content[0].text if result.content else str(result)
            try:
                return json.loads(result_text)
            except json.JSONDecodeError:
                return {"raw_output": result_text}
        elif agent_name == "mobsf_analyzer":
            agent_apk_path = job.apk_path.replace(str(self.shared_volume), "/work")
            result = await session.call_tool(
                "analyze_with_mobsf", arguments={"apk_path": agent_apk_path}
            )
            result_text = result.content[0].text if result.content else str(result)
            try:
                return json.loads(result_text)
            except json.JSONDecodeError:
                return {"raw_output": result_text}
        elif "read_file" in tool_names:
            return {"status": "completed", "agent": agent_name}
        return {}

    def _digest_mobsf_findings(self, job: JobRequest) -> None:
        """Read mobsf_analyzer.json and write per-agent context snippet files.

        Writes to the job findings directory:
          mobsf_code_context.txt    — flagged-class list for code_analyzer
          mobsf_network_context.txt — net-sec-config issues for network_mapper
          mobsf_api_flagged.txt     — filename stems for api_extractor Phase 4 scoring
        """
        findings_dir = self.shared_volume / "findings" / job.job_id
        mobsf_file = findings_dir / "mobsf_analyzer.json"
        if not mobsf_file.exists():
            logger.warning("MobSF findings not found, skipping digest")
            return

        try:
            data = json.loads(mobsf_file.read_text())
        except Exception:
            logger.warning("Failed to parse MobSF findings, skipping digest")
            return

        if "error" in data:
            logger.warning("MobSF scan reported an error: %s — running without MobSF context", data["error"])
            return

        code_issues = data.get("code_issues", [])

        # -- code_analyzer: flagged class list --
        if code_issues:
            lines = ["MobSF flagged these files for dangerous API patterns:"]
            for issue in code_issues:
                fp = issue.get("file", "")
                if fp:
                    lines.append(f"  [{issue.get('severity', '')}] {fp} — {issue.get('title', '')}")
            snippet = "\n".join(lines)[:1500]
            (findings_dir / "mobsf_code_context.txt").write_text(snippet)
            logger.info("MobSF digest: wrote code context (%d chars)", len(snippet))

        # -- network_mapper: network security issues --
        net_issues = data.get("network_security_issues", [])
        if net_issues:
            lines = ["MobSF network security config findings:"]
            lines.extend(f"  - {issue}" for issue in net_issues[:10])
            snippet = "\n".join(lines)[:1000]
            (findings_dir / "mobsf_network_context.txt").write_text(snippet)
            logger.info("MobSF digest: wrote network context (%d chars)", len(snippet))

        # -- api_extractor Phase 4: network-flagged filename stems --
        network_keywords = {"http", "url", "network", "socket", "ssl", "tls", "request", "retrofit"}
        flagged_stems: set[str] = set()
        for issue in code_issues:
            if any(kw in issue.get("title", "").lower() for kw in network_keywords):
                fp = issue.get("file", "")
                if fp:
                    flagged_stems.add(Path(fp).stem.lower())
        if flagged_stems:
            (findings_dir / "mobsf_api_flagged.txt").write_text("\n".join(sorted(flagged_stems)))
            logger.info("MobSF digest: flagged %d stems for api_extractor", len(flagged_stems))

    def _snippet_path(self, job: JobRequest, filename: str) -> str:
        """Return agent-mount path to a snippet file, or empty string if it doesn't exist."""
        host_path = self.shared_volume / "findings" / job.job_id / filename
        if not host_path.exists():
            return ""
        return str(host_path).replace(str(self.shared_volume), "/work")

    def _write_status(self, job_dir: Path, status: JobStatus) -> None:
        status_file = job_dir / "status.json"
        status_file.write_text(status.model_dump_json(indent=2))

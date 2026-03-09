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
    # Default agent names that map to docker-compose service names
    AGENT_NAMES = [
        "unpacker", "manifest_analyzer", "string_extractor",
        "network_mapper", "code_analyzer", "api_extractor",
        "report_synthesizer",
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

        findings_dir = self.shared_volume / "findings" / job.job_id
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_file = findings_dir / f"{agent_name}.json"

        try:
            async with sse_client(url) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()

                    tools = await session.list_tools()
                    tool_names = [t.name for t in tools.tools]

                    result = await self._execute_agent_tools(session, agent_name, tool_names, job)

                    findings_file.write_text(
                        json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
                    )
        except Exception as e:
            error_result = {"status": "error", "agent": agent_name, "error": str(e)}
            findings_file.write_text(json.dumps(error_result, indent=2))

    async def _execute_agent_tools(
        self, session: ClientSession, agent_name: str, tool_names: list[str], job: JobRequest
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
            result = await session.call_tool("map_network", arguments={"source_dir": source_dir})
            result_text = result.content[0].text if result.content else str(result)
            try:
                return json.loads(result_text)
            except json.JSONDecodeError:
                return {"raw_output": result_text}
        elif agent_name == "code_analyzer":
            source_dir = "/work/decompiled/jadx"
            if "triage_classes" in tool_names:
                result = await session.call_tool("triage_classes", arguments={"source_dir": source_dir})
                result_text = result.content[0].text if result.content else str(result)
                try:
                    return json.loads(result_text)
                except json.JSONDecodeError:
                    return {"raw_output": result_text}
            return {"status": "completed", "agent": agent_name}
        elif "read_file" in tool_names:
            return {"status": "completed", "agent": agent_name}
        return {}

    def _write_status(self, job_dir: Path, status: JobStatus) -> None:
        status_file = job_dir / "status.json"
        status_file.write_text(status.model_dump_json(indent=2))

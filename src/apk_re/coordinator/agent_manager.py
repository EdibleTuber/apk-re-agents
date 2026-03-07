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

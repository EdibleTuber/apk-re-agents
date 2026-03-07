# tests/test_agent_manager.py
from unittest.mock import MagicMock, patch
from apk_re.coordinator.agent_manager import AgentManager, AgentInfo


def test_agent_info_port_assignment():
    info = AgentInfo(name="unpacker", image="agent-unpacker:latest", port=9000)
    assert info.mcp_url == "http://localhost:9000/sse"


@patch("apk_re.coordinator.agent_manager.docker")
def test_agent_manager_registers_agents(mock_docker):
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

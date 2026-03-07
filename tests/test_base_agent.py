from apk_re.agents.base.base_agent import create_agent_server


def test_create_agent_server_returns_mcp():
    server = create_agent_server("test_agent")
    assert server.name == "test_agent"


def test_agent_server_has_read_file_tool():
    server = create_agent_server("test_agent")
    # FastMCP registers tools internally -- check via the tools dict
    assert "read_file" in server._tool_manager._tools

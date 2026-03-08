from apk_re.agents.unpacker.server import create_unpacker_server


def test_unpacker_has_tools():
    server = create_unpacker_server()
    tool_names = list(server._tool_manager._tools.keys())
    assert "read_file" in tool_names
    assert "run_jadx" in tool_names
    assert "run_apktool" in tool_names

import json
import os
from unittest.mock import MagicMock, patch

from pydantic import BaseModel, Field

from apk_re.agents.base.base_agent import create_agent_server, call_ollama


class MockOutput(BaseModel):
    name: str
    count: int


@patch("apk_re.agents.base.base_agent.ollama.Client")
def test_call_ollama_returns_validated_model(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.chat.return_value = {
        "message": {"content": '{"name": "test", "count": 42}'}
    }

    result = call_ollama(
        prompt="Extract data",
        output_schema=MockOutput,
        ollama_host="http://localhost:11434",
        model="qwen2.5-coder:7b",
    )

    assert isinstance(result, MockOutput)
    assert result.name == "test"
    assert result.count == 42

    mock_client.chat.assert_called_once()
    call_kwargs = mock_client.chat.call_args[1]
    assert call_kwargs["model"] == "qwen2.5-coder:7b"
    assert call_kwargs["format"] == MockOutput.model_json_schema()


@patch("apk_re.agents.base.base_agent.ollama.Client")
def test_call_ollama_with_system_prompt(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.chat.return_value = {
        "message": {"content": '{"name": "x", "count": 1}'}
    }

    call_ollama(
        prompt="Extract data",
        output_schema=MockOutput,
        system_prompt="You are an analyst.",
        ollama_host="http://localhost:11434",
        model="qwen2.5-coder:7b",
    )

    messages = mock_client.chat.call_args[1]["messages"]
    assert messages[0]["role"] == "system"
    assert messages[0]["content"] == "You are an analyst."
    assert messages[1]["role"] == "user"


@patch("apk_re.agents.base.base_agent.ollama.Client")
def test_call_ollama_raises_on_invalid_json(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.chat.return_value = {
        "message": {"content": "not json at all"}
    }

    import pytest
    with pytest.raises(Exception):
        call_ollama(
            prompt="Extract data",
            output_schema=MockOutput,
            ollama_host="http://localhost:11434",
            model="qwen2.5-coder:7b",
        )

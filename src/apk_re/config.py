from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ollama_host: str = "http://localhost:11434"
    small_model: str = "qwen2.5-coder:7b"
    large_model: str = "qwen2.5-coder:32b-instruct-q4_K_M"
    shared_volume: Path = Path("/data/apk_re/shared")
    coordinator_port: int = 8000
    agent_base_port: int = 9000

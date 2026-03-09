from apk_re.config import Settings


def test_default_settings():
    settings = Settings()
    assert settings.ollama_host == "http://localhost:11434"
    assert settings.small_model == "qwen2.5-coder:7b"
    assert settings.large_model == "qwen2.5-coder:32b-instruct-q4_K_M"
    assert settings.shared_volume.is_absolute()


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://10.0.0.5:11434")
    monkeypatch.setenv("SMALL_MODEL", "mistral:7b")
    settings = Settings()
    assert settings.ollama_host == "http://10.0.0.5:11434"
    assert settings.small_model == "mistral:7b"

# src/apk_re/agents/api_extractor/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY src/apk_re/agents/api_extractor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the package with correct module structure
COPY src/apk_re/__init__.py ./apk_re/__init__.py
COPY src/apk_re/schemas.py ./apk_re/schemas.py
COPY src/apk_re/agents/__init__.py ./apk_re/agents/__init__.py
COPY src/apk_re/agents/base/__init__.py ./apk_re/agents/base/__init__.py
COPY src/apk_re/agents/base/base_agent.py ./apk_re/agents/base/base_agent.py
COPY src/apk_re/agents/api_extractor/__init__.py ./apk_re/agents/api_extractor/__init__.py
COPY src/apk_re/agents/api_extractor/server.py ./apk_re/agents/api_extractor/server.py

ENV PYTHONPATH=/app

EXPOSE 8080
CMD ["python", "-m", "apk_re.agents.api_extractor.server"]

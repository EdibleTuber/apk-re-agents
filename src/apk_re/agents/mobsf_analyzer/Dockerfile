FROM python:3.11-slim

WORKDIR /app

COPY src/apk_re/agents/mobsf_analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/apk_re/__init__.py ./apk_re/__init__.py
COPY src/apk_re/schemas.py ./apk_re/schemas.py
COPY src/apk_re/agents/__init__.py ./apk_re/agents/__init__.py
COPY src/apk_re/agents/base/__init__.py ./apk_re/agents/base/__init__.py
COPY src/apk_re/agents/base/base_agent.py ./apk_re/agents/base/base_agent.py
COPY src/apk_re/agents/mobsf_analyzer/__init__.py ./apk_re/agents/mobsf_analyzer/__init__.py
COPY src/apk_re/agents/mobsf_analyzer/server.py ./apk_re/agents/mobsf_analyzer/server.py

ENV PYTHONPATH=/app

EXPOSE 8080
CMD ["python", "-m", "apk_re.agents.mobsf_analyzer.server"]

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jdk \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install jadx
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip -O /tmp/jadx.zip \
    && unzip /tmp/jadx.zip -d /opt/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip

# Install apktool
RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool \
    && wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O /usr/local/bin/apktool.jar

WORKDIR /app
COPY src/apk_re/agents/base/base_agent.py ./apk_re/agents/base/base_agent.py
COPY src/apk_re/agents/base/__init__.py ./apk_re/agents/base/__init__.py
COPY src/apk_re/agents/__init__.py ./apk_re/agents/__init__.py
COPY src/apk_re/__init__.py ./apk_re/__init__.py
COPY src/apk_re/agents/unpacker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/apk_re/agents/unpacker/server.py .

EXPOSE 8080
CMD ["python", "server.py"]

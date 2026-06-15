FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        freerdp3-x11 \
        novnc \
        openbox \
        python3 \
        python3-pip \
        python3-venv \
        x11vnc \
        xvfb \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin servermanager \
    && mkdir -p /tmp/.X11-unix /data \
    && chown servermanager:servermanager /data \
    && chmod 1777 /tmp/.X11-unix

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/servermanager \
    && /opt/servermanager/bin/pip install --no-cache-dir -r /app/requirements.txt
COPY app/ /app/

USER servermanager
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD /opt/servermanager/bin/python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"

CMD ["/opt/servermanager/bin/python", "/app/server.py"]

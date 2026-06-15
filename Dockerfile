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
        python3-aiohttp \
        x11vnc \
        xvfb \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin servermanager \
    && mkdir -p /tmp/.X11-unix \
    && chmod 1777 /tmp/.X11-unix

WORKDIR /app
COPY app/ /app/

USER servermanager
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"

CMD ["python3", "/app/server.py"]

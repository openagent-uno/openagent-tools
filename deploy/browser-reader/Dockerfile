# syntax=docker/dockerfile:1.7
# Independent model-free reader, installed only from immutable public wheels.
FROM python:3.12-slim-trixie
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium xvfb xauth nodejs npm tini ca-certificates fonts-liberation fonts-noto-core fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*
ARG DEVICE_TOOLS_VERSION=1.0.0b19
ARG DEVICE_TOOLS_RELEASE=device-tools-v1.0.0-beta.19
ARG DEVICE_TOOLS_SHA256
ADD --checksum=sha256:${DEVICE_TOOLS_SHA256} https://github.com/openagent-uno/openagent-tools/releases/download/${DEVICE_TOOLS_RELEASE}/openagent_device_tools-${DEVICE_TOOLS_VERSION}-py3-none-any.whl /tmp/wheels/
ADD --checksum=sha256:1e0cbdc1007ddcf96aae9538983727841228b40ebb50f481a915d2020115ea6c https://github.com/openagent-uno/openagent-tools/releases/download/v1.0.0-beta.7/openagent_tool_protocol-1.0.0b2-py3-none-any.whl /tmp/wheels/
RUN pip install --no-cache-dir /tmp/wheels/*.whl \
    && cd "$(python -c 'from openagent_device_tools.sources import sidecar_source; print(sidecar_source("agent-in-chrome"))')/host" \
    && npm ci --omit=dev --ignore-scripts && npm cache clean --force && rm -rf /tmp/wheels \
    && mkdir -p /etc/chromium/policies/managed \
    && printf '{"URLBlocklist":["file://*"]}\n' > /etc/chromium/policies/managed/openagent-no-local-files.json \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin openagent
ENV OPENAGENT_CHROME_BINARY=/usr/bin/chromium PYTHONUNBUFFERED=1
USER 10001
WORKDIR /home/openagent
ENTRYPOINT ["/usr/bin/tini", "--", "xvfb-run", "-a", "openagent-browser-read"]

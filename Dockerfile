FROM python:3.12-slim

WORKDIR /app

# Install deps first (cache layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]" 2>/dev/null; pip install --no-cache-dir -e . || true

# Copy source
COPY src/ src/

# Embed skill.yaml as an image label so the orchestrator can read it
# without pulling the full image.
COPY skill.yaml /skill.yaml
RUN SKILL_YAML_B64=$(base64 -w0 /skill.yaml 2>/dev/null || base64 /skill.yaml) \
 && echo "LABEL com.virgil.skill.yaml=${SKILL_YAML_B64}" > /tmp/label.txt

LABEL com.virgil.skill.yaml=""    # overwritten by build pipeline; see CI

# MCP server listens on :9230
EXPOSE 9230

# Graceful shutdown
STOPSIGNAL SIGTERM

CMD ["python", "-m", "virgil_skill_my_skill"]

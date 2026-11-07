FROM python:3.11-slim@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79
WORKDIR /app
COPY requirements.lock download_model.py /app/
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements.lock \
 && python download_model.py /model
COPY src/ /app/
ENV PYTHONDONTWRITEBYTECODE=1 OPENAGENT_SPEECH_MODEL=/model HF_HUB_OFFLINE=1
USER 10001
EXPOSE 8080
CMD ["python", "-m", "openagent_media_inspector"]

# One image for all three services (collector, engine, dashboard).
# Fully-qualified base image name so Podman doesn't prompt for a registry.
FROM docker.io/library/python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Train the model at build time so the artifact always matches the installed
# scikit-learn version. Training is deterministic (seed 42).
RUN python -m models.train > /dev/null \
 && useradd --uid 10001 --create-home soc \
 && mkdir -p /data \
 && chown -R soc:soc /data

# Run as an unprivileged user (on top of rootless Podman).
USER soc

CMD ["python", "-m", "pipeline.engine"]

# Build from the repository root:
#   docker build -f deploy/dashboard/Dockerfile .
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY scripts/ghsa scripts/ghsa
COPY assets assets
# Editable install keeps the package under /app, where the dashboard looks
# for assets/ to embed the favicon.
RUN pip install --no-cache-dir -e .

COPY deploy/dashboard/serve.py /app/serve.py

RUN useradd --system --uid 10001 ghsa \
    && mkdir -p /srv/dashboard && chown ghsa /srv/dashboard
USER ghsa

EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["python", "/app/serve.py"]

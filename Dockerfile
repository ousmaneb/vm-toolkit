FROM python:3.12.10-slim-bookworm

# Tailscale gives the container a private route to Nessus without exposing Nessus to the internet.
COPY --from=tailscale/tailscale:v1.84.0 /usr/local/bin/tailscaled /usr/local/bin/tailscale /usr/local/bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    VMT_ENV=production \
    VMT_DATA_DIR=/data \
    TZ=UTC

RUN useradd --create-home --uid 10001 app
WORKDIR /app

# Dependencies first, pinned, so a rebuild without dependency changes reuses this layer.
COPY requirements.lock ./
RUN pip install -r requirements.lock

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps . && rm -rf src

COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
VOLUME /data
EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://localhost:{os.environ.get(\"PORT\", 8501)}/_stcore/health', timeout=4)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

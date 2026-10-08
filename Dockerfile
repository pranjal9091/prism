# ==============================================================================
# PRism — Production Container Dockerfile
# Multi-stage optimized, non-root user, persistent volume support, healthchecked
# ==============================================================================

FROM python:3.12-slim

# Install minimal OS dependencies for healthcheck & network security
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager binary
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /uvx /bin/

# Create unprivileged system user and group (UID/GID 1000)
RUN useradd -m -u 1000 -s /bin/bash prism

# Create application and persistent data directories with non-root ownership
RUN mkdir -p /app /data && chown -R prism:prism /app /data

# Work as unprivileged user
USER prism
WORKDIR /app

# Set container environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    CHECKPOINT_DB_PATH=/data/prism_checkpoints.db \
    REVIEW_DB_PATH=/data/prism_reviews.db \
    ENVIRONMENT=production

# Copy dependency manifests first to leverage Docker layer caching
COPY --chown=prism:prism pyproject.toml uv.lock README.md /app/

# Install dependencies into virtual environment
RUN uv sync --frozen --no-dev

# Copy application source code
COPY --chown=prism:prism prism/ /app/prism/
COPY --chown=prism:prism scripts/ /app/scripts/

# Re-run uv sync to install package in editable/local mode
RUN uv sync --frozen --no-dev

# Lightweight container healthcheck
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

# Start FastAPI application
CMD ["uvicorn", "prism.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

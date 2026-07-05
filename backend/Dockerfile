# ────────────────────────────────────────────────────────────────────
# Multi-Cloud IPAM Scanner — FastAPI Application
# Multi-stage Docker build for a minimal production image.
# ────────────────────────────────────────────────────────────────────

# ── Stage 1: Build ────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# Install runtime-only system packages (libpq for asyncpg, curl for health checks).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage.
COPY --from=builder /root/.local /root/.local

# Ensure local bin is in PATH.
ENV PATH=/root/.local/bin:$PATH

# Create a non-root user for security.
RUN addgroup --system --gid 1001 appuser \
    && adduser --system --uid 1001 --ingroup appuser --home /app --shell /sbin/nologin appuser

# Copy application code and adjust ownership.
COPY --chown=appuser:appuser . .

# Switch to non-root user.
USER appuser

# Expose FastAPI port.
EXPOSE 8000

# Health check (matches the /api/v1/health endpoint defined in the router).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

# Run with uvicorn.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

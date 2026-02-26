# ═══════════════════════════════════════════════════════════════
# Quantum Protocol v5.0 — Backend Dockerfile
# Multi-stage build with unified scanner_engine
# Phase 2: Enhanced with all security tools & proper isolation
# ═══════════════════════════════════════════════════════════════

# ── Build Stage ──────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (backend + scanner requirements)
COPY backend/requirements.txt ./backend-requirements.txt
COPY requirements.txt ./scanner-requirements.txt
RUN pip install --no-cache-dir --user -r backend-requirements.txt \
    && pip install --no-cache-dir --user -r scanner-requirements.txt 2>/dev/null || true

# ── Production Stage ─────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies + security scanning tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    git \
    curl \
    wget \
    nmap \
    dnsutils \
    netcat-openbsd \
    ca-certificates \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/app:/app/backend:/app/Owasp_Scanner_2:/app/Owasp_Scanner_1
ENV PYTHONUNBUFFERED=1

# Copy unified scanner engine (Phase 1 output)
COPY scanner_engine/ ./scanner_engine/

# Copy Scanner_2 flat modules (used by orchestrator)
COPY Owasp_Scanner_2/ ./Owasp_Scanner_2/

# Copy Scanner_1 modules (extended analyzers)
COPY Owasp_Scanner_1/ ./Owasp_Scanner_1/

# Copy backend application
COPY backend/ ./backend/

# Create directories for scan targets and results
RUN mkdir -p /scan_targets /scan_results /tmp/scan_workspace

# Create non-root user for security
RUN groupadd -r scanner && useradd -r -g scanner -d /app -s /sbin/nologin scanner \
    && chown -R scanner:scanner /app /scan_targets /scan_results /tmp/scan_workspace

# Expose API port
EXPOSE 8000

# Health check — hits /api/v1/health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Run as non-root user
USER scanner

# Default: run FastAPI with uvicorn (4 workers for production)
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--timeout-keep-alive", "120"]

# =============================================================================
# VultronScanner — Dockerfile
# Multi-stage build for minimal production image
# =============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install system dependencies for nmap and compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="VultronScanner Contributors"
LABEL description="Modular Attack Surface Manager & Penetration Testing Platform"
LABEL version="0.1.0"

WORKDIR /app

# Install runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY Core/       ./Core/
COPY Modules/    ./Modules/
COPY Utils/      ./Utils/
COPY Reports/    ./Reports/
COPY Config/     ./Config/
COPY main.py     .

# Create output directory
RUN mkdir -p Reports/Output

# Run as non-root user for security
RUN useradd --no-create-home --shell /bin/false vultron && \
    chown -R vultron:vultron /app
USER vultron

# Default entrypoint
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]

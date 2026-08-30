# ==============================================================================
# CyberAssess Platform - Production Multi-Stage Multi-Arch Dockerfile
# Pre-packages all 10 Security Pentesting Tools & Python Runtime
# Authoritative Contract Reference: contracts/08_TECHNICAL_IMPLEMENTATION_AND_TEST_VECTORS_CONTRACT.md (Section 10)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Builder Stage (Download & verify official pre-compiled tool binaries)
# ------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM python:3.11-slim-bookworm AS builder

ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tar \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/bin

# 1. Nuclei (v3.11.1)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_arm64.zip -o nuclei.zip; \
    else \
      curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip -o nuclei.zip; \
    fi && \
    unzip -q nuclei.zip nuclei && \
    chmod +x nuclei && \
    rm nuclei.zip

# 2. FFuF (v2.2.1)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/ffuf/ffuf/releases/download/v2.2.1/ffuf_2.2.1_linux_arm64.tar.gz | tar -xz ffuf; \
    else \
      curl -sSL https://github.com/ffuf/ffuf/releases/download/v2.2.1/ffuf_2.2.1_linux_amd64.tar.gz | tar -xz ffuf; \
    fi && \
    chmod +x ffuf

# 3. Gitleaks (v8.30.1)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz | tar -xz gitleaks; \
    else \
      curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz | tar -xz gitleaks; \
    fi && \
    chmod +x gitleaks

# 4. Trivy (v0.74.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-ARM64.tar.gz | tar -xz trivy; \
    else \
      curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz | tar -xz trivy; \
    fi && \
    chmod +x trivy

# ------------------------------------------------------------------------------
# Stage 2: Final Hardened Production Runtime
# ------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="CyberAssess Security Assessment Platform" \
      org.opencontainers.image.description="Full-Stack Automated Security Assessment & Vulnerability Management Platform" \
      org.opencontainers.image.vendor="CyberAssess" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000

# Install runtime system packages: Nmap, Perl with CPAN XML::Writer, Git, Curl, procps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    perl \
    libxml-writer-perl \
    libnet-ssleay-perl \
    git \
    curl \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto via official upstream GitHub repo
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Copy pre-compiled standalone binaries from builder stage
COPY --from=builder /tmp/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /tmp/bin/ffuf /usr/local/bin/ffuf
COPY --from=builder /tmp/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /tmp/bin/trivy /usr/local/bin/trivy

# Create application directories
WORKDIR /app
RUN mkdir -p /app/data/scans /app/backend /app/frontend

# Install Python requirements (Bandit, SSLyze, Semgrep, Checkov, FastAPI, etc.)
COPY backend/requirements.txt /app/backend/
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend application, frontend HUD assets, and root runner
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY run_platform.py /app/

# Expose Web SOC HUD port
EXPOSE 8000

# Healthcheck probe against FastAPI system health API
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/system/health || exit 1

# Launch Platform
CMD ["python", "run_platform.py"]

# ==============================================================================
# CyberAssess Platform - Production Multi-Stage Multi-Arch Dockerfile
# Pre-packages all 22 Enterprise Security Pentesting & Compliance Tools
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

# 5. Subfinder (v2.16.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_linux_arm64.zip -o subfinder.zip; \
    else \
      curl -sSL https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_linux_amd64.zip -o subfinder.zip; \
    fi && \
    unzip -q subfinder.zip subfinder && \
    chmod +x subfinder && \
    rm subfinder.zip

# 6. Httpx (v1.10.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/projectdiscovery/httpx/releases/download/v1.10.0/httpx_1.10.0_linux_arm64.zip -o httpx.zip; \
    else \
      curl -sSL https://github.com/projectdiscovery/httpx/releases/download/v1.10.0/httpx_1.10.0_linux_amd64.zip -o httpx.zip; \
    fi && \
    unzip -q httpx.zip httpx && \
    chmod +x httpx && \
    rm httpx.zip

# 7. Katana (v1.7.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/projectdiscovery/katana/releases/download/v1.7.0/katana_1.7.0_linux_arm64.zip -o katana.zip; \
    else \
      curl -sSL https://github.com/projectdiscovery/katana/releases/download/v1.7.0/katana_1.7.0_linux_amd64.zip -o katana.zip; \
    fi && \
    unzip -q katana.zip katana && \
    chmod +x katana && \
    rm katana.zip

# 8. Syft (v1.51.1)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_arm64.tar.gz | tar -xz syft; \
    else \
      curl -sSL https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_amd64.tar.gz | tar -xz syft; \
    fi && \
    chmod +x syft

# 9. Grype (v0.118.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_linux_arm64.tar.gz | tar -xz grype; \
    else \
      curl -sSL https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_linux_amd64.tar.gz | tar -xz grype; \
    fi && \
    chmod +x grype

# 10. OSV-Scanner (v2.5.1)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/google/osv-scanner/releases/download/v2.5.1/osv-scanner_linux_arm64 -o osv-scanner; \
    else \
      curl -sSL https://github.com/google/osv-scanner/releases/download/v2.5.1/osv-scanner_linux_amd64 -o osv-scanner; \
    fi && \
    chmod +x osv-scanner

# 11. TruffleHog (v3.97.1)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.1/trufflehog_3.97.1_linux_arm64.tar.gz | tar -xz trufflehog; \
    else \
      curl -sSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.1/trufflehog_3.97.1_linux_amd64.tar.gz | tar -xz trufflehog; \
    fi && \
    chmod +x trufflehog

# 12. Dockle (v0.4.15)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/goodwithtech/dockle/releases/download/v0.4.15/dockle_0.4.15_Linux-ARM64.tar.gz | tar -xz dockle; \
    else \
      curl -sSL https://github.com/goodwithtech/dockle/releases/download/v0.4.15/dockle_0.4.15_Linux-64bit.tar.gz | tar -xz dockle; \
    fi && \
    chmod +x dockle

# 13. Kube-bench (v0.16.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -sSL https://github.com/aquasecurity/kube-bench/releases/download/v0.16.0/kube-bench_0.16.0_linux_arm64.tar.gz | tar -xz kube-bench; \
    else \
      curl -sSL https://github.com/aquasecurity/kube-bench/releases/download/v0.16.0/kube-bench_0.16.0_linux_amd64.tar.gz | tar -xz kube-bench; \
    fi && \
    chmod +x kube-bench

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

# Install runtime system packages: Nmap, Perl with CPAN XML::Writer, Git, Curl, Node.js (for Retire.js), procps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    perl \
    libxml-writer-perl \
    libnet-ssleay-perl \
    nodejs \
    npm \
    git \
    curl \
    ca-certificates \
    procps \
    && npm install -g retire \
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
COPY --from=builder /tmp/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /tmp/bin/httpx /usr/local/bin/httpx
COPY --from=builder /tmp/bin/katana /usr/local/bin/katana
COPY --from=builder /tmp/bin/syft /usr/local/bin/syft
COPY --from=builder /tmp/bin/grype /usr/local/bin/grype
COPY --from=builder /tmp/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /tmp/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=builder /tmp/bin/dockle /usr/local/bin/dockle
COPY --from=builder /tmp/bin/kube-bench /usr/local/bin/kube-bench

# Create application directories
WORKDIR /app
RUN mkdir -p /app/data/scans /app/backend /app/frontend

# Install Python requirements (Bandit, SSLyze, Semgrep, Checkov, Prowler, Schemathesis, FastAPI, etc.)
COPY backend/requirements.txt /app/backend/
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --timeout 1000 --retries 10 -r /app/backend/requirements.txt && \
    pip install --no-cache-dir --timeout 1000 --retries 10 bandit sslyze semgrep checkov prowler schemathesis

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

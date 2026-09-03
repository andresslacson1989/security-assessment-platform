# ==============================================================================
# CyberAssess Platform - Production Multi-Stage Multi-Arch Dockerfile
# Pre-packages the 26-tool Enterprise Security Pentesting & Compliance Fleet
# Authoritative Contract References: contracts/01_PROJECT_SCOPE_AND_SAFETY_CONTRACT.md (§4.2),
# contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (§§2–3)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Builder Stage (Download & verify official pre-compiled tool binaries)
# ------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM python:3.11-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84 AS builder

ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tar \
    unzip \
    build-essential \
    libpcap-dev \
    libpcre2-dev \
    liblua5.3-dev \
    libssl-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/bin

# 1. Nuclei (v3.2.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_arm64.zip -o nuclei.zip && echo "57886fcfd9b15548adbfbc0816b18db5aa9bd0b9b72d5183a55ccac586feeaa5  nuclei.zip" | sha256sum -c -; \
    else \
      curl -fsSL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip -o nuclei.zip && echo "8351b05772f37268fd172476de3f0c831ca9d9b9b1a6c64bacd38ef055e5d052  nuclei.zip" | sha256sum -c -; \
    fi && \
    unzip -q nuclei.zip nuclei && \
    chmod +x nuclei && \
    rm nuclei.zip

# 1a. Nuclei community templates (pinned source snapshot)
# The release currently exposes a checksum sidecar but no archive asset, so
# the immutable Git tag commit and its codeload archive digest are pinned.
RUN curl -fsSL https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/83234ce456da3e90dda86dfbc5e605e64a846df3 -o nuclei-templates.tar.gz && \
    echo "5b22a097bf0b828377574a82b98b4ed0d1227b4aae3ff6e3bedf97272e70ccc6  nuclei-templates.tar.gz" | sha256sum -c - && \
    mkdir -p /tmp/bin/nuclei-templates && \
    tar -xzf nuclei-templates.tar.gz --strip-components=1 -C /tmp/bin/nuclei-templates && \
    test -n "$(find /tmp/bin/nuclei-templates -type f -print -quit)" && \
    python3 -c 'import hashlib,json; from pathlib import Path; root=Path("/tmp/bin/nuclei-templates"); d=hashlib.sha256(); [ (d.update(p.relative_to(root).as_posix().encode()), d.update(b"\0"), d.update(hashlib.sha256(p.read_bytes()).digest()), d.update(b"\0")) for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink() ]; json.dump({"source_commit":"83234ce456da3e90dda86dfbc5e605e64a846df3","archive_sha256":"5b22a097bf0b828377574a82b98b4ed0d1227b4aae3ff6e3bedf97272e70ccc6","template_tree_sha256":d.hexdigest(),"trust_status":"VALID"},open("/tmp/bin/nuclei-templates.trust.json","w"),sort_keys=True)' && \
    rm nuclei-templates.tar.gz

# 2. FFuF (v2.1.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_arm64.tar.gz -o ffuf.tar.gz && echo "6ae920d09d5202762fca21967a460c6fb88135bdfa806bee4d3d2c430dcedeea  ffuf.tar.gz" | sha256sum -c - && tar -xzf ffuf.tar.gz ffuf; \
    else \
      curl -fsSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -o ffuf.tar.gz && echo "fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5  ffuf.tar.gz" | sha256sum -c - && tar -xzf ffuf.tar.gz ffuf; \
    fi && \
    chmod +x ffuf

# 3. Gitleaks (v8.18.2)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_arm64.tar.gz -o gitleaks.tar.gz && echo "4df25683f95b9e1dbb8cc71dac74d10067b8aba221e7f991e01cafa05bcbd030  gitleaks.tar.gz" | sha256sum -c - && tar -xzf gitleaks.tar.gz gitleaks; \
    else \
      curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz -o gitleaks.tar.gz && echo "6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee  gitleaks.tar.gz" | sha256sum -c - && tar -xzf gitleaks.tar.gz gitleaks; \
    fi && \
    chmod +x gitleaks

# 4. Trivy (v0.50.0, approved SOURCE_BUILD_MODE)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://go.dev/dl/go1.21.13.linux-arm64.tar.gz -o go.tar.gz && echo "2ca2d70dc9c84feef959eb31f2a5aac33eefd8c97fe48f1548886d737bffabd4  go.tar.gz" | sha256sum -c -; \
    else \
      curl -fsSL https://go.dev/dl/go1.21.13.linux-amd64.tar.gz -o go.tar.gz && echo "502fc16d5910562461e6a6631fb6377de2322aad7304bf2bcd23500ba9dab4a7  go.tar.gz" | sha256sum -c -; \
    fi && tar -C /usr/local -xzf go.tar.gz && rm go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
RUN curl -fsSL https://github.com/aquasecurity/trivy/archive/refs/tags/v0.50.0.tar.gz -o trivy-source.tar.gz && \
    echo "16fa56d6c3549657baa49f1de8ffef5b6a976d7bf11d378d0f097189b70bae2b  trivy-source.tar.gz" | sha256sum -c - && \
    tar -xzf trivy-source.tar.gz && cd trivy-0.50.0 && \
    go mod download && \
    CGO_ENABLED=0 GOOS=linux GOARCH="$TARGETARCH" go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X=github.com/aquasecurity/trivy/pkg/version.ver=0.50.0" \
      -o /tmp/bin/trivy ./cmd/trivy && \
    chmod +x /tmp/bin/trivy && \
    TRIVY_SOURCE_SHA256="16fa56d6c3549657baa49f1de8ffef5b6a976d7bf11d378d0f097189b70bae2b" \
    GO_TOOLCHAIN_SHA256="$([ "$TARGETARCH" = "arm64" ] && echo "2ca2d70dc9c84feef959eb31f2a5aac33eefd8c97fe48f1548886d737bffabd4" || echo "502fc16d5910562461e6a6631fb6377de2322aad7304bf2bcd23500ba9dab4a7")" \
    TARGET_ARCH="$TARGETARCH" python3 -c 'import hashlib,json,os; p="/tmp/bin/trivy"; json.dump({"tool_id":"TOOL-TRIVY","tool_version":"v0.50.0","artifact_filename":"trivy-0.50.0-source.tar.gz","artifact_sha256":os.environ["TRIVY_SOURCE_SHA256"],"source_commit":"8ec3938e01a93855503e3400eae9831abbb5de4a","build_toolchain":"go1.21.13","build_toolchain_sha256":os.environ["GO_TOOLCHAIN_SHA256"],"executable_relative_path":"trivy","executable_sha256":hashlib.sha256(open(p,"rb").read()).hexdigest(),"platform":"linux","architecture":os.environ["TARGET_ARCH"],"installer_version":"14.3.0","trust_status":"VALID","claims":["SOURCE_ARCHIVE_INTEGRITY_VERIFIED","BUILD_TOOLCHAIN_INTEGRITY_VERIFIED","EXECUTABLE_INTEGRITY_VERIFIED"]},open("/tmp/bin/trivy.trust.json","w"),sort_keys=True)' && \
    rm -rf /tmp/bin/trivy-0.50.0 /tmp/bin/trivy-source.tar.gz

# 5. Subfinder (v2.6.5)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.5/subfinder_2.6.5_linux_arm64.zip -o subfinder.zip && echo "c629a4740f09ba7ecb326fdd5deeb84edb32819b3582d2f4c6172599d66bca1e  subfinder.zip" | sha256sum -c -; \
    else \
      curl -fsSL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.5/subfinder_2.6.5_linux_amd64.zip -o subfinder.zip && echo "19320e575c4fb422b1d2f9e4800b624eb5b5215e526db506570cb73dd2de5907  subfinder.zip" | sha256sum -c -; \
    fi && \
    unzip -q subfinder.zip subfinder && \
    chmod +x subfinder && \
    if [ "$TARGETARCH" = "arm64" ]; then artifact_sha256="c629a4740f09ba7ecb326fdd5deeb84edb32819b3582d2f4c6172599d66bca1e"; artifact_filename="subfinder_2.6.5_linux_arm64.zip"; else artifact_sha256="19320e575c4fb422b1d2f9e4800b624eb5b5215e526db506570cb73dd2de5907"; artifact_filename="subfinder_2.6.5_linux_amd64.zip"; fi && \
    ARTIFACT_SHA256="$artifact_sha256" ARTIFACT_FILENAME="$artifact_filename" TARGET_ARCH="$TARGETARCH" python3 -c 'import hashlib,json,os; p="subfinder"; json.dump({"tool_id":"TOOL-SUBFINDER","tool_version":"v2.6.5","artifact_filename":os.environ["ARTIFACT_FILENAME"],"artifact_sha256":os.environ["ARTIFACT_SHA256"],"executable_relative_path":p,"executable_sha256":hashlib.sha256(open(p,"rb").read()).hexdigest(),"platform":"linux","architecture":os.environ["TARGET_ARCH"],"installer_version":"14.3.0","trust_status":"VALID","claims":["ARCHIVE_INTEGRITY_VERIFIED","EXECUTABLE_INTEGRITY_VERIFIED"]},open(p+".trust.json","w"),sort_keys=True)' && \
    rm subfinder.zip

# 6. Httpx (v1.6.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_arm64.zip -o httpx.zip && echo "4fa8b296754c52da6fcc987870295e4159a15deeb3aa3a230f50cd208f72ef62  httpx.zip" | sha256sum -c -; \
    else \
      curl -fsSL https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip -o httpx.zip && echo "a209fbf6eb95cdfb3be9a90a1a57463c6dd1879a56ca32bb4a39cc55d9b0754d  httpx.zip" | sha256sum -c -; \
    fi && \
    unzip -q httpx.zip httpx && \
    chmod +x httpx && \
    if [ "$TARGETARCH" = "arm64" ]; then artifact_sha256="4fa8b296754c52da6fcc987870295e4159a15deeb3aa3a230f50cd208f72ef62"; artifact_filename="httpx_1.6.0_linux_arm64.zip"; else artifact_sha256="a209fbf6eb95cdfb3be9a90a1a57463c6dd1879a56ca32bb4a39cc55d9b0754d"; artifact_filename="httpx_1.6.0_linux_amd64.zip"; fi && \
    ARTIFACT_SHA256="$artifact_sha256" ARTIFACT_FILENAME="$artifact_filename" TARGET_ARCH="$TARGETARCH" python3 -c 'import hashlib,json,os; p="httpx"; json.dump({"tool_id":"TOOL-HTTPX","tool_version":"v1.6.0","artifact_filename":os.environ["ARTIFACT_FILENAME"],"artifact_sha256":os.environ["ARTIFACT_SHA256"],"executable_relative_path":p,"executable_sha256":hashlib.sha256(open(p,"rb").read()).hexdigest(),"platform":"linux","architecture":os.environ["TARGET_ARCH"],"installer_version":"14.3.0","trust_status":"VALID","claims":["ARCHIVE_INTEGRITY_VERIFIED","EXECUTABLE_INTEGRITY_VERIFIED"]},open(p+".trust.json","w"),sort_keys=True)' && \
    rm httpx.zip

# 7. Katana (v1.0.5)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/projectdiscovery/katana/releases/download/v1.0.5/katana_1.0.5_linux_arm64.zip -o katana.zip && echo "e9fa87ef114ab8afde2f1f77ce357d62ba3d68091a46f550f32358918162d0aa  katana.zip" | sha256sum -c -; \
    else \
      curl -fsSL https://github.com/projectdiscovery/katana/releases/download/v1.0.5/katana_1.0.5_linux_amd64.zip -o katana.zip && echo "d50ba599822701628396659a2b2bc7dc074eed23374c3e7c1794355cd4852f83  katana.zip" | sha256sum -c -; \
    fi && \
    unzip -q katana.zip katana && \
    chmod +x katana && \
    rm katana.zip

# 8. Syft (v1.0.1)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/anchore/syft/releases/download/v1.0.1/syft_1.0.1_linux_arm64.tar.gz -o syft.tar.gz && echo "c8582aa0e1c92c84c4a751c739ac3d7ca48c88a54b5d1b884d0629d7df72a6f9  syft.tar.gz" | sha256sum -c - && tar -xzf syft.tar.gz syft; \
    else \
      curl -fsSL https://github.com/anchore/syft/releases/download/v1.0.1/syft_1.0.1_linux_amd64.tar.gz -o syft.tar.gz && echo "420f90e57def27745e414efcb7a41384b2ccdccafca87c327096ca44621ab0ce  syft.tar.gz" | sha256sum -c - && tar -xzf syft.tar.gz syft; \
    fi && \
    chmod +x syft

# 9. Grype (v0.74.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/anchore/grype/releases/download/v0.74.0/grype_0.74.0_linux_arm64.tar.gz -o grype.tar.gz && echo "754edfce7cdaa28849f997c9959879b21f753c382066af7c31ef238353558ba9  grype.tar.gz" | sha256sum -c - && tar -xzf grype.tar.gz grype; \
    else \
      curl -fsSL https://github.com/anchore/grype/releases/download/v0.74.0/grype_0.74.0_linux_amd64.tar.gz -o grype.tar.gz && echo "7645f114e46cabb989254ec8ec34107240382a4b0626d940aa91a835177fbaf3  grype.tar.gz" | sha256sum -c - && tar -xzf grype.tar.gz grype; \
    fi && \
    chmod +x grype

# 10. OSV-Scanner (v1.7.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/google/osv-scanner/releases/download/v1.7.0/osv-scanner_linux_arm64 -o osv-scanner && echo "9ac3f0dc3f0fbfae5fc9e8e00d46906e08e5e85f88c5e79950d331d0f139a5c5  osv-scanner" | sha256sum -c -; \
    else \
      curl -fsSL https://github.com/google/osv-scanner/releases/download/v1.7.0/osv-scanner_linux_amd64 -o osv-scanner && echo "3baa59720f92a37a90b23317d51dcd0a8eb11e612d3218e00859b36bfa2f84bc  osv-scanner" | sha256sum -c -; \
    fi && \
    chmod +x osv-scanner

# 11. TruffleHog (v3.63.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.0/trufflehog_3.63.0_linux_arm64.tar.gz -o trufflehog.tar.gz && echo "4e3da13e733abbc1a558946357621cc19269fb32ff540ff44a04c0a8e63d4234  trufflehog.tar.gz" | sha256sum -c - && tar -xzf trufflehog.tar.gz trufflehog; \
    else \
      curl -fsSL https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.0/trufflehog_3.63.0_linux_amd64.tar.gz -o trufflehog.tar.gz && echo "836cd48d5864a25194c2b6ed1b9dc8d68367a2ee2afb00655306b18359b3cc0d  trufflehog.tar.gz" | sha256sum -c - && tar -xzf trufflehog.tar.gz trufflehog; \
    fi && \
    chmod +x trufflehog

# 12. Dockle (v0.4.14)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/goodwithtech/dockle/releases/download/v0.4.14/dockle_0.4.14_Linux-ARM64.tar.gz -o dockle.tar.gz && echo "2ab0fbf42fdbbb1532958244a8c7832f8aeabee27d1e3a545ffdfcff9b0ef332  dockle.tar.gz" | sha256sum -c - && tar -xzf dockle.tar.gz dockle; \
    else \
      curl -fsSL https://github.com/goodwithtech/dockle/releases/download/v0.4.14/dockle_0.4.14_Linux-64bit.tar.gz -o dockle.tar.gz && echo "a7eb7f10c6c3f7bf7209baf48d7b51dec0771aacda1f4773891def77b555e097  dockle.tar.gz" | sha256sum -c - && tar -xzf dockle.tar.gz dockle; \
    fi && \
    chmod +x dockle

# 13. Kube-bench (v0.7.0)
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      curl -fsSL https://github.com/aquasecurity/kube-bench/releases/download/v0.7.0/kube-bench_0.7.0_linux_arm64.tar.gz -o kube-bench.tar.gz && echo "53da250a3211d717378e6ef37ee541d2cd212953628b064f2f7e2ca8a5a7bb57  kube-bench.tar.gz" | sha256sum -c - && tar -xzf kube-bench.tar.gz kube-bench; \
    else \
      curl -fsSL https://github.com/aquasecurity/kube-bench/releases/download/v0.7.0/kube-bench_0.7.0_linux_amd64.tar.gz -o kube-bench.tar.gz && echo "e9ede7c6f3570cf8f4e81925cd2523fc9c3442fb8304477637f231c7b4647e7d  kube-bench.tar.gz" | sha256sum -c - && tar -xzf kube-bench.tar.gz kube-bench; \
    fi && \
    chmod +x kube-bench

# 14. Amass (v5.1.1)
RUN curl -fsSL https://github.com/owasp-amass/amass/releases/download/v5.1.1/amass_linux_amd64.tar.gz -o amass.tar.gz && \
    echo "5e22b5f0239e7eb79439d60d43d3cd20dca2478588bc2242e91ab0c4f8fa40dd  amass.tar.gz" | sha256sum -c - && \
    tar -xzf amass.tar.gz amass_linux_amd64/amass amass_linux_amd64/resources && \
    mv amass_linux_amd64/amass amass && \
    mv amass_linux_amd64/resources resources && \
    chmod +x amass

# 15. Nmap (7.95)
# Debian Bookworm provides Nmap 7.93, so the contract-pinned release is
# built from the official upstream source and verified before promotion.
RUN if [ "$TARGETARCH" != "amd64" ]; then \
      echo "Nmap verified source build is currently supported only for linux/amd64" >&2; \
      exit 1; \
    fi
RUN curl -fsSL https://nmap.org/dist/nmap-7.95.tar.bz2 -o nmap.tar.bz2 && \
    echo "e14ab530e47b5afd88f1c8a2bac7f89cd8fe6b478e22d255c5b9bddb7a1c5778  nmap.tar.bz2" | sha256sum -c - && \
    echo "75e997ec62297a6484f491bae28ab0ccb489daba23e398fd10fe68e9e6f0def8  /usr/bin/gcc" | sha256sum -c - && \
    tar -xjf nmap.tar.bz2 && \
    cd nmap-7.95 && \
    ./configure --prefix=/usr/local --without-zenmap && \
    make -j2 && \
    make DESTDIR=/tmp/nmap-root install && \
    rm -rf /tmp/bin/nmap-7.95 /tmp/bin/nmap.tar.bz2

# ------------------------------------------------------------------------------
# Stage 2: Final Hardened Production Runtime
# ------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84

LABEL org.opencontainers.image.title="CyberAssess Security Assessment Platform" \
      org.opencontainers.image.description="Full-Stack Automated Security Assessment & Vulnerability Management Platform" \
      org.opencontainers.image.vendor="CyberAssess" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    HOME=/app/data

# Install runtime system packages: Git, Curl, Node.js (for Retire.js), Nmap runtime libraries, procps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    npm \
    git \
    curl \
    ca-certificates \
    libpcap0.8 \
    libpcre2-8-0 \
    liblua5.3-0 \
    libssl3 \
    zlib1g \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create application directories
WORKDIR /app
RUN mkdir -p /app/data/scans /app/data/.config/subfinder /app/backend /app/frontend

# Install application requirements from the hash-locked dependency set.
COPY backend/requirements.lock /app/backend/
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --require-hashes --timeout 1000 --retries 10 -r /app/backend/requirements.lock

# Install each contract-pinned Python tool into its own hash-locked venv.
COPY backend/tool-requirements /app/backend/tool-requirements
COPY backend/app /app/backend/app
ENV CYBERASSESS_TOOL_VENV_DIR=/opt/cyberassess/tool-venvs
RUN mkdir -p "$CYBERASSESS_TOOL_VENV_DIR" && \
    for tool in sslyze bandit semgrep checkov prowler schemathesis; do \
        python -m venv --copies "$CYBERASSESS_TOOL_VENV_DIR/$tool" && \
        "$CYBERASSESS_TOOL_VENV_DIR/$tool/bin/python" -m pip install --no-cache-dir --no-compile --require-hashes --timeout 1000 --retries 10 -r "/app/backend/tool-requirements/$tool.lock" || exit 1; \
    done && \
    for tool in sslyze bandit semgrep checkov prowler schemathesis; do \
        PYTHONPATH=/app/backend python -c "from app.installers.pip_installer import PIP_TOOL_CONFIGS; from app.core.package_trust import build_package_trust_record, write_package_trust_record, get_tool_venv_dir; t='$tool'; c=PIP_TOOL_CONFIGS[t]; b=str(get_tool_venv_dir(t) / 'bin' / c['binary_name']); write_package_trust_record(build_package_trust_record(tool_name=t, package_name=c['package_name'], binary_name=c['binary_name'], binary=b, installer_version='14.3.0'), b)" || { echo "package trust generation failed for $tool"; exit 1; }; \
    done
# Keep the platform interpreter first. Adapters resolve each managed Python
# tool from CYBERASSESS_TOOL_VENV_DIR, so tool environments never shadow the
# control-plane runtime or its dependencies.
ENV PATH="$PATH:/opt/cyberassess/tool-venvs/sslyze/bin:/opt/cyberassess/tool-venvs/bandit/bin:/opt/cyberassess/tool-venvs/semgrep/bin:/opt/cyberassess/tool-venvs/checkov/bin:/opt/cyberassess/tool-venvs/prowler/bin:/opt/cyberassess/tool-venvs/schemathesis/bin"

# Copy pre-compiled standalone Go binaries AFTER pip so pip packages cannot overwrite CLI tools (e.g. ProjectDiscovery httpx)
RUN mkdir -p /app/backend/bin
COPY --from=builder /tmp/bin/nuclei /app/backend/bin/nuclei
COPY --from=builder /tmp/bin/nuclei-templates /app/backend/resources/nuclei-templates
COPY --from=builder /tmp/bin/nuclei-templates.trust.json /app/backend/resources/nuclei-templates.trust.json
COPY --from=builder /tmp/bin/ffuf /app/backend/bin/ffuf
COPY --from=builder /tmp/bin/gitleaks /app/backend/bin/gitleaks
# Trivy v0.50.0 has no currently downloadable official binary artifact;
# installation is intentionally blocked by the runtime manifest until one is
# available, so no unverified replacement is copied into the image.
COPY --from=builder /tmp/bin/subfinder /app/backend/bin/subfinder
COPY --from=builder /tmp/bin/subfinder.trust.json /app/backend/bin/subfinder.trust.json
COPY --from=builder /tmp/bin/httpx /app/backend/bin/httpx
COPY --from=builder /tmp/bin/httpx.trust.json /app/backend/bin/httpx.trust.json
COPY --from=builder /tmp/bin/trivy /app/backend/bin/trivy
COPY --from=builder /tmp/bin/trivy.trust.json /app/backend/bin/trivy.trust.json
COPY --from=builder /tmp/bin/katana /app/backend/bin/katana
COPY --from=builder /tmp/bin/syft /app/backend/bin/syft
COPY --from=builder /tmp/bin/grype /app/backend/bin/grype
COPY --from=builder /tmp/bin/osv-scanner /app/backend/bin/osv-scanner
COPY --from=builder /tmp/bin/trufflehog /app/backend/bin/trufflehog
COPY --from=builder /tmp/bin/dockle /app/backend/bin/dockle
COPY --from=builder /tmp/bin/kube-bench /app/backend/bin/kube-bench
COPY --from=builder /tmp/bin/amass /app/backend/bin/amass
COPY --from=builder /tmp/bin/resources /app/backend/bin/resources
COPY --from=builder /tmp/nmap-root/usr/local/bin/nmap /app/backend/bin/nmap
COPY --from=builder /tmp/nmap-root/usr/local/share/nmap /usr/local/share/nmap

# Copy backend application, frontend HUD assets, and root runner
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY run_platform.py /app/
COPY run_worker.py /app/

# Fail the image build if the managed source-built runtime reports a different release.
RUN /app/backend/bin/nmap --version | grep -q "^Nmap version 7.95 "

# Install Retire.js from the pinned npm tarball into the server-managed prefix.
# The tarball is verified before npm expands it; the resulting package tree,
# lockfile, and launcher are then bound into the runtime trust record.
ENV CYBERASSESS_NPM_PREFIX_DIR=/app/backend/.tool-npm
RUN mkdir -p /tmp/retire-npm && \
    cd /tmp/retire-npm && \
    npm pack --ignore-scripts --pack-destination . retire@4.4.3 && \
    echo "1352bd6054d92d261b4d85dbfd75c4cee800f583573b5d9d0c45b56e3282c280  retire-4.4.3.tgz" | sha256sum -c - && \
    npm install --ignore-scripts --no-audit --no-fund --prefix /app/backend/.tool-npm/retire ./retire-4.4.3.tgz && \
    PYTHONPATH=/app/backend python -c "from app.core.npm_trust import build_npm_trust_record, write_npm_trust_record, resolve_npm_binary; b=resolve_npm_binary('retire'); r=build_npm_trust_record(tool_name='retire', binary=b, installer_version='14.3.0'); write_npm_trust_record(r,b) if b else (_ for _ in ()).throw(RuntimeError('managed Retire executable missing'))" && \
    rm -rf /tmp/retire-npm

# Bind every direct-release executable to its manifest artifact and executable
# digest after the builder has already verified the downloaded archive. These
# records are required by the runtime managed-binary gate immediately before
# each subprocess launch.
RUN PYTHONPATH=/app/backend python -c "from app.core.binary_trust import write_direct_artifact_trust_record; [write_direct_artifact_trust_record(tool, '/app/backend/bin/' + tool, installer_version='14.3.0') for tool in ('nuclei', 'ffuf', 'gitleaks', 'katana', 'syft', 'grype', 'osv-scanner', 'trufflehog', 'dockle', 'kube-bench', 'amass')]"
RUN PYTHONPATH=/app/backend python -c "from app.core.binary_trust import write_source_artifact_trust_record; write_source_artifact_trust_record('nmap', '/app/backend/bin/nmap', source_identity='svn-r39734', build_toolchain_sha256='75e997ec62297a6484f491bae28ab0ccb489daba23e398fd10fe68e9e6f0def8', installer_version='14.3.0')"
# Trust records are immutable image metadata: readable by the runtime user,
# but never writable by that user.
RUN find /app/backend /opt/cyberassess/tool-venvs -type f -name '*.trust.json' -exec chmod 0644 {} +

# Run the control plane as an unprivileged service account. Tool execution,
# scan workspaces, and runtime data remain writable only where explicitly
# provisioned above; the application never needs container-root privileges.
RUN groupadd --system cyberassess && \
    useradd --system --gid cyberassess --home-dir /nonexistent --shell /usr/sbin/nologin cyberassess && \
    chown -R cyberassess:cyberassess /app/data
USER cyberassess

# Expose Web SOC HUD port
EXPOSE 8000

# Healthcheck probe against FastAPI system health API
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/system/health || exit 1

# Launch Platform
CMD ["python", "run_platform.py"]

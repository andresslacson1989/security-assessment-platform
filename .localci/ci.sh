#!/usr/bin/env bash
# ==============================================================================
# CyberAssess Platform - LocalCI Automated Pipeline
# Target Stack: Python 3.13 LTS (LocalCI 'python313' Profile on CT107)
# Authoritative Contract Reference: contracts/08_TECHNICAL_IMPLEMENTATION_AND_TEST_VECTORS_CONTRACT.md (Section 10.5)
# ==============================================================================
set -euo pipefail

echo "========================================================"
echo "   CyberAssess Platform - LocalCI Automated Pipeline"
echo "========================================================"
echo "Runner Host: $(hostname)"
echo "Python Version: $(python3 --version)"
echo "Working Directory: $(pwd)"
echo "Git Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'N/A')"
echo "========================================================"

# 1. Prepare Virtual Environment
echo "=== Step 1: Setting up Python 3.13 Virtual Environment ==="
python3 -m venv .venv
source .venv/bin/activate

# 2. Install Core Dependencies & Testing Framework
echo "=== Step 2: Installing Dependencies & Pytest Suite ==="
pip install --upgrade pip setuptools wheel
pip install -r backend/requirements.txt pytest

# 3. Execute 100% Comprehensive Acceptance Test Suite
echo "=== Step 3: Executing Full Pytest Test Suite (153 Tests / 25 Scenarios) ==="
pytest tests/ -v --tb=short

# 4. Generate & Validate Output Artifacts
echo "=== Step 4: Validating System Capabilities & Exporting Diagnostics ==="
mkdir -p /output
python3 -c "
import sys, os
sys.path.insert(0, 'backend')
from app.core.models import SystemCapabilities
from app.adapters import discover_system_capabilities
caps = discover_system_capabilities()
print(f'[LocalCI Diagnostic] System Capabilities: {len(caps.tools)} tool adapters registered')
print(f'[LocalCI Diagnostic] Native Engines Ready: {caps.native_engines_ready}')
"

echo "========================================================"
echo "   LocalCI Pipeline Completed Successfully (100% Pass)"
echo "========================================================"
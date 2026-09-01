"""
Pytest configuration and python path setup.
"""

import sys
import os
from pathlib import Path

# Contract 01: production must fail closed without a configured JWT secret.
# Tests explicitly opt into TEST mode rather than weakening production startup.
os.environ.setdefault("OPERATING_MODE", "TEST")
os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-012345678901234567890123456789")

# Add the repository root and backend directory to sys.path.  Tests exercise
# both the backend package and root-level execution-plane entry points such as
# run_worker.py; keeping both paths explicit makes root-level pytest behavior
# deterministic rather than dependent on the runner's implicit sys.path.
repository_root = Path(__file__).resolve().parent.parent
backend_path = repository_root / "backend"
if str(repository_root) not in sys.path:
    sys.path.insert(0, str(repository_root))
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

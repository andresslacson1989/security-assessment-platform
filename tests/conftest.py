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

# Add backend directory to sys.path
backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

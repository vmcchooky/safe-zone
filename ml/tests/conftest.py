"""Make ML tests independently collectible from repository or ml roots."""

from __future__ import annotations

import sys
from pathlib import Path


ML_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ML_DIR.parent
for path in (REPOSITORY_ROOT, ML_DIR):
    value = str(path)
    if value not in sys.path:
        sys.path.insert(0, value)

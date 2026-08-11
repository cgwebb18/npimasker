"""Make the repo root importable so `pytest tests/` works the way the
README documents it, not just `python -m pytest` (which puts the CWD on
sys.path itself)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

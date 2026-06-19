"""Root conftest — ensures src/ is on sys.path for all pytest invocations.

This is the belt-and-suspenders fallback: even without `uv sync` having
run the editable install, pytest will still find compliance_scan.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

"""Make the project importable under ``python -m unittest`` / ``run_tests.py``.

The interpreter may be started with ``-E -P`` (as hardened service managers
do), in which case neither the working directory nor ``PYTHONPATH`` reaches
``sys.path``.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

"""``python -m haven.server`` entry point."""

from __future__ import annotations

from .daemon import main

if __name__ == "__main__":
    raise SystemExit(main())

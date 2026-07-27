"""Allow ``python -m edgedefense_mcp`` in addition to the console script."""

from __future__ import annotations

from .server import main

if __name__ == "__main__":
    main()

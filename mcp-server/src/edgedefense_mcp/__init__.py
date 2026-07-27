"""EdgeDefense MCP server.

A local, zero-configuration MCP server that answers questions about the home
network. Ships independently of the rest of the monorepo: its own packaging,
its own repository, its own MIT licence.

All detection logic lives in ``edgedefense_core`` and is shared with the
EdgeDefense application. This package is the MCP wrapper and nothing more.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__", "main"]


def main() -> None:
    """Console-script entry point (``edgedefense-mcp``)."""
    from .server import main as _main

    _main()

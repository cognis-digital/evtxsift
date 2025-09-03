"""EVTXSIFT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from evtxsift.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-evtxsift[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-evtxsift[mcp]'")
        return 1
    app = FastMCP("evtxsift")

    @app.tool()
    def evtxsift_scan(target: str) -> str:
        """Find brute-force, persistence & lateral-movement signals in exported Windows event logs. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0

"""EVTXSIFT MCP server — exposes the hunt tool as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-evtxsift[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-evtxsift[mcp]'", file=sys.stderr)
        return 1

    from evtxsift.core import analyze, load_records
    from evtxsift.cli import _render_json

    app = FastMCP("evtxsift")

    @app.tool()
    def evtxsift_scan(target: str) -> str:
        """Find brute-force, persistence & lateral-movement signals in exported
        Windows event logs (JSON array or CSV).  Returns a JSON findings report."""
        p = Path(target)
        if not p.exists():
            return json.dumps({"error": f"File not found: {target}"})
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return json.dumps({"error": f"Cannot read file: {exc}"})
        try:
            records = load_records(text)
        except (json.JSONDecodeError, ValueError) as exc:
            return json.dumps({"error": f"Failed to parse events: {exc}"})
        findings = analyze(records)
        return _render_json(findings, source=target)

    try:
        app.run()
    except Exception as exc:  # pragma: no cover
        print(f"MCP server error: {exc}", file=sys.stderr)
        return 1
    return 0

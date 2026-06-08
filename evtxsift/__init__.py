"""EVTXSIFT - threat-hunting over exported Windows event logs.

Defensive forensics/triage tool. Parses normalized Windows Security event
records (JSON or CSV exported from EVTX) and surfaces brute-force,
persistence, and lateral-movement signals. Standard library only.
"""
from .core import (
    Finding,
    Record,
    load_records,
    analyze,
    SEVERITY_ORDER,
)

TOOL_NAME = "evtxsift"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "Record",
    "load_records",
    "analyze",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "TOOL_VERSION",
]

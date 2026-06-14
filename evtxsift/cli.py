"""Command-line interface for EVTXSIFT."""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import Finding, SEVERITY_ORDER, analyze, load_records

_SEV_COLOR = {
    "critical": "#7c1d1d",
    "high": "#b4341c",
    "medium": "#b8860b",
    "low": "#2d6a4f",
    "info": "#345995",
}


def _render_table(findings: list[Finding]) -> str:
    if not findings:
        return "No findings. (0 detections)"
    lines = []
    header = f"{'SEV':<9} {'RULE':<26} {'COUNT':>6}  TITLE"
    lines.append(header)
    lines.append("-" * len(header))
    for f in findings:
        lines.append(
            f"{f.severity.upper():<9} {f.rule:<26} {f.count:>6}  {f.title}"
        )
        lines.append(f"          {f.first_seen} -> {f.last_seen}")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(
        f"{k}={counts[k]}" for k in sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 9))
    )
    lines.append("")
    lines.append(f"Total: {len(findings)} finding(s)  [{summary}]")
    return "\n".join(lines)


def _render_json(findings: list[Finding], source: str) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "source": source,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def _render_html(findings: list[Finding], source: str) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    e = html.escape

    summary_cells = "".join(
        f'<div class="card" style="border-top:4px solid {_SEV_COLOR.get(s, "#555")}">'
        f'<div class="num">{counts.get(s, 0)}</div>'
        f'<div class="lbl">{s.upper()}</div></div>'
        for s in ("critical", "high", "medium", "low", "info")
    )

    rows = []
    for f in findings:
        color = _SEV_COLOR.get(f.severity, "#555")
        ents = "".join(
            f"<li><b>{e(str(k))}:</b> {e(str(v))}</li>"
            for k, v in f.entities.items()
        )
        rows.append(
            f'<tr><td><span class="badge" style="background:{color}">'
            f"{e(f.severity.upper())}</span></td>"
            f"<td><code>{e(f.rule)}</code></td>"
            f'<td><b>{e(f.title)}</b><br><span class="desc">{e(f.description)}</span>'
            f'<ul class="ents">{ents}</ul></td>'
            f'<td class="num">{f.count}</td>'
            f'<td class="ts">{e(f.first_seen)}<br>{e(f.last_seen)}</td></tr>'
        )
    if not rows:
        rows.append('<tr><td colspan="5">No findings.</td></tr>')

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(TOOL_NAME)} report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; background: #f4f5f7; color: #1c1e21; }}
  header {{ background: #11161d; color: #fff; padding: 20px 28px; }}
  header h1 {{ margin: 0; font-size: 20px; letter-spacing: .5px; }}
  header .meta {{ color: #9aa7b4; font-size: 13px; margin-top: 4px; }}
  .wrap {{ padding: 24px 28px; max-width: 1100px; margin: 0 auto; }}
  .cards {{ display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }}
  .card {{ background: #fff; border-radius: 8px; padding: 14px 22px;
          box-shadow: 0 1px 3px rgba(0,0,0,.1); min-width: 90px; text-align: center; }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .lbl {{ font-size: 11px; color: #66707a; letter-spacing: 1px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
          border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  th {{ text-align: left; background: #e9ecef; padding: 10px 12px; font-size: 12px;
       text-transform: uppercase; letter-spacing: .5px; color: #495057; }}
  td {{ padding: 12px; border-top: 1px solid #eceff1; vertical-align: top; font-size: 14px; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; font-weight: 600; }}
  td.ts {{ font-size: 12px; color: #66707a; white-space: nowrap; }}
  .badge {{ color: #fff; padding: 3px 9px; border-radius: 12px; font-size: 11px;
           font-weight: 700; letter-spacing: .5px; }}
  .desc {{ color: #495057; font-size: 13px; }}
  code {{ background: #eceff1; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
  ul.ents {{ margin: 6px 0 0; padding-left: 18px; font-size: 12px; color: #66707a; }}
  footer {{ text-align: center; color: #9aa7b4; font-size: 12px; padding: 20px; }}
</style></head>
<body>
<header>
  <h1>EVTXSIFT &mdash; Windows Event Log Threat Hunt</h1>
  <div class="meta">source: {e(source)} &middot; {len(findings)} finding(s)
     &middot; {e(TOOL_NAME)} v{e(TOOL_VERSION)}</div>
</header>
<div class="wrap">
  <div class="cards">{summary_cells}</div>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Finding</th>
      <th>Count</th><th>Window</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>
<footer>Generated by {e(TOOL_NAME)} &middot; defensive triage only &middot;
  heuristic results require analyst review</footer>
</body></html>"""


def _cmd_hunt(args: argparse.Namespace) -> int:
    # Validate numeric thresholds — must be at least 1.
    for flag, val in (
        ("--window", args.window),
        ("--fail-threshold", args.fail_threshold),
        ("--spray-threshold", args.spray_threshold),
        ("--lateral-threshold", args.lateral_threshold),
    ):
        if val < 1:
            print(f"error: {flag} must be >= 1 (got {val})", file=sys.stderr)
            return 2

    path = Path(args.input)
    if not path.exists():
        print(f"error: input file does not exist: {args.input}", file=sys.stderr)
        return 2
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        return 2
    try:
        records = load_records(text, fmt=args.input_format)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"error: failed to parse events: {exc}", file=sys.stderr)
        return 2

    findings = analyze(
        records,
        bf_window_min=args.window,
        bf_threshold=args.fail_threshold,
        spray_threshold=args.spray_threshold,
        lateral_threshold=args.lateral_threshold,
    )

    if args.format == "json":
        out = _render_json(findings, source=str(path))
    elif args.format == "html":
        out = _render_html(findings, source=str(path))
    else:
        out = _render_table(findings)

    if args.output:
        try:
            Path(args.output).write_text(out, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write output to {args.output}: {exc}", file=sys.stderr)
            return 2
        print(f"wrote {args.format} report to {args.output} "
              f"({len(findings)} finding(s), {len(records)} event(s) scanned)",
              file=sys.stderr)
    else:
        print(out)

    # Non-zero exit when findings exist (useful for CI / pipelines).
    return 1 if findings else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Threat-hunt brute-force, persistence & lateral-movement "
                    "signals in exported Windows event logs (defensive triage).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    hunt = sub.add_parser(
        "hunt", help="analyze an exported event log (JSON/CSV) for threats"
    )
    hunt.add_argument("input", help="path to exported events (JSON array or CSV)")
    hunt.add_argument("--input-format", choices=["auto", "json", "csv"],
                      default="auto", help="input parser (default: auto-detect)")
    hunt.add_argument("--format", choices=["table", "json", "html"],
                      default="table", help="report format (default: table)")
    hunt.add_argument("-o", "--output", help="write report to file instead of stdout")
    hunt.add_argument("--window", type=int, default=5,
                      help="brute-force window in minutes (default: 5)")
    hunt.add_argument("--fail-threshold", type=int, default=5,
                      help="failed logons in window to flag (default: 5)")
    hunt.add_argument("--spray-threshold", type=int, default=5,
                      help="distinct users per source IP to flag spray (default: 5)")
    hunt.add_argument("--lateral-threshold", type=int, default=3,
                      help="distinct hosts per identity to flag lateral (default: 3)")
    hunt.set_defaults(func=_cmd_hunt)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

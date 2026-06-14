"""Core detection engine for EVTXSIFT.

Consumes Windows Security event records that have already been exported from
.evtx into a portable format (JSON array of objects, or CSV). This avoids the
proprietary binary EVTX parser while still operating on real log fields.

Expected record fields (case-insensitive, common Windows Security log names):
    EventID       int   e.g. 4625 (failed logon), 4624 (success), 4720, 7045
    TimeCreated   ISO-8601 timestamp string
    Computer      host name
    TargetUserName / SubjectUserName
    IpAddress     source IP
    LogonType     int (3=network, 10=RDP, ...)
    ServiceName / ServiceFileName (for 7045 / new service)
    TaskName      (for scheduled-task creation 4698)

Detections are heuristic and intended for triage, not as proof.
"""
from __future__ import annotations

import csv
import io
import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Iterable

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Windows Security event IDs we reason about.
E_FAILED_LOGON = 4625
E_SUCCESS_LOGON = 4624
E_EXPLICIT_CREDS = 4648  # logon using explicit credentials
E_USER_CREATED = 4720
E_ADDED_TO_GROUP = 4732  # added to security-enabled local group
E_NEW_SERVICE = 7045
E_SCHED_TASK = 4698

# Logon types that indicate remote access (lateral movement candidates).
REMOTE_LOGON_TYPES = {3, 8, 10}  # network, networkcleartext, remote-interactive(RDP)


@dataclass
class Record:
    """A normalized event record."""
    event_id: int
    time: datetime | None
    computer: str
    user: str
    ip: str
    logon_type: int | None
    detail: str
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    description: str
    count: int
    first_seen: str
    last_seen: str
    entities: dict[str, Any] = field(default_factory=dict)
    sample_event_ids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ci_get(d: dict[str, Any], *names: str, default: str = "") -> str:
    """Case-insensitive multi-key lookup."""
    lower = {str(k).lower(): v for k, v in d.items()}
    for n in names:
        v = lower.get(n.lower())
        if v not in (None, "", "-"):
            return str(v)
    return default


def _parse_time(s: str) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    # Normalize trailing Z to +00:00 for fromisoformat.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    for parser in (
        lambda x: datetime.fromisoformat(x),
        lambda x: datetime.strptime(x, "%Y-%m-%d %H:%M:%S"),
        lambda x: datetime.strptime(x, "%m/%d/%Y %I:%M:%S %p"),
    ):
        try:
            dt = parser(s)
            # Drop tzinfo so all comparisons are naive and consistent.
            return dt.replace(tzinfo=None)
        except (ValueError, TypeError):
            continue
    return None


def _to_int(s: str) -> int | None:
    try:
        return int(str(s).strip())
    except (ValueError, TypeError):
        return None


def _record_from_dict(d: dict[str, Any]) -> Record | None:
    eid = _to_int(_ci_get(d, "EventID", "Event ID", "id"))
    if eid is None:
        return None
    user = _ci_get(d, "TargetUserName", "SubjectUserName", "AccountName", "user")
    ip = _ci_get(d, "IpAddress", "SourceAddress", "ip", default="")
    detail = _ci_get(
        d, "ServiceFileName", "ServiceName", "TaskName", "NewProcessName", "detail"
    )
    return Record(
        event_id=eid,
        time=_parse_time(_ci_get(d, "TimeCreated", "Time", "timestamp", "@timestamp")),
        computer=_ci_get(d, "Computer", "Hostname", "host", default="unknown"),
        user=user,
        ip=ip,
        logon_type=_to_int(_ci_get(d, "LogonType", "Logon Type")),
        detail=detail,
        raw=d,
    )


def load_records(text: str, fmt: str = "auto") -> list[Record]:
    """Parse exported events from JSON or CSV text into Records."""
    text = text.strip()
    if not text:
        return []
    if fmt == "auto":
        fmt = "json" if text[0] in "[{" else "csv"

    rows: list[dict[str, Any]] = []
    if fmt == "json":
        data = json.loads(text)
        if isinstance(data, dict):
            # Allow {"Events": [...]} or a single record.
            _ENVELOPE_KEYS = ("Events", "events", "records", "data")
            for key in _ENVELOPE_KEYS:
                val = data.get(key)
                if val is not None:
                    # Key exists — it must be a list or the input is malformed.
                    if not isinstance(val, list):
                        raise ValueError(
                            f"Expected a JSON array under '{key}', "
                            f"got {type(val).__name__!r}"
                        )
                    data = val
                    break
            else:
                # No envelope key found — treat the dict itself as a single record.
                data = [data]
        if not isinstance(data, list):
            raise ValueError(
                f"Expected a JSON array of event records, got {type(data).__name__}"
            )
        rows = [r for r in data if isinstance(r, dict)]
    else:
        reader = csv.DictReader(io.StringIO(text))
        rows = [dict(r) for r in reader]

    records = [r for r in (_record_from_dict(d) for d in rows) if r is not None]
    return records


def _fmt_time(dt: datetime | None) -> str:
    return dt.isoformat(sep=" ") if dt else "unknown"


def _span(times: list[datetime]) -> tuple[str, str]:
    valid = sorted(t for t in times if t is not None)
    if not valid:
        return ("unknown", "unknown")
    return (_fmt_time(valid[0]), _fmt_time(valid[-1]))


def _detect_bruteforce(
    records: list[Record], window_min: int, threshold: int
) -> list[Finding]:
    """Sliding-window count of 4625 failures per (ip,user)."""
    findings: list[Finding] = []
    buckets: dict[tuple[str, str], list[Record]] = defaultdict(list)
    for r in records:
        if r.event_id == E_FAILED_LOGON:
            key = (r.ip or "local", r.user or "?")
            buckets[key].append(r)

    window = timedelta(minutes=window_min)
    for (ip, user), recs in buckets.items():
        timed = sorted([r for r in recs if r.time], key=lambda r: r.time)
        untimed = [r for r in recs if not r.time]
        # Find the densest window.
        best = 0
        best_slice: list[Record] = []
        i = 0
        for j in range(len(timed)):
            while timed[j].time - timed[i].time > window:
                i += 1
            if j - i + 1 > best:
                best = j - i + 1
                best_slice = timed[i : j + 1]
        # If no timestamps, fall back to raw count.
        total = best if timed else len(untimed)
        if total < threshold:
            continue

        slice_recs = best_slice if best_slice else recs
        # Did any success follow from same ip/user? (possible compromise)
        compromised = any(
            r.event_id == E_SUCCESS_LOGON
            and (r.ip or "local") == ip
            and r.user == user
            for r in records
        )
        fs, ls = _span([r.time for r in slice_recs])
        sev = "critical" if compromised else "high"
        title = f"Brute-force against '{user}' from {ip}"
        desc = (
            f"{total} failed logons (4625) within {window_min}m."
            + (" A SUCCESSFUL logon from the same source/user was also "
               "observed - possible account compromise." if compromised else "")
        )
        findings.append(
            Finding(
                rule="bruteforce_logon",
                severity=sev,
                title=title,
                description=desc,
                count=total,
                first_seen=fs,
                last_seen=ls,
                entities={"ip": ip, "user": user, "compromised": compromised},
                sample_event_ids=[E_FAILED_LOGON]
                + ([E_SUCCESS_LOGON] if compromised else []),
            )
        )
    return findings


def _detect_password_spray(records: list[Record], threshold: int) -> list[Finding]:
    """One source IP failing against many distinct users = spray."""
    by_ip: dict[str, set[str]] = defaultdict(set)
    times_by_ip: dict[str, list[datetime]] = defaultdict(list)
    for r in records:
        if r.event_id == E_FAILED_LOGON and r.ip:
            by_ip[r.ip].add(r.user or "?")
            if r.time:
                times_by_ip[r.ip].append(r.time)
    findings: list[Finding] = []
    for ip, users in by_ip.items():
        if len(users) < threshold:
            continue
        fs, ls = _span(times_by_ip[ip])
        findings.append(
            Finding(
                rule="password_spray",
                severity="high",
                title=f"Password spray from {ip}",
                description=(
                    f"Source {ip} produced failed logons against "
                    f"{len(users)} distinct accounts."
                ),
                count=len(users),
                first_seen=fs,
                last_seen=ls,
                entities={"ip": ip, "users": sorted(users)[:20]},
                sample_event_ids=[E_FAILED_LOGON],
            )
        )
    return findings


def _detect_persistence(records: list[Record]) -> list[Finding]:
    """New services (7045), scheduled tasks (4698), new users / group adds."""
    findings: list[Finding] = []
    susp_tokens = (
        "powershell", "cmd.exe", "-enc", "-encodedcommand", "wscript",
        "cscript", "mshta", "rundll32", "regsvr32", "\\temp\\",
        "\\appdata\\", "certutil", "bitsadmin",
    )
    for r in records:
        if r.event_id == E_NEW_SERVICE:
            low = r.detail.lower()
            suspicious = any(t in low for t in susp_tokens)
            findings.append(
                Finding(
                    rule="new_service_install",
                    severity="high" if suspicious else "medium",
                    title=f"Service installed on {r.computer}",
                    description=(
                        f"New service (7045): {r.detail or 'unknown'}"
                        + (" - command line matches known LOLBin/script "
                           "persistence pattern." if suspicious else "")
                    ),
                    count=1,
                    first_seen=_fmt_time(r.time),
                    last_seen=_fmt_time(r.time),
                    entities={"computer": r.computer, "service": r.detail,
                              "user": r.user},
                    sample_event_ids=[E_NEW_SERVICE],
                )
            )
        elif r.event_id == E_SCHED_TASK:
            findings.append(
                Finding(
                    rule="scheduled_task_created",
                    severity="medium",
                    title=f"Scheduled task created on {r.computer}",
                    description=f"Scheduled task registered (4698): {r.detail}",
                    count=1,
                    first_seen=_fmt_time(r.time),
                    last_seen=_fmt_time(r.time),
                    entities={"computer": r.computer, "task": r.detail,
                              "user": r.user},
                    sample_event_ids=[E_SCHED_TASK],
                )
            )
        elif r.event_id == E_USER_CREATED:
            findings.append(
                Finding(
                    rule="local_user_created",
                    severity="medium",
                    title=f"New account '{r.user}' created",
                    description=f"A user account was created (4720) on {r.computer}.",
                    count=1,
                    first_seen=_fmt_time(r.time),
                    last_seen=_fmt_time(r.time),
                    entities={"computer": r.computer, "user": r.user},
                    sample_event_ids=[E_USER_CREATED],
                )
            )
        elif r.event_id == E_ADDED_TO_GROUP:
            findings.append(
                Finding(
                    rule="privileged_group_change",
                    severity="high",
                    title=f"Account added to security group on {r.computer}",
                    description=(
                        f"Member added to a security-enabled group (4732): "
                        f"{r.user or r.detail}"
                    ),
                    count=1,
                    first_seen=_fmt_time(r.time),
                    last_seen=_fmt_time(r.time),
                    entities={"computer": r.computer, "member": r.user},
                    sample_event_ids=[E_ADDED_TO_GROUP],
                )
            )
    return findings


def _detect_lateral(records: list[Record], threshold: int) -> list[Finding]:
    """One source identity authenticating to many hosts via remote logon."""
    findings: list[Finding] = []
    # Key on (user, ip) -> set of target computers via remote logon types.
    reach: dict[tuple[str, str], set[str]] = defaultdict(set)
    times: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    for r in records:
        if (
            r.event_id in (E_SUCCESS_LOGON, E_EXPLICIT_CREDS)
            and r.logon_type in REMOTE_LOGON_TYPES
        ):
            key = (r.user or "?", r.ip or "unknown")
            reach[key].add(r.computer)
            if r.time:
                times[key].append(r.time)
    for (user, ip), hosts in reach.items():
        if len(hosts) < threshold:
            continue
        fs, ls = _span(times[(user, ip)])
        findings.append(
            Finding(
                rule="lateral_movement",
                severity="high",
                title=f"Lateral movement by '{user}' from {ip}",
                description=(
                    f"Identity '{user}' (src {ip}) remotely authenticated to "
                    f"{len(hosts)} distinct hosts (logon types "
                    f"{sorted(REMOTE_LOGON_TYPES)})."
                ),
                count=len(hosts),
                first_seen=fs,
                last_seen=ls,
                entities={"user": user, "ip": ip, "hosts": sorted(hosts)},
                sample_event_ids=[E_SUCCESS_LOGON],
            )
        )
    return findings


def analyze(
    records: Iterable[Record],
    bf_window_min: int = 5,
    bf_threshold: int = 5,
    spray_threshold: int = 5,
    lateral_threshold: int = 3,
) -> list[Finding]:
    """Run all detection rules and return findings sorted by severity.

    All threshold/window parameters must be >= 1; a ValueError is raised
    otherwise so callers get a clear diagnostic instead of silent misfires.
    """
    for name, val in (
        ("bf_window_min", bf_window_min),
        ("bf_threshold", bf_threshold),
        ("spray_threshold", spray_threshold),
        ("lateral_threshold", lateral_threshold),
    ):
        if not isinstance(val, int) or val < 1:
            raise ValueError(f"{name} must be a positive integer >= 1, got {val!r}")
    recs = list(records)
    findings: list[Finding] = []
    findings += _detect_bruteforce(recs, bf_window_min, bf_threshold)
    findings += _detect_password_spray(recs, spray_threshold)
    findings += _detect_persistence(recs)
    findings += _detect_lateral(recs, lateral_threshold)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule))
    return findings

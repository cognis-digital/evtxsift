"""Smoke tests for EVTXSIFT. No network. Standard library only."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from evtxsift import TOOL_NAME, TOOL_VERSION, analyze, load_records  # noqa: E402
from evtxsift.cli import _render_html, _render_json, main  # noqa: E402

DEMO = REPO / "demos" / "01-basic" / "security_events.json"


class LoadTests(unittest.TestCase):
    def test_load_json(self):
        recs = load_records(DEMO.read_text(encoding="utf-8"))
        self.assertTrue(len(recs) >= 15)
        self.assertTrue(any(r.event_id == 4625 for r in recs))

    def test_load_csv(self):
        csv_text = (
            "EventID,TimeCreated,Computer,TargetUserName,IpAddress,LogonType\n"
            "4625,2026-06-01T02:14:01,DC01,admin,1.2.3.4,3\n"
            "4624,2026-06-01T02:15:01,DC01,admin,1.2.3.4,3\n"
        )
        recs = load_records(csv_text)
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0].event_id, 4625)

    def test_empty(self):
        self.assertEqual(load_records(""), [])


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.recs = load_records(DEMO.read_text(encoding="utf-8"))
        self.findings = analyze(self.recs)
        self.rules = {f.rule for f in self.findings}

    def test_bruteforce_detected_and_critical(self):
        bf = [f for f in self.findings if f.rule == "bruteforce_logon"]
        self.assertTrue(bf)
        # Success followed failures -> critical.
        self.assertTrue(any(f.severity == "critical" for f in bf))

    def test_password_spray_detected(self):
        self.assertIn("password_spray", self.rules)

    def test_persistence_detected(self):
        self.assertIn("new_service_install", self.rules)
        svc = next(f for f in self.findings if f.rule == "new_service_install")
        # Encoded-powershell binary should escalate to high.
        self.assertEqual(svc.severity, "high")

    def test_lateral_movement_detected(self):
        self.assertIn("lateral_movement", self.rules)
        lat = next(f for f in self.findings if f.rule == "lateral_movement")
        self.assertGreaterEqual(lat.count, 3)

    def test_clean_log_no_findings(self):
        clean = json.dumps([
            {"EventID": 4624, "TimeCreated": "2026-06-01T08:00:00",
             "Computer": "WS01", "TargetUserName": "alice",
             "IpAddress": "10.0.0.5", "LogonType": 2},
        ])
        self.assertEqual(analyze(load_records(clean)), [])


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.findings = analyze(load_records(DEMO.read_text(encoding="utf-8")))

    def test_json_render_roundtrip(self):
        payload = json.loads(_render_json(self.findings, "x"))
        self.assertEqual(payload["tool"], TOOL_NAME)
        self.assertEqual(payload["finding_count"], len(self.findings))

    def test_html_self_contained(self):
        out = _render_html(self.findings, "x")
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("<style>", out)  # inline CSS, no external deps
        self.assertNotIn("http://", out)
        self.assertNotIn("https://", out)


class CliTests(unittest.TestCase):
    def test_version(self):
        proc = subprocess.run(
            [sys.executable, "-m", "evtxsift", "--version"],
            cwd=str(REPO), capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn(TOOL_VERSION, proc.stdout)

    def test_hunt_exit_nonzero_on_findings(self):
        rc = main(["hunt", str(DEMO), "--format", "json"])
        self.assertEqual(rc, 1)  # findings present -> exit 1

    def test_hunt_table(self):
        rc = main(["hunt", str(DEMO)])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

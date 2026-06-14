"""Hardening tests for EVTXSIFT: error paths, bad input, edge cases."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from evtxsift.core import analyze, load_records  # noqa: E402
from evtxsift.cli import main  # noqa: E402


class LoadRecordsEdgeCases(unittest.TestCase):
    """Validate load_records on malformed and edge-case input."""

    def test_whitespace_only_returns_empty(self):
        """Whitespace-only text is treated as empty — no crash."""
        self.assertEqual(load_records("   \n\t  "), [])

    def test_malformed_json_raises(self):
        """Truncated JSON raises json.JSONDecodeError (not a silent empty list)."""
        with self.assertRaises(json.JSONDecodeError):
            load_records("[{bad")

    def test_json_scalar_raises_value_error(self):
        """A bare JSON scalar (not array or dict) raises ValueError when fmt=json."""
        with self.assertRaises(ValueError):
            load_records("42", fmt="json")

    def test_json_dict_with_non_list_events_key_raises(self):
        """A dict whose 'Events' value is a string (not a list) raises ValueError."""
        payload = json.dumps({"Events": "not-a-list"})
        with self.assertRaises(ValueError):
            load_records(payload)

    def test_json_array_of_non_dicts_ignored(self):
        """Non-dict elements in the array are silently skipped."""
        payload = json.dumps([1, "string", None, {"EventID": 4624}])
        recs = load_records(payload)
        # Only the dict element is kept; and it must have EventID to produce a Record.
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].event_id, 4624)

    def test_records_missing_event_id_skipped(self):
        """Records without an EventID field are silently skipped."""
        payload = json.dumps([
            {"TimeCreated": "2026-01-01T00:00:00", "Computer": "HOST"},
            {"EventID": 4625, "Computer": "HOST2"},
        ])
        recs = load_records(payload)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].event_id, 4625)

    def test_csv_empty_rows_handled(self):
        """CSV with only a header row produces an empty record list."""
        recs = load_records("EventID,TimeCreated,Computer\n")
        self.assertEqual(recs, [])

    def test_json_wrapped_in_dict_events_key(self):
        """{'Events': [...]} envelope is unwrapped correctly."""
        payload = json.dumps({"Events": [
            {"EventID": 4720, "Computer": "DC01"},
        ]})
        recs = load_records(payload)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].event_id, 4720)


class AnalyzeThresholdValidation(unittest.TestCase):
    """analyze() must reject non-positive threshold/window values."""

    def test_zero_window_raises(self):
        with self.assertRaises(ValueError):
            analyze([], bf_window_min=0)

    def test_negative_threshold_raises(self):
        with self.assertRaises(ValueError):
            analyze([], bf_threshold=-1)

    def test_zero_spray_threshold_raises(self):
        with self.assertRaises(ValueError):
            analyze([], spray_threshold=0)

    def test_zero_lateral_threshold_raises(self):
        with self.assertRaises(ValueError):
            analyze([], lateral_threshold=0)

    def test_valid_thresholds_accepted(self):
        """Minimum valid thresholds (all = 1) must not raise."""
        result = analyze([], bf_window_min=1, bf_threshold=1,
                         spray_threshold=1, lateral_threshold=1)
        self.assertEqual(result, [])


class CliInputValidation(unittest.TestCase):
    """CLI error paths must return exit code 2 with a message to stderr."""

    def test_missing_file_exits_2(self):
        rc = main(["hunt", "/nonexistent/path/events.json"])
        self.assertEqual(rc, 2)

    def test_zero_window_exits_2(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w",
                                        delete=False) as f:
            f.write("[]")
            tmp = f.name
        try:
            rc = main(["hunt", tmp, "--window", "0"])
            self.assertEqual(rc, 2)
        finally:
            Path(tmp).unlink(missing_ok=True)

    def test_negative_fail_threshold_exits_2(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w",
                                        delete=False) as f:
            f.write("[]")
            tmp = f.name
        try:
            rc = main(["hunt", tmp, "--fail-threshold", "-1"])
            self.assertEqual(rc, 2)
        finally:
            Path(tmp).unlink(missing_ok=True)

    def test_malformed_json_exits_2(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w",
                                        delete=False) as f:
            f.write("{bad json")
            tmp = f.name
        try:
            rc = main(["hunt", tmp])
            self.assertEqual(rc, 2)
        finally:
            Path(tmp).unlink(missing_ok=True)

    def test_empty_input_exits_0(self):
        """An empty (but valid) JSON array produces no findings — exit 0."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w",
                                        delete=False) as f:
            f.write("[]")
            tmp = f.name
        try:
            rc = main(["hunt", tmp])
            self.assertEqual(rc, 0)
        finally:
            Path(tmp).unlink(missing_ok=True)

    def test_output_write_error_exits_2(self):
        """Writing to an unwritable path returns exit code 2."""
        demo = REPO / "demos" / "01-basic" / "security_events.json"
        # Use a path in a non-existent directory to guarantee write failure.
        bad_out = str(REPO / "nonexistent_dir_xyz" / "out.html")
        rc = main(["hunt", str(demo), "-o", bad_out])
        self.assertEqual(rc, 2)


class McpServerImport(unittest.TestCase):
    """mcp_server module must be importable without errors."""

    def test_module_imports_without_crash(self):
        """Importing mcp_server must not raise (broken scan/to_json was a regression)."""
        import importlib
        import evtxsift.mcp_server as m
        importlib.reload(m)  # force re-import to catch any top-level errors
        self.assertTrue(callable(m.serve))


if __name__ == "__main__":
    unittest.main()

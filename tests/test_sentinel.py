import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel import detect, file_sha256, load_jsonl


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"timestamp": f"2026-01-01T10:00:0{i}+00:00", "event_type": "login_failed",
             "source_ip": "192.0.2.1", "username": "alice"}
            for i in range(5)
        ]

    def test_brute_force_ip_detected(self):
        alerts = detect(self.events, failed_threshold=5, window_minutes=10)
        self.assertIn("BRUTE_FORCE_IP", {a.rule for a in alerts})

    def test_no_alert_below_threshold(self):
        alerts = detect(self.events[:3], failed_threshold=5, window_minutes=10)
        self.assertNotIn("BRUTE_FORCE_IP", {a.rule for a in alerts})

    def test_success_after_failures(self):
        events = self.events[:3] + [
            {"timestamp": "2026-01-01T10:01:00+00:00", "event_type": "login_success",
             "source_ip": "192.0.2.1", "username": "alice"}
        ]
        alerts = detect(events, failed_threshold=5, window_minutes=10)
        self.assertIn("SUCCESS_AFTER_FAILURES", {a.rule for a in alerts})

    def test_unknown_user_allowlist(self):
        alerts = detect(self.events[:1], known_users={"bob"})
        self.assertIn("UNKNOWN_USER", {a.rule for a in alerts})

    def test_jsonl_and_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text(json.dumps(self.events[0]) + "\n", encoding="utf-8")
            loaded = load_jsonl(path)
            self.assertEqual(len(loaded), 1)
            first_hash = file_sha256(path)
            path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            self.assertNotEqual(first_hash, file_sha256(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)

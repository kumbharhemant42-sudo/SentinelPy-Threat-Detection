import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel import detect, validate_event

class AddedFeatureSmokeTests(unittest.TestCase):
    def test_live_monitor_event_validation(self):
        event = validate_event({"timestamp":"2026-01-01T10:00:00+00:00", "event_type":"login_failed", "source_ip":"192.0.2.1", "username":"alice"}, 1)
        self.assertEqual(event["event_type"], "login_failed")

    def test_live_monitor_detects_failure_burst(self):
        events = [{"timestamp":f"2026-01-01T10:00:0{i}+00:00", "event_type":"login_failed", "source_ip":"192.0.2.1", "username":"alice"} for i in range(5)]
        self.assertIn("BRUTE_FORCE_IP", {a.rule for a in detect(events)})

if __name__ == '__main__': unittest.main()

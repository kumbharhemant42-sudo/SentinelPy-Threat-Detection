#!/usr/bin/env python3
"""Follow a JSONL security log and alert on newly appended entries.
Use only with logs you own or are authorized to monitor. Ctrl+C stops monitoring.
"""
from __future__ import annotations
import argparse, json, time
from collections import deque
from pathlib import Path
from sentinel import detect, load_jsonl, validate_event, SEVERITY_RANK


def follow(path: Path, poll_seconds: float = 1.0, start_at_end: bool = True) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Log file does not exist: {path}")
    print(f"SentinelPy live monitor watching: {path.resolve()}")
    print("Append JSONL events to this file. Press Ctrl+C to stop.\n")
    offset = path.stat().st_size if start_at_end else 0
    history = deque(maxlen=5000)
    seen_alerts: set[tuple[str, str, str, str]] = set()
    line_number = 0
    try:
        while True:
            size = path.stat().st_size
            if size < offset:  # file was truncated/rotated
                offset = 0
                history.clear()
                seen_alerts.clear()
                print("[INFO] Log file was truncated/rotated; monitoring from start.")
            if size > offset:
                with path.open('r', encoding='utf-8') as handle:
                    handle.seek(offset)
                    chunk = handle.read()
                    offset = handle.tell()
                # If the last write was partial, defer that tail until next poll.
                if chunk and not chunk.endswith('\n'):
                    last_newline = chunk.rfind('\n')
                    complete = chunk[:last_newline + 1] if last_newline >= 0 else ''
                    remainder = chunk[last_newline + 1:]
                    offset -= len(remainder.encode('utf-8'))
                    chunk = complete
                for raw in chunk.splitlines():
                    line_number += 1
                    if not raw.strip() or raw.lstrip().startswith('#'):
                        continue
                    try:
                        event = validate_event(json.loads(raw), line_number)
                    except (json.JSONDecodeError, ValueError) as exc:
                        print(f"[WARN] Skipping malformed new log line: {exc}")
                        continue
                    history.append(event)
                    alerts = detect(list(history))
                    for alert in alerts:
                        key = (alert.rule, alert.source_ip, alert.username, alert.timestamp)
                        if key in seen_alerts:
                            continue
                        seen_alerts.add(key)
                        print(f"[{alert.severity}] {alert.rule} | IP={alert.source_ip} user={alert.username}")
                        print(f"        {alert.message}")
            time.sleep(max(0.2, poll_seconds))
    except KeyboardInterrupt:
        print("\nLive monitoring stopped by user.")


def main() -> int:
    parser = argparse.ArgumentParser(description='Monitor appended JSONL security events')
    parser.add_argument('--log', type=Path, default=Path(__file__).resolve().parent/'data'/'sample_events.jsonl')
    parser.add_argument('--poll', type=float, default=1.0, help='poll interval in seconds (default: 1)')
    parser.add_argument('--from-start', action='store_true', help='read existing lines as well as new lines')
    args = parser.parse_args()
    try:
        follow(args.log, args.poll, start_at_end=not args.from_start)
    except (OSError, UnicodeError) as exc:
        print(f"Error: {exc}")
        return 2
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

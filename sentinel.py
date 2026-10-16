#!/usr/bin/env python3
"""SentinelPy: local, defensive security-log analyzer. Python 3.10+, standard library only."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

APP_DIR = Path(__file__).resolve().parent
DEFAULT_DB = APP_DIR / "sentinel.db"
DEFAULT_LOG = APP_DIR / "data" / "sample_events.jsonl"
DEFAULT_REPORT = APP_DIR / "reports" / "alerts.csv"
KNOWN_EVENTS = {"login_failed", "login_success", "access_denied", "privileged_action", "file_changed"}
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Alert:
    timestamp: str
    severity: str
    rule: str
    source_ip: str
    username: str
    message: str
    event_ids: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"Invalid ISO-8601 timestamp: {value!r}") from exc


def validate_event(event: Any, line_no: int) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError(f"Line {line_no}: each JSONL line must be a JSON object")
    required = ("timestamp", "event_type", "source_ip", "username")
    missing = [key for key in required if not event.get(key)]
    if missing:
        raise ValueError(f"Line {line_no}: missing required field(s): {', '.join(missing)}")
    event["timestamp"] = parse_time(str(event["timestamp"])).isoformat()
    event["event_type"] = str(event["event_type"]).strip().lower()
    event["source_ip"] = str(event["source_ip"]).strip()
    event["username"] = str(event["username"]).strip()
    if event["event_type"] not in KNOWN_EVENTS:
        event["unknown_event_type"] = True
    return event


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                parsed = json.loads(line)
                events.append(validate_event(parsed, line_no))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Line {line_no}: invalid JSON ({exc.msg})") from exc
    return sorted(events, key=lambda item: item["timestamp"])


def connect_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            raw_json TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            rule TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            event_ids TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def store_events(conn: sqlite3.Connection, events: Iterable[dict[str, Any]]) -> int:
    inserted = 0
    for event in events:
        cur = conn.execute(
            "INSERT INTO events(timestamp,event_type,source_ip,username,raw_json) VALUES(?,?,?,?,?)",
            (event["timestamp"], event["event_type"], event["source_ip"], event["username"],
             json.dumps(event, sort_keys=True)),
        )
        inserted += cur.rowcount
    conn.commit()
    return inserted


def make_alert(event: dict[str, Any], severity: str, rule: str, message: str,
               event_ids: list[int] | None = None) -> Alert:
    return Alert(
        timestamp=event["timestamp"], severity=severity, rule=rule,
        source_ip=event["source_ip"], username=event["username"], message=message,
        event_ids=",".join(map(str, event_ids or [])),
    )


def detect(events: list[dict[str, Any]], failed_threshold: int = 5,
           window_minutes: int = 10, known_users: set[str] | None = None) -> list[Alert]:
    """Apply transparent rules to normalized events; thresholds are configurable."""
    if failed_threshold < 2:
        raise ValueError("failed_threshold must be at least 2")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")
    known_users = known_users or set()
    failures_by_ip: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    failures_by_user: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    alerts: list[Alert] = []
    emitted_bursts: set[tuple[str, str]] = set()
    failed_for_user: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        when = parse_time(event["timestamp"])
        etype = event["event_type"]
        ip = event["source_ip"]
        user = event["username"]

        if event.get("unknown_event_type"):
            alerts.append(make_alert(event, "LOW", "UNKNOWN_EVENT_TYPE",
                                     f"Unrecognized event type: {etype}"))

        if known_users and user not in known_users and user not in {"-", "unknown", "system"}:
            alerts.append(make_alert(event, "MEDIUM", "UNKNOWN_USER",
                                     f"Event references user not in configured allowlist: {user}"))

        if etype == "login_failed":
            by_ip = failures_by_ip[ip]
            by_user = failures_by_user[user]
            cutoff = when - timedelta(minutes=window_minutes)
            while by_ip and parse_time(by_ip[0]["timestamp"]) < cutoff:
                by_ip.popleft()
            while by_user and parse_time(by_user[0]["timestamp"]) < cutoff:
                by_user.popleft()
            by_ip.append(event)
            by_user.append(event)
            failed_for_user[user].append(event)

            if len(by_ip) >= failed_threshold and ("ip", ip) not in emitted_bursts:
                alerts.append(make_alert(
                    event, "HIGH", "BRUTE_FORCE_IP",
                    f"{len(by_ip)} failed logins from {ip} within {window_minutes} minutes",
                    [e.get("_db_id", 0) for e in by_ip]))
                emitted_bursts.add(("ip", ip))

            if len(by_user) >= failed_threshold and ("user", user) not in emitted_bursts:
                alerts.append(make_alert(
                    event, "HIGH", "BRUTE_FORCE_USER",
                    f"{len(by_user)} failed logins for account {user} within {window_minutes} minutes",
                    [e.get("_db_id", 0) for e in by_user]))
                emitted_bursts.add(("user", user))

        elif etype == "login_success":
            recent = failed_for_user.get(user, [])
            cutoff = when - timedelta(minutes=window_minutes)
            recent = [e for e in recent if parse_time(e["timestamp"]) >= cutoff]
            if len(recent) >= 3:
                alerts.append(make_alert(
                    event, "HIGH", "SUCCESS_AFTER_FAILURES",
                    f"Successful login for {user} followed {len(recent)} failed attempts in {window_minutes} minutes",
                    [e.get("_db_id", 0) for e in recent] + [event.get("_db_id", 0)]))

        elif etype == "access_denied":
            alerts.append(make_alert(event, "MEDIUM", "ACCESS_DENIED",
                                     "Access was denied; review resource and account context"))

        elif etype == "privileged_action":
            alerts.append(make_alert(event, "MEDIUM", "PRIVILEGED_ACTION",
                                     "Privileged action recorded; verify it was authorized"))

        elif etype == "file_changed":
            alerts.append(make_alert(event, "LOW", "FILE_CHANGED",
                                     "File change event recorded; compare against approved change window"))

    # Deduplicate identical rule + source + user + timestamp combinations.
    unique: dict[tuple[str, str, str, str], Alert] = {}
    for alert in alerts:
        unique[(alert.rule, alert.source_ip, alert.username, alert.timestamp)] = alert
    return sorted(unique.values(), key=lambda a: (a.timestamp, -SEVERITY_RANK.get(a.severity, 0)))


def save_alerts(conn: sqlite3.Connection, alerts: list[Alert]) -> int:
    created = utc_now().isoformat()
    count = 0
    for a in alerts:
        conn.execute(
            """INSERT INTO alerts(timestamp,severity,rule,source_ip,username,message,event_ids,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (a.timestamp, a.severity, a.rule, a.source_ip, a.username, a.message, a.event_ids, created),
        )
        count += 1
    conn.commit()
    return count


def print_dashboard(conn: sqlite3.Connection) -> None:
    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    print("\n=== SentinelPy Security Dashboard ===")
    print(f"Events stored: {total_events} | Alerts stored: {total_alerts}")
    print("\nAlert severity summary:")
    rows = conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity ORDER BY COUNT(*) DESC")
    summary = list(rows)
    if not summary:
        print("  No alerts yet.")
    else:
        for severity, count in summary:
            print(f"  {severity:<8} {count}")
    print("\nLatest alerts:")
    rows = conn.execute(
        "SELECT timestamp,severity,rule,source_ip,username,message FROM alerts ORDER BY id DESC LIMIT 15"
    )
    latest = list(rows)
    if not latest:
        print("  No alerts yet.")
    for timestamp, severity, rule, ip, username, message in latest:
        print(f"[{severity:<8}] {timestamp} | {rule} | IP={ip} user={username}")
        print(f"           {message}")


def export_csv(conn: sqlite3.Connection, path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = conn.execute(
        "SELECT id,timestamp,severity,rule,source_ip,username,message,event_ids,created_at "
        "FROM alerts ORDER BY id"
    ).fetchall()
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "timestamp", "severity", "rule", "source_ip", "username",
                         "message", "event_ids", "created_at"])
        writer.writerows(rows)
    return len(rows)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def integrity_command(log_path: Path, baseline_path: Path, create: bool) -> int:
    if not log_path.exists():
        print(f"Error: log file not found: {log_path}", file=sys.stderr)
        return 2
    current = file_sha256(log_path)
    if create:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps({
            "file": str(log_path.resolve()), "sha256": current, "created_at": utc_now().isoformat()
        }, indent=2) + "\n", encoding="utf-8")
        print(f"Baseline created: {baseline_path}\nSHA-256: {current}")
        return 0
    if not baseline_path.exists():
        print(f"No baseline found at {baseline_path}. Create one with --create-baseline.", file=sys.stderr)
        return 2
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    expected = baseline.get("sha256")
    if current == expected:
        print("OK: log file matches the saved SHA-256 baseline.")
        return 0
    print("WARNING: log file differs from the saved baseline!")
    print(f"Expected: {expected}\nCurrent:  {current}")
    return 1


def create_demo(path: Path) -> None:
    now = utc_now().replace(microsecond=0)
    events: list[dict[str, Any]] = []
    # All events are synthetic and use documentation-only IP addresses.
    for i in range(6):
        events.append({
            "timestamp": (now - timedelta(minutes=5) + timedelta(seconds=i * 20)).isoformat(),
            "event_type": "login_failed", "source_ip": "192.0.2.44",
            "username": "demo_admin", "resource": "/login", "message": "Synthetic failed login"
        })
    events.append({
        "timestamp": (now - timedelta(minutes=3)).isoformat(),
        "event_type": "login_success", "source_ip": "192.0.2.44",
        "username": "demo_admin", "resource": "/login", "message": "Synthetic successful login"
    })
    events.extend([
        {"timestamp": (now - timedelta(minutes=2)).isoformat(), "event_type": "access_denied",
         "source_ip": "198.51.100.21", "username": "guest", "resource": "/admin"},
        {"timestamp": (now - timedelta(minutes=1)).isoformat(), "event_type": "privileged_action",
         "source_ip": "203.0.113.8", "username": "demo_admin", "action": "user_created"},
    ])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    print(f"Wrote {len(events)} synthetic events to {path}")


def run_analysis(args: argparse.Namespace) -> int:
    log_path = args.log
    if not log_path.exists():
        print(f"Error: log file not found: {log_path}", file=sys.stderr)
        return 2
    try:
        events = load_jsonl(log_path)
    except (ValueError, OSError) as exc:
        print(f"Error reading logs: {exc}", file=sys.stderr)
        return 2
    conn = connect_db(args.db)
    try:
        inserted = store_events(conn, events)
        known = set(args.known_user or [])
        alerts = detect(events, args.threshold, args.window, known)
        saved = save_alerts(conn, alerts)
        print(f"Loaded {len(events)} events; stored {inserted}; generated {len(alerts)} alerts; saved {saved}.")
        print_dashboard(conn)
        if args.export:
            count = export_csv(conn, args.export)
            print(f"\nExported {count} alert rows to {args.export}")
    finally:
        conn.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SentinelPy defensive security log analyzer")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a JSON Lines event log")
    analyze.add_argument("--log", type=Path, default=DEFAULT_LOG, help=f"JSONL log path (default: {DEFAULT_LOG})")
    analyze.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite database path (default: {DEFAULT_DB})")
    analyze.add_argument("--threshold", type=int, default=5, help="failed-login threshold (default: 5)")
    analyze.add_argument("--window", type=int, default=10, help="time window in minutes (default: 10)")
    analyze.add_argument("--known-user", action="append", help="known username allowlist; may be repeated")
    analyze.add_argument("--export", type=Path, default=DEFAULT_REPORT, help=f"CSV output path (default: {DEFAULT_REPORT})")
    analyze.set_defaults(func=run_analysis)

    demo = sub.add_parser("demo", help="Create synthetic demo logs")
    demo.add_argument("--out", type=Path, default=DEFAULT_LOG)
    demo.set_defaults(func=lambda a: (create_demo(a.out) or 0))

    integrity = sub.add_parser("integrity", help="Check log file SHA-256 against a baseline")
    integrity.add_argument("--log", type=Path, default=DEFAULT_LOG)
    integrity.add_argument("--baseline", type=Path, default=APP_DIR / "data" / "log_baseline.json")
    integrity.add_argument("--create-baseline", action="store_true", help="save current hash as baseline")
    integrity.set_defaults(func=lambda a: integrity_command(a.log, a.baseline, a.create_baseline))

    dashboard = sub.add_parser("dashboard", help="Show stored database summary")
    dashboard.add_argument("--db", type=Path, default=DEFAULT_DB)
    def run_dashboard(a: argparse.Namespace) -> int:
        conn = connect_db(a.db)
        try:
            print_dashboard(conn)
        finally:
            conn.close()
        return 0
    dashboard.set_defaults(func=run_dashboard)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except (OSError, sqlite3.Error, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

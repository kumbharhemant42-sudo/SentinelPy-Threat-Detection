# SentinelPy — Defensive Python Threat Detection

A local, rule-based security log analyzer for **authorized defensive monitoring**. Includes JSONL parsing, SQLite storage, brute-force indicators, SHA-256 integrity checks, a Tkinter control panel, live JSONL tailing, an analytics dashboard, PDF reports, and unit tests.

## Requirements
- Python 3.10+ (Windows: `py --version`)
- Tkinter is included with most standard Python Windows installations
- `reportlab` is only needed for PDF export: `py -m pip install -r requirements.txt`

## Quick start (Windows)
Open Command Prompt in the folder containing `sentinel.py`:

```bat
py sentinel.py analyze
py -m unittest discover -s tests -v
py gui.py
```

## New features

### 1. Live monitoring
```bat
py live_monitor.py
```
By default it watches `data\sample_events.jsonl` for **newly appended** complete JSONL lines and starts at the end of the existing file. Stop with `Ctrl+C`. To read the file from the beginning:

```bat
py live_monitor.py --from-start
```

To monitor a different authorized JSONL log:

```bat
py live_monitor.py --log "C:\path\to\authorized-events.jsonl" --poll 1
```
Each line must be a JSON object with `timestamp`, `event_type`, `source_ip`, and `username`. It must be ISO-8601 timestamped. The monitor watches a file; it does not automatically collect Windows Event Logs or network traffic.

### 2. Advanced charts and filters
Run analysis first so `sentinel.db` has data, then:

```bat
py advanced_dashboard.py
```
The window shows severity and rule charts, an alert table, severity dropdown, text search, and refresh button. Charts use Tkinter Canvas; no chart package is required.

### 3. PDF report
Install the one optional dependency:

```bat
py -m pip install -r requirements.txt
```
Then create a report:

```bat
py pdf_report.py
```
Output: `reports\sentinelpy_security_report.pdf`. To choose another path:

```bat
py pdf_report.py --out reports\my_report.pdf
```
The PDF contains event/alert counts, severity summary, and up to 100 latest alerts. Treat reports as sensitive if your real logs contain personal or operational details.

### 4. Original GUI
```bat
py gui.py
```
This keeps the existing Dashboard, Analyze Events, Run Tests, Verify Log Integrity, and Create Baseline buttons.

## Integrity check
The current GUI baseline uses `data\sample_events.sha256`; the CLI default uses `data\log_baseline.json`. To explicitly verify the same sample file used by the GUI:

```bat
py sentinel.py integrity --log data\sample_events.jsonl --baseline data\sample_events.sha256
```
Only create a new baseline when you trust the file contents. Keep the baseline protected separately for stronger tamper resistance.

## GitHub publishing (safe workflow)
1. Create a new **empty private repository** on GitHub first while learning.
2. In this project folder, inspect `.gitignore` and make sure `sentinel.db`, real logs, reports, secrets, `.env`, and keys are excluded.
3. Initialize and commit:

```bat
git init
git add .
git status
git commit -m "Initial SentinelPy defensive log analyzer"
```
4. Check `git status` carefully. Do **not** commit real logs, database files, PDF/CSV reports, API keys, service-account JSON, or passwords.
5. Copy the repository's HTTPS URL from GitHub, then run (replace the example URL):

```bat
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```
If Git asks you to sign in, complete GitHub's official browser/device login flow. Do not paste tokens or passwords into chat.

If Git is not installed, install Git for Windows from https://git-scm.com/download/win and reopen Command Prompt. If you prefer, GitHub's web interface can upload source files, but still exclude sensitive files.

## Tests
```bat
py -m unittest discover -s tests -v
```
Expected current baseline: five tests pass. Alerts are heuristics, may have false positives, and are not proof of compromise. Use only logs you own or are authorized to monitor. The sample IP addresses are documentation-only ranges.

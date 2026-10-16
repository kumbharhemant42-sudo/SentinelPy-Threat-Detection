"""
SentinelPy GUI Dashboard
Save this file as gui.py in the same folder as sentinel.py.
Uses Python's built-in Tkinter; no extra packages are required.
"""

import subprocess
import sys
import tkinter as tk
from tkinter import messagebox
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
SENTINEL_SCRIPT = PROJECT_DIR / "sentinel.py"
LOG_FILE = PROJECT_DIR / "data" / "sample_events.jsonl"
BASELINE_FILE = PROJECT_DIR / "data" / "sample_events.sha256"


class SentinelGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SentinelPy | Security Dashboard")
        self.root.geometry("900x620")
        self.root.minsize(700, 500)
        self.root.configure(bg="#101827")

        header = tk.Frame(root, bg="#172338", padx=22, pady=18)
        header.pack(fill="x")

        tk.Label(
            header, text="SENTINELPY", font=("Segoe UI", 22, "bold"),
            fg="#62e6c7", bg="#172338"
        ).pack(anchor="w")
        tk.Label(
            header, text="Defensive Security • Event Analysis • Integrity Checks",
            font=("Segoe UI", 10), fg="#c6d2e2", bg="#172338"
        ).pack(anchor="w", pady=(4, 0))

        button_area = tk.Frame(root, bg="#101827", padx=18, pady=14)
        button_area.pack(fill="x")

        buttons = [
            ("Dashboard", self.show_dashboard, "#187c72"),
            ("Analyze Events", self.analyze, "#245fa8"),
            ("Run Tests", self.run_tests, "#6b4bb8"),
            ("Verify Log Integrity", self.verify_integrity, "#98651c"),
            ("Create Baseline", self.create_baseline, "#475569"),
            ("Clear Output", self.clear_output, "#374151"),
            ("Live Monitor", self.live_monitor, "#0f766e"),
            ("Advanced Charts", self.advanced_dashboard, "#1d4ed8"),
            ("PDF Report", self.pdf_report, "#7c3aed"),
        ]

        for index, (label, command, color) in enumerate(buttons):
            button = tk.Button(
                button_area, text=label, command=command,
                bg=color, fg="white", activebackground=color,
                activeforeground="white", relief="flat",
                font=("Segoe UI", 10, "bold"), padx=12, pady=9,
                cursor="hand2"
            )
            button.grid(row=index // 3, column=index % 3, padx=5, pady=5, sticky="ew")

        for column in range(3):
            button_area.grid_columnconfigure(column, weight=1)

        status_frame = tk.Frame(root, bg="#101827", padx=22)
        status_frame.pack(fill="x")
        tk.Label(
            status_frame, text="OUTPUT", font=("Segoe UI", 10, "bold"),
            fg="#62e6c7", bg="#101827"
        ).pack(anchor="w")

        output_frame = tk.Frame(root, bg="#101827", padx=18, pady=8)
        output_frame.pack(fill="both", expand=True)

        self.output = tk.Text(
            output_frame, wrap="word", bg="#0b1220", fg="#dbe7f5",
            insertbackground="white", font=("Consolas", 10),
            relief="flat", padx=12, pady=12
        )
        scrollbar = tk.Scrollbar(output_frame, command=self.output.yview)
        self.output.configure(yscrollcommand=scrollbar.set)
        self.output.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        footer = tk.Label(
            root,
            text="For authorized defensive analysis only • Demo IPs are examples, not proof of real attacks",
            bg="#172338", fg="#c6d2e2", font=("Segoe UI", 9), pady=8
        )
        footer.pack(fill="x")

        self.write_output(
            "SentinelPy GUI is ready.\n"
            f"Project folder: {PROJECT_DIR}\n\n"
            "Choose Dashboard to view stored alerts, Analyze Events to run analysis, "
            "or Run Tests to check the project."
        )

        if not SENTINEL_SCRIPT.exists():
            messagebox.showerror(
                "Project file not found",
                "gui.py must be saved in the same folder as sentinel.py."
            )

    def write_output(self, text):
        self.output.insert("end", text.rstrip() + "\n")
        self.output.see("end")

    def clear_output(self):
        self.output.delete("1.0", "end")

    def run_command(self, args, title):
        if not SENTINEL_SCRIPT.exists():
            messagebox.showerror(
                "File not found",
                f"Cannot find sentinel.py in:\n{PROJECT_DIR}\n\n"
                "Move gui.py into the same folder as sentinel.py."
            )
            return

        self.write_output("\n" + "=" * 68)
        self.write_output(title)
        self.write_output("$ " + " ".join(str(part) for part in args))
        self.write_output("-" * 68)

        try:
            result = subprocess.run(
                args,
                cwd=PROJECT_DIR,
                capture_output=True,
                text=True,
                timeout=120,
                errors="replace"
            )
            if result.stdout:
                self.write_output(result.stdout)
            if result.stderr:
                self.write_output("\nMessages / errors:\n" + result.stderr)
            self.write_output(f"\nProcess exit code: {result.returncode}")
            if result.returncode == 0:
                self.write_output("Status: command completed.")
            else:
                self.write_output("Status: command reported an error; review output above.")
        except subprocess.TimeoutExpired:
            self.write_output("The command took longer than 120 seconds and was stopped.")
        except Exception as exc:
            self.write_output(f"Could not run command: {exc}")

    def show_dashboard(self):
        self.run_command([sys.executable, str(SENTINEL_SCRIPT), "dashboard"], "SECURITY DASHBOARD")

    def analyze(self):
        self.run_command([sys.executable, str(SENTINEL_SCRIPT), "analyze"], "ANALYZE EVENTS")

    def run_tests(self):
        self.run_command(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            "PROJECT TESTS"
        )

    def verify_integrity(self):
        if not LOG_FILE.exists():
            messagebox.showerror("Log file missing", f"Cannot find:\n{LOG_FILE}")
            return
        if not BASELINE_FILE.exists():
            messagebox.showinfo(
                "Baseline not found",
                "No saved baseline exists yet. Click Create Baseline first."
            )
            return
        self.run_command(
            [
                sys.executable, str(SENTINEL_SCRIPT), "integrity",
                "--log", str(LOG_FILE.relative_to(PROJECT_DIR)),
                "--baseline", str(BASELINE_FILE.relative_to(PROJECT_DIR))
            ],
            "VERIFY LOG INTEGRITY"
        )

    def live_monitor(self):
        self.launch_tool("live_monitor.py", "LIVE LOG MONITOR")

    def advanced_dashboard(self):
        self.launch_tool("advanced_dashboard.py", "ADVANCED DASHBOARD")

    def pdf_report(self):
        self.run_command([sys.executable, str(PROJECT_DIR / "pdf_report.py")], "PDF SECURITY REPORT")

    def launch_tool(self, filename, title):
        script = PROJECT_DIR / filename
        if not script.exists():
            messagebox.showerror("File not found", f"Cannot find {filename} in:\n{PROJECT_DIR}")
            return
        try:
            subprocess.Popen([sys.executable, str(script)], cwd=PROJECT_DIR)
            self.write_output(f"\n{title}: launched {filename} in a separate window.")
        except Exception as exc:
            self.write_output(f"Could not launch {filename}: {exc}")

    def create_baseline(self):
        if not LOG_FILE.exists():
            messagebox.showerror("Log file missing", f"Cannot find:\n{LOG_FILE}")
            return
        confirm = messagebox.askyesno(
            "Create baseline?",
            "This will save the current sample log's SHA-256 hash as the baseline.\n\n"
            "Only create a new baseline when you trust the current log contents."
        )
        if not confirm:
            return
        self.run_command(
            [
                sys.executable, str(SENTINEL_SCRIPT), "integrity",
                "--log", str(LOG_FILE.relative_to(PROJECT_DIR)),
                "--baseline", str(BASELINE_FILE.relative_to(PROJECT_DIR)),
                "--create-baseline"
            ],
            "CREATE SHA-256 BASELINE"
        )


def main():
    root = tk.Tk()
    SentinelGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

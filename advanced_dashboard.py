#!/usr/bin/env python3
"""Tkinter dashboard with severity chart, rule chart, filters, and alert table."""
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB = BASE / 'sentinel.db'
BG = '#101827'; PANEL = '#172338'; FG = '#e5edf7'; TEAL = '#62e6c7'
SEV_COLORS = {'CRITICAL':'#ff4d6d', 'HIGH':'#f97316', 'MEDIUM':'#facc15', 'LOW':'#60a5fa', 'INFO':'#94a3b8'}

class Dashboard:
    def __init__(self, root):
        self.root = root
        root.title('SentinelPy | Advanced Security Dashboard')
        root.geometry('1120x760'); root.minsize(850, 600); root.configure(bg=BG)
        header = tk.Frame(root, bg=PANEL, padx=18, pady=14); header.pack(fill='x')
        tk.Label(header, text='SENTINELPY / ADVANCED ANALYTICS', bg=PANEL, fg=TEAL,
                 font=('Segoe UI', 18, 'bold')).pack(anchor='w')
        tk.Label(header, text=f'Database: {DB}', bg=PANEL, fg=FG, font=('Segoe UI', 9)).pack(anchor='w')
        top = tk.Frame(root, bg=BG, padx=12, pady=10); top.pack(fill='x')
        tk.Button(top, text='Refresh data', command=self.refresh, bg='#187c72', fg='white', relief='flat', padx=14, pady=7).pack(side='left')
        tk.Label(top, text='Severity filter:', bg=BG, fg=FG).pack(side='left', padx=(18,5))
        self.severity = tk.StringVar(value='ALL')
        choice = ttk.Combobox(top, textvariable=self.severity, values=['ALL','CRITICAL','HIGH','MEDIUM','LOW','INFO'], state='readonly', width=12)
        choice.pack(side='left'); choice.bind('<<ComboboxSelected>>', lambda _e: self.refresh_table())
        tk.Label(top, text='Search:', bg=BG, fg=FG).pack(side='left', padx=(18,5))
        self.search = tk.StringVar(); searchbox = tk.Entry(top, textvariable=self.search, width=26)
        searchbox.pack(side='left'); searchbox.bind('<KeyRelease>', lambda _e: self.refresh_table())
        charts = tk.Frame(root, bg=BG, padx=12); charts.pack(fill='x')
        self.sev_canvas = tk.Canvas(charts, height=220, bg=PANEL, highlightthickness=0)
        self.sev_canvas.pack(side='left', fill='both', expand=True, padx=(0,6))
        self.rule_canvas = tk.Canvas(charts, height=220, bg=PANEL, highlightthickness=0)
        self.rule_canvas.pack(side='left', fill='both', expand=True, padx=(6,0))
        table_frame = tk.Frame(root, bg=BG, padx=12, pady=12); table_frame.pack(fill='both', expand=True)
        columns = ('timestamp','severity','rule','source_ip','username','message')
        self.table = ttk.Treeview(table_frame, columns=columns, show='headings', height=14)
        widths = [155,85,190,115,110,350]
        for col, width in zip(columns, widths):
            self.table.heading(col, text=col.replace('_',' ').title()); self.table.column(col, width=width, minwidth=65, anchor='w')
        yscroll = ttk.Scrollbar(table_frame, orient='vertical', command=self.table.yview)
        xscroll = ttk.Scrollbar(table_frame, orient='horizontal', command=self.table.xview)
        self.table.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.table.grid(row=0,column=0,sticky='nsew'); yscroll.grid(row=0,column=1,sticky='ns'); xscroll.grid(row=1,column=0,sticky='ew')
        table_frame.rowconfigure(0, weight=1); table_frame.columnconfigure(0, weight=1)
        self.status = tk.Label(root, text='', bg=PANEL, fg=FG, anchor='w', padx=12, pady=7); self.status.pack(fill='x')
        self.refresh()

    def fetch(self):
        if not DB.exists(): return [], [], []
        with sqlite3.connect(DB) as conn:
            total = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            alerts = conn.execute('SELECT timestamp,severity,rule,source_ip,username,message FROM alerts ORDER BY id DESC').fetchall()
            severity = conn.execute('SELECT severity,COUNT(*) FROM alerts GROUP BY severity ORDER BY severity').fetchall()
            rules = conn.execute('SELECT rule,COUNT(*) FROM alerts GROUP BY rule ORDER BY COUNT(*) DESC LIMIT 8').fetchall()
        return alerts, severity, rules, total

    def draw_bars(self, canvas, title, rows, color_map=None):
        canvas.delete('all'); w=max(canvas.winfo_width(), 380); h=220
        canvas.create_text(14, 15, text=title, fill=TEAL, anchor='w', font=('Segoe UI', 12, 'bold'))
        if not rows:
            canvas.create_text(w/2, h/2, text='No alert data yet. Run Analyze Events first.', fill=FG); return
        maxval=max(v for _,v in rows) or 1; usable_w=w-150; top=42; row_h=min(30, (h-55)/max(len(rows),1))
        for i,(label,value) in enumerate(rows):
            y=top+i*row_h
            canvas.create_text(14,y+8,text=str(label)[:19],fill=FG,anchor='w',font=('Segoe UI',9))
            x=130; barw=max(2, usable_w*value/maxval)
            color=(color_map or {}).get(label, '#38bdf8')
            canvas.create_rectangle(x,y,x+barw,y+16,fill=color,outline='')
            canvas.create_text(min(x+barw+8,w-22),y+8,text=str(value),fill=FG,anchor='w',font=('Segoe UI',9,'bold'))

    def refresh(self):
        try:
            data = self.fetch()
            if len(data)==3:
                self.status.config(text='No database yet. Run Analyze Events from gui.py first.')
                self.draw_bars(self.sev_canvas,'Alerts by severity',[]); self.draw_bars(self.rule_canvas,'Top detection rules',[])
                self.refresh_table(); return
            alerts, severity, rules, total = data
            self.draw_bars(self.sev_canvas,'Alerts by severity',severity,SEV_COLORS)
            self.draw_bars(self.rule_canvas,'Top detection rules',rules)
            self.status.config(text=f'Events stored: {total}  |  Alerts: {len(alerts)}  |  Refresh updates the view from the local SQLite database.')
            self.refresh_table(alerts)
        except sqlite3.Error as exc:
            messagebox.showerror('Database error', str(exc))

    def refresh_table(self, alerts=None):
        if alerts is None:
            data = self.fetch(); alerts = data[0] if data else []
        for item in self.table.get_children(): self.table.delete(item)
        sev = self.severity.get(); term = self.search.get().strip().lower()
        for row in alerts:
            if sev != 'ALL' and row[1] != sev: continue
            if term and term not in ' '.join(map(str,row)).lower(): continue
            self.table.insert('', 'end', values=row)

def main():
    root=tk.Tk(); Dashboard(root); root.mainloop()
if __name__=='__main__': main()

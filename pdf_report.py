#!/usr/bin/env python3
"""Export a concise PDF summary from the local SentinelPy SQLite database."""
import argparse, sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE=Path(__file__).resolve().parent
DB=BASE/'sentinel.db'
OUT=BASE/'reports'/'sentinelpy_security_report.pdf'

def create_report(db_path: Path, out_path: Path) -> int:
    if not db_path.exists():
        raise FileNotFoundError(f'Database not found: {db_path}. Run `py sentinel.py analyze` first.')
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    except ImportError as exc:
        raise RuntimeError('PDF dependency missing. Install it with: py -m pip install reportlab') from exc
    with sqlite3.connect(db_path) as conn:
        event_count=conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        alert_count=conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        by_sev=conn.execute('SELECT severity,COUNT(*) FROM alerts GROUP BY severity ORDER BY COUNT(*) DESC').fetchall()
        latest=conn.execute('SELECT timestamp,severity,rule,source_ip,username,message FROM alerts ORDER BY id DESC LIMIT 100').fetchall()
    out_path.parent.mkdir(parents=True,exist_ok=True)
    doc=SimpleDocTemplate(str(out_path), pagesize=landscape(A4), rightMargin=12*mm,leftMargin=12*mm,topMargin=12*mm,bottomMargin=12*mm)
    styles=getSampleStyleSheet(); styles.add(ParagraphStyle(name='SmallCell',parent=styles['BodyText'],fontSize=7,leading=9))
    story=[Paragraph('SentinelPy Security Report',styles['Title']),
           Paragraph('Generated: '+datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),styles['Normal']),
           Spacer(1,5*mm), Paragraph(f'<b>Events stored:</b> {event_count} &nbsp;&nbsp; <b>Alerts stored:</b> {alert_count}',styles['Heading2']),
           Spacer(1,3*mm), Paragraph('Alert severity summary',styles['Heading2'])]
    sev_data=[['Severity','Count']]+[[str(s),str(n)] for s,n in by_sev]
    sev_table=Table(sev_data,colWidths=[45*mm,25*mm]); sev_table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#17324d')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),.4,colors.grey),('PADDING',(0,0),(-1,-1),5)]))
    story.extend([sev_table,Spacer(1,5*mm),Paragraph('Latest alerts (up to 100)',styles['Heading2'])])
    data=[['Timestamp','Severity','Rule','Source IP','Username','Message']]
    for row in latest:
        data.append([Paragraph(str(x).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;'),styles['SmallCell']) for x in row])
    table=Table(data,repeatRows=1,colWidths=[39*mm,18*mm,39*mm,28*mm,25*mm,105*mm])
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#17324d')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),.35,colors.HexColor('#9ca3af')),('VALIGN',(0,0),(-1,-1),'TOP'),('PADDING',(0,0),(-1,-1),4),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f1f5f9')])]))
    story.append(table)
    story.extend([Spacer(1,5*mm),Paragraph('<b>Important:</b> Alerts are rule-based indicators, not proof of compromise. Validate against authorized source logs. This report may contain sensitive usernames and IP addresses; store and share it carefully.',styles['Normal'])])
    doc.build(story)
    print(f'PDF report created: {out_path.resolve()}')
    print(f'Events: {event_count} | Alerts: {alert_count} | Alert rows in report: {len(latest)}')
    return 0

def main():
    p=argparse.ArgumentParser(description='Create a PDF report from SentinelPy database')
    p.add_argument('--db',type=Path,default=DB); p.add_argument('--out',type=Path,default=OUT)
    a=p.parse_args()
    try: return create_report(a.db,a.out)
    except (OSError,sqlite3.Error,RuntimeError) as exc:
        print(f'Error: {exc}'); return 2
if __name__=='__main__': raise SystemExit(main())

"""Veytrix - Single File Edition
Upload as veytrix.py. Runs on Windows 10/11 and Kali Linux.
Run: python veytrix.py
"""
from __future__ import annotations
import sys, subprocess, re, uuid, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional

def _ensure(pkg, name=None):
    try:
        __import__(name or pkg)
    except ImportError:
        print(f"Installing {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

_ensure("PySide6"); _ensure("psutil"); _ensure("reportlab")

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QFrame,
    QMessageBox, QFileDialog,
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QBrush
import psutil

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors as rlc
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)
from xml.sax.saxutils import escape as xesc


# ============================================================
# Domain
# ============================================================
class RiskLevel(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self):
        return ["Info", "Low", "Medium", "High", "Critical"][int(self)]


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    name: str
    exe_path: Optional[str] = None
    cmdline: Optional[str] = None
    user: Optional[str] = None
    ppid: Optional[int] = None
    parent_name: Optional[str] = None
    cpu_percent: float = 0.0
    memory_bytes: int = 0
    risk: RiskLevel = RiskLevel.INFO
    risk_score: int = 0
    flags: tuple = ()
    is_flagged: bool = False


@dataclass(frozen=True)
class DetectionEvent:
    event_id: str
    timestamp: datetime
    rule_id: str
    rule_name: str
    severity: RiskLevel
    risk_score: int
    process: ProcessRecord
    explanation: str


# ============================================================
# Detection rules
# ============================================================
_SYS = {"svchost.exe", "lsass.exe", "services.exe", "winlogon.exe",
        "csrss.exe", "smss.exe", "wininit.exe", "explorer.exe",
        "spoolsv.exe", "taskhostw.exe"}

_CMD_PATTERNS = [
    (re.compile(r"(?i)-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}"), 30, "encoded PowerShell"),
    (re.compile(r"(?i)\b(?:iex|invoke-expression)\b"), 20, "Invoke-Expression"),
    (re.compile(r"(?i)downloadstring"), 25, "DownloadString"),
    (re.compile(r"(?i)-w(?:indowstyle)?\s+hidden"), 15, "hidden window"),
    (re.compile(r"(?i)certutil(?:\.exe)?\s+.*-urlcache"), 30, "certutil download"),
    (re.compile(r"(?i)bitsadmin(?:\.exe)?\s+.*/transfer"), 25, "bitsadmin transfer"),
    (re.compile(r"(?i)mshta(?:\.exe)?\s+https?://"), 30, "mshta remote"),
    (re.compile(r"(?i)regsvr32(?:\.exe)?\s+.*/i:https?://"), 30, "regsvr32 scriptlet"),
    (re.compile(r"(?i)vssadmin(?:\.exe)?\s+.*delete\s+shadows"), 40, "shadow deletion"),
    (re.compile(r"(?i)wbadmin(?:\.exe)?\s+.*delete\s+catalog"), 40, "backup deletion"),
    (re.compile(r"(?i)mimikatz"), 60, "mimikatz"),
    (re.compile(r"(?i)sekurlsa"), 60, "sekurlsa"),
    (re.compile(r"(?i)procdump(?:\.exe)?\s+.*lsass"), 55, "procdump LSASS"),
    (re.compile(r"(?i)bash\s+-i\s+>&\s*/dev/tcp/"), 50, "bash reverse shell"),
    (re.compile(r"(?i)/dev/tcp/"), 35, "/dev/tcp"),
    (re.compile(r"(?i)\bnc\b\s+.*-e\s+/bin/(?:ba)?sh"), 50, "netcat shell"),
    (re.compile(r"(?i)New-Object\s+Net\.Sockets\.TCPClient"), 45, "PowerShell TCPClient"),
]


def analyze(rec):
    flags, score = [], 0
    cmd = rec.cmdline or ""
    path_l = (rec.exe_path or "").replace("\\", "/").lower()
    name_l = (rec.name or "").lower()

    for pat, s, label in _CMD_PATTERNS:
        if cmd and pat.search(cmd):
            flags.append(label)
            score += s

    if name_l in _SYS and rec.exe_path and not path_l.startswith("c:/windows/"):
        flags.append("masquerading system binary")
        score += 45

    writable = ("/appdata/local/temp/", "/tmp/", "/dev/shm/", "/users/public/")
    if path_l and any(m in path_l for m in writable):
        flags.append("user-writable directory")
        score += 15

    if not flags or score < 25:
        return None

    score = min(100, score)
    if score >= 85:   sev = RiskLevel.CRITICAL
    elif score >= 70: sev = RiskLevel.HIGH
    elif score >= 45: sev = RiskLevel.MEDIUM
    else:             sev = RiskLevel.LOW

    return DetectionEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        rule_id="VX-AUTO",
        rule_name=", ".join(flags[:2]),
        severity=sev,
        risk_score=score,
        process=rec,
        explanation=" | ".join(flags),
    )


# ============================================================
# Telemetry
# ============================================================
class Monitor(QThread):
    snapshot = Signal(list, list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True
        self._baselines = {}

    def stop(self):
        self._running = False

    def run(self):
        while self._running:
            try:
                records, events = self._scan()
                self.snapshot.emit(records, events)
            except Exception as e:
                print(f"scan error: {e}")
            for _ in range(40):
                if not self._running:
                    return
                self.msleep(50)

    def _scan(self):
        import time
        records, events = [], []
        now = time.monotonic()
        new_baselines = {}
        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "username",
             "ppid", "cpu_times", "memory_info"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                name = info.get("name") or f"pid-{pid}"
                exe = info.get("exe")
                cmd = " ".join(info.get("cmdline") or [])
                user = info.get("username")
                ppid = info.get("ppid")
                parent_name = None
                if ppid:
                    try:
                        parent_name = psutil.Process(ppid).name()
                    except Exception:
                        pass

                cpu = 0.0
                ct = info.get("cpu_times")
                if ct:
                    try:
                        ctime = proc.create_time()
                    except Exception:
                        ctime = 0
                    key = (pid, ctime)
                    cur = (now, ct.user, ct.system)
                    prev = self._baselines.get(key)
                    if prev:
                        elapsed = cur[0] - prev[0]
                        if elapsed > 0.05 and cur[1] >= prev[1] and cur[2] >= prev[2]:
                            cpu = ((cur[1] - prev[1]) + (cur[2] - prev[2])) / elapsed * 100.0
                            cpu = max(0.0, cpu)
                    new_baselines[key] = cur

                mem = info.get("memory_info")
                mem_bytes = int(mem.rss) if mem else 0

                rec = ProcessRecord(
                    pid=pid, name=name, exe_path=exe, cmdline=cmd,
                    user=user, ppid=ppid, parent_name=parent_name,
                    cpu_percent=cpu, memory_bytes=mem_bytes,
                )

                ev = analyze(rec)
                if ev:
                    rec = ProcessRecord(
                        pid=rec.pid, name=rec.name, exe_path=rec.exe_path,
                        cmdline=rec.cmdline, user=rec.user, ppid=rec.ppid,
                        parent_name=rec.parent_name, cpu_percent=rec.cpu_percent,
                        memory_bytes=rec.memory_bytes, risk=ev.severity,
                        risk_score=ev.risk_score,
                        flags=tuple(ev.explanation.split(" | ")),
                        is_flagged=True,
                    )
                    ev = DetectionEvent(
                        event_id=ev.event_id, timestamp=ev.timestamp,
                        rule_id=ev.rule_id, rule_name=ev.rule_name,
                        severity=ev.severity, risk_score=ev.risk_score,
                        process=rec, explanation=ev.explanation,
                    )
                    events.append(ev)
                records.append(rec)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
        self._baselines = new_baselines
        return records, events


# ============================================================
# Storage
# ============================================================
class DB:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        self.conn.execute("""CREATE TABLE IF NOT EXISTS events(
            event_id TEXT PRIMARY KEY, timestamp TEXT, rule_id TEXT,
            rule_name TEXT, severity TEXT, risk_score INT,
            process_name TEXT, process_pid INT, process_path TEXT,
            cmdline TEXT, user TEXT, explanation TEXT)""")

    def save(self, events):
        rows = [
            (e.event_id, e.timestamp.isoformat(), e.rule_id, e.rule_name,
             e.severity.label, e.risk_score, e.process.name, e.process.pid,
             e.process.exe_path, e.process.cmdline, e.process.user,
             e.explanation)
            for e in events
        ]
        self.conn.executemany(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# ============================================================
# PDF
# ============================================================
def export_pdf(events, records, dest):
    styles = getSampleStyleSheet()
    title = ParagraphStyle("T", parent=styles["Title"], fontSize=20,
                           textColor=rlc.HexColor("#0B1F3A"), alignment=0)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14,
                        textColor=rlc.HexColor("#0B1F3A"))
    body = ParagraphStyle("B", parent=styles["Normal"], fontSize=9.5, leading=13)
    meta = ParagraphStyle("M", parent=styles["Normal"], fontSize=9,
                          textColor=rlc.grey)

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(rlc.grey)
        canvas.drawString(18 * mm, 10 * mm, "Veytrix - Confidential")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(dest), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title="Veytrix Report", author="Veytrix",
    )

    story = []
    story.append(Paragraph("Veytrix Detection Report", title))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        meta,
    ))
    story.append(Paragraph(
        f"Events: {len(events)} &nbsp; Flagged processes: {len(records)}", meta,
    ))
    story.append(Spacer(1, 6 * mm))

    if events:
        story.append(Paragraph("Event Summary", h2))
        rows = [["#", "Time", "Severity", "Rule", "Process", "Score"]]
        for i, e in enumerate(events, 1):
            rows.append([
                str(i),
                e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                e.severity.label,
                xesc(e.rule_name[:40]),
                xesc(e.process.name[:30]),
                str(e.risk_score),
            ])
        t = Table(rows, colWidths=[10 * mm, 34 * mm, 18 * mm, 45 * mm, 40 * mm, 15 * mm],
                  repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), rlc.HexColor("#1F3A5F")),
            ("TEXTCOLOR", (0, 0), (-1, 0), rlc.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, rlc.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [rlc.white, rlc.HexColor("#F5F7FA")]),
        ]))
        story.append(t)
        story.append(Spacer(1, 5 * mm))

        story.append(Paragraph("Event Details", h2))
        for i, e in enumerate(events, 1):
            story.append(Paragraph(f"<b>Event #{i}:</b> {xesc(e.rule_name)}", body))
            story.append(Paragraph(
                f"PID: {e.process.pid} | Process: {xesc(e.process.name)}", meta,
            ))
            story.append(Paragraph(
                f"Command: {xesc((e.process.cmdline or 'n/a')[:200])}", meta,
            ))
            story.append(Paragraph(f"Why: {xesc(e.explanation)}", body))
            story.append(Spacer(1, 3 * mm))

    if records:
        story.append(Paragraph("Flagged Processes", h2))
        rows = [["PID", "Process", "Risk", "Score", "User"]]
        for r in records:
            rows.append([
                str(r.pid), xesc(r.name[:30]), r.risk.label,
                str(r.risk_score), xesc((r.user or "")[:20]),
            ])
        t = Table(rows, colWidths=[18 * mm, 50 * mm, 20 * mm, 18 * mm, 50 * mm],
                  repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), rlc.HexColor("#1F3A5F")),
            ("TEXTCOLOR", (0, 0), (-1, 0), rlc.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, rlc.lightgrey),
        ]))
        story.append(t)

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


# ============================================================
# UI
# ============================================================
RISK_BG = {
    RiskLevel.INFO: "#E5E7EB",
    RiskLevel.LOW: "#DBEAFE",
    RiskLevel.MEDIUM: "#FEF3C7",
    RiskLevel.HIGH: "#FFEDD5",
    RiskLevel.CRITICAL: "#FEE2E2",
}


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Veytrix")
        self.resize(1200, 800)
        self.monitor = None
        self.all_records = []
        self.all_events = []
        self.db = DB(Path.home() / ".veytrix" / "events.db")

        self._build()
        self._apply_style()

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background: #F8FAFC; color: #111827;
                font-family: "Segoe UI", sans-serif; font-size: 10pt;
            }
            QLabel#title { font-size: 22pt; font-weight: bold; color: #0B1F3A; }
            QLabel#status {
                background: #E5E7EB; color: #374151; padding: 6px 12px;
                border-radius: 10px; font-weight: bold;
            }
            QLabel#status[running="true"] { background: #D1FAE5; color: #065F46; }
            QLabel#muted { color: #6B7280; }
            QPushButton {
                background: white; border: 1px solid #D1D5DB;
                padding: 7px 14px; border-radius: 6px;
            }
            QPushButton:hover { background: #F3F4F6; }
            QPushButton#primary {
                background: #0B1F3A; color: white; border: none;
                font-weight: bold;
            }
            QPushButton#primary:hover { background: #16345C; }
            QLineEdit, QComboBox {
                border: 1px solid #D1D5DB; border-radius: 6px;
                padding: 6px 10px; background: white;
            }
            QTableWidget {
                border: 1px solid #E5E7EB; border-radius: 6px;
                background: white; gridline-color: #E5E7EB;
            }
            QHeaderView::section {
                background: #F3F4F6; border: none;
                border-bottom: 1px solid #E5E7EB;
                padding: 6px; font-weight: bold;
            }
            QFrame#panel {
                background: white; border: 1px solid #E5E7EB;
                border-radius: 8px;
            }
        """)

    def _build(self):
        title = QLabel("Veytrix"); title.setObjectName("title")
        sub = QLabel("Suspicious process detection & security logs")
        sub.setObjectName("muted")

        self.status = QLabel("● Stopped"); self.status.setObjectName("status")
        self.status.setProperty("running", "false")

        self.btn_toggle = QPushButton("Start Monitoring")
        self.btn_toggle.setObjectName("primary")
        self.btn_toggle.clicked.connect(self._toggle)

        title_box = QVBoxLayout(); title_box.setSpacing(0)
        title_box.addWidget(title); title_box.addWidget(sub)

        header = QHBoxLayout(); header.setSpacing(12)
        header.addLayout(title_box); header.addStretch()
        header.addWidget(self.status); header.addWidget(self.btn_toggle)

        self.kpi_proc = self._kpi("Processes")
        self.kpi_flagged = self._kpi("Flagged")
        self.kpi_events = self._kpi("Events")
        self.kpi_critical = self._kpi("Critical")

        kpis = QHBoxLayout(); kpis.setSpacing(10)
        for k in (self.kpi_proc, self.kpi_flagged, self.kpi_events, self.kpi_critical):
            kpis.addWidget(k, stretch=1)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search process, PID, user, command...")
        self.search.textChanged.connect(self._refresh)
        self.risk_filter = QComboBox()
        for label, lvl in [("All levels", RiskLevel.INFO),
                           ("Low+", RiskLevel.LOW),
                           ("Medium+", RiskLevel.MEDIUM),
                           ("High+", RiskLevel.HIGH),
                           ("Critical", RiskLevel.CRITICAL)]:
            self.risk_filter.addItem(label, lvl)
        self.risk_filter.currentIndexChanged.connect(self._refresh)
        self.flagged_only = QCheckBox("Flagged only")
        self.flagged_only.stateChanged.connect(self._refresh)

        filters = QHBoxLayout(); filters.setSpacing(8)
        filters.addWidget(self.search, stretch=1)
        filters.addWidget(self.risk_filter)
        filters.addWidget(self.flagged_only)

        self.proc_table = QTableWidget(0, 8)
        self.proc_table.setHorizontalHeaderLabels(
            ["Risk", "Score", "Process", "PID", "CPU%", "Memory", "User", "Flags"])
        self.proc_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.proc_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.proc_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.proc_table.setAlternatingRowColors(True)
        self.proc_table.verticalHeader().setVisible(False)
        hdr = self.proc_table.horizontalHeader()
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.proc_table.setSortingEnabled(True)

        self.evt_table = QTableWidget(0, 6)
        self.evt_table.setHorizontalHeaderLabels(
            ["Time", "Severity", "Rule", "Process", "PID", "Explanation"])
        self.evt_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.evt_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.evt_table.setAlternatingRowColors(True)
        self.evt_table.verticalHeader().setVisible(False)
        hdr2 = self.evt_table.horizontalHeader()
        hdr2.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)

        proc_title = QLabel("Processes")
        proc_title.setStyleSheet("font-weight:bold; color:#0B1F3A; font-size:11pt;")
        proc_panel = QFrame(); proc_panel.setObjectName("panel")
        pl = QVBoxLayout(proc_panel); pl.setContentsMargins(12, 10, 12, 12)
        pl.setSpacing(8); pl.addWidget(proc_title); pl.addLayout(filters)
        pl.addWidget(self.proc_table)

        evt_title = QLabel("Detection events")
        evt_title.setStyleSheet("font-weight:bold; color:#0B1F3A; font-size:11pt;")
        evt_panel = QFrame(); evt_panel.setObjectName("panel")
        el = QVBoxLayout(evt_panel); el.setContentsMargins(12, 10, 12, 12)
        el.setSpacing(8); el.addWidget(evt_title); el.addWidget(self.evt_table)

        self.btn_export = QPushButton("Export PDF")
        self.btn_export.clicked.connect(self._export)
        self.export_status = QLabel(""); self.export_status.setObjectName("muted")

        export_bar = QHBoxLayout()
        export_bar.addWidget(self.export_status, stretch=1)
        export_bar.addWidget(self.btn_export)

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 16, 16, 12)
        root.setSpacing(12)
        root.addLayout(header)
        root.addLayout(kpis)
        root.addWidget(proc_panel, stretch=3)
        root.addWidget(evt_panel, stretch=2)
        root.addLayout(export_bar)
        self.setCentralWidget(central)

    def _kpi(self, title):
        f = QFrame(); f.setObjectName("panel")
        l = QVBoxLayout(f); l.setContentsMargins(14, 10, 14, 10); l.setSpacing(2)
        t = QLabel(title); t.setObjectName("muted")
        v = QLabel("0"); v.setStyleSheet(
            "font-size:18pt; font-weight:bold; color:#0B1F3A;")
        l.addWidget(t); l.addWidget(v)
        f._value = v
        return f

    def _toggle(self):
        if self.monitor is None:
            self._start()
        else:
            self._stop()

    def _start(self):
        self.monitor = Monitor()
        self.monitor.snapshot.connect(self._on_snapshot)
        self.monitor.start()
        self.btn_toggle.setText("Stop Monitoring")
        self.status.setText("● Running")
        self.status.setProperty("running", "true")
        self._restyle(self.status)

    def _stop(self):
        if self.monitor:
            self.monitor.stop()
            self.monitor.wait(3000)
            self.monitor = None
        self.btn_toggle.setText("Start Monitoring")
        self.status.setText("● Stopped")
        self.status.setProperty("running", "false")
        self._restyle(self.status)

    def _restyle(self, w):
        w.style().unpolish(w); w.style().polish(w); w.update()

    def _on_snapshot(self, records, events):
        self.all_records = records
        self.all_events.extend(events)
        self.all_events = self.all_events[-5000:]
        if events:
            try:
                self.db.save(events)
            except Exception as e:
                print(f"db save error: {e}")
        self._refresh()

    def _refresh(self):
        text = self.search.text().strip().lower()
        min_risk = self.risk_filter.currentData()
        flagged_only = self.flagged_only.isChecked()

        rows = []
        for r in self.all_records:
            if r.risk < min_risk: continue
            if flagged_only and not r.is_flagged: continue
            if text:
                hay = f"{r.name} {r.cmdline or ''} {r.user or ''} {r.pid} {' '.join(r.flags)}".lower()
                if text not in hay:
                    continue
            rows.append(r)

        rows.sort(key=lambda r: (int(r.risk), r.risk_score), reverse=True)
        rows = rows[:1000]

        self.proc_table.setSortingEnabled(False)
        self.proc_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            mem = r.memory_bytes / (1024 * 1024) if r.memory_bytes else 0
            vals = [r.risk.label, str(r.risk_score), r.name, str(r.pid),
                    f"{r.cpu_percent:.1f}", f"{mem:.1f} MB",
                    r.user or "", ", ".join(r.flags)]
            for j, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if j in (1, 3, 4, 5):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight |
                                          Qt.AlignmentFlag.AlignVCenter)
                if j == 0:
                    item.setBackground(QBrush(QColor(RISK_BG[r.risk])))
                self.proc_table.setItem(i, j, item)
        self.proc_table.setSortingEnabled(True)

        evs = list(reversed(self.all_events))[:500]
        self.evt_table.setRowCount(len(evs))
        for i, e in enumerate(evs):
            vals = [
                e.timestamp.astimezone().strftime("%H:%M:%S"),
                e.severity.label,
                e.rule_id,
                e.process.name,
                str(e.process.pid),
                e.explanation,
            ]
            for j, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if j == 1:
                    item.setBackground(QBrush(QColor(RISK_BG[e.severity])))
                self.evt_table.setItem(i, j, item)

        self.kpi_proc._value.setText(f"{len(self.all_records):,}")
        self.kpi_flagged._value.setText(
            f"{sum(1 for r in self.all_records if r.is_flagged):,}")
        self.kpi_events._value.setText(f"{len(self.all_events):,}")
        self.kpi_critical._value.setText(
            f"{sum(1 for e in self.all_events if e.severity == RiskLevel.CRITICAL):,}")

    def _export(self):
        if not self.all_events and not self.all_records:
            QMessageBox.information(
                self, "Nothing to export",
                "Start monitoring first, or wait for detections.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save report",
            str(Path.home() / "veytrix-report.pdf"),
            "PDF files (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        try:
            flagged = [r for r in self.all_records if r.is_flagged]
            export_pdf(self.all_events, flagged, path)
            self.export_status.setText(f"Saved: {path}")
            QMessageBox.information(self, "Report saved", f"Saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))

    def closeEvent(self, event):
        self._stop()
        self.db.close()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Veytrix")
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

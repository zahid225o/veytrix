# Veytrix 2.0

**Endpoint Security Monitoring & Threat Detection** — local, single-file,
no cloud, no AI APIs, no telemetry.

Runs on **Windows 10/11** and **Kali Linux** (also any Linux with Python 3.10+).

---

## Quick start

```bash
# 1. Optional — install dependencies
pip install -r requirements.txt

# 2. Verify everything works (runs built-in tests)
python veytrix.py --test

# 3. Generate sample DB + PDF report
python veytrix.py demo --outdir ./veytrix_demo

# 4. Launch the GUI dashboard
python veytrix.py ui
```

That's it. One file, one command.

---

## What's inside

| Component | Description |
|---|---|
| **`DetectionEvent`** | Shared event contract with strict validation & sanitization |
| **`EventDatabase`** | SQLite store — WAL mode, versioned migrations, indexed search, retention |
| **Dedupe** | Groups duplicate alerts by fingerprint; **every event preserved** |
| **Scoring** | Transparent 0–100 risk score with per-indicator evidence |
| **Behavior engine** | Rule-based cross-event correlation (encoded PS + network, Office→shell, LSASS→egress) |
| **PDF reports** | Executive summary, severity pie, rule bar chart, per-group detail, evidence tables |
| **Process monitoring** | Live process list via `psutil` (CPU, RAM, cmdline, PPID) |
| **Network monitoring** | Active TCP/UDP connections with owning process |
| **File integrity** | SHA-256 baselines + create/modify/delete detection |
| **Quarantine** | Manual, confirmed-only quarantine with restore + system-file guard |
| **GUI dashboard** | Dark-theme Tkinter — Dashboard, Alerts, Processes, Network, Reports, Settings |
| **CLI** | `init-db`, `ingest`, `search`, `report`, `correlate`, `retention`, `monitor-*`, `demo`, `ui` |
| **Tests** | 40+ unit tests covering all subsystems (`--test`) |

---

## Requirements

- **Python ≥ 3.10**
- **`reportlab`** — required for PDF reports
- **`psutil`** — optional; enables process & network monitoring
- **`tkinter`** — optional; enables GUI
  - Windows: included with Python installer
  - Kali/Debian: `sudo apt install python3-tk`

Missing optional dependencies never crash the app — the affected feature
is disabled with a clear message.

---

## Usage — CLI

```bash
python veytrix.py --version

# Initialize an empty database inside a sandbox directory
python veytrix.py init-db --db events.db --base-dir ~/.veytrix

# Ingest a JSON file (list of events or a single object)
python veytrix.py ingest --db events.db --json events.json --base-dir ~/.veytrix

# Search
python veytrix.py search --db events.db --min-severity high --limit 20
python veytrix.py search --db events.db --text powershell --json

# PDF report
python veytrix.py report --db events.db --out report.pdf \
    --base-dir ~/.veytrix --min-severity high --include-raw

# Run behavior correlation over stored events
python veytrix.py correlate --db events.db --window 300

# Retention
python veytrix.py retention --db events.db --max-age-days 30 --vacuum

# Live monitoring (needs psutil)
python veytrix.py monitor-procs
python veytrix.py monitor-net
python veytrix.py monitor-procs --json
```

### GUI

```bash
python veytrix.py ui
```

Sidebar tabs: **Dashboard · Alerts · Processes · Network · Reports · Settings**.
Live process/network data refreshes every 3 s in a background thread — the
UI never freezes.

---

## Event schema (JSON)

Any field can be supplied under its canonical name or a supported alias.
Minimum required: `rule_id`, `rule_name`, `severity`, `timestamp`.

```json
{
  "event_id": "evt-1001",
  "timestamp": "2024-06-01T12:34:56Z",
  "rule_id": "R-1001",
  "rule_name": "Encoded PowerShell",
  "severity": "high",
  "description": "PowerShell with Base64 payload.",
  "explanation": "Encoded commands hide intent.",
  "investigation_notes": "Decode payload; check egress.",
  "host": "WS-0142",
  "user": "CORP\\alice",
  "process": {
    "name": "powershell.exe",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "pid": 5120,
    "ppid": 1024,
    "cmdline": "powershell -nop -w hidden -enc SQBFAFgA",
    "hash": "e3b0c44298..."
  },
  "source": "endpoint-edr",
  "raw": {"session_id": 42}
}
```

Aliases accepted: `id`→`rule_id`, `risk_level`→`severity`, `time`→`timestamp`,
`name`/`title`→`rule_name`, `cmdline`/`command_line`→`process_cmdline`, etc.

---

## Scoring

Every event is scored 0–100 with an **explicit evidence trail** visible in the
PDF. Weights live in `DEFAULT_WEIGHTS` in `veytrix.py` — override by passing
a JSON file:

```bash
python veytrix.py report --db events.db --out r.pdf --weights my_weights.json
```

```json
{
  "base": {"low": 10, "medium": 30, "high": 60, "critical": 85},
  "encoded_cmd": 15,
  "hidden_window": 10,
  "lsass_access": 25,
  "echoed_penalty": -30,
  "echoed_cap": 15
}
```

**Echo detection:** a command that merely *echoes* or *quotes* a suspicious
string (e.g. `echo "powershell -enc ..."`) is penalised — score capped at 15,
confidence capped at 0.25. This kills the classic false-positive pattern.

---

## Behavior rules (built-in)

| Rule ID | Trigger | Confidence |
|---|---|---|
| `R-BEH-01` | Encoded PowerShell + network egress within window | 0.85 |
| `R-BEH-02` | Office application (Word/Excel) spawns shell | 0.90 |
| `R-BEH-03` | LSASS access + suspicious-port connection | 0.88 |

Configure by editing `DEFAULT_RULES` in `veytrix.py` — each rule is a plain
Python callable taking `(events, window_seconds)` and returning a
`BehaviorAlert` or `None`.

---

## Safety guarantees

- **Path safety** — every file write goes through `safe_path()`; rejects
  absolute paths, `..` traversal, symlinks, wrong extensions when a
  `--base-dir` is set.
- **Input sanitization** — all text is stripped of control chars, length-capped,
  and XML-escaped before PDF rendering.
- **Parameterized SQL** — no string concatenation in queries.
- **Quarantine guard** — refuses `C:\Windows`, `/bin`, `/usr/bin`, `/etc`,
  `/boot`, etc. Requires `confirm=True`.
- **No automatic responses** — the app never deletes, kills, or blocks
  anything on its own.
- **No network calls** — except optional `psutil` local introspection.

---

## Architecture

```
DetectionEvent ──► EventDatabase (SQLite, WAL)
                     │
                     ├── group_events()      → EventGroup[]
                     ├── score_event()       → ScoreResult
                     ├── correlate()         → BehaviorAlert[]
                     └── ReportGenerator     → PDF

Live signals (psutil) ──► snapshot_processes / snapshot_connections
FIM (hashlib)         ──► snapshot_files / diff_snapshots
Quarantine (shutil)   ──► QuarantineManager
```

---

## Testing

```bash
python veytrix.py --test
```

Covers: validation, path safety, DB migrations & retention, dedupe, scoring,
echo detection, behavior correlation, FIM create/modify/delete, quarantine
roundtrip, PDF generation with hostile text, process monitor logic.

---

## Platform support

| Feature | Windows | Kali Linux |
|---|---|---|
| Event store | ✅ | ✅ |
| PDF reports | ✅ | ✅ |
| Process monitoring | ✅ | ✅ |
| Network monitoring | ✅ | ✅ (needs `CAP_NET_ADMIN` for some fields) |
| File integrity | ✅ | ✅ |
| Quarantine | ✅ | ✅ (root for system files) |
| GUI | ✅ | ✅ (`python3-tk`) |

---

## Known limitations

- **No encryption at rest** — rely on disk encryption (BitLocker / LUKS).
- **No full-text index** — `--text` uses SQL `LIKE`; add FTS5 for millions of rows.
- **PDF font is Helvetica** — CJK/emoji render as boxes; register a TTF to fix.
- **No PDF signing** — sign externally (GPG, PDF/A signer).
- **SQLite single-writer** — multi-process ingestion serializes on `BEGIN IMMEDIATE`.
- **Behavior rules are per-host** — cross-host correlation is out of scope.
- **Quarantine is local only** — no EDR-side restoration.

---

## License

MIT — see `LICENSE`.

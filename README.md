# Veytrix

Offline suspicious-process detection and PDF reporting for Windows 10/11 and Kali Linux.

## Features

- Live process monitoring
- Rule-based suspicious-process detection (PowerShell, mimikatz, reverse shells, etc.)
- Local SQLite event history
- Professional PDF report export
- No cloud, no AI, no destructive actions

## Install & Run

```bash
pip install -r requirements.txt
python veytrix.py
```

Windows users can also double-click `veytrix.py` after installing Python from python.org.

## Usage

1. Click **Start Monitoring**
2. Watch processes populate; suspicious ones are flagged
3. Click **Export PDF** to save a report
4. Data is stored at `~/.veytrix/events.db`

## Detectable patterns

- Encoded PowerShell commands
- `Invoke-Expression`, `DownloadString`, `-WindowStyle Hidden`
- `certutil` URL cache downloads, `bitsadmin` transfers
- `mshta` / `regsvr32` remote payloads
- `vssadmin` shadow copy deletion
- Mimikatz / sekurlsa / procdump LSASS
- Bash reverse shells (`/dev/tcp`, `nc -e`)
- Masquerading Windows system binaries
- Execution from user-writable directories

## Security notes

- Command lines may contain secrets — treat the SQLite DB and PDFs as sensitive.
- No automatic destructive actions (no process killing, no quarantine).
- No elevation requested automatically.

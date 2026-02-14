# CISCO FLASH SCANNER

C64-ish terminal UI to fetch AP inventory from a Cisco WLC and scan AP filesystems via SSH.

## Requirements

- `python3`
- `ssh`
- `expect`
  - macOS: `brew install expect`

## Run

```bash
cd wlc_ap_tui
./wlc_ap_tui.py
```

## Keys (Scan Screen)

- `↑/↓` scroll
- `SPACE` mark/unmark
- `s` scan selected
- `S` scan marked
- `a` autoscan toggle
- `b` set batch size
- `c` set concurrency
- `r` refresh WLC list
- `e` show last error of selected AP (footer)
- `R` reload selected AP (2-step confirm, red modal)
- `q` back to home

## Output

Each scan creates a folder under `wlc_ap_tui/scan_results/<scanname>_<timestamp>/`:

- `aps.json`
- `aps.csv`
- `wlc_show_ap_summary.txt`
- `events.log`

## Demo Data

This repo may include anonymized demo scans under `wlc_ap_tui/demo_data/`.

## Disclaimer

Use at your own risk. No warranty. Authorized use only.

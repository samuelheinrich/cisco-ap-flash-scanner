#!/usr/bin/env python3
"""
CISCO FLASH SCANNER (C64-ish TUI)

Home screen -> New scan wizard -> AP list scanner

Wizard:
- WLC host/user/pass (optional enable pass; if empty, no "en" is executed)
- AP user/pass/enable-pass
- Passwords are masked ('*' per character)

Scanning screen:
- Pulls "show ap summary" from WLC via SSH (expect)
- Lists APs: Name | Model | IP | Location
- Manual scan selected/marked APs: "show filesystems" (expect)
- Shows /part1, /part2, /tmp Use% per AP
- Autoscan with batch size and concurrency
- Arrow-key scrolling; does not exit when all APs are scanned

Results:
- Continuously written (no passwords) to scan_results/<scanname>_<YYYY-MM-DD_HHMMSS>.json
- Events written to scan_results/<scanname>_<...>.log
"""

from __future__ import annotations

import curses
import dataclasses
import datetime as dt
import json
import os
import queue
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from collections import deque
import csv
from typing import Optional


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_ROOT = os.path.join(BASE_DIR, "scan_results")

# Run the boot animation only once per program start.
HOME_BOOT_DONE = False


SUMMARY_RE = re.compile(
    # We only care about name/model/ip/location. State can contain spaces, so we split location by 2+ spaces.
    r"^(?P<name>\S+)\s+"
    r"(?P<slots>\d+)\s+"
    r"(?P<model>\S+)\s+"
    r".*?\s+"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<rest>.+)$",
    re.IGNORECASE,
)

STATE_LOC_RE = re.compile(r"^(?P<state>.+?)\s{2,}(?P<location>.+)$")

FS_LINE_RE = re.compile(r"^\S+\s+\S+\s+\S+\s+\S+\s+(?P<use>\d{1,3})%\s+(?P<mount>/\S+)\s*$")


@dataclasses.dataclass
class APRow:
    name: str
    model: str
    ip: str
    location: str
    part1: Optional[int] = None
    part2: Optional[int] = None
    tmp: Optional[int] = None
    last_scan: Optional[dt.datetime] = None
    status: str = "NEW"  # NEW|SCANNING|OK|FAIL
    marked: bool = False
    last_error: str = ""


@dataclasses.dataclass
class ScanConfig:
    scan_name: str
    created_at: dt.datetime
    wlc_host: str
    wlc_user: str
    wlc_pass: str
    wlc_enable_pass: str
    ap_user: str
    ap_pass: str
    ap_enable_pass: str
    out_dir: str
    json_path: str
    csv_path: str
    wlc_raw_path: str
    events_path: str


class ScanStore:
    def __init__(self, cfg: ScanConfig) -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        self.last_refresh = cfg.created_at

    def set_refresh(self, t: dt.datetime) -> None:
        with self._lock:
            self.last_refresh = t

    def _atomic_write(self, path: str, data: str) -> None:
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, path)

    def event(self, msg: str) -> None:
        ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} {msg}\n"
        with self._lock:
            with open(self.cfg.events_path, "a", encoding="utf-8") as f:
                f.write(line)

    def save(self, rows: list[APRow]) -> None:
        # Never write passwords to disk.
        with self._lock:
            payload = {
                "scan_name": self.cfg.scan_name,
                "created_at": self.cfg.created_at.isoformat(timespec="seconds"),
                "out_dir": self.cfg.out_dir,
                "wlc": {
                    "host": self.cfg.wlc_host,
                    "user": self.cfg.wlc_user,
                    "enable_used": bool(self.cfg.wlc_enable_pass),
                    "last_refresh": self.last_refresh.isoformat(timespec="seconds"),
                },
                "ap_auth": {
                    "user": self.cfg.ap_user,
                    "enable_used": True,
                },
                "aps": [
                    {
                        "name": r.name,
                        "model": r.model,
                        "ip": r.ip,
                        "location": r.location,
                        "part1_use": r.part1,
                        "part2_use": r.part2,
                        "tmp_use": r.tmp,
                        "status": r.status,
                        "marked": r.marked,
                        "last_scan": None if r.last_scan is None else r.last_scan.isoformat(timespec="seconds"),
                        "last_error": r.last_error,
                    }
                    for r in rows
                ],
            }
            self._atomic_write(self.cfg.json_path, json.dumps(payload, indent=2) + "\n")

            # CSV export
            tmp = f"{self.cfg.csv_path}.tmp"
            with open(tmp, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["name", "model", "ip", "location", "part1_use", "part2_use", "tmp_use", "status", "marked", "last_scan", "last_error"])
                for r in rows:
                    w.writerow(
                        [
                            r.name,
                            r.model,
                            r.ip,
                            r.location,
                            r.part1,
                            r.part2,
                            r.tmp,
                            r.status,
                            int(r.marked),
                            "" if r.last_scan is None else r.last_scan.isoformat(timespec="seconds"),
                            r.last_error,
                        ]
                    )
            os.replace(tmp, self.cfg.csv_path)


def sanitize_name(s: str) -> str:
    s = s.strip()
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    s = re.sub(r"_+", "_", s)
    s = s.strip("_")
    return s or "scan"


def run_expect(script: str, env: dict[str, str], timeout: int = 120) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["expect"],
        input=script,
        text=True,
        capture_output=True,
        env={**os.environ, **env},
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_expect_live(
    script: str,
    env: dict[str, str],
    debug_lines: "deque[str]",
    cancel: threading.Event,
    timeout: int = 120,
) -> tuple[int, str, str]:
    proc = subprocess.Popen(
        ["expect"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, **env},
        bufsize=1,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None

    out_chunks: list[str] = []
    err_chunks: list[str] = []

    def _reader(stream, prefix: str, sink: list[str]) -> None:
        for line in iter(stream.readline, ""):
            if cancel.is_set():
                return
            sink.append(line)
            debug_lines.append(f"{prefix}{line.rstrip()}")

    t_out = threading.Thread(target=_reader, args=(proc.stdout, "O: ", out_chunks), daemon=True)
    t_err = threading.Thread(target=_reader, args=(proc.stderr, "E: ", err_chunks), daemon=True)
    t_out.start()
    t_err.start()

    try:
        proc.stdin.write(script)
        proc.stdin.close()
    except Exception:
        pass

    deadline = time.time() + timeout
    while time.time() < deadline:
        if cancel.is_set():
            try:
                proc.terminate()
            except Exception:
                pass
            break
        rc = proc.poll()
        if rc is not None:
            break
        time.sleep(0.05)

    if proc.poll() is None:
        try:
            proc.terminate()
        except Exception:
            pass

    # Give readers a moment to drain
    t_out.join(timeout=0.5)
    t_err.join(timeout=0.5)

    return proc.returncode or 0, "".join(out_chunks), "".join(err_chunks)


def parse_wlc_summary(out: str, err: str) -> tuple[list[APRow], str, str]:
    if "__ERR__" in out:
        msg = out.split("__ERR__", 1)[1].strip()
        return [], msg or "unknown WLC error", ""
    if "__BEGIN__" not in out or "__END__" not in out:
        return [], (err.strip() or "unexpected WLC output format"), ""
    body = out.split("__BEGIN__", 1)[1].split("__END__", 1)[0]
    rows: list[APRow] = []
    for raw in body.splitlines():
        line = raw.strip("\r").strip()
        m = SUMMARY_RE.match(line)
        if not m:
            continue
        rest = m.group("rest").strip()
        loc = ""
        m2 = STATE_LOC_RE.match(rest)
        if m2:
            loc = m2.group("location").strip()
        else:
            # Fallback: no clear state/location split, keep rest as location-ish string.
            loc = rest
        rows.append(
            APRow(
                name=m.group("name"),
                model=m.group("model"),
                ip=m.group("ip"),
                location=loc,
            )
        )
    if not rows:
        return [], "parsed 0 AP rows from summary (regex mismatch?)", body
    return rows, "", body


def wlc_fetch_ap_summary(wlc_host: str, wlc_user: str, wlc_pass: str, wlc_enable_pass: str) -> tuple[list[APRow], str, str]:
    expect_script = r"""
match_max 4000000
set timeout 120
log_user 0

set host $env(WLC_HOST)
set user $env(WLC_USER)
set pass $env(WLC_PASS)
set enpass $env(WLC_ENPASS)

proc bail {msg} {
  puts "__ERR__"
  puts $msg
  flush stdout
  exit 2
}

    spawn ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ${user}@${host}

expect {
  -re ".*assword:.*" { send -- "${pass}\r" }
  timeout { bail "timeout waiting for password prompt" }
  eof { bail "connection closed during login" }
}

expect {
  -re {#\s*$} {}
  -re {>\s*$} {
    if {$enpass eq ""} { bail "wlc prompt is '>' but enable password is empty" }
    send -- "en\r"
    expect {
      -re ".*assword:.*" { send -- "${enpass}\r" }
      timeout { bail "enable password prompt timeout" }
    }
    expect {
      -re {#\s*$} {}
      timeout { bail "no privileged prompt after enable" }
    }
  }
  timeout { bail "no WLC prompt after login" }
  eof { bail "connection closed after login" }
}

send -- "term len 0\r"
expect -re {[#>]\s*$}
send -- "terminal length 0\r"
expect -re {[#>]\s*$}
send -- "config paging disable\r"
expect -re {[#>]\s*$}
send -- "terminal width 0\r"
expect -re {[#>]\s*$}

send -- "show ap summary\r"
set all ""
expect {
  -re {(?i)--more--} {
    append all $expect_out(buffer)
    send -- " "
    exp_continue
  }
  -re {(?i)press any key to continue} {
    append all $expect_out(buffer)
    send -- " "
    exp_continue
  }
  -re {#\s*$} {
    append all $expect_out(buffer)
    # Strip pager artifacts/backspaces to keep raw readable.
    regsub -all {\x08} $all {} all
    regsub -all {(?i)--more--} $all {} all
    puts "__BEGIN__"
    puts $all
    puts "__END__"
    flush stdout
  }
  -re {.+} {
    append all $expect_out(buffer)
    exp_continue
  }
  timeout { bail "timeout waiting for show ap summary output" }
  eof { bail "connection closed while reading summary" }
}

send -- "exit\r"
"""
    rc, out, err = run_expect(
        expect_script,
        {"WLC_HOST": wlc_host, "WLC_USER": wlc_user, "WLC_PASS": wlc_pass, "WLC_ENPASS": wlc_enable_pass},
        timeout=120,
    )
    return parse_wlc_summary(out, err)


def wlc_fetch_ap_summary_live(
    wlc_host: str,
    wlc_user: str,
    wlc_pass: str,
    wlc_enable_pass: str,
    debug_lines: "deque[str]",
    cancel: threading.Event,
) -> tuple[list[APRow], str, str]:
    # Same as wlc_fetch_ap_summary, but streams output for UI debug pane.
    expect_script = r"""
match_max 4000000
set timeout 120
log_user 1

set host $env(WLC_HOST)
set user $env(WLC_USER)
set pass $env(WLC_PASS)
set enpass $env(WLC_ENPASS)

proc bail {msg} {
  puts "__ERR__"
  puts $msg
  flush stdout
  exit 2
}

puts "STEP: spawn ssh"
flush stdout
spawn ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 ${user}@${host}

expect {
  -re ".*assword:.*" { puts "STEP: send password"; send -- "${pass}\r" }
  timeout { bail "timeout waiting for password prompt" }
  eof { bail "connection closed during login" }
}

puts "STEP: wait for prompt"
flush stdout
expect {
  -re {#\s*$} { puts "STEP: privileged prompt"; }
  -re {>\s*$} {
    puts "STEP: non-privileged prompt"
    if {$enpass eq ""} { bail "wlc prompt is '>' but enable password is empty" }
    send -- "en\r"
    expect {
      -re ".*assword:.*" { puts "STEP: send enable password"; send -- "${enpass}\r" }
      timeout { bail "enable password prompt timeout" }
    }
    expect {
      -re {#\s*$} { puts "STEP: privileged after enable"; }
      timeout { bail "no privileged prompt after enable" }
    }
  }
  timeout { bail "no WLC prompt after login" }
  eof { bail "connection closed after login" }
}

puts "STEP: term len 0"
flush stdout
send -- "term len 0\r"
expect -re {#\s*$}
puts "STEP: term width 0"
flush stdout
send -- "term width 0\r"
expect -re {#\s*$}
puts "STEP: terminal length 0"
flush stdout
send -- "terminal length 0\r"
expect -re {[#>]\s*$}
puts "STEP: config paging disable"
flush stdout
send -- "config paging disable\r"
expect -re {[#>]\s*$}
puts "STEP: terminal width 0"
flush stdout
send -- "terminal width 0\r"
expect -re {[#>]\s*$}

puts "STEP: show ap summary"
flush stdout
send -- "show ap summary\r"
set all ""
expect {
  -re {(?i)--more--} {
    append all $expect_out(buffer)
    send -- " "
    exp_continue
  }
  -re {(?i)press any key to continue} {
    append all $expect_out(buffer)
    send -- " "
    exp_continue
  }
  -re {#\s*$} {
    append all $expect_out(buffer)
    regsub -all {\x08} $all {} all
    regsub -all {(?i)--more--} $all {} all
    puts "__BEGIN__"
    puts $all
    puts "__END__"
    flush stdout
  }
  -re {.+} {
    append all $expect_out(buffer)
    exp_continue
  }
  timeout { bail "timeout waiting for show ap summary output" }
  eof { bail "connection closed while reading summary" }
}

send -- "exit\r"
"""
    rc, out, err = run_expect_live(
        expect_script,
        {"WLC_HOST": wlc_host, "WLC_USER": wlc_user, "WLC_PASS": wlc_pass, "WLC_ENPASS": wlc_enable_pass},
        debug_lines,
        cancel,
        timeout=120,
    )
    return parse_wlc_summary(out, err)


def ap_scan_filesystems(ip: str, ap_user: str, ap_pass: str, enable_pass: str) -> tuple[Optional[int], Optional[int], Optional[int], str]:
    expect_script = r"""
set timeout 45
log_user 0

set host $env(AP_HOST)
set user $env(AP_USER)
set pass $env(AP_PASS)
set enpass $env(AP_ENPASS)

proc bail {msg} {
  puts "__ERR__"
  puts $msg
  flush stdout
  exit 2
}

spawn ssh -o StrictHostKeyChecking=accept-new ${user}@${host}

expect {
  -re ".*assword:.*" { send -- "${pass}\r" }
  timeout { bail "timeout waiting for ssh password prompt" }
  eof { bail "connection closed during ssh login" }
}

expect {
  -re ".*>\\s*$" { send -- "en\r" }
  -re ".*#\\s*$" {}
  timeout { bail "no AP prompt after login" }
  eof { bail "connection closed after login" }
}

expect {
  -re ".*assword:.*" { send -- "${enpass}\r"; exp_continue }
  -re ".*#\\s*$" {}
  timeout { bail "enable password timeout" }
}

send -- "term len 0\r"
expect -re {#\s*$}

send -- "show filesystems\r"
expect {
  -re {#\s*$} {
    set buf $expect_out(buffer)
    puts "__BEGIN__"
    puts $buf
    puts "__END__"
    flush stdout
  }
  timeout { bail "timeout waiting for show filesystems output" }
  eof { bail "connection closed while reading filesystems" }
}

send -- "exit\r"
"""
    rc, out, err = run_expect(
        expect_script,
        {"AP_HOST": ip, "AP_USER": ap_user, "AP_PASS": ap_pass, "AP_ENPASS": enable_pass},
        timeout=120,
    )
    if "__ERR__" in out:
        msg = out.split("__ERR__", 1)[1].strip()
        return None, None, None, msg or "unknown AP error"
    if "__BEGIN__" not in out or "__END__" not in out:
        return None, None, None, (err.strip() or "unexpected AP output format")
    body = out.split("__BEGIN__", 1)[1].split("__END__", 1)[0]

    part1 = part2 = tmp = None
    for raw in body.splitlines():
        line = raw.strip("\r").strip()
        m = FS_LINE_RE.match(line)
        if not m:
            continue
        mount = m.group("mount")
        use = int(m.group("use"))
        if mount == "/part1":
            part1 = use
        elif mount == "/part2":
            part2 = use
        elif mount == "/tmp":
            tmp = use
    return part1, part2, tmp, ""


def ap_reload(ip: str, ap_user: str, ap_pass: str, enable_pass: str) -> str:
    expect_script = r"""
set timeout 60
log_user 0
match_max 200000

set host $env(AP_HOST)
set user $env(AP_USER)
set pass $env(AP_PASS)
set enpass $env(AP_ENPASS)

proc bail {msg} {
  puts "__ERR__"
  puts $msg
  flush stdout
  exit 2
}

spawn ssh -o StrictHostKeyChecking=accept-new ${user}@${host}

expect {
  -re {(?i)are you sure you want to continue connecting} { send -- "yes\r"; exp_continue }
  -re {(?i)password:} { send -- "${pass}\r" }
  timeout { bail "timeout waiting for ssh password prompt" }
  eof { bail "connection closed during ssh login" }
}

expect {
  -re {>\s*$} { send -- "en\r" }
  -re {#\s*$} {}
  timeout { bail "no AP prompt after login" }
  eof { bail "connection closed after login" }
}

expect {
  -re {(?i)password:} { send -- "${enpass}\r"; exp_continue }
  -re {#\s*$} {}
  timeout { bail "enable password timeout" }
}

send -- "term len 0\r"
expect -re {#\s*$}

send -- "reload\r"
expect {
  -re {(?i)system configuration has been modified.*} { send -- "no\r"; exp_continue }
  -re {(?i)save\?\s*\[yes/no\].*} { send -- "no\r"; exp_continue }
  -re {(?i)proceed with reload\?\s*\[confirm\]} { send -- "\r"; puts "__OK__"; flush stdout; exit 0 }
  -re {(?i)\[confirm\]} { send -- "\r"; puts "__OK__"; flush stdout; exit 0 }
  timeout { bail "timeout waiting for reload confirmation" }
  eof { bail "connection closed before reload confirmation" }
}
"""
    rc, out, err = run_expect(
        expect_script,
        {"AP_HOST": ip, "AP_USER": ap_user, "AP_PASS": ap_pass, "AP_ENPASS": enable_pass},
        timeout=120,
    )
    if "__OK__" in out:
        return ""
    if "__ERR__" in out:
        msg = out.split("__ERR__", 1)[1].strip()
        return msg or "reload failed"
    if rc != 0 and err.strip():
        return err.strip()[:160]
    return "reload failed (unexpected output)"


class ScanEngine:
    def __init__(self, rows: list[APRow], cfg: ScanConfig, store: ScanStore):
        self.rows = rows
        self.cfg = cfg
        self.store = store

        self._lock = threading.Lock()
        self._q: "queue.Queue[int]" = queue.Queue()
        self._stop = threading.Event()
        self._autoscan = False
        self.batch_size = 10
        self.concurrency = 5

        self._pool = ThreadPoolExecutor(max_workers=32)
        self._worker_thread = threading.Thread(target=self._loop, daemon=True)
        self._worker_thread.start()

    def stop(self) -> None:
        self._stop.set()

    def set_autoscan(self, on: bool) -> None:
        self._autoscan = on

    def enqueue(self, idxs: list[int]) -> None:
        for i in idxs:
            self._q.put(i)

    def enqueue_marked(self) -> None:
        self.enqueue([i for i, r in enumerate(self.rows) if r.marked])

    def enqueue_next_batch(self) -> None:
        idxs: list[int] = []
        with self._lock:
            for i, r in enumerate(self.rows):
                if r.status in ("NEW", "FAIL"):
                    idxs.append(i)
                if len(idxs) >= self.batch_size:
                    break
        self.enqueue(idxs)

    def reload(self, idx: int) -> None:
        # Manual only; we do not put this into the autoscan queue.
        self._pool.submit(self._reload_one, idx)

    def _scan_one(self, idx: int) -> None:
        with self._lock:
            r = self.rows[idx]
            r.status = "SCANNING"
            r.last_error = ""
        try:
            p1, p2, t, err = ap_scan_filesystems(r.ip, self.cfg.ap_user, self.cfg.ap_pass, self.cfg.ap_enable_pass)
            with self._lock:
                r.part1, r.part2, r.tmp = p1, p2, t
                r.last_scan = dt.datetime.now()
                if err:
                    r.status = "FAIL"
                    r.last_error = err[:160]
                else:
                    r.status = "OK"
            self.store.event(f"scan ip={r.ip} name={r.name} status={r.status}")
        except Exception as e:  # noqa: BLE001
            with self._lock:
                r.status = "FAIL"
                r.last_error = f"{type(e).__name__}: {e}"[:160]
            self.store.event(f"scan ip={self.rows[idx].ip} error={type(e).__name__}")
        finally:
            # Continuous export
            self.store.save(self.rows)

    def _reload_one(self, idx: int) -> None:
        with self._lock:
            r = self.rows[idx]
            if r.status == "SCANNING":
                self.store.event(f"reload skipped busy ip={r.ip} name={r.name}")
                return
            r.status = "RELOAD"
            r.last_error = ""

        self.store.event(f"reload start ip={r.ip} name={r.name}")
        try:
            err = ap_reload(r.ip, self.cfg.ap_user, self.cfg.ap_pass, self.cfg.ap_enable_pass)
            with self._lock:
                if err:
                    r.status = "FAIL"
                    r.last_error = err[:160]
                else:
                    r.status = "RELOADED"
            self.store.event(f"reload done ip={r.ip} name={r.name} status={r.status}")
        except Exception as e:  # noqa: BLE001
            with self._lock:
                r.status = "FAIL"
                r.last_error = f"{type(e).__name__}: {e}"[:160]
            self.store.event(f"reload error ip={self.rows[idx].ip} error={type(e).__name__}")
        finally:
            self.store.save(self.rows)

    def _loop(self) -> None:
        inflight: set[int] = set()
        while not self._stop.is_set():
            try:
                idx = self._q.get(timeout=0.2)
            except queue.Empty:
                if self._autoscan:
                    self.enqueue_next_batch()
                continue

            if idx in inflight:
                continue

            while len(inflight) >= self.concurrency and not self._stop.is_set():
                time.sleep(0.05)

            inflight.add(idx)

            def _done(_f, i=idx):
                inflight.discard(i)

            fut = self._pool.submit(self._scan_one, idx)
            fut.add_done_callback(_done)


def format_pct(v: Optional[int]) -> str:
    return "-" if v is None else f"{v:>3d}%"


def c64_init_colors() -> None:
    curses.start_color()
    # Avoid default background bleeding through (some terminals show magenta as default).
    # C64-ish: light text on blue
    curses.init_pair(10, curses.COLOR_WHITE, curses.COLOR_BLUE)   # base
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLUE)      # fail
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLUE)    # ok
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLUE)   # scanning
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLUE)     # accent
    curses.init_pair(5, curses.COLOR_CYAN, curses.COLOR_BLUE)     # border-ish (same bg as base)
    curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED)     # DANGER modal (reload)


def _modal_window(stdscr, height: int, width: int, attr: int):
    h, w = stdscr.getmaxyx()
    # Keep a visible margin so we can safely draw full borders without hitting bottom-right of the screen.
    height = max(7, min(height, h - 6))
    width = max(30, min(width, w - 6))
    y0 = max(2, (h - height) // 2)
    x0 = max(3, (w - width) // 2)
    win = curses.newwin(height, width, y0, x0)
    win.keypad(True)
    win.bkgd(" ", attr)
    win.erase()
    return win


def _draw_win_border(win, title: str, attr: int) -> None:
    h, w = win.getmaxyx()
    if h < 3 or w < 10:
        return
    top = "+" + ("-" * (w - 2)) + "+"
    mid = "|" + (" " * (w - 2)) + "|"
    bot = top
    try:
        win.addnstr(0, 0, top, w, attr | curses.A_BOLD)
        for y in range(1, h - 1):
            win.addnstr(y, 0, mid, w, attr)
        win.addnstr(h - 1, 0, bot, w, attr | curses.A_BOLD)
    except curses.error:
        return
    if title:
        t = f" {title} "
        x = max(2, (w // 2) - (len(t) // 2))
        try:
            win.addnstr(0, x, t, max(0, w - x), attr | curses.A_BOLD)
        except curses.error:
            return


def _confirm_reload_popup(stdscr, ap: APRow) -> bool:
    # Step 1: Yes/No
    attr = curses.color_pair(6) | curses.A_BOLD
    win = _modal_window(stdscr, height=15, width=78, attr=attr)
    _draw_win_border(win, "DANGER ZONE", curses.color_pair(6))
    h, w = win.getmaxyx()

    lines = [
        "do really want to reload this AP?",
        "",
        f"NAME: {ap.name}",
        f"IP  : {ap.ip}",
        f"MODEL: {ap.model}",
        f"LOC : {ap.location}",
        "",
        "Y = yes, reload it",
        "N/ESC = abort",
    ]
    y = 2
    for ln in lines:
        if y >= h - 2:
            break
        x = max(2, (w // 2) - (len(ln) // 2))
        try:
            win.addnstr(y, x, ln, w - 4, attr)
        except curses.error:
            pass
        y += 1
    win.refresh()

    while True:
        ch = win.getch()
        if ch in (ord("y"), ord("Y")):
            break
        if ch in (ord("n"), ord("N"), 27):  # ESC
            return False

    # Step 2: keyword confirmation
    win.erase()
    _draw_win_border(win, "FINAL CONFIRM", curses.color_pair(6))
    prompt = "Type RELOAD and press ENTER (ESC abort):"
    try:
        win.addnstr(2, max(2, (w // 2) - (len(prompt) // 2)), prompt, w - 4, attr)
        win.addnstr(4, 4, f"TARGET: {ap.name}  {ap.ip}", w - 8, attr)
    except curses.error:
        pass
    typed: list[str] = []
    while True:
        shown = "".join(typed)
        try:
            win.addnstr(7, 4, " " * (w - 8), w - 8, attr)
            win.addnstr(7, 4, shown[: (w - 8)], w - 8, attr | curses.A_REVERSE)
        except curses.error:
            pass
        win.refresh()
        ch = win.getch()
        if ch in (27,):  # ESC
            return False
        if ch in (10, 13, curses.KEY_ENTER):
            if "".join(typed).strip().upper() == "RELOAD":
                return True
            # Wrong keyword -> flash message, then reset input.
            msg = "WRONG KEYWORD. Type RELOAD to confirm."
            try:
                win.addnstr(9, max(2, (w // 2) - (len(msg) // 2)), msg, w - 4, attr)
            except curses.error:
                pass
            win.refresh()
            time.sleep(0.8)
            try:
                win.addnstr(9, 2, " " * (w - 4), w - 4, attr)
            except curses.error:
                pass
            typed = []
            continue
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if typed:
                typed.pop()
            continue
        if 32 <= ch <= 126:
            if len(typed) < 32:
                typed.append(chr(ch))


def fill_bg(stdscr) -> None:
    stdscr.bkgd(" ", curses.color_pair(10))


def clear_full(stdscr) -> None:
    # Ensure the whole screen becomes the base color (no "unpainted" areas).
    fill_bg(stdscr)
    stdscr.erase()
    # Fill the last column (except the bottom-right cell) to avoid default-bg stripes.
    h, w = stdscr.getmaxyx()
    if w > 0 and h > 1:
        try:
            for y in range(0, h - 1):
                stdscr.addch(y, w - 1, ord(" "), curses.color_pair(10))
        except curses.error:
            pass


def draw_border(stdscr, title: str = "") -> None:
    h, w = stdscr.getmaxyx()
    if h < 3 or w < 10:
        return
    # Outer border (C64-ish "frame")
    # Avoid drawing into the last column: many terminals/curses setups error on bottom-right cell.
    width = w - 1
    if width < 10:
        return
    top = "+" + ("-" * (width - 2)) + "+"
    mid = "|" + (" " * (width - 2)) + "|"
    bot = top
    try:
        stdscr.addnstr(0, 0, top, width, curses.color_pair(5) | curses.A_BOLD)
        for y in range(1, h - 1):
            stdscr.addnstr(y, 0, mid, width, curses.color_pair(5))
        stdscr.addnstr(h - 1, 0, bot, width, curses.color_pair(5) | curses.A_BOLD)
    except curses.error:
        return

    if title:
        t = f" {title} "
        x = max(2, (w // 2) - (len(t) // 2))
        try:
            stdscr.addnstr(0, x, t, max(0, (w - 1) - x), curses.color_pair(5) | curses.A_BOLD)
        except curses.error:
            return


def prompt_line(stdscr, label: str) -> str:
    curses.echo()
    h, w = stdscr.getmaxyx()
    stdscr.move(h - 1, 0)
    stdscr.clrtoeol()
    stdscr.addnstr(h - 1, 0, label, w - 1, curses.color_pair(10))
    stdscr.refresh()
    s = stdscr.getstr(h - 1, min(len(label), w - 2)).decode(errors="ignore")
    curses.noecho()
    return s.strip()


def prompt_secret(stdscr, label: str) -> str:
    # no echo; show '*' per character
    curses.noecho()
    h, w = stdscr.getmaxyx()
    buf: list[str] = []
    while True:
        stdscr.move(h - 1, 0)
        stdscr.clrtoeol()
        shown = "*" * len(buf)
        stdscr.addnstr(h - 1, 0, f"{label}{shown}", w - 1, curses.color_pair(10))
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (10, 13, curses.KEY_ENTER):
            return "".join(buf)
        if ch in (27,):  # ESC cancels this field
            return ""
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if buf:
                buf.pop()
            continue
        if 32 <= ch <= 126:
            buf.append(chr(ch))


def home_screen(stdscr) -> str:
    global HOME_BOOT_DONE

    clear_full(stdscr)
    h, w = stdscr.getmaxyx()
    draw_border(stdscr, "CISCO FLASH SCANNER")

    def safe_add(y: int, x: int, s: str, n: int, attr: int) -> None:
        try:
            stdscr.addnstr(y, x, s, n, attr)
        except curses.error:
            return

    def boot_like_animation() -> None:
        # Any key skips.
        global HOME_BOOT_DONE
        if HOME_BOOT_DONE:
            return
        if h < 18 or w < 60:
            HOME_BOOT_DONE = True
            return

        stdscr.nodelay(True)
        try:
            y = 3
            x = 4
            attr = curses.color_pair(10) | curses.A_BOLD
            dim = curses.color_pair(10) | curses.A_DIM

            lines = [
                "**** CISCO FLASH SCANNER ****",
                "",
                "64K RAM SYSTEM  38911 BASIC BYTES FREE",
                "",
                "READY.",
                "",
                "PRESS ENTER TO START   (Q TO QUIT)",
            ]

            for line in lines:
                # Typewriter effect
                for i in range(len(line) + 1):
                    if stdscr.getch() != -1:
                        HOME_BOOT_DONE = True
                        return
                    part = line[:i]
                    safe_add(y, x, " " * (w - 8), w - 8, curses.color_pair(10))
                    safe_add(y, x, part, w - 8, attr if line else dim)
                    stdscr.refresh()
                    time.sleep(0.01 if line else 0.06)
                y += 1
                time.sleep(0.05)

            # Blink cursor
            cur_y = y
            cur_x = x
            for _ in range(10):
                if stdscr.getch() != -1:
                    HOME_BOOT_DONE = True
                    return
                safe_add(cur_y, cur_x, " " if _ % 2 == 0 else "_", 1, curses.color_pair(4) | curses.A_BOLD)
                stdscr.refresh()
                time.sleep(0.12)
        finally:
            stdscr.nodelay(False)
            HOME_BOOT_DONE = True

    boot_like_animation()

    # Controls + disclaimer near bottom.
    controls = [
        "ENTER  ->  NEW SCAN",
        "Q      ->  QUIT",
    ]
    disclaimer = [
        "USE AT YOUR OWN RISK. NO WARRANTY.",
        "AUTHORIZED USE ONLY. YOU ARE RESPONSIBLE FOR YOUR ACTIONS.",
    ]
    y_controls = max(2, h - 8)
    for j, line in enumerate(controls):
        x = max(2, (w - len(line)) // 2)
        safe_add(y_controls + j, x, line, w - x - 2, curses.color_pair(10) | curses.A_BOLD)

    y_dis = max(2, h - 5)
    for j, line in enumerate(disclaimer):
        x = max(2, (w - len(line)) // 2)
        safe_add(y_dis + j, x, line, w - x - 2, curses.color_pair(1) | curses.A_BOLD)

    stdscr.refresh()
    while True:
        ch = stdscr.getch()
        if ch in (10, 13, curses.KEY_ENTER):
            return "new"
        if ch in (ord("q"), ord("Q")):
            return "quit"


def scan_wizard(stdscr) -> Optional[ScanConfig]:
    def input_at(y: int, x: int, width: int, secret: bool) -> str:
        buf: list[str] = []
        while True:
            shown = ""
            if secret:
                shown = "*" * len(buf)
            else:
                shown = "".join(buf)
            stdscr.addnstr(y, x, " " * width, width, curses.color_pair(10))
            stdscr.addnstr(y, x, shown[:width], width, curses.color_pair(10) | curses.A_BOLD)
            stdscr.move(y, min(x + len(shown), x + width - 1))
            stdscr.refresh()
            ch = stdscr.getch()
            if ch in (10, 13, curses.KEY_ENTER):
                return "".join(buf).strip()
            if ch in (27,):  # ESC clears
                buf = []
                continue
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                if buf:
                    buf.pop()
                continue
            # ignore navigation keys
            if ch in (curses.KEY_UP, curses.KEY_DOWN, curses.KEY_LEFT, curses.KEY_RIGHT, curses.KEY_HOME, curses.KEY_END):
                continue
            if 32 <= ch <= 126:
                buf.append(chr(ch))

    while True:
        clear_full(stdscr)
        draw_border(stdscr, "NEW SCAN WIZARD")
        h, w = stdscr.getmaxyx()

        col_label = 4
        col_in = 28
        width = max(20, min(40, w - col_in - 6))
        y = 3

        stdscr.addnstr(y, col_label, "SCAN NAME", w - col_label - 2, curses.color_pair(4) | curses.A_BOLD)
        stdscr.addnstr(y + 1, col_label, "name:", w - col_label - 2, curses.color_pair(10))
        scan_name_raw = input_at(y + 1, col_in, width, secret=False)
        scan_name = sanitize_name(scan_name_raw)

        y += 3
        stdscr.addnstr(y, col_label, "WLC CONFIG", w - col_label - 2, curses.color_pair(4) | curses.A_BOLD)
        stdscr.addnstr(y + 1, col_label, "host/ip:", w - col_label - 2, curses.color_pair(10))
        wlc_host = input_at(y + 1, col_in, width, secret=False)
        stdscr.addnstr(y + 2, col_label, "username:", w - col_label - 2, curses.color_pair(10))
        wlc_user = input_at(y + 2, col_in, width, secret=False)
        stdscr.addnstr(y + 3, col_label, "password:", w - col_label - 2, curses.color_pair(10))
        wlc_pass = input_at(y + 3, col_in, width, secret=True)
        stdscr.addnstr(y + 4, col_label, "enable pw (opt):", w - col_label - 2, curses.color_pair(10))
        wlc_en = input_at(y + 4, col_in, width, secret=True)

        y += 6
        stdscr.addnstr(y, col_label, "AP CONFIG", w - col_label - 2, curses.color_pair(4) | curses.A_BOLD)
        stdscr.addnstr(y + 1, col_label, "username:", w - col_label - 2, curses.color_pair(10))
        ap_user = input_at(y + 1, col_in, width, secret=False)
        stdscr.addnstr(y + 2, col_label, "password:", w - col_label - 2, curses.color_pair(10))
        ap_pass = input_at(y + 2, col_in, width, secret=True)
        stdscr.addnstr(y + 3, col_label, "enable pw (ENTER = password):", w - col_label - 2, curses.color_pair(10))
        ap_en = input_at(y + 3, col_in, width, secret=True)
        if not ap_en:
            ap_en = ap_pass

        # Validate
        if not (wlc_host and wlc_user and wlc_pass and ap_user and ap_pass and ap_en):
            stdscr.addnstr(h - 3, 4, "ERROR: Missing required fields. Press any key to retry.", w - 8, curses.color_pair(1) | curses.A_BOLD)
            stdscr.refresh()
            stdscr.getch()
            continue

        os.makedirs(RESULTS_ROOT, exist_ok=True)
        ts = dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        base = f"{scan_name}_{ts}"
        out_dir = os.path.join(RESULTS_ROOT, base)
        os.makedirs(out_dir, exist_ok=True)
        json_path = os.path.join(out_dir, "aps.json")
        csv_path = os.path.join(out_dir, "aps.csv")
        wlc_raw_path = os.path.join(out_dir, "wlc_show_ap_summary.txt")
        events_path = os.path.join(out_dir, "events.log")

        return ScanConfig(
            scan_name=scan_name,
            created_at=dt.datetime.now(),
            wlc_host=wlc_host,
            wlc_user=wlc_user,
            wlc_pass=wlc_pass,
            wlc_enable_pass=wlc_en,
            ap_user=ap_user,
            ap_pass=ap_pass,
            ap_enable_pass=ap_en,
            out_dir=out_dir,
            json_path=json_path,
            csv_path=csv_path,
            wlc_raw_path=wlc_raw_path,
            events_path=events_path,
        )


def draw_scan_screen(
    stdscr,
    rows: list[APRow],
    sel: int,
    top: int,
    msg: str,
    engine: ScanEngine,
    store: ScanStore,
) -> None:
    clear_full(stdscr)
    h, w = stdscr.getmaxyx()

    draw_border(stdscr, "SCAN")

    def safe_add(y: int, x: int, s: str, n: int, attr: int) -> None:
        try:
            stdscr.addnstr(y, x, s, n, attr)
        except curses.error:
            return

    # Layout: left table + optional right panel when wide enough.
    inside_w = max(0, w - 4)
    gap = 3
    panel_target = 60 if inside_w >= 170 else 52 if inside_w >= 150 else 0
    has_right = panel_target > 0 and inside_w >= (90 + gap + panel_target)
    if has_right:
        panel_w = panel_target
        left_w = max(80, inside_w - panel_w - gap)
        right_x = 2 + left_w + gap
    else:
        panel_w = 0
        left_w = inside_w
        right_x = 0

    # Column layout (use fixed widths + dynamic location to keep perfect alignment).
    col_sel = 1
    col_name = 18
    col_model = 13
    col_ip = 15
    col_p1 = 5
    col_p2 = 6
    col_tmp = 5
    col_status = 8
    fixed = (col_sel + col_name + col_model + col_ip + col_p1 + col_p2 + col_tmp + col_status) + 8
    col_loc = max(10, left_w - fixed)

    header_line = " ".join(
        [
            " " * col_sel,
            "NAME".ljust(col_name),
            "MODEL".ljust(col_model),
            "IP".ljust(col_ip),
            "LOCATION".ljust(col_loc),
            "PART1".rjust(col_p1),
            "PART2".rjust(col_p2),
            "TMP".rjust(col_tmp),
            "STATUS".ljust(col_status),
        ]
    )
    safe_add(1, 2, header_line, left_w, curses.color_pair(4) | curses.A_BOLD)
    stdscr.addnstr(
        2,
        2,
        f"WLC {store.cfg.wlc_host}  USER {store.cfg.wlc_user}  LAST {store.last_refresh.strftime('%H:%M:%S')}  SCAN {store.cfg.scan_name}",
        left_w,
        curses.color_pair(10) | curses.A_DIM,
    )
    stdscr.addnstr(3, 2, f"OUT {store.cfg.out_dir}", left_w, curses.color_pair(10) | curses.A_DIM)

    view_h = h - 9
    for i in range(view_h):
        idx = top + i
        if idx >= len(rows):
            break
        r = rows[idx]
        y = 4 + i

        mark = "*" if r.marked else " "
        name = r.name[:col_name].ljust(col_name)
        model = r.model[:col_model].ljust(col_model)
        ip = r.ip[:col_ip].ljust(col_ip)
        loc = r.location[:col_loc].ljust(col_loc)
        p1 = format_pct(r.part1).rjust(col_p1)
        p2 = format_pct(r.part2).rjust(col_p2)
        tmp = format_pct(r.tmp).rjust(col_tmp)
        status = r.status[:col_status].ljust(col_status)

        line = f"{mark}{name} {model} {ip} {loc} {p1} {p2} {tmp} {status}"
        base_attr = curses.color_pair(10) | (curses.A_REVERSE if idx == sel else 0)
        safe_add(y, 2, line, left_w, base_attr)

        # Overlay per-column colors.
        def pct_attr(v: Optional[int]) -> int:
            if v is None:
                return curses.color_pair(10)
            if v >= 90:
                return curses.color_pair(1) | curses.A_BOLD
            if v >= 70:
                return curses.color_pair(3) | curses.A_BOLD
            return curses.color_pair(2)

        x_sel = 2
        x_name = x_sel + col_sel
        x_model = x_name + col_name + 1
        x_ip = x_model + col_model + 1
        x_loc = x_ip + col_ip + 1
        x_p1 = x_loc + col_loc + 1
        x_p2 = x_p1 + col_p1 + 1
        x_tmp = x_p2 + col_p2 + 1
        x_status = x_tmp + col_tmp + 1

        safe_add(y, x_sel, mark, col_sel, (curses.color_pair(4) if r.marked else curses.color_pair(10)) | (curses.A_REVERSE if idx == sel else 0))
        safe_add(y, x_p1, p1, col_p1, pct_attr(r.part1) | (curses.A_REVERSE if idx == sel else 0))
        safe_add(y, x_p2, p2, col_p2, pct_attr(r.part2) | (curses.A_REVERSE if idx == sel else 0))
        safe_add(y, x_tmp, tmp, col_tmp, pct_attr(r.tmp) | (curses.A_REVERSE if idx == sel else 0))

        st_attr = curses.color_pair(10)
        if r.status in ("OK", "RELOADED"):
            st_attr = curses.color_pair(2) | curses.A_BOLD
        elif r.status == "FAIL":
            st_attr = curses.color_pair(1) | curses.A_BOLD
        elif r.status in ("SCANNING", "RELOAD"):
            st_attr = curses.color_pair(3) | curses.A_BOLD
        safe_add(y, x_status, status, col_status, st_attr | (curses.A_REVERSE if idx == sel else 0))

    # Right info panel
    if has_right:
        stdscr.addnstr(1, right_x, "SYSTEM STATUS", panel_w, curses.color_pair(4) | curses.A_BOLD)
        total = len(rows)
        counts = {"NEW": 0, "SCANNING": 0, "OK": 0, "FAIL": 0}
        for r in rows:
            counts[r.status] = counts.get(r.status, 0) + 1
        stdscr.addnstr(3, right_x, f"connected: YES", panel_w, curses.color_pair(2) | curses.A_BOLD)
        stdscr.addnstr(4, right_x, f"total APs : {total}", panel_w, curses.color_pair(10))
        stdscr.addnstr(5, right_x, f"OK/FAIL  : {counts['OK']}/{counts['FAIL']}", panel_w, curses.color_pair(10))
        stdscr.addnstr(6, right_x, f"NEW      : {counts['NEW']}", panel_w, curses.color_pair(10))
        stdscr.addnstr(7, right_x, f"SCANNING : {counts['SCANNING']}", panel_w, curses.color_pair(10))

        # model distribution top 5
        model_cnt: dict[str, int] = {}
        for r in rows:
            model_cnt[r.model] = model_cnt.get(r.model, 0) + 1
        top_models = sorted(model_cnt.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        stdscr.addnstr(9, right_x, "top models:", panel_w, curses.color_pair(10) | curses.A_DIM)
        for j, (m, c) in enumerate(top_models):
            stdscr.addnstr(10 + j, right_x, f"{c:>3}  {m}", panel_w, curses.color_pair(10))

        blink = (int(time.time() * 2) % 2) == 0
        yb = 15
        stdscr.addnstr(yb, right_x, "MODE:", panel_w, curses.color_pair(10) | curses.A_DIM)
        stdscr.addnstr(yb + 1, right_x, "MANUAL SCAN", panel_w, curses.color_pair(10) | curses.A_BOLD)
        if engine._autoscan:
            attr = curses.color_pair(3) | (curses.A_REVERSE if blink else curses.A_BOLD)
            stdscr.addnstr(yb + 3, right_x, "AUTOSCAN ENABLED", panel_w, attr)
        else:
            stdscr.addnstr(yb + 3, right_x, "AUTOSCAN DISABLED", panel_w, curses.color_pair(10) | curses.A_DIM)

        # Tiny ASCII flair
        flair = [
            r"  .----.   .----.",
            r" / .--. \ / .--. \ ",
            r"| |    | | |    | |",
            r"| |    | | |    | |",
            r" \ '--' / \ '--' / ",
            r"  '----'   '----'  ",
        ]
        yfl = yb + 6
        for k, line in enumerate(flair):
            if yfl + k >= h - 4:
                break
            stdscr.addnstr(yfl + k, right_x, line, panel_w, curses.color_pair(4) | curses.A_DIM)

        # selected AP detail
        r = rows[sel] if rows else None
        if r:
            y0 = max(17, yb + 13)
            stdscr.addnstr(y0, right_x, "selected:", panel_w, curses.color_pair(10) | curses.A_DIM)
            stdscr.addnstr(y0 + 1, right_x, f"{r.name}", panel_w, curses.color_pair(10) | curses.A_BOLD)
            stdscr.addnstr(y0 + 2, right_x, f"ip: {r.ip}", panel_w, curses.color_pair(10))
            stdscr.addnstr(y0 + 3, right_x, f"model: {r.model}", panel_w, curses.color_pair(10))
            stdscr.addnstr(y0 + 4, right_x, f"tmp: {format_pct(r.tmp)} part1:{format_pct(r.part1)} part2:{format_pct(r.part2)}", panel_w, curses.color_pair(10))
            if r.last_scan:
                stdscr.addnstr(y0 + 5, right_x, f"last scan: {r.last_scan.strftime('%H:%M:%S')}", panel_w, curses.color_pair(10))
            if r.last_error:
                stdscr.addnstr(y0 + 7, right_x, "last error:", panel_w, curses.color_pair(1) | curses.A_BOLD)
                stdscr.addnstr(y0 + 8, right_x, r.last_error, panel_w, curses.color_pair(10) | curses.A_DIM)

    footer = (
        f"rows={len(rows)} sel={sel+1}/{len(rows)} top={top+1}  "
        f"autoscan={'ON' if engine._autoscan else 'OFF'}  batch={engine.batch_size}  conc={engine.concurrency}  "
        f"keys: ↑↓ scroll  SPACE mark  s scan sel  S scan marked  R reload  a autoscan  b batch  c conc  r refresh WLC  e err  q home"
    )
    stdscr.addnstr(h - 3, 2, footer, w - 4, curses.color_pair(10) | curses.A_DIM)
    stdscr.addnstr(h - 2, 2, msg[: w - 4], w - 4, curses.color_pair(10))
    stdscr.refresh()


def scan_screen(stdscr, cfg: ScanConfig) -> None:
    store = ScanStore(cfg)
    store.event("scan created")

    # Visible "connecting" screen with live debug pane (never looks stuck).
    cancel = threading.Event()
    debug_lines: "deque[str]" = deque(maxlen=200)
    result: dict[str, object] = {"done": False, "rows": [], "err": "", "raw": ""}

    def _worker() -> None:
        rows, err, raw = wlc_fetch_ap_summary_live(
            cfg.wlc_host, cfg.wlc_user, cfg.wlc_pass, cfg.wlc_enable_pass, debug_lines, cancel
        )
        result["rows"] = rows
        result["err"] = err
        result["raw"] = raw
        result["done"] = True

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

    stdscr.timeout(100)
    while not bool(result["done"]):
        clear_full(stdscr)
        draw_border(stdscr, "FETCHING AP SUMMARY")
        h, w = stdscr.getmaxyx()

        split = max(40, w // 2)
        left_x = 3
        right_x = split + 2

        stdscr.addnstr(2, left_x, "CONNECTING TO WLC", split - left_x - 2, curses.color_pair(3) | curses.A_BOLD)
        stdscr.addnstr(4, left_x, f"host  : {cfg.wlc_host}", split - left_x - 2, curses.color_pair(10))
        stdscr.addnstr(5, left_x, f"user  : {cfg.wlc_user}", split - left_x - 2, curses.color_pair(10))
        stdscr.addnstr(6, left_x, f"enable: {'YES' if cfg.wlc_enable_pass else 'NO'}", split - left_x - 2, curses.color_pair(10))
        stdscr.addnstr(8, left_x, "Q = cancel", split - left_x - 2, curses.color_pair(10) | curses.A_DIM)

        stdscr.addnstr(2, right_x, "SSH/EXPECT OUTPUT (tail)", w - right_x - 2, curses.color_pair(4) | curses.A_BOLD)
        dbg_h = h - 6
        tail = list(debug_lines)[-dbg_h:]
        for i, line in enumerate(tail):
            stdscr.addnstr(4 + i, right_x, line, w - right_x - 2, curses.color_pair(10) | curses.A_DIM)

        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q")):
            cancel.set()
            debug_lines.append("E: canceled by user")
            break

    stdscr.timeout(-1)
    rows = result.get("rows", [])
    err = result.get("err", "")
    raw = result.get("raw", "")

    if err:
        store.event(f"wlc fetch failed: {err}")
        stdscr.erase()
        fill_bg(stdscr)
        stdscr.addnstr(2, 2, f"WLC fetch failed: {err}", curses.COLS - 4, curses.color_pair(1) | curses.A_BOLD)
        stdscr.addnstr(4, 2, "press any key...", curses.COLS - 4, curses.color_pair(10))
        stdscr.refresh()
        stdscr.getch()
        return

    # Ask before importing (slows transition and lets user confirm).
    declared = None
    m = re.search(r"Number of APs:\\s*(\\d+)", str(raw))
    if m:
        declared = int(m.group(1))

    raw_lines = [ln.rstrip("\r") for ln in str(raw).splitlines()]
    raw_top = 0
    while True:
        clear_full(stdscr)
        draw_border(stdscr, "IMPORT (WLC SHOW AP SUMMARY)")
        h, w = stdscr.getmaxyx()
        mismatch = ""
        if declared is not None and declared != len(rows):
            mismatch = "  MISMATCH!"
        stdscr.addnstr(
            1,
            2,
            f"parsed={len(rows)}  declared={declared if declared is not None else 'n/a'}{mismatch}  out={cfg.out_dir}",
            w - 4,
            (curses.color_pair(1) | curses.A_BOLD) if mismatch else (curses.color_pair(10) | curses.A_BOLD),
        )
        stdscr.addnstr(2, 2, "Scroll: ↑/↓ PgUp/PgDn   Import: y/n", w - 4, curses.color_pair(10) | curses.A_DIM)

        view_h = h - 6
        for i in range(view_h):
            idx = raw_top + i
            if idx >= len(raw_lines):
                break
            stdscr.addnstr(3 + i, 2, raw_lines[idx], w - 4, curses.color_pair(10))

        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (ord("y"), ord("Y")):
            break
        if ch in (ord("n"), ord("N"), ord("q"), ord("Q")):
            store.event("import canceled")
            return
        if ch == curses.KEY_UP:
            raw_top = max(0, raw_top - 1)
        elif ch == curses.KEY_DOWN:
            raw_top = min(max(0, len(raw_lines) - 1), raw_top + 1)
        elif ch == curses.KEY_PPAGE:  # PgUp
            raw_top = max(0, raw_top - view_h)
        elif ch == curses.KEY_NPAGE:  # PgDn
            raw_top = min(max(0, len(raw_lines) - 1), raw_top + view_h)

    # Persist raw WLC output for this scan.
    try:
        with open(cfg.wlc_raw_path, "w", encoding="utf-8") as f:
            f.write(raw)
            if not raw.endswith("\n"):
                f.write("\n")
    except OSError:
        store.event("failed to write wlc raw output")

    store.set_refresh(dt.datetime.now())
    store.save(rows)  # initial export

    engine = ScanEngine(rows, cfg, store)
    sel = 0
    top = 0
    msg = "ready"
    try:
        while True:
            draw_scan_screen(stdscr, rows, sel, top, msg, engine, store)
            ch = stdscr.getch()

            if ch in (curses.KEY_UP, ord("k")):
                sel = max(0, sel - 1)
                if sel < top:
                    top = sel
                msg = ""
            elif ch in (curses.KEY_DOWN, ord("j")):
                sel = min(len(rows) - 1, sel + 1)
                h, _w = stdscr.getmaxyx()
                view_h = h - 9
                if sel >= top + view_h:
                    top = sel - view_h + 1
                msg = ""
            elif ch == ord(" "):
                rows[sel].marked = not rows[sel].marked
                store.save(rows)
                msg = f"marked={rows[sel].marked} {rows[sel].name}"
            elif ch == ord("s"):
                engine.enqueue([sel])
                msg = f"queued: {rows[sel].name} {rows[sel].ip}"
            elif ch == ord("S"):
                engine.enqueue_marked()
                msg = "queued: marked rows"
            elif ch == ord("a"):
                engine.set_autoscan(not engine._autoscan)
                store.event(f"autoscan={engine._autoscan}")
                msg = f"autoscan={'ON' if engine._autoscan else 'OFF'}"
            elif ch == ord("b"):
                val = prompt_line(stdscr, "batch size: ")
                if val.isdigit() and int(val) > 0:
                    engine.batch_size = int(val)
                    store.event(f"batch={engine.batch_size}")
                    msg = f"batch={engine.batch_size}"
                else:
                    msg = "invalid batch"
            elif ch == ord("c"):
                val = prompt_line(stdscr, "concurrency: ")
                if val.isdigit() and int(val) > 0:
                    engine.concurrency = int(val)
                    store.event(f"conc={engine.concurrency}")
                    msg = f"conc={engine.concurrency}"
                else:
                    msg = "invalid conc"
            elif ch == ord("e"):
                r = rows[sel]
                msg = (r.last_error or "(no error)")[:200]
            elif ch == ord("r"):
                new_rows, werr, raw2 = wlc_fetch_ap_summary(cfg.wlc_host, cfg.wlc_user, cfg.wlc_pass, cfg.wlc_enable_pass)
                if werr:
                    msg = f"WLC refresh failed: {werr}"
                    store.event(f"wlc refresh failed: {werr}")
                else:
                    by_ip = {r.ip: r for r in rows}
                    merged: list[APRow] = []
                    for nr in new_rows:
                        if nr.ip in by_ip:
                            old = by_ip[nr.ip]
                            nr.part1, nr.part2, nr.tmp = old.part1, old.part2, old.tmp
                            nr.last_scan = old.last_scan
                            nr.status = old.status
                            nr.marked = old.marked
                            nr.last_error = old.last_error
                        merged.append(nr)
                    rows[:] = merged
                    store.set_refresh(dt.datetime.now())
                    store.save(rows)
                    store.event(f"wlc refresh ok rows={len(rows)}")
                    try:
                        with open(cfg.wlc_raw_path, "w", encoding="utf-8") as f:
                            f.write(raw2)
                            if not raw2.endswith("\n"):
                                f.write("\n")
                    except OSError:
                        store.event("failed to write wlc raw output")
                    sel = min(sel, len(rows) - 1) if rows else 0
                    top = min(top, max(0, len(rows) - 1))
                    msg = f"WLC refreshed: {len(rows)} APs"
            elif ch == ord("R"):
                if not rows:
                    msg = "no APs"
                    continue
                r = rows[sel]
                if r.status == "SCANNING":
                    msg = f"busy: {r.name} is scanning"
                    continue
                if _confirm_reload_popup(stdscr, r):
                    store.event(f"reload requested ip={r.ip} name={r.name}")
                    engine.reload(sel)
                    msg = f"reload queued: {r.name} {r.ip}"
                else:
                    msg = "reload canceled"
            elif ch in (ord("q"), ord("Q")):
                store.event("back to home")
                break
    finally:
        engine.stop()


def app(stdscr) -> int:
    curses.curs_set(0)
    c64_init_colors()
    stdscr.keypad(True)
    clear_full(stdscr)

    while True:
        mode = home_screen(stdscr)
        if mode == "quit":
            return 0
        cfg = scan_wizard(stdscr)
        if cfg is None:
            continue
        scan_screen(stdscr, cfg)


def main() -> int:
    # No argparse: pure TUI flow as requested.
    return curses.wrapper(app)


if __name__ == "__main__":
    raise SystemExit(main())

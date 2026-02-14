#!/usr/bin/env python3
"""
Anonymize a scan folder produced by CISCO FLASH SCANNER.

Goal: produce demo data safe for publishing.
- Consistent mapping across aps.csv, aps.json, events.log, wlc_show_ap_summary.txt
- Replaces AP names, AP IPs, WLC host/user, locations
- Also anonymizes MAC addresses found in WLC summary

NOTE: This tool does not modify the input folder.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
from typing import Any


IP_RE = re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
MAC_DOT_RE = re.compile(r"\b(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\b")
TERM_RE = re.compile(r"(?i)\b(selmoni|selution)\b")


def _sha12(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:12]


def fake_mac_dot(mac: str) -> str:
    h = _sha12(mac)
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}"


def build_maps(scan: dict[str, Any], wlc_raw: str) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str]]:
    aps = scan.get("aps", [])
    names = sorted({a.get("name") for a in aps if a.get("name")})
    ips = sorted({a.get("ip") for a in aps if a.get("ip")})
    locs = sorted({a.get("location") for a in aps if a.get("location")})

    name_map = {n: f"AP-ANON-{i+1:03d}" for i, n in enumerate(names)}
    # Use RFC5737 TEST-NET-1 for APs.
    ip_map = {ip: f"192.0.2.{i+10}" for i, ip in enumerate(ips)}
    loc_map = {loc: f"LOC-{i+1:03d}" for i, loc in enumerate(locs)}

    macs = sorted(set(MAC_DOT_RE.findall(wlc_raw)))
    mac_map = {m: fake_mac_dot(m) for m in macs}
    return name_map, ip_map, loc_map, mac_map


def apply_text_maps(text: str, name_map: dict[str, str], ip_map: dict[str, str], loc_map: dict[str, str], mac_map: dict[str, str]) -> str:
    # Replace longer strings first to reduce overlap risk.
    for old, new in sorted(loc_map.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(old, new)
    for old, new in sorted(name_map.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(old, new)

    def _ip_sub(m: re.Match[str]) -> str:
        ip = m.group("ip")
        return ip_map.get(ip, ip)

    def _mac_sub(m: re.Match[str]) -> str:
        mac = m.group("mac")
        return mac_map.get(mac, mac)

    text = IP_RE.sub(_ip_sub, text)
    text = MAC_DOT_RE.sub(_mac_sub, text)
    # Strip specific org terms even if they appear elsewhere.
    text = TERM_RE.sub("ANON", text)
    return text


def anonymize_folder(in_dir: str, out_dir: str) -> None:
    aps_json = os.path.join(in_dir, "aps.json")
    aps_csv = os.path.join(in_dir, "aps.csv")
    events_log = os.path.join(in_dir, "events.log")
    wlc_txt = os.path.join(in_dir, "wlc_show_ap_summary.txt")

    for p in (aps_json, aps_csv, events_log, wlc_txt):
        if not os.path.isfile(p):
            raise SystemExit(f"missing file: {p}")

    with open(aps_json, "r", encoding="utf-8") as f:
        scan = json.load(f)
    with open(wlc_txt, "r", encoding="utf-8") as f:
        wlc_raw = f.read()

    name_map, ip_map, loc_map, mac_map = build_maps(scan, wlc_raw)

    os.makedirs(out_dir, exist_ok=True)

    # aps.json
    scan2 = scan
    scan2["scan_name"] = "demo_scan"
    scan2["out_dir"] = f"demo_data/{os.path.basename(out_dir)}"
    if isinstance(scan2.get("wlc"), dict):
        scan2["wlc"]["host"] = "198.51.100.10"
        scan2["wlc"]["user"] = "wlc_user"
    if isinstance(scan2.get("ap_auth"), dict):
        scan2["ap_auth"]["user"] = "ap_user"

    aps = scan2.get("aps", [])
    for a in aps:
        if isinstance(a, dict):
            n = a.get("name")
            ip = a.get("ip")
            loc = a.get("location")
            if n in name_map:
                a["name"] = name_map[n]
            if ip in ip_map:
                a["ip"] = ip_map[ip]
            if loc in loc_map:
                a["location"] = loc_map[loc]
            # last_error might contain hostnames/ips
            if a.get("last_error"):
                a["last_error"] = apply_text_maps(str(a["last_error"]), name_map, ip_map, loc_map, mac_map)

    with open(os.path.join(out_dir, "aps.json"), "w", encoding="utf-8") as f:
        json.dump(scan2, f, indent=2)
        f.write("\n")

    # aps.csv (parse -> rewrite)
    with open(aps_csv, "r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        rows = list(r)
        fieldnames = r.fieldnames or []

    for row in rows:
        if "name" in row and row["name"] in name_map:
            row["name"] = name_map[row["name"]]
        if "ip" in row and row["ip"] in ip_map:
            row["ip"] = ip_map[row["ip"]]
        if "location" in row and row["location"] in loc_map:
            row["location"] = loc_map[row["location"]]
        if "last_error" in row and row["last_error"]:
            row["last_error"] = apply_text_maps(str(row["last_error"]), name_map, ip_map, loc_map, mac_map)

    with open(os.path.join(out_dir, "aps.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)

    # events.log
    with open(events_log, "r", encoding="utf-8") as f:
        ev = f.read()
    ev2 = apply_text_maps(ev, name_map, ip_map, loc_map, mac_map)
    with open(os.path.join(out_dir, "events.log"), "w", encoding="utf-8") as f:
        f.write(ev2)

    # wlc_show_ap_summary.txt
    wlc2 = apply_text_maps(wlc_raw, name_map, ip_map, loc_map, mac_map)
    with open(os.path.join(out_dir, "wlc_show_ap_summary.txt"), "w", encoding="utf-8") as f:
        f.write(wlc2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_dir", required=True, help="input scan folder (contains aps.json/aps.csv/events.log/wlc_show_ap_summary.txt)")
    ap.add_argument("--out", dest="out_dir", required=True, help="output folder to write anonymized files")
    args = ap.parse_args()
    anonymize_folder(args.in_dir, args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


#!/usr/bin/env python3
import json
import argparse
from pathlib import Path


DEFAULT_SRC = Path(__file__).resolve().parent / "regression.json"
OUT = Path(__file__).resolve().parent / "test_devices.json"


def normalize_str(s):
    if not isinstance(s, str):
        return ""
    return s.strip().lower()


def build_entry(d):
    expected = d.get("device_type", "")
    vendor = normalize_str(d.get("device_vendor", ""))
    hostname = normalize_str(d.get("hostname", ""))

    mdns = [normalize_str(x) for x in d.get("mdns_services", []) if isinstance(x, str) and x.strip()]

    # open_ports can be [] or list of objects; keep only port and banner
    ports = []
    for p in d.get("open_ports", []) or []:
        if isinstance(p, dict):
            port = p.get("port")
            banner = normalize_str(p.get("banner", ""))
            if isinstance(port, int):
                ports.append({"port": port, "banner": banner})
        elif isinstance(p, int):
            ports.append({"port": p, "banner": ""})

    label = hostname or (vendor.replace(" ", "_") if vendor else d.get("ip_address", "")) or "device"

    return {
        "label": label,
        "expected": expected,
        "input": {
            "open_ports": ports,
            "mdns_services": mdns,
            "vendor": vendor,
            "hostname": hostname,
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Build compact test set from a larger dataset")
    ap.add_argument("--src", default=str(DEFAULT_SRC), help="Path to source dataset JSON (default: regression.json)")
    ap.add_argument("--out", default=str(OUT), help="Output test set path (default: test_devices.json)")
    args = ap.parse_args()

    src_path = Path(args.src)
    out_path = Path(args.out)

    with open(src_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    devices = data.get("devices", [])
    out = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        entry = build_entry(d)
        # Keep only entries with an expected type
        if entry["expected"]:
            out.append(entry)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")

    print(f"Wrote {len(out)} test entries to {out_path}")


if __name__ == "__main__":
    main()




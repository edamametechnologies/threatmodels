#!/usr/bin/env python3
import json
import re
from pathlib import Path

BASE = Path(__file__).resolve().parent
IN_FILE = BASE / "test_devices.json"
OUT_FILE = BASE / "test_devices.json"
BACKUP_FILE = BASE / "test_devices.raw.json"

# Known vendor tokens to preserve in hostnames when present
VENDOR_TOKENS = [
    "sonos", "bose", "jbl", "harman", "hp", "freebox", "samsung", "apple",
    "philips", "raspberrypi", "raspberry", "netgear", "withings", "nest",
    "qnap", "synology", "asustor", "dell", "lenovo", "acer", "msi", "asus",
    "tpvision", "vizio", "tcl", "hisense", "toshiba", "hue", "lifx", "wemo",
    "dyson", "tuya", "shelly", "tasmota"
]

# Also preserve common console tokens used by rules
CONSOLE_TOKENS = ["ps4", "ps5", "xbox"]

HEX_LONG = re.compile(r"\b[0-9a-fA-F]{8,}\b")
MAC = re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
UUID = re.compile(r"\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b")
SERIAL_LABEL = re.compile(r"serial\s*number\s*:[^;,\n]+", re.IGNORECASE)


def anonymize_banner(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    t = SERIAL_LABEL.sub("serial number: XXXX", text)
    t = MAC.sub("xx:xx:xx:xx:xx:xx", t)
    t = UUID.sub("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", t)
    t = HEX_LONG.sub("XXXX", t)
    return t


def anonymize_mdns(service: str, vendor_base: str) -> str:
    if not isinstance(service, str) or not service:
        return service
    # Preserve service/type suffix; replace instance name before ._
    dot_idx = service.find("._")
    if dot_idx > 0:
        inst = service[:dot_idx]
        suffix = service[dot_idx:]
        # scrub identifiers in instance while keeping words (e.g., vendor + room)
        inst = anonymize_banner(inst)
        inst = re.sub(r"[-_]?([0-9a-fA-F]{6,}|\d{6,})", "", inst)
        inst = re.sub(r"\s+", " ", inst).strip(" -_.")
        low = inst.lower()
        if not inst or low.startswith("rincon") or low.startswith("sonosrincon"):
            inst = vendor_base or "device"
        return inst + suffix
    # If plain hostname.local, anonymize hostname
    if service.endswith(".local"):
        base = service[:-6]
        base = anonymize_banner(base)
        base = re.sub(r"[-_]?([0-9a-fA-F]{6,}|\d{6,})", "", base).strip(" -_.")
        if not base:
            base = vendor_base or "device"
        return base + ".local"
    return service


def should_preserve_hostname(hostname: str) -> bool:
    low = hostname.lower()
    return any(k in low for k in HOSTNAME_KEYWORDS)


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        items = json.load(f)

    # Backup original once
    if not BACKUP_FILE.exists():
        with open(BACKUP_FILE, "w", encoding="utf-8") as bf:
            json.dump(items, bf, indent=2)
            bf.write("\n")

    counter = 1
    out = []
    for it in items:
        inp = it.get("input", {})
        hostname = inp.get("hostname", "")
        vendor_field = inp.get("vendor", "")
        vendor_base = ""
        if isinstance(vendor_field, str):
            m = re.search(r"[a-zA-Z][a-zA-Z0-9_-]*", vendor_field)
            vendor_base = (m.group(0).lower() if m else "")
        # Hostname anonymization: keep vendor token if present; remove serial-like tails
        if isinstance(hostname, str) and hostname:
            host_out = hostname
            if hostname.endswith(".local"):
                base = hostname[:-6]
                low = base.lower()
                has_vendor = any(tok in low for tok in VENDOR_TOKENS) or any(tok in low for tok in CONSOLE_TOKENS)
                if not has_vendor:
                    host_out = f"host-{counter}.local"
                    counter += 1
                else:
                    base = anonymize_banner(base)
                    base = re.sub(r"[-_]?([0-9a-fA-F]{6,}|\d{6,})", "", base).strip(" -_.")
                    if not base:
                        base = vendor_base or "host"
                    host_out = base + ".local"
            inp["hostname"] = host_out

        # Anonymize mdns instance parts and de-duplicate while preserving order
        mdns = inp.get("mdns_services", [])
        if isinstance(mdns, list):
            anon = [anonymize_mdns(s, vendor_base) for s in mdns]
            seen = set()
            deduped = []
            for s in anon:
                if s not in seen:
                    seen.add(s)
                    deduped.append(s)
            inp["mdns_services"] = deduped

        # Anonymize banners
        ports = inp.get("open_ports", [])
        if isinstance(ports, list):
            for p in ports:
                if isinstance(p, dict) and "banner" in p:
                    p["banner"] = anonymize_banner(p.get("banner", ""))

        # Normalize label to non-identifying string
        it["label"] = f"{it.get('expected','device')}-{len(out)+1:04d}"
        it["input"] = inp
        out.append(it)

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")

    print(f"Anonymized {len(out)} entries. Backup saved to {BACKUP_FILE}")


if __name__ == "__main__":
    main()



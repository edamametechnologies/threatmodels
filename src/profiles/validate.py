#!/usr/bin/env python3
import argparse
import json
import sys
from typing import Any, Dict, List, Tuple
from pathlib import Path


FAIL = "FAIL"
WARN = "WARN"


# --- Classification test runner ---
def classify_device(db: Dict[str, Any], device: Dict[str, Any]) -> str:
    """Pure-Python mirror of profiles.rs logic at a high level.
    Evaluates profiles against one device input and returns device_type or 'Unknown'.

    Parsing and order semantics mirror Rust after change:
    - Preserve JSON order and return on the first matching rule (first match wins)
    """
    profiles_list = db.get("profiles", [])
    # Normalize inputs
    vendor = (device.get("vendor") or "").lower()
    hostname = (device.get("hostname") or "").lower()
    mdns = [(s or "").lower() for s in device.get("mdns_services", [])]
    ports = set()
    banners = []
    for p in device.get("open_ports", []) or []:
        if isinstance(p, dict):
            if isinstance(p.get("port"), int):
                ports.add(p["port"])
            if isinstance(p.get("banner"), str):
                banners.append(p["banner"].lower())
    
    def leaf_matches(attrs: Dict[str, Any]) -> bool:
        # AND across attributes; within each attribute, OR/contains semantics
        # open_ports: all listed must be present
        # negate: invert result
        result = True
        if "open_ports" in attrs and isinstance(attrs["open_ports"], list):
            op = attrs["open_ports"]
            result = result and all(isinstance(x, int) and x in ports for x in op)
        if "mdns_services" in attrs and isinstance(attrs["mdns_services"], list) and attrs["mdns_services"]:
            result = result and any(any(s in m for m in mdns) for s in attrs["mdns_services"])
        if "vendors" in attrs and isinstance(attrs["vendors"], list) and attrs["vendors"]:
            result = result and any((v or "").lower() in vendor for v in attrs["vendors"])
        if "hostnames" in attrs and isinstance(attrs["hostnames"], list) and attrs["hostnames"]:
            result = result and any((h or "").lower() in hostname for h in attrs["hostnames"])
        if "banners" in attrs and isinstance(attrs["banners"], list) and attrs["banners"]:
            result = result and any(any(bfrag in b for b in banners) for bfrag in attrs["banners"])
        if attrs.get("negate") is True:
            result = not result
        return result

    def cond_matches(cond: Dict[str, Any]) -> bool:
        if "Leaf" in cond and isinstance(cond["Leaf"], dict):
            return leaf_matches(cond["Leaf"])
        if "Node" in cond and isinstance(cond["Node"], dict):
            ctype = cond["Node"].get("type")
            subs = cond["Node"].get("sub_conditions") or []
            if ctype == "AND":
                return all(cond_matches(s) for s in subs)
            if ctype == "OR":
                return any(cond_matches(s) for s in subs)
        return False

    # Iterate strictly in JSON order; first match wins
    for idx, prof in enumerate(profiles_list):
        for cond in prof.get("conditions", []):
            if cond_matches(cond):
                return prof.get("device_type", "Unknown")
    return "Unknown"


def matching_device_types(db: Dict[str, Any], device: Dict[str, Any]) -> List[str]:
    """Return all device_types whose rules would match the given device.

    Uses last-write-wins effective profile set (same as classify_device) but
    does not stop at first match, to detect overlapping rules.
    """
    profiles_list = db.get("profiles", [])
    last_index: Dict[str, int] = {}
    for idx, prof in enumerate(profiles_list):
        dt = prof.get("device_type")
        if isinstance(dt, str) and dt:
            last_index[dt] = idx

    # Normalize inputs (same as classify_device)
    vendor = (device.get("vendor") or "").lower()
    hostname = (device.get("hostname") or "").lower()
    mdns = [(s or "").lower() for s in device.get("mdns_services", [])]
    ports = set()
    banners = []
    for p in device.get("open_ports", []) or []:
        if isinstance(p, dict):
            if isinstance(p.get("port"), int):
                ports.add(p["port"]) 
            if isinstance(p.get("banner"), str):
                banners.append(p["banner"].lower())

    def leaf_matches(attrs: Dict[str, Any]) -> bool:
        result = True
        if "open_ports" in attrs and isinstance(attrs["open_ports"], list):
            op = attrs["open_ports"]
            result = result and all(isinstance(x, int) and x in ports for x in op)
        if "mdns_services" in attrs and isinstance(attrs["mdns_services"], list) and attrs["mdns_services"]:
            result = result and any(any(s in m for m in mdns) for s in attrs["mdns_services"])
        if "vendors" in attrs and isinstance(attrs["vendors"], list) and attrs["vendors"]:
            result = result and any((v or "").lower() in vendor for v in attrs["vendors"])
        if "hostnames" in attrs and isinstance(attrs["hostnames"], list) and attrs["hostnames"]:
            result = result and any((h or "").lower() in hostname for h in attrs["hostnames"])
        if "banners" in attrs and isinstance(attrs["banners"], list) and attrs["banners"]:
            result = result and any(any(bfrag in b for b in banners) for bfrag in attrs["banners"])
        if attrs.get("negate") is True:
            result = not result
        return result

    def cond_matches(cond: Dict[str, Any]) -> bool:
        if "Leaf" in cond and isinstance(cond["Leaf"], dict):
            return leaf_matches(cond["Leaf"])
        if "Node" in cond and isinstance(cond["Node"], dict):
            ctype = cond["Node"].get("type")
            subs = cond["Node"].get("sub_conditions") or []
            if ctype == "AND":
                return all(cond_matches(s) for s in subs)
            if ctype == "OR":
                return any(cond_matches(s) for s in subs)
        return False

    matches: List[str] = []
    for idx, prof in enumerate(profiles_list):
        dt = prof.get("device_type")
        if not (isinstance(dt, str) and dt):
            continue
        if last_index.get(dt, idx) != idx:
            continue
        for cond in prof.get("conditions", []):
            if cond_matches(cond):
                matches.append(dt)
                break
    return matches


def run_classification_tests(db: Dict[str, Any], test_path: str) -> int:
    with open(test_path, "r", encoding="utf-8") as f:
        tests = json.load(f)
    failures = 0
    for t in tests:
        expected = t.get("expected", "")
        device = t.get("input", {})
        got = classify_device(db, device)
        overlaps = matching_device_types(db, device)
        if len(overlaps) > 1:
            print(f"[WARN] Overlapping match for {t.get('label','device')}: matches={overlaps}")
        if expected and got != expected:
            print(f"[FAIL] Classification mismatch for {t.get('label','device')}: expected={expected}, got={got}")
            failures += 1
    if failures:
        raise RuntimeError(f"{failures} classification mismatches in test set")
    return len(tests)


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def is_single_port_only(open_ports: Any) -> bool:
    return isinstance(open_ports, list) and len(open_ports) == 1


def list_contains_empty(values: List[str]) -> bool:
    return any((v is None) or (isinstance(v, str) and v.strip() == "") for v in values)


def normalize_attr_list(values: Any) -> List[str]:
    if not isinstance(values, list):
        return []
    out: List[str] = []
    for v in values:
        if isinstance(v, str):
            out.append(v)
    return out


def leaf_has_any_constraints(leaf: Dict[str, Any]) -> bool:
    open_ports = leaf.get("open_ports")
    if isinstance(open_ports, list) and len(open_ports) > 0:
        return True
    for name in ("mdns_services", "vendors", "hostnames", "banners"):
        vals = leaf.get(name)
        if isinstance(vals, list) and any(isinstance(v, str) and v.strip() != "" for v in vals):
            return True
    return False


def cond_classification(cond: Dict[str, Any]) -> str:
    """Return 'always_true', 'always_false', or 'unknown' for a condition subtree.
    This mirrors runtime semantics for trivial cases.
    """
    if "Leaf" in cond and isinstance(cond["Leaf"], dict):
        leaf = cond["Leaf"]
        negate = leaf.get("negate") is True
        has_constraints = leaf_has_any_constraints(leaf)
        if not has_constraints:
            return "always_false" if negate else "always_true"
        return "unknown"
    if "Node" in cond and isinstance(cond["Node"], dict):
        node = cond["Node"]
        ctype = node.get("type")
        subs = node.get("sub_conditions") or []
        child_classes = [cond_classification(s) for s in subs]
        if ctype == "AND":
            if any(c == "always_false" for c in child_classes):
                return "always_false"
            if all(c == "always_true" for c in child_classes):
                return "always_true"
            return "unknown"
        if ctype == "OR":
            if any(c == "always_true" for c in child_classes):
                return "always_true"
            if all(c == "always_false" for c in child_classes):
                return "always_false"
            return "unknown"
    # Malformed → unknown
    return "unknown"


def validate_leaf(device_type: str, leaf: Dict[str, Any], safe_context: bool, path: str) -> List[Tuple[str, str]]:
    issues: List[Tuple[str, str]] = []
    open_ports = leaf.get("open_ports")
    mdns_services = normalize_attr_list(leaf.get("mdns_services"))
    vendors = normalize_attr_list(leaf.get("vendors"))
    hostnames = normalize_attr_list(leaf.get("hostnames"))
    banners = normalize_attr_list(leaf.get("banners"))
    negate = leaf.get("negate")

    # Empty string sentinels are dangerous (e.g., vendors: [""])
    if vendors and list_contains_empty(vendors):
        issues.append((FAIL, f"{device_type}: vendors list contains empty string (at {path})"))
    if mdns_services and list_contains_empty(mdns_services):
        issues.append((FAIL, f"{device_type}: mdns_services contains empty string (at {path})"))
    if hostnames and list_contains_empty(hostnames):
        issues.append((FAIL, f"{device_type}: hostnames contains empty string (at {path})"))
    if banners and list_contains_empty(banners):
        issues.append((FAIL, f"{device_type}: banners contains empty string (at {path})"))

    # Weak open_ports usage without supporting constraints
    if isinstance(open_ports, list):
        try:
            _ = [int(p) for p in open_ports]
        except Exception:
            issues.append((FAIL, f"{device_type}: open_ports must be integers (at {path})"))
        has_other_constraints = any([
            bool(mdns_services), bool(vendors), bool(hostnames), bool(banners)
        ])
        if is_single_port_only(open_ports) and not has_other_constraints and not safe_context:
            issues.append((WARN, f"{device_type}: leaf relies only on a single port with no other constraints (at {path})"))
    elif open_ports is not None and not isinstance(open_ports, list):
        issues.append((FAIL, f"{device_type}: open_ports must be a list of integers (at {path})"))

    # Warn if explicitly specifying empty arrays (they act as no constraint)
    for name, arr in (
        ("mdns_services", leaf.get("mdns_services")),
        ("vendors", leaf.get("vendors")),
        ("hostnames", leaf.get("hostnames")),
        ("banners", leaf.get("banners")),
    ):
        if isinstance(arr, list) and len(arr) == 0:
            issues.append((WARN, f"{device_type}: {name} is an empty list; omit it instead (at {path})"))

    # Type check negate
    if negate is not None and not isinstance(negate, bool):
        issues.append((FAIL, f"{device_type}: negate must be a boolean (at {path})"))

    # Universal leaf (no constraints present) is dangerous and will always match
    has_constraints = any([
        isinstance(open_ports, list) and len(open_ports) > 0,
        len(mdns_services) > 0,
        len(vendors) > 0,
        len(hostnames) > 0,
        len(banners) > 0,
    ])
    if not has_constraints:
        issues.append((FAIL, f"{device_type}: Leaf has no constraints and will match everything (at {path})"))

    return issues


def walk_condition(device_type: str, condition: Dict[str, Any], safe_context: bool, path: str) -> List[Tuple[str, str]]:
    issues: List[Tuple[str, str]] = []
    if "Leaf" in condition:
        leaf = condition["Leaf"]
        if not isinstance(leaf, dict):
            issues.append((FAIL, f"{device_type}: Leaf must be an object (at {path})"))
        else:
            issues.extend(validate_leaf(device_type, leaf, safe_context, path))
    elif "Node" in condition:
        node = condition["Node"]
        if not isinstance(node, dict):
            issues.append((FAIL, f"{device_type}: Node must be an object (at {path})"))
        else:
            ctype = node.get("type")
            subs = node.get("sub_conditions")
            if ctype not in ("AND", "OR"):
                issues.append((FAIL, f"{device_type}: Node.type must be 'AND' or 'OR' (at {path})"))
            if not isinstance(subs, list) or not subs:
                issues.append((FAIL, f"{device_type}: Node.sub_conditions must be a non-empty array (at {path})"))
            else:
                if ctype == "AND":
                    # For each child, if any sibling subtree is not always_true, mark child context as safe
                    constraining = [cond_classification(s) != "always_true" for s in subs]
                    for idx, sub in enumerate(subs):
                        sibling_constraining = any(constraining[j] for j in range(len(subs)) if j != idx)
                        child_safe = safe_context or sibling_constraining
                        issues.extend(walk_condition(device_type, sub, child_safe, path + f"->AND[{idx}]"))
                else:  # OR
                    for idx, sub in enumerate(subs):
                        issues.extend(walk_condition(device_type, sub, safe_context, path + f"->OR[{idx}]"))
    else:
        issues.append((FAIL, f"{device_type}: Condition must be a Leaf or Node (at {path})"))
    return issues


def validate_profiles(db: Dict[str, Any]) -> List[Tuple[str, str]]:
    issues: List[Tuple[str, str]] = []
    profiles = db.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        return [(FAIL, "profiles must be a non-empty array")] 

    seen_types = set()
    for prof in profiles:
        device_type = prof.get("device_type")
        if not isinstance(device_type, str) or not device_type:
            issues.append((FAIL, "device_type must be a non-empty string"))
            continue
        if device_type in seen_types:
            issues.append((FAIL, f"duplicate device_type '{device_type}' (will overwrite in map)") )
        seen_types.add(device_type)

        conditions = prof.get("conditions")
        if not isinstance(conditions, list) or not conditions:
            issues.append((FAIL, f"{device_type}: conditions must be a non-empty array"))
            continue
        # Top-level conditions are ORed
        for idx, cond in enumerate(conditions):
            issues.extend(walk_condition(device_type, cond, safe_context=False, path=f"conditions[{idx}]"))

        # No device-specific checks here: rely on generic safety rules above

    return issues


def print_tree(db: Dict[str, Any]) -> None:
    def summarize_leaf(leaf: Dict[str, Any]) -> str:
        ports = leaf.get("open_ports")
        negate = leaf.get("negate")
        parts: List[str] = []
        if isinstance(ports, list):
            parts.append(f"ports={ports}")
            if is_single_port_only(ports):
                parts.append("single_port")
        for k in ("mdns_services", "vendors", "hostnames", "banners"):
            v = leaf.get(k)
            if isinstance(v, list) and v:
                parts.append(f"{k}={v}")
        if isinstance(negate, bool):
            parts.append(f"negate={negate}")
        return ", ".join(parts) if parts else "<no-constraints>"

    def walk(cond: Dict[str, Any], indent: int) -> None:
        pad = "  " * indent
        if "Leaf" in cond and isinstance(cond["Leaf"], dict):
            leaf = cond["Leaf"]
            print(f"{pad}- Leaf: {summarize_leaf(leaf)}")
            return
        if "Node" in cond and isinstance(cond["Node"], dict):
            ctype = cond["Node"].get("type")
            subs = cond["Node"].get("sub_conditions") or []
            cls = cond_classification(cond)
            print(f"{pad}- Node({ctype}) class={cls}")
            for s in subs:
                walk(s, indent + 1)
            return
        print(f"{pad}- <invalid condition>")

    for prof in db.get("profiles", []):
        dt = prof.get("device_type")
        print(f"Profile: {dt}")
        for c in prof.get("conditions", []):
            walk(c, 1)


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate lanscan profiles DB")
    ap.add_argument("--db", default="threatmodels/lanscan-profiles-db.json", help="Path to profiles DB JSON")
    ap.add_argument("--print-tree", action="store_true", help="Print a summary of the rule tree before validation")
    args = ap.parse_args()

    db = load_json(args.db)
    if args.print_tree:
        print_tree(db)
    issues = validate_profiles(db)
    failed = False
    for level, msg in issues:
        stream = sys.stderr if level == FAIL else sys.stdout
        print(f"[{level}] {msg}", file=stream)
        if level == FAIL:
            failed = True

    # Run semantic tests against anonymized test set if present
    try:
        # Locate test set next to this script
        script_dir = Path(__file__).resolve().parent
        test_path = script_dir / "test_devices.json"
        if test_path.exists():
            total = run_classification_tests(db, str(test_path))
            print(f"[INFO] Classification tests executed: {total} cases")
        else:
            print(f"[INFO] No test set found at {test_path}; skipping classification tests")
    except FileNotFoundError:
        # Optional tests – skip when not present
        print("[INFO] No test set found; skipping classification tests")
    except Exception as e:
        print(f"[FAIL] Test set execution error: {e}")
        failed = True

    if failed:
        return 1
    print("OK: no blocking issues found")
    return 0


if __name__ == "__main__":
    sys.exit(main())



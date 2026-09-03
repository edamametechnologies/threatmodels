#!/usr/bin/env python3
"""Keep the AI Agent Posture checks' framework tags in sync with the crosswalk.

The tags ("<Framework>,<Id>-<Title>") for OWASP GenAI Agentic / LLM Top 10,
MITRE ATLAS, Agentic Trust Controls and the publisher's ISO/IEC 42001 /
ISO 27001:2022 mappings are DERIVED, not hand-written: they come from
edamame_foundation::agent_framework_tags, the same tables the app's OWASP /
ATLAS / Trust Controls scorecards render. This script is the only thing that
writes them into threatmodel-*.json, so the app and the Hub cannot disagree.

Usage:
  # regenerate (after building the test runner against edamame_foundation main)
  python3 src/publish/sync-ai-framework-tags.py --runner src/test/target/release/run_cli_test --apply
  # CI drift gate: exit 1 when a model's AI check tags differ from the crosswalk
  python3 src/publish/sync-ai-framework-tags.py --runner src/test/target/release/run_cli_test --check
  # or feed a catalog dumped earlier
  python3 src/publish/sync-ai-framework-tags.py --catalog catalog.json --check

Only framework-derived tags are touched (identified by their framework prefix);
the product tag "AI Agent Posture" and any other tag are preserved as-is.
"""
import argparse
import json
import subprocess
import sys

MODELS = [
    "threatmodel-macOS.json",
    "threatmodel-Windows.json",
    "threatmodel-Linux.json",
    "threatmodel-iOS.json",
    "threatmodel-Android.json",
]

# Must match edamame_foundation::agent_framework_tags::AI_FRAMEWORK_PREFIXES.
FRAMEWORK_PREFIXES = {
    "OWASP GenAI Agentic Top 10",
    "OWASP GenAI LLM Top 10",
    "MITRE ATLAS",
    "Agentic Trust Controls",
    "ISO/IEC 42001:2023",
    "ISO 27001:2022",
}
PRODUCT_TAG = "AI Agent Posture"


def is_framework_tag(tag: str) -> bool:
    return tag.split(",", 1)[0].strip() in FRAMEWORK_PREFIXES


def is_ai_check(name: str) -> bool:
    return name in {
        "agents_with_blast_radius",
        "agents_without_harness",
        "harness_divergence",
        "mcp_risk",
        "vulnerabilities",
        "divergence",
        "escalated",
    } or name.startswith("unsecured_")


def load_catalog(args) -> dict:
    if args.catalog:
        with open(args.catalog, encoding="utf-8") as fh:
            return json.load(fh)
    out = subprocess.run([args.runner, "dump-ai-framework-tags"], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


def expected_tags(current: list, derived: list) -> list:
    kept = [t for t in current if not is_framework_tag(t)]
    if PRODUCT_TAG not in kept:
        kept.insert(0, PRODUCT_TAG)
    return kept + sorted(derived)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner", help="path to run_cli_test (built against edamame_foundation main)")
    ap.add_argument("--catalog", help="JSON file with {check: [tags]} (alternative to --runner)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true", help="rewrite the tags in every threat model")
    mode.add_argument("--check", action="store_true", help="exit 1 if any model's tags drift from the crosswalk")
    args = ap.parse_args()
    if not (args.runner or args.catalog):
        ap.error("one of --runner / --catalog is required")

    catalog = load_catalog(args)
    drift = []
    for path in MODELS:
        with open(path, encoding="utf-8") as fh:
            model = json.load(fh)
        changed = False
        for metric in model["metrics"]:
            name = metric["name"]
            if not is_ai_check(name):
                continue
            derived = catalog.get(name)
            if derived is None:
                print(f"::warning::{path}: AI check {name} has no crosswalk entry; left untouched", file=sys.stderr)
                continue
            want = expected_tags(metric.get("tags", []), derived)
            if metric.get("tags", []) != want:
                drift.append((path, name, len(metric.get("tags", [])), len(want)))
                metric["tags"] = want
                changed = True
        if args.apply and changed:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(model, fh, indent=2, ensure_ascii=False, sort_keys=True)
                fh.write("\n")
            print(f"updated {path}")

    if args.check:
        if drift:
            for path, name, have, want in drift:
                print(f"::error::{path}: tags for {name} drift from the crosswalk ({have} -> {want} tags); run sync-ai-framework-tags.py --apply", file=sys.stderr)
            return 1
        print("AI framework tags are in sync with the crosswalk")
    return 0


if __name__ == "__main__":
    sys.exit(main())

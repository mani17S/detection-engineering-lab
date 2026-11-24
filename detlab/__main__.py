"""Scan JSON-lines events with the Sigma rules in a directory.

    python -m detlab <rules-dir> <events.jsonl|-> [--min-level LEVEL] [--format text|json]

Exit code: 0 = no detections, 1 = at least one detection, 2 = usage error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import load_rules, scan

LEVELS = ["informational", "low", "medium", "high", "critical"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m detlab", description=__doc__.split("\n")[0])
    parser.add_argument("rules", type=Path, help="directory of Sigma rules (searched recursively)")
    parser.add_argument("events", help="JSON-lines file of events, or - for stdin")
    parser.add_argument("--min-level", choices=LEVELS, default="informational",
                        help="only report rules at or above this severity")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    floor = LEVELS.index(args.min_level)
    rules = [r for _, r in load_rules(args.rules) if LEVELS.index(r["level"]) >= floor]

    stream = sys.stdin if args.events == "-" else open(args.events, encoding="utf-8")
    with stream:
        events = [json.loads(line) for line in stream if line.strip()]

    hits = [
        {"event": index, "level": rule["level"], "title": rule["title"], "id": rule["id"],
         "attack": [t.split(".", 1)[1].upper() for t in rule.get("tags", [])
                    if t.startswith("attack.t")]}
        for index, rule in scan(rules, events)
    ]

    if args.format == "json":
        print(json.dumps({"events": len(events), "rules": len(rules), "detections": hits}, indent=2))
    else:
        for h in hits:
            print(f"event #{h['event']}: [{h['level'].upper()}] {h['title']}  ({', '.join(h['attack'])})")
        print(f"{len(hits)} detection(s) across {len(events)} event(s) using {len(rules)} rule(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())

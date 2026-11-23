"""CLI: python -m detlab <rules-dir> <events.jsonl>   (use - for stdin)

Exit code: 0 = no detections, 1 = at least one detection, 2 = usage error.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .engine import load_rules, scan


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    rules = [rule for _, rule in load_rules(Path(argv[0]))]
    stream = sys.stdin if argv[1] == "-" else open(argv[1], encoding="utf-8")
    with stream:
        events = [json.loads(line) for line in stream if line.strip()]
    hits = 0
    for index, rule in scan(rules, events):
        hits += 1
        print(f"event #{index}: [{rule['level'].upper()}] {rule['title']}")
    print(f"{hits} detection(s) across {len(events)} event(s) using {len(rules)} rule(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

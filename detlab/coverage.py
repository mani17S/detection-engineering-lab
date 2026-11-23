"""Print a MITRE ATT&CK coverage table (markdown) for a rules directory."""
from __future__ import annotations

import re
import sys
from pathlib import Path

from .engine import load_rules

TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


def main(directory: str = "rules") -> None:
    rows = []
    for path, rule in load_rules(Path(directory)):
        tags = rule.get("tags", [])
        techniques = [m.group(1).upper() for t in tags if (m := TECHNIQUE.match(t))]
        tactics = [t.split(".", 1)[1].replace("_", " ") for t in tags
                   if t.startswith("attack.") and not TECHNIQUE.match(t)]
        rows.append((", ".join(tactics), ", ".join(techniques), rule["title"], rule["level"], path.as_posix()))
    print("| Tactic | Technique | Rule | Level | File |\n|---|---|---|---|---|")
    for tactic, tech, title, level, file in sorted(rows):
        print(f"| {tactic} | {tech} | {title} | {level} | `{file}` |")


if __name__ == "__main__":
    main(*sys.argv[1:2])

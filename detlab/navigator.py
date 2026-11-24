"""Export rule coverage as an ATT&CK Navigator layer (JSON).

    python -m detlab.navigator rules > layer.json [--attack-version 16]

Open the file in https://mitre-attack.github.io/attack-navigator/ via "Open Existing Layer".
The score of a technique is the number of rules tagged with it.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

from .engine import load_rules

TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


def build_layer(rules_dir: Path, attack_version: str = "16") -> dict:
    by_technique: dict[str, list[str]] = defaultdict(list)
    for _, rule in load_rules(rules_dir):
        for tag in rule.get("tags", []):
            if m := TECHNIQUE.match(tag):
                by_technique[m.group(1).upper()].append(rule["title"])
    top = max((len(v) for v in by_technique.values()), default=1)
    return {
        "name": "detection-engineering-lab coverage",
        "versions": {"attack": attack_version, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by at least one rule in mani17S/detection-engineering-lab.",
        "gradient": {"colors": ["#d6e4ff", "#2f6fed"], "minValue": 0, "maxValue": top},
        "techniques": [
            {"techniqueID": tid, "score": len(titles), "comment": "; ".join(sorted(titles))}
            for tid, titles in sorted(by_technique.items())
        ],
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("rules", type=Path)
    parser.add_argument("--attack-version", default="16",
                        help="ATT&CK version your Navigator uses (default: 16)")
    args = parser.parse_args(argv)
    print(json.dumps(build_layer(args.rules, args.attack_version), indent=2))


if __name__ == "__main__":
    main()

"""Quality gates for every rule: metadata, ATT&CK tagging, and behavioural tests.

Each rule `rules/<...>/<name>.yml` must have `tests/events/<name>.json` with:
  positive: events that MUST match
  negative: benign look-alikes that MUST NOT match
"""
import json
import re
import uuid
from pathlib import Path

import pytest

from detlab.engine import load_rules, matches

ROOT = Path(__file__).resolve().parent.parent
RULES = list(load_rules(ROOT / "rules"))
IDS = [path.stem for path, _ in RULES]
REQUIRED = {"title", "id", "status", "description", "author", "date", "tags", "logsource",
            "detection", "falsepositives", "level"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
ATTACK_TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def test_rules_exist():
    assert len(RULES) >= 6


@pytest.mark.parametrize("path,rule", RULES, ids=IDS)
def test_metadata(path, rule):
    assert REQUIRED <= rule.keys(), f"missing: {REQUIRED - rule.keys()}"
    uuid.UUID(rule["id"])
    assert rule["level"] in LEVELS
    assert any(ATTACK_TECHNIQUE.match(t) for t in rule["tags"]), "needs an attack.tNNNN tag"
    assert "condition" in rule["detection"]


def test_rule_ids_are_unique():
    ids = [rule["id"] for _, rule in RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("path,rule", RULES, ids=IDS)
def test_positive_and_negative_events(path, rule):
    events_file = ROOT / "tests" / "events" / f"{path.stem}.json"
    assert events_file.exists(), f"missing test events: {events_file.name}"
    data = json.loads(events_file.read_text(encoding="utf-8"))
    assert data["positive"] and data["negative"], "need at least one of each"
    for event in data["positive"]:
        assert matches(rule, event), f"should detect: {event}"
    for event in data["negative"]:
        assert not matches(rule, event), f"false positive: {event}"

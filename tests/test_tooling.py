"""Tests for the CLI, the Navigator export, and the benign-events regression guard."""
import json
from pathlib import Path

from detlab.__main__ import main as cli_main
from detlab.engine import load_rules, matches
from detlab.navigator import build_layer

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"


def test_benign_events_trigger_no_rules():
    data = json.loads((ROOT / "tests" / "benign" / "benign_events.json").read_text(encoding="utf-8"))
    events = [e for key, group in data.items() if not key.startswith("_") for e in group]
    assert len(events) >= 30
    rules = list(load_rules(RULES))
    false_positives = [(r["title"], e) for _, r in rules for e in events if matches(r, e)]
    assert not false_positives, f"benign events flagged: {false_positives}"


def _write_events(tmp_path, events):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return str(path)


ATTACK = {"Image": "C:\\Windows\\System32\\vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet"}
BENIGN = {"Image": "C:\\Windows\\System32\\ping.exe", "CommandLine": "ping -n 1 example.invalid"}


def test_cli_exit_codes_and_json(tmp_path, capsys):
    attack_file = _write_events(tmp_path, [BENIGN, ATTACK])
    assert cli_main([str(RULES), attack_file, "--format", "json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["events"] == 2
    assert [d["event"] for d in out["detections"]] == [1]
    assert out["detections"][0]["attack"] == ["T1490"]

    clean_file = _write_events(tmp_path, [BENIGN])
    assert cli_main([str(RULES), clean_file]) == 0


def test_cli_min_level_filters_rules(tmp_path, capsys):
    path = _write_events(tmp_path, [{"Image": "C:\\Windows\\System32\\schtasks.exe",
                                     "CommandLine": "schtasks.exe /create /tn x /tr calc.exe"}])
    assert cli_main([str(RULES), path, "--min-level", "medium"]) == 1  # schtasks rule is medium
    capsys.readouterr()
    assert cli_main([str(RULES), path, "--min-level", "high"]) == 0


def test_navigator_layer_shape():
    layer = build_layer(RULES)
    assert layer["domain"] == "enterprise-attack"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1490", "T1003.001", "T1611", "T1548.001"} <= ids
    assert all(t["score"] >= 1 for t in layer["techniques"])
    # certutil has two rules but each maps to a different technique; T1059.004 is shared by three Linux rules
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores["T1059.004"] == 3

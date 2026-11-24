"""Replay EVTX files through the Sigma rules and report which rules fire where.

Usage (treat the dataset as untrusted data; -I keeps Python from importing from it):
    python -I scripts/replay_evtx.py <dir-with-evtx-files> [--json out.json]

Only process-creation events are evaluated: Sysmon EventID 1 and Security EventID 4688.
Their fields are mapped to Sigma names (Image, CommandLine, ParentImage).

IMPORTANT: a sample collection of attacks can only tell you *recall-style* information
(did a rule fire on activity that it targets?). It says nothing about the false-positive
rate, because it contains no representative benign baseline.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root (our code)

from evtx import PyEvtxParser  # noqa: E402

from detlab.engine import load_rules, matches  # noqa: E402


def _event_id(system: dict) -> str:
    raw = system.get("EventID")
    return str(raw.get("#text") if isinstance(raw, dict) else raw)


def process_events(path: Path):
    """Yield (record_number, sigma_event) for each process-creation record in the file."""
    for record in PyEvtxParser(str(path)).records_json():
        try:
            event = json.loads(record["data"])["Event"]
            system, data = event["System"], event.get("EventData")
        except (KeyError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        eid, channel = _event_id(system), system.get("Channel") or ""
        if eid == "1" and "Sysmon" in channel:
            yield record["event_record_id"], {
                "Image": data.get("Image"),
                "CommandLine": data.get("CommandLine"),
                "ParentImage": data.get("ParentImage"),
            }
        elif eid == "4688" and channel == "Security":
            yield record["event_record_id"], {
                "Image": data.get("NewProcessName"),
                "CommandLine": data.get("CommandLine"),
                "ParentImage": data.get("ParentProcessName"),
            }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--rules", type=Path, default=Path(__file__).resolve().parent.parent / "rules")
    parser.add_argument("--json", type=Path, help="write full results to this file")
    args = parser.parse_args()

    rules = list(load_rules(args.rules))
    files = sorted(args.directory.rglob("*.evtx"))
    hits = defaultdict(list)
    scanned_files = scanned_events = skipped = 0

    for path in files:
        try:
            events = list(process_events(path))
        except Exception as exc:  # corrupt/unsupported file: count it, keep going
            skipped += 1
            print(f"skip {path.name}: {exc}", file=sys.stderr)
            continue
        if events:
            scanned_files += 1
        scanned_events += len(events)
        for record_id, event in events:
            for rule_path, rule in rules:
                if matches(rule, event):
                    hits[rule["title"]].append({
                        "file": path.relative_to(args.directory).as_posix(),
                        "record": record_id,
                        "image": event["Image"],
                        "command_line": (event["CommandLine"] or "")[:300],
                    })

    print(f"{len(files)} EVTX files, {scanned_files} with process-creation events, "
          f"{scanned_events} such events scanned, {skipped} files skipped\n")
    print(f"{'rule':58} {'events':>7} {'files':>6}")
    for _, rule in rules:
        rows = hits.get(rule["title"], [])
        print(f"{rule['title']:58} {len(rows):>7} {len({r['file'] for r in rows}):>6}")

    if args.json:
        args.json.write_text(json.dumps({
            "files": len(files), "files_with_process_events": scanned_files,
            "process_events": scanned_events, "skipped": skipped, "hits": hits,
        }, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

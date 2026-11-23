# 🛡️ Detection Engineering Lab

[![CI](https://github.com/mani17S/detection-engineering-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/mani17S/detection-engineering-lab/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

A small, **test-driven** collection of [Sigma](https://sigmahq.io) detection rules for Windows process-creation telemetry (Sysmon event 1 / Windows 4688), mapped to MITRE ATT&CK.

Every rule ships with **attack events that must fire** and **benign look-alikes that must not**, and CI fails if either breaks. The goal is to treat detections like code: reviewed, tested and measurable, not copy-pasted and hoped for.

> **Defensive use only.** Rules describe behaviour to *detect*. Sample events use placeholder domains (`example.invalid`) and contain no working payloads.

## Rules

| Tactic | Technique | Rule | Level | File |
|---|---|---|---|---|
| command and control | T1105 | Certutil Used to Download a File | high | `rules/windows/proc_creation_certutil_download.yml` |
| credential access | T1003.001 | LSASS Memory Dump via comsvcs or ProcDump | high | `rules/windows/proc_creation_lsass_dump_tools.yml` |
| execution | T1204.002, T1059 | Office Application Spawning Script or Shell Interpreter | high | `rules/windows/proc_creation_office_spawns_shell.yml` |
| execution, defense evasion | T1059.001, T1027 | PowerShell Encoded Command Execution | medium | `rules/windows/proc_creation_powershell_encoded_command.yml` |
| impact | T1490 | Volume Shadow Copy Deletion | high | `rules/windows/proc_creation_shadow_copy_deletion.yml` |
| persistence, execution | T1053.005 | Scheduled Task Created via schtasks | medium | `rules/windows/proc_creation_schtasks_create.yml` |

Regenerate this table with `python -m detlab.coverage rules`.

## Quick start

```bash
git clone https://github.com/mani17S/detection-engineering-lab.git
cd detection-engineering-lab
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

pytest -q                                   # run all rule + engine tests
python -m detlab rules my_events.jsonl      # scan your own JSON-lines events
```

Example output:

```
event #0: [HIGH] Certutil Used to Download a File
event #6: [MEDIUM] PowerShell Encoded Command Execution
2 detection(s) across 12 event(s) using 6 rule(s)
```

Exit code is `1` when something is detected, so it can gate a pipeline.

## How a rule is tested

```
rules/windows/<name>.yml        the detection
tests/events/<name>.json        { "positive": [...must match], "negative": [...must NOT match] }
tests/test_rules.py             metadata gates + behavioural tests for every rule
tests/test_engine.py            unit tests for the evaluator
```

`test_rules.py` also enforces: all required Sigma fields, a valid unique UUID, a valid severity, at least one ATT&CK technique tag, and at least one positive **and** one negative event per rule.

### Adding a rule

1. Create `rules/<platform>/<name>.yml` (copy an existing one).
2. Add `tests/events/<name>.json` with real-world-shaped positives and *tricky* negatives (same binary, benign arguments).
3. `pytest -q` until green, then open a PR. CI runs the same checks.

## The evaluator (`detlab/`)

A ~150-line Sigma-subset evaluator so rules can be unit-tested without a SIEM. It supports `contains` / `startswith` / `endswith` / `all` modifiers, wildcards, lists, and conditions with `and`/`or`/`not`/parentheses/`1 of x*`/`all of them`. It is **case-insensitive**, like most Sigma backends.

It deliberately does **not** support regex, CIDR, base64 modifiers, aggregations or correlation. For production, convert rules with [sigma-cli / pySigma](https://github.com/SigmaHQ/pySigma) to your SIEM's query language; this repo's evaluator exists to test logic, not replace those tools.

## Limitations (read before trusting these)

- **Tested on hand-written events, not real telemetry.** Passing tests shows the logic does what I intended, not that it has a good false-positive rate in your environment.
- **Command-line rules are evadable** (renamed binaries, different flag spellings, obfuscation). They are tripwires for common tradecraft, not complete coverage.
- `status: experimental` on every rule, on purpose: none has been validated against production data.
- Severity levels are my starting point; tune them to your environment.

## Roadmap

- [ ] Rules for Linux auditd and container runtime events (building on [DockerScape](https://github.com/mani17S/DockerScape))
- [ ] Replay public datasets (e.g. EVTX samples) through the rules and record true/false-positive counts
- [ ] Convert to a SIEM query (via pySigma) and validate in a home-lab Wazuh/Elastic stack
- [ ] Sigma regex and `count()` support in the evaluator, with tests

## License

MIT, see [LICENSE](LICENSE).

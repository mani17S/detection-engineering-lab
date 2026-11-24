# 🛡️ Detection Engineering Lab

[![CI](https://github.com/mani17S/detection-engineering-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/mani17S/detection-engineering-lab/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-2.0.0-informational)

**Detections treated as code.** Twelve [Sigma](https://sigmahq.io) rules for Windows and Linux/container process telemetry, mapped to MITRE ATT&CK. Every rule ships with attack events that must fire and benign look-alikes that must not, and CI fails if either breaks. A small evaluator lets you test, scan logs and export ATT&CK coverage without a SIEM.

> **Defensive use only.** Rules describe behaviour to *detect*. Sample events use placeholder domains and reserved IPs, and contain no working payloads.

## What's new in v2

- **7 → 12 rules:** five new Linux/container rules (reverse shell, download-and-run, base64-to-shell, container-escape tooling, setuid backdoor), tied to my [DockerScape](https://github.com/mani17S/DockerScape) container-escape lab.
- **Harder to evade:** the new `windash` modifier makes flag rules match `-enc`, `/enc` and Unicode-dash variants; regex (`re`) support added.
- **Real-data validation:** replayed against 278 public Windows attack samples with every hit and miss reviewed ([results](docs/REPLAY_RESULTS.md)).
- **Tooling:** CLI with `--min-level` and `--format json`, and an **ATT&CK Navigator layer** export.
- **False-positive guard:** a benign-events regression test, plus a CI matrix for Python 3.10–3.13.

See the [CHANGELOG](CHANGELOG.md).

## Rules

### Windows (Sysmon event 1 / Security 4688)

| Tactic | Technique | Rule | Level |
|---|---|---|---|
| command and control | T1105 | Certutil Used to Download a File | high |
| credential access | T1003.001 | LSASS Memory Dump via comsvcs or ProcDump | high |
| defense evasion | T1140 | Certutil Used to Encode or Decode a File | medium |
| execution | T1204.002, T1059 | Office Application Spawning Script or Shell Interpreter | high |
| execution, defense evasion | T1059.001, T1027 | PowerShell Encoded Command Execution | medium |
| impact | T1490 | Volume Shadow Copy Deletion | high |
| persistence, execution | T1053.005 | Scheduled Task Created via schtasks | medium |

### Linux / containers (process creation)

| Tactic | Technique | Rule | Level |
|---|---|---|---|
| command and control, execution | T1105, T1059.004 | Remote Script Downloaded and Piped to a Shell | medium |
| defense evasion, execution | T1140, T1059.004 | Base64-Decoded Content Piped to a Shell | high |
| execution | T1059.004 | Bash Reverse Shell via /dev/tcp | high |
| privilege escalation | T1611 | Container Escape Indicators (Privileged Run, Root Mount, nsenter PID 1) | high |
| privilege escalation, persistence | T1548.001 | SetUID Bit Added to a File | medium |

Full table with file paths: [docs/ATTACK_COVERAGE.md](docs/ATTACK_COVERAGE.md). Navigator layer: [docs/attack-navigator-layer.json](docs/attack-navigator-layer.json) (open it with *Open Existing Layer* in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)).

## Quick start

```bash
git clone https://github.com/mani17S/detection-engineering-lab.git
cd detection-engineering-lab
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

pytest -q                                            # 49 tests across rules, engine, CLI, benign guard
python -m detlab rules examples/sample_events.jsonl  # scan JSON-lines events (try your own)
python -m detlab rules examples/sample_events.jsonl --min-level high --format json
python -m detlab.navigator rules > layer.json        # ATT&CK Navigator coverage layer
python -m detlab.coverage rules                      # markdown coverage table
```

Example scan of the bundled sample (`examples/sample_events.jsonl`, 4 benign + 4 attack events):

```
$ python -m detlab rules examples/sample_events.jsonl
event #1: [HIGH] Certutil Used to Download a File  (T1105)
event #3: [MEDIUM] Remote Script Downloaded and Piped to a Shell  (T1105, T1059.004)
event #5: [MEDIUM] PowerShell Encoded Command Execution  (T1059.001, T1027)
event #6: [HIGH] Container Escape Indicators (Privileged Run, Root Mount, nsenter PID 1)  (T1611)
4 detection(s) across 8 event(s) using 12 rule(s)
```

Exit code is `1` when something is detected, so the scanner can gate a pipeline. Events are flat JSON objects with Sigma field names (`Image`, `CommandLine`, `ParentImage`).

## How detections are tested

| Layer | What it proves | Where |
|---|---|---|
| **Rule metadata** | Valid Sigma fields, unique UUID, severity, ATT&CK tag | `tests/test_rules.py` |
| **Positive / negative events** | Each rule fires on attack events and stays quiet on tricky look-alikes (same binary, benign arguments) | `tests/events/<rule>.json` |
| **Benign regression set** | 34 everyday admin commands trigger **no** rule | `tests/benign/benign_events.json` |
| **Engine unit tests** | The evaluator itself (conditions, modifiers, `windash`, regex) | `tests/test_engine*.py` |
| **Replay on real attack logs** | Rules fire on recorded attacker activity (Windows only) | `scripts/replay_evtx.py`, [results](docs/REPLAY_RESULTS.md) |

### Adding a rule

1. Create `rules/<platform>/<name>.yml` (copy a similar one).
2. Add `tests/events/<name>.json` with realistic positives and *tricky* negatives.
3. Run `pytest -q` until green. See [CONTRIBUTING.md](CONTRIBUTING.md).

## The evaluator (`detlab/`)

A ~170-line Sigma-subset evaluator so rules can be unit-tested without a SIEM. It supports `contains` / `startswith` / `endswith` / `re` / `windash` / `all` modifiers, `*` wildcards, value lists, and conditions with `and` / `or` / `not` / parentheses / `1 of x*` / `all of them`. Matching is case-insensitive, like most Sigma backends.

It deliberately does **not** support CIDR, base64 modifiers, aggregations (`count() by`), temporal correlation or field mappings. For production, convert rules with [sigma-cli / pySigma](https://github.com/SigmaHQ/pySigma) to your SIEM's query language; this evaluator exists to *test logic*, not replace those tools.

## Limitations (read before trusting these)

- **Unit tests use hand-written events.** Passing them shows the logic does what I intended, not that it has a good false-positive rate in your environment. The benign set is also hand-written: it guards against obvious regressions, nothing more.
- **Replay covers Windows only**, on lab-recorded attack samples (not production telemetry), and I tuned two rules after seeing misses there, so those numbers are optimistic. The **Linux rules have not been replayed against real logs**; they are unit-tested only.
- **No false-positive rate has been measured.** `schtasks /create` in particular will be noisy.
- **Command-line rules are evadable** (renamed binaries, obfuscation, other tools). They are tripwires for common tradecraft, not complete coverage.
- Every rule is `status: experimental` on purpose; severities are my starting point.

## Roadmap

- [x] Linux/container rules ([DockerScape](https://github.com/mani17S/DockerScape) tie-in)
- [x] Replay of public EVTX attack samples with hit/miss review
- [ ] Replay a benign baseline to measure false positives
- [ ] Replay Linux auditd/Falco data through the Linux rules
- [ ] Convert via pySigma and validate in a home-lab Wazuh/Elastic stack
- [ ] Parent-process and path context to cut `schtasks` noise

## License

MIT, see [LICENSE](LICENSE).

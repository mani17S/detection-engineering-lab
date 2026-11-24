# Changelog

All notable changes to this project. Format follows [Keep a Changelog](https://keepachangelog.com/);
versions follow [SemVer](https://semver.org/).

## [2.1.0] - 2026-11-24

### Added
- Rule `LSASS Accessed by Code Calling Minidump Libraries` (Sysmon event 10, `process_access`), keyed on
  `dbgcore.dll`/`dbghelp.dll` in the call trace. Replayed on public samples: 7 of 28 LSASS-access events flagged;
  misses documented in `docs/REPLAY_RESULTS.md`.
- Case study `docs/case-studies/comsvcs-minidump.md`.
- Replay tool support for Sysmon event 10; per-category rule matching.
- Benign process-access events in the regression set.

### Changed
- The comsvcs `MiniDump` command-line rule also matches the ordinal form (`#24`, `#+000024`).

## [2.0.1] - 2026-11-24

### Fixed
- CI: the "coverage docs are up to date" check compared the generated table against the whole file
  including its header, so it failed on every run. It now compares the table only. No rule or engine changes.

## [2.0.0] - 2026-11-24

### Added
- Five Linux/container rules: bash `/dev/tcp` reverse shell, download piped to a shell, base64-decoded
  content piped to a shell, container-escape indicators (privileged run, root mount, `nsenter` to PID 1),
  setuid bit set. Each has positive and negative test events.
- Evaluator modifiers: `re` (regex) and `windash` (`-flag` also matches `/flag` and Unicode dashes).
- CLI options `--min-level` and `--format json`.
- `python -m detlab.navigator`: export an ATT&CK Navigator layer. Generated layer and coverage table in `docs/`.
- Benign-events regression test (`tests/benign/benign_events.json`).
- `CONTRIBUTING.md`, `pyproject.toml`, CI test matrix for Python 3.10-3.13.

### Changed
- Flag-matching Windows rules (encoded PowerShell, certutil download and encode/decode, schtasks create) now use
  `windash`, closing a trivial `/enc` vs `-enc` evasion. New attack variants added to their test events.
- README rewritten; limitations section expanded (Linux rules are not replay-validated).

## [1.0.0] - 2026-11-24 (initial, unpublished)

- Six Windows rules, later seven, with test events, a Sigma-subset evaluator, CLI, CI.
- EVTX replay script and results on 278 public attack samples; miss review led to PPLdump coverage
  in the LSASS rule and a new certutil encode/decode rule (T1140).

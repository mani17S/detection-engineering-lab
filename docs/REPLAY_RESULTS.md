# Replay results: public attack samples

Rules were replayed against [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`, GPL-3.0; **not redistributed here**) using
`scripts/replay_evtx.py`. Only process-creation events are evaluated (Sysmon EID 1, Security EID 4688).

```bash
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
git -C EVTX-ATTACK-SAMPLES checkout 4ceed2f4706daf601c212a8f91c113dd85349a2c
python -I scripts/replay_evtx.py EVTX-ATTACK-SAMPLES --json results.json
```

## Corpus

| | |
|---|---|
| EVTX files | 278 |
| Files containing process-creation events | 153 |
| Process-creation events scanned | 1,533 |
| Files skipped (parse error) | 0 |

## Detections

| Rule | Events | Files |
|---|---:|---:|
| Scheduled Task Created via schtasks | 7 | 6 |
| LSASS Memory Dump via comsvcs or ProcDump | 3 | 3 |
| Certutil Used to Download a File | 1 | 1 |
| Office Application Spawning Script or Shell Interpreter | 1 | 1 |
| PowerShell Encoded Command Execution | 1 | 1 |
| Volume Shadow Copy Deletion | 1 | 1 |
| **Total** | **14** | |

I read every one of the 14 hits. All were genuine attack activity from the labelled samples, for
example `rundll32 comsvcs.dll, MiniDump <pid> ... full`, `vssadmin.exe delete shadows /all /quiet`
and `certutil -urlcache -split -f https://...`. One (Office rule) is a `cmd /c ... del wwlib.dll` spawned
from a Word DLL side-loading sample, which I counted as a true positive.

## What this does and does not show

- **Shows:** each rule fires on real recorded attack activity for the behaviour it targets, not only
  on events I wrote myself.
- **Does not show a false-positive rate.** The corpus contains attacks, not a representative benign
  baseline, so nothing here measures noise. `schtasks /create` in particular will be noisy in real
  environments.
- **Does not show recall.** The corpus is not labelled per event; I only checked misses for the
  behaviours these rules target (below).
- **Tuned on this data.** I added `ppldump.exe` to the LSASS rule *after* seeing it missed here
  (`ppldump.exe -v lsass lsass.dmp` was in the corpus). Treat results on this dataset as optimistic;
  the honest next test is a different dataset.

## Misses reviewed

I searched all process-creation events for keywords related to each rule (`certutil`, `lsass`,
`procdump`, `vssadmin`, `shadowcopy`, `schtasks`, `comsvcs`, encoded-command flags) and examined
every event that no rule matched.

| Unmatched activity | Verdict |
|---|---|
| `ppldump.exe -v lsass ...`, `ppldump.exe -p lsass.exe ...` | **Real gap, fixed** (added `ppldump.exe`; test events added) |
| `cmd /c "<tool> ..."` wrapper lines | Not a gap: the child process event was matched; the wrapper only duplicates it |
| `vssadmin create shadow`, `wmic shadowcopy call create`, `vssadmin list shadows` | Correct non-detections (not deletion) |
| `schtasks /run`, `/delete` | Correct non-detections (not creation) |
| `certutil -encode` / `-decode` | Out of scope for the download rule (different technique, T1140); candidate for a new rule |
| `procdump.exe -ma lsass.exe` seen only inside a `cmd /c` wrapper | Possible gap if the child process event was not logged in that sample; not confirmed |

## Next

- Replay a **benign** Windows baseline to estimate false positives.
- Add a `certutil -encode/-decode` rule (T1140) and tune `schtasks /create` (e.g. by parent or task path).

# Case study: process-memory dump via `rundll32 comsvcs.dll, MiniDump`

An analyst-style write-up of one public attack sample, covering what happened, what the logs prove, what they do not, how this repo's detections performed, and what a responder would do.

> **Scope and honesty notes**
> - **Source:** a public lab sample, [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (commit `4ceed2f`, GPL-3.0, not redistributed here), file `Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx`. Host `MSEDGEWIN10`, a test VM, 2019-08-30 UTC. This is **not a real incident**.
> - **The dumped process is `notepad.exe`, not LSASS.** The sample demonstrates the technique with a harmless stand-in target. Everything below about LSASS is about what the *same technique* would do against `lsass.exe`.
> - Only what appears in the log is stated as fact. Inferences are labelled as such.

## Summary

A script host (`cscript.exe`) running `c:\ProgramData\memdump.vbs` caused `rundll32.exe` to call the Windows-supplied `comsvcs.dll` export `MiniDump` against another process, writing a full memory dump to `C:\Windows\System32\notepad.bin`. The whole chain took about 0.6 seconds and ran at **High** integrity as `MSEDGEWIN10\IEUser`. Pointed at `lsass.exe`, the same chain yields a file from which account credentials can be extracted offline.

## Timeline (UTC, from Sysmon)

| Time | Sysmon event | What the log shows |
|---|---|---|
| 12:54:07.823 | 1 Process create | `cscript c:\ProgramData\memdump.vbs notepad.exe` (PID 2576), parent `cmd.exe`, user `IEUser`, integrity High |
| 12:54:08.079 / .127 | 7 Image load | Two image-load events for `cscript.exe` |
| 12:54:08.331 | 1 Process create | `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin full` (PID 2888), **parent `wmiprvse.exe -secured -Embedding`** |
| 12:54:08.392 | 11 File create | `rundll32.exe` creates `C:\Windows\System32\notepad.bin` |
| 12:54:08.424 | 10 Process access | `rundll32.exe` (2888) opens `notepad.exe` (4868) with `GrantedAccess 0x1fffff`; call trace passes through `dbgcore.dll` then `comsvcs.dll` |

(Event order reflects when each event was logged.)

## What the evidence shows

1. **Argument 1 is the target PID, argument 2 the output file, `full` requests a complete dump.** This is the documented `MiniDump` calling convention for `comsvcs.dll`.
2. **`0x1fffff` is `PROCESS_ALL_ACCESS`**, far more than a benign tool normally needs.
3. **`dbgcore.dll` in the call trace is the tell.** `MiniDumpWriteDump` lives in `dbgcore.dll`/`dbghelp.dll`; seeing them on the stack of a process opening another process is a behavioural signature of a dump in progress, independent of command-line text.
4. **The dump was written under `C:\Windows\System32\` with a `.bin` extension.** This blends with system content and avoids the obvious `.dmp` name (observation; intent is not provable from the log).
5. **High integrity.** Opening `lsass.exe` for this kind of access normally requires administrative rights and debug privilege, so this technique implies the attacker already holds admin on the host.

## Inferences (not proven by this log)

- **WMI was likely used to launch `rundll32`.** A process whose parent is `wmiprvse.exe -secured -Embedding` is how WMI-created processes appear, and `cscript` is the likeliest launcher. The script's contents are **not** in this log, so the exact API call cannot be confirmed.
- **Intent to evade parent-based detection.** Spawning via WMI breaks the obvious `cscript -> rundll32` parent-child link. Plausible, but a design choice I am inferring, not observing.

## ATT&CK mapping

| Technique | Basis |
|---|---|
| **T1003.001** OS Credential Dumping: LSASS Memory | Technique demonstrated (stand-in target: `notepad.exe`) |
| **T1218.011** System Binary Proxy Execution: Rundll32 | Observed |
| **T1059.005** Command and Scripting Interpreter: Visual Basic | Observed (`cscript` running a `.vbs`) |
| **T1047** Windows Management Instrumentation | Inferred from the `wmiprvse.exe` parent |

## How this repo's detections performed

| Detection | Result on this sample |
|---|---|
| [`LSASS Memory Dump via comsvcs or ProcDump`](../../rules/windows/proc_creation_lsass_dump_tools.yml) (process creation) | **Fires** on the `rundll32 ... comsvcs.dll, MiniDump` event (confirmed by replay) |
| [`LSASS Accessed by Code Calling Minidump Libraries`](../../rules/windows/proc_access_lsass_minidump_libraries.yml) (process access) | **Does not fire here, correctly**, because it requires `TargetImage` = `lsass.exe` and this sample targets `notepad.exe`. It keys on exactly the `dbgcore.dll` call-trace pattern seen above. On real LSASS-dump samples it fires, see [REPLAY_RESULTS.md](../REPLAY_RESULTS.md) |
| Any rule for `cscript` running scripts from `C:\ProgramData`, or `rundll32` spawned by `wmiprvse.exe` | **None exist yet.** Both would be useful precursors; neither has been written or tested |

### Gap found while writing this, and the fix

The command-line rule originally required the text `minidump`. `MiniDump` is exported from `comsvcs.dll` as **ordinal 24**, so `rundll32 comsvcs.dll, #24 <pid> <file> full` performs the same dump without that word. The rule now also matches `#24` and `#+000024`. This variant comes from public documentation of the technique, so its tests are **hand-written**, not drawn from this sample. It also illustrates why the behavioural (process-access) rule matters: it does not care how the function was named.

## If this were real: response outline

1. **Contain:** isolate the host from the network; do not reboot (memory evidence).
2. **Preserve:** collect the dump file (`notepad.bin` here), the script `c:\ProgramData\memdump.vbs`, the relevant Sysmon/Security logs, and a memory image if possible. Hash everything.
3. **Scope:** assume every credential in LSASS at the time is exposed (all interactive and service logons on that host). Identify those accounts and where else they are valid.
4. **Eradicate and recover:** reset exposed credentials (and Kerberos secrets if a domain controller was involved); find how the attacker obtained admin, since this technique requires it.
5. **Hunt:** search fleet-wide for `comsvcs.dll` with `MiniDump`/`#24`, for `dbgcore.dll`/`dbghelp.dll` in call traces targeting `lsass.exe`, for new `.bin`/`.dmp` files in unusual paths, and for `wmiprvse.exe`-parented `rundll32.exe`.
6. **Harden:** enable LSA protection (RunAsPPL) and Credential Guard, enable the "Block credential stealing from the Windows local security authority subsystem" ASR rule, and restrict who holds debug privilege.

## Limitations of this analysis

- One lab sample, one host; no network, authentication or EDR telemetry.
- The VBScript is not captured, so the launch mechanism is inferred.
- The dumped process is `notepad.exe`; real-world behaviour against LSASS (including protected-process settings) is described, not observed here.

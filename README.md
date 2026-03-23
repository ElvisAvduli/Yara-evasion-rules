# YARA Anti-Analysis Ruleset

A focused, well-structured YARA ruleset for detecting **anti-debugging**, **anti-VM**, **anti-sandbox**, and **code injection** techniques commonly found in malware and evasive binaries.

Designed to be used by malware analysts, threat hunters, and reverse engineers as a detection aid during static analysis or as part of an automated triage pipeline.

---

## Contents

```
YaraRules.yar   — Main ruleset (all categories in one file)
```

---

## Rule Categories

### Debugger Detection (`DebuggerCheck`, `DebuggerPattern`, `DebuggerTiming`)
Identifies binaries that probe for the presence of a debugger using:
- Win32 API checks (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`)
- Native NT API queries (`NtQueryInformationProcess`, `NtSetInformationProcess`)
- PEB flag inspection (`BeingDebugged`, `NtGlobalFlags`) via direct memory access (FS/GS segment patterns for x86/x64)
- Timing-based detection (RDTSC, RDTSCP, `QueryPerformanceCounter`, `GetTickCount`)
- Exception-based tricks (`SetUnhandledExceptionFilter`, `RaiseException`, `GenerateConsoleCtrlEvent`)
- Software breakpoint clusters (INT3 / `0xCC`), INT 2D, and the ICE breakpoint (`0xF1`)

### Debugger Hiding (`DebuggerHiding`)
Detects attempts to actively hide from or manipulate a debugger:
- `NtSetInformationThread` — hides threads from the debugger
- `DebugActiveProcess` / `DebugSetProcessKillOnExit` — debugger attachment/detachment abuse

### SEH Manipulation (`SEH`)
Flags use of Structured Exception Handling mechanisms often abused for anti-debug purposes:
- MSVC SEH v3 / v4 runtime handlers
- Vectored Exception Handlers (`AddVectoredExceptionHandler`)
- VBA exception handlers

### Virtual Machine Detection (`AntiVM`)
Catches environment fingerprinting targeting common hypervisors:
- Registry key checks for VMware, VirtualBox, Hyper-V, Parallels
- VM-specific driver and device names (`vboxhook.dll`, `vmhgfs.sys`, etc.)
- CPUID hypervisor bit inspection (leaf 0x1, ECX bit 31)
- IDT base address check via SIDT (Red Pill technique)
- SLDT-based No Pill technique
- VM-associated MAC address prefixes (`00-0C-29`, `08-00-27`, etc.)
- Accelerated sleep detection (`GetTickCount` + `Sleep` delta)

### Sandbox Evasion (`AntiSandbox`)
Identifies techniques used to detect or outlast sandbox environments:
- User interaction checks (`GetCursorPos`, `GetForegroundWindow`, `GetAsyncKeyState`)
- Known sandbox username strings (`sandbox`, `cuckoo`, `TEQUILABOOMBOOM`, etc.)
- Analysis tool enumeration (OllyDbg, x64dbg, Wireshark, Process Hacker, Fiddler, etc.)
- Process enumeration (`CreateToolhelp32Snapshot`, `Process32First/Next`)
- System uptime checks (`GetTickCount`)
- Disk size checks (`GetDiskFreeSpaceEx` + `DeviceIoControl`)
- Native stall via `NtDelayExecution` / `ZwDelayExecution`
- WMI environment queries (`Win32_ComputerSystem`, `Win32_BIOS`, `Win32_VideoController`)

### Code Injection (`Injection`)
Detects common process injection patterns:
- Classic injection (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`)
- APC injection (`QueueUserAPC` + `OpenThread`)
- Native thread injection (`NtCreateThread`, `NtCreateThreadEx`, `RtlCreateUserThread`)
- Process hollowing (`NtUnmapViewOfSection` + context manipulation)
- Reflective DLL loading (`ReflectiveLoader` string / raw bytes)

### Aggregate / Correlation Rules (`AntiAnalysis`)
High-confidence compound rules that fire when multiple evasion signals are present simultaneously:

| Rule | Trigger | Weight |
|---|---|---|
| `AntiDebug__Heavy_Presence` | 4+ distinct anti-debug APIs | 5 |
| `AntiVM_AntiDebug__Combined` | 2+ anti-debug + 1+ anti-VM indicator | 7 |
| `AntiAnalysis__PE_Anomalies` | Zero imports + writable `.text` section | 4 |

---

## Rule Tags

Each rule is tagged for easy filtering:

| Tag | Meaning |
|---|---|
| `AntiDebug` | Debugger detection or evasion |
| `AntiVM` | Virtual machine detection |
| `AntiSandbox` | Sandbox detection or evasion |
| `Injection` | Code / process injection |
| `AntiAnalysis` | Aggregate high-confidence evasion signal |
| `DebuggerCheck` | API-based debugger presence check |
| `DebuggerPattern` | Byte-pattern / instruction-level trick |
| `DebuggerTiming` | Timing-based detection |
| `DebuggerHiding` | Active hiding from debugger |
| `DebuggerException` | Exception-based anti-debug |
| `SEH` | Structured Exception Handling abuse |
| `ThreadControl` | Thread context manipulation |

---

## Weight System

Every rule carries a `weight` metadata field indicating its confidence and severity:

| Weight | Meaning |
|---|---|
| 1 | Low — common API, possible legitimate use |
| 2 | Medium — suspicious in context |
| 3 | High — strong indicator of evasive intent |
| 4 | Very High — rare outside malicious code |
| 5–7 | Critical — aggregate rule, multiple signals confirmed |

Use weights to prioritize findings during triage or to build a scoring pipeline.

---

## Usage

### Basic scan
```bash
yara YaraRules.yar /path/to/sample.exe
```

### Scan a directory recursively
```bash
yara -r YaraRules.yar /path/to/samples/
```

### Filter by tag
```bash
yara --tag AntiVM YaraRules.yar sample.exe
```

### Output only rule names (no metadata)
```bash
yara -n YaraRules.yar sample.exe
```

### Use with `yarax` or integration frameworks
The ruleset is compatible with any YARA 4.x-compatible engine, including:
- [yaralyzer](https://github.com/michelcrypt4d4mus/yaralyzer)
- [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2)
- [Cuckoo Sandbox](https://cuckoosandbox.org/)
- [Assemblyline](https://cybercentrecanada.github.io/assemblyline4_docs/)

---

## Requirements

- [YARA](https://github.com/VirusTotal/yara) **4.0+**
- The `pe` module is required (included by default in standard YARA builds)

---

## Known Limitations

- `DebuggerPattern__ICE` matches on a single byte (`0xF1`) and **will produce false positives**. Use with caution and consider pairing it with other signals before acting on it alone.
- String-based rules (API names) may miss statically linked or obfuscated binaries where import names are not present as plaintext.
- This ruleset targets **Windows PE binaries** primarily. Rules referencing the `pe` module will not apply to other formats.

---

## Contributing

Contributions are welcome. If you'd like to add rules, please follow the existing conventions:

- Use descriptive rule names in the format `Category__Technique`
- Include `description` and `weight` in the `meta` block
- Tag rules appropriately
- Test against both positive samples and benign binaries to minimize false positives

---

## References & Further Reading

- [The Ultimate Anti-Reversing Reference — Peter Ferrie](https://anti-reversing.com/Downloads/Anti-Reversing/The_Ultimate_Anti-Reversing_Reference.pdf)
- [YARA Documentation](https://yara.readthedocs.io/)
- [Unprotect Project — Anti-Analysis Techniques](https://unprotect.it/)
- [Al-Khaser — Anti-Analysis PoC Collection](https://github.com/LordNoteworthy/al-khaser)

---

## License

MIT License — see `LICENSE` for details.

import "pe"

////////////////////////////////////////////////////////////////////////////////
// DEBUGGER DETECTION — API Checks
////////////////////////////////////////////////////////////////////////////////

rule DebuggerCheck__API : AntiDebug DebuggerCheck {
    meta:
        description = "Detects use of IsDebuggerPresent API"
        weight      = 1
        reference   = "https://anti-reversing.com/Downloads/Anti-Reversing/The_Ultimate_Anti-Reversing_Reference.pdf"
    strings:
        $s = "IsDebuggerPresent"
    condition:
        $s
}

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck {
    meta:
        description = "Detects CheckRemoteDebuggerPresent API"
        weight      = 1
    strings:
        $s = "CheckRemoteDebuggerPresent"
    condition:
        $s
}

rule DebuggerCheck__QueryInfo : AntiDebug DebuggerCheck {
    meta:
        description = "Detects NtQueryInformationProcess — used to query debug port/flags"
        weight      = 2
    strings:
        $a = "QueryInformationProcess"
        $b = "NtQueryInformationProcess"
        $c = "ZwQueryInformationProcess"
    condition:
        any of them
}

rule DebuggerCheck__DrWatson : AntiDebug DebuggerCheck {
    meta:
        description = "Dr. Watson / Windows error reporting hook check"
        weight      = 1
    strings:
        $s = "__invoke__watson"
    condition:
        $s
}

rule DebuggerCheck__NtSetInfo : AntiDebug DebuggerCheck {
    meta:
        description = "NtSetInformationProcess — used to remove debug object handle"
        weight      = 2
    strings:
        $a = "NtSetInformationProcess"
        $b = "ZwSetInformationProcess"
    condition:
        any of them
}

rule DebuggerCheck__OpenProcess : AntiDebug DebuggerCheck {
    meta:
        description = "OpenProcess on own PID — classic self-debug check"
        weight      = 1
    strings:
        $a = "OpenProcess"
        $b = "GetCurrentProcessId"
    condition:
        all of them
}

////////////////////////////////////////////////////////////////////////////////
// DEBUGGER DETECTION — PEB / Global Flags
////////////////////////////////////////////////////////////////////////////////

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck {
    meta:
        description = "PEB.IsDebugged flag check"
        weight      = 1
    strings:
        $s = "IsDebugged"
    condition:
        $s
}

rule DebuggerCheck__GlobalFlags : AntiDebug DebuggerCheck {
    meta:
        description = "NtGlobalFlags check in PEB (heap flags set by debugger)"
        weight      = 2
    strings:
        $s = "NtGlobalFlags"
    condition:
        $s
}

// PEB.NtGlobalFlags accessed directly via FS/GS segment (x86 / x64)
rule DebuggerPattern__PEB_NtGlobalFlags_x86 : AntiDebug DebuggerPattern {
    meta:
        description = "Direct PEB NtGlobalFlags read via FS segment (x86)"
        weight      = 3
    strings:
        // mov eax, fs:[30h]  →  mov eax, [eax+68h]
        $peb  = { 64 A1 30 00 00 00 }
        $flag = { 8B 40 68 }
    condition:
        $peb and $flag
}

rule DebuggerPattern__PEB_BeingDebugged_x86 : AntiDebug DebuggerPattern {
    meta:
        description = "Direct PEB BeingDebugged byte read (x86)"
        weight      = 3
    strings:
        // mov eax, fs:[30h]  ; movzx eax, byte ptr [eax+2]
        $peb  = { 64 A1 30 00 00 00 }
        $flag = { 0F B6 40 02 }
    condition:
        $peb and $flag
}

rule DebuggerPattern__PEB_x64 : AntiDebug DebuggerPattern {
    meta:
        description = "PEB access via GS segment (x64)"
        weight      = 3
    strings:
        // mov rax, gs:[60h]
        $s = { 65 48 8B 04 25 60 00 00 00 }
    condition:
        $s
}

////////////////////////////////////////////////////////////////////////////////
// DEBUGGER HIDING
////////////////////////////////////////////////////////////////////////////////

rule DebuggerHiding__Thread : AntiDebug DebuggerHiding {
    meta:
        description = "NtSetInformationThread — hides thread from debugger"
        weight      = 2
    strings:
        $a = "SetInformationThread"
        $b = "NtSetInformationThread"
        $c = "ZwSetInformationThread"
    condition:
        any of them
}

rule DebuggerHiding__Active : AntiDebug DebuggerHiding {
    meta:
        description = "DebugActiveProcess — attach debugger to another process"
        weight      = 1
    strings:
        $s = "DebugActiveProcess"
    condition:
        $s
}

rule DebuggerHiding__KillOnExit : AntiDebug DebuggerHiding {
    meta:
        description = "DebugSetProcessKillOnExit — detach without killing target"
        weight      = 1
    strings:
        $s = "DebugSetProcessKillOnExit"
    condition:
        $s
}

////////////////////////////////////////////////////////////////////////////////
// DEBUGGER TIMING CHECKS
////////////////////////////////////////////////////////////////////////////////

rule DebuggerTiming__PerformanceCounter : AntiDebug DebuggerTiming {
    meta:
        description = "QueryPerformanceCounter — timing-based debugger detection"
        weight      = 1
    strings:
        $s = "QueryPerformanceCounter"
    condition:
        $s
}

rule DebuggerTiming__Ticks : AntiDebug DebuggerTiming {
    meta:
        description = "GetTickCount / GetTickCount64 — timing checks"
        weight      = 1
    strings:
        $a = "GetTickCount"
        $b = "GetTickCount64"
    condition:
        any of them
}

rule DebuggerTiming__SystemTime : AntiDebug DebuggerTiming {
    meta:
        description = "GetSystemTime / GetLocalTime used for timing delta checks"
        weight      = 1
    strings:
        $a = "GetSystemTime"
        $b = "GetLocalTime"
        $c = "NtQuerySystemTime"
    condition:
        any of them
}

rule DebuggerPattern__RDTSC : AntiDebug DebuggerPattern {
    meta:
        description = "RDTSC instruction — read timestamp counter for timing"
        weight      = 2
    strings:
        $s = { 0F 31 }
    condition:
        $s
}

rule DebuggerPattern__RDTSCP : AntiDebug DebuggerPattern {
    meta:
        description = "RDTSCP instruction (serializing RDTSC)"
        weight      = 2
    strings:
        $s = { 0F 01 F9 }
    condition:
        $s
}

rule DebuggerPattern__CPUID : AntiDebug DebuggerPattern {
    meta:
        description = "CPUID instruction — used to detect hypervisors / timing"
        weight      = 1
    strings:
        $s = { 0F A2 }
    condition:
        $s
}

////////////////////////////////////////////////////////////////////////////////
// EXCEPTION-BASED TRICKS
////////////////////////////////////////////////////////////////////////////////

rule DebuggerException__UnhandledFilter : AntiDebug DebuggerException {
    meta:
        description = "SetUnhandledExceptionFilter — overrides debugger exception handling"
        weight      = 1
    strings:
        $s = "SetUnhandledExceptionFilter"
    condition:
        $s
}

rule DebuggerException__ConsoleCtrl : AntiDebug DebuggerException {
    meta:
        description = "GenerateConsoleCtrlEvent — trigger and catch CTRL+C exception"
        weight      = 1
    strings:
        $s = "GenerateConsoleCtrlEvent"
    condition:
        $s
}

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException {
    meta:
        description = "SetConsoleCtrlHandler — intercept console control signals"
        weight      = 1
    strings:
        $s = "SetConsoleCtrlHandler"
    condition:
        $s
}

rule DebuggerException__RaiseException : AntiDebug DebuggerException {
    meta:
        description = "RaiseException used for SEH-based anti-debug tricks"
        weight      = 1
    strings:
        $s = "RaiseException"
    condition:
        $s
}

rule DebuggerOutput__String : AntiDebug DebuggerOutput {
    meta:
        description = "OutputDebugString — presence check via GetLastError delta"
        weight      = 1
    strings:
        $s = "OutputDebugString"
    condition:
        $s
}

////////////////////////////////////////////////////////////////////////////////
// SEH — Structured Exception Handling
////////////////////////////////////////////////////////////////////////////////

rule SEH__v3 : AntiDebug SEH {
    meta:
        description = "MSVC SEH v3 runtime handlers"
        weight      = 1
    strings:
        $a = "____except__handler3"
        $b = "____local__unwind3"
    condition:
        any of them
}

rule SEH__v4 : AntiDebug SEH {
    meta:
        description = "MSVC SEH v4 runtime handlers (VS 8.0+)"
        weight      = 1
    strings:
        $a = "____except__handler4"
        $b = "____local__unwind4"
        $c = "__XcptFilter"
    condition:
        any of them
}

rule SEH__vba : AntiDebug SEH {
    meta:
        description = "VBA exception handler"
        weight      = 1
    strings:
        $s = "vbaExceptHandler"
    condition:
        $s
}

rule SEH__vectored : AntiDebug SEH {
    meta:
        description = "Vectored Exception Handler registration"
        weight      = 1
    strings:
        $a = "AddVectoredExceptionHandler"
        $b = "RemoveVectoredExceptionHandler"
    condition:
        any of them
}

rule DebuggerPattern__SEH_Saves : AntiDebug DebuggerPattern {
    meta:
        description = "Push FS:[0] — SEH chain save (x86)"
        weight      = 1
    strings:
        $s = { 64 FF 35 00 00 00 00 }
    condition:
        $s
}

rule DebuggerPattern__SEH_Inits : AntiDebug DebuggerPattern {
    meta:
        description = "Install new SEH frame via FS:[0] (x86)"
        weight      = 1
    strings:
        $a = { 64 A3 00 00 00 00 }
        $b = { 64 89 25 00 00 00 00 }
    condition:
        any of them
}

rule DebuggerPattern__INT3 : AntiDebug DebuggerPattern {
    meta:
        description = "Software breakpoint (INT3 / 0xCC) clusters — may indicate self-debugging or breakpoint scanning"
        weight      = 2
    strings:
        // Three or more consecutive INT3 bytes
        $s = { CC CC CC }
    condition:
        #s > 4
}

rule DebuggerPattern__INT2D : AntiDebug DebuggerPattern {
    meta:
        description = "INT 2D — kernel debugger breakpoint / anti-debug trick"
        weight      = 3
    strings:
        $s = { CD 2D }
    condition:
        $s
}

rule DebuggerPattern__ICE : AntiDebug DebuggerPattern {
    meta:
        description = "ICE breakpoint (0xF1) — single-step trap trick"
        weight      = 3
    strings:
        $s = { F1 }
    condition:
        $s
}

////////////////////////////////////////////////////////////////////////////////
// THREAD / CONTEXT MANIPULATION
////////////////////////////////////////////////////////////////////////////////

rule ThreadControl__Context : AntiDebug ThreadControl {
    meta:
        description = "SetThreadContext — used to manipulate execution flow"
        weight      = 1
    strings:
        $a = "SetThreadContext"
        $b = "GetThreadContext"
    condition:
        any of them
}

rule ThreadControl__Suspend : AntiDebug ThreadControl {
    meta:
        description = "SuspendThread / NtSuspendThread — thread freezing"
        weight      = 1
    strings:
        $a = "SuspendThread"
        $b = "NtSuspendThread"
        $c = "ResumeThread"
    condition:
        any of them
}

////////////////////////////////////////////////////////////////////////////////
// VIRTUAL MACHINE DETECTION
////////////////////////////////////////////////////////////////////////////////

rule AntiVM__Registry_VMware : AntiVM {
    meta:
        description = "Registry keys associated with VMware"
        weight      = 3
    strings:
        $a = "VMware" nocase
        $b = "SOFTWARE\\VMware, Inc." nocase
        $c = "VMwareService" nocase
        $d = "VMwareTray" nocase
    condition:
        any of them
}

rule AntiVM__Registry_VBox : AntiVM {
    meta:
        description = "Registry keys associated with VirtualBox"
        weight      = 3
    strings:
        $a = "VirtualBox" nocase
        $b = "VBOX" nocase
        $c = "VBoxService" nocase
        $d = "VBoxTray" nocase
        $e = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase
    condition:
        any of them
}

rule AntiVM__Drivers : AntiVM {
    meta:
        description = "VM-specific driver/device names"
        weight      = 3
    strings:
        $a = "\\\\.\\VBoxMiniRdrDN"
        $b = "\\\\.\\VBoxGuest"
        $c = "\\\\.\\vmci"
        $d = "\\\\.\\HGFS"
        $e = "vmhgfs.sys" nocase
        $f = "vmmouse.sys" nocase
        $g = "vmtoolsd.exe" nocase
        $h = "vboxhook.dll" nocase
    condition:
        any of them
}

rule AntiVM__CPUID_Hypervisor : AntiVM {
    meta:
        description = "CPUID hypervisor bit check — leaf 0x1, ECX bit 31"
        weight      = 3
    strings:
        // CPUID; test ecx, 80000000h
        $a = { 0F A2 F7 C1 00 00 00 80 }
        // CPUID; bt ecx, 1Fh
        $b = { 0F A2 0F BA E1 1F }
    condition:
        any of them
}

rule AntiVM__SIDT_Red_Pill : AntiVM {
    meta:
        description = "SIDT instruction — Red Pill technique to detect VM via IDT base"
        weight      = 3
    strings:
        $s = { 0F 01 ?? }   // SIDT [mem]
    condition:
        $s
}

rule AntiVM__SLDT : AntiVM {
    meta:
        description = "SLDT — used in No Pill VM detection technique"
        weight      = 2
    strings:
        $s = { 0F 00 C0 }  // SLDT eax
    condition:
        $s
}

rule AntiVM__Accelerated_Sleep : AntiVM {
    meta:
        description = "GetTickCount before/after Sleep — detects accelerated sandbox time"
        weight      = 2
    strings:
        $a = "GetTickCount"
        $b = "Sleep"
    condition:
        all of them
}

rule AntiVM__MAC_Vendor : AntiVM {
    meta:
        description = "Checks for VM-associated MAC address prefixes"
        weight      = 2
    strings:
        $vmware = "00-0C-29" nocase
        $vbox   = "08-00-27" nocase
        $msft   = "00-03-FF" nocase   // Hyper-V
        $paral  = "00-1C-42" nocase   // Parallels
    condition:
        any of them
}

////////////////////////////////////////////////////////////////////////////////
// SANDBOX EVASION
////////////////////////////////////////////////////////////////////////////////

rule AntiSandbox__UserInteraction : AntiSandbox {
    meta:
        description = "Checks for user interaction (mouse moves, clicks, foreground window)"
        weight      = 2
    strings:
        $a = "GetCursorPos"
        $b = "GetForegroundWindow"
        $c = "GetAsyncKeyState"
        $d = "BlockInput"
    condition:
        2 of them
}

rule AntiSandbox__Username : AntiSandbox {
    meta:
        description = "Sandbox-associated username strings"
        weight      = 3
    strings:
        $a = "sandbox" nocase
        $b = "malware" nocase
        $c = "virus" nocase
        $d = "cuckoo" nocase
        $e = "TEQUILABOOMBOOM" nocase
        $f = "CurrentUser" nocase
        $g = "schmidti" nocase
    condition:
        any of them
}

rule AntiSandbox__ProcessEnum : AntiSandbox {
    meta:
        description = "Enumerates processes — often used to detect analysis tools"
        weight      = 2
    strings:
        $a = "CreateToolhelp32Snapshot"
        $b = "Process32First"
        $c = "Process32Next"
        $d = "EnumProcesses"
    condition:
        2 of them
}

rule AntiSandbox__KnownAnalysisTools : AntiSandbox {
    meta:
        description = "Strings matching well-known analysis / reversing tools"
        weight      = 3
    strings:
        $a  = "ollydbg.exe"     nocase
        $b  = "x64dbg.exe"      nocase
        $c  = "x32dbg.exe"      nocase
        $d  = "windbg.exe"      nocase
        $e  = "idaq.exe"        nocase
        $f  = "idaq64.exe"      nocase
        $g  = "wireshark.exe"   nocase
        $h  = "procmon.exe"     nocase
        $i  = "procexp.exe"     nocase
        $j  = "processhacker.exe" nocase
        $k  = "fiddler.exe"     nocase
        $l  = "regmon.exe"      nocase
        $m  = "filemon.exe"     nocase
        $n  = "lordpe.exe"      nocase
        $o  = "pestudio.exe"    nocase
        $p  = "autoruns.exe"    nocase
        $q  = "dumpcap.exe"     nocase
    condition:
        any of them
}

rule AntiSandbox__LowUptime : AntiSandbox {
    meta:
        description = "GetTickCount used to check system uptime — sandboxes often have low uptime"
        weight      = 2
    strings:
        $a = "GetTickCount"
        $b = "GetTickCount64"
    condition:
        any of them
}

rule AntiSandbox__Disk_Size : AntiSandbox {
    meta:
        description = "Checks disk size — sandboxes often have small disks"
        weight      = 2
    strings:
        $a = "GetDiskFreeSpaceEx"
        $b = "DeviceIoControl"
    condition:
        all of them
}

rule AntiSandbox__NtDelayExecution : AntiSandbox {
    meta:
        description = "NtDelayExecution — stalling via native sleep to outlast sandbox timeout"
        weight      = 2
    strings:
        $a = "NtDelayExecution"
        $b = "ZwDelayExecution"
    condition:
        any of them
}

rule AntiSandbox__WMI_Query : AntiSandbox {
    meta:
        description = "WMI queries used to fingerprint host environment"
        weight      = 2
    strings:
        $a = "SELECT * FROM Win32_ComputerSystem" nocase
        $b = "SELECT * FROM Win32_BIOS" nocase
        $c = "SELECT * FROM Win32_VideoController" nocase
        $d = "Win32_Processor" nocase
        $e = "WQL" nocase
    condition:
        2 of them
}

////////////////////////////////////////////////////////////////////////////////
// CODE INJECTION INDICATORS
////////////////////////////////////////////////////////////////////////////////

rule Injection__Classic : Injection {
    meta:
        description = "Classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread injection"
        weight      = 3
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        all of them
}

rule Injection__QueueUserAPC : Injection {
    meta:
        description = "APC injection via QueueUserAPC"
        weight      = 3
    strings:
        $a = "QueueUserAPC"
        $b = "OpenThread"
    condition:
        all of them
}

rule Injection__NtCreateThread : Injection {
    meta:
        description = "Native thread creation API used in injection"
        weight      = 3
    strings:
        $a = "NtCreateThread"
        $b = "NtCreateThreadEx"
        $c = "RtlCreateUserThread"
    condition:
        any of them
}

rule Injection__Hollowing : Injection {
    meta:
        description = "Process hollowing — unmaps and replaces PE in remote process"
        weight      = 4
    strings:
        $a = "NtUnmapViewOfSection"
        $b = "ZwUnmapViewOfSection"
        $c = "VirtualAllocEx"
        $d = "WriteProcessMemory"
        $e = "SetThreadContext"
        $f = "ResumeThread"
    condition:
        4 of them
}

rule Injection__ReflectiveDLL : Injection {
    meta:
        description = "Reflective DLL loading — self-loading PE without LoadLibrary"
        weight      = 4
    strings:
        $a = "ReflectiveLoader"
        $b = { 52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72 }  // "ReflectiveLoader" raw
    condition:
        any of them
}

////////////////////////////////////////////////////////////////////////////////
// AGGREGATE / CORRELATION RULES
////////////////////////////////////////////////////////////////////////////////

rule AntiDebug__Heavy_Presence : AntiDebug AntiAnalysis {
    meta:
        description = "Binary uses 4+ distinct anti-debug APIs — strong evasion signal"
        weight      = 5
    strings:
        $a = "IsDebuggerPresent"
        $b = "CheckRemoteDebuggerPresent"
        $c = "QueryInformationProcess"
        $d = "SetInformationThread"
        $e = "NtGlobalFlags"
        $f = "OutputDebugString"
        $g = "SetUnhandledExceptionFilter"
        $h = "QueryPerformanceCounter"
        $i = "GetTickCount"
    condition:
        4 of them
}

rule AntiVM_AntiDebug__Combined : AntiVM AntiDebug AntiAnalysis {
    meta:
        description = "Sample combines both VM detection and anti-debug — high evasion confidence"
        weight      = 7
    strings:
        // Anti-debug
        $dbg1 = "IsDebuggerPresent"
        $dbg2 = "NtGlobalFlags"
        $dbg3 = "SetInformationThread"
        // Anti-VM
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "vboxhook.dll" nocase
    condition:
        2 of ($dbg*) and 1 of ($vm*)
}

rule AntiAnalysis__PE_Anomalies : AntiAnalysis {
    meta:
        description = "PE has no standard imports but uses known evasion strings — packed/obfuscated"
        weight      = 4
    condition:
        pe.number_of_imports == 0 and
        (
            for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].name == ".text" and
                pe.sections[i].characteristics & pe.SECTION_MEM_WRITE
            )
        )
}

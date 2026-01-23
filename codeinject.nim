// NullSec CodeInject - Code Injection Detector
// Nim language security tool demonstrating:
//   - Zero-cost abstractions
//   - Compile-time metaprogramming
//   - Memory safety with manual control
//   - Efficient string handling
//   - Cross-platform compilation
//
// Author: bad-antics
// License: MIT

import std/[os, strformat, strutils, tables, times, json, hashes, sequtils]

const Version = "1.0.0"

# ANSI Colors
const
  Red = "\x1b[31m"
  Green = "\x1b[32m"
  Yellow = "\x1b[33m"
  Cyan = "\x1b[36m"
  Gray = "\x1b[90m"
  Reset = "\x1b[0m"

proc colored(text: string, color: string): string =
  result = color & text & Reset

# Severity levels
type Severity = enum
  svCritical = "CRITICAL"
  svHigh = "HIGH"
  svMedium = "MEDIUM"
  svLow = "LOW"
  svInfo = "INFO"

proc severityColor(s: Severity): string =
  case s
  of svCritical, svHigh: Red
  of svMedium: Yellow
  of svLow: Cyan
  of svInfo: Gray

# Injection techniques
type InjectionTechnique = enum
  itDllInjection = "DLL Injection"
  itProcessHollowing = "Process Hollowing"
  itAtomBombing = "AtomBombing"
  itEarlyBirdApc = "Early Bird APC"
  itThreadHijacking = "Thread Hijacking"
  itReflectiveDll = "Reflective DLL"
  itPeInjection = "PE Injection"
  itShellcodeInjection = "Shellcode Injection"
  itHookInjection = "Hook Injection"
  itUnknown = "Unknown"

# API call patterns
type ApiCall = object
  name: string
  module: string
  address: uint64
  timestamp: float
  threadId: int

# Suspicious pattern
type SuspiciousPattern = object
  technique: InjectionTechnique
  confidence: float
  apis: seq[ApiCall]
  description: string

# Finding
type Finding = object
  severity: Severity
  technique: InjectionTechnique
  pid: int
  processName: string
  description: string
  evidence: seq[string]
  recommendation: string
  timestamp: DateTime

# Process info
type ProcessInfo = object
  pid: int
  name: string
  path: string
  parentPid: int
  threads: int
  modules: seq[string]

# Detection rules
const DllInjectionApis = @[
  "VirtualAllocEx",
  "WriteProcessMemory",
  "CreateRemoteThread",
  "NtCreateThreadEx",
  "RtlCreateUserThread"
]

const ProcessHollowingApis = @[
  "CreateProcessA",
  "CreateProcessW",
  "NtUnmapViewOfSection",
  "VirtualAllocEx",
  "WriteProcessMemory",
  "SetThreadContext",
  "ResumeThread"
]

const AtomBombingApis = @[
  "GlobalAddAtomA",
  "GlobalAddAtomW",
  "NtQueueApcThread",
  "GlobalGetAtomNameA",
  "GlobalGetAtomNameW"
]

const ApcInjectionApis = @[
  "OpenThread",
  "VirtualAllocEx",
  "WriteProcessMemory",
  "QueueUserAPC",
  "NtQueueApcThread"
]

const ThreadHijackApis = @[
  "SuspendThread",
  "GetThreadContext",
  "SetThreadContext",
  "ResumeThread"
]

const ReflectiveApis = @[
  "VirtualAlloc",
  "VirtualProtect",
  "NtProtectVirtualMemory",
  "CreateThread"
]

# Known suspicious modules
const SuspiciousModules = @[
  "ntdll.dll",
  "kernel32.dll",
  "kernelbase.dll"
]

# Detector object
type Detector = object
  apiCalls: seq[ApiCall]
  findings: seq[Finding]
  processCache: Table[int, ProcessInfo]

proc newDetector(): Detector =
  result = Detector(
    apiCalls: @[],
    findings: @[],
    processCache: initTable[int, ProcessInfo]()
  )

# Check for API sequence match
proc matchesPattern(calls: seq[ApiCall], pattern: seq[string], threshold: float = 0.7): tuple[matched: bool, confidence: float, matches: seq[ApiCall]] =
  var matchedApis: seq[ApiCall] = @[]
  var matchedNames: seq[string] = @[]
  
  for call in calls:
    if call.name in pattern and call.name notin matchedNames:
      matchedApis.add(call)
      matchedNames.add(call.name)
  
  let confidence = matchedApis.len.float / pattern.len.float
  result = (confidence >= threshold, confidence, matchedApis)

# Detect DLL injection
proc detectDllInjection(d: var Detector, calls: seq[ApiCall]): seq[SuspiciousPattern] =
  result = @[]
  let (matched, confidence, matches) = matchesPattern(calls, DllInjectionApis)
  
  if matched:
    result.add(SuspiciousPattern(
      technique: itDllInjection,
      confidence: confidence,
      apis: matches,
      description: "Classic DLL injection pattern detected"
    ))

# Detect process hollowing
proc detectProcessHollowing(d: var Detector, calls: seq[ApiCall]): seq[SuspiciousPattern] =
  result = @[]
  let (matched, confidence, matches) = matchesPattern(calls, ProcessHollowingApis, 0.6)
  
  if matched:
    result.add(SuspiciousPattern(
      technique: itProcessHollowing,
      confidence: confidence,
      apis: matches,
      description: "Process hollowing/RunPE pattern detected"
    ))

# Detect AtomBombing
proc detectAtomBombing(d: var Detector, calls: seq[ApiCall]): seq[SuspiciousPattern] =
  result = @[]
  let (matched, confidence, matches) = matchesPattern(calls, AtomBombingApis, 0.6)
  
  if matched:
    result.add(SuspiciousPattern(
      technique: itAtomBombing,
      confidence: confidence,
      apis: matches,
      description: "AtomBombing injection technique detected"
    ))

# Detect APC injection
proc detectApcInjection(d: var Detector, calls: seq[ApiCall]): seq[SuspiciousPattern] =
  result = @[]
  let (matched, confidence, matches) = matchesPattern(calls, ApcInjectionApis, 0.6)
  
  if matched:
    result.add(SuspiciousPattern(
      technique: itEarlyBirdApc,
      confidence: confidence,
      apis: matches,
      description: "APC injection pattern detected"
    ))

# Detect thread hijacking
proc detectThreadHijacking(d: var Detector, calls: seq[ApiCall]): seq[SuspiciousPattern] =
  result = @[]
  let (matched, confidence, matches) = matchesPattern(calls, ThreadHijackApis)
  
  if matched:
    result.add(SuspiciousPattern(
      technique: itThreadHijacking,
      confidence: confidence,
      apis: matches,
      description: "Thread hijacking pattern detected"
    ))

# Detect reflective loading
proc detectReflectiveLoading(d: var Detector, calls: seq[ApiCall]): seq[SuspiciousPattern] =
  result = @[]
  let (matched, confidence, matches) = matchesPattern(calls, ReflectiveApis, 0.75)
  
  # Check for self-injection indicators
  var selfInject = false
  for call in calls:
    if call.name == "VirtualAlloc" or call.name == "VirtualProtect":
      selfInject = true
      break
  
  if matched and selfInject:
    result.add(SuspiciousPattern(
      technique: itReflectiveDll,
      confidence: confidence,
      apis: matches,
      description: "Reflective DLL loading pattern detected"
    ))

# Run all detectors
proc analyze(d: var Detector, calls: seq[ApiCall], pid: int, processName: string) =
  var patterns: seq[SuspiciousPattern] = @[]
  
  patterns.add(d.detectDllInjection(calls))
  patterns.add(d.detectProcessHollowing(calls))
  patterns.add(d.detectAtomBombing(calls))
  patterns.add(d.detectApcInjection(calls))
  patterns.add(d.detectThreadHijacking(calls))
  patterns.add(d.detectReflectiveLoading(calls))
  
  for pattern in patterns:
    let severity = if pattern.confidence >= 0.9: svCritical
                   elif pattern.confidence >= 0.7: svHigh
                   elif pattern.confidence >= 0.5: svMedium
                   else: svLow
    
    var evidence: seq[string] = @[]
    for api in pattern.apis:
      evidence.add(fmt"{api.name} @ 0x{api.address:016X}")
    
    d.findings.add(Finding(
      severity: severity,
      technique: pattern.technique,
      pid: pid,
      processName: processName,
      description: pattern.description,
      evidence: evidence,
      recommendation: "Investigate process for malicious activity",
      timestamp: now()
    ))

# Output procedures
proc printBanner() =
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════╗"
  echo "║           NullSec CodeInject - Code Injection Detector           ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo ""

proc printUsage() =
  echo "USAGE:"
  echo "    codeinject [OPTIONS] [pid]"
  echo ""
  echo "OPTIONS:"
  echo "    -h, --help      Show this help"
  echo "    -a, --all       Monitor all processes"
  echo "    -j, --json      JSON output"
  echo "    -v, --verbose   Verbose output"
  echo ""
  echo "TECHNIQUES DETECTED:"
  echo "    • DLL Injection (CreateRemoteThread)"
  echo "    • Process Hollowing (RunPE)"
  echo "    • AtomBombing"
  echo "    • APC Injection (Early Bird)"
  echo "    • Thread Hijacking"
  echo "    • Reflective DLL Loading"
  echo ""
  echo "EXAMPLES:"
  echo "    codeinject 1234"
  echo "    codeinject --all"
  echo "    codeinject -j 5678"

proc printFinding(f: Finding) =
  let sev = colored(fmt"[{f.severity}]", f.severity.severityColor())
  echo ""
  echo fmt"  {sev} {f.technique}"
  echo fmt"    Process: {f.processName} (PID: {f.pid})"
  echo fmt"    {f.description}"
  echo "    Evidence:"
  for e in f.evidence:
    echo fmt"      • {e}"
  echo colored(fmt"    Recommendation: {f.recommendation}", Gray)

proc printStats(d: Detector) =
  echo ""
  echo colored("═══════════════════════════════════════════", Gray)
  echo ""
  echo "  Statistics:"
  echo fmt"    API Calls:    {d.apiCalls.len}"
  echo fmt"    Findings:     {d.findings.len}"
  echo fmt"    Critical:     {d.findings.filterIt(it.severity == svCritical).len}"
  echo fmt"    High:         {d.findings.filterIt(it.severity == svHigh).len}"
  echo fmt"    Medium:       {d.findings.filterIt(it.severity == svMedium).len}"

# Demo mode
proc demoMode() =
  echo colored("[Demo Mode]", Yellow)
  echo ""
  
  var detector = newDetector()
  
  # Simulate DLL injection API sequence
  let dllInjectionCalls = @[
    ApiCall(name: "OpenProcess", module: "kernel32.dll", address: 0x7FF8A1234560'u64, timestamp: 1.0, threadId: 1000),
    ApiCall(name: "VirtualAllocEx", module: "kernel32.dll", address: 0x7FF8A1234570'u64, timestamp: 1.1, threadId: 1000),
    ApiCall(name: "WriteProcessMemory", module: "kernel32.dll", address: 0x7FF8A1234580'u64, timestamp: 1.2, threadId: 1000),
    ApiCall(name: "CreateRemoteThread", module: "kernel32.dll", address: 0x7FF8A1234590'u64, timestamp: 1.3, threadId: 1000),
  ]
  
  # Simulate process hollowing
  let processHollowingCalls = @[
    ApiCall(name: "CreateProcessW", module: "kernel32.dll", address: 0x7FF8A1234600'u64, timestamp: 2.0, threadId: 2000),
    ApiCall(name: "NtUnmapViewOfSection", module: "ntdll.dll", address: 0x7FF8A5678900'u64, timestamp: 2.1, threadId: 2000),
    ApiCall(name: "VirtualAllocEx", module: "kernel32.dll", address: 0x7FF8A1234610'u64, timestamp: 2.2, threadId: 2000),
    ApiCall(name: "WriteProcessMemory", module: "kernel32.dll", address: 0x7FF8A1234620'u64, timestamp: 2.3, threadId: 2000),
    ApiCall(name: "SetThreadContext", module: "kernel32.dll", address: 0x7FF8A1234630'u64, timestamp: 2.4, threadId: 2000),
    ApiCall(name: "ResumeThread", module: "kernel32.dll", address: 0x7FF8A1234640'u64, timestamp: 2.5, threadId: 2000),
  ]
  
  echo colored("Analyzing API call sequences...", Cyan)
  echo ""
  
  detector.analyze(dllInjectionCalls, 1234, "suspicious.exe")
  detector.analyze(processHollowingCalls, 5678, "malware.exe")
  
  echo "Injection Detection Results:"
  
  for finding in detector.findings:
    printFinding(finding)
  
  printStats(detector)

# Main entry point
when isMainModule:
  printBanner()
  
  let args = commandLineParams()
  
  if args.len == 0 or "-h" in args or "--help" in args:
    printUsage()
    echo ""
    demoMode()
  else:
    printUsage()

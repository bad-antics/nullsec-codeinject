# NullSec CodeInject

**Code Injection Detector** built with **Nim** - Identify and analyze process injection techniques in real-time.

[![Language](https://img.shields.io/badge/Nim-FFE953?style=flat-square&logo=nim&logoColor=black)](https://nim-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square)]()
[![NullSec](https://img.shields.io/badge/NullSec-Tool-red?style=flat-square)](https://bad-antics.github.io)

## Overview

NullSec CodeInject is a code injection detection tool written in Nim, designed to identify malicious process injection techniques through API call pattern analysis. Detects DLL injection, process hollowing, AtomBombing, and more.

## Features

- **Multiple Technique Detection** - DLL injection, hollowing, APC, thread hijacking
- **API Sequence Analysis** - Pattern matching on Windows API calls
- **Confidence Scoring** - Probability-based detection results
- **Real-time Monitoring** - Live process analysis
- **Cross-compilation** - Windows and Linux support
- **Zero Dependencies** - Pure Nim implementation

## Detection Techniques

| Technique | APIs Monitored | Severity |
|-----------|---------------|----------|
| DLL Injection | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | Critical |
| Process Hollowing | CreateProcess, NtUnmapViewOfSection, SetThreadContext | Critical |
| AtomBombing | GlobalAddAtom, NtQueueApcThread | High |
| APC Injection | QueueUserAPC, NtQueueApcThread | High |
| Thread Hijacking | SuspendThread, GetThreadContext, SetThreadContext | High |
| Reflective DLL | VirtualAlloc, VirtualProtect, CreateThread | Medium |

## Installation

```bash
# Install Nim
curl https://nim-lang.org/choosenim/init.sh -sSf | sh

# Clone and build
git clone https://github.com/bad-antics/nullsec-codeinject
cd nullsec-codeinject
nim c -d:release codeinject.nim
```

## Usage

### Basic Usage

```bash
# Run demo mode
./codeinject

# Monitor specific process
./codeinject 1234

# Monitor all processes
./codeinject --all

# JSON output
./codeinject -j 5678
```

### Options

```
-h, --help      Show help message
-a, --all       Monitor all processes
-j, --json      Output results as JSON
-v, --verbose   Enable verbose output
```

### Examples

```bash
# Detect injection in suspicious process
./codeinject $(pgrep suspicious)

# Full system monitoring
./codeinject --all -v

# CI/CD integration
./codeinject -j 1234 > findings.json
```

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                   Detection Pipeline                       │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              API Call Monitor                        │ │
│  │   VirtualAllocEx, WriteProcessMemory, etc.          │ │
│  └──────────────────────┬──────────────────────────────┘ │
│                         │                                 │
│                         ▼                                 │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Pattern Matchers                        │ │
│  ├─────────────────────────────────────────────────────┤ │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐         │ │
│  │  │    DLL    │ │  Process  │ │   Atom    │         │ │
│  │  │ Injection │ │ Hollowing │ │  Bombing  │         │ │
│  │  └───────────┘ └───────────┘ └───────────┘         │ │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐         │ │
│  │  │    APC    │ │  Thread   │ │ Reflective│         │ │
│  │  │ Injection │ │  Hijack   │ │    DLL    │         │ │
│  │  └───────────┘ └───────────┘ └───────────┘         │ │
│  └──────────────────────┬──────────────────────────────┘ │
│                         │                                 │
│                         ▼                                 │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Confidence Scorer                       │ │
│  │   confidence = matches / required_apis              │ │
│  └──────────────────────┬──────────────────────────────┘ │
│                         │                                 │
│                         ▼                                 │
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Finding Generator                       │ │
│  │   severity, evidence, recommendations               │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

## API Patterns

### DLL Injection Pattern

```nim
const DllInjectionApis = @[
  "VirtualAllocEx",       # Allocate memory in target
  "WriteProcessMemory",   # Write DLL path/shellcode
  "CreateRemoteThread",   # Execute in target context
  "NtCreateThreadEx",     # Alternative thread creation
  "RtlCreateUserThread"   # Undocumented alternative
]
```

### Process Hollowing Pattern

```nim
const ProcessHollowingApis = @[
  "CreateProcessW",         # Create suspended process
  "NtUnmapViewOfSection",   # Hollow out the process
  "VirtualAllocEx",         # Allocate new memory
  "WriteProcessMemory",     # Write malicious payload
  "SetThreadContext",       # Set new entry point
  "ResumeThread"            # Resume execution
]
```

## Output Example

```
[CRITICAL] DLL Injection
  Process: suspicious.exe (PID: 1234)
  Classic DLL injection pattern detected
  Evidence:
    • VirtualAllocEx @ 0x00007FF8A1234570
    • WriteProcessMemory @ 0x00007FF8A1234580
    • CreateRemoteThread @ 0x00007FF8A1234590
  Recommendation: Investigate process for malicious activity

[CRITICAL] Process Hollowing
  Process: malware.exe (PID: 5678)
  Process hollowing/RunPE pattern detected
  Evidence:
    • CreateProcessW @ 0x00007FF8A1234600
    • NtUnmapViewOfSection @ 0x00007FF8A5678900
    • SetThreadContext @ 0x00007FF8A1234630
  Recommendation: Investigate process for malicious activity
```

## Why Nim?

- **Zero-Cost Abstractions** - C-level performance
- **Memory Safety** - Automatic memory management
- **Metaprogramming** - Powerful compile-time features
- **Cross-Platform** - Windows and Linux from same code
- **Clean Syntax** - Python-like readability
- **Small Binaries** - Minimal runtime overhead

## Confidence Scoring

```nim
proc matchesPattern(calls, pattern, threshold = 0.7):
  # Calculate match confidence
  confidence = matchedApis.len / pattern.len
  
  # Return detection result
  return (confidence >= threshold, confidence, matchedApis)
```

## Resources

- [Nim Language](https://nim-lang.org/)
- [Process Injection Techniques](https://attack.mitre.org/techniques/T1055/)
- [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/)
- [MITRE ATT&CK](https://attack.mitre.org/)

## NullSec Toolkit

Part of the **NullSec** security toolkit collection:
- 🌐 [Portal](https://bad-antics.github.io)
- 💬 [Discord](https://x.com/AnonAntics)
- 📦 [GitHub](https://github.com/bad-antics)

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**NullSec** - *Detecting code injection for defense and research*

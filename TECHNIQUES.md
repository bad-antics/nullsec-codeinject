# Code Injection Techniques Guide

## Overview
Process injection techniques for red team operations.

## Classic Techniques

### DLL Injection
- CreateRemoteThread
- SetWindowsHookEx
- AppInit_DLLs
- QueueUserAPC

### Shellcode Injection
- VirtualAllocEx
- WriteProcessMemory
- NtCreateThreadEx
- RtlCreateUserThread

## Advanced Techniques

### Process Hollowing
- Create suspended process
- Unmap original image
- Write malicious code
- Resume execution

### Process Doppelganging
- TxF transactions
- Section creation
- Transaction rollback
- Clean image creation

### Module Stomping
- Overwrite legitimate DLL
- Maintain exports
- Blend with process

## Evasion Methods

### Direct Syscalls
- Bypass user-mode hooks
- Ntdll extraction
- Syscall numbers
- Gate address

### Unhooking
- Remap ntdll
- Byte patching
- Memory restoration

## Detection Indicators
- Memory anomalies
- Thread creation events
- Module discrepancies
- API call patterns

## Legal Notice
For authorized red team operations only.

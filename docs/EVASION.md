# Evasion

## Fresh ntdll

EDRs place userland hooks in `ntdll.dll` at process startup. Loading a clean copy from `\KnownDlls\ntdll.dll` (section object, no filesystem minifilter callbacks) bypasses these hooks.

Does not bypass kernel callbacks (CrowdStrike AUMD, MDE kernel ETW consumers, `PsSetCreateThreadNotifyRoutine`).

## Indirect syscalls

Direct `syscall` from non-ntdll memory is flagged. Jumping to a `syscall; ret` gadget inside the fresh ntdll makes the instruction pointer originate from legitimate ntdll code.

Remaining gap: the stack return address at syscall time still points to `loader.exe`. A deep EDR stack walk (sampling the return address chain) can detect this. Not addressed in the current version.

## Hell's Gate SSN resolution

Syscall numbers change across Windows builds. Parsing the fresh ntdll export table extracts the SSN from each `Nt*` stub at runtime instead of hardcoding.

## AMSI/ETW patching

`AmsiScanBuffer` → patched to `xor eax, eax; ret`. `EtwEventWrite` → patched to `ret`. Both run through `NtProtectVirtualMemory` (indirect syscall) after the syscall table is populated.

## Shellcode XOR encoding

Shellcode bytes are XOR-encoded at comptime (`0xAB` mask). Only the encoded form exists in `.data`. Decoded in-place after allocation.

## SSN/gadget XOR obfuscation

The `wSystemCall` and `qSyscallInsAddress` globals in `.data` are stored XORed with static masks (`0xDEADBEEF` / `0xDEADBEEFDEADBEEF`). Decoded in the asm dispatch before use. Prevents plaintext YARA scanning of SSN and gadget pointer values.

## Technique comparison

| Technique | Bypasses | Does not bypass |
|-----------|----------|-----------------|
| Fresh ntdll | Userland EDR hooks | Kernel callbacks, kernel ETW |
| Indirect syscall | `syscall` IP monitoring | Stack return address walk |
| AMSI patch | PowerShell/VBA scanning | Kernel-level AMSI |
| ETW patch | Userland ETW providers | Kernel-level ETW consumers |
| Hell's Gate | Hardcoded SSN versioning | — |
| XOR globals | Static YARA byte scanning | Memory dumping |

# Architecture

## Pipeline

```
Entry → Fresh ntdll → SSN/gadget resolution → AMSI/ETW patches
    → Jitter → Alloc RW → Copy shellcode → Decode XOR
    → Protect RX → CreateThread → Wait
```

### 1. Fresh ntdll (`fresh.zig`)

Opens `\KnownDlls\ntdll.dll` section via `NtOpenSection` (avoids filesystem minifilter callbacks), maps a clean copy with `NtMapViewOfSection`. Returns a pointer to the unmodified PE image.

### 2. Syscall table (`syscall.zig` + `hells_gate.s`)

For each required `Nt*` function, `syscall.zig` parses the fresh ntdll export table, validates the `mov r10, rcx` (`4C 8B D1`) stub prefix, extracts the syscall number from `mov eax, imm32`, and scans for the `syscall; ret` gadget (`0F 05 C3`).

The assembly dispatch (`hells_gate.s`) stores SSN and gadget address XOR-encoded in `.data` globals. `hell_descent` decodes them at call time, moves arg1 to `r10`, loads SSN into `eax`, and jumps to the gadget. The XOR masks prevent plaintext SSN/gadget scanning.

### 3. AMSI/ETW patches (`main.zig`)

Both patches run after the syscall table is populated. `VirtualProtect` is replaced with `NtProtectVirtualMemory` through the indirect syscall path.

- `patchAmsiScanBuffer`: Writes `xor eax, eax; ret` (`31 C0 C3`) to `AmsiScanBuffer`.
- `patchEtwEventWrite`: Writes `ret` (`C3`) to `EtwEventWrite`.

### 4. Shellcode execution

- `NtDelayExecution` (50ms jitter) between stages
- `NtAllocateVirtualMemory` → RW allocation, NTSTATUS checked
- Shellcode XOR-decoded in-place at runtime (comptime-encoded in `.data`)
- `NtProtectVirtualMemory` → RX
- `NtCreateThreadEx` → thread at shellcode base
- `NtWaitForSingleObject` → wait for completion

All NT operations go through the indirect syscall dispatch.

## Module Dependencies

```
main.zig
  ├── win32.zig (types, externs)
  ├── fresh.zig
  │     └── win32.zig
  └── syscall.zig
        └── pe.zig
```

`hells_gate.s` linked via `build.zig` → `addAssemblyFile`.

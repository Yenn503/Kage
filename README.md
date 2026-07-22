# Kage <sub>影</sub>

<p align="center">
  <img src="assets/Kage.png" alt="Kage">
</p>

> 影に潜む

Shellcode loader using indirect syscalls. Self-injection, RecycledGate SSN extraction, random gadget pool, callstack spoofing, per-build XOR key, jitter. Windowless.

## Build

```bash
# 1. drop your shellcode as src/payload.bin
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseFast
# → zig-out/bin/kage.exe
```

## 仕掛け

- **影探し** — ntdll via PEB walk (`gs:[0x60]`)
- **闇渡り** — indirect syscall dispatch (64 random gadgets)
- **血判** — RecycledGate SSN extraction (FreshyCalls RVA sort + stub byte-scan + delta correction, hook-safe)
- **封印** — build-time shellcode XOR with per-build 128-bit random key
- **影纏い** — XOR-encoded asm dispatch globals + callstack spoofing

For evasion use [Valak](https://git.churchofmalware.org/JYenn/valak).

## Layout

```
src/
├── main.zig       entry, unified syscall dispatch
├── nt.zig         NT pseudo-handles not in stdlib
├── pe.zig         PE parser, export resolver, section headers
├── syscall.zig    PEB walk, FreshyCalls table, gadget pool, PRNG
├── hells_gate.s   asm dispatch (XOR globals, stack spoof)
build.zig
```

## License

MIT

## Sophos Evasion

Kage + Valak chain bypassing Sophos EDR with command execution:

<p align="center">
  <img src="assets/Sophos.png" alt="Sophos Bypass">
  <img src="assets/whoami.png" alt="Command Execution">
</p>
